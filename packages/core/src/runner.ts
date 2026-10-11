import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { extname, join, relative, sep } from "node:path";
import { SEVERITY_ORDER, meetsThreshold, type Finding } from "./findings.js";
import "./rules/builtin/index.js"; // side effect: registers built-in rules
import { registry } from "./rules/registry.js";
import { TextEngine } from "./engines/text-engine.js";
import * as astEngineModule from "./engines/ast-engine.js";
import { languageForExtension, type Engine } from "./engines/types.js";
import { resolveProvider } from "./llm/providers.js";
import { AttackAgent } from "./llm/attack-agent.js";
import type { DismissedFinding } from "./llm/attack-agent.js";
// Same shape as the attack agent's dismissal record; re-exported (not
// redefined) so index.ts has a single DismissedFinding export.
export type { DismissedFinding };
import { render as renderJson } from "./reporters/json.js";
import { render as renderMarkdown } from "./reporters/markdown.js";
import { render as renderSarif } from "./reporters/sarif.js";
import { render as renderHtml } from "./reporters/html.js";
import type { RedteamConfig } from "./config.js";

export interface RunResult {
  findings: Finding[];
  dismissed: DismissedFinding[];
  notices: string[];
  exitCode: 0 | 1 | 2;
  report: string;
}

const MAX_FILES = 20_000;
const SCAN_CONCURRENCY = 8;

const SCAN_EXTENSIONS = new Set([
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".mts",
  ".cts",
  ".py",
]);

/* ------------------------------------------------------------------ */
/* Inline glob matching (no new dependencies): supports `**`, `*`, `?` */
/* ------------------------------------------------------------------ */

const REGEXP_SPECIAL = /[.*+?^${}()|[\]\\]/g;

/** Escape a literal string for use in a RegExp. */
function escapeRegExp(s: string): string {
  return s.replace(REGEXP_SPECIAL, "\\$&");
}

/** Compile a glob pattern to a RegExp. A double-star-slash segment matches zero or more path segments. */
export function compileGlob(glob: string): RegExp {
  let out = "";
  let i = 0;
  while (i < glob.length) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 3;
        } else {
          out += ".*";
          i += 2;
        }
      } else {
        out += "[^/]*";
        i += 1;
      }
    } else if (c === "?") {
      out += "[^/]";
      i += 1;
    } else {
      out += escapeRegExp(c);
      i += 1;
    }
  }
  return new RegExp(`^${out}$`);
}

/** True if `path` (forward-slash relative) matches any of the glob patterns. */
export function matchesGlob(patterns: string[], path: string): boolean {
  return patterns.some((p) => compileGlob(p).test(path));
}

/** Rule-id wildcard: `*` matches any run of characters. */
function matchesRulePattern(pattern: string, ruleId: string): boolean {
  const re = new RegExp("^" + pattern.split("*").map(escapeRegExp).join(".*") + "$");
  return re.test(ruleId);
}

/* ------------------------------------------------------------------ */
/* File collection                                                     */
/* ------------------------------------------------------------------ */

interface CollectedFile {
  abs: string;
  /** Forward-slash path relative to the scan root. */
  rel: string;
}

async function collectFiles(
  dir: string,
  excludes: string[],
): Promise<{ files: CollectedFile[]; notices: string[] }> {
  const notices: string[] = [];
  const files: CollectedFile[] = [];
  const seenDirs = new Set<string>();
  const stack: string[] = [dir];
  let capped = false;

  while (stack.length > 0 && !capped) {
    const current = stack.pop() as string;
    let real: string;
    try {
      real = await realpath(current);
    } catch {
      continue; // unreadable dir: skip
    }
    if (seenDirs.has(real)) continue; // symlink loop guard
    seenDirs.add(real);

    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        if (files.length >= MAX_FILES) {
          capped = true;
          break;
        }
        pushIfScannable(files, dir, full, excludes);
      } else if (entry.isSymbolicLink()) {
        let st;
        try {
          st = await stat(full); // follows the link
        } catch {
          continue;
        }
        if (st.isDirectory()) {
          stack.push(full); // loop guard applies via realpath on pop
        } else if (st.isFile()) {
          if (files.length >= MAX_FILES) {
            capped = true;
            break;
          }
          pushIfScannable(files, dir, full, excludes);
        }
      }
    }
  }

  if (capped) {
    notices.push(
      `File cap reached (${MAX_FILES} files); remaining files were skipped.`,
    );
  }
  return { files, notices };
}

function pushIfScannable(
  out: CollectedFile[],
  dir: string,
  full: string,
  excludes: string[],
): void {
  if (!SCAN_EXTENSIONS.has(extname(full).toLowerCase())) return;
  const rel = relative(dir, full).split(sep).join("/");
  if (matchesGlob(excludes, rel)) return;
  out.push({ abs: full, rel });
}

/* ------------------------------------------------------------------ */
/* Engines                                                             */
/* ------------------------------------------------------------------ */

/**
 * The AST engine is owned by a parallel agent; it may still be a stub when
 * this module loads. Resolve it defensively so the runner works either way.
 */
function engines(): { list: Engine[]; notices: string[] } {
  const list: Engine[] = [new TextEngine()];
  const notices: string[] = [];
  const ctor = (astEngineModule as { AstEngine?: unknown }).AstEngine;
  if (typeof ctor === "function") {
    try {
      list.push(new (ctor as new () => Engine)());
    } catch {
      notices.push(
        "AST engine unavailable — results are text-only (syntax rules skipped).",
      );
    }
  } else {
    notices.push(
      "AST engine unavailable — results are text-only (syntax rules skipped).",
    );
  }
  return { list, notices };
}

async function scanFiles(enginesList: Engine[], files: CollectedFile[]): Promise<Finding[]> {
  const findings: Finding[] = [];
  let index = 0;
  const workers = Array.from(
    { length: Math.max(1, Math.min(SCAN_CONCURRENCY, files.length)) },
    async () => {
      while (true) {
        const i = index++;
        if (i >= files.length) return;
        const f = files[i];
        let content: string;
        try {
          content = await readFile(f.abs, "utf8");
        } catch {
          continue;
        }
        const scanned = {
          path: f.rel,
          content,
          language: languageForExtension(extname(f.abs)),
        };
        for (const engine of enginesList) {
          try {
            findings.push(...(await engine.scan(scanned)));
          } catch {
            // One engine failing on one file must not kill the whole scan.
          }
        }
      }
    },
  );
  await Promise.all(workers);
  return findings;
}

/* ------------------------------------------------------------------ */
/* runScan                                                             */
/* ------------------------------------------------------------------ */

function activeRuleIds(config: RedteamConfig): Set<string> {
  const include = config.rules.include ?? [];
  const exclude = config.rules.exclude ?? [];
  return new Set(
    registry
      .list()
      .filter((r) => include.length === 0 || include.some((p) => matchesRulePattern(p, r.id)))
      .filter((r) => !exclude.some((p) => matchesRulePattern(p, r.id)))
      .map((r) => r.id),
  );
}

function dedupeSort(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.ruleId}\0${f.file}\0${f.line}\0${f.col}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  out.sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.col - b.col,
  );
  return out;
}

function renderReport(config: RedteamConfig, findings: Finding[], dir: string): string {
  switch (config.format) {
    case "json":
      return renderJson(findings);
    case "sarif":
      return renderSarif(findings);
    case "html":
      return renderHtml(findings, { dir });
    default:
      return renderMarkdown(findings);
  }
}

/**
 * Run a full scan: collect files → engines → rule filtering → LLM
 * attack-agent stage → report → exit code.
 *
 * ConfigError propagates to the caller (the CLI maps it to exit code 2).
 */
export async function runScan(opts: { dir: string; config: RedteamConfig }): Promise<RunResult> {
  const { dir, config } = opts;
  const notices: string[] = [];
  const dismissed: DismissedFinding[] = [];

  const { files, notices: walkNotices } = await collectFiles(dir, config.exclude);
  notices.push(...walkNotices);

  const active = activeRuleIds(config);
  const { list: engineList, notices: engineNotices } = engines();
  notices.push(...engineNotices);
  let findings = dedupeSort(
    (await scanFiles(engineList, files)).filter((f) => active.has(f.ruleId)),
  );

  // LLM attack-agent stage (post-processor).
  if (config.llm.enabled) {
    const provider = resolveProvider();
    if (provider) {
      const needsLlm = findings.some((f) => f.severity === "high" || f.severity === "medium");
      if (needsLlm) {
        const agent = new AttackAgent({ provider });
        const result = await agent.analyze(findings, (path) =>
          readFile(join(dir, path), "utf8"),
        );
        findings = result.findings;
        dismissed.push(...result.dismissed);
        if (result.notice) notices.push(result.notice);
      }
    } else {
      notices.push(
        "LLM attack-agent skipped: no API key (set ANTHROPIC_API_KEY or OPENAI_API_KEY); static results unaffected.",
      );
    }
  } else {
    notices.push("LLM attack-agent disabled by config.");
  }

  const report = renderReport(config, findings, dir);
  const exitCode: 0 | 1 = findings.some((f) => meetsThreshold(f.severity, config.failOn)) ? 1 : 0;

  return { findings, dismissed, notices, exitCode, report };
}
