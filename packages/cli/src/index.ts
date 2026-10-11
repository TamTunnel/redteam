#!/usr/bin/env node
/**
 * `redteam` — adversarial security scanner CLI.
 *
 * Commands: `scan [dir]`, `rules list`, `init`.
 *
 * The heavy lifting (config resolution, scanning, reporting) lives in
 * `@tamtunnel/redteam-core`. This package only wires CLI flags to the core
 * contracts:
 *   - loadConfig(cwd, overrides) -> RedteamConfig        (core: config.ts)
 *   - runScan({ dir, config }) -> ScanResult              (core: runner.ts)
 *   - registry.list() for `rules list`                   (core: rules/)
 */
import { createRequire } from "node:module";
import { promises as fs } from "node:fs";
import { resolve } from "node:path";
import { defineCommand, runMain } from "citty";
import {
  registry,
  SEVERITY_ORDER,
  type Finding,
  type Severity,
} from "@tamtunnel/redteam-core";

// ---------------------------------------------------------------------------
// Core contracts (the config/runner agents are still building these).
// Kept behind a lazy dynamic import + structural cast so that `rules list`,
// `init`, `--help` and `--version` work before the core is complete, and so
// this file needs no changes when the real implementations land.
// ---------------------------------------------------------------------------

/** Assumed shape of the core's RedteamConfig (the config agent owns the truth). */
interface RedteamConfig {
  failOn: Severity;
  format: "json" | "markdown" | "sarif" | "html";
  exclude: string[];
  rules?: { include?: string[]; exclude?: string[] };
  llm: boolean;
  [key: string]: unknown;
}

/** Flag overrides passed to loadConfig — only for flags the user actually gave. */
interface ConfigOverrides {
  failOn?: Severity;
  format?: RedteamConfig["format"];
  exclude?: string[];
  rules?: { include: string[]; exclude: string[] };
  llm?: boolean;
}

interface ScanResult {
  findings: Finding[];
  dismissed: unknown[];
  notices: string[];
  exitCode: 0 | 1 | 2;
  report: string;
}

interface CoreContracts {
  loadConfig: (cwd: string, overrides: ConfigOverrides) => Promise<RedteamConfig>;
  runScan: (opts: { dir: string; config: RedteamConfig }) => Promise<ScanResult>;
  ConfigError?: new (message?: string) => Error;
}

let cachedCore: Promise<CoreContracts> | undefined;

function loadCore(): Promise<CoreContracts> {
  cachedCore ??= (async () => {
    const mod = (await import("@tamtunnel/redteam-core")) as unknown as Partial<CoreContracts>;
    const missing = (["loadConfig", "runScan"] as const).filter(
      (k) => typeof mod[k] !== "function",
    );
    if (missing.length > 0) {
      throw new Error(
        `@tamtunnel/redteam-core does not export ${missing.join(", ")} yet — the core build is incomplete`,
      );
    }
    return mod as CoreContracts;
  })();
  return cachedCore;
}

function isConfigError(err: unknown, ctor: CoreContracts["ConfigError"]): boolean {
  if (typeof ctor === "function" && err instanceof ctor) return true;
  return err instanceof Error && err.name === "ConfigError";
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const FORMATS = ["json", "markdown", "sarif", "html"] as const;

function isSeverity(v: string): v is Severity {
  return (SEVERITIES as readonly string[]).includes(v);
}

function isFormat(v: string): v is RedteamConfig["format"] {
  return (FORMATS as readonly string[]).includes(v);
}

/** citty hands back `string` for a single use and `string[]` for repeats. */
function toStringArray(v: unknown): string[] {
  if (v === undefined || v === null) return [];
  const arr = Array.isArray(v) ? v.map(String) : [String(v)];
  // Split comma-separated globs: --exclude "test/**,fixtures/**" works.
  return arr.flatMap((s) => s.split(",").map((p) => p.trim()).filter(Boolean));
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Parse a `--rules` spec like "+sec-*,-sec-regex-dos" into include/exclude id
 * lists. `*` wildcards are expanded against the registered rule ids; a part
 * with no sign defaults to include.
 */
function parseRulesSpec(spec: string): { include: string[]; exclude: string[] } {
  const include: string[] = [];
  const exclude: string[] = [];
  for (const raw of spec.split(",")) {
    const part = raw.trim();
    if (part === "") continue;
    const sign = part[0] === "+" || part[0] === "-" ? part[0] : "+";
    const id = (sign === "+" || sign === "-" ? part.slice(1) : part).trim();
    if (id === "") continue;
    const ids = id.includes("*")
      ? registry
          .list()
          .map((r) => r.id)
          .filter((rid) =>
            new RegExp(`^${id.split("*").map(escapeRegExp).join(".*")}$`).test(rid),
          )
      : [id];
    (sign === "-" ? exclude : include).push(...ids);
  }
  return { include, exclude };
}

function summaryLine(findings: Finding[], threshold: Severity): string {
  const counts = new Map<Severity, number>();
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const parts = (Object.keys(SEVERITY_ORDER) as Severity[])
    .sort((a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a])
    .filter((s) => (counts.get(s) ?? 0) > 0)
    .map((s) => `${counts.get(s)} ${s}`);
  return `redteam: ${findings.length} finding(s) (${parts.join(", ")}) — threshold ${threshold}`;
}

function printTable(rows: Record<string, string>[]): void {
  const headers = Object.keys(rows[0] as Record<string, string>);
  const widths = headers.map((h) => Math.max(h.length, ...rows.map((r) => r[h]?.length ?? 0)));
  const line = (cells: string[]): string =>
    cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join("  ");
  console.log(line(headers));
  console.log(line(headers.map((_, i) => "-".repeat(widths[i] ?? 0))));
  for (const r of rows) console.log(line(headers.map((h) => r[h] ?? "")));
}

// ---------------------------------------------------------------------------
// `redteam scan [dir]`
// ---------------------------------------------------------------------------

const scanCmd = defineCommand({
  meta: {
    name: "scan",
    description: "Scan a directory for security findings",
  },
  args: {
    dir: {
      type: "positional",
      description: "Directory to scan",
      required: false,
      default: ".",
    },
    "fail-on": {
      type: "string",
      description: `Minimum severity that fails the scan (${SEVERITIES.join("|")})`,
      valueHint: "severity",
    },
    format: {
      type: "string",
      description: `Report format (${FORMATS.join("|")})`,
      valueHint: "format",
    },
    exclude: {
      type: "string",
      description: "Glob of paths to exclude (repeatable)",
      valueHint: "glob",
    },
    rules: {
      type: "string",
      description: 'Rule filter, e.g. "+sec-*,-sec-regex-dos" (+include/-exclude, * = wildcard)',
      valueHint: "spec",
    },
    llm: {
      type: "boolean",
      description: "Enable the LLM attack-agent pass (default true; --no-llm to disable)",
    },
    output: {
      type: "string",
      description: "Write the report to a file instead of stdout",
      alias: "o",
      valueHint: "file",
    },
  },
  async run({ args }) {
    const failOnRaw = args["fail-on"] as string | undefined;
    if (failOnRaw !== undefined && !isSeverity(failOnRaw)) {
      console.error(
        `redteam: invalid --fail-on "${failOnRaw}" (expected one of: ${SEVERITIES.join(", ")})`,
      );
      process.exitCode = 2;
      return;
    }

    const formatRaw = args.format as string | undefined;
    if (formatRaw !== undefined && !isFormat(formatRaw)) {
      console.error(
        `redteam: invalid --format "${formatRaw}" (expected one of: ${FORMATS.join(", ")})`,
      );
      process.exitCode = 2;
      return;
    }

    // Only pass flags the user actually gave, so config-file values survive
    // (precedence: flags > config file > core defaults).
    const overrides: ConfigOverrides = {};
    if (failOnRaw !== undefined) overrides.failOn = failOnRaw;
    if (formatRaw !== undefined) overrides.format = formatRaw;
    const excludes = toStringArray(args.exclude);
    if (excludes.length > 0) overrides.exclude = excludes;
    const rulesRaw = args.rules as string | undefined;
    if (rulesRaw !== undefined && rulesRaw.trim() !== "") {
      overrides.rules = parseRulesSpec(rulesRaw);
    }
    const llmRaw = args.llm as boolean | undefined;
    if (llmRaw !== undefined) overrides.llm = llmRaw;

    let core: CoreContracts;
    try {
      core = await loadCore();
    } catch (err) {
      console.error(`redteam: ${messageOf(err)}`);
      process.exitCode = 2;
      return;
    }

    const cwd = process.cwd();
    let config: RedteamConfig;
    try {
      config = await core.loadConfig(cwd, overrides);
    } catch (err) {
      if (isConfigError(err, core.ConfigError)) {
        console.error(`redteam: configuration error: ${messageOf(err)}`);
      } else {
        console.error("redteam: unexpected error while loading config:", err);
      }
      process.exitCode = 2;
      return;
    }

    let result: ScanResult;
    try {
      result = await core.runScan({ dir: resolve(cwd, args.dir), config });
    } catch (err) {
      console.error("redteam: scan failed:", err);
      process.exitCode = 2;
      return;
    }

    const outFile = args.output as string | undefined;
    if (outFile !== undefined) {
      try {
        await fs.writeFile(resolve(cwd, outFile), result.report, "utf8");
      } catch (err) {
        console.error(`redteam: cannot write report to "${outFile}": ${messageOf(err)}`);
        process.exitCode = 2;
        return;
      }
    } else {
      process.stdout.write(result.report.endsWith("\n") ? result.report : `${result.report}\n`);
    }

    for (const notice of result.notices ?? []) {
      console.error(notice);
    }

    if (result.exitCode !== 0 && result.findings.length > 0) {
      console.error(summaryLine(result.findings, config.failOn));
    }
    process.exitCode = result.exitCode;
  },
});

// ---------------------------------------------------------------------------
// `redteam rules list`
// ---------------------------------------------------------------------------

const rulesListCmd = defineCommand({
  meta: { name: "list", description: "List all registered rules" },
  run() {
    const rules = [...registry.list()].sort((a, b) => a.id.localeCompare(b.id));
    if (rules.length === 0) {
      console.log("No rules registered.");
      return;
    }
    printTable(
      rules.map((r) => ({
        ID: r.id,
        SEVERITY: r.severity,
        LANGUAGES: r.languages.join(","),
        MESSAGE: r.message,
      })),
    );
  },
});

const rulesCmd = defineCommand({
  meta: { name: "rules", description: "Inspect the rule registry" },
  subCommands: { list: rulesListCmd },
});

// ---------------------------------------------------------------------------
// `redteam init`
// ---------------------------------------------------------------------------

const initCmd = defineCommand({
  meta: {
    name: "init",
    description: "Write a starter .redteamrc.json in the current directory",
  },
  args: {
    force: {
      type: "boolean",
      description: "Overwrite an existing .redteamrc.json",
    },
  },
  async run({ args }) {
    const path = resolve(process.cwd(), ".redteamrc.json");
    const exists = await fs
      .access(path)
      .then(() => true)
      .catch((err: unknown) =>
        (err as NodeJS.ErrnoException).code === "ENOENT" ? false : Promise.reject(err),
      );
    if (exists && !args.force) {
      console.error("redteam: .redteamrc.json already exists (use --force to overwrite)");
      process.exitCode = 2;
      return;
    }
    const starter = {
      failOn: "medium",
      format: "markdown",
      exclude: ["node_modules/**", "dist/**"],
      llm: true,
    };
    await fs.writeFile(path, `${JSON.stringify(starter, null, 2)}\n`, "utf8");
    console.log(`redteam: wrote ${path}`);
  },
});

// ---------------------------------------------------------------------------
// Root
// ---------------------------------------------------------------------------

const require = createRequire(import.meta.url);
const { version } = require("../package.json") as { version: string };

const main = defineCommand({
  meta: {
    name: "redteam",
    version,
    description: "Adversarial security scanner for agent-built code",
  },
  subCommands: {
    scan: scanCmd,
    rules: rulesCmd,
    init: initCmd,
  },
});

runMain(main);
