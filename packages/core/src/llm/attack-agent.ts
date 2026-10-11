/**
 * LLM attack-agent pass (ARCHITECTURE.md §3 "LLM pass").
 *
 * Post-processor stage: takes high/medium static findings plus surrounding code
 * and, for each finding, asks the model to do two jobs in ONE prompt —
 *   (a) confirm-or-dismiss the static finding WITH a reason (false-positive filter), and
 *   (b) hunt for logic flaws static analysis misses (auth bypass, IDOR, insecure
 *       defaults, race conditions, crypto misuse, …), reported as new
 *       `source: "llm"` findings (the corroboration path — high/critical allowed).
 *
 * Prompts go out sequentially (one per finding) to be kind to rate limits.
 * Defensive JSON parsing: on parse failure the static finding is kept —
 * findings are never silently dropped. No API key → the stage is skipped via
 * `maybeAttack` with a one-line notice; static results are unaffected.
 */

import type { Finding, Severity } from "../findings.js";
import { resolveProvider, type LlmProvider } from "./providers.js";

export interface AttackAgentOptions {
  provider: LlmProvider;
  /** Max static findings sent to the LLM (highest severity first). Default 25. */
  maxFindings?: number;
  /** Source lines of context on each side of a finding. Default 15. */
  contextLines?: number;
}

export interface DismissedFinding {
  ruleId: string;
  file: string;
  line: number;
  reason: string;
}

export interface AttackAgentResult {
  findings: Finding[];
  dismissed: DismissedFinding[];
  notice?: string;
}

export interface MaybeAttackOptions {
  /** Explicit provider; defaults to `resolveProvider()`. */
  provider?: LlmProvider;
  maxFindings?: number;
  contextLines?: number;
}

const DEFAULT_MAX_FINDINGS = 25;
const DEFAULT_CONTEXT_LINES = 15;
/** Snippet radius (lines each side) attached to new LLM findings. */
const NEW_FINDING_SNIPPET_RADIUS = 5;
const MAX_RAW_OUTPUT_CHARS = 400;

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

interface LlmNewFinding {
  line: number;
  severity: Severity;
  message: string;
  remediation?: string;
}

interface LlmVerdict {
  verdict: "confirm" | "dismiss";
  reason: string;
  newFindings: LlmNewFinding[];
}

interface CodeWindow {
  /** 1-based line number of the first line in `lines`. */
  startLine: number;
  lines: string[];
}

export class AttackAgent {
  private readonly provider: LlmProvider;
  private readonly maxFindings: number;
  private readonly contextLines: number;

  constructor(opts: AttackAgentOptions) {
    if (!opts.provider) {
      throw new Error("AttackAgent requires a provider");
    }
    this.provider = opts.provider;
    this.maxFindings = opts.maxFindings ?? DEFAULT_MAX_FINDINGS;
    this.contextLines = opts.contextLines ?? DEFAULT_CONTEXT_LINES;
  }

  async analyze(
    findings: Finding[],
    readFile: (path: string) => Promise<string>,
  ): Promise<AttackAgentResult> {
    // Only high/medium go to the LLM; highest severity first, capped at maxFindings.
    const candidates = findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => finding.severity === "high" || finding.severity === "medium")
      .sort(
        (a, b) =>
          SEVERITY_RANK[a.finding.severity] - SEVERITY_RANK[b.finding.severity] ||
          a.index - b.index,
      )
      .slice(0, Math.max(0, this.maxFindings));
    const analyzedIndexes = new Set(candidates.map((c) => c.index));

    const fileCache = new Map<string, string[] | null>();
    const readLines = async (path: string): Promise<string[] | null> => {
      if (fileCache.has(path)) return fileCache.get(path) ?? null;
      try {
        const lines = (await readFile(path)).split("\n");
        fileCache.set(path, lines);
        return lines;
      } catch {
        fileCache.set(path, null);
        return null;
      }
    };

    const outFindings: Finding[] = [];
    const dismissed: DismissedFinding[] = [];
    const notices: string[] = [];

    // Sequential: one prompt per finding, to be kind to rate limits.
    for (let i = 0; i < findings.length; i++) {
      const finding = findings[i];
      if (!analyzedIndexes.has(i)) {
        outFindings.push(finding); // below threshold or beyond the cap: untouched
        continue;
      }
      const lines = await readLines(finding.file);
      if (!lines) {
        notices.push(
          `could not read ${finding.file}; kept static finding ${finding.ruleId} as-is`,
        );
        outFindings.push(finding);
        continue;
      }
      const context = windowedLines(lines, finding.line, this.contextLines);
      let parsed: { verdict: LlmVerdict; note?: string };
      try {
        const raw = await this.provider.complete(buildPrompt(finding, context));
        parsed = parseVerdict(raw, finding);
      } catch (err) {
        notices.push(
          `LLM call failed for ${finding.file}:${finding.line} (${err instanceof Error ? err.message : String(err)}); kept static finding ${finding.ruleId} as-is`,
        );
        outFindings.push(finding);
        continue;
      }
      if (parsed.note) notices.push(parsed.note);
      if (parsed.verdict.verdict === "dismiss") {
        dismissed.push({
          ruleId: finding.ruleId,
          file: finding.file,
          line: finding.line,
          reason: parsed.verdict.reason,
        });
      } else {
        outFindings.push(finding);
      }
      for (const nf of parsed.verdict.newFindings) {
        outFindings.push(toFinding(nf, finding.file, lines));
      }
    }

    const result: AttackAgentResult = { findings: outFindings, dismissed };
    if (notices.length > 0) result.notice = notices.join("\n");
    return result;
  }
}

/**
 * Zero-config entry point: no API key → skip the LLM stage with a one-line
 * notice and return the static findings unchanged. Never throws for the
 * no-provider case.
 */
export async function maybeAttack(
  findings: Finding[],
  readFile: (path: string) => Promise<string>,
  opts: MaybeAttackOptions = {},
): Promise<AttackAgentResult> {
  const provider = opts.provider ?? resolveProvider();
  if (!provider) {
    return {
      findings,
      dismissed: [],
      notice:
        "LLM attack-agent skipped: no API key (set ANTHROPIC_API_KEY or OPENAI_API_KEY); static results unaffected.",
    };
  }
  return new AttackAgent({
    provider,
    maxFindings: opts.maxFindings,
    contextLines: opts.contextLines,
  }).analyze(findings, readFile);
}

function windowedLines(all: string[], centerLine: number, radius: number): CodeWindow {
  const startLine = Math.max(1, centerLine - radius);
  const endLine = Math.min(all.length, centerLine + radius);
  return { startLine, lines: all.slice(startLine - 1, endLine) };
}

function buildPrompt(finding: Finding, context: CodeWindow): string {
  const numbered = context.lines
    .map((text, i) => `${context.startLine + i}: ${text}`)
    .join("\n");
  const remediationLine = finding.remediation
    ? `\n- static rule's suggested fix: ${finding.remediation}`
    : "";
  return `You are an adversarial security reviewer. A static analysis scanner flagged a potential vulnerability in the code below. You have two jobs:

1. VERDICT — Decide whether the flagged issue is a REAL vulnerability ("confirm") or a FALSE POSITIVE ("dismiss"). False positives are common: dead code, test fixtures, properly validated input, safe wrappers, or preconditions that cannot actually occur. Give a one- or two-sentence reason either way.

2. HUNT — Independently look for logic flaws the syntactic scanner likely missed: authentication/authorization bypass, IDOR / missing ownership checks, insecure defaults, race conditions / TOCTOU, cryptographic misuse, SSRF, command/SQL/LDAP injection, sensitive data exposure. Report each NEW issue you find. Do NOT re-report the flagged issue itself as a new finding; if you find nothing new, use an empty array.

Flagged finding:
- rule: ${finding.ruleId} (severity: ${finding.severity})
- location: ${finding.file}:${finding.line}:${finding.col}
- message: ${finding.message}${remediationLine}

Code under review (line numbers are absolute file line numbers):
${numbered}

Reply with ONLY one JSON object — no markdown fences, no commentary — in exactly this shape:
{
  "verdict": "confirm",
  "reason": "why you confirmed or dismissed the flagged issue, in one or two sentences",
  "newFindings": [
    {
      "line": 42,
      "severity": "high",
      "message": "what is wrong and why it is exploitable",
      "remediation": "how to fix it"
    }
  ]
}

Rules for the JSON:
- "verdict" must be exactly "confirm" or "dismiss".
- "reason" must be a non-empty string.
- "newFindings" entries must use ABSOLUTE line numbers from the code above; "severity" must be one of "critical", "high", "medium", "low".`;
}

/** Find the first {...} block that parses as a JSON object (tolerates preamble/postamble). */
function extractJsonObject(raw: string): { ok: true; value: unknown } | { ok: false } {
  const lastBrace = raw.lastIndexOf("}");
  if (lastBrace === -1) return { ok: false };
  let open = raw.indexOf("{");
  while (open !== -1 && open < lastBrace) {
    try {
      const value: unknown = JSON.parse(raw.slice(open, lastBrace + 1));
      if (typeof value === "object" && value !== null) {
        return { ok: true, value };
      }
    } catch {
      // try the next opening brace
    }
    open = raw.indexOf("{", open + 1);
  }
  return { ok: false };
}

function normalizeSeverity(input: unknown): Severity {
  const s = typeof input === "string" ? input.toLowerCase().trim() : "";
  if (s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info") {
    return s;
  }
  return "medium";
}

function normalizeNewFindings(input: unknown): LlmNewFinding[] {
  if (!Array.isArray(input)) return [];
  const out: LlmNewFinding[] = [];
  for (const item of input) {
    if (typeof item !== "object" || item === null) continue;
    const rec = item as Record<string, unknown>;
    const message = typeof rec.message === "string" ? rec.message.trim() : "";
    if (!message) continue;
    const line =
      typeof rec.line === "number" && Number.isInteger(rec.line) && rec.line > 0
        ? rec.line
        : null;
    if (line === null) continue;
    const remediation =
      typeof rec.remediation === "string" && rec.remediation.trim()
        ? rec.remediation.trim()
        : undefined;
    out.push({ line, severity: normalizeSeverity(rec.severity), message, remediation });
  }
  return out;
}

function keepStatic(finding: Finding, raw: string): { verdict: LlmVerdict; note: string } {
  const truncated =
    raw.length > MAX_RAW_OUTPUT_CHARS ? raw.slice(0, MAX_RAW_OUTPUT_CHARS) + "…" : raw;
  return {
    verdict: { verdict: "confirm", reason: "(unparseable LLM output)", newFindings: [] },
    note:
      `LLM output for ${finding.file}:${finding.line} was not valid JSON; ` +
      `kept static finding ${finding.ruleId} as-is. Raw output (truncated): ${truncated}`,
  };
}

function parseVerdict(
  raw: string,
  finding: Finding,
): { verdict: LlmVerdict; note?: string } {
  const extracted = extractJsonObject(raw);
  if (!extracted.ok) return keepStatic(finding, raw);
  const rec = extracted.value as Record<string, unknown>;
  const reason =
    typeof rec.reason === "string" && rec.reason.trim() ? rec.reason.trim() : "(no reason given)";
  return {
    verdict: {
      verdict: rec.verdict === "dismiss" ? "dismiss" : "confirm",
      reason,
      newFindings: normalizeNewFindings(rec.newFindings),
    },
  };
}

function slugify(message: string): string {
  const words = message
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .slice(0, 5);
  return `llm-${words.join("-") || "issue"}`;
}

function toFinding(nf: LlmNewFinding, file: string, lines: string[]): Finding {
  const line = Math.min(Math.max(nf.line, 1), Math.max(lines.length, 1));
  const window = windowedLines(lines, line, NEW_FINDING_SNIPPET_RADIUS);
  const finding: Finding = {
    ruleId: slugify(nf.message),
    severity: nf.severity,
    file,
    line,
    col: 1,
    endLine: window.startLine + window.lines.length - 1,
    message: nf.message,
    snippet: window.lines.join("\n"),
    source: "llm",
  };
  if (nf.remediation) finding.remediation = nf.remediation;
  return finding;
}
