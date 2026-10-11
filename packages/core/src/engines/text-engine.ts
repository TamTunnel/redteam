import type { Finding } from "../findings.js";
import { registry } from "../rules/registry.js";
import type { Engine, ScannedFile } from "./types.js";

/** Quoted string literals (single, double, backtick), single-line, ≥20 chars. */
const QUOTED_STRING_RE = /"((?:[^"\\\r\n]|\\.){20,})"|'((?:[^'\\\r\n]|\\.){20,})'|`((?:[^`\\\r\n]|\\.){20,})`/g;

function toGlobal(pattern: RegExp): RegExp {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

function offsetToLineCol(content: string, offset: number): { line: number; col: number } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < offset; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) {
      line++;
      lineStart = i + 1;
    }
  }
  return { line, col: offset - lineStart + 1 };
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Raw-text secret scanner. Pulls every registered rule that declares
 * `textPatterns` and/or `entropyScan` — language-agnostic by design.
 */
export class TextEngine implements Engine {
  readonly name = "text" as const;

  scan(file: ScannedFile): Finding[] {
    const findings: Finding[] = [];
    const lines = file.content.split(/\r?\n/);
    const rules = registry
      .list()
      .filter((r) => (r.textPatterns?.length ?? 0) > 0 || r.entropyScan !== undefined);

    for (const rule of rules) {
      for (const tp of rule.textPatterns ?? []) {
        const re = toGlobal(tp.pattern);
        let m: RegExpExecArray | null;
        while ((m = re.exec(file.content)) !== null) {
          if (m[0].length === 0) {
            re.lastIndex++;
            continue;
          }
          const { line, col } = offsetToLineCol(file.content, m.index);
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            file: file.path,
            line,
            col,
            message: tp.message ?? rule.message,
            snippet: (lines[line - 1] ?? "").trim().slice(0, 200),
            remediation: rule.remediation,
            source: "text",
          });
        }
      }

      const es = rule.entropyScan;
      if (es) {
        const re = new RegExp(QUOTED_STRING_RE.source, QUOTED_STRING_RE.flags);
        let m: RegExpExecArray | null;
        while ((m = re.exec(file.content)) !== null) {
          const inner = m[1] ?? m[2] ?? m[3] ?? "";
          if (inner.length < es.minLength) continue;
          // Natural language isn't a secret: real tokens/keys never contain
          // whitespace. This kills the test-description false positives.
          if (/\s/.test(inner)) continue;
          // Template interpolations (${…}) pollute entropy measurement —
          // a URL template is not a secret.
          if (m[3] !== undefined && inner.includes("${")) continue;
          if (shannonEntropy(inner) < es.threshold) continue;
          const { line, col } = offsetToLineCol(file.content, m.index);
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            file: file.path,
            line,
            col,
            message: es.message ?? rule.message,
            snippet: (lines[line - 1] ?? "").trim().slice(0, 200),
            remediation: rule.remediation,
            source: "text",
          });
        }
      }
    }

    return findings;
  }
}
