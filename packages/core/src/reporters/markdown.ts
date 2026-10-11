import { SEVERITY_ORDER, type Finding, type Severity } from "../findings.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Fence length that can't collide with backtick runs inside the snippet:
 * one more than the longest run found.
 */
export function fenceFor(snippet: string): string {
  const runs = snippet.match(/`+/g) ?? [];
  const longest = runs.reduce((n, r) => Math.max(n, r.length), 0);
  return "`".repeat(longest + 3);
}

/** Markdown reporter: human-readable report, per-severity sections. */
export function render(findings: Finding[]): string {
  const lines: string[] = ["# Redteam report", ""];

  if (findings.length === 0) {
    lines.push("No findings.", "", "The scan completed and found no issues.");
    return lines.join("\n");
  }

  const counts = new Map<Severity, number>();
  for (const s of SEVERITIES) counts.set(s, 0);
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);

  const parts = SEVERITIES.filter((s) => (counts.get(s) ?? 0) > 0).map(
    (s) => `${counts.get(s)} ${s}`,
  );
  lines.push(
    `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${parts.join(", ")}.`,
    "",
  );

  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  for (const severity of SEVERITIES) {
    const group = sorted.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`## ${severity}`, "");
    for (const f of group) {
      lines.push(`### \`${f.file}:${f.line}\``, "");
      lines.push(`- **Rule:** \`${f.ruleId}\``);
      lines.push(`- **Severity:** ${f.severity} (source: ${f.source})`);
      lines.push(`- ${f.message}`);
      if (f.snippet) {
        lines.push("", fenceFor(f.snippet), f.snippet, fenceFor(f.snippet));
      }
      if (f.remediation) {
        lines.push("", `**Remediation:** ${f.remediation}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
