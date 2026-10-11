import type { Finding, Severity } from "../findings.js";

/** JSON reporter: machine-readable report with a per-severity summary. */
export function render(findings: Finding[]): string {
  const summary: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    summary[f.severity]++;
  }
  return JSON.stringify(
    {
      version: "1.0.0",
      generatedAt: new Date().toISOString(),
      summary,
      findings,
    },
    null,
    2,
  );
}
