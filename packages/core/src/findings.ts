// Core finding shape shared by every engine (ast, text, llm) and every reporter.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingSource = "ast" | "text" | "llm";

export interface Finding {
  ruleId: string;
  severity: Severity;
  /** Repo-relative path of the scanned file. */
  file: string;
  /** 1-based line number. */
  line: number;
  /** 1-based column number. */
  col: number;
  endLine?: number;
  message: string;
  /** Offending source excerpt, trimmed. */
  snippet: string;
  remediation?: string;
  source: FindingSource;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function meetsThreshold(sev: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[threshold];
}
