import { SEVERITY_ORDER, type Severity } from "../findings.js";

export interface TextPattern {
  pattern: RegExp;
  message?: string;
}

/**
 * Shannon-entropy scan over quoted string literals.
 * The text engine extracts string literals with at least `minLength` characters
 * and flags those whose entropy is >= `threshold`.
 */
export interface EntropyScan {
  minLength: number;
  threshold: number;
  message?: string;
}

export interface Rule {
  /** e.g. "sec-hardcoded-secret". Must match /^[a-z0-9-]+$/. */
  id: string;
  /**
   * Static rules CAP AT "medium" per severity discipline (ARCHITECTURE.md §5):
   * purely syntactic matches are medium at most unless corroborated.
   */
  severity: Severity;
  /** Subset of "javascript" | "typescript" | "python". */
  languages: string[];
  /** tree-sitter S-expressions per language (consumed by the AST engine). */
  queries?: Partial<Record<"javascript" | "typescript" | "python", string>>;
  /** Raw-text regexes (consumed by the text engine). */
  textPatterns?: TextPattern[];
  /** Shannon-entropy string scan (consumed by the text engine). */
  entropyScan?: EntropyScan;
  message: string;
  remediation: string;
  /**
   * Optional precision valve: tested against the `@arg` capture's source
   * text (falls back to the primary `@node` text when the query has no
   * `@arg`). If it matches, the finding is suppressed — use for
   * sanitizer/constant awareness (e.g. allowlisted identifiers, escaped
   * values). Keep patterns narrow; over-suppression is a recall bug.
   */
  suppressionPattern?: RegExp;
  /**
   * Set to true for high-precision findings that are corroborated by their
   * very nature (e.g. a hardcoded AWS key matching the full AKIA pattern) —
   * these may use severity "high". Purely syntactic matches stay capped at
   * "medium" to keep `--fail-on high` usable.
   */
  corroborated?: boolean;
}

const ID_RE = /^[a-z0-9-]+$/;

/**
 * Validate a rule definition and return it unchanged.
 * Throws on malformed ids and on severity above the static-rule cap ("medium").
 */
export function defineRule(r: Rule): Rule {
  if (!ID_RE.test(r.id)) {
    throw new Error(`Invalid rule id "${r.id}": must match ${ID_RE}`);
  }
  if (SEVERITY_ORDER[r.severity] > SEVERITY_ORDER.medium && !r.corroborated) {
    throw new Error(
      `Rule "${r.id}" has severity "${r.severity}", exceeding the static-rule cap of "medium" (severity discipline) — set corroborated: true only for high-precision findings`,
    );
  }
  return r;
}

export class RuleRegistry {
  private readonly rules = new Map<string, Rule>();

  /** Register a rule. Throws on duplicate id. */
  register(rule: Rule): void {
    if (this.rules.has(rule.id)) {
      throw new Error(`Duplicate rule id: "${rule.id}"`);
    }
    this.rules.set(rule.id, rule);
  }

  list(): Rule[] {
    return [...this.rules.values()];
  }

  byLanguage(lang: string): Rule[] {
    return this.list().filter((r) => r.languages.includes(lang));
  }

  get(id: string): Rule | undefined {
    return this.rules.get(id);
  }
}

export const registry = new RuleRegistry();
