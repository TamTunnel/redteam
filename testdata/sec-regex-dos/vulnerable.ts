// Vulnerable: nested quantifiers — catastrophic backtracking on crafted input.
export const CLEANUP_RE = /(a+)+$/;

export function makeSplitter(delim: string): RegExp {
  return new RegExp("(" + delim + "+)+");
}
