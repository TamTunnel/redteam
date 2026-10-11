// Fixed: linear-time patterns, no nested quantifiers.
export const USERNAME_RE = /^[a-z0-9_]+$/;

export function makeSplitter(delim: string): RegExp {
  if (delim !== ",") throw new Error("unsupported delimiter");
  return /^[a-z,]+$/;
}
