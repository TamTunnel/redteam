import type { Finding } from "../findings.js";

export interface ScannedFile {
  /** Repo-relative path. */
  path: string;
  content: string;
  /** "javascript" | "typescript" | "python" | "unknown" */
  language: string;
}

export interface Engine {
  name: "ast" | "text";
  scan(file: ScannedFile): Promise<Finding[]> | Finding[];
}

/**
 * Map a file extension (with leading dot) to a language name.
 * Unknown extensions → "unknown".
 */
export function languageForExtension(ext: string): string {
  switch (ext.toLowerCase()) {
    case ".js":
    case ".jsx":
    case ".mjs":
    case ".cjs":
      return "javascript";
    case ".ts":
    case ".tsx":
    case ".mts":
    case ".cts":
      return "typescript";
    case ".py":
      return "python";
    default:
      return "unknown";
  }
}
