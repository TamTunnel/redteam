import { createRequire } from "node:module";
import { SEVERITY_ORDER, type Finding, type Severity } from "../findings.js";

const require = createRequire(import.meta.url);

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#d73a49",
  high: "#e36209",
  medium: "#b08800",
  low: "#0366d6",
  info: "#6a737d",
};

export interface HtmlReportOptions {
  /** Directory that was scanned (shown in the summary header). */
  dir?: string;
  /** ISO timestamp; defaults to now. */
  generatedAt?: string;
  /** Tool version; defaults to the @tamtunnel/redteam-core package version. */
  version?: string;
}

function toolVersion(): string {
  try {
    const pkg = require("../../package.json") as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

/**
 * Escape every HTML-significant character. All finding content (file paths,
 * rule IDs, messages, snippets, remediations) is attacker-influenced source
 * text, so everything injected into the document goes through here.
 */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const CSS = `
:root { color-scheme: light dark; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 0; padding: 0 0 3rem; background: #ffffff; color: #24292e; line-height: 1.5; }
@media (prefers-color-scheme: dark) { body { background: #0d1117; color: #c9d1d9; } }
header { padding: 2rem 2rem 1.5rem; border-bottom: 1px solid #e1e4e8; }
@media (prefers-color-scheme: dark) { header { border-bottom-color: #30363d; } }
header h1 { margin: 0 0 0.5rem; font-size: 1.75rem; }
.summary { font-size: 1.1rem; margin: 0.25rem 0; }
.meta { color: #6a737d; font-size: 0.9rem; margin: 0.25rem 0; }
@media (prefers-color-scheme: dark) { .meta { color: #8b949e; } }
.badge { display: inline-block; padding: 0.1em 0.6em; border-radius: 2em; color: #fff; font-size: 0.85em; font-weight: 600; margin-right: 0.4em; }
.badge.rule { background: #6a737d; }
.badge.source { background: transparent; color: #6a737d; border: 1px solid #d1d5da; font-weight: 400; }
@media (prefers-color-scheme: dark) { .badge.source { color: #8b949e; border-color: #30363d; } }
section.severity { padding: 0 2rem; }
section.severity h2 { text-transform: capitalize; border-bottom: 2px solid; padding-bottom: 0.25rem; }
article.finding { border: 1px solid #e1e4e8; border-radius: 6px; padding: 1rem 1.25rem; margin: 1rem 0; }
@media (prefers-color-scheme: dark) { article.finding { border-color: #30363d; background: #161b22; } }
article.finding h3 { margin: 0 0 0.5rem; font-size: 1.05rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }
article.finding p.message { margin: 0.5rem 0; }
article.finding p.remediation { margin: 0.5rem 0 0; }
article.finding pre { background: #f6f8fa; border-radius: 6px; padding: 0.75rem 1rem; overflow-x: auto; font-size: 0.85rem; }
@media (prefers-color-scheme: dark) { article.finding pre { background: #0d1117; } }
article.finding pre code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.empty { padding: 2rem; font-size: 1.1rem; }
footer { padding: 1.5rem 2rem 0; color: #6a737d; font-size: 0.85rem; }
@media (prefers-color-scheme: dark) { footer { color: #8b949e; } }
`.trim();

/**
 * HTML reporter: a single self-contained HTML file (inline CSS, zero
 * external dependencies) that renders correctly opened from disk or hosted
 * on GitHub Pages. Findings are grouped by severity, critical first.
 */
export function render(findings: Finding[], opts: HtmlReportOptions = {}): string {
  const version = opts.version ?? toolVersion();
  const generatedAt = opts.generatedAt ?? new Date().toISOString();
  const dir = opts.dir;

  const counts = new Map<Severity, number>();
  for (const s of SEVERITIES) counts.set(s, 0);
  for (const f of findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const parts = SEVERITIES.filter((s) => (counts.get(s) ?? 0) > 0).map(
    (s) => `${counts.get(s)} ${s}`,
  );
  const summaryText =
    findings.length === 0
      ? "No findings."
      : `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${parts.join(", ")}.`;

  const sorted = [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  const out: string[] = [
    "<!DOCTYPE html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>Redteam report</title>",
    `<style>${CSS}</style>`,
    "</head>",
    "<body>",
    "<header>",
    "<h1>Redteam report</h1>",
    `<p class="summary">${escapeHtml(summaryText)}</p>`,
  ];
  if (dir !== undefined) {
    out.push(`<p class="meta">Scanned: <code>${escapeHtml(dir)}</code></p>`);
  }
  out.push(
    `<p class="meta">Generated ${escapeHtml(generatedAt)} · redteam v${escapeHtml(version)}</p>`,
    "</header>",
  );

  if (findings.length === 0) {
    out.push('<p class="empty">The scan completed and found no issues.</p>');
  } else {
    for (const severity of SEVERITIES) {
      const group = sorted.filter((f) => f.severity === severity);
      if (group.length === 0) continue;
      const color = SEVERITY_COLORS[severity];
      out.push(
        `<section class="severity">`,
        `<h2 style="border-color: ${color}"><span class="badge" style="background: ${color}">${escapeHtml(severity)}</span> ${group.length} finding${group.length === 1 ? "" : "s"}</h2>`,
      );
      for (const f of group) {
        out.push(
          `<article class="finding">`,
          `<h3>${escapeHtml(f.file)}:${f.line}</h3>`,
          `<p><span class="badge rule">${escapeHtml(f.ruleId)}</span>` +
            `<span class="badge source">source: ${escapeHtml(f.source)}</span></p>`,
          `<p class="message">${escapeHtml(f.message)}</p>`,
        );
        if (f.snippet) {
          out.push(`<pre><code>${escapeHtml(f.snippet)}</code></pre>`);
        }
        if (f.remediation) {
          out.push(
            `<p class="remediation"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>`,
          );
        }
        out.push(`</article>`);
      }
      out.push(`</section>`);
    }
  }

  out.push(
    `<footer>Generated by <a href="https://github.com/TamTunnel/redteam">redteam</a> v${escapeHtml(version)}.</footer>`,
    "</body>",
    "</html>",
    "",
  );
  return out.join("\n");
}
