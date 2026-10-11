import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { escapeHtml, render } from "../../src/reporters/html.js";
import { sampleFindings } from "./fixtures.js";
import type { Finding } from "../../src/findings.js";

const here = dirname(fileURLToPath(import.meta.url));
const corePkg = JSON.parse(
  readFileSync(join(here, "../../package.json"), "utf8"),
) as { version: string };

describe("html reporter", () => {
  it("produces a valid self-contained HTML document", () => {
    const out = render(sampleFindings());
    expect(out.startsWith("<!DOCTYPE html>")).toBe(true);
    expect(out).toContain('<html lang="en">');
    expect(out).toContain("<head>");
    expect(out).toContain('<meta charset="utf-8">');
    expect(out).toContain("<title>Redteam report</title>");
    expect(out).toContain("<style>");
    expect(out).toContain("</body>");
    expect(out).toContain("</html>");
    // zero external dependencies: no <script src>, no <link rel=stylesheet>
    expect(out).not.toContain("<script");
    expect(out).not.toMatch(/<link[^>]*stylesheet/);
  });

  it("renders the summary header with counts, dir, timestamp, and version", () => {
    const out = render(sampleFindings(), { dir: "/repo/src", generatedAt: "2026-10-10T00:00:00.000Z" });
    expect(out).toContain("5 findings: 2 high, 2 medium, 1 info.");
    expect(out).toContain("Scanned:");
    expect(out).toContain("/repo/src");
    expect(out).toContain("2026-10-10T00:00:00.000Z");
    // version read from @tamtunnel/redteam-core package.json
    expect(out).toContain(`redteam v${corePkg.version}`);
  });

  it("groups findings by severity, critical first", () => {
    const out = render(sampleFindings());
    const highIdx = out.indexOf(">high<");
    const mediumIdx = out.indexOf(">medium<");
    const infoIdx = out.indexOf(">info<");
    expect(highIdx).toBeGreaterThan(-1);
    expect(mediumIdx).toBeGreaterThan(-1);
    expect(infoIdx).toBeGreaterThan(-1);
    expect(highIdx).toBeLessThan(mediumIdx);
    expect(mediumIdx).toBeLessThan(infoIdx);
  });

  it("renders each finding with file:line, rule id, message, snippet, remediation", () => {
    const out = render(sampleFindings());
    expect(out).toContain("src/app.js:42");
    expect(out).toContain("js-eval-injection");
    expect(out).toContain("eval() with non-constant input enables code injection");
    expect(out).toContain("<pre><code>eval(userInput);</code></pre>");
    expect(out).toContain("Use JSON.parse or a constrained parser.");
    expect(out).toContain("source: ast");
  });

  it("escapes HTML entities in all injected content", () => {
    const evil: Finding = {
      ruleId: 'sec-xss"><script>alert(1)</script>',
      severity: "high",
      file: 'src/<img src=x onerror=alert(1)>.js',
      line: 1,
      col: 1,
      message: "Message with <b>tags</b> & \"quotes\"",
      snippet: "<script>alert(document.cookie)</script>",
      remediation: "Fix it & don't <blink>.",
      source: "ast",
    };
    const out = render([evil]);
    // raw attacker-controlled markup must not appear
    expect(out).not.toContain("<script>alert(1)</script>");
    expect(out).not.toContain("<script>alert(document.cookie)</script>");
    expect(out).not.toContain("<img src=x");
    expect(out).not.toContain("<b>tags</b>");
    // escaped forms must appear
    expect(out).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(out).toContain("&lt;script&gt;alert(document.cookie)&lt;/script&gt;");
    expect(out).toContain("&lt;img src=x onerror=alert(1)&gt;.js");
    expect(out).toContain("&lt;b&gt;tags&lt;/b&gt; &amp; &quot;quotes&quot;");
    expect(out).toContain("Fix it &amp; don&#39;t &lt;blink&gt;.");
  });

  it("renders zero findings with a clean empty state", () => {
    const out = render([]);
    expect(out).toContain("<title>Redteam report</title>");
    expect(out).toContain("No findings.");
    expect(out).toContain("The scan completed and found no issues.");
    expect(out).not.toContain("<article");
  });

  it("omits the scanned-dir line when no dir is given", () => {
    const out = render(sampleFindings());
    expect(out).not.toContain("Scanned:");
  });
});

describe("escapeHtml", () => {
  it("escapes &, <, >, quotes", () => {
    expect(escapeHtml(`<a href="x">&'y'</a>`)).toBe(
      "&lt;a href=&quot;x&quot;&gt;&amp;&#39;y&#39;&lt;/a&gt;",
    );
  });

  it("leaves plain text untouched", () => {
    expect(escapeHtml("hello world 123")).toBe("hello world 123");
  });
});
