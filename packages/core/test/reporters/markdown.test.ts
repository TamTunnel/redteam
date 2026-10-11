import { describe, expect, it } from "vitest";
import { render } from "../../src/reporters/markdown.js";
import { sampleFindings } from "./fixtures.js";

describe("markdown reporter", () => {
  it("renders a heading, summary line, and per-severity sections", () => {
    const out = render(sampleFindings());
    expect(out).toContain("# Redteam report");
    expect(out).toContain("5 findings: 2 high, 2 medium, 1 info.");
    expect(out).toContain("## high");
    expect(out).toContain("## medium");
    expect(out).toContain("## info");
    // sections ordered critical -> info
    expect(out.indexOf("## high")).toBeLessThan(out.indexOf("## medium"));
    expect(out.indexOf("## medium")).toBeLessThan(out.indexOf("## info"));
  });

  it("renders each finding with rule id, message, fenced snippet, remediation", () => {
    const out = render(sampleFindings());
    expect(out).toContain("`src/app.js:42`");
    expect(out).toContain("`js-eval-injection`");
    expect(out).toContain("eval() with non-constant input enables code injection");
    expect(out).toContain("```\neval(userInput);\n```");
    expect(out).toContain("Use JSON.parse or a constrained parser.");
  });

  it("renders zero findings as 'No findings.' with a one-line note", () => {
    const out = render([]);
    expect(out).toContain("# Redteam report");
    expect(out).toContain("No findings.");
    expect(out).toContain("The scan completed and found no issues.");
  });
});
