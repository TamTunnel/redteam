import { describe, expect, it } from "vitest";
import { render } from "../../src/reporters/json.js";
import { sampleFindings } from "./fixtures.js";

describe("json reporter", () => {
  it("renders a parseable report with version, generatedAt, summary, findings", () => {
    const out = render(sampleFindings());
    const parsed = JSON.parse(out) as {
      version: string;
      generatedAt: string;
      summary: Record<string, number>;
      findings: unknown[];
    };
    expect(parsed.version).toBe("1.0.0");
    expect(typeof parsed.generatedAt).toBe("string");
    expect(Number.isNaN(Date.parse(parsed.generatedAt))).toBe(false);
    expect(parsed.summary).toEqual({
      critical: 0,
      high: 2,
      medium: 2,
      low: 0,
      info: 1,
    });
    expect(parsed.findings).toHaveLength(5);
  });

  it("renders an empty summary for zero findings", () => {
    const parsed = JSON.parse(render([])) as { summary: Record<string, number> };
    expect(parsed.summary).toEqual({
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    });
  });
});
