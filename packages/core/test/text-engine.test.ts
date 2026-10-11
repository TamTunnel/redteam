import { readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../src/rules/builtin/index.js";
import { TextEngine } from "../src/engines/text-engine.js";
import { languageForExtension } from "../src/engines/types.js";
import type { Finding } from "../src/findings.js";

const here = dirname(fileURLToPath(import.meta.url));
// Note: task spec said ../../../../testdata; the testdata dir lives at the
// repo root, which is ../../../ from packages/core/test.
const TESTDATA = join(here, "..", "..", "..", "testdata");

function scanFixture(ruleId: string, name: string): Finding[] {
  const content = readFileSync(join(TESTDATA, ruleId, name), "utf8");
  const engine = new TextEngine();
  return engine.scan({
    path: `testdata/${ruleId}/${name}`,
    content,
    language: languageForExtension(extname(name)),
  });
}

const RULE_IDS = [
  "sec-aws-key",
  "sec-private-key",
  "sec-generic-api-key",
  "sec-high-entropy-string",
] as const;

describe.each(RULE_IDS)("text rule %s", (ruleId) => {
  it("fires on its vulnerable fixture", () => {
    const findings = scanFixture(ruleId, "vulnerable.txt").filter((f) => f.ruleId === ruleId);
    expect(findings.length).toBeGreaterThanOrEqual(1);
    for (const f of findings) {
      expect(f.line).toBeGreaterThanOrEqual(1);
      expect(f.col).toBeGreaterThanOrEqual(1);
      expect(f.snippet.length).toBeGreaterThan(0);
      expect(f.snippet.length).toBeLessThanOrEqual(200);
      expect(f.source).toBe("text");
      expect(f.severity).toBeDefined();
    }
  });

  it("is silent on its fixed fixture", () => {
    const findings = scanFixture(ruleId, "fixed.txt").filter((f) => f.ruleId === ruleId);
    expect(findings).toEqual([]);
  });
});

describe("TextEngine line/col computation", () => {
  it("reports correct 1-based line and column", () => {
    const engine = new TextEngine();
    const content = 'harmless = "x"\napi_key = "sk-4f8d2c9a1b7e5f3d9a2c"\n';
    const findings = engine
      .scan({ path: "t.txt", content, language: "unknown" })
      .filter((f) => f.ruleId === "sec-generic-api-key");
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(2);
    expect(findings[0].col).toBe(1);
    expect(findings[0].snippet).toContain("api_key");
  });

  it("handles matches on the first line", () => {
    const engine = new TextEngine();
    const content = '-----BEGIN RSA PRIVATE KEY-----\nfake\n';
    const findings = engine
      .scan({ path: "k.txt", content, language: "unknown" })
      .filter((f) => f.ruleId === "sec-private-key");
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(1);
    expect(findings[0].col).toBe(1);
  });
});
