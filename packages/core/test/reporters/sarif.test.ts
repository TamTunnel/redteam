import { describe, expect, it } from "vitest";
import Ajv from "ajv";
import { render } from "../../src/reporters/sarif.js";
import { sampleFindings } from "./fixtures.js";
// Vendored from https://json.schemastore.org/sarif-2.1.0.json
// (mirror of https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json).
import schemaJson from "../fixtures/sarif-schema.json";

describe("sarif reporter", () => {
  it("emits SARIF 2.1.0 with deduped driver rules and one result per finding", () => {
    const parsed = JSON.parse(render(sampleFindings())) as {
      version: string;
      $schema: string;
      runs: Array<{
        tool: { driver: { name: string; version: string; informationUri: string; rules: Array<{ id: string; name: string }> } };
        results: Array<{
          ruleId: string;
          level: string;
          message: { text: string };
          locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number; startColumn: number; endLine: number } } }>;
          properties: { source: string };
        }>;
      }>;
    };
    expect(parsed.version).toBe("2.1.0");
    expect(parsed.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe("redteam");
    expect(run.tool.driver.informationUri).toBe("https://github.com/TamTunnel/redteam");
    // 5 findings, 5 distinct rule ids -> 5 driver rules, deduped
    expect(run.tool.driver.rules.map((r) => r.id).sort()).toEqual(
      ["info-note", "js-eval-injection", "llm-missing-auth-check", "sec-aws-key", "sec-private-key"].sort(),
    );
    expect(run.results).toHaveLength(5);
    const byRule = new Map(run.results.map((r) => [r.ruleId, r]));
    // severity -> level mapping
    expect(byRule.get("js-eval-injection")?.level).toBe("error");
    expect(byRule.get("sec-aws-key")?.level).toBe("warning");
    expect(byRule.get("info-note")?.level).toBe("note");
    // location shape
    const loc = byRule.get("js-eval-injection")?.locations[0].physicalLocation;
    expect(loc?.artifactLocation.uri).toBe("src/app.js");
    expect(loc?.region.startLine).toBe(42);
    expect(loc?.region.startColumn).toBe(5);
    expect(byRule.get("js-eval-injection")?.properties.source).toBe("ast");
  });

  it("dedupes driver rules when several findings share a rule id", () => {
    const findings = [...sampleFindings(), ...sampleFindings()];
    const parsed = JSON.parse(render(findings)) as {
      runs: Array<{ tool: { driver: { rules: unknown[] } }; results: unknown[] }>;
    };
    expect(parsed.runs[0].tool.driver.rules).toHaveLength(5);
    expect(parsed.runs[0].results).toHaveLength(10);
  });

  it("validates against the official SARIF 2.1.0 JSON schema", () => {
    const ajv = new Ajv({ allErrors: true, strict: false });
    const validate = ajv.compile(schemaJson);
    const valid = validate(JSON.parse(render(sampleFindings())));
    if (!valid) {
      console.error(JSON.stringify(validate.errors, null, 2));
    }
    expect(valid).toBe(true);
    // and the empty report validates too
    expect(validate(JSON.parse(render([])))).toBe(true);
  });
});
