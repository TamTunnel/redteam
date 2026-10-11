import { describe, expect, it } from "vitest";
import { defineRule, RuleRegistry } from "../src/rules/registry.js";
import type { Rule } from "../src/rules/registry.js";

function stubRule(overrides: Partial<Rule> = {}): Rule {
  return {
    id: "sec-test-rule",
    severity: "low",
    languages: ["python"],
    message: "test message",
    remediation: "test remediation",
    ...overrides,
  };
}

describe("defineRule", () => {
  it("accepts a well-formed rule and returns it unchanged", () => {
    const r = stubRule();
    expect(defineRule(r)).toBe(r);
  });

  it("rejects malformed ids", () => {
    for (const bad of ["Bad_Id", "has space", "UPPER", "sec!rule", ""]) {
      expect(() => defineRule(stubRule({ id: bad })), `id ${JSON.stringify(bad)}`).toThrow(
        /rule id/i,
      );
    }
  });

  it("rejects severity above the static-rule cap of medium", () => {
    expect(() => defineRule(stubRule({ id: "sec-too-hot", severity: "high" }))).toThrow(/medium/i);
    expect(() => defineRule(stubRule({ id: "sec-crit", severity: "critical" }))).toThrow(/medium/i);
    expect(defineRule(stubRule({ id: "sec-ok", severity: "medium" })).severity).toBe("medium");
  });
});

describe("RuleRegistry", () => {
  it("throws on duplicate id registration", () => {
    const reg = new RuleRegistry();
    reg.register(defineRule(stubRule({ id: "sec-dup" })));
    expect(() => reg.register(defineRule(stubRule({ id: "sec-dup" })))).toThrow(/duplicate/i);
  });

  it("byLanguage returns only rules declaring that language", () => {
    const reg = new RuleRegistry();
    reg.register(defineRule(stubRule({ id: "sec-js-only", languages: ["javascript"] })));
    reg.register(defineRule(stubRule({ id: "sec-py-only", languages: ["python"] })));
    reg.register(
      defineRule(stubRule({ id: "sec-both", languages: ["javascript", "python"] })),
    );
    expect(reg.byLanguage("javascript").map((r) => r.id).sort()).toEqual([
      "sec-both",
      "sec-js-only",
    ]);
    expect(reg.byLanguage("python").map((r) => r.id).sort()).toEqual([
      "sec-both",
      "sec-py-only",
    ]);
    expect(reg.byLanguage("ruby")).toEqual([]);
  });

  it("get returns the rule or undefined", () => {
    const reg = new RuleRegistry();
    const rule = defineRule(stubRule({ id: "sec-get-me" }));
    reg.register(rule);
    expect(reg.get("sec-get-me")).toBe(rule);
    expect(reg.get("sec-missing")).toBeUndefined();
  });

  it("list returns registered rules in registration order", () => {
    const reg = new RuleRegistry();
    expect(reg.list()).toEqual([]);
    reg.register(defineRule(stubRule({ id: "sec-a" })));
    reg.register(defineRule(stubRule({ id: "sec-b" })));
    expect(reg.list().map((r) => r.id)).toEqual(["sec-a", "sec-b"]);
  });
});
