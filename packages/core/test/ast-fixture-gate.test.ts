/**
 * AST fixture gate (ARCHITECTURE.md §5): every AST built-in rule must fire on
 * each of its vulnerable.* fixtures and stay silent on each of its fixed.*
 * fixtures. Runs the real AstEngine end to end (parse → compiled queries →
 * findings). Plus engine unit tests (unknown language, broken input, query
 * cache, dispose).
 */
import { existsSync, readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
// Importing the rule modules self-registers them (do NOT import
// rules/builtin/index.js here — wiring that is the integrator's job).
import "../src/rules/builtin/sec-child-process.js";
import "../src/rules/builtin/sec-command-injection.js";
import "../src/rules/builtin/sec-eval.js";
import "../src/rules/builtin/sec-insecure-random.js";
import "../src/rules/builtin/sec-open-redirect.js";
import "../src/rules/builtin/sec-path-traversal.js";
import "../src/rules/builtin/sec-regex-dos.js";
import "../src/rules/builtin/sec-sql-injection.js";
import "../src/rules/builtin/sec-ssrf.js";
import "../src/rules/builtin/sec-weak-crypto.js";
import "../src/rules/builtin/sec-xss.js";
import "../src/rules/builtin/sec-xxe.js";
import { registry } from "../src/rules/registry.js";
import { AstEngine } from "../src/engines/ast-engine.js";
import { languageForExtension } from "../src/engines/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const TESTDATA = join(here, "..", "..", "..", "testdata");

const AST_RULE_IDS = [
  "sec-eval",
  "sec-child-process",
  "sec-command-injection",
  "sec-sql-injection",
  "sec-xss",
  "sec-ssrf",
  "sec-path-traversal",
  "sec-weak-crypto",
  "sec-insecure-random",
  "sec-open-redirect",
  "sec-xxe",
  "sec-regex-dos",
];

const EXT_FOR_LANG: Record<string, string> = {
  javascript: ".js",
  typescript: ".ts",
  python: ".py",
};

function scanFixture(engine: AstEngine, ruleId: string, name: string): Promise<ReturnType<AstEngine["scan"]>> {
  const content = readFileSync(join(TESTDATA, ruleId, name), "utf8");
  return engine.scan({
    path: `${ruleId}/${name}`,
    content,
    language: languageForExtension(extname(name)),
  });
}

describe("ast fixture gate", () => {
  const engine = new AstEngine();

  it("registers all 12 AST rules with per-language queries", () => {
    for (const id of AST_RULE_IDS) {
      const rule = registry.get(id);
      expect(rule, `rule ${id} registered`).toBeDefined();
      for (const lang of rule!.languages) {
        expect(rule!.queries?.[lang as "javascript" | "typescript" | "python"], `${id} has query for ${lang}`).toBeTruthy();
      }
      expect(existsSync(join(TESTDATA, id)), `testdata/${id} exists`).toBe(true);
    }
  });

  for (const ruleId of AST_RULE_IDS) {
    describe(`rule ${ruleId}`, () => {
      const rule = registry.get(ruleId)!;
      for (const lang of rule.languages) {
        const ext = EXT_FOR_LANG[lang];
        it(`${lang}: vulnerable${ext} triggers ${ruleId}`, async () => {
          const findings = (await scanFixture(engine, ruleId, `vulnerable${ext}`)).filter(
            (f) => f.ruleId === ruleId,
          );
          expect(findings.length).toBeGreaterThanOrEqual(1);
          for (const f of findings) {
            expect(f.source).toBe("ast");
            expect(f.severity).toBe(rule.severity);
            expect(f.line).toBeGreaterThanOrEqual(1);
            expect(f.snippet.length).toBeGreaterThan(0);
          }
        });

        it(`${lang}: fixed${ext} does not trigger ${ruleId}`, async () => {
          const findings = (await scanFixture(engine, ruleId, `fixed${ext}`)).filter(
            (f) => f.ruleId === ruleId,
          );
          expect(findings).toEqual([]);
        });
      }
    });
  }
});

describe("AstEngine", () => {
  it("returns [] for unknown language without throwing", async () => {
    const engine = new AstEngine();
    const findings = await engine.scan({
      path: "notes.txt",
      content: "eval(anything)",
      language: "unknown",
    });
    expect(findings).toEqual([]);
    engine.dispose();
  });

  it("returns [] (no throw) on syntactically broken input", async () => {
    const engine = new AstEngine();
    const findings = await engine.scan({
      path: "broken.js",
      // Unparseable: error nodes only, nothing a query can match.
      content: "const = = = ;;; ((( ;;;",
      language: "javascript",
    });
    expect(findings).toEqual([]);
    engine.dispose();
  });

  it("query cache: repeated scans give identical findings", async () => {
    const engine = new AstEngine();
    const file = {
      path: "sec-eval/vulnerable.js",
      content: readFileSync(join(TESTDATA, "sec-eval", "vulnerable.js"), "utf8"),
      language: "javascript",
    };
    const first = await engine.scan(file);
    const second = await engine.scan(file);
    expect(second).toEqual(first);
    expect(first.filter((f) => f.ruleId === "sec-eval").length).toBeGreaterThanOrEqual(1);
    engine.dispose();
  });

  it("dispose() is safe to call and the engine still scans afterwards", async () => {
    const engine = new AstEngine();
    engine.dispose();
    engine.dispose();
    const findings = await engine.scan({
      path: "x.py",
      content: "eval(user_input)\n",
      language: "python",
    });
    expect(findings.filter((f) => f.ruleId === "sec-eval").length).toBeGreaterThanOrEqual(1);
    engine.dispose();
  });

  it("finding positions are 1-based and snippets are capped", async () => {
    const engine = new AstEngine();
    const findings = await engine.scan({
      path: "x.js",
      content: "const t = 1;\nconst r = eval(input);\n",
      language: "javascript",
    });
    const hit = findings.find((f) => f.ruleId === "sec-eval")!;
    expect(hit).toBeDefined();
    expect(hit.line).toBe(2);
    expect(hit.col).toBeGreaterThanOrEqual(1);
    expect(hit.endLine).toBeGreaterThanOrEqual(hit.line);
    expect(hit.snippet.length).toBeLessThanOrEqual(200);
    engine.dispose();
  });
});
