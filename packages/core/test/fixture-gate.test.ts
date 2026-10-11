/**
 * Fixture gate (ARCHITECTURE.md §5): every registered rule with a
 * testdata/<rule-id>/ directory must fire on each of its vulnerable.*
 * fixtures and stay silent on each of its fixed.* fixtures.
 *
 * The AST agent extends this gate by adding its engine to enginesForGate()
 * — the gate itself needs no other changes.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import "../src/rules/builtin/index.js";
import { registry } from "../src/rules/registry.js";
import { TextEngine } from "../src/engines/text-engine.js";
import { AstEngine } from "../src/engines/ast-engine.js";
import { languageForExtension } from "../src/engines/types.js";
import type { Engine } from "../src/engines/types.js";
import type { Finding } from "../src/findings.js";

const here = dirname(fileURLToPath(import.meta.url));
const TESTDATA = join(here, "..", "..", "..", "testdata");

/** Engines under test. AST agent: append your engine here. */
export function enginesForGate(): Engine[] {
  return [new TextEngine(), new AstEngine()];
}

async function scanAll(engines: Engine[], path: string, content: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const e of engines) {
    out.push(
      ...(await e.scan({ path, content, language: languageForExtension(extname(path)) })),
    );
  }
  return out;
}

describe("fixture gate", () => {
  const gated = registry.list().filter((r) => existsSync(join(TESTDATA, r.id)));

  it("covers at least one registered rule", () => {
    expect(gated.length).toBeGreaterThan(0);
  });

  for (const rule of gated) {
    describe(`rule ${rule.id}`, () => {
      const dir = join(TESTDATA, rule.id);
      const files = readdirSync(dir);
      const vulnerable = files.filter((f) => f.startsWith("vulnerable."));
      const fixed = files.filter((f) => f.startsWith("fixed."));

      it("ships vulnerable.* and fixed.* fixtures", () => {
        expect(vulnerable.length).toBeGreaterThan(0);
        expect(fixed.length).toBeGreaterThan(0);
      });

      for (const name of vulnerable) {
        it(`${name} triggers ${rule.id}`, async () => {
          const content = readFileSync(join(dir, name), "utf8");
          const findings = (await scanAll(enginesForGate(), `${rule.id}/${name}`, content)).filter(
            (f) => f.ruleId === rule.id,
          );
          expect(findings.length).toBeGreaterThanOrEqual(1);
        });
      }

      for (const name of fixed) {
        it(`${name} does not trigger ${rule.id}`, async () => {
          const content = readFileSync(join(dir, name), "utf8");
          const findings = (await scanAll(enginesForGate(), `${rule.id}/${name}`, content)).filter(
            (f) => f.ruleId === rule.id,
          );
          expect(findings).toEqual([]);
        });
      }
    });
  }
});
