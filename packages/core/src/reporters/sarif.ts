import { createRequire } from "node:module";
import type { Finding } from "../findings.js";

const TOOL_NAME = "redteam";
const TOOL_VERSION = (() => {
  try {
    const require = createRequire(import.meta.url);
    return (require("../../package.json") as { version?: string }).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();
const TOOL_URI = "https://github.com/TamTunnel/redteam";

type SarifLevel = "error" | "warning" | "note";

function levelFor(f: Finding): SarifLevel {
  if (f.severity === "critical" || f.severity === "high") return "error";
  if (f.severity === "medium") return "warning";
  return "note";
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  help: { text: string };
}

/**
 * SARIF 2.1.0 reporter (hand-rolled, validated against the official schema
 * in tests). Rules are deduped by ruleId; results carry file, line, column
 * and the rule's origin (ast/text/llm) in properties.
 */
export function render(findings: Finding[]): string {
  const ruleById = new Map<string, SarifRule>();
  for (const f of findings) {
    if (ruleById.has(f.ruleId)) continue;
    ruleById.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: f.message },
      help: { text: f.remediation ?? f.message },
    });
  }

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: levelFor(f),
    message: { text: f.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.file },
          region: {
            startLine: f.line,
            startColumn: f.col,
            endLine: f.endLine ?? f.line,
          },
        },
      },
    ],
    properties: { source: f.source },
  }));

  const sarif = {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: TOOL_URI,
            rules: [...ruleById.values()],
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
