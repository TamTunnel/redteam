import type { Finding } from "../../src/findings.js";

/** Fixed finding set shared by the reporter golden tests. */
export function sampleFindings(): Finding[] {
  return [
    {
      ruleId: "sec-aws-key",
      severity: "medium",
      file: "src/config.js",
      line: 12,
      col: 15,
      message: "AWS access key ID committed to source",
      snippet: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      remediation: "Remove the credential from the repo and rotate it in IAM.",
      source: "text",
    },
    {
      ruleId: "js-eval-injection",
      severity: "high",
      file: "src/app.js",
      line: 42,
      col: 5,
      endLine: 42,
      message: "eval() with non-constant input enables code injection",
      snippet: "eval(userInput);",
      remediation: "Use JSON.parse or a constrained parser.",
      source: "ast",
    },
    {
      ruleId: "llm-missing-auth-check",
      severity: "high",
      file: "src/routes.js",
      line: 7,
      col: 1,
      message: "Route handler performs a privileged action without an auth check",
      snippet: "app.post('/admin/reset', (req, res) => { resetAll(); });",
      remediation: "Add authentication and authorization middleware.",
      source: "llm",
    },
    {
      ruleId: "sec-private-key",
      severity: "medium",
      file: "src/config.js",
      line: 30,
      col: 1,
      message: "Private key material committed to source",
      snippet: "-----BEGIN RSA PRIVATE KEY-----",
      remediation: "Remove the key from the repo and rotate it.",
      source: "text",
    },
    {
      ruleId: "info-note",
      severity: "info",
      file: "src/notes.js",
      line: 1,
      col: 1,
      message: "Informational note",
      snippet: "// nothing here",
      source: "ast",
    },
  ];
}
