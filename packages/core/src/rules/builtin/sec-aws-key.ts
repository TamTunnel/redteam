// Built-in rule: AWS credentials committed to source.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-aws-key",
    severity: "high",
    corroborated: true, // AKIA-pattern / PEM-header matches are high-precision
    languages: ["javascript", "typescript", "python"],
    textPatterns: [
      {
        pattern: /\bAKIA[0-9A-Z]{16}\b/g,
        message: "AWS access key ID committed to source",
      },
      {
        // 40-char base64-ish secret adjacent to an aws_secret / secret_access_key name.
        pattern: /aws[_-]?secret(?:[_-]?access[_-]?key)?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/gi,
        message: "AWS secret access key committed to source",
      },
    ],
    message: "AWS credential committed to source",
    remediation:
      "Remove the credential from the repo, rotate it in IAM, and load credentials from a secrets manager or environment variables at runtime. Purge history if it was committed (e.g. git filter-repo).",
  }),
);
