// Built-in rule: private key material committed to source.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-private-key",
    severity: "high",
    corroborated: true, // AKIA-pattern / PEM-header matches are high-precision
    languages: ["javascript", "typescript", "python"],
    textPatterns: [
      {
        pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
        message: "Private key material committed to source",
      },
    ],
    message: "Private key material committed to source",
    remediation:
      "Remove the key from the repo, revoke/rotate it, and provision it from a secrets manager or mounted secret at deploy time. Purge history if it was committed (e.g. git filter-repo).",
  }),
);
