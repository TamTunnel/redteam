// Built-in rule: high-entropy string literals that may be embedded secrets.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-high-entropy-string",
    severity: "low",
    languages: ["javascript", "typescript", "python"],
    entropyScan: {
      minLength: 20,
      threshold: 4.5,
      message:
        "High-entropy string literal (Shannon entropy ≥ 4.5 over ≥ 20 chars) — may be an embedded secret; review manually",
    },
    message: "High-entropy string literal may be an embedded secret",
    remediation:
      "Verify whether this value is a secret. If so, remove it, rotate it, and load it from a secrets manager or environment variable. If it is a benign random-looking constant (e.g. a nonce prefix), no action is needed.",
  }),
);
