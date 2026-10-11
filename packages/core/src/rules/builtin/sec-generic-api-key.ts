// Built-in rule: hardcoded API keys and tokens.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-generic-api-key",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    textPatterns: [
      {
        // api_key / apikey / api-secret / access_token / auth_token = "...." (16+ chars)
        pattern:
          /\b(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][^'"]{16,}['"]/gi,
        message: "Hardcoded API key / token assignment",
      },
      {
        pattern: /\b(?:ghp|gho)_[A-Za-z0-9]{36}\b/g,
        message: "GitHub token committed to source",
      },
      {
        pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
        message: "GitHub fine-grained personal access token committed to source",
      },
      {
        pattern: /\bxox[bap]-[A-Za-z0-9-]{10,}/g,
        message: "Slack token committed to source",
      },
      {
        pattern: /\bsk_live_[A-Za-z0-9]{20,}/g,
        message: "Stripe live secret key committed to source",
      },
      {
        pattern: /\b[bB]earer\s+[A-Za-z0-9\-._~+/]{20,}/g,
        message: "Hardcoded bearer token",
      },
    ],
    message: "Hardcoded API key or token committed to source",
    remediation:
      "Remove the secret from the repo, revoke/rotate it with the provider, and load it from a secrets manager or environment variable at runtime. Purge history if it was committed (e.g. git filter-repo).",
  }),
);
