// Built-in rule: insecure randomness — Math.random (JS/TS) and the
// random module (Python) are deterministic PRNGs.
//
// Precision tuning (dogfood-driven): the rule ONLY fires when the PRNG
// output is assigned to a secret-scented variable (token, secret,
// password, nonce, session, …). A bare Math.random() used for a branch
// suffix, jitter, or sampling is legitimate code — flagging it is the
// false positive that gets scanners disabled. The value's text must
// contain the PRNG call, so chained forms (Math.random().toString(36))
// are caught too.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// Case-insensitive without (?i) (unsupported by tree-sitter predicates).
const SECRET_NAME =
  "[Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Pp][Ww][Dd]|[Nn][Oo][Nn][Cc][Ee]|[Ss][Ee][Ss][Ss][Ii][Oo][Nn]|[Aa][Uu][Tt][Hh]|[Oo][Tt][Pp]|[Ss][Aa][Ll][Tt]|[Cc][Ss][Rr][Ff]";

const JS_TS = `
  (variable_declarator
    name: (identifier) @v (#match? @v "${SECRET_NAME}")
    value: (_) @node (#match? @node "Math\\.random"))
  (assignment_expression
    left: (identifier) @v (#match? @v "${SECRET_NAME}")
    right: (_) @node (#match? @node "Math\\.random"))
`;

registry.register(
  defineRule({
    id: "sec-insecure-random",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (assignment
          left: (identifier) @v (#match? @v "${SECRET_NAME}")
          right: (_) @node (#match? @node "random\\.(random|randint|randrange|choice|uniform)"))
      `,
    },
    message:
      "Insecure randomness: Math.random()/random.* is a predictable PRNG — not for secrets/tokens; an attacker who observes outputs can predict future values",
    remediation:
      "Use a CSPRNG: crypto.getRandomValues()/crypto.randomUUID() (JS/TS) or the secrets module / os.urandom (Python) for tokens, session ids, and password resets.",
  }),
);
