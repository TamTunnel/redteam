// Built-in rule: regular-expression denial of service — a regex literal,
// new RegExp(), or re.compile() whose pattern contains nested quantifiers
// ((a+)+-style), the classic catastrophic-backtracking shape.
// The AST match finds regex nodes; the nested-quantifier check is a
// #match? predicate on the node's text (a group containing a quantifier,
// itself quantified). NOTE: in web-tree-sitter a predicate is only part of
// the pattern when it sits inside the same top-level paren group —
// `(regex) @node (#match? …)` on the next line would silently not apply.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// A `(` … quantifier … `)` group followed by another quantifier.
const NESTED_QUANTIFIER = "[(][^()]*[+*][^()]*[)][+*]";

const JS_TS = `
  (
    (regex) @node
    (#match? @node "${NESTED_QUANTIFIER}")
  )
  (
    (new_expression constructor: (identifier) @c) @node
    (#eq? @c "RegExp")
    (#match? @node "${NESTED_QUANTIFIER}")
  )
  (
    (call_expression function: (identifier) @f) @node
    (#eq? @f "RegExp")
    (#match? @node "${NESTED_QUANTIFIER}")
  )
`;

registry.register(
  defineRule({
    id: "sec-regex-dos",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (
          (call function: (attribute object: (identifier) @r attribute: (identifier) @c)) @node
          (#eq? @r "re")
          (#eq? @c "compile")
          (#match? @node "${NESTED_QUANTIFIER}")
        )
      `,
    },
    message:
      "Possible ReDoS: regex contains nested quantifiers ((a+)+-style) — crafted input can cause catastrophic backtracking and hang the process",
    remediation:
      "Rewrite the pattern to avoid nested quantifiers (use possessive/atomic groups or a linear-time engine like RE2); add input length limits and timeouts.",
  }),
);
