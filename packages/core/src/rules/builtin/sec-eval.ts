// Built-in rule: dynamic code execution (eval / Function / exec).
// Syntactic only — any use is flagged; the message tells the reader what to
// use instead. Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// NOTE: predicates must be the last child of their enclosing node pattern
// (or the pattern wrapped in an extra paren group); a predicate placed
// before a sibling field breaks query compilation in web-tree-sitter.
const JS_TS = `
  (call_expression function: (identifier) @fn (#eq? @fn "eval")) @node
  (call_expression function: (identifier) @fn (#eq? @fn "Function")) @node
  (new_expression constructor: (identifier) @c (#eq? @c "Function")) @node
  (call_expression
    function: (member_expression property: (property_identifier) @p (#eq? @p "eval"))) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(setTimeout|setInterval)$")
    arguments: (arguments . [(string) (template_string) (binary_expression) (call_expression)] @arg)) @node
`;

registry.register(
  defineRule({
    id: "sec-eval",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call function: (identifier) @fn (#eq? @fn "eval")) @node
        (call function: (identifier) @fn (#eq? @fn "exec")) @node
      `,
    },
    message:
      "Dynamic code execution: eval()/Function()/exec() runs its argument as code, enabling code injection if the input is attacker-influenced",
    remediation:
      "Avoid eval-style APIs. For data use JSON.parse (or ast.literal_eval in Python); for dynamic behavior dispatch through a lookup table of pre-defined functions.",
  }),
);
