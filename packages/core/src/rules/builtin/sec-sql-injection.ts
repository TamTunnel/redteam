// Built-in rule: SQL injection — string concatenation or a template/f-string
// used as the SQL argument to query()/execute().
// Fixed fixtures use parameterized queries, which have a plain string plus
// separate parameters and do not match. Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

const JS_TS = `
  (call_expression
    function: (member_expression property: (property_identifier) @p (#match? @p "^(query|execute)$"))
    arguments: (arguments . [(binary_expression operator: "+") (template_string (template_substitution))] @arg)) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(query|execute)$")
    arguments: (arguments . [(binary_expression operator: "+") (template_string (template_substitution))] @arg)) @node
  (call_expression
    function: (member_expression property: (property_identifier) @p (#match? @p "^(query|execute)$"))
    arguments: (arguments . [(identifier) (member_expression)] @arg)) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(query|execute)$")
    arguments: (arguments . [(identifier) (member_expression)] @arg)) @node
`;

// Bare identifiers are the most common real-world SQLi shape
// (db.query(req.query.id)), but UPPER_SNAKE constants are typically safe
// pre-built query strings — suppress those.
const SUPPRESS = /^[A-Z][A-Z0-9_]*$/;

registry.register(
  defineRule({
    id: "sec-sql-injection",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (attribute
            object: (_)
            attribute: (identifier) @a (#match? @a "^(execute|executemany)$"))
          arguments: (argument_list . [(binary_operator operator: "+") (string (interpolation))] @arg)) @node
        (call
          function: (attribute
            object: (_)
            attribute: (identifier) @a (#match? @a "^(execute|executemany)$"))
          arguments: (argument_list . (identifier) @arg)) @node
      `,
    },
    suppressionPattern: SUPPRESS,
    message:
      "Possible SQL injection: SQL text is built with string concatenation or a template/f-string instead of bound parameters",
    remediation:
      "Use parameterized queries / prepared statements (placeholders + a separate parameters argument) so user input is never interpolated into SQL text.",
  }),
);
