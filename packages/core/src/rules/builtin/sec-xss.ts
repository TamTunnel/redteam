// Built-in rule: cross-site scripting sinks — assignment to innerHTML /
// outerHTML and React's dangerouslySetInnerHTML.
// NOTE: the plain tree-sitter-typescript grammar has no JSX nodes, so the
// TypeScript query only covers the innerHTML/outerHTML assignment; the
// engine skips a rule whose query fails to compile for a language.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

registry.register(
  defineRule({
    id: "sec-xss",
    severity: "medium",
    languages: ["javascript", "typescript"],
    queries: {
      javascript: `
        (assignment_expression
          left: (member_expression property: (property_identifier) @p (#match? @p "^(innerHTML|outerHTML)$"))) @node
        (jsx_attribute (property_identifier) @a (#eq? @a "dangerouslySetInnerHTML")) @node
        (call_expression
          function: (member_expression
            object: (identifier) @o (#eq? @o "document")
            property: (property_identifier) @p (#match? @p "^(write|writeln)$"))
          arguments: (arguments . [(identifier) (member_expression) (binary_expression) (template_string) (call_expression)] @arg)) @node
      `,
      typescript: `
        (assignment_expression
          left: (member_expression property: (property_identifier) @p (#match? @p "^(innerHTML|outerHTML)$"))) @node
        (call_expression
          function: (member_expression
            object: (identifier) @o (#eq? @o "document")
            property: (property_identifier) @p (#match? @p "^(write|writeln)$"))
          arguments: (arguments . [(identifier) (member_expression) (binary_expression) (template_string) (call_expression)] @arg)) @node
      `,
    },
    message:
      "Possible XSS sink: raw HTML is assigned to innerHTML/outerHTML (or dangerouslySetInnerHTML); unescaped user input here executes script",
    remediation:
      "Prefer textContent / safe DOM APIs or a sanitizer (e.g. DOMPurify) before assigning HTML; never assign unescaped user input to innerHTML.",
  }),
);
