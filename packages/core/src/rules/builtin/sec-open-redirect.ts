// Built-in rule: open redirect — res.redirect() / window.location= /
// location.href= (JS/TS) and redirect() (Python) with a non-literal target.
// Deliberate precision trade-off: a bare function call such as
// redirect(url_for("dashboard")) is treated as a sanitizer and does NOT
// match, so framework URL builders stay silent. Self-registers on import;
// see ./index.ts.
import { defineRule, registry } from "../registry.js";

// No (call_expression): url_for("dashboard")-style builders are sanitizers.
const DYNAMIC_NO_CALL =
  "[(identifier) (binary_expression) (template_string (template_substitution)) (member_expression) (subscript_expression)]";

const JS_TS = `
  (call_expression
    function: (member_expression property: (property_identifier) @p (#eq? @p "redirect"))
    arguments: (arguments . ${DYNAMIC_NO_CALL} @arg)) @node
  (assignment_expression
    left: (member_expression
      object: (identifier) @o (#match? @o "^(window|location|document)$")
      property: (property_identifier) @p (#match? @p "^(href|location)$"))
    right: [(identifier) (binary_expression) (template_string (template_substitution))] @rhs) @node
  (assignment_expression
    left: (member_expression
      object: (member_expression
        object: (identifier) @w (#eq? @w "window")
        property: (property_identifier) @l (#eq? @l "location"))
      property: (property_identifier) @p (#eq? @p "href"))
    right: [(identifier) (binary_expression) (template_string (template_substitution))] @rhs) @node
`;

registry.register(
  defineRule({
    id: "sec-open-redirect",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (identifier) @fn (#eq? @fn "redirect")
          arguments: (argument_list . [(binary_operator) (string (interpolation))] @arg)) @node
      `,
    },
    message:
      "Possible open redirect: the redirect target is a non-literal value; an attacker-supplied URL here enables phishing via your domain's trust",
    remediation:
      "Redirect only to a fixed allowlist of paths/hosts (or validate the target with new URL() and check origin); never redirect to raw user input.",
  }),
);
