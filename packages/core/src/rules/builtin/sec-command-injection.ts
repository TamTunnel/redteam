// Built-in rule: command injection — a dynamic string (concatenation,
// template literal / f-string, or a variable) passed as the command argument
// to a shell-ish process API.
// This is deliberately distinct from sec-child-process (which is about
// shell:true at all): here the *command itself* is built from parts.
// Trade-off: a variable command is flagged even when it is a fixed allowlist
// value — verify the input is validated. Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// Non-literal first-argument shapes (anchored `.` = first argument, so e.g.
// fetch("https://x", opts) does not flag on the trailing identifier).
const DYNAMIC_JS =
  "[(identifier) (binary_expression) (template_string (template_substitution)) (call_expression) (member_expression) (subscript_expression)]";

const JS_TS = `
  (call_expression
    function: (member_expression
      object: (identifier)
      property: (property_identifier) @p (#match? @p "^(exec|execSync|spawn|spawnSync)$"))
    arguments: (arguments . ${DYNAMIC_JS} @arg)) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(exec|execSync|spawn|spawnSync)$")
    arguments: (arguments . ${DYNAMIC_JS} @arg)) @node
`;

registry.register(
  defineRule({
    id: "sec-command-injection",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (attribute
            object: (identifier) @o (#eq? @o "os")
            attribute: (identifier) @a (#match? @a "^(system|popen)$"))
          arguments: (argument_list . [(binary_operator operator: "+") (string (interpolation)) (identifier)] @arg)) @node
        (call
          function: (attribute object: (identifier) @s (#eq? @s "subprocess"))
          arguments: (argument_list . [(binary_operator operator: "+") (string (interpolation)) (identifier)] @arg)) @node
      `,
    },
    message:
      "Possible command injection: a dynamically built string (concatenation, template/f-string, or variable) is passed as the shell command",
    remediation:
      "Pass arguments as an argv array (execFile/spawn, subprocess without shell=True) and validate any dynamic parts against an allowlist; never interpolate untrusted input into a shell command.",
  }),
);
