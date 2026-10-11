// Built-in rule: child-process execution with an explicit shell.
// Flags exec/execSync/spawn/spawnSync with `shell: true` (JS/TS) and
// os.system / os.popen / subprocess.*(shell=True) (Python).
// The member-expression form intentionally matches ANY receiver object
// (child_process, cp, proc, …) — the `shell: true` argument is the strong
// signal, and aliased requires are idiomatic. The bare-identifier form
// covers `const { exec } = require("child_process")`.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

const JS_TS = `
  (call_expression
    function: (member_expression
      object: (identifier)
      property: (property_identifier) @p (#match? @p "^(exec|execSync|spawn|spawnSync)$"))
    arguments: (arguments
      (object (pair key: (property_identifier) @k (#eq? @k "shell") value: (true))))) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(exec|execSync|spawn|spawnSync)$")
    arguments: (arguments
      (object (pair key: (property_identifier) @k (#eq? @k "shell") value: (true))))) @node
`;

registry.register(
  defineRule({
    id: "sec-child-process",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (attribute
            object: (identifier) @o (#eq? @o "os")
            attribute: (identifier) @a (#match? @a "^(system|popen)$"))) @node
        (call
          function: (attribute object: (identifier) @s (#eq? @s "subprocess"))
          arguments: (argument_list
            (keyword_argument name: (identifier) @n (#eq? @n "shell") value: (true)))) @node
      `,
    },
    message:
      "Child process spawned with shell:true / shell=True (or os.system/os.popen): the command is interpreted by a shell, so any interpolated input becomes shell injection",
    remediation:
      "Drop the shell option (use execFile/spawn with an argv array, or subprocess without shell=True) so arguments are passed directly without shell interpretation.",
  }),
);
