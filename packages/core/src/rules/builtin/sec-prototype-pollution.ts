// Built-in rule: prototype pollution — assignment to __proto__,
// constructor.prototype, or prototype itself with a dynamic value.
// The deep-merge-loop variant needs taint tracking (out of scope);
// this catches the direct assignment shapes.
// Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

const JS_TS = `
  (assignment_expression
    left: (member_expression
      property: (property_identifier) @p (#match? @p "^(__proto__|prototype)$"))) @node
  (assignment_expression
    left: (subscript_expression
      object: (subscript_expression index: (string) @s (#match? @s "__proto__")))) @node
  (assignment_expression
    left: (member_expression
      object: (subscript_expression index: (string) @s (#match? @s "__proto__")))) @node
  (assignment_expression
    left: (member_expression
      object: (member_expression
        property: (property_identifier) @c (#eq? @c "constructor"))
      property: (property_identifier) @p (#eq? @p "prototype"))) @node
`;

registry.register(
  defineRule({
    id: "sec-prototype-pollution",
    severity: "medium",
    languages: ["javascript", "typescript"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
    },
    message:
      "Possible prototype pollution: assignment to __proto__ / constructor.prototype / prototype lets attacker input mutate shared object prototypes",
    remediation:
      "Never assign attacker-influenced keys to __proto__ or prototype chains. Use Map for dynamic keys, Object.create(null) for dictionaries, or validate keys against an allowlist.",
  }),
);
