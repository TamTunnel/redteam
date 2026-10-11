// Built-in rule: server-side request forgery — fetch / axios / http(s).request
// (JS/TS) and requests / httpx / urllib (Python) called with a non-literal URL.
// The URL must be the FIRST argument (anchored `.`); a string literal first
// argument does not match. Trade-off: a variable holding a constant URL is
// still flagged — verify the input is validated. Self-registers on import;
// see ./index.ts.
import { defineRule, registry } from "../registry.js";

const DYNAMIC_JS =
  "[(identifier) (binary_expression) (template_string (template_substitution)) (call_expression) (member_expression) (subscript_expression)]";
const DYNAMIC_PY =
  "[(identifier) (binary_operator) (string (interpolation)) (call) (attribute) (subscript)]";

const JS_TS = `
  (call_expression
    function: (identifier) @fn (#match? @fn "^(fetch|axios)$")
    arguments: (arguments . ${DYNAMIC_JS} @arg)) @node
  (call_expression
    function: (member_expression
      object: (identifier) @o (#match? @o "^(axios|http|https)$")
      property: (property_identifier) @p (#match? @p "^(get|post|put|delete|patch|head|request)$"))
    arguments: (arguments . ${DYNAMIC_JS} @arg)) @node
  (call_expression
    function: (identifier) @fn (#match? @fn "^(fetch|axios)$")
    arguments: (arguments . (string) @arg (#match? @arg "169\\.254\\.169\\.254|100\\.100\\.100\\.200"))) @node
  (call_expression
    function: (member_expression
      object: (identifier) @o (#match? @o "^(axios|http|https)$")
      property: (property_identifier) @p (#match? @p "^(get|post|put|delete|patch|head|request)$"))
    arguments: (arguments . (string) @arg (#match? @arg "169\\.254\\.169\\.254|100\\.100\\.100\\.200"))) @node
`;

// Suppress the URL-is-a-constant cases: a bare UPPER_SNAKE identifier
// (config constant, e.g. fetch(WALLET_URL)), or a template whose every
// interpolation is either an UPPER_SNAKE constant (e.g. `${MERCHANT_URL}/path`)
// or an encodeURIComponent(...) call (e.g. `${API_BASE}/users/${encodeURIComponent(id)}`).
// Anything with a raw dynamic interpolation still fires.
const SUPPRESS =
  /^([A-Z][A-Z0-9_]+|`(?:\$\{(?:[A-Z][A-Z0-9_]*|encodeURIComponent\([^`$\\]*\))\}|[^`$\\])+`)$/;

registry.register(
  defineRule({
    id: "sec-ssrf",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (attribute
            object: (identifier) @o (#match? @o "^(requests|httpx)$")
            attribute: (identifier) @a (#match? @a "^(get|post|put|delete|request)$"))
          arguments: (argument_list . ${DYNAMIC_PY} @arg)) @node
        (call
          function: (attribute
            object: (attribute
              object: (identifier) @u (#eq? @u "urllib")
              attribute: (identifier) @ur (#eq? @ur "request"))
            attribute: (identifier) @a (#eq? @a "urlopen"))
          arguments: (argument_list . ${DYNAMIC_PY} @arg)) @node
        (call
          function: (identifier) @fn (#eq? @fn "urlopen")
          arguments: (argument_list . ${DYNAMIC_PY} @arg)) @node
      `,
    },
    suppressionPattern: SUPPRESS,
    message:
      "Possible SSRF: an HTTP request is made to a non-literal URL; if any part is attacker-controlled the server can be made to request internal resources",
    remediation:
      "Validate the URL against an allowlist of hosts/schemes (or resolve it to a fixed set of endpoints); never fetch a raw user-supplied URL server-side.",
  }),
);
