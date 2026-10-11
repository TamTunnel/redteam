// Built-in rule: path traversal — fs.readFile / path.join (JS/TS) and
// open() (Python) called with a non-literal path argument.
//
// Precision tuning (dogfood-driven):
// - ANY argument position is checked (the traversal payload is often the
//   2nd arg to path.join), but only for directly dynamic shapes:
//   identifiers, string concat, interpolated templates, subscripts.
//   Call/member expressions are excluded — path.join(os.homedir(), "x")
//   and path.join(stateDir(), "fixed") are the safe norm, not the signal.
// - suppressionPattern drops: __dirname/__filename, UPPER_SNAKE constants
//   (anchored base dirs), and args that visibly sanitize (.replace(),
//   .normalize(), encodeURIComponent).
// Trade-off: a variable that was validated out-of-band is still flagged —
// the message says to verify. Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// Note: (call_expression) is excluded except via the REPLACE_CALL alternative
// below — path.join(os.homedir(), "x") is the safe norm, not the signal.
// (member_expression) IS included: req.query.f-style user-data shapes are the
// primary traversal vector.
const DYNAMIC_JS =
  "[(identifier) (binary_expression) (template_string (template_substitution)) (subscript_expression) (member_expression)]";
const DYNAMIC_PY =
  "[(identifier) (binary_operator) (string (interpolation)) (subscript) (attribute)]";

// Bypassable sanitizer: X.replace("../", "") — string-literal first arg only
// strips the first occurrence. (Regex-first-arg replaces are suppressed as
// likely-global sanitizers.) Inlined in the query below.

const JS_TS = `
  (call_expression
    function: (member_expression
      object: (identifier) @o (#eq? @o "fs")
      property: (property_identifier) @p (#match? @p "^(readFile|readFileSync)$"))
    arguments: (arguments . ${DYNAMIC_JS} @arg)) @node
  (call_expression
    function: (member_expression
      object: (identifier) @o (#eq? @o "fs")
      property: (property_identifier) @p (#match? @p "^(readFile|readFileSync)$"))
    arguments: (arguments . (call_expression
      function: (member_expression property: (property_identifier) @rp (#eq? @rp "replace"))
      arguments: (arguments . (string) @rs)) @arg)) @node
  (call_expression
    function: (member_expression
      object: (identifier) @o (#eq? @o "path")
      property: (property_identifier) @p (#match? @p "^(join|resolve)$"))
    arguments: (arguments ${DYNAMIC_JS} @arg)) @node
`;

const SUPPRESS =
  // __dirname / __filename / UPPER_SNAKE constants (anchored base dirs),
  // encodeURIComponent() (sound for a path segment), or .replace() with a
  // regex first arg (likely a global sanitizer). Deliberately NOT suppressed:
  // .replace("../", "") (string literal only replaces the first occurrence —
  // classic bypass), .normalize() alone (does not prevent traversal).
  /^(__dirname|__filename|[A-Z][A-Z0-9_]*)$|encodeURIComponent\s*\(|\.replace\s*\(\s*\//;

registry.register(
  defineRule({
    id: "sec-path-traversal",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call
          function: (identifier) @fn (#eq? @fn "open")
          arguments: (argument_list ${DYNAMIC_PY} @arg)) @node
      `,
    },
    suppressionPattern: SUPPRESS,
    message:
      "Possible path traversal: a filesystem path built from a non-literal value reaches fs.readFile/path.join/open(); '../' segments could escape the intended directory",
    remediation:
      "Resolve the path against a base directory and verify the result stays inside it (path.resolve + startsWith check), or map user input through an allowlist to fixed paths.",
  }),
);
