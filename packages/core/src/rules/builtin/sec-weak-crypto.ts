// Built-in rule: weak cryptography — MD5/SHA-1 hashes and DES ciphers.
// The algorithm name is matched case-insensitively against the string
// literal (both quote styles). Self-registers on import; see ./index.ts.
import { defineRule, registry } from "../registry.js";

// Matches "md5", "MD5", "sha1", "SHA-1", "des", "DES-EDE3-CBC", … (any quotes).
// NOTE: the inner double quote must stay backslash-escaped in the query
// source (`[\"']`), otherwise the query string terminates early and the
// whole query fails to compile.
const WEAK_ALGO = `[\\"']([mM][dD]5|[sS][hH][aA]-?1|[dD][eE][sS](-[A-Za-z0-9]+)*)[\\"']`;

const JS_TS = `
  (call_expression
    function: (identifier) @fn (#match? @fn "^(createHash|createCipher|createDecipher)$")
    arguments: (arguments . (string) @algo (#match? @algo "${WEAK_ALGO}"))) @node
  (call_expression
    function: (member_expression property: (property_identifier) @p (#match? @p "^(createHash|createCipher|createDecipher)$"))
    arguments: (arguments . (string) @algo (#match? @algo "${WEAK_ALGO}"))) @node
`;

registry.register(
  defineRule({
    id: "sec-weak-crypto",
    severity: "medium",
    languages: ["javascript", "typescript", "python"],
    queries: {
      javascript: JS_TS,
      typescript: JS_TS,
      python: `
        (call function: (identifier) @fn (#match? @fn "^(md5|sha1)$")) @node
        (call function: (attribute object: (_) attribute: (identifier) @a (#match? @a "^(md5|sha1)$"))) @node
        (call
          function: (attribute
            object: (attribute attribute: (identifier) @d (#eq? @d "DES"))
            attribute: (identifier) @n (#eq? @n "new"))) @node
        (call
          function: (attribute
            object: (identifier) @d (#eq? @d "DES")
            attribute: (identifier) @n (#eq? @n "new"))) @node
      `,
    },
    message:
      "Weak cryptography: MD5/SHA-1 are broken for integrity/password use and DES is brute-forceable — collisions and key recovery are practical",
    remediation:
      "Use SHA-256/SHA-512 (hashlib.sha256, createHash('sha256')) and AES-GCM; for passwords use bcrypt/scrypt/argon2, never a fast hash.",
  }),
);
