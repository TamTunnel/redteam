// Importing this module registers every built-in rule with the global
// registry (each rule file self-registers on import as a side effect).
// Other agents: import this module (not the individual rule files) to get
// all built-in rules registered, e.g.
//   import "@tamtunnel/redteam-core/dist/rules/builtin/index.js";
// or, from inside packages/core/src:
//   import "./rules/builtin/index.js";

import "./sec-aws-key.js";
import "./sec-generic-api-key.js";
import "./sec-high-entropy-string.js";
import "./sec-private-key.js";
import "./sec-eval.js";
import "./sec-child-process.js";
import "./sec-command-injection.js";
import "./sec-sql-injection.js";
import "./sec-xss.js";
import "./sec-ssrf.js";
import "./sec-path-traversal.js";
import "./sec-weak-crypto.js";
import "./sec-insecure-random.js";
import "./sec-open-redirect.js";
import "./sec-xxe.js";
import "./sec-regex-dos.js";
import "./sec-prototype-pollution.js";
