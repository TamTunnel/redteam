// Tree-sitter WASM spike for Redteam.
// Verifies: web-tree-sitter loads on Node 24, grammar .wasm files ship inside
// the tree-sitter-* npm packages, parse + S-expression query capture works.
//
// Run: node scripts/ts-spike.mjs
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const require = createRequire(import.meta.url);
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");

// 1. Resolve the runtime's own wasm (web-tree-sitter.wasm) via package exports.
const runtimeWasm = require.resolve("web-tree-sitter/web-tree-sitter.wasm");
console.log("runtime wasm:", runtimeWasm);

// 2. Resolve the grammar wasm from the grammar npm package — it ships at
//    <pkg-root>/tree-sitter-<lang>.wasm (e.g. tree-sitter-javascript.wasm).
const jsPkgDir = path.dirname(require.resolve("tree-sitter-javascript/package.json"));
const jsGrammarWasm = path.join(jsPkgDir, "tree-sitter-javascript.wasm");
console.log("js grammar wasm:", jsGrammarWasm);

const { Parser, Language, Query } = await import("web-tree-sitter");

// 3. Init: locateFile points the emscripten loader at the installed runtime wasm.
//    (Defaults to the file next to the JS bundle, which also works in Node,
//    but the explicit locateFile is bulletproof when bundled/moved.)
await Parser.init({
  locateFile: () => runtimeWasm,
});
console.log("Parser.init() OK");

// 4. Load the grammar.
const jsLang = await Language.load(jsGrammarWasm);
console.log("Language.load() OK — version:", jsLang.version);

// 5. Parse a sample file.
const parser = new Parser();
parser.setLanguage(jsLang);
const source = `
// sample.js — tiny vulnerable fixture
const apiKey = "sk-live-abcdef1234567890";
eval(userInput);
`;
const tree = parser.parse(source);
console.log("parsed OK, root type:", tree.rootNode.type, "hasError:", tree.rootNode.hasError);

// 6. Run one S-expression query and print a capture.
const query = new Query(jsLang, `
  (call_expression
    function: (identifier) @fn
    (#eq? @fn "eval"))
`);
const captures = query.captures(tree.rootNode);
for (const c of captures) {
  const { row, column } = c.node.startPosition;
  console.log(
    `capture @${c.name}: "${c.node.text}" at line ${row + 1}, col ${column + 1}`,
  );
}

if (captures.length === 0) {
  console.error("FAIL: expected at least one capture for eval(...)");
  process.exit(1);
}
console.log("SPIKE OK — tree-sitter WASM parse + query capture works on", process.version);
