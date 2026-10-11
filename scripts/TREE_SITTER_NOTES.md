# tree-sitter WASM on Node — verified working API

Verified on Node v24.20.0 with `web-tree-sitter@0.26.13` + grammar packages
(`tree-sitter-javascript@0.25.0`, `tree-sitter-python`, `tree-sitter-typescript`).
Spike: `scripts/ts-spike.mjs` (`node scripts/ts-spike.mjs`).

## Dependency placement

- `web-tree-sitter` + the `tree-sitter-*` grammar packages are **runtime
  dependencies of `@tamtunnel/redteam-core`** (`packages/core/package.json`).
  Grammar WASM files ship *inside* the grammar npm packages — no separate
  download step, no CLI-generated files.

## WASM file locations

- Runtime: `<repo>/node_modules/web-tree-sitter/web-tree-sitter.wasm`
  (exposed via package exports: `require.resolve("web-tree-sitter/web-tree-sitter.wasm")`).
- Grammars: `<repo>/node_modules/tree-sitter-<lang>/tree-sitter-<lang>.wasm`
  (e.g. `tree-sitter-javascript.wasm`, `tree-sitter-python.wasm`).
  For typescript: `tree-sitter-typescript` ships `tree-sitter-typescript.wasm`
  (the `.ts` grammar; `.tsx` needs a separate build — see gotcha 4).

## Working call sequence (ESM)

```js
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
import { Parser, Language, Query } from "web-tree-sitter";

const runtimeWasm = require.resolve("web-tree-sitter/web-tree-sitter.wasm");
await Parser.init({ locateFile: () => runtimeWasm });  // see gotcha 1

const jsLang = await Language.load(grammarWasmPath);   // absolute path, see gotcha 2

const parser = new Parser();
parser.setLanguage(jsLang);
const tree = parser.parse(sourceText);

const query = new Query(jsLang, `(call_expression function: (identifier) @fn (#eq? @fn "eval"))`);
const captures = query.captures(tree.rootNode);
for (const c of captures) {
  c.node.text;                    // "eval"
  c.node.startPosition;           // { row: 3, column: 0 } — zero-based
  c.node.startIndex; c.node.endIndex;
}
```

## Gotchas (all discovered empirically — do not regress)

1. **`Parser.init()` needs `locateFile` in Node.** The default emscripten
   loader looks for `web-tree-sitter.wasm` next to the JS bundle; it resolves
   in a bare install, but passing `locateFile: () => runtimeWasm` (resolved
   through the package's own exports, not a hardcoded relative path) is
   bulletproof against bundling/cwd changes. If you ever use the debug build,
   point at `web-tree-sitter/debug/web-tree-sitter.wasm` instead.
2. **`Language.load()` takes a filesystem path, not a name.** Resolve the
   grammar wasm via `createRequire` + `path.join(pkgDir, "tree-sitter-<lang>.wasm")`.
   Do not hardcode `node_modules/...` strings — pnpm/Yarn hoisting layouts differ.
3. **Named exports, not methods.** In web-tree-sitter 0.26 ESM:
   - `Language.load(path)` — NOT `Parser.Language.load()`.
   - `new Query(lang, source)` — NOT `lang.query(source)`.
   (The CJS README example uses `Parser.Language.load()` because `require`
   returns the whole namespace object; in ESM they are top-level exports.)
4. **`hasError` is a getter.** `tree.rootNode.hasError` — NOT `hasError()`.
5. **Language ABI compatibility.** web-tree-sitter 0.26 loads grammars built
   with the tree-sitter CLI of the same generation (LANGUAGE_VERSION 14/15
   family). The npm-shipped `.wasm` files load cleanly — verified for
   javascript. Re-verify with the spike when upgrading either package.
6. **No fallback needed.** The `tree-sitter` (native) npm package was not
   required: `web-tree-sitter` WASM works on Node 24 out of the box.
   Prefer WASM (zero native build, matches the architecture decision).

## Performance baseline (from the spike)

Parse of a small file: <1ms. Full ARCHITECTURE.md §5 week-1 spike (parse ~1k
files across all target languages, wall-clock vs the 2-min budget) is still
open for the AST-engine agent.
