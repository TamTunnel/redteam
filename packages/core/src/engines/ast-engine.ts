// AST engine: parses files with tree-sitter (WASM) and runs the compiled
// tree-sitter queries of every registered rule that declares one for the
// file's language. See scripts/TREE_SITTER_NOTES.md for the verified API.

import { createRequire } from "node:module";
import { Language, Parser, Query } from "web-tree-sitter";
import type { Finding } from "../findings.js";
import { registry } from "../rules/registry.js";
import type { Rule } from "../rules/registry.js";
import type { Engine, ScannedFile } from "./types.js";

const require = createRequire(import.meta.url);

type LangName = "javascript" | "typescript" | "python";

const GRAMMAR_WASM: Record<LangName, string> = {
  javascript: "tree-sitter-javascript/tree-sitter-javascript.wasm",
  // The typescript package ships tree-sitter-typescript.wasm (plain .ts;
  // .tsx has a separate build — see TREE_SITTER_NOTES.md gotcha 4).
  typescript: "tree-sitter-typescript/tree-sitter-typescript.wasm",
  python: "tree-sitter-python/tree-sitter-python.wasm",
};

// Lazy singleton: Parser.init() runs once per process; languages and compiled
// queries are cached process-wide (grammars + queries are immutable).
let initPromise: Promise<void> | null = null;
const languageCache = new Map<string, Language>();
const queryCache = new Map<string, Query>();

function ensureInit(): Promise<void> {
  if (!initPromise) {
    initPromise = (async () => {
      const runtimeWasm = require.resolve("web-tree-sitter/web-tree-sitter.wasm");
      await Parser.init({ locateFile: () => runtimeWasm });
    })();
  }
  return initPromise;
}

async function loadLanguage(lang: string): Promise<Language | null> {
  const spec = (GRAMMAR_WASM as Record<string, string>)[lang];
  if (!spec) return null;
  let language = languageCache.get(lang);
  if (!language) {
    language = await Language.load(require.resolve(spec));
    languageCache.set(lang, language);
  }
  return language;
}

/**
 * Compile (once per rule+language) the rule's query for `lang`.
 * Returns null when the rule has no query for the language or the query
 * fails to compile (e.g. it references node types absent from that grammar
 * build) — the rule is then skipped for that language.
 */
function compileQuery(rule: Rule, lang: LangName, language: Language): Query | null {
  const key = `${rule.id}:${lang}`;
  const cached = queryCache.get(key);
  if (cached) return cached;
  const source = rule.queries?.[lang];
  if (!source) return null;
  try {
    const query = new Query(language, source);
    queryCache.set(key, query);
    return query;
  } catch {
    return null;
  }
}

export class AstEngine implements Engine {
  readonly name = "ast" as const;
  private parser: Parser | null = null;

  async scan(file: ScannedFile): Promise<Finding[]> {
    const lang = file.language;
    if (lang === "unknown") return [];
    try {
      await ensureInit();
      const language = await loadLanguage(lang);
      if (!language) return [];
      if (!this.parser) this.parser = new Parser();
      // setLanguage + parse are synchronous back-to-back, so no concurrent
      // scan() can interleave between them on the event loop.
      this.parser.setLanguage(language);
      // tree-sitter is error-tolerant, but a pathological input could still
      // throw — the outer try/catch turns that into "no findings".
      const tree = this.parser.parse(file.content);
      const findings: Finding[] = [];
      const seen = new Set<string>();
      const rules = registry
        .byLanguage(lang)
        .filter((r) => r.queries?.[lang as LangName] !== undefined);
      for (const rule of rules) {
        const query = compileQuery(rule, lang as LangName, language);
        if (!query) continue;
        let matches;
        try {
          if (!tree) continue;
          matches = query.matches(tree.rootNode);
        } catch {
          continue;
        }
        for (const match of matches) {
          // Query convention: rules capture the primary offending node as
          // @node; fall back to the first capture otherwise.
          const capture =
            match.captures.find((c) => c.name === "node") ?? match.captures[0];
          if (!capture) continue;
          const node = capture.node;
          // Precision valve: rules can suppress matches whose @arg looks
          // sanitized or constant (e.g. allowlisted identifiers).
          if (rule.suppressionPattern) {
            const argCapture = match.captures.find((c) => c.name === "arg");
            const testText = (argCapture?.node ?? node).text;
            if (rule.suppressionPattern.test(testText)) continue;
          }
          const dedupeKey = `${rule.id}:${node.startIndex}:${node.endIndex}`;
          if (seen.has(dedupeKey)) continue;
          seen.add(dedupeKey);
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            file: file.path,
            line: node.startPosition.row + 1,
            col: node.startPosition.column + 1,
            endLine: node.endPosition.row + 1,
            message: rule.message,
            snippet: node.text.slice(0, 200),
            remediation: rule.remediation,
            source: "ast",
          });
        }
      }
      return findings;
    } catch {
      return [];
    }
  }

  /** Best-effort release of parser resources. */
  dispose(): void {
    try {
      this.parser?.delete();
    } catch {
      // ignore — dispose must never throw
    }
    this.parser = null;
  }
}
