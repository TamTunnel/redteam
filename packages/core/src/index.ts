// Public API surface of @tamtunnel/redteam-core.
//
// Importing this module registers every built-in rule as a side effect,
// so `registry.list()` is populated for consumers (CLI, runner, tests).
import "./rules/builtin/index.js";

export * from "./findings.js";
export * from "./engines/types.js";
export * from "./engines/ast-engine.js";
export * from "./engines/text-engine.js";
export * from "./rules/registry.js";
export * from "./llm/providers.js";
export * from "./llm/attack-agent.js";
// The three reporters each export `render` — namespace them to avoid the
// export * collision (TS2308).
export * as jsonReporter from "./reporters/json.js";
export * as markdownReporter from "./reporters/markdown.js";
export * as sarifReporter from "./reporters/sarif.js";
export * as htmlReporter from "./reporters/html.js";
export * from "./config.js";
export * from "./runner.js";
