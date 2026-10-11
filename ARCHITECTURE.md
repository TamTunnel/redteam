# Redteam — Architecture Assessment

**Verdict: TypeScript on Node. No Rust. No Python core.** One-line reasons below; full reasoning in §2.

## 1. Recommended stack

| Choice | Pick | One-line reason |
|---|---|---|
| Language | TypeScript (Node 20+) | Org fluency (TamTunnel/P/Branchline), contributor-friendly for open core, first-class LLM SDKs |
| CLI framework | `citty` | Already proven in Branchline; typed args, zero boilerplate, consistent with P's tooling |
| Pattern matching | tree-sitter (WASM bindings on Node) + raw-text secret scanner | Real syntactic precision per language without native-module pain; secrets need text/entropy scanning anyway |
| Test framework | `vitest` | Matches Branchline; fast; fixture-driven rule tests are trivial |
| Packaging | npm (`@tamtunnel/redteam`, bin `redteam`) | `npx` zero-install is the smoothest dev-tool distribution; GH Action is a one-liner on `node20` |
| Config | cosmiconfig-style (`redteam.config.js`, `.redteamrc.json`), flags override | Standard, no new DSL to learn |
| SARIF | Hand-rolled emitter validated against the SARIF JSON schema in tests | No heavy dep needed; schema test keeps GitHub code-scanning integration honest |

## 2. The Rust / Python / TypeScript call

**Rust: no.** Checklist against the bar (concrete reason required):
- *Profiler/workload*: The 50k-LOC / <2-min budget is not at risk in Node. tree-sitter's C core does the parsing (~single-digit ms per file; ~1000 files ≈ 5–10s); the host language only iterates compiled queries. No measurement suggests Node breaches the budget — so no performance justification.
- *Security*: The tool **reads** untrusted code; it never **executes** it. No sandboxing requirement, which is Rust's strongest card here.
- *Deployment*: It's a CLI, not a hot server path or a binary-distribution story that demands it (npm is fine for v1).
- *Contributor cost*: Open core lives or dies on easy check contributions. P's community is TS-fluent; Rust would tax every rule author.
- Revisit only if: profiling shows the Node host loop as the bottleneck (unlikely), or a later daemon/IDE-server mode needs high concurrency.

**Python: no (as core).** Python is P's default for AI orchestration, but the "AI" here is just HTTPS calls to LLM APIs — no local inference, no agent framework, no orchestration. `fetch` + provider SDKs on npm cover it. A Python core would also split the repo (pip core + TS action wrapper) for zero gain. Revisit only if a future "local-model attack agent" mode needs transformers — that's a Python sidecar then, not a rewrite.

**TypeScript wins** on org fluency, npm distribution, LLM SDK quality, and check-contributor ergonomics. The multi-language scanning requirement is met by tree-sitter grammars, not by the host language.

*Alternative considered and rejected:* wrapping Semgrep. It's the incumbent and would be faster to v0, but Redteam's differentiation is (a) rules tuned for AI-generated failure modes, (b) the LLM attack-agent pass deeply integrated with findings, (c) an open, contributor-friendly rule registry. Owning a small tree-sitter engine keeps the dependency tree light and the rule format reviewable.

## 3. Architecture sketch

```
redteam/
  packages/core/src/
    findings.ts        # Finding { ruleId, severity, file, line, col, message, snippet, source: "ast"|"text"|"llm" }
    engines/
      ast-engine.ts    # per-extension grammar load, run compiled tree-sitter queries
      text-engine.ts   # secret/entropy scan over raw text (API keys, tokens, private keys)
    rules/
      registry.ts      # RuleRegistry: register(rule), list(), byLanguage()
      builtin/         # one file per rule
    llm/
      providers.ts     # { complete(prompt): Promise<string> } — anthropic/openai/openai-compatible; key from env
      attack-agent.ts  # findings + code context → adversarial prompts → parsed Findings (source: "llm")
    reporters/
      json.ts  markdown.ts  sarif.ts   # (findings: Finding[]) => string
    config.ts          # flags > redteam.config.js > .redteamrc.json > defaults
    runner.ts          # collect files → engines → llm stage → reporters → exit code
  packages/cli/        # citty: `scan`, `rules list`, `init`
  action/              # action.yml — thin wrapper calling the npm package
  testdata/<rule-id>/  # vulnerable.<ext> + fixed.<ext> fixtures per rule
```

**Rule definition** (what contributors write — declarative, no parser code):
```ts
defineRule({
  id: "js-eval-injection",
  severity: "high",
  languages: ["javascript", "typescript"],
  queries: {
    javascript: `(call_expression function: (identifier) @fn (#eq? @fn "eval"))`,
    // …per-language tree-sitter S-expressions
  },
  message: "eval() with non-constant input enables code injection",
  remediation: "Use JSON.parse or a constrained parser",
})
```

**LLM pass** is a post-processor stage, not a separate tool: runner feeds high/medium findings plus surrounding code into adversarial prompts ("find logic flaws a syntactic scan misses; also dismiss false positives with reasons"). Provider-agnostic interface; **zero-config guarantee**: no API key → stage skipped with a one-line notice, static checks unaffected.

**Config resolution**: `--fail-on=high`, `--exclude`, rule enable/disable; flags > config file > defaults. Exit codes: `0` clean or below threshold, `1` findings at/above `--fail-on`, `2` config/usage error.

**Reporter pipeline**: `Finding[]` → `reporter.render()` → stdout or `-o`. SARIF emitter has a schema-validation test so GitHub code-scanning ingestion doesn't silently break.

## 4. Deliberately deferred to v2

- `--fix` auto-remediation — dangerous for a security tool; report-only in MVP.
- Taint tracking / dataflow analysis — tree-sitter queries are syntactic; real dataflow is a research project. MVP covers syntax + LLM pass for logic.
- Baseline/delta mode (only new findings vs `main`) — high value, but v2.
- Custom rule DSL beyond raw tree-sitter queries.
- IDE/LSP integration.
- Single-binary distribution (`pkg`/platform binaries).
- Local-model attack agent (the Python-sidecar conversation).

## 5. Biggest technical risk

**False-positive rate.** A scanner that cries wolf gets disabled in CI — that's what kills SAST tools, not missed vulns. Syntactic queries ("any `exec(` call") will flag legitimate code.

De-risk in the MVP, non-negotiable:
1. **Fixture gate**: every built-in rule ships `vulnerable.*` + `fixed.*` fixtures per language; CI fails if a rule fires on its own fixed fixture. Precision is tested, not hoped for.
2. **Severity discipline**: purely syntactic matches cap at `medium` unless corroborated (user-input proximity or LLM confirmation). This keeps `--fail-on=high` usable from day one.
3. **LLM as false-positive filter**, not just finder: the attack-agent prompt must dismiss as well as confirm, with reasons.
4. **Dogfood before done**: run against Branchline and si-wallet-mcp; tune rules until the signal is clean.

*Second risk:* tree-sitter WASM ergonomics on Node. De-risk with a week-1 spike: parse ~1k files across all five target languages, measure wall-clock, confirm headroom under the 2-min budget before building the rule corpus on top of it.
