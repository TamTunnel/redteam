# Redteam

[![npm version](https://img.shields.io/npm/v/@tamtunnel/redteam)](https://www.npmjs.com/package/@tamtunnel/redteam)
[![CI](https://img.shields.io/github/actions/workflow/status/TamTunnel/redteam/ci.yml?branch=main)](https://github.com/TamTunnel/redteam/actions)
[![license](https://img.shields.io/github/license/TamTunnel/redteam)](LICENSE)

An adversarial security scanner that finds vulnerabilities in agent-built code before it reaches production.

## The problem

Coding agents write a lot of code, fast — and nobody reads all of it. They repeat known-bad patterns with confidence: string-concatenated SQL, `eval()` on user input, credentials checked into the repo, missing authz checks on routes. These are the exact patterns traditional SAST tools were built to catch, but the existing tools are tuned for human-written code. They flag everything, so teams disable them, and the agent's failure modes — the specific things LLMs do wrong over and over — aren't in their rule sets at all.

## The solution

Redteam is a security reviewer that reads your code like an attacker would. Two stages:

1. **Fast syntactic checks.** Tree-sitter parses your code into a real syntax tree, and per-language query rules flag known-bad patterns (dangerous calls, missing checks, hardcoded secrets — secrets get their own raw-text/entropy scan). Runs fully offline, no API keys.
2. **Optional AI attack agent.** With an API key present, the findings from stage 1 plus surrounding code are fed to an LLM with adversarial prompts: dismiss the false alarms (with reasons), and hunt for the logic flaws no syntactic scan can catch — broken access control, flawed business logic, the things that actually bite.

A smart developer who's never seen this project should be able to read this far and understand exactly what it does. That's the bar.

## Quick start

```bash
npx @tamtunnel/redteam scan ./src
```

Sample output (markdown reporter; real output from the CLI):

```markdown
# Redteam report

2 findings: 2 medium.

## medium

### `app.js:3`

- **Rule:** `sec-eval`
- **Severity:** medium (source: ast)
- Dynamic code execution: eval()/Function()/exec() runs its argument as code, enabling code injection if the input is attacker-influenced

```
eval("db.find(" + q + ")")
```

**Remediation:** Avoid eval-style APIs. For data use JSON.parse (or ast.literal_eval in Python); for dynamic behavior dispatch through a lookup table of pre-defined functions.

### `app.js:1`

- **Rule:** `sec-generic-api-key`
- **Severity:** medium (source: text)
- Hardcoded API key / token assignment
...
```

Generate a starter config:

```bash
redteam init
```

Useful flags:

```bash
redteam scan ./src --fail-on high --format sarif   # exit 1 if any HIGH finding, SARIF output
redteam scan ./src --format json                   # JSON report
redteam scan ./src --format html -o report.html    # self-contained HTML report
redteam scan ./src --exclude "test/**" --exclude "fixtures/**"  # skip globs (repeatable)
redteam scan ./src --rules "+sec-*, -sec-regex-dos" # enable/disable rules (wildcards ok)
redteam scan ./src --no-llm                        # disable the attack-agent stage
```

The LLM stage is **zero-config**: with no API key set, it skips with a one-line notice and the static checks run normally. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or point an OpenAI-compatible provider at it to enable the attack-agent pass.

## Architecture

- **Engines**: tree-sitter AST queries per language, plus a raw-text secret/entropy scanner. The scanner reads code — it never executes it. (One exception: `redteam.config.js`, if present, is loaded with a dynamic `import()` and therefore *executed* — same as eslint/vite configs. When scanning an untrusted repo, run from a directory whose config you trust, or delete the repo's `redteam.config.js` first.)
- **Rule registry**: one file per rule, each with per-language queries, severity, message, and remediation. Open for contributions; every rule ships with `vulnerable` and `fixed` fixtures.
- **LLM attack-agent**: post-processor over high/medium findings — adversarial prompts that confirm real issues, dismiss false positives with reasons, and hunt logic flaws. Provider-agnostic (`anthropic` / `openai` / openai-compatible); skipped gracefully with no key.
- **Reporters**: JSON, Markdown, SARIF (for GitHub code scanning), and HTML (single self-contained file, inline CSS, zero dependencies — open it from disk or host it on GitHub Pages) — SARIF is schema-validated in tests.
- **Config**: CLI flags > `redteam.config.js` > `.redteamrc.json` > defaults.
- **Exit codes**: `0` = clean or below threshold · `1` = findings at or above `--fail-on` · `2` = config/usage error.

Commands: `scan [dir]`, `rules list`, `init`. There's also a GitHub Action in `action/`.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design, rule-definition format, and the deliberate v2 deferrals (taint tracking, auto-fix, baseline mode, IDE integration).

## FAQs

**How is this different from Semgrep?**
Three things: (1) the rule corpus is tuned for AI-generated failure modes — the patterns coding agents actually repeat — not a general-purpose grab bag; (2) the LLM attack-agent pass is built in and deeply integrated with the findings, not bolted on; (3) the rule registry is one file per rule and contributor-friendly, designed to take outside checks easily.

**Won't it drown me in false positives?**
That's the failure mode that kills security scanners, so it's engineered against:
- **Fixture gate**: every rule must stay silent on its own `fixed` fixture, enforced in CI. Precision is tested, not hoped for.
- **Severity discipline**: purely syntactic matches cap at `medium` unless corroborated (user-input proximity or LLM confirmation), so `--fail-on high` is usable from day one.
- **LLM as filter, not just finder**: the attack-agent prompt is instructed to dismiss false positives with reasons, not just hunt for more.

**Which languages?**
JavaScript, TypeScript, and Python in v0.

**Do I need an LLM API key?**
No. The static checks (AST queries + secret scanner) run fully offline. Without a key, the attack-agent stage skips with a one-line notice and everything else works unchanged.

**How do I add a rule?**
One file in the rules registry with your tree-sitter queries, severity, message, remediation, and a pair of fixtures (`vulnerable.*` / `fixed.*`). See [CONTRIBUTING.md](CONTRIBUTING.md).

**Can it auto-fix findings?**
No — report-only by design in v0. Auto-remediation is dangerous for a security tool and deliberately deferred to v2.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add rules, run the fixture gate, and submit PRs.

## License

Apache-2.0 — © TamTunnel Contributors.
