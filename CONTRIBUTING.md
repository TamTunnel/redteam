# Contributing

## Dev setup

Requirements: **Node 20+** (CI runs 20, 22, 24).

```sh
npm install
npm run build     # tsc -b (project references)
npm test          # vitest run
npm run typecheck # tsc --noEmit
```

## Adding a rule

One file per rule in `packages/core/src/rules/builtin/`, registered in the
registry, written with `defineRule()` (see `ARCHITECTURE.md` §3).

**Every rule MUST ship fixtures** in `testdata/<rule-id>/`:

- `vulnerable.<ext>` — minimal code that MUST trigger the rule.
- `fixed.<ext>` — minimal safe code that MUST NOT trigger the rule.

One pair per language the rule declares. CI runs the **fixture gate**:
the suite fails if the rule fires on its own `fixed.*` fixture. A rule
without fixtures is rejected in review — precision is tested, not hoped for.

Keep the severity discipline from `ARCHITECTURE.md` §5 in mind: purely
syntactic matches cap at `medium` unless corroborated.

## Release notes (changesets-style)

Describe your change in the PR body under a `## Release notes` heading:

```md
## Release notes
- `rule/js-hardcoded-secret`: added high-severity secret rule for JS/TS.
- `cli`: `--format sarif` now writes to stdout by default.
```

Use package-scoped bullet points (`rule/<id>`, `cli`, `core`, `action`).
The release agent compiles these into the changelog at publish time.
