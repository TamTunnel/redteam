# testdata/ — per-rule fixtures

Every built-in rule MUST ship its fixtures here. CI enforces the fixture gate
(see ARCHITECTURE.md §5): a rule that fires on its own `fixed.*` fixture fails CI.

## Convention

```
testdata/<rule-id>/
  vulnerable.js        # MUST trigger the rule (per supported language)
  fixed.js             # MUST NOT trigger the rule
  vulnerable.py
  fixed.py
  vulnerable.ts        # typescript + tsx grammars both cover .ts/.tsx
  fixed.ts
```

- Directory name is exactly the rule `id` (e.g. `testdata/js-eval-injection/`).
- One `vulnerable.*` / `fixed.*` pair per language the rule declares in `languages`.
- File extensions map to tree-sitter grammars: `.js`→javascript, `.ts`/`.tsx`→typescript,
  `.py`→python. A missing pair for a declared language fails CI.
- Keep fixtures minimal: they should demonstrate exactly one instance of the
  pattern and one clean fix, not realistic programs.
- `fixed.*` is the precision contract — it must be genuinely safe code,
  not code that dodges the rule by accident.
