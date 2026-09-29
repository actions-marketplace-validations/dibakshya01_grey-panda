# How to write a Grey Panda scanner rule

Adding a rule is editing **one dataclass** with a bad + good example. Every rule is
standards-anchored and high-precision by design.

## Anatomy of a rule

Rules live in [`src/greypanda/scanner/rules.py`](../src/greypanda/scanner/rules.py):

```python
Rule(
    id="GP-AI-031",                       # sequential; GP-AI / GP-MCP / GP-AGT
    owasp_id="LLM02:2026",                # a specific standard ID (required)
    severity=HIGH,                        # CRITICAL | HIGH | MEDIUM | LOW
    title="Short, specific problem statement",
    description="One sentence: what's wrong and why it matters.",
    remediation="The concrete fix, naming a Grey Panda SDK control if one applies.",
    pattern=r"""(?ix)your-regex-that-matches-the-BAD-form""",
    suppress=r"the-safe-form|# grey-panda: ignore",   # optional guard for the GOOD form
    file_globs=("*.py", "*.js"),          # defaults to ("*.py",)
    sdk="from greypanda import DLPScanner",# optional pointer shown in reports
    profiles=("team", "enterprise"),      # defaults to all three
)
```

## The precision rule: bad **and** good

Every rule must match a **bad** snippet and **not** match the **good** (fixed) form.
The `suppress` regex is how you achieve that — if it matches the same line, the
finding is skipped. Example: the vector-store rule fires on `similarity_search(q)`
but its suppressor `filter=` makes `similarity_search(q, filter=...)` pass.

## Steps

1. Add your `Rule(...)` to the `RULES` list.
2. Add a bad line to [`examples/vulnerable_app/app.py`](../examples/vulnerable_app/app.py)
   and confirm it's flagged:
   ```bash
   gp scan examples/vulnerable_app --profile enterprise
   ```
3. Add the fixed form to [`examples/secure_app/app.py`](../examples/secure_app/app.py)
   and confirm it stays **clean**.
4. If it maps to a standard control, add its ID to the relevant
   `src/greypanda/data/standards/*.json` `scanner_rules` list.
5. Regenerate the docs:
   ```bash
   PYTHONPATH=src python tools/generate_rules_catalog.py
   PYTHONPATH=src python tools/generate_mappings.py
   ```
6. Add/extend a test in `tests/test_scanner.py` (or `tests/test_ignore.py` for a
   precision guard), then run `python -m unittest discover -s tests`.

## Keep it precise
- Anchor where you can (`^\s*`, `\bdef\s+`) so you match the *definition*, not any
  mention.
- Prefer word boundaries (`\bprompt\b`) so you don't match inside identifiers.
- Add a `suppress` for the obvious safe form — a noisy rule gets muted, which helps
  no one.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contributor flow.
