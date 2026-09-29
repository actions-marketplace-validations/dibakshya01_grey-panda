# Contributing to Grey Panda 🐼

Thank you — Grey Panda gets better every time someone adds a rule, sharpens a
control, or improves the docs. This project is built to be *easy to extend*.

## Ground rules
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Never** include real secrets, PII, or customer data in issues, PRs, or tests.
- Every rule and control **cites a specific standard ID** (OWASP/AISVS/ACS). No bare assertions.
- Keep the shipped package **zero-dependency** (standard library only). Dev tools are extras.

## Dev setup
```bash
git clone https://github.com/dibakshya01/grey-panda && cd grey-panda
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v      # zero-dependency test suite
gp scan . --profile enterprise --fail-on HIGH    # dogfood: Grey Panda scans itself
```

## Add a scanner rule (the most common contribution)
1. Append a `Rule(...)` to `src/greypanda/scanner/rules.py`:
   - a sequential `id` (`GP-AI-###`, `GP-MCP-###`, or `GP-AGT-###`),
   - a specific `owasp_id`,
   - a `severity` with justification (in the PR),
   - a `pattern` that matches a **bad** sample,
   - a `suppress` guard so the **good** sample passes,
   - a `remediation` naming the Grey Panda SDK control that fixes it.
2. Add a bad snippet to `examples/vulnerable_app/` and confirm it's flagged; add the
   fixed form to `examples/secure_app/` and confirm it stays **clean**.
3. Add/extend a test in `tests/test_scanner.py`.
4. If you touched a standards JSON, run `python tools/generate_mappings.py`.

Every rule must be **testable against a sample bad and a sample good snippet.**

## Add an SDK control
Each module follows one pattern: one class per control, a dataclass for results,
zero external dependencies, an OWASP ID in the module docstring, and (where it
produces an event) a matching `log_*` method on `AuditLogger`. Add tests.

## Add / update a standard
Edit the JSON in `src/greypanda/data/standards/`, keep the entry schema (see
[`standards/README.md`](standards/README.md)), then regenerate the mapping docs.

## Commit & PR
- Small, focused PRs. Fill in the PR template checklist.
- Tests must pass and Grey Panda must scan itself clean.
- Conventional-ish commit messages are appreciated (`feat:`, `fix:`, `docs:`, `rule:`).

## Good first issues
Look for the [`good first issue`](https://github.com/dibakshya01/grey-panda/labels/good%20first%20issue)
label — adding a new rule from the [`new_rule`](.github/ISSUE_TEMPLATE/new_rule.yml)
template is a great start.
