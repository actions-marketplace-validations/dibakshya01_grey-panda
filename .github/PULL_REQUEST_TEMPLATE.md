<!-- Thanks for contributing to Grey Panda! 🐼 -->

## What & why
<!-- What does this change and why? Link any issue: Closes #123 -->

## Type
- [ ] 🛡️ New/updated scanner rule
- [ ] 🧰 SDK control
- [ ] 📚 Docs / mappings
- [ ] 🐞 Bug fix
- [ ] ✨ Feature
- [ ] 🧹 Chore / refactor

## Checklist
- [ ] Tests pass locally: `python -m unittest discover -s tests`
- [ ] Grey Panda scans itself clean: `gp scan src --profile enterprise --fail-on HIGH`
- [ ] New scanner rule (if any) has a **bad** example (flagged) **and** a **good** example (passes)
- [ ] New rule/control cites a specific OWASP/AISVS/ACS ID
- [ ] Docs/mappings regenerated if standards changed: `python tools/generate_mappings.py`
- [ ] No real secrets, PII, or customer data in the diff

## Notes for reviewers
<!-- Anything reviewers should focus on -->
