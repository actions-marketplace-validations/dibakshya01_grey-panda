# How to add Grey Panda to your CI/CD

## The one-command way

```bash
gp init .
```
This scaffolds, into your repo:
- `.github/workflows/grey-panda.yml` — the PR gate (SARIF upload + PR comment + fail on HIGH+)
- `.greypanda.toml` — your profile + threshold config
- `greypanda-precommit.snippet.yaml` — a ready-to-paste pre-commit hook

Pick your rigor with `--profile solo|team|enterprise` (default `team`).

## GitHub Actions (what the gate does)

The generated workflow:
1. Installs Grey Panda (`pip install grey-panda`).
2. Scans → **SARIF**, uploaded to code scanning so findings show **inline in the PR diff**.
3. Scans → **Markdown**, posted as a PR comment.
4. Enforces the gate: **fails the build on HIGH+**.

It needs these permissions (already set in the generated file):
```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write   # required to upload SARIF
```

## Pre-commit (catch it before you push)

```bash
pip install pre-commit
# add the snippet from `gp init` to .pre-commit-config.yaml, then:
pre-commit install
```
Now `gp scan --fail-on HIGH` runs on every commit.

## Tuning the gate

- **Threshold:** `--fail-on CRITICAL|HIGH|MEDIUM|LOW` (defaults to the profile's).
- **Scope:** commit a `.greypandaignore` (gitignore-style) to exclude vendored code,
  fixtures, or intentionally-insecure demos.
- **Per-line:** append `# grey-panda: ignore` to a line you've reviewed and accepted.

## Other CI systems

Grey Panda is just a CLI with a zero/one exit code, so any runner works:

```bash
# GitLab CI / CircleCI / Jenkins step
pip install grey-panda
gp scan . --profile team --fail-on HIGH
```
For inline findings, produce SARIF (`--format sarif -o gp.sarif`) and hand it to your
platform's code-scanning ingestion.

## What this does not do
CI scanning is a **gate at PR/commit cadence**, not continuous runtime monitoring,
and it inherits the scanner's static-analysis limits. Pair the gate with the runtime
SDK ([Module 1](../Module%201%20-%20Developer%20Kit)) and a human review
([Module 2](../Module%202%20-%20Security%20Reviewer%20Kit)) for high-stakes features.
