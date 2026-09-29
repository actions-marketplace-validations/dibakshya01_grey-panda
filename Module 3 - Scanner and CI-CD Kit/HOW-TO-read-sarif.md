# How to read Grey Panda findings inline (SARIF)

SARIF (Static Analysis Results Interchange Format) is the standard that lets tools
render findings **right on the offending line**. Grey Panda emits SARIF 2.1.0.

## Generate it
```bash
gp scan . --format sarif --output grey-panda.sarif
```

## See it in VS Code
1. Install the **SARIF Viewer** extension (Microsoft / MS-SarifVSCode).
2. Open `grey-panda.sarif`. Findings appear in the Problems panel and as squiggles on
   the exact lines, with the rule, OWASP ID, and fix.

## See it in GitHub code scanning
Upload the SARIF in CI (the [generated workflow](HOW-TO-add-to-ci.md) does this):
```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: grey-panda.sarif
    category: grey-panda
```
Findings then show under **Security → Code scanning alerts** and **inline in the PR
diff**, with severity driven by Grey Panda's `security-severity` scores
(CRITICAL≈9.5, HIGH≈8.0, MEDIUM≈5.0, LOW≈2.0).

## What's in the SARIF
- A `rules` table: every Grey Panda rule with its title, description, help text
  (remediation + OWASP ID), and default level.
- A `results` list: one per finding, with file, line, snippet, message (title + fix +
  OWASP ID), and properties (`owasp`, `severity`).

Levels map as: CRITICAL/HIGH → `error`, MEDIUM → `warning`, LOW → `note`.

## Tip
SARIF is also great for dashboards — most security platforms ingest it. If you'd
rather have raw data, use `--format json` for Grey Panda's native schema
(`severity_counts`, `findings[]`, etc.).
