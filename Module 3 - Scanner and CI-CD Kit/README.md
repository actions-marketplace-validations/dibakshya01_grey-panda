# 🔍 Module 3 — Scanner & CI/CD Kit

> **For:** platform, DevOps, and anyone who wants AI security **enforced
> automatically** — in CI, in pre-commit, and in the PR diff.
> **Goal:** catch AI/agent/MCP risks before they merge, with signal not noise.

---

## What's in this kit

| Piece | What it does |
|---|---|
| **`gp scan`** | Static scanner: **26 high-precision rules** → OWASP IDs, in Markdown / JSON / SARIF. |
| **[RULES_CATALOG.md](RULES_CATALOG.md)** | Every rule, its severity, standard mapping, and fix (auto-generated from code). |
| **[HOW-TO-add-to-ci.md](HOW-TO-add-to-ci.md)** | Wire the GitHub Action, pre-commit, and the gate. |
| **[HOW-TO-read-sarif.md](HOW-TO-read-sarif.md)** | Get findings inline in VS Code + GitHub code scanning. |
| **[HOW-TO-write-a-rule.md](HOW-TO-write-a-rule.md)** | Add your own rule in a few lines. |

## Run it

```bash
gp scan .                                   # Markdown report to your terminal
gp scan . --format sarif -o gp.sarif        # for IDE / code scanning
gp scan . --format json  -o gp.json         # for pipelines
gp scan . --fail-on HIGH                    # exit 1 if any finding is HIGH+
gp scan . --profile enterprise              # turn every rule on
```

## Signal, not noise

A scanner people mute is worthless. Grey Panda keeps precision high with three
mechanisms:

- **Suppress guards** — the *safe* form of a pattern passes cleanly (e.g. a vector
  query *with* a user filter isn't flagged).
- **Profiles** — `solo` runs only the highest-signal rules; `team`/`enterprise` add more.
- **Ignores** — silence a line with `# grey-panda: ignore`, or a path with a
  `.greypandaignore` file (gitignore-style). Grey Panda uses this on itself, so it
  **scans its own repo clean** in CI.

## Rule ID scheme

| Prefix | Area |
|---|---|
| `GP-AI-###` | General LLM / data-security rules |
| `GP-MCP-###` | Model Context Protocol rules |
| `GP-AGT-###` | Agentic-application rules |

Every rule cites a specific OWASP / AISVS / ACS ID and names the Grey Panda control
that fixes it. See **[RULES_CATALOG.md](RULES_CATALOG.md)**.

## ✅ What this kit can do — and ❌ what it can't

**Can:** find hardcoded secrets, unsafe output rendering, missing HITL gates,
unpinned AI deps, shadow-AI endpoints, RAG-without-filter, MCP RCE sinks, tool
poisoning markers, unsafe deserialization, and more — fast, in CI, with SARIF.

**Cannot:** understand runtime behaviour (it's static), follow data across functions
(no taint tracking), or cover every language equally (it's Python-centric, with
partial coverage for JS/TS via secrets/HTTP/output rules). Expect some false
positives on benign code and false negatives on obfuscated patterns. Full honesty:
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
