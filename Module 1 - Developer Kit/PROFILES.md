# Profiles: Solo, Team, Enterprise

Grey Panda gives **everyone the same safety floor** and lets the **profile scale the
process, not the safety**. A solo developer isn't drowned in process; an enterprise
gets the full gate. Pick a profile with `--profile` (default: `team`).

| Profile | For | Active rules | Fails build on |
|---|---|---|---|
| `solo` | Indie / solo developers, prototypes, hackathons | High-signal core (CRITICAL + key HIGH) | **CRITICAL** |
| `team` | Startups, product teams | + RAG isolation, no-raw-logging, MCP, shadow-AI | **HIGH** |
| `enterprise` | Regulated / large orgs | Every rule + MEDIUM advisories (cost/consumption, memory-poisoning, DLP-before-call reminder) + AISVS L1/L2/L3 | **HIGH** |

## Solo
```bash
gp scan . --profile solo
```
Quiet and precise. Only the rules a single developer must not ship without. No CI,
no reviewer process required — though `gp init --profile solo` still gives you a
one-file GitHub Action if you want it.

## Team
```bash
gp init . --profile team      # config + GitHub Action + pre-commit
gp scan . --profile team
```
Adds the controls a team sharing a codebase needs: DLP before model calls, RAG
per-user isolation, no-raw-logging, MCP tool checks, and shadow-AI detection. The
gate fails on HIGH so risky code doesn't merge.

## Enterprise
```bash
gp scan   . --profile enterprise
gp verify . --level 2
```
Everything on, including MEDIUM cost/consumption and agent-memory checks, plus the
AppSec reviewer workflow and AISVS verification. Pair with the
[AppSec Reviewer Guide](../Module%202%20-%20Security%20Reviewer%20Kit/APPSEC_REVIEWER_GUIDE.md).

## Configuring
`gp init` writes a `.greypanda.toml` you can commit:
```toml
[greypanda]
profile = "team"
fail_on = "HIGH"
paths = ["."]
```

## Customising rules for your domain
- **DLP:** enable regional packs (`regional_in`, `regional_eu`) or add your customer/
  order/seller ID formats via `custom_patterns` (see `dlp.py`).
- **Injection:** pass `extra_patterns` to `PromptGuardrail` for domain-specific attacks.
- **Scanner:** add a `Rule` to `src/greypanda/scanner/rules.py` (see [CONTRIBUTING](../CONTRIBUTING.md)).
- **Gateway allowlist:** add your AI gateway domain so `GP-AI-013` stops flagging it.
