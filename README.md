<div align="center">

<img src="docs/assets/logo.svg" alt="Grey Panda" width="140" />

# 🐼 Grey Panda

### The calm guardian for AI, agent, and MCP code.

**A zero-dependency, standards-anchored AI security toolkit that any developer or security reviewer can run in seconds — in the IDE, in CI, or from the terminal.**

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](.github/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Zero runtime deps](https://img.shields.io/badge/runtime%20deps-0-success)](pyproject.toml)
[![OWASP anchored](https://img.shields.io/badge/OWASP-LLM%20%7C%20Agentic%20%7C%20AISVS%20%7C%20MCP-6f42c1)](docs/mappings)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quick start](#-60-second-quick-start) · [What it does](#what-grey-panda-does) · [Standards](#-standards-anchored-not-opinion-driven) · [In your IDE](#-in-your-ide-the-mcp-server) · [Honest limits](docs/WHAT_IT_CAN_AND_CANNOT_DO.md) · [Contributing](CONTRIBUTING.md)

</div>

---

> _"Stop trying to build a model that cannot be fooled. Build the system around it, so that when the model is fooled — and it will be — nothing important breaks."_

Grey Panda makes **the secure path the easy path** for anyone building LLM-powered, agentic, or Model Context Protocol (MCP) features. It ships a static **scanner**, a drop-in **SDK**, and an **MCP server** — all grounded in published standards, all with **zero runtime dependencies**, all runnable in under a minute.

## Why this exists

Prompt injection is the **#1 AI attack pattern and it requires no authentication** (OWASP LLM Top 10 2026, `LLM01`). Agentic systems can take an *irreversible* action — send money, delete data, call a tool with your credentials — from a *single* injected instruction. And MCP has opened a whole new attack surface: **tool poisoning** and **rug pulls**, where a tool's description or behaviour is crafted or silently swapped to hijack your model.

Most teams know this. What they lack is a way to make the secure choice the *frictionless* choice — for a solo dev shipping an indie project just as much as for an enterprise AppSec team. That's Grey Panda.

## ⚡ 60-second quick start

```bash
pip install grey-panda           # zero dependencies, pure Python
gp scan .                        # scan your repo — beautiful report, real findings
```

Add drop-in guardrails to an existing LLM call in **under two minutes**:

```python
from greypanda import PromptGuardrail, DLPScanner, OutputGuardrail

guard, dlp, out = PromptGuardrail(), DLPScanner(), OutputGuardrail()

safe   = guard.assert_safe(user_input)        # blocks known injection + strips invisible Unicode
clean  = dlp.redact(safe)                      # removes PII & secrets before the model sees them
reply  = call_your_llm(clean)                  # ← your existing call, unchanged
answer = out.sanitize(reply).sanitized_text    # blocks data-exfil image URLs & unsafe HTML
```

That's the whole idea: **you never rewrite your LLM call** — you wrap it.

## What Grey Panda does

| | Pillar | What you get |
|---|---|---|
| 🔍 | **Scanner** (`gp scan`) | ~20 high-precision rules for AI/agent/MCP risks, each citing an OWASP ID. Outputs **Markdown**, **JSON**, and **SARIF** (renders inline in VS Code + GitHub code scanning). |
| 🧰 | **SDK** (drop-in) | `PromptGuardrail`, `DLPScanner`, `OutputGuardrail`, `SecureContextBuilder`, `AgentSecurityWrapper`, `AuditLogger`, plus **MCP** (`McpServerGuard`, manifest pinning) and **ACS** (`Guardian`, AgBOM). |
| 🤖 | **MCP server** (`gp mcp`) | Grey Panda *secures* MCP — and ships **as** an MCP server, so Claude Code, Cursor, Windsurf, or VS Code can call it while you code. |
| ✅ | **AISVS verify** (`gp verify`) | Check a codebase against AISVS **Level 1 / 2 / 3** and produce a signable report. |
| 🛡️ | **CI/CD + governance** | One-command GitHub Action, pre-commit hook, AppSec reviewer guide, and OWASP Threat Dragon templates. |

### See it work: before → after

```bash
gp scan examples/vulnerable_app --profile enterprise    # 🔴 7 critical · 🟠 7 high
gp scan examples/secure_app     --profile enterprise    # ✅ no findings
```

The two example apps are line-for-line comparable — [`vulnerable_app`](examples/vulnerable_app/app.py) is what insecure AI code looks like; [`secure_app`](examples/secure_app/app.py) is the same app rebuilt with Grey Panda controls. A sample finding:

```markdown
### 🔴 `GP-AI-001` User input interpolated directly into a prompt string
**OWASP:** LLM01:2026  ·  **Severity:** CRITICAL  ·  `app.py:30`

- **Issue:** Untrusted user input is f-string-ed straight into a prompt, collapsing
  the boundary between instructions and data.
- **Fix:** Build context with SecureContextBuilder.add_user(); never f-string user input into a prompt.
- **SDK:** `from greypanda import SecureContextBuilder`
```

## 🔐 Standards-anchored, not opinion-driven

Every rule, checklist item, and SDK control cites a specific ID. No bare assertions.

| Standard | Coverage |
|---|---|
| **OWASP Top 10 for LLM Applications 2026** | `LLM01`–`LLM10` |
| **OWASP GenAI Data Security 2026** | `DSGAI01`–`DSGAI21` |
| **OWASP Top 10 for Agentic Applications 2026** | `ASI01`–`ASI10` |
| **OWASP AI Security Verification Standard (AISVS)** | `C1`–`C12`, Levels L1/L2/L3 |
| **OWASP Secure MCP Server Development** + **Third-Party MCP** | 8 control domains + minimum bar |
| **Agent Control Standard (ACS)** | Guardian hooks, 5 dispositions, AgBOM |
| **NIST AI 100-2**, **Meta "Rule of Two"** / lethal trifecta | Deterministic mediation, agent design constraint |

Full mapping tables live in [`docs/mappings/`](docs/mappings). Explore any control from the CLI:

```bash
gp standards LLM01:2026      # explain a control + its Grey Panda fix
gp standards                 # list every standard and control ID
```

## 🤝 In your IDE: the MCP server

Register Grey Panda once and call it from your AI editor while you code:

```jsonc
// Claude Code / Cursor / Windsurf MCP config
{ "mcpServers": { "grey-panda": { "command": "gp", "args": ["mcp"] } } }
```

Then ask your assistant to `review this file with grey panda` or `explain LLM03`. Exposed tools: `greypanda_scan_path`, `greypanda_review_snippet`, `greypanda_explain_risk`, `greypanda_list_standards`, `greypanda_checklist`.

## 👥 One tool, three audiences

Same safety floor for everyone; the **profile scales the process, not the safety**.

| Profile | For | Gate |
|---|---|---|
| `solo` | Indie / solo devs | High-signal core rules, fail on **CRITICAL** |
| `team` | Startups & teams | + DLP, RAG isolation, logging, MCP, shadow-AI · fail on **HIGH** |
| `enterprise` | Regulated / large orgs | Every rule + AppSec gate + AISVS L1/L2/L3 · fail on **HIGH** |

```bash
gp scan . --profile solo
gp init  . --profile team          # scaffold config + GitHub Action + pre-commit
gp verify . --level 2              # AISVS Level 2 verification report
```

## 🏛️ Architecture

```
                          🐼 GREY PANDA
   ┌──────────────────────────────────────────────────────────┐
   │  standards/ knowledge pack — every OWASP/AISVS/ACS/MCP    │
   │  control ID → fix → citation (one source of truth)        │
   └──────────────────────────────────────────────────────────┘
        │                     │                      │
   ┌────▼─────┐         ┌─────▼──────┐        ┌──────▼───────┐
   │ SCANNER  │         │    SDK     │        │ INTEGRATIONS │
   │ gp scan  │         │ guardrails │        │ Claude/Cursor│
   │ md/json/ │         │ dlp/context│        │ skill        │
   │ SARIF    │         │ agent/audit│        │ MCP server   │
   │ GP-AI-## │         │ mcp / acs  │        │ GitHub Action│
   └────┬─────┘         └─────┬──────┘        └──────┬───────┘
        │                     │                      │
   ┌────▼─────────────────────▼──────────────────────▼────────┐
   │  DEVELOPER → CI/CD GATE → APPSEC REVIEW → PRODUCTION      │
   └───────────────────────────────────────────────────────────┘
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design.

## 🧭 Honest about limits

Grey Panda is a **strong floor, not a ceiling**. Pattern matching cannot stop *all* prompt injection; regex DLP is language-specific; static analysis has false positives and negatives. We ship a whole document about exactly what Grey Panda **can and cannot do**, with confidence levels and failure conditions for every capability: **[docs/WHAT_IT_CAN_AND_CANNOT_DO.md](docs/WHAT_IT_CAN_AND_CANNOT_DO.md)**. Read it before you rely on the tool.

## 📦 Install

```bash
pip install grey-panda           # from PyPI
pipx install grey-panda          # isolated CLI
uvx grey-panda scan .            # zero-install run
```

Or from source:

```bash
git clone https://github.com/greypanda/grey-panda && cd grey-panda
pip install -e ".[dev]"
python -m unittest discover -s tests    # 69 tests, zero deps
```

## 🗺️ Command reference

| Command | Does |
|---|---|
| `gp scan [path]` | Scan for AI/agent/MCP issues (`--profile`, `--format md/json/sarif`, `--fail-on`) |
| `gp init [path]` | Scaffold config, GitHub Action, and pre-commit into a repo |
| `gp verify [path]` | AISVS Level 1/2/3 verification report |
| `gp checklist` | Print the AI security checklist |
| `gp standards [id]` | List or explain standards / control IDs |
| `gp agbom <agent>` | Emit an Agent Bill of Materials |
| `gp mcp` | Run Grey Panda as an MCP server (stdio) |
| `gp doctor` | Environment self-check + honest-limits pointer |

## 🌱 Contributing

Grey Panda is built to be extended — adding a scanner rule is editing one dataclass with a bad + good example. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [`good first issue`](https://github.com/greypanda/grey-panda/labels/good%20first%20issue) label. Everyone is welcome under our [Code of Conduct](CODE_OF_CONDUCT.md).

Found a security issue in Grey Panda itself? See [SECURITY.md](SECURITY.md).

## 📄 License

[Apache-2.0](LICENSE). Standards cited are the property of their respective authors (see [NOTICE](NOTICE)). OWASP® is a registered trademark of the OWASP Foundation; Grey Panda is an independent, community project and is not affiliated with or endorsed by OWASP.

<div align="center">
<sub>🐼 Grey Panda — make the secure path the easy path.</sub>
</div>
