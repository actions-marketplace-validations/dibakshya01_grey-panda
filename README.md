<!-- ╔══════════════════════════════════════════════════════════════════╗ -->
<!-- ║  🐼 GREY PANDA — README pitch deck. Slides live in docs/assets/.  ║ -->
<!-- ╚══════════════════════════════════════════════════════════════════╝ -->

<p align="center">
  <img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/hero.png" alt="Grey Panda — the calm guardian for AI, agent, and MCP code" width="100%" />
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/License-Apache%202.0-1c222a?style=for-the-badge&labelColor=1c222a&color=12b886"></a>
  <a href="pyproject.toml"><img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-1c222a?style=for-the-badge&labelColor=1c222a&color=3f4753"></a>
  <a href="pyproject.toml"><img alt="Zero runtime dependencies" src="https://img.shields.io/badge/runtime%20deps-0-1c222a?style=for-the-badge&labelColor=1c222a&color=12b886"></a>
  <a href="Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md"><img alt="Deterministic — no LLM in the loop" src="https://img.shields.io/badge/deterministic-no%20LLM%20in%20the%20loop-1c222a?style=for-the-badge&labelColor=1c222a&color=12b886"></a>
  <a href="Module%204%20-%20MCP%20and%20Agent%20Security%20Kit/HOW-TO-run-the-mcp-server.md"><img alt="MCP-ready — ships as an MCP server" src="https://img.shields.io/badge/MCP-ready%20·%20ships%20as%20a%20server-1c222a?style=for-the-badge&labelColor=1c222a&color=12b886"></a>
  <a href="Module%205%20-%20Standards%20and%20Governance%20Kit/mappings"><img alt="OWASP anchored" src="https://img.shields.io/badge/OWASP-LLM·Agentic·AISVS·MCP-1c222a?style=for-the-badge&labelColor=1c222a&color=3f4753"></a>
  <a href="CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-1c222a?style=for-the-badge&labelColor=1c222a&color=12b886"></a>
</p>

<p align="center">
  <b>A zero-dependency, standards-anchored AI security toolkit that any developer or security reviewer can run in seconds — in the IDE, in CI, or from the terminal.</b>
</p>

<p align="center">
  <sub>🔌 <b>MCP-native.</b> Grey Panda <i>secures</i> MCP <b>and ships as an MCP server</b> — wire it into Claude Code, Cursor, Windsurf, or VS Code with one command and review code without leaving your editor. <a href="#-in-your-ide">Jump to setup ↓</a></sub>
</p>

<p align="center">
  <sub>👋 <b>Not a developer?</b> Start with the <a href="ELI5.md">ELI5 — a plain-English explainer for non-technical readers &amp; leaders</a> (no jargon).</sub>
</p>

<p align="center">
  <sub><b>Deterministic by design — no LLM in the loop.</b> Same code, same verdict, every run; fully offline, private, and free. Your CI gate never flakes and your source never leaves your machine.</sub>
</p>

<p align="center">
  <a href="ELI5.md">ELI5 (non-technical)</a> ·
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-whats-in-the-bundle">The bundle</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-standards-anchored">Standards</a> ·
  <a href="#-in-your-ide">In your IDE</a> ·
  <a href="Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md">Honest limits</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/demo.gif" alt="Grey Panda in action: scan a vulnerable app, then the same app rebuilt clean" width="84%" />
</p>

---

> _"Stop trying to build a model that cannot be fooled. Build the system around it, so that when the model is fooled — and it will be — nothing important breaks."_

Grey Panda makes **the secure path the easy path** for anyone building LLM-powered, agentic, or Model Context Protocol (MCP) features — from a solo indie developer to an enterprise AppSec team.

## ⚡ Quick start

```bash
pip install grey-panda        # pure Python, zero dependencies
gp scan .                     # scan your repo — real findings, beautiful report
```

Add drop-in guardrails to an existing LLM call in **under two minutes** — you never rewrite the call, you wrap it:

```python
from greypanda import PromptGuardrail, DLPScanner, OutputGuardrail

guard, dlp, out = PromptGuardrail(), DLPScanner(), OutputGuardrail()

safe   = guard.assert_safe(user_input)        # block known injection + strip invisible Unicode
clean  = dlp.redact(safe)                       # remove PII & secrets before the model sees them
reply  = call_your_llm(clean)                   # ← your existing call, unchanged
answer = out.sanitize(reply).sanitized_text     # XSS-safe by default (HTML-escapes model output)
```

---

## 🎯 Why this exists

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-1-problem.png" alt="The problem: AI ships a new, mostly-unguarded attack surface" width="100%"></p>

Prompt injection is the **#1 AI attack pattern and it needs no authentication** (OWASP `LLM01`). Agentic systems can take an *irreversible* action from a *single* injected instruction. And MCP has opened a whole new surface — **tool poisoning** and **rug pulls**. Your existing AppSec tools don't see any of it.

## 🐼 The idea: one calm guardian

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-2-solution.png" alt="One calm guardian — the secure path becomes the easy path" width="100%"></p>

Grey Panda keeps two rare qualities as non-negotiable: **intellectual honesty** (a whole doc on what it [can and cannot do](Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md)) and **standards-anchoring** (every rule cites an OWASP ID). No neon-hacker theatre — just controls that are a joy to adopt.

## 📦 What's in the bundle

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-3-modules.png" alt="Five kits, one engine" width="100%"></p>

Five audience-facing **module kits**, all powered by one shared, zero-dependency engine:

| Kit | For | Start here |
|---|---|---|
| 🧰 **[Module 1 — Developer Kit](Module%201%20-%20Developer%20Kit)** | Building AI features | Drop-in SDK + IDE integration |
| 🛡️ **[Module 2 — Security Reviewer Kit](Module%202%20-%20Security%20Reviewer%20Kit)** | Reviewing / gating | AISVS verify, threat models, sign-off |
| 🔍 **[Module 3 — Scanner & CI/CD Kit](Module%203%20-%20Scanner%20and%20CI-CD%20Kit)** | Platform / DevOps | 27 rules, SARIF, GitHub Action |
| 🤖 **[Module 4 — MCP & Agent Security Kit](Module%204%20-%20MCP%20and%20Agent%20Security%20Kit)** | Agents & MCP | Rule of Two, HITL, manifest pinning, ACS |
| 📚 **[Module 5 — Standards & Governance Kit](Module%205%20-%20Standards%20and%20Governance%20Kit)** | Everyone / compliance | Knowledge pack, mappings, Can/Cannot-Do |

## ⚙️ How it works

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-4-pipeline.png" alt="A 7-step request pipeline" width="100%"></p>

Defense in depth, not prevention theatre. Full walkthrough: **[HOW-TO-add-guardrails](Module%201%20-%20Developer%20Kit/HOW-TO-add-guardrails.md)** · architecture: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## 🔐 Standards-anchored

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-5-standards.png" alt="Standards anchored, not opinion-driven" width="100%"></p>

Every rule, checklist item, and SDK control cites a specific ID. Explore any control from the CLI:

```bash
gp standards LLM01:2026      # explain a control + its Grey Panda fix
gp standards                 # list every standard and control ID
```

Full mapping tables: **[Module 5 → mappings/](Module%205%20-%20Standards%20and%20Governance%20Kit/mappings)**.

## ✅ Proof

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-6-proof.png" alt="Spotless by construction — scans itself clean" width="100%"></p>

See the before/after for yourself — the same app, insecure vs. rebuilt with Grey Panda controls:

```bash
gp scan examples/vulnerable_app --profile enterprise    # 🔴 findings
gp scan examples/secure_app     --profile enterprise    # ✅ clean
```

## 👥 For everyone

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-7-audiences.png" alt="Same safety floor, scaled process" width="100%"></p>

```bash
gp scan . --profile solo          # high-signal core, fail on CRITICAL
gp init  . --profile team         # scaffold config + GitHub Action + pre-commit
gp verify . --level 2             # AISVS Level 2 verification report
```

More: **[Module 1 → PROFILES](Module%201%20-%20Developer%20Kit/PROFILES.md)**.

## 🚀 Get started

<p align="center"><img src="https://raw.githubusercontent.com/dibakshya01/grey-panda/main/docs/assets/slide-8-start.png" alt="Two minutes to safer AI" width="100%"></p>

```bash
pip install grey-panda           # from PyPI
pipx install grey-panda          # isolated CLI
uvx grey-panda scan .            # zero-install run
```

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

## 🚀 Use as a GitHub Action

Grey Panda ships as a composite GitHub Action — drop it into any workflow to gate pull requests on AI/agent/MCP findings, with SARIF rendered inline in the PR diff:

```yaml
- uses: dibakshya01/grey-panda@v1
  with:
    path: .            # file or directory to scan
    profile: team      # solo | team | enterprise
    fail-on: HIGH      # CRITICAL | HIGH | MEDIUM | LOW
    format: sarif      # markdown | json | sarif
    output: grey-panda.sarif
```

Pair it with `github/codeql-action/upload-sarif@v3` to surface findings in **Security → Code scanning**. All inputs are optional; the defaults above are the recommended CI baseline.

## 🤝 In your IDE

Grey Panda *secures* MCP — and ships **as** an MCP server, so Claude Code, Cursor, Windsurf, or VS Code can call it while you code. One command wires it into Claude Code:

```bash
claude mcp add grey-panda -- gp mcp
```

<sub>Cursor / Windsurf / VS Code use a tiny config file — see the how-to. The server is <b>deterministic</b>: the model in your IDE does the reasoning, Grey Panda hands back reproducible, OWASP-cited findings.</sub>

Then ask your assistant *"review this file with grey panda"*, *"are we AISVS Level 2 ready?"*, or *"explain LLM01:2026"*. It exposes six tools — scan, review-snippet, verify, explain-risk, list-standards, checklist. Details: **[Module 1 → HOW-TO-use-in-your-ide](Module%201%20-%20Developer%20Kit/HOW-TO-use-in-your-ide.md)** and **[Module 4 → HOW-TO-run-the-mcp-server](Module%204%20-%20MCP%20and%20Agent%20Security%20Kit/HOW-TO-run-the-mcp-server.md)**.

## 🧭 Honest about limits

Grey Panda is a **strong floor, not a ceiling**. Pattern matching cannot stop *all* prompt injection; regex DLP is language-specific; static analysis has false positives and negatives. We ship a whole document — with a confidence level and failure condition for **every** capability: **[WHAT_IT_CAN_AND_CANNOT_DO.md](Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md)**. Read it before you rely on the tool.

## 🌱 Contributing

Adding a scanner rule is editing **one dataclass** with a bad + good example — see **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[Module 3 → HOW-TO-write-a-rule](Module%203%20-%20Scanner%20and%20CI-CD%20Kit/HOW-TO-write-a-rule.md)**. Everyone is welcome under our [Code of Conduct](CODE_OF_CONDUCT.md). Found a vulnerability in Grey Panda itself? See [SECURITY.md](SECURITY.md).

Build from source:

```bash
git clone https://github.com/dibakshya01/grey-panda && cd grey-panda
pip install -e ".[dev]"
python -m unittest discover -s tests        # zero-dependency test suite
gp scan . --profile enterprise --fail-on HIGH   # Grey Panda scans itself, clean
```

## 📄 License

[Apache-2.0](LICENSE). Standards cited are the property of their respective authors (see [NOTICE](NOTICE)). OWASP® is a registered trademark of the OWASP Foundation; Grey Panda is an independent, community project and is not affiliated with or endorsed by OWASP.

<p align="center"><sub>🐼 <b>Grey Panda</b> — make the secure path the easy path.</sub></p>
