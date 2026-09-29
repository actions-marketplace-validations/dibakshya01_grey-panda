# Changelog

All notable changes to Grey Panda are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-09-29

### Changed
- **Lowered the Python floor to 3.9+** (from 3.10+). The toolkit is stdlib-only and
  runs on Python 3.9, so this widens reach to machines on the system Python (e.g.
  macOS) with no code changes. 3.10–3.13 remain fully supported and recommended.

## [1.0.0] — 2026-09-29

The first public release. 🐼

### Added
- **Five module kits** — the bundle is organised into audience-facing kits
  (Developer, Security Reviewer, Scanner & CI/CD, MCP & Agent Security, Standards &
  Governance), each with its own friendly README and how-to guides, all powered by
  one shared zero-dependency engine.
- **Scanner** (`gp scan`) — **26 high-precision rules** for AI, agent, and MCP risks,
  each citing an OWASP ID, with false-positive suppress guards and per-line /
  per-file ignores. Outputs **Markdown**, **JSON**, and **SARIF 2.1.0** (renders
  inline in VS Code + GitHub code scanning).
- **SDK** (zero dependencies) — `PromptGuardrail`, `OutputGuardrail`, `DLPScanner`,
  `SecureContextBuilder`, `AgentSecurityWrapper` (Rule of Two, HITL, kill switch,
  call budgets), `AuditLogger`, plus **MCP** controls (`McpToolManifest`,
  `McpServerGuard` — manifest pinning/hashing, rug-pull detection, schema/scope/origin
  checks) and **ACS** controls (`Guardian` with five dispositions, `agent_bill_of_materials`).
- **MCP server** (`gp mcp`) — Grey Panda ships as an MCP server (JSON-RPC over stdio)
  so any MCP-capable IDE can call `scan`, `review_snippet`, `explain_risk`,
  `list_standards`, and `checklist`.
- **AISVS verification** (`gp verify`) — check a codebase against AISVS Level 1/2/3
  and produce a signable report.
- **Standards knowledge pack** — machine-readable JSON for OWASP LLM Top 10 2026,
  GenAI Data Security, Agentic Apps Top 10, AISVS (C1–C12), MCP security, and the
  Agent Control Standard; the single source of truth for scanner, verify, MCP, and skill.
- **Integrations & governance** — Claude Code/Cursor skill, GitHub Action (SARIF +
  PR comment + gate), pre-commit hooks, AppSec Reviewer Guide, and an OWASP Threat
  Dragon template.
- **Profiles** — `solo`, `team`, `enterprise`: same safety floor, scaled process.
- **Docs** — README, Quickstart, Profiles, Architecture, standards mappings, and the
  signature **What It Can and Cannot Do** honesty document.
- **Examples** — `vulnerable_app` (flagged) vs `secure_app` (clean) and a full SDK tour.
- **Tests** — 76 zero-dependency `unittest` tests; Grey Panda scans its own repo clean in CI.

[1.0.1]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.1
[1.0.0]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.0
