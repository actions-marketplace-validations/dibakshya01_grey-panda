# Changelog

All notable changes to Grey Panda are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] — 2026-09-29

Hardening pass in response to an adversarial pre-announcement code review.

### Fixed / changed
- **`OutputGuardrail` now actually neutralises XSS.** It strips/flags `<script>`,
  inline event handlers, `javascript:`/`data:` URIs and embed tags (not just
  external-image URLs), and adds `escape_html=True` for full safety. Every
  "blocks unsafe HTML" claim in the docs is corrected to describe exactly what it
  does. **This closes a false-assurance issue** — the previous version claimed HTML
  protection it did not provide.
- **`PromptGuardrail` no longer rejects legitimate emoji/Indic text.** ZWJ/ZWNJ are
  left intact; only genuinely-dangerous invisibles (bidi overrides/isolates, tag
  chars) are flagged and stripped; benign zero-width chars are stripped silently.
- **Scanner false positive on the recommended secure pattern fixed.** `suppress`
  now honours a small multi-line window, so a `redact()` or `max_tokens` on a
  nearby/wrapped line correctly suppresses `GP-AI-003` / `GP-AI-012`. `secure_app`
  now *satisfies* the rules with a real client call instead of hiding behind a
  wrapper.
- **Lightweight model-taint tracking** catches flagship SQL/exec and HTML sinks fed
  from a model call even when the variable isn't named with a trigger keyword.
- **`SecureContextBuilder` hardened:** per-call nonce fence delimiters, breakout
  tokens stripped, and untrusted content placed under the `user` role (never
  `system`).
- **`.greypanda.toml` is now read** by `gp scan` (profile / fail_on).
- **Self-scan hardened:** `guardrails.py` and `mcp.py` are scanned (line-level
  ignores on signature lines only) instead of whole-file excluded.
- **DLP:** IPv4 moved to an opt-in `network` category; SSN/card/national-ID matches
  are fully masked in reports.
- **SARIF:** fixed the 404 `helpUri` and emit repo-relative URIs with `uriBaseId`.
- **Metadata honesty:** Development Status → Beta; real maintainer handle in
  `authors` and `CODEOWNERS`.
- **Packaging:** `examples/` (with intentional fake secrets) excluded from the
  sdist so `pip download` doesn't trip consumers' secret scanners.
- **CI:** type-checking is a visibly-advisory step rather than masked by `|| true`.

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

[1.0.2]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.2
[1.0.1]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.1
[1.0.0]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.0
