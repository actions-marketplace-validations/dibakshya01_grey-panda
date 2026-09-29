# Changelog

All notable changes to Grey Panda are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.5] — 2026-09-30

Round-3 hardening, driven by a third adversarial review — plus honest-labeling
polish and a positive framing of the tool's determinism.

### Fixed
- **Catastrophic ReDoS in `PromptGuardrail` is closed.** The baseline HTML-comment
  injection pattern used nested `.*?` quantifiers (`<!--.*?(?:instruction|system|
  ignore).*?-->`); a crafted ~30 KB input drove the regex engine into pathological
  backtracking (>20 s hang — a trivial denial-of-service against the guardrail
  itself). It is now a bounded, linear pattern (`<!--[^>]{0,200}(?:instruction|
  system|ignore)`), and `check()` never hands an unbounded attacker string to the
  pattern engine (`to_match = cleaned[:max_chars]`). The same 30 KB input now
  completes in ~0.04 s and real injections are still detected. A
  `TestGuardrailReDoS` regression test asserts sub-second completion so this cannot
  silently return.

### Changed
- **Honest labeling.** `gp verify` no longer prints "pass" for a scanner-clean
  control — a clean scan means "no violation *detected*," not "control present," so
  those now read **"checked"** (☑️, "no violation detected") with an explicit callout
  that checked ≠ implemented. The Can/Cannot-Do doc softens "known phrasings: High"
  to "exact known phrasings; close paraphrases slip," and reframes the Rule-of-Two
  wrapper as enforcing "the constraint you declare." The `Guardian` default
  disposition docstring now warns it is fail-OPEN and recommends
  `default=Disposition.DENY`.
- **Determinism, framed as the strength it is.** README, the website (hero, docs,
  and architecture pages), `ARCHITECTURE.md`, and the Can/Cannot-Do doc now state
  plainly that the core makes **no LLM calls** on purpose: reproducible verdicts (a
  gate that never flakes), fully offline (source never leaves the machine), free,
  fast, and auditable. Semantic AI review is positioned as an explicit opt-in via
  the MCP server, never baked into the deterministic gate.
- The scanner caps per-line length (`_MAX_LINE_LEN = 5_000`) before applying rule
  patterns, as defense-in-depth against pathological single-line inputs, and the
  sdist no longer ships `/tests`.

## [1.0.4] — 2026-09-30

### Changed
- **`GP-AI-003` ("no DLP before an LLM call") is now an enterprise-only, MEDIUM
  advisory** (was a `team`+ HIGH rule). Whether a specific call's data was redacted
  cannot be *proven* by static analysis without whole-program dataflow, so rather
  than dress a proximity heuristic up as a precise finding, it surfaces as a note
  that never gates a build. The real control is the runtime `DLPScanner` (or a
  DLP-enforcing gateway). Docs/profiles updated accordingly.

## [1.0.3] — 2026-09-30

Round-2 hardening, driven by a second adversarial review — and, crucially, an
adversarial test suite so these cannot silently regress.

### Fixed
- **`OutputGuardrail` is now safe by default.** `escape_html` defaults to `True`:
  `sanitize()` HTML-escapes output, which is XSS-safe. The previous regex default
  was bypassable (`<svg/onload>`, `<body/onload>`, `javascript:` cookie-exfil, CSS
  `expression()`) yet reported `passed=True` — false confidence. The opt-in
  best-effort regex mode now **fails closed** (escapes) on any detected construct
  and its detection is broadened; docs teach the safe default.
- **The CI gate can no longer fail open on a config typo.** `profile`/`fail_on`
  from `.greypanda.toml` are validated up front (exit 2 on an unknown value), and
  `exceeds_threshold` fails closed on an unrecognised severity.
- **Adversarial test suite added** (`tests/test_adversarial.py`): an XSS
  cheat-sheet corpus, config-typo → exit-code assertions, function-scoped taint
  FP/FN fixtures, and fence-breakout/truncation tests. CI gates on them. (76 → 87 tests.)
- **Taint tracking is now function-scoped (`ast`-based)** — no more cross-function
  false positives from same-named variables. Python-only sinks only (the JS-only
  sinks were removed from the Python pass; the catalog no longer implies coverage
  it lacks).
- **`SecureContextBuilder` truncation re-appends the closing fence**, so oversized
  untrusted content is never left in an unterminated fence.
- **`.greypanda.toml` `paths` is now honoured** by `gp scan` (was parsed but unused).

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

[1.0.4]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.4
[1.0.3]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.3
[1.0.2]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.2
[1.0.1]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.1
[1.0.0]: https://github.com/dibakshya01/grey-panda/releases/tag/v1.0.0
