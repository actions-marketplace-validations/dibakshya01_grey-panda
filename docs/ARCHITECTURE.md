# Architecture

Grey Panda is built on four principles, then implemented as one knowledge pack
feeding three surfaces (scanner, SDK, integrations) across the whole delivery path.

## Principles (first-class, not aspirational)
1. **Secure path = easy path.** Every control is a drop-in. Adding the core
   guardrails to an existing LLM call takes under two minutes and never requires
   rewriting the call.
2. **Honest about limits.** Every capability ships with a confidence level and a
   failure condition ([WHAT_IT_CAN_AND_CANNOT_DO.md](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md)).
3. **Defense in depth, not prevention theater.** No single layer stops everything.
   Known patterns are blocked at input; data is quarantined even if injection
   succeeds; blast radius is limited by least-privilege agents; every action is
   auditable.
4. **Standards-anchored, not opinion-driven.** Every rule, checklist item, and SDK
   control cites a specific OWASP/AISVS/ACS ID.
5. **Works for one dev or ten thousand.** Profiles scale the process, not the floor.

## The knowledge pack (single source of truth)
`src/greypanda/data/standards/*.json` is the brain: every control ID → title →
description → remediation → the Grey Panda controls and scanner rules that address
it. The scanner, `gp verify`, the MCP server, and the AI skill all cite from it.
The mapping tables in Module 5 are generated from it (`tools/generate_mappings.py`).

## The SDK: a 7-step request pipeline
```
1. PromptGuardrail.assert_safe()   # block injection, strip invisible Unicode, size cap
2. DLPScanner.redact()             # remove PII + secrets before the model sees input
3. SecureContextBuilder            # tag trust per segment, enforce size budget
4. (your LLM call)                 # through your gateway — unchanged
5. DLPScanner.redact()             # scan the response for leaked PII
6. OutputGuardrail.sanitize()      # escape output → XSS-safe by default
7. AuditLogger                     # structured event, zero raw text, SIEM-ready
```
For agents, `AgentSecurityWrapper` adds init-time Rule-of-Two enforcement, a
deny-by-default tool allowlist, per-session call budgets, HITL gates, and a kill
switch. For MCP, `McpServerGuard` + `McpToolManifest` add manifest pinning/hashing
(rug-pull detection), schema validation, origin/TLS/scope checks, and session
isolation. For agent oversight, the ACS `Guardian` returns the five dispositions
(allow/deny/modify/ask/defer) and `agent_bill_of_materials` emits an AgBOM.

## The scanner
`scanner/rules.py` holds `Rule` objects (id, OWASP id, severity, pattern, suppress
guard, remediation, SDK pointer, profiles). `scanner/engine.py` walks files and
applies rules line-by-line with false-positive suppressors. `scanner/reporters.py`
renders Markdown (PR-ready), JSON, and SARIF 2.1.0. `scanner/profiles.py` decides
which rules are active and the default fail threshold.

## Integrations
- **MCP server** (`mcpserver/server.py`): JSON-RPC 2.0 over stdio, stdlib only.
- **Skill** (`skill/SKILL.md`): turns an AI coding assistant into an AI Security Advisor.
- **CI**: GitHub Action uploads SARIF and enforces the gate; pre-commit runs locally.

## Delivery path
```
DEVELOPER  →  CI/CD GATE  →  APPSEC REVIEW  →  PRODUCTION
 SDK+skill     gp scan +      reviewer guide    runtime SDK
 gp scan       GitHub Action  + AISVS verify    + audit + kill switch
```

## Repository layout

The **bundle is organised into five audience-facing module kits** at the repo root,
all powered by one shared, zero-dependency engine under `src/greypanda/`.

```
grey-panda/
├── Module 1 - Developer Kit/            quickstart, profiles, SDK how-tos
├── Module 2 - Security Reviewer Kit/    reviewer guide, AISVS how-to, threat-models/
├── Module 3 - Scanner and CI-CD Kit/    rules catalog, CI + SARIF how-tos
├── Module 4 - MCP and Agent Security Kit/ MCP + agent how-tos
├── Module 5 - Standards and Governance Kit/ can/cannot, mappings/
├── src/greypanda/          ← the shared engine (installable package)
│   ├── sdk/          guardrails, dlp, context, agent, audit, mcp, acs
│   ├── scanner/      rules, engine, reporters, profiles
│   ├── verify/       aisvs
│   ├── mcpserver/    server (stdio MCP)
│   ├── cli/          main (argparse)
│   └── data/         standards/*.json + checklist (the knowledge pack)
├── standards/        README for the pack
├── docs/             ARCHITECTURE, assets
├── skill/            SKILL.md (AI Security Advisor)
├── examples/         vulnerable_app, secure_app, example_usage.py
├── tests/            unittest suite (zero deps)
└── tools/            generate_mappings.py, generate_rules_catalog.py
```

Why modules on top of one engine? So each audience has a clear front door, while the
security logic stays in a single, tested, importable place — no duplication, no drift.

## Zero dependencies, on purpose
The shipped package imports only the Python standard library. Nothing to install,
nothing to break, nothing new in your supply chain. Dev tools (pytest/mypy/ruff)
are optional extras.

## Deterministic by design — no LLM in the loop
The core engine makes **no model calls**. It is pure deterministic code (regex +
Python's `ast` module), and that is a feature, not a limitation:

- **Reproducible.** Same code in, same verdict out — every run, forever. A CI gate
  that flakes is a CI gate teams learn to ignore; Grey Panda's never does.
- **Private & offline.** Your source never leaves the machine. There is no data
  egress — which would be a strange thing for a *security* scanner to have.
- **Free & fast.** No per-scan API bill, no rate limits, no network round-trip.
- **Auditable.** Every finding maps to a rule you can read, cite (OWASP ID), and
  reason about. There is no opaque model judgement to second-guess.

Semantic, LLM-powered review is genuinely useful — for catching paraphrased
injection and intent — but it belongs in the AI IDE you already use (Grey Panda
ships **as an MCP server** those assistants can call) or in a later, explicit
**opt-in** layer. It is deliberately never baked into the deterministic gate, so
the thing that blocks your build stays boring, predictable, and trustworthy.
