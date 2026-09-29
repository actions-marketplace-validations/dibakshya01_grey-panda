# 🐼 Grey Panda — AI Security Checklist

A pre-ship checklist for AI, agent, and MCP features. Every item names a severity
and an OWASP anchor. **Any `Critical` FAIL blocks the release until resolved.**

Severity: 🔴 Critical (blocker) · 🟠 High · 🟡 Medium · ⚪ Low
Mark each: ✅ Pass · ❌ Fail · ➖ N/A

---

## 1. Prompt Security — `LLM01:2026`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| P1 | System prompt and user input are structurally separated (typed roles) | 🔴 | | |
| P2 | No user-controlled text is interpolated into the system prompt | 🔴 | | |
| P3 | RAG / retrieved content is tagged as untrusted | 🟠 | | |
| P4 | External/tool content is treated as untrusted | 🟠 | | |
| P5 | Injection-detection layer runs on all inputs | 🟠 | | |
| P6 | Multimodal inputs (image/PDF/audio via OCR/transcription) are sanitised | 🟡 | | |
| P7 | Invisible/bidi Unicode is stripped from inputs | 🟠 | | |
| P8 | Cross-session memory writes are sanitised and rate-limited | 🟡 | | |
| P9 | LLM output schema is validated by application code (not a second LLM) | 🟠 | | |
| P10 | System prompt is never returned in responses | 🔴 | | |

## 2. Data Leakage & Sensitive Info — `LLM02` / `DSGAI01`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| D1 | PII is redacted before training / RAG ingestion | 🔴 | | |
| D2 | Real-time DLP runs on input **and** output | 🔴 | | |
| D3 | No credentials/secrets in prompts | 🔴 | | |
| D4 | Per-document ACL on RAG sources | 🔴 | | |
| D5 | Output is scanned for PII before it leaves the system | 🔴 | | |
| D6 | Secrets come from a vault/env, never hardcoded | 🟠 | | |
| D7 | Logs/telemetry never contain raw prompt/response text | 🟠 | | |

## 3. Excessive Agency & Agent Permissions — `LLM03` / `DSGAI02` / `ASI03`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| A1 | Agents use minimum-viable permissions (deny by default) | 🔴 | | |
| A2 | Credentials live in app code, never in model context | 🔴 | | |
| A3 | HITL gate on every irreversible action | 🔴 | | |
| A4 | Rule of Two respected (no lethal trifecta without a gate) | 🔴 | | |
| A5 | Per-session call budgets enforced | 🟠 | | |
| A6 | Kill switch halts tool calls within seconds | 🟠 | | |

## 4. Supply Chain — `LLM04` / `DSGAI04` / `ASI04`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| S1 | AI dependencies pinned to exact versions | 🟠 | | |
| S2 | Model artifacts signed / provenance verified | 🔴 | | |
| S3 | Third-party providers & MCP servers assessed before use | 🔴 | | |
| S4 | AIBOM / AgBOM produced for the system | 🟠 | | |

## 5. Model & Data Poisoning — `LLM05` / `DSGAI04` / `DSGAI21`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| M1 | Training/fine-tune data curated and reviewed for adversarial content | 🟠 | | |
| M2 | Memory writes validated and attributed | 🟠 | | |

## 6. Unbounded Consumption — `LLM06`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| U1 | Per-user token limits | 🟠 | | |
| U2 | Cost monitoring / alerts | 🟡 | | |
| U3 | Recursive/agent call-depth limits | 🟠 | | |

## 7. Output Handling & Misinformation — `LLM07` / `LLM10`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| O1 | No raw model output rendered as HTML | 🔴 | | |
| O2 | LLM-generated code/SQL validated before execution | 🔴 | | |
| O3 | No downstream execution without deterministic validation | 🔴 | | |
| O4 | External image/link URLs in output are neutralised | 🟠 | | |

## 8. Vector Store & RAG Security — `LLM09` / `DSGAI13` / `DSGAI15`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| V1 | Vector store authenticated & authorised | 🔴 | | |
| V2 | Every retrieval scoped by the requesting user | 🔴 | | |
| V3 | No unauthorised data in the context window | 🟠 | | |

## 9. Shadow AI & Governance — `DSGAI03` / `DSGAI07`
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| G1 | No unsanctioned external AI services in production flows | 🟠 | | |
| G2 | All model calls routed through the approved gateway | 🟠 | | |
| G3 | AI use cases registered in the internal inventory | 🟡 | | |

## 10. MCP Security — `AISVS C10` / OWASP MCP guides
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| C1 | Remote MCP uses OAuth 2.1/OIDC + TLS; no token passthrough | 🔴 | | |
| C2 | Tool manifests pinned & hashed; rug pulls detected | 🟠 | | |
| C3 | Tool inputs/outputs schema-validated & treated as untrusted | 🟠 | | |
| C4 | Tool descriptions reviewed for poisoning | 🟠 | | |
| C5 | Users/sessions isolated; no shared state; per-session quotas | 🟠 | | |

## 11. Agentic-Specific — OWASP Agentic Apps 2026 / State of Agentic AI v2.01
| # | Check | Sev | Status | Notes |
|---|---|---|---|---|
| AG1 | Agent identity lifecycle managed | 🔴 | | |
| AG2 | Inter-agent messages authenticated (no forged instructions) | 🔴 | | |
| AG3 | Kill switch halts the agent in < 60s | 🔴 | | |
| AG4 | Cascading-failure limits (circuit breakers, budgets) | 🟠 | | |

---

## Sign-off
| Role | Name | Date | Signature |
|---|---|---|---|
| Developer | | | |
| Tech Lead | | | |
| AppSec Reviewer | | | |

> **Critical blocker rule:** any 🔴 FAIL blocks the PR/release until resolved.
