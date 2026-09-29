# 🧰 Module 1 — Developer Kit

> **For:** developers building anything with an LLM, an agent, or MCP.
> **Goal:** make the secure choice the *frictionless* choice. You should be able to
> add real protection to an existing LLM call in **under two minutes** — without
> rewriting the call.

This is the kit you reach for first. It gives you the **drop-in SDK** (runtime
guardrails), the **scanner** for your own code, and the **IDE integration** so your
AI assistant reviews security as you type.

---

## What's in this kit

| Piece | What it does | Where |
|---|---|---|
| **The SDK** | Drop-in runtime controls: input/output guardrails, DLP, secure context, agent security, audit | `import greypanda` |
| **The scanner** | Finds AI/agent/MCP issues in your code (`gp scan`) | see [Module 3](../Module%203%20-%20Scanner%20and%20CI-CD%20Kit) |
| **IDE / AI integration** | Grey Panda as an MCP server + a Claude/Cursor skill | [HOW-TO-use-in-your-ide.md](HOW-TO-use-in-your-ide.md) |
| **Quickstart & Profiles** | Get running in 60 seconds; pick your rigor level | [QUICKSTART.md](QUICKSTART.md) · [PROFILES.md](PROFILES.md) |
| **Runnable examples** | `vulnerable_app` (flagged) vs `secure_app` (clean) + a full SDK tour | [`/examples`](../examples) |

## The 60-second version

```bash
pip install grey-panda
gp scan .                       # scan your repo
```

```python
from greypanda import PromptGuardrail, DLPScanner, OutputGuardrail

guard, dlp, out = PromptGuardrail(), DLPScanner(), OutputGuardrail()

safe   = guard.assert_safe(user_input)        # block known injection + strip invisible Unicode
clean  = dlp.redact(safe)                       # remove PII & secrets before the model sees them
reply  = call_your_llm(clean)                   # ← your existing call, unchanged
answer = out.sanitize(reply).sanitized_text     # block data-exfil URLs & unsafe HTML
```

## The SDK at a glance

| Control | Import | Protects against |
|---|---|---|
| `PromptGuardrail` | `from greypanda import PromptGuardrail` | Prompt injection, invisible-Unicode smuggling (`LLM01`) |
| `DLPScanner` | `from greypanda import DLPScanner` | PII & secret leakage (`LLM02`, `DSGAI01`) |
| `OutputGuardrail` | `from greypanda import OutputGuardrail` | XSS / data-exfil via model output (`LLM10`, `LLM02`) |
| `SecureContextBuilder` | `from greypanda import SecureContextBuilder` | Indirect injection, cross-user bleed (`LLM01`, `LLM09`) |
| `AgentSecurityWrapper` | `from greypanda import AgentSecurityWrapper` | Excessive agency, lethal trifecta (`LLM03`) → see [Module 4](../Module%204%20-%20MCP%20and%20Agent%20Security%20Kit) |
| `AuditLogger` | `from greypanda import AuditLogger` | Telemetry leakage (`DSGAI14`) |

Full walkthroughs:
- **[HOW-TO-add-guardrails.md](HOW-TO-add-guardrails.md)** — wire the 7-step pipeline into a real request.
- **[HOW-TO-use-in-your-ide.md](HOW-TO-use-in-your-ide.md)** — Grey Panda in Claude Code / Cursor / VS Code.

## ✅ What this kit can do — and ❌ what it can't

**Can:** block *known* injection patterns cheaply at the edge; redact structured PII
and known secret shapes; keep instructions and untrusted data structurally
separate; give you an auditable, SIEM-ready event stream — all with **zero runtime
dependencies**.

**Cannot:** stop *all* prompt injection, catch paraphrased/novel attacks, or
understand meaning. Regex DLP is language-specific. Treat this as the **first layer
of defense in depth**, never as "injection-proof." The complete, honest breakdown
(with confidence levels per capability) is in
**[Module 5 → WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md)**.

## Where to go next
- Shipping an agent or MCP server? → **[Module 4 — MCP & Agent Security Kit](../Module%204%20-%20MCP%20and%20Agent%20Security%20Kit)**
- Want a CI gate? → **[Module 3 — Scanner & CI/CD Kit](../Module%203%20-%20Scanner%20and%20CI-CD%20Kit)**
- Getting reviewed by security? → **[Module 2 — Security Reviewer Kit](../Module%202%20-%20Security%20Reviewer%20Kit)**
