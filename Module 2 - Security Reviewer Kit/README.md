# 🛡️ Module 2 — Security Reviewer Kit

> **For:** AppSec / InfoSec reviewers at the gate-approval stage (after CI passes).
> **Goal:** turn "is this AI feature safe to ship?" into a repeatable, evidence-based,
> signable decision.

Developers ship with [Module 1](../Module%201%20-%20Developer%20Kit). This kit is
what *you* use to review what they ship.

---

## What's in this kit

| Piece | What it does |
|---|---|
| **[APPSEC_REVIEWER_GUIDE.md](APPSEC_REVIEWER_GUIDE.md)** | The full gate workflow: scanner review → manual threat-model review → utility checks → Threat Dragon → sign-off. |
| **[HOW-TO-run-aisvs-verification.md](HOW-TO-run-aisvs-verification.md)** | Run AISVS Level 1/2/3 verification and produce a report. |
| **[threat-models/](threat-models)** | An OWASP Threat Dragon v2 template for a generic agentic + MCP system, with STRIDE threats pre-annotated. |
| **The checklist** | `gp checklist` prints the 11-section AI security checklist with a sign-off table. |

## The 5-minute reviewer flow

```bash
# 1. Pull the findings (or run them yourself)
gp scan <service_dir> --profile enterprise --format json -o findings.json

# 2. Run AISVS verification for the target level
gp verify <service_dir> --level 2 -o aisvs-l2.md

# 3. Print the checklist for the manual pass
gp checklist
```

Then follow **[APPSEC_REVIEWER_GUIDE.md](APPSEC_REVIEWER_GUIDE.md)** for the manual
threat-model review, the 6-prompt injection battery, the RAG isolation test, the DLP
output test, the Threat Dragon model, and the sign-off template.

## Gate rules (from the reviewer guide)
- **Any CRITICAL** → automatic block, no waiver possible.
- **3+ HIGH without compensating controls** → block.
- **Waivers** require VP Engineering + InfoSec/CISO sign-off, with an expiry.

## ✅ What this kit can do — and ❌ what it can't

**Can:** give you ground-truth scanner findings mapped to OWASP/AISVS, a structured
manual-review checklist, a runnable injection/RAG/DLP test battery, a ready threat
model, and a sign-off template that produces an auditable record.

**Cannot:** replace human judgment or a red-team engagement. `gp verify` automates
only what can be automated — a clean automated pass is **necessary but not
sufficient** for AISVS L2/L3, which require human attestation and evidence. The
threat model is a *template*, not your architecture. Full honesty:
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
