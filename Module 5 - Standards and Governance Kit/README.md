# 📚 Module 5 — Standards & Governance Kit

> **For:** engineering leads, compliance, and *everyone* — the shared "brain" and the
> honest truth about what Grey Panda can and can't do.
> **Goal:** every control traceable to a published standard, and no overclaiming.

This kit is Grey Panda's conscience. It holds the standards knowledge pack, the
mappings that make every finding traceable, and the document we're proudest of: an
honest account of the tool's limits.

---

## What's in this kit

| Piece | What it does |
|---|---|
| **[WHAT_IT_CAN_AND_CANNOT_DO.md](WHAT_IT_CAN_AND_CANNOT_DO.md)** | Every capability with its confidence level and failure condition. **Read this first.** |
| **[mappings/](mappings)** | Generated tables: each OWASP/AISVS/ACS/MCP control → the Grey Panda control and scanner rule that address it. |
| **The checklist** | `gp checklist` — 11 sections, 60+ items, with a sign-off table. |
| **The knowledge pack** | Machine-readable JSON (in the package) that the scanner, `gp verify`, the MCP server, and the AI skill all cite from. |

## Standards Grey Panda is anchored to

| Standard | Coverage | Mapping |
|---|---|---|
| OWASP **LLM Top 10 2026** | `LLM01`–`LLM10` | [OWASP_LLM_TOP10.md](mappings/OWASP_LLM_TOP10.md) |
| OWASP **GenAI Data Security 2026** | `DSGAI01`–`DSGAI21` | [OWASP_DSGAI.md](mappings/OWASP_DSGAI.md) |
| OWASP **Top 10 for Agentic Apps 2026** | `ASI01`–`ASI10` | [OWASP_AGENTIC.md](mappings/OWASP_AGENTIC.md) |
| OWASP **AISVS** | `C1`–`C12`, L1/L2/L3 | [AISVS.md](mappings/AISVS.md) |
| OWASP **MCP** security guides | 8 domains + minimum bar | [MCP_SECURITY.md](mappings/MCP_SECURITY.md) |
| **Agent Control Standard (ACS)** | Guardian hooks, 5 dispositions, AgBOM | [AGENT_CONTROL_STANDARD.md](mappings/AGENT_CONTROL_STANDARD.md) |
| **NIST AI 100-2**, **Meta Rule of Two** | Deterministic mediation; lethal trifecta | (referenced throughout) |

Explore any control from the CLI:
```bash
gp standards                 # list every standard + control ID
gp standards LLM01:2026      # explain one, with its Grey Panda fix
```

## The knowledge pack (single source of truth)

The canonical, machine-readable pack ships **inside the package**
(`greypanda/data/standards/*.json`), so it's always available after `pip install`
with zero dependencies. The scanner rules, `gp verify`, the MCP server, and the AI
skill all cite from it, and the mapping tables here are generated from it:

```bash
PYTHONPATH=src python tools/generate_mappings.py
```

See [`standards/README.md`](../standards/README.md) for the entry schema and how to
extend the pack.

## Governance
- **Principles that don't change lightly:** zero runtime dependencies · every control
  cites a standard ID · honesty about limits · same safety floor for every profile.
  See [GOVERNANCE.md](../GOVERNANCE.md).
- **Attribution:** standards are the property of their authors; see [NOTICE](../NOTICE).
  Grey Panda is independent and not endorsed by OWASP.

## The most important page in the whole repo
👉 **[WHAT_IT_CAN_AND_CANNOT_DO.md](WHAT_IT_CAN_AND_CANNOT_DO.md)** — before you rely on
Grey Panda for anything, read what it *cannot* do. A tool that's honest about its
limits is a tool you can actually trust.
