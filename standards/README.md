# Standards knowledge pack

This directory documents Grey Panda's **standards knowledge pack** — the single
source of truth that the scanner, `gp verify`, the MCP server, and the AI skill all
cite from.

## Where the machine-readable pack lives
The canonical JSON ships **inside the package** so it is always available after a
`pip install`, with zero dependencies (stdlib `json` + `importlib.resources`):

```
src/greypanda/data/standards/
├── owasp-llm-top10-2026.json      # LLM01–LLM10
├── owasp-dsgai-2026.json          # DSGAI01–DSGAI21
├── owasp-agentic-top10-2026.json  # ASI01–ASI10
├── aisvs.json                     # C1–C12, Levels L1/L2/L3
├── mcp-security.json              # OWASP MCP dev + third-party guides
└── agent-control-standard.json    # ACS: hooks, dispositions, AgBOM
```

Load it in code:
```python
from greypanda.data import load_standard, lookup, all_standards
load_standard("aisvs")           # one document
lookup("LLM01:2026")             # one control, across all standards
all_standards()                  # everything
```

Or from the CLI:
```bash
gp standards                     # list all
gp standards C10                 # explain one
```

## Entry schema
Each control entry has:
| Field | Meaning |
|---|---|
| `id` | Canonical control ID (e.g. `LLM01:2026`, `ASI02`, `C10`, `MCP-TOOL`) |
| `title` | Human-readable name |
| `description` | What the risk/control is |
| `remediation` | The concrete fix |
| `grey_panda_controls` | SDK controls that address it |
| `scanner_rules` | Scanner rule IDs that detect it |

AISVS entries additionally carry `level` and a `requirements` list with per-
requirement `level` and `verify` (`scanner` / `sdk` / `manual`).

## Human-readable mappings
See [`Module 5 → mappings/`](../Module%205%20-%20Standards%20and%20Governance%20Kit/mappings) for generated tables. Regenerate them
after editing any JSON:
```bash
PYTHONPATH=src python tools/generate_mappings.py
```

## Attribution
These standards are the property of their respective authors and are used for
identification and interoperability. See [`../NOTICE`](../NOTICE). Standards content
under CC BY-SA 4.0 is attributed to the OWASP GenAI Security Project. Grey Panda is
an independent project and is not endorsed by OWASP.
