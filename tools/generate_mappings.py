#!/usr/bin/env python3
"""
Regenerate "Module 5 - Standards and Governance Kit/mappings/*.md" from the pack.

    PYTHONPATH=src python tools/generate_mappings.py

Keeps the human-readable mapping tables in sync with the single source of truth
in src/greypanda/data/standards/. Run this whenever you edit a standards JSON file.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from greypanda.data import load_standard  # noqa: E402

OUT = os.path.join(
    os.path.dirname(__file__), "..", "Module 5 - Standards and Governance Kit", "mappings"
)

FLAT = {
    "owasp-llm-top10": "OWASP_LLM_TOP10.md",
    "owasp-dsgai": "OWASP_DSGAI.md",
    "owasp-agentic": "OWASP_AGENTIC.md",
    "mcp": "MCP_SECURITY.md",
    "acs": "AGENT_CONTROL_STANDARD.md",
}


def _table(doc: dict) -> str:
    rows = ["| ID | Title | Grey Panda controls | Scanner rules |", "| --- | --- | --- | --- |"]
    for c in doc["controls"]:
        gp = ", ".join(f"`{x}`" for x in c.get("grey_panda_controls", [])) or "—"
        sr = ", ".join(f"`{x}`" for x in c.get("scanner_rules", [])) or "—"
        rows.append(f"| `{c['id']}` | {c['title']} | {gp} | {sr} |")
    return "\n".join(rows)


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    for key, fname in FLAT.items():
        doc = load_standard(key)
        md = [
            f"# {doc['name']} → Grey Panda mapping", "",
            f"_Version: {doc.get('version','')} · License: {doc.get('license','')} · Source: {doc.get('source','')}_",
            "", "How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.",
            "", _table(doc), "",
            "> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.",
        ]
        with open(os.path.join(OUT, fname), "w") as f:
            f.write("\n".join(md) + "\n")
        print("wrote", fname)

    aisvs = load_standard("aisvs")
    md = [
        f"# {aisvs['name']} → Grey Panda mapping", "",
        f"_Version: {aisvs.get('version','')} · License: {aisvs.get('license','')} · Source: {aisvs.get('source','')}_",
        "", "**Levels:** " + " · ".join(f"L{k} = {v}" for k, v in aisvs["levels"].items()),
        "", "> " + aisvs.get("note", ""), "",
    ]
    for ch in aisvs["controls"]:
        md += [f"## {ch['id']} — {ch['title']}", "", f"_{ch['description']}_"]
        gp = ", ".join(f"`{x}`" for x in ch.get("grey_panda_controls", []))
        if gp:
            md.append(f"\nGrey Panda controls: {gp}")
        md += ["", "| Requirement | Level | Verify | Text |", "| --- | --- | --- | --- |"]
        for r in ch.get("requirements", []):
            md.append(f"| `{r['id']}` | L{r['level']} | {r.get('verify','manual')} | {r['text']} |")
        md.append("")
    with open(os.path.join(OUT, "AISVS.md"), "w") as f:
        f.write("\n".join(md) + "\n")
    print("wrote AISVS.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
