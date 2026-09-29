#!/usr/bin/env python3
"""
Regenerate the scanner rules catalog from the live rule set.

    PYTHONPATH=src python tools/generate_rules_catalog.py

Writes "Module 3 - Scanner and CI-CD Kit/RULES_CATALOG.md". Run whenever you add
or change a rule so the catalog never drifts from the code.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from greypanda.scanner.rules import RULES  # noqa: E402
from greypanda.scanner.engine import SEVERITY_ORDER  # noqa: E402

OUT = os.path.join(
    os.path.dirname(__file__), "..", "Module 3 - Scanner and CI-CD Kit", "RULES_CATALOG.md"
)
EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}


def main() -> int:
    rules = sorted(RULES, key=lambda r: (SEVERITY_ORDER[r.severity], r.id))
    counts: dict[str, int] = {}
    for r in RULES:
        counts[r.severity] = counts.get(r.severity, 0) + 1

    md = [
        "# 🐼 Grey Panda — Scanner Rules Catalog", "",
        f"**{len(RULES)} rules.** "
        + " · ".join(f"{EMOJI[s]} {counts.get(s,0)} {s.title()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
        "",
        "Every rule cites a specific standard ID and points at the Grey Panda control "
        "that fixes it. Rules run per-profile (`solo` / `team` / `enterprise`) and can be "
        "silenced per-line with `# grey-panda: ignore` or per-file with `.greypandaignore`.",
        "",
        "> This file is generated from the code (`tools/generate_rules_catalog.py`). Do not edit by hand.",
        "",
        "| Rule | Sev | OWASP / AISVS | Title | Profiles | Fix (SDK) |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in rules:
        profiles = "all" if len(r.profiles) == 3 else ", ".join(r.profiles)
        sdk = f"`{r.sdk}`" if r.sdk else "—"
        md.append(
            f"| `{r.id}` | {EMOJI[r.severity]} | {r.owasp_id} | {r.title} | {profiles} | {sdk} |"
        )
    md.append("")
    md.append("## Remediations")
    md.append("")
    for r in rules:
        md.append(f"### {EMOJI[r.severity]} `{r.id}` — {r.title}")
        md.append(f"*{r.owasp_id} · {r.severity}*")
        md.append("")
        md.append(f"- **What:** {r.description}")
        md.append(f"- **Fix:** {r.remediation}")
        if r.sdk:
            md.append(f"- **SDK:** `{r.sdk}`")
        md.append("")

    with open(OUT, "w") as f:
        f.write("\n".join(md) + "\n")
    print(f"wrote {OUT} ({len(RULES)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
