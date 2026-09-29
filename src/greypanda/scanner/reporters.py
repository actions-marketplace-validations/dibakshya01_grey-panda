"""
reporters.py — render scan findings as Markdown, JSON, or SARIF.

Markdown is PR-comment-ready (and truncates safely for very large codebases).
JSON is a stable machine format for pipelines. SARIF 2.1.0 is the killer feature
for "runs in the IDE": GitHub code scanning and VS Code render SARIF findings
inline, right on the offending line, with zero extra config.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .._version import __version__
from .engine import Finding, severity_counts

_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
_PR_COMMENT_LIMIT = 65_000


def report_markdown(findings: list[Finding], scan_path: str, elapsed: float, profile: str = "team") -> str:
    counts = severity_counts(findings)
    lines: list[str] = []
    lines.append("## 🐼 Grey Panda — AI Security Scan")
    lines.append("")
    lines.append(
        f"**Path:** `{scan_path}`  ·  **Profile:** `{profile}`  ·  "
        f"**Findings:** {len(findings)}  ·  **Time:** {elapsed:.2f}s  ·  "
        f"**Scanner:** v{__version__}"
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"| {_EMOJI[sev]} {sev.title()} | {counts[sev]} |")
    lines.append("")

    if not findings:
        lines.append("✅ **No findings.** Baseline AI security controls appear to be in place.")
        lines.append("")
        lines.append("> Grey Panda is static analysis and a floor, not a ceiling. See "
                     "`WHAT_IT_CAN_AND_CANNOT_DO.md` and complete the checklist.")
        return "\n".join(lines)

    lines.append("---")
    for f in findings:
        lines.append(f"### {_EMOJI[f.severity]} `{f.rule_id}` {f.title}")
        lines.append(f"**OWASP:** {f.owasp_id}  ·  **Severity:** {f.severity}  ·  "
                     f"`{f.file}:{f.line}`")
        lines.append("")
        lines.append(f"- **Issue:** {f.description}")
        lines.append(f"- **Fix:** {f.remediation}")
        if f.sdk:
            lines.append(f"- **SDK:** `{f.sdk}`")
        lines.append("")
        lines.append("```")
        lines.append(f.snippet)
        lines.append("```")
        lines.append("")

    lines.append("---")
    lines.append("**Next steps:** 1) fix 🔴/🟠 before merge  ·  2) adopt the SDK controls "
                 "shown above  ·  3) run `gp checklist`  ·  4) for agentic/MCP features, "
                 "complete an AppSec review (`APPSEC_REVIEWER_GUIDE.md`).")
    out = "\n".join(lines)
    if len(out) > _PR_COMMENT_LIMIT:
        out = out[:_PR_COMMENT_LIMIT] + "\n\n> …report truncated for size. Run locally or read the JSON artifact for the full list."
    return out


def report_json(findings: list[Finding], scan_path: str, elapsed: float, profile: str = "team") -> str:
    import time

    payload = {
        "scanner": "grey-panda",
        "scanner_version": __version__,
        "profile": profile,
        "scan_path": str(scan_path),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "elapsed_seconds": round(elapsed, 4),
        "total_findings": len(findings),
        "severity_counts": severity_counts(findings),
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def report_sarif(findings: list[Finding], scan_path: str, elapsed: float, profile: str = "team") -> str:
    """Emit SARIF 2.1.0 so findings render inline in VS Code + GitHub code scanning."""
    from .rules import RULES

    # Deduplicate rule metadata for the SARIF "rules" table.
    seen: dict[str, dict] = {}
    for r in RULES:
        if r.id in seen:
            continue
        seen[r.id] = {
            "id": r.id,
            "name": r.title.replace(" ", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": r.description},
            "helpUri": "https://github.com/dibakshya01/grey-panda/blob/main/Module%203%20-%20Scanner%20and%20CI-CD%20Kit/RULES_CATALOG.md",
            "help": {"text": f"{r.remediation} (OWASP {r.owasp_id})"},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(r.severity, "warning")},
            "properties": {"security-severity": _security_severity(r.severity), "owasp": r.owasp_id},
        }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title} — {f.remediation} (OWASP {f.owasp_id})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file), "uriBaseId": "SRCROOT"},
                    "region": {"startLine": max(1, f.line), "snippet": {"text": f.snippet}},
                }
            }],
            "properties": {"owasp": f.owasp_id, "severity": f.severity},
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Grey Panda",
                "informationUri": "https://github.com/dibakshya01/grey-panda",
                "version": __version__,
                "rules": list(seen.values()),
            }},
            "originalUriBaseIds": {"SRCROOT": {"uri": _root_uri()}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _root_uri() -> str:
    import os
    from pathlib import Path

    try:
        return Path(os.getcwd()).as_uri().rstrip("/") + "/"
    except Exception:
        return "file:///"


def _security_severity(severity: str) -> str:
    # GitHub code scanning uses a 0-10 numeric scale.
    return {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"}.get(severity, "5.0")


def _uri(path: str) -> str:
    """Repo-relative, forward-slashed path (relative to SRCROOT = the run's cwd)."""
    import os

    p = path.replace("\\", "/")
    try:
        rel = os.path.relpath(path, os.getcwd()).replace("\\", "/")
        if not rel.startswith(".."):
            return rel
    except Exception:
        pass
    return os.path.basename(p)
