"""
aisvs.py — verify a codebase against the OWASP AISVS levels.

``gp verify --level 2 <path>`` runs the scanner, maps findings to AISVS
requirements, and produces a verification report. Requirements whose evidence
Grey Panda can automate (``verify: scanner``) are marked pass/fail from the scan;
requirements Grey Panda enforces via SDK controls (``verify: sdk``) and manual
ones (``verify: manual``) are listed for attestation.

Honesty: a clean automated pass is necessary, not sufficient. AISVS Level 2/3
requires human review and evidence. This tool gets you to a rigorous, repeatable
starting point and a signable report — not an auto-certification.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .._version import __version__
from ..data import load_standard
from ..scanner.engine import AISecurityScanner, Finding


@dataclass
class RequirementResult:
    id: str
    level: int
    text: str
    verify: str          # scanner | sdk | manual
    status: str          # pass | fail | attest | n/a
    evidence: list[str] = field(default_factory=list)


@dataclass
class VerificationReport:
    level: int
    scan_path: str
    timestamp: str
    total: int
    checked: int  # scanner ran and found no violation ("checked" ≠ "control present")
    failed: int
    attest: int
    chapters: dict[str, list[RequirementResult]] = field(default_factory=dict)

    @property
    def blocking_failures(self) -> int:
        return self.failed


def verify_aisvs(path: str | Path, level: int = 1, profile: str = "enterprise") -> VerificationReport:
    """Verify ``path`` against AISVS requirements up to ``level``."""
    aisvs = load_standard("aisvs")
    scanner = AISecurityScanner(profile=profile)
    findings = scanner.scan_path(Path(path))
    fired_rules = {f.rule_id for f in findings}
    findings_by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    chapters: dict[str, list[RequirementResult]] = {}
    checked = failed = attest = 0

    for chapter in aisvs["controls"]:
        ch_key = f"{chapter['id']} {chapter['title']}"
        results: list[RequirementResult] = []
        for req in chapter.get("requirements", []):
            if req["level"] > level:
                continue
            verify = req.get("verify", "manual")
            status = "attest"
            evidence: list[str] = []
            if verify == "scanner":
                rules = req.get("scanner_rules", [])
                hit = [r for r in rules if r in fired_rules]
                if hit:
                    status = "fail"
                    for r in hit:
                        for f in findings_by_rule.get(r, [])[:5]:
                            evidence.append(f"{r} @ {f.file}:{f.line}")
                else:
                    status = "checked"  # no violation detected — NOT proof the control exists
            elif verify == "sdk":
                status = "attest"
                evidence.append("enforce via: " + ", ".join(req.get("grey_panda_controls", chapter.get("grey_panda_controls", []))))
            else:
                status = "attest"

            if status == "checked":
                checked += 1
            elif status == "fail":
                failed += 1
            else:
                attest += 1
            results.append(RequirementResult(
                id=req["id"], level=req["level"], text=req["text"],
                verify=verify, status=status, evidence=evidence,
            ))
        if results:
            chapters[ch_key] = results

    total = checked + failed + attest
    return VerificationReport(
        level=level,
        scan_path=str(path),
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        total=total, checked=checked, failed=failed, attest=attest,
        chapters=chapters,
    )


_STATUS_EMOJI = {"checked": "☑️", "fail": "❌", "attest": "📝", "n/a": "➖"}
_STATUS_WORD = {"checked": "no violation detected", "fail": "fail", "attest": "attest", "n/a": "n/a"}


def report_markdown(report: VerificationReport) -> str:
    lines: list[str] = []
    lines.append(f"# 🐼 Grey Panda — AISVS Level {report.level} Verification")
    lines.append("")
    lines.append(
        f"**Path:** `{report.scan_path}`  ·  **Date:** {report.timestamp}  ·  "
        f"**Grey Panda:** v{__version__}"
    )
    lines.append("")
    lines.append(f"**Summary:** ☑️ {report.checked} checked (no violation)  ·  ❌ {report.failed} failed  ·  "
                 f"📝 {report.attest} to attest  ·  {report.total} total")
    lines.append("")
    verdict = "❌ NOT VERIFIED" if report.failed else "🟢 No automated violations — complete attestations to certify"
    lines.append(f"**Verdict:** {verdict}")
    lines.append("")
    lines.append("> ☑️ **checked** = the scanner ran and found no violation. That is *not* proof "
                 "the control is present — only that no known bad pattern was detected.")
    lines.append("")
    for ch, results in report.chapters.items():
        lines.append(f"## {ch}")
        lines.append("")
        lines.append("| Req | L | Status | Requirement |")
        lines.append("| --- | --- | --- | --- |")
        for r in results:
            lines.append(f"| `{r.id}` | {r.level} | {_STATUS_EMOJI[r.status]} {_STATUS_WORD[r.status]} | {r.text} |")
        lines.append("")
        for r in results:
            if r.evidence:
                lines.append(f"- `{r.id}` evidence: " + "; ".join(r.evidence))
        lines.append("")
    lines.append("---")
    lines.append("> 📝 = requires human attestation/evidence. A clean automated pass is "
                 "necessary but not sufficient for AISVS L2/L3 — see the AppSec Reviewer Guide.")
    lines.append("")
    lines.append("**Sign-off:** Reviewer __________  Date __________  Signature __________")
    return "\n".join(lines)
