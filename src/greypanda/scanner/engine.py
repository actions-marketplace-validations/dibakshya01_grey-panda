"""
engine.py — the Grey Panda scanning engine.

Walks a file or directory, applies the active rules line by line, and returns
findings sorted by severity. Static analysis only: it reads code, it never runs
it. Honest limits (see WHAT_IT_CAN_AND_CANNOT_DO.md): it is pattern-based, so it
can produce false positives on benign code and false negatives on obfuscated or
dynamically constructed patterns, and it does not follow data across functions.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .profiles import DEFAULT_PROFILE, get_profile
from .rules import RULES, Rule, rules_for_profile

# Standard SAST escape hatch: a line containing this is skipped entirely.
_INLINE_IGNORE = re.compile(r"grey-?panda:\s*ignore\b", re.IGNORECASE)
_IGNORE_FILENAME = ".greypandaignore"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Directories never worth scanning.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    "dist", "build", ".mypy_cache", ".pytest_cache", ".tox", ".idea",
    ".ruff_cache", "site-packages", ".eggs",
}

_MAX_FILE_BYTES = 2_000_000  # skip very large / likely-binary files


@dataclass
class Finding:
    rule_id: str
    owasp_id: str
    severity: str
    title: str
    description: str
    remediation: str
    file: str
    line: int
    snippet: str
    sdk: str = ""


class AISecurityScanner:
    """Scan source for AI/agent/MCP security issues.

    Args:
        profile: One of ``solo``/``team``/``enterprise``. Selects the active rules.
        rules: Explicit rule list (overrides ``profile`` when provided).
    """

    def __init__(self, profile: str = DEFAULT_PROFILE, rules: list[Rule] | None = None) -> None:
        self.profile = profile
        get_profile(profile)  # validate name
        self.rules: list[Rule] = rules if rules is not None else rules_for_profile(profile)
        self._ignore_globs: list[str] = []

    def _load_ignore(self, root: Path) -> None:
        """Load .greypandaignore patterns from the scan root directory only.

        Scoping the ignore file to the exact directory being scanned keeps it
        predictable: a `.greypandaignore` at your repo root applies to
        `gp scan .`, and it does not silently reach into unrelated sub-scans.
        """
        patterns: list[str] = []
        base = root if root.is_dir() else root.parent
        f = base / _IGNORE_FILENAME
        if f.is_file():
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
        self._ignore_globs = patterns

    def _is_ignored(self, path: Path) -> bool:
        if not self._ignore_globs:
            return False
        p = path.as_posix()
        name = path.name
        for pat in self._ignore_globs:
            if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(p, "*/" + pat):
                return True
        return False

    # -- matching ------------------------------------------------------------ #
    def _rules_for_file(self, path: Path) -> list[Rule]:
        name = path.name
        active = []
        for rule in self.rules:
            if any(fnmatch.fnmatch(name, g) for g in rule.file_globs):
                active.append(rule)
        return active

    def scan_file(self, filepath: Path) -> list[Finding]:
        path = Path(filepath)
        if self._is_ignored(path):
            return []
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return []
        except OSError:
            return []
        rules = self._rules_for_file(path)
        if not rules:
            return []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _INLINE_IGNORE.search(line):
                continue
            for rule in rules:
                rx = rule.compiled()
                if rx is None or not rx.search(line):
                    continue
                sup = rule.suppressor()
                if sup is not None and sup.search(line):
                    continue
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                findings.append(Finding(
                    rule_id=rule.id, owasp_id=rule.owasp_id, severity=rule.severity,
                    title=rule.title, description=rule.description,
                    remediation=rule.remediation, file=str(path), line=lineno,
                    snippet=snippet, sdk=rule.sdk,
                ))
        return findings

    def scan_path(self, root: Path) -> list[Finding]:
        root = Path(root)
        self._load_ignore(root)
        findings: list[Finding] = []
        if root.is_file():
            findings.extend(self.scan_file(root))
        else:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
                for fn in filenames:
                    findings.extend(self.scan_file(Path(dirpath) / fn))
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
        return findings


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def exceeds_threshold(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding is at ``fail_on`` severity or above."""
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 0)
    return any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings)
