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
from .rules import Rule, rules_for_profile

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

# --------------------------------------------------------------------------- #
# Lightweight model-output taint tracking (Python only).
#
# The keyword-based rules miss a model-fed sink when the variable isn't named
# with a trigger word (e.g. `query`/`html`). This small pass follows variables
# assigned from a model call across a file and flags the highest-impact sinks
# (SQL/exec and HTML) when they consume a tainted variable — a pragmatic, stdlib
# approximation of taint analysis, not a full data-flow engine.
# --------------------------------------------------------------------------- #
_TAINT_CALL = re.compile(
    r"(?i)(?:\.(?:chat\b|completions\b|create\b|invoke\b|generate\b|generate_content\b|predict\b|complete\b)"
    r"|\bask_(?:model|llm|ai|gpt)\b|\bcall_(?:model|llm|ai|gateway)\b|\bllm\.(?:invoke|generate|predict|complete)"
    r"|\.choices\[0\]\.message\.content|\.choices\[0\]\.text)"
)
_TAINT_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$")
_TAINT_SINKS = [
    ("GP-AI-014", re.compile(
        r"(?i)(?:cursor\.execute|\bdb\.execute|\.executescript|\bexecute)\s*\(\s*([A-Za-z_]\w*)")),
    ("GP-AI-014", re.compile(
        r"(?i)(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|\beval|\bexec)\s*\(\s*([A-Za-z_]\w*)")),
    ("GP-AI-004", re.compile(
        r"(?i)(?:mark_safe|dangerouslySetInnerHTML|Markup|\.innerHTML\s*=|render_template_string)\s*\(?\s*([A-Za-z_]\w*)")),
]
_TAINT_SUPPRESS = re.compile(
    r"(?i)escape|sanitize|OutputGuardrail|validate|allowlist|parametri|shlex\.quote|bleach|grey-?panda:\s*ignore")


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
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            lineno = idx + 1
            if _INLINE_IGNORE.search(line):
                continue
            for rule in rules:
                rx = rule.compiled()
                if rx is None or not rx.search(line):
                    continue
                sup = rule.suppressor()
                if sup is not None:
                    if sup.search(line):
                        continue
                    # Some rules flag the ABSENCE of a control (e.g. no DLP before a
                    # call, no max_tokens). The safe form may sit a few lines away or
                    # on a wrapped line, so honour a small window to avoid false
                    # positives on correct, idiomatic (Black-formatted) code.
                    if rule.suppress_window:
                        w = rule.suppress_window
                        window = "\n".join(lines[max(0, idx - w): idx + w + 1])
                        if sup.search(window):
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

        if path.suffix == ".py":
            findings.extend(self._taint_findings(path, lines, findings))
        return findings

    def _taint_findings(self, path: Path, lines: list[str], existing: list[Finding]) -> list[Finding]:
        """Flag SQL/exec/HTML sinks that consume a model-tainted variable."""
        active = {r.id: r for r in self.rules}
        if not ({"GP-AI-014", "GP-AI-004"} & set(active)):
            return []
        # Build the set of model-tainted variables (a couple of propagation hops).
        tainted: set[str] = set()
        for _ in range(2):
            for line in lines:
                m = _TAINT_ASSIGN.match(line)
                if not m:
                    continue
                var, rhs = m.group(1), m.group(2)
                if _TAINT_CALL.search(rhs) or any(re.search(rf"\b{re.escape(t)}\b", rhs) for t in tainted):
                    tainted.add(var)
        if not tainted:
            return []
        already = {(f.rule_id, f.line) for f in existing}
        out: list[Finding] = []
        for idx, line in enumerate(lines):
            if _INLINE_IGNORE.search(line):
                continue
            window = "\n".join(lines[max(0, idx - 2): idx + 3])
            if _TAINT_SUPPRESS.search(window):
                continue
            for rule_id, rx in _TAINT_SINKS:
                if rule_id not in active:
                    continue
                m = rx.search(line)
                if not m or m.group(1) not in tainted:
                    continue
                if (rule_id, idx + 1) in already:
                    continue
                rule = active[rule_id]
                snippet = line.strip()[:157]
                out.append(Finding(
                    rule_id=rule.id, owasp_id=rule.owasp_id, severity=rule.severity,
                    title=rule.title,
                    description=rule.description + " (model-tainted variable reaches this sink)",
                    remediation=rule.remediation, file=str(path), line=idx + 1,
                    snippet=snippet, sdk=rule.sdk,
                ))
                already.add((rule_id, idx + 1))
        return out

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
