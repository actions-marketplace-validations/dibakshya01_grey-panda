"""
engine.py — the Grey Panda scanning engine.

Walks a file or directory, applies the active rules line by line, and returns
findings sorted by severity. Static analysis only: it reads code, it never runs
it. Honest limits (see WHAT_IT_CAN_AND_CANNOT_DO.md): it is pattern-based, so it
can produce false positives on benign code and false negatives on obfuscated or
dynamically constructed patterns, and it does not follow data across functions.
"""

from __future__ import annotations

import ast
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
# Lightweight, FUNCTION-SCOPED model-output taint tracking (Python only, via ast).
#
# The keyword-based rules miss a model-fed sink when the variable isn't named with
# a trigger word (e.g. `query`/`html`). This pass parses the file and, WITHIN EACH
# FUNCTION SCOPE, follows variables assigned from a model call into the highest-
# impact Python sinks (SQL/exec and server-side HTML) — a pragmatic, stdlib
# approximation of taint analysis, not a full data-flow engine. Scoping per
# function avoids cross-function false positives from same-named variables.
# --------------------------------------------------------------------------- #
_MODEL_ATTRS = {
    "chat", "completions", "create", "invoke", "generate", "generate_content",
    "predict", "complete",
}
_MODEL_NAME = re.compile(r"^(?:ask_(?:model|llm|ai|gpt)|call_(?:model|llm|ai|gateway))$", re.IGNORECASE)
# Python-only sinks. (React/JS sinks like dangerouslySetInnerHTML are intentionally
# NOT here — this pass only runs on .py files; the keyword rules cover JS/TS.)
_SQL_SINK_ATTRS = {"execute", "executescript", "executemany", "system"}
_SQL_SINK_NAMES = {"eval", "exec"}
_HTML_SINK = {"mark_safe", "Markup", "render_template_string"}
_TAINT_SUPPRESS = re.compile(
    r"(?i)escape|sanitize|OutputGuardrail|validate|allowlist|parametri|shlex\.quote|bleach|grey-?panda:\s*ignore")


def _expr_is_model_call(node: ast.AST) -> bool:
    """True if an expression subtree produces model output (a call or .content access)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Attribute) and (f.attr in _MODEL_ATTRS or _MODEL_NAME.match(f.attr)):
                return True
            if isinstance(f, ast.Name) and _MODEL_NAME.match(f.id):
                return True
        if isinstance(n, ast.Attribute) and n.attr in ("content", "text"):
            dumped = ast.dump(n)
            if "choices" in dumped or "message" in dumped:
                return True
    return False


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _first_arg_name(call: ast.Call) -> str | None:
    if call.args and isinstance(call.args[0], ast.Name):
        return call.args[0].id
    return None


def _scope_bodies(module: ast.Module):
    """Yield each independent scope body: the module top-level and every function."""
    yield [s for s in module.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.body


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
            findings.extend(self._taint_findings(path, text, lines, findings))
        return findings

    def _taint_findings(
        self, path: Path, text: str, lines: list[str], existing: list[Finding]
    ) -> list[Finding]:
        """Flag Python SQL/exec/HTML sinks that consume a model-tainted variable.

        Taint is scoped per function (via ``ast``), so a same-named variable in an
        unrelated function does not cause a false positive.
        """
        active = {r.id: r for r in self.rules}
        if not ({"GP-AI-014", "GP-AI-004"} & set(active)):
            return []
        try:
            module = ast.parse(text)
        except (SyntaxError, ValueError):
            return []  # not valid Python 3 source — skip taint (regex rules still ran)

        already = {(f.rule_id, f.line) for f in existing}
        out: list[Finding] = []

        for body in _scope_bodies(module):
            # 1. Tainted variables in THIS scope (a couple of propagation hops).
            tainted: set[str] = set()
            assigns = [n for stmt in body for n in ast.walk(stmt) if isinstance(n, ast.Assign)]
            for _ in range(2):
                for a in assigns:
                    targets = {t.id for t in a.targets if isinstance(t, ast.Name)}
                    if not targets:
                        continue
                    if _expr_is_model_call(a.value) or (_names_in(a.value) & tainted):
                        tainted |= targets
            if not tainted:
                continue

            # 2. Sinks in THIS scope consuming a tainted variable.
            for stmt in body:
                for node in ast.walk(stmt):
                    if not isinstance(node, ast.Call):
                        continue
                    f = node.func
                    rule_id = None
                    if isinstance(f, ast.Attribute) and f.attr in _SQL_SINK_ATTRS:
                        rule_id = "GP-AI-014"
                    elif isinstance(f, ast.Name) and f.id in _SQL_SINK_NAMES:
                        rule_id = "GP-AI-014"
                    elif isinstance(f, ast.Name) and f.id in _HTML_SINK:
                        rule_id = "GP-AI-004"
                    elif isinstance(f, ast.Attribute) and f.attr in _HTML_SINK:
                        rule_id = "GP-AI-004"
                    if rule_id is None or rule_id not in active:
                        continue
                    arg = _first_arg_name(node)
                    if arg is None or arg not in tainted:
                        continue
                    lineno = getattr(node, "lineno", 1)
                    if (rule_id, lineno) in already:
                        continue
                    line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
                    win = "\n".join(lines[max(0, lineno - 3): lineno + 2])
                    if _INLINE_IGNORE.search(line) or _TAINT_SUPPRESS.search(win):
                        continue
                    rule = active[rule_id]
                    out.append(Finding(
                        rule_id=rule.id, owasp_id=rule.owasp_id, severity=rule.severity,
                        title=rule.title,
                        description=rule.description + " (model-tainted variable reaches this sink)",
                        remediation=rule.remediation, file=str(path), line=lineno,
                        snippet=line.strip()[:157], sdk=rule.sdk,
                    ))
                    already.add((rule_id, lineno))
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
    """True if any finding is at ``fail_on`` severity or above.

    Fails **closed**: an unknown ``fail_on`` maps to the most permissive threshold
    (any finding trips the gate) so a config typo can never silently downgrade the
    gate. Callers should also validate ``fail_on`` up front (see the CLI).
    """
    threshold = SEVERITY_ORDER.get(fail_on.upper(), max(SEVERITY_ORDER.values()))
    return any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings)
