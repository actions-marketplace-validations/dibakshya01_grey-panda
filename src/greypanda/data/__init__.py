"""
Packaged data for Grey Panda — the machine-readable standards knowledge pack.

The pack is the single source of truth that the scanner, the ``gp verify`` command,
the MCP server, and the AI skill all cite from. Files live in ``data/standards``
as JSON (stdlib-loadable, zero dependency).
"""

from __future__ import annotations

import json
from importlib import resources
from functools import lru_cache
from typing import Any

_STANDARDS = {
    "owasp-llm-top10": "owasp-llm-top10-2026.json",
    "owasp-dsgai": "owasp-dsgai-2026.json",
    "owasp-agentic": "owasp-agentic-top10-2026.json",
    "aisvs": "aisvs.json",
    "mcp": "mcp-security.json",
    "acs": "agent-control-standard.json",
}


@lru_cache(maxsize=None)
def load_standard(key: str) -> dict[str, Any]:
    """Load one standard document from the packaged pack by key."""
    if key not in _STANDARDS:
        raise KeyError(f"unknown standard '{key}'. Options: {', '.join(_STANDARDS)}")
    ref = resources.files("greypanda.data").joinpath("standards", _STANDARDS[key])
    with resources.as_file(ref) as path:
        return json.loads(path.read_text(encoding="utf-8"))


def all_standards() -> dict[str, dict[str, Any]]:
    """Load every standard document, keyed by short key."""
    return {key: load_standard(key) for key in _STANDARDS}


@lru_cache(maxsize=None)
def control_index() -> dict[str, dict[str, Any]]:
    """A flat ``{control_id: entry}`` index across every standard, for fast lookup."""
    index: dict[str, dict[str, Any]] = {}
    for key, doc in all_standards().items():
        for entry in doc.get("controls", []):
            entry = {**entry, "_standard": doc.get("name", key), "_standard_key": key}
            index[entry["id"]] = entry
    return index


def lookup(control_id: str) -> dict[str, Any] | None:
    """Look up a single control by ID (e.g. ``LLM01:2026`` or ``C10.2.1``)."""
    return control_index().get(control_id)


def load_checklist() -> str:
    """Return the packaged AI Security Checklist as Markdown text."""
    ref = resources.files("greypanda.data").joinpath("AI_SECURITY_CHECKLIST.md")
    with resources.as_file(ref) as path:
        return path.read_text(encoding="utf-8")
