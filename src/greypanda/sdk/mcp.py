"""
mcp.py — runtime guardrails for Model Context Protocol (MCP) integrations.

Whether you build an MCP server or consume third-party ones, the two defining MCP
risks are (1) *tool poisoning / rug pulls* — a tool's description or behaviour is
crafted or silently swapped to smuggle instructions or change what it does after
you approved it — and (2) *over-trust* — passing unvalidated tool I/O and
forwarding client tokens downstream (the "confused deputy").

This module gives you drop-in controls for both:
    * McpToolManifest  — pin + hash a tool's description/schema/version so a later
      change is detected (rug-pull / tool-poisoning detection).
    * McpServerGuard    — verify manifests against a pinned registry, enforce an
      origin allowlist, require OAuth scopes, and validate tool arguments against
      a JSON-schema-lite spec, with a per-session isolation helper.

Addresses:
    * OWASP "Secure MCP Server Development" (all 8 domains) + the MCP Minimum Bar
    * OWASP "Securely Using Third-Party MCP Servers" cheat sheet
    * AISVS C10 Model Context Protocol (MCP) Security
    * ASI02 Tool Misuse, ASI04 Agentic Supply Chain, ASI07 Insecure Inter-Agent Comms
    * LLM01:2026 Prompt Injection (indirect, via tool descriptions/output)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("greypanda.mcp")


class McpManifestViolation(Exception):
    """Raised when a tool manifest fails verification (integrity / policy)."""


# Suspicious substrings frequently seen in poisoned tool descriptions. These are
# a cheap first pass — not a guarantee (see WHAT_IT_CAN_AND_CANNOT_DO.md).
_POISON_MARKERS = (
    r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:your\s+)?(?:system\s+prompt|instructions)",
    r"do\s+not\s+(?:tell|inform|mention\s+to)\s+the\s+user",
    r"</?\s*(?:system|instructions?)\s*>",
    r"\bexfiltrat",  # grey-panda: ignore (poison-marker signature)
    r"send\s+(?:the\s+)?[\w./]*\s*(?:contents?|data|secret|token|file|\.env)s?\s+to\b",
    r"\bsend\s+the\s+\.env\b",
    r"base64",
    r"(?:read|cat|exfiltrate|leak)\s+(?:the\s+)?(?:\.env|/etc/passwd|ssh\s+keys?|credentials?|secrets?)\b",  # grey-panda: ignore (poison-marker signature)
    r"<!--.*?-->",
)
_POISON_RE = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _POISON_MARKERS]


@dataclass
class McpGuardResult:
    passed: bool
    violations: list[str] = field(default_factory=list)


@dataclass
class McpToolManifest:
    """A pinnable description of one MCP tool.

    The ``fingerprint`` is a stable hash over the security-relevant fields. Pin it
    at first approval; if a later manifest produces a different fingerprint, the
    tool changed under you — a potential rug pull.
    """

    name: str
    description: str
    version: str = "0.0.0"
    input_schema: dict[str, Any] = field(default_factory=dict)
    required_scopes: list[str] = field(default_factory=list)

    def fingerprint(self) -> str:
        payload = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "version": self.version,
                "input_schema": self.input_schema,
                "required_scopes": sorted(self.required_scopes),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def scan_description(self) -> list[str]:
        """Return descriptions of any tool-poisoning markers found."""
        hits = []
        for rx in _POISON_RE:
            if rx.search(self.description):
                hits.append(f"suspicious marker in tool description: /{rx.pattern}/")
        return hits


class McpServerGuard:
    """Policy gate for MCP tool usage.

    Args:
        pinned_fingerprints: ``{tool_name: fingerprint}`` captured at approval
            time. Verification fails if a tool's current fingerprint differs.
        allowed_origins: Hostnames you trust to serve MCP tools. Empty means
            "do not enforce origin" (log-only).
        granted_scopes: OAuth scopes actually held by the caller. A tool whose
            ``required_scopes`` are not all present is denied.
        require_https: Reject non-HTTPS remote origins. Defaults to ``True``.
    """

    def __init__(
        self,
        pinned_fingerprints: dict[str, str] | None = None,
        allowed_origins: list[str] | None = None,
        granted_scopes: list[str] | None = None,
        require_https: bool = True,
    ) -> None:
        self.pinned = dict(pinned_fingerprints or {})
        self.allowed_origins = [o.lower() for o in (allowed_origins or [])]
        self.granted_scopes = set(granted_scopes or [])
        self.require_https = require_https

    def pin(self, manifest: McpToolManifest) -> str:
        """Record (or update) the pinned fingerprint for a tool. Returns it."""
        fp = manifest.fingerprint()
        self.pinned[manifest.name] = fp
        return fp

    def verify_tool(self, manifest: McpToolManifest, origin: str | None = None) -> McpGuardResult:
        """Verify a tool manifest against pin, poison markers, origin, and scopes."""
        violations: list[str] = []

        # 1. Rug-pull / integrity check.
        current = manifest.fingerprint()
        pinned = self.pinned.get(manifest.name)
        if pinned is None:
            violations.append(
                f"tool '{manifest.name}' is not pinned — approve and pin it before use"
            )
        elif pinned != current:
            violations.append(
                f"tool '{manifest.name}' fingerprint changed since approval "
                f"(pinned {pinned[:19]}…, now {current[:19]}…) — possible rug pull"
            )

        # 2. Tool-poisoning markers in the description.
        violations.extend(manifest.scan_description())

        # 3. Origin allowlist + TLS.
        if origin is not None:
            host = _host(origin)
            if self.require_https and origin.lower().startswith("http://") and not _is_loopback(host):
                violations.append(f"remote MCP origin is not HTTPS: {origin}")
            if self.allowed_origins and not any(
                host == o or host.endswith("." + o) for o in self.allowed_origins
            ):
                violations.append(f"MCP origin '{host}' is not on the allowlist")

        # 4. OAuth scope check (least privilege).
        missing = [s for s in manifest.required_scopes if s not in self.granted_scopes]
        if missing:
            violations.append(
                f"tool '{manifest.name}' requires scopes not granted: {', '.join(missing)}"
            )

        passed = not violations
        if not passed:
            logger.warning("MCP tool '%s' failed verification: %s", manifest.name, "; ".join(violations))
        return McpGuardResult(passed=passed, violations=violations)

    def validate_arguments(self, manifest: McpToolManifest, arguments: dict[str, Any]) -> McpGuardResult:
        """Validate tool-call arguments against the manifest's input schema.

        A pragmatic JSON-Schema subset: ``type: object`` with ``properties`` and
        ``required``, plus per-property ``type`` and ``maxLength``. Enough to make
        "reject anything that does not match the expected schema" a one-liner
        without adding a dependency. Use a full JSON-Schema validator for complex
        schemas.
        """
        violations: list[str] = []
        schema = manifest.input_schema or {}
        props = schema.get("properties", {})
        required = schema.get("required", [])

        for name in required:
            if name not in arguments:
                violations.append(f"missing required argument '{name}'")

        additional = schema.get("additionalProperties", True)
        for key, value in arguments.items():
            spec = props.get(key)
            if spec is None:
                if additional is False:
                    violations.append(f"unexpected argument '{key}' (additionalProperties=false)")
                continue
            expected = spec.get("type")
            if expected and not _type_ok(value, expected):
                violations.append(f"argument '{key}' should be {expected}, got {type(value).__name__}")
            max_len = spec.get("maxLength")
            if max_len is not None and isinstance(value, str) and len(value) > max_len:
                violations.append(f"argument '{key}' exceeds maxLength {max_len}")

        passed = not violations
        return McpGuardResult(passed=passed, violations=violations)

    @staticmethod
    def new_session_state() -> dict[str, Any]:
        """Return a fresh, isolated per-session state dict.

        MCP servers must never store user data in globals/singletons. Instantiate
        one of these per session (keyed by session_id) and never share it across
        users — this is the "isolate users and sessions" control made trivial.
        """
        return {}


_JSON_TYPES = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _type_ok(value: Any, expected: str) -> bool:
    py = _JSON_TYPES.get(expected)
    if py is None:
        return True
    if expected == "number" and isinstance(value, bool):
        return False  # bool is a subclass of int; exclude it from number/integer
    if expected == "integer" and isinstance(value, bool):
        return False
    return isinstance(value, py)


def _host(url: str) -> str:
    host = re.sub(r"^[a-zA-Z]+://", "", url).split("/")[0]
    return host.split("@")[-1].split(":")[0].lower()


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")
