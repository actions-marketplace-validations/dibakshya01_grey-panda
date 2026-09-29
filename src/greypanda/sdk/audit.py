"""
audit.py — structured, privacy-preserving audit events for AI actions.

Every security decision Grey Panda makes should be auditable — but audit logs
must never become a new leak channel. The invariant here is absolute: audit
events carry structure and decisions, never raw prompt or completion text and
never raw secret/PII values.

Addresses:
    * DSGAI14 Excessive Telemetry & Monitoring Leakage
    * DSGAI07 Data Governance, Lifecycle & Classification for AI
    * AISVS C12 Monitoring, Logging & Anomaly Detection

Events are emitted as single-line JSON via the standard ``logging`` module under
the logger name ``greypanda.audit`` (override the org prefix via ``org``), so you
can ship them straight to a SIEM (Splunk / ELK / Datadog) with your existing
logging pipeline.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AuditEvent:
    """A single audit record.

    INVARIANT: ``metadata`` must NEVER contain raw prompt/completion text or raw
    secret values. Only safe, structural fields (counts, category names, IDs).
    """

    event_type: str
    agent_id: str
    session_id: str
    user_id: str
    passed: bool
    violations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


class AuditLogger:
    """Emit structured audit events with zero raw text.

    Args:
        agent_id: Identifier of the agent/service producing the events.
        session_id: The current session identifier.
        org: Logger-name prefix, e.g. ``"acme"`` -> logger ``acme.ai.audit``.
    """

    def __init__(self, agent_id: str, session_id: str, org: str = "greypanda") -> None:
        self.agent_id = agent_id
        self.session_id = session_id
        self._logger = logging.getLogger(f"{org}.ai.audit")

    def _emit(self, event: AuditEvent) -> AuditEvent:
        if not event.timestamp:
            event.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._logger.info(json.dumps(asdict(event), separators=(",", ":"), sort_keys=True))
        return event

    def log_prompt_check(
        self, user_id: str, passed: bool, violations: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        return self._emit(AuditEvent(
            "prompt_check", self.agent_id, self.session_id, user_id, passed,
            violations or [], metadata or {},
        ))

    def log_dlp_scan(
        self, user_id: str, passed: bool, categories_hit: list[str] | None = None,
        context: str = "",
    ) -> AuditEvent:
        return self._emit(AuditEvent(
            "dlp_scan", self.agent_id, self.session_id, user_id, passed,
            categories_hit or [], {"context": context} if context else {},
        ))

    def log_tool_call(
        self, user_id: str, tool_name: str, approved: bool, call_count: int,
    ) -> AuditEvent:
        return self._emit(AuditEvent(
            "tool_call", self.agent_id, self.session_id, user_id, approved,
            [] if approved else ["hitl_denied"],
            {"tool": tool_name, "call_count": call_count},
        ))

    def log_output_check(
        self, user_id: str, passed: bool, violations: list[str] | None = None,
    ) -> AuditEvent:
        return self._emit(AuditEvent(
            "output_check", self.agent_id, self.session_id, user_id, passed,
            violations or [], {},
        ))

    def log_mcp_event(
        self, user_id: str, event: str, passed: bool, violations: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        return self._emit(AuditEvent(
            f"mcp_{event}", self.agent_id, self.session_id, user_id, passed,
            violations or [], metadata or {},
        ))
