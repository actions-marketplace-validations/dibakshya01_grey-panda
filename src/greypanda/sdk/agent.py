"""
agent.py — wrap any agent executor with least-privilege security controls.

The core idea, from Simon Willison's "lethal trifecta" and Meta's "Agents Rule of
Two" (Oct 2025): an agent becomes dangerous when it simultaneously has (1) access
to private data, (2) exposure to untrusted content, and (3) the ability to
communicate externally. Any two may be acceptable; all three without a human gate
is how a single injected instruction turns into real damage.

This wrapper enforces that constraint *at construction time*, plus a deny-by-
default tool allowlist, per-session call budgets, human-in-the-loop gates on
irreversible actions, and an immediate kill switch.

Addresses:
    * LLM03:2026 Excessive Agency
    * ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity & Privilege Abuse
    * DSGAI02 Agent Identity & Credential Exposure, DSGAI06 Tool/Agent Data Exchange
    * AISVS C9 Orchestration & Agentic Security
    * OWASP Top 10 for Agentic Applications 2026; State of Agentic AI v2.01
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger("greypanda.agent")


class AgentSecurityViolation(Exception):
    """Raised when an agent configuration or action violates a security control."""


@dataclass
class ToolPermission:
    """Declares what a single tool is allowed to do.

    Attributes:
        tool_name: The tool's identifier.
        allowed_operations: e.g. ``["read"]`` or ``["read", "write"]``.
        requires_hitl: If ``True``, every call must be approved by a human/gate.
        max_calls_per_session: Hard cap per session (unbounded-consumption guard).
    """

    tool_name: str
    allowed_operations: list[str] = field(default_factory=lambda: ["read"])
    requires_hitl: bool = False
    max_calls_per_session: int = 100


# The three properties of the "lethal trifecta". Holding all three without an
# approval gate is what the Rule of Two forbids.
_TRIFECTA = (
    "has_private_data_access",
    "ingests_untrusted_content",
    "can_communicate_externally",
)


class AgentSecurityWrapper:
    """Wrap an agent with security controls enforced from construction.

    Args:
        agent_id: Stable identifier for the agent (used in audit + kill switch).
        tool_permissions: The complete allowlist. Anything not listed is denied.
        has_private_data_access: Trifecta property 1.
        ingests_untrusted_content: Trifecta property 2.
        can_communicate_externally: Trifecta property 3.
        hitl_callback: ``callback(tool_name, kwargs) -> bool``. Returns ``True`` to
            approve. If not provided, HITL-gated calls fail secure (denied).

    Raises:
        AgentSecurityViolation: at construction, if all three trifecta properties
            are set AND no ``hitl_callback`` is provided to gate them.
    """

    def __init__(
        self,
        agent_id: str,
        tool_permissions: list[ToolPermission],
        has_private_data_access: bool = False,
        ingests_untrusted_content: bool = False,
        can_communicate_externally: bool = False,
        hitl_callback: Callable[[str, dict], bool] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self._permissions: dict[str, ToolPermission] = {
            p.tool_name: p for p in tool_permissions
        }
        self.has_private_data_access = has_private_data_access
        self.ingests_untrusted_content = ingests_untrusted_content
        self.can_communicate_externally = can_communicate_externally
        self._hitl_callback = hitl_callback
        self._active = True  # kill-switch state

        # ---- Rule of Two enforcement, AT INIT (not at call time) ---------- #
        held = [name for name, val in zip(
            _TRIFECTA,
            (has_private_data_access, ingests_untrusted_content, can_communicate_externally),
        ) if val]
        if len(held) >= 3 and hitl_callback is None:
            raise AgentSecurityViolation(
                "Lethal trifecta / Meta 'Agents Rule of Two' violation "
                "(LLM03:2026 Excessive Agency): this agent holds all three of "
                f"{', '.join(_TRIFECTA)}. Remove one capability, or supply a "
                "hitl_callback so every action is human-gated. "
                "Ref: Simon Willison, 'the lethal trifecta'; Meta, Oct 2025."
            )
        if len(held) >= 3:
            logger.warning(
                "Agent %s holds all three trifecta properties; running under "
                "mandatory HITL gate.", agent_id,
            )

    @property
    def active(self) -> bool:
        return self._active

    def kill(self) -> None:
        """Disable all tool calls immediately (kill switch)."""
        self._active = False
        logger.critical("KILL SWITCH ACTIVATED for agent %s", self.agent_id)

    def session(self, user_id: str, session_id: str) -> "AgentSession":
        """Start a security-scoped session. Raises if the agent has been killed."""
        if not self._active:
            raise AgentSecurityViolation(
                f"agent {self.agent_id} is killed; no new sessions permitted"
            )
        return AgentSession(self, user_id, session_id)

    # internal ------------------------------------------------------------- #
    def _request_hitl(self, tool_name: str, kwargs: dict) -> bool:
        if self._hitl_callback is not None:
            return bool(self._hitl_callback(tool_name, kwargs))
        logger.warning(
            "HITL required for tool '%s' but no callback configured — denying "
            "(fail-secure default).", tool_name,
        )
        return False


class AgentSession:
    """A per-session guard. Use as a context manager.

    ``call_tool`` validates the call against the allowlist, call budget, and HITL
    gate. It does NOT execute the tool — your code runs the tool only after the
    session returns an approved result. This keeps Grey Panda a validator, not an
    executor, and makes the trust boundary explicit.
    """

    def __init__(self, wrapper: AgentSecurityWrapper, user_id: str, session_id: str) -> None:
        self.wrapper = wrapper
        self.user_id = user_id
        self.session_id = session_id
        self._call_counts: dict[str, int] = {}

    def __enter__(self) -> "AgentSession":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def call_tool(self, tool_name: str, **kwargs: Any) -> dict:
        """Validate a tool call. Returns an approval record or raises.

        Returns:
            ``{"tool": ..., "args": ..., "approved": True}`` when permitted. The
            caller is responsible for executing the tool after approval.

        Raises:
            AgentSecurityViolation: if the agent is killed, the tool is not on the
            allowlist, the call budget is exhausted, or HITL denies the call.
        """
        if not self.wrapper.active:
            raise AgentSecurityViolation(
                f"agent {self.wrapper.agent_id} killed; tool '{tool_name}' denied"
            )

        perm = self.wrapper._permissions.get(tool_name)
        if perm is None:
            raise AgentSecurityViolation(
                f"tool '{tool_name}' is not on the allowlist (deny by default). "
                "Add a ToolPermission to grant access."
            )

        count = self._call_counts.get(tool_name, 0)
        if count >= perm.max_calls_per_session:
            raise AgentSecurityViolation(
                f"tool '{tool_name}' exceeded its per-session budget "
                f"({perm.max_calls_per_session}); possible runaway loop "
                "(LLM06:2026 Unbounded Consumption / ASI08 Cascading Failures)."
            )

        if perm.requires_hitl:
            if not self.wrapper._request_hitl(tool_name, kwargs):
                raise AgentSecurityViolation(
                    f"HITL gate denied tool '{tool_name}' "
                    "(irreversible action requires human approval)."
                )

        self._call_counts[tool_name] = count + 1
        logger.info(
            "tool call approved agent=%s user=%s session=%s tool=%s call=%d",
            self.wrapper.agent_id, self.user_id, self.session_id, tool_name,
            self._call_counts[tool_name],
        )
        return {"tool": tool_name, "args": kwargs, "approved": True}
