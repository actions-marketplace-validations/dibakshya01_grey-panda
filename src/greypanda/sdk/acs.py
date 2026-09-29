"""
acs.py — an Agent Control Standard (ACS) compatible Guardian.

ACS (an OWASP GenAI Security Project standard) defines a way to place a *Guardian*
between an agent and its actions: before a tool call executes, the Guardian
inspects it and returns one of five dispositions — allow, deny, modify, ask, or
defer — deterministically, before any optional LLM-based judgement.

Grey Panda ships a lightweight, dependency-free Guardian that composes your
policies over the ACS ``steps/toolCallRequest`` and ``steps/toolCallResult`` hook
points, plus an Agent Bill of Materials (AgBOM) emitter. It is wire-compatible in
spirit with ACS v0.1.0 request/response envelopes (JSON-RPC-style dicts), so you
can adopt the model now and connect a full ACS transport later.

Addresses:
    * Agent Control Standard (ACS) — Instrument pillar, 5 dispositions, AgBOM
    * LLM03:2026 Excessive Agency; ASI02 Tool Misuse; ASI10 Rogue Agents
    * AISVS C9 Orchestration & Agentic Security
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Disposition(str, Enum):
    """The five ACS dispositions a Guardian may return for an action."""

    ALLOW = "allow"      # permit unchanged
    DENY = "deny"        # block
    MODIFY = "modify"    # permit with parameter overrides
    ASK = "ask"          # route to a human/agent/service approver
    DEFER = "defer"      # postpone pending more context


ACS_VERSION = "0.1.0"

# ACS hook lifecycle points this Guardian understands.
HOOK_TOOL_CALL_REQUEST = "steps/toolCallRequest"
HOOK_TOOL_CALL_RESULT = "steps/toolCallResult"


@dataclass
class HookContext:
    """The action under review at a hook point.

    Attributes:
        hook: One of the ``HOOK_*`` constants.
        agent_id: The observed agent.
        tool_name: Tool being invoked (for tool hooks).
        arguments: Proposed tool arguments.
        result: Tool result (for the result hook).
        metadata: Any extra context (session_id, user_id, trust info, …).
    """

    hook: str = HOOK_TOOL_CALL_REQUEST
    agent_id: str = ""
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class HookDecision:
    """A Guardian verdict, shaped like an ACS response envelope."""

    disposition: Disposition
    reasoning: str = ""
    modifications: dict[str, Any] = field(default_factory=dict)

    def to_envelope(self, request_id: str = "") -> dict[str, Any]:
        """Serialise to an ACS-style response envelope (dict)."""
        env: dict[str, Any] = {
            "acs_version": ACS_VERSION,
            "type": "response",
            "request_id": request_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "decision": self.disposition.value,
        }
        if self.reasoning:
            env["reasoning"] = self.reasoning
        if self.modifications:
            env["modifications"] = self.modifications
        return env


# A policy takes the hook context and returns a HookDecision, or None to abstain.
Policy = Callable[[HookContext], "HookDecision | None"]


class Guardian:
    """Compose deterministic policies into an ACS Guardian.

    Policies are evaluated in order. The first policy that returns a decision
    wins, with precedence so that a hard stop can never be undone by a later
    permissive policy: any ``DENY`` short-circuits immediately; otherwise the
    most restrictive decision seen (ask/defer/modify over allow) is returned.
    If no policy fires, the ``default`` disposition applies.

    Args:
        policies: Ordered list of policy callables.
        default: Disposition when no policy returns a decision. Defaults to ALLOW
            for composability (you add your own deny/allowlist policies). **This is
            fail-OPEN: an action no policy matched is permitted.** For a security
            posture, pass ``default=Disposition.DENY`` (or ``ASK``) and add explicit
            allow policies — an allowlist is safer than a denylist.
    """

    _RANK = {
        Disposition.ALLOW: 0,
        Disposition.MODIFY: 1,
        Disposition.DEFER: 2,
        Disposition.ASK: 3,
        Disposition.DENY: 4,
    }

    def __init__(self, policies: list[Policy] | None = None, default: Disposition = Disposition.ALLOW) -> None:
        self.policies: list[Policy] = list(policies or [])
        self.default = default

    def add_policy(self, policy: Policy) -> Guardian:
        self.policies.append(policy)
        return self

    def evaluate(self, ctx: HookContext) -> HookDecision:
        """Run all policies over ``ctx`` and return the winning decision."""
        best: HookDecision | None = None
        for policy in self.policies:
            decision = policy(ctx)
            if decision is None:
                continue
            if decision.disposition is Disposition.DENY:
                return decision  # hard stop wins immediately
            if best is None or self._RANK[decision.disposition] > self._RANK[best.disposition]:
                best = decision
        return best or HookDecision(self.default, reasoning="no policy fired; default")

    def handle_request(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Handle an ACS-style request envelope and return a response envelope."""
        payload = envelope.get("payload", {})
        ctx = HookContext(
            hook=envelope.get("hook", HOOK_TOOL_CALL_REQUEST),
            agent_id=payload.get("agent_id", ""),
            tool_name=payload.get("tool_name", ""),
            arguments=payload.get("arguments", {}),
            result=payload.get("result"),
            metadata=payload.get("metadata", {}),
        )
        decision = self.evaluate(ctx)
        return decision.to_envelope(request_id=envelope.get("request_id", ""))


# --------------------------------------------------------------------------- #
# Ready-made policies
# --------------------------------------------------------------------------- #
def deny_tools(*tool_names: str, reason: str = "tool is denied by policy") -> Policy:
    """Deny any call to the named tools."""
    denied = set(tool_names)

    def _policy(ctx: HookContext) -> HookDecision | None:
        if ctx.tool_name in denied:
            return HookDecision(Disposition.DENY, reasoning=f"{ctx.tool_name}: {reason}")
        return None

    return _policy


def ask_on_tools(*tool_names: str, reason: str = "requires approval") -> Policy:
    """Route calls to the named (irreversible) tools to a human approver."""
    watched = set(tool_names)

    def _policy(ctx: HookContext) -> HookDecision | None:
        if ctx.tool_name in watched:
            return HookDecision(Disposition.ASK, reasoning=f"{ctx.tool_name}: {reason}")
        return None

    return _policy


def allowlist_tools(*tool_names: str) -> Policy:
    """Deny anything not on the allowlist (deny by default)."""
    allowed = set(tool_names)

    def _policy(ctx: HookContext) -> HookDecision | None:
        if ctx.tool_name and ctx.tool_name not in allowed:
            return HookDecision(
                Disposition.DENY,
                reasoning=f"{ctx.tool_name} not on allowlist (deny by default)",
            )
        return None

    return _policy


def agent_bill_of_materials(
    agent_id: str,
    tools: list[str],
    models: list[str] | None = None,
    mcp_servers: list[str] | None = None,
    data_sources: list[str] | None = None,
    version: str = "0.0.0",
) -> dict[str, Any]:
    """Emit a minimal Agent Bill of Materials (AgBOM) in a CycloneDX-flavoured shape.

    An AgBOM enumerates what an agent is *made of* — its tools, models, MCP
    servers, and data sources — so reviewers can reason about its blast radius
    and supply chain. This is a compact, dependency-free representation; feed it
    into a full CycloneDX/SPDX pipeline when you have one.
    """
    components: list[dict[str, Any]] = []
    for t in tools:
        components.append({"type": "tool", "name": t})
    for m in models or []:
        components.append({"type": "machine-learning-model", "name": m})
    for s in mcp_servers or []:
        components.append({"type": "service", "name": s, "kind": "mcp-server"})
    for d in data_sources or []:
        components.append({"type": "data", "name": d})
    return {
        "bomFormat": "GreyPanda-AgBOM",
        "specVersion": "1.0",
        "acsVersion": ACS_VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metadata": {"component": {"type": "application", "name": agent_id, "version": version}},
        "components": components,
    }
