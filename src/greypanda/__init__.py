"""
Grey Panda — the calm guardian for AI, agent, and MCP code.

A zero-dependency, standards-anchored AI security toolkit. Grey Panda makes the
secure path the easy path for anyone building LLM-powered, agentic, or Model
Context Protocol (MCP) features — from a solo indie developer to an enterprise
AppSec team.

Everything here is grounded in published standards (OWASP LLM Top 10 2026, OWASP
GenAI Data Security 2026, OWASP Top 10 for Agentic Applications 2026, OWASP AISVS,
the OWASP MCP security guides, the Agent Control Standard, NIST AI 100-2, and
Meta's "Agents Rule of Two"). No bare assertions — every control cites an ID.

Quick start (drop-in runtime guardrails, under two minutes)::

    from greypanda import PromptGuardrail, DLPScanner, OutputGuardrail

    guard = PromptGuardrail()
    dlp = DLPScanner()
    out = OutputGuardrail()

    safe_input = guard.assert_safe(user_input)      # blocks known injection
    clean_input = dlp.redact(safe_input)            # strips PII / secrets
    reply = call_your_llm(clean_input)              # your existing call
    safe_reply = out.sanitize(reply).sanitized_text # blocks exfil / XSS
"""

from ._version import __version__
from .sdk.guardrails import (
    PromptGuardrail,
    OutputGuardrail,
    GuardrailResult,
)
from .sdk.dlp import DLPScanner, DLPResult, DLPMatch
from .sdk.context import SecureContextBuilder, TrustLevel, ContextSegment
from .sdk.agent import (
    AgentSecurityWrapper,
    AgentSession,
    ToolPermission,
    AgentSecurityViolation,
)
from .sdk.audit import AuditLogger, AuditEvent
from .sdk.mcp import (
    McpToolManifest,
    McpServerGuard,
    McpGuardResult,
    McpManifestViolation,
)
from .sdk.acs import (
    Guardian,
    Disposition,
    HookDecision,
    HookContext,
    agent_bill_of_materials,
)

__all__ = [
    "__version__",
    # guardrails
    "PromptGuardrail",
    "OutputGuardrail",
    "GuardrailResult",
    # dlp
    "DLPScanner",
    "DLPResult",
    "DLPMatch",
    # context
    "SecureContextBuilder",
    "TrustLevel",
    "ContextSegment",
    # agent
    "AgentSecurityWrapper",
    "AgentSession",
    "ToolPermission",
    "AgentSecurityViolation",
    # audit
    "AuditLogger",
    "AuditEvent",
    # mcp
    "McpToolManifest",
    "McpServerGuard",
    "McpGuardResult",
    "McpManifestViolation",
    # acs
    "Guardian",
    "Disposition",
    "HookDecision",
    "HookContext",
    "agent_bill_of_materials",
]
