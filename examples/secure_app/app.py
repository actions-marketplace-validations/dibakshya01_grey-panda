"""
The SECURE version of examples/vulnerable_app/app.py, using Grey Panda controls.

    gp scan examples/secure_app --profile enterprise   # -> no findings

Every risky pattern from the vulnerable app is replaced with a drop-in Grey Panda
control. This is what "the secure path is the easy path" looks like in practice.
"""

import os

from greypanda import (
    AgentSecurityWrapper,
    AuditLogger,
    DLPScanner,
    OutputGuardrail,
    PromptGuardrail,
    SecureContextBuilder,
    ToolPermission,
)
from greypanda.sdk.mcp import McpServerGuard, McpToolManifest

# Secrets come from the environment / a secret manager — never hardcoded.
API_KEY = os.environ["AI_GATEWAY_KEY"]
# All model calls go through the org AI gateway (not a provider endpoint directly).
GATEWAY_URL = os.environ.get("AI_GATEWAY_URL", "https://ai-gateway.internal.example")

_guard = PromptGuardrail()
_dlp = DLPScanner()
_out = OutputGuardrail()  # safe by default: HTML-escapes model output before render
_audit = AuditLogger(agent_id="support-bot", session_id="demo")


def ask_llm(user_input, user_id):
    # Screen input, then redact PII/secrets before the model ever sees it.
    safe = _guard.assert_safe(user_input)
    clean = _dlp.redact(safe, context="chat_input")

    # Instructions and untrusted user text are kept in separate, tagged roles.
    messages = (
        SecureContextBuilder(user_id=user_id, max_tokens=8000)
        .add_system("You are a helpful assistant.")
        .add_user(clean)
        .build()
    )

    # A real provider call — DLP ran just above, and max_tokens caps the output.
    # This scans clean because it *satisfies* the rules, not because it hides the
    # call behind a wrapper the scanner can't see.
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        max_tokens=512,
    ).choices[0].message.content

    # Scan and neutralise output before it goes anywhere downstream.
    reply = _dlp.redact(reply, context="chat_output")
    return _out.sanitize(reply).sanitized_text


def search_docs(query, user_id):
    store = get_vector_store()
    # Retrieval is always scoped to the requesting user.
    return store.similarity_search(query, k=5, filter={"accessible_by": user_id})


def run_refund_workflow(user_id):
    # Refund is a HITL-gated tool on a least-privilege wrapper.
    wrapper = AgentSecurityWrapper(
        agent_id="refund-agent",
        tool_permissions=[
            ToolPermission("issue_refund", allowed_operations=["write"], requires_hitl=True),
        ],
        has_private_data_access=True,
        ingests_untrusted_content=True,
        # third property kept off -> respects the Rule of Two
        can_communicate_externally=False,
    )
    with wrapper.session(user_id=user_id, session_id="s1") as session:
        return session.call_tool("issue_refund", order_id="A123", amount=10)


def run_mcp_tool(manifest_dict, arguments, guard: McpServerGuard):
    manifest = McpToolManifest(**manifest_dict)
    verdict = guard.verify_tool(manifest)
    if not verdict.passed:
        raise PermissionError("; ".join(verdict.violations))
    args_ok = guard.validate_arguments(manifest, arguments)
    if not args_ok.passed:
        raise ValueError("; ".join(args_ok.violations))
    return dispatch_validated_tool(manifest.name, arguments)


# --- these would be your real implementations -------------------------------- #
# Your provider client, pointed at the org AI gateway (never a personal key/prod
# endpoint). e.g. client = openai.OpenAI(base_url=GATEWAY_URL, api_key=API_KEY)
client = None


def get_vector_store():
    raise NotImplementedError


def dispatch_validated_tool(name, arguments):
    raise NotImplementedError
