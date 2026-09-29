"""
rules.py — the Grey Panda scanner rule set.

Each rule is standards-anchored: it names a specific OWASP ID and gives a concrete
remediation that points at a Grey Panda SDK control. Rules are intentionally
high-precision — where a naive pattern would be noisy, a ``suppress`` guard makes
the safe form pass cleanly. Contributors: add rules by appending to ``RULES``
(see CONTRIBUTING.md); every new rule needs a matching bad + good example.

Rule ID prefixes:
    GP-AI-###   general LLM / data-security rules
    GP-MCP-###  Model Context Protocol rules
    GP-AGT-###  agentic-application rules
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Which profiles include which severities is decided in profiles.py; a rule may
# also restrict itself to specific profiles via ``profiles``.
ALL_PROFILES = ("solo", "team", "enterprise")


@dataclass
class Rule:
    id: str
    owasp_id: str
    severity: str
    title: str
    description: str
    remediation: str
    pattern: str | None = None
    suppress: str | None = None  # if this matches the same line, skip (guard)
    file_globs: tuple[str, ...] = ("*.py",)
    sdk: str = ""  # e.g. "from greypanda import DLPScanner"
    profiles: tuple[str, ...] = ALL_PROFILES
    _rx: "re.Pattern[str] | None" = field(default=None, repr=False, compare=False)
    _sup: "re.Pattern[str] | None" = field(default=None, repr=False, compare=False)

    def compiled(self) -> "re.Pattern[str] | None":
        if self.pattern and self._rx is None:
            self._rx = re.compile(self.pattern)
        return self._rx

    def suppressor(self) -> "re.Pattern[str] | None":
        if self.suppress and self._sup is None:
            self._sup = re.compile(self.suppress)
        return self._sup


RULES: list[Rule] = [
    # ---------------------- LLM01 Prompt Injection ----------------------- #
    Rule(
        id="GP-AI-001",
        owasp_id="LLM01:2026",
        severity=CRITICAL,
        title="User input interpolated directly into a prompt string",
        description="Untrusted user input is f-string/format/concat-ed straight into a "
                    "prompt, collapsing the boundary between instructions and data.",
        remediation="Build context with SecureContextBuilder.add_user(); never f-string "
                    "user input into a system/prompt string.",
        pattern=r"""(?ix)(?:prompt|system_prompt|messages|template)\s*(?:=|\+=|\+)\s*(?:f['"]|.*?\.format\(|.*?%\s*\()""",
        suppress=r"SecureContextBuilder|add_user\(",
        sdk="from greypanda import SecureContextBuilder",
    ),
    Rule(
        id="GP-AI-002",
        owasp_id="LLM01:2026",
        severity=CRITICAL,
        title="System prompt concatenated with user content in one string",
        description="System instructions and user content are joined into a single "
                    "string instead of separate typed roles.",
        remediation="Use separate system and user message roles. Never concatenate "
                    "system_prompt + user_input.",
        pattern=r"""(?ix)system_prompt\s*\+\s*.*?(?:user|input|query|message)""",
        sdk="from greypanda import SecureContextBuilder",
    ),
    Rule(
        id="GP-AI-017",
        owasp_id="LLM01:2026",
        severity=MEDIUM,
        title="External/fetched content sent to the model without trust tagging",
        description="Content from requests/httpx/urllib/fetch is passed toward the model "
                    "without being wrapped as untrusted (indirect prompt injection).",
        remediation="Wrap external content with SecureContextBuilder.add_external_content() "
                    "so the model is told to treat it as data, not instructions.",
        pattern=r"""(?ix)\b(?:requests|httpx|urllib|aiohttp)\b.*?\.(?:get|post|request)\(""",
        suppress=r"add_external_content|SecureContextBuilder",
        sdk="from greypanda import SecureContextBuilder",
        profiles=("team", "enterprise"),
    ),

    # ------------------ LLM02 Sensitive Info Disclosure ------------------ #
    Rule(
        id="GP-AI-003",
        owasp_id="LLM02:2026",
        severity=HIGH,
        title="LLM call without a preceding DLP scan",
        description="A model call is made on input that has not been scanned for PII and "
                    "secrets, risking sensitive-data leakage to the provider/logs.",
        remediation="Run DLPScanner().redact(text) on inputs (and outputs) before the call.",
        pattern=r"""(?ix)\b(?:openai|anthropic|client|llm|bedrock|litellm|genai)\b[^\n]*?\.(?:chat|complete|completions|invoke|generate|messages)\b""",
        suppress=r"DLPScanner|\.redact\(|\.scan\(",
        sdk="from greypanda import DLPScanner",
        profiles=("team", "enterprise"),
    ),
    Rule(
        id="GP-AI-010",
        owasp_id="DSGAI01",
        severity=CRITICAL,
        title="Hardcoded AI provider key or secret in source",
        description="An API key or secret is embedded in source code where it can leak via "
                    "version control, logs, or model context.",
        remediation="Load secrets from environment or a secret manager; rotate any exposed "
                    "key immediately. Never place a secret in model context.",
        pattern=r"""(?ix)(?:sk-ant-[a-z0-9_\-]{20,}|sk-(?:proj-)?[a-z0-9_\-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|(?:api[_-]?key|secret[_-]?key|token|password)\s*=\s*['"][^'"]{12,}['"])""",
        suppress=r"os\.environ|getenv|os\.getenv|<[A-Z_]+>|EXAMPLE|example|dummy|xxxx|your[_-]?key|placeholder|redacted|\.\.\.",
        file_globs=("*.py", "*.js", "*.ts", "*.env", "*.yaml", "*.yml", "*.json"),
        sdk="",
    ),
    Rule(
        id="GP-AI-011",
        owasp_id="DSGAI14",
        severity=HIGH,
        title="Raw prompt or model response written to logs",
        description="Prompt/response/user_message text is logged directly, turning your "
                    "telemetry pipeline into a sensitive-data leak channel.",
        remediation="Use AuditLogger, which emits structured events with no raw text.",
        pattern=r"""(?ix)\b(?:logger|logging|log|print)\b[^\n]*?\(\s*[^\n]*?(?:\bprompt\b|\bcompletion\b|\bresponse\b|\buser_message\b|\buser_input\b)""",
        suppress=r"AuditLogger|redact\(|\bmask\(|DLPScanner",
        sdk="from greypanda import AuditLogger",
        profiles=("team", "enterprise"),
    ),

    # ---------------------- LLM03 Excessive Agency ----------------------- #
    Rule(
        id="GP-AGT-005",
        owasp_id="LLM03:2026",
        severity=CRITICAL,
        title="Irreversible agent action without a human-in-the-loop gate",
        description="A tool that sends/deletes/refunds/transfers/executes is defined "
                    "without any approval gate; one injected instruction could trigger it.",
        remediation="Wrap tools with AgentSecurityWrapper and set requires_hitl=True on any "
                    "ToolPermission with side effects.",
        pattern=r"""(?ix)\bdef\s+(?:send|delete|cancel|refund|transfer|wire|pay|purchase|update|write|execute|deploy|drop)_\w+\s*\(""",
        suppress=r"hitl|human_approval|requires_approval|requires_hitl|approve|confirm",
        sdk="from greypanda import AgentSecurityWrapper, ToolPermission",
    ),
    Rule(
        id="GP-AGT-006",
        owasp_id="LLM03:2026",
        severity=HIGH,
        title="Agent tool marked as not requiring human approval",
        description="A ToolPermission (or similar) explicitly disables the HITL gate. "
                    "Confirm the tool has no irreversible side effects.",
        remediation="Set requires_hitl=True for tools that can change state, move money, or "
                    "touch production data.",
        pattern=r"""(?ix)requires_hitl\s*=\s*False""",
        sdk="from greypanda import ToolPermission",
        profiles=("team", "enterprise"),
    ),

    # ------------------------- LLM04 Supply Chain ------------------------ #
    Rule(
        id="GP-AI-007",
        owasp_id="LLM04:2026",
        severity=HIGH,
        title="Unpinned AI/agent dependency",
        description="An AI framework dependency is declared without an exact version pin, "
                    "exposing you to malicious or breaking upgrades.",
        remediation="Pin AI dependencies to exact versions (==) and enable Dependabot/Snyk.",
        pattern=r"""(?ix)^\s*['"]?(?:langchain|langgraph|openai|anthropic|litellm|llama[-_]?index|haystack|transformers|crewai|autogen|semantic-kernel|mcp)\b""",
        suppress=r"==\s*\d|@\s*git|#\s*noqa|#\s*grey-?panda:\s*ignore",
        file_globs=("requirements*.txt", "pyproject.toml", "setup.cfg", "Pipfile"),
        sdk="",
    ),

    # ------------------------ LLM06 Unbounded ---------------------------- #
    Rule(
        id="GP-AI-012",
        owasp_id="LLM06:2026",
        severity=MEDIUM,
        title="Model call without an explicit token/output cap",
        description="A completion/chat call is made without max_tokens, allowing "
                    "unbounded output and cost/DoS exposure.",
        remediation="Set max_tokens on the call and add per-user rate limiting.",
        pattern=r"""(?ix)\.(?:create|chat|complete|completions|invoke|generate)\s*\(""",
        suppress=r"max_tokens|max_output_tokens|max_completion_tokens",
        sdk="",
        profiles=("enterprise",),
    ),

    # ---------------------- LLM08 Hidden Context ------------------------- #
    Rule(
        id="GP-AI-008",
        owasp_id="LLM08:2026",
        severity=HIGH,
        title="System prompt returned in an API response",
        description="The system prompt / hidden instructions are placed into an outbound "
                    "response, exposing internal logic and expanding the attack surface.",
        remediation="Never include system_prompt content in output returned to clients.",
        pattern=r"""(?ix)(?:return|['"](?:response|content|message|data)['"]\s*:)\s*[^\n]*\bsystem_prompt\b""",
        sdk="",
    ),

    # ------------- LLM09 Vector & Embedding / RAG isolation -------------- #
    Rule(
        id="GP-AI-009",
        owasp_id="LLM09:2026",
        severity=HIGH,
        title="Vector store query without a user-scoped filter",
        description="A similarity search/retrieval runs without a per-user filter, risking "
                    "cross-user data bleed from the vector store.",
        remediation="Always pass a user-scoped filter (e.g. filter={'accessible_by': user_id}) "
                    "to retrieval calls.",
        pattern=r"""(?ix)\.(?:similarity_search(?:_with_score)?|max_marginal_relevance_search|as_retriever|get_relevant_documents|mmr_search)\s*\(""",
        suppress=r"filter\s*=|where\s*=|user_id|namespace\s*=|scope\s*=|accessible_by",
        sdk="",
        profiles=("team", "enterprise"),
    ),

    # -------------------- LLM10 Improper Output -------------------------- #
    Rule(
        id="GP-AI-004",
        owasp_id="LLM10:2026",
        severity=CRITICAL,
        title="Raw model output rendered as HTML without sanitization",
        description="Model output flows into mark_safe/|safe/innerHTML/"
                    "dangerouslySetInnerHTML, enabling XSS from a manipulated response.",
        remediation="Apply OutputGuardrail.sanitize() and rely on template autoescaping; "
                    "never mark model output as safe HTML.",
        pattern=r"""(?ix)(?:mark_safe|dangerouslySetInnerHTML|\.innerHTML\s*=|\|\s*safe\b|Markup\()[^\n]*?(?:llm|gpt|ai_|response|completion|answer|model_output)""",
        sdk="from greypanda import OutputGuardrail",
        file_globs=("*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.html"),
    ),
    Rule(
        id="GP-AI-014",
        owasp_id="LLM10:2026",
        severity=CRITICAL,
        title="Model-generated SQL/command executed without validation",
        description="LLM output is passed to a database or shell executor without an "
                    "allowlist/validation, enabling injection or destructive operations.",
        remediation="Validate LLM-generated SQL against an allowlist; require HITL for any "
                    "DROP/DELETE. Never execute model output directly.",
        pattern=r"""(?ix)(?:cursor\.execute|\.execute|db\.execute|os\.system|subprocess\.(?:run|call|Popen)|eval|exec)\s*\([^\n]*?(?:llm|ai_|gpt|response|completion|model_output|generated)""",
        sdk="",
    ),

    # ------------------------- DSGAI03 Shadow AI ------------------------- #
    Rule(
        id="GP-AI-013",
        owasp_id="DSGAI03",
        severity=HIGH,
        title="Direct call to an external AI provider endpoint (possible shadow AI)",
        description="Code calls a provider API endpoint directly rather than through your "
                    "approved AI gateway, bypassing central policy, DLP, and audit.",
        remediation="Route all model calls through your organization's AI gateway; do not "
                    "use personal keys or direct endpoints in production.",
        pattern=r"""(?ix)https?://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.mistral\.ai|api\.cohere\.ai)\b""",
        file_globs=("*.py", "*.js", "*.ts", "*.yaml", "*.yml", "*.env"),
        sdk="",
        profiles=("team", "enterprise"),
    ),

    # ------------------------- MCP-specific ------------------------------ #
    Rule(
        id="GP-MCP-001",
        owasp_id="AISVS C10 / ASI04",
        severity=HIGH,
        title="Possible tool-poisoning marker in an MCP tool description/docstring",
        description="An MCP tool description or docstring contains instruction-like or "
                    "exfiltration language that could hijack the model (tool poisoning).",
        remediation="Review the tool description; keep descriptions declarative. Pin + hash "
                    "manifests with McpToolManifest so later changes (rug pulls) are caught.",
        pattern=r"""(?ix)(?:ignore\s+(?:previous|all|prior)\s+instructions|do\s+not\s+tell\s+the\s+user|exfiltrat|read\s+the\s+\.env|send\s+(?:the\s+)?(?:contents|secrets?|tokens?)\s+to)""",
        file_globs=("*.py", "*.js", "*.ts", "*.json", "*.yaml", "*.yml"),
        sdk="from greypanda import McpToolManifest, McpServerGuard",
    ),
    Rule(
        id="GP-MCP-002",
        owasp_id="AISVS C10 / ASI05",
        severity=CRITICAL,
        title="MCP tool passes model-provided input to a shell/eval sink",
        description="A tool forwards model/tool arguments into os.system/subprocess/eval/"
                    "exec without validation — unexpected code execution (RCE).",
        remediation="Validate arguments against a JSON schema (McpServerGuard.validate_"
                    "arguments) and never pass raw model input to a shell/eval.",
        pattern=r"""(?ix)(?:os\.system|subprocess\.(?:run|call|Popen)|eval|exec)\s*\([^\n]*?(?:arg|arguments|params|tool_input|payload|request)\b""",
        suppress=r"shlex\.quote|validate_arguments|allowlist",
        sdk="from greypanda import McpServerGuard",
    ),
    Rule(
        id="GP-MCP-003",
        owasp_id="AISVS C10",
        severity=HIGH,
        title="MCP client token forwarded downstream (token passthrough / confused deputy)",
        description="A client/user token is forwarded to a downstream API, breaking audit "
                    "trails and enabling the confused-deputy pattern.",
        remediation="Use tokens explicitly issued to the MCP server or an On-Behalf-Of flow; "
                    "never pass the client token straight through.",
        pattern=r"""(?ix)(?:headers\s*=\s*\{[^\n]*Authorization[^\n]*(?:client_token|incoming|request\.headers)|Authorization['"]\s*:\s*[^\n]*request\.headers)""",
        file_globs=("*.py", "*.js", "*.ts"),
        sdk="",
        profiles=("team", "enterprise"),
    ),
    Rule(
        id="GP-MCP-004",
        owasp_id="AISVS C10",
        severity=HIGH,
        title="Remote MCP endpoint configured over plaintext HTTP",
        description="A non-loopback MCP server URL uses http:// with no TLS, exposing tool "
                    "traffic and tokens to interception.",
        remediation="Use HTTPS (TLS 1.2+) for all remote MCP connections; only bind plain "
                    "HTTP to 127.0.0.1 for local STDIO/loopback use.",
        pattern=r"""(?ix)['"]http://(?!localhost|127\.0\.0\.1|\[::1\])[^'"\s]+['"]""",
        file_globs=("*.py", "*.js", "*.ts", "*.json", "*.yaml", "*.yml", "*.toml", "*.env"),
        sdk="from greypanda import McpServerGuard",
        profiles=("team", "enterprise"),
    ),

    # --------------- Agentic: inter-agent + memory ----------------------- #
    Rule(
        id="GP-AGT-007",
        owasp_id="ASI06",
        severity=MEDIUM,
        title="Agent memory write without validation/attribution",
        description="A value is written into agent long-term memory/vector store with no "
                    "validation or source attribution (memory poisoning risk).",
        remediation="Validate every memory update, attach source attribution, and isolate "
                    "memory by session/user. Consider a TTL on stored entries.",
        pattern=r"""(?ix)\b(?:memory|vectorstore|vector_store|index|collection)\b[^\n]*?\.(?:add|add_texts|upsert|save|write|insert|store)\s*\(""",
        suppress=r"validate|attribut|verify|source=|user_id|namespace",
        sdk="",
        profiles=("enterprise",),
    ),
]


def rules_for_profile(profile: str) -> list[Rule]:
    """Return the rules active for a given profile name."""
    return [r for r in RULES if profile in r.profiles]
