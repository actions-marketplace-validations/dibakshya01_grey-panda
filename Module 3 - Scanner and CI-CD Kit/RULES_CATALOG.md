# 🐼 Grey Panda — Scanner Rules Catalog

**27 rules.** 🔴 7 Critical · 🟠 13 High · 🟡 7 Medium · ⚪ 0 Low

Every rule cites a specific standard ID and points at the Grey Panda control that fixes it. Rules run per-profile (`solo` / `team` / `enterprise`) and can be silenced per-line with `# grey-panda: ignore` or per-file with `.greypandaignore`.

> This file is generated from the code (`tools/generate_rules_catalog.py`). Do not edit by hand.

| Rule | Sev | OWASP / AISVS | Title | Profiles | Fix (SDK) |
| --- | --- | --- | --- | --- | --- |
| `GP-AGT-005` | 🔴 | LLM03:2026 | Irreversible agent action without a human-in-the-loop gate | all | `from greypanda import AgentSecurityWrapper, ToolPermission` |
| `GP-AI-001` | 🔴 | LLM01:2026 | User input interpolated directly into a prompt string | all | `from greypanda import SecureContextBuilder` |
| `GP-AI-002` | 🔴 | LLM01:2026 | System prompt concatenated with user content in one string | all | `from greypanda import SecureContextBuilder` |
| `GP-AI-004` | 🔴 | LLM10:2026 | Raw model output rendered as HTML without sanitization | all | `from greypanda import OutputGuardrail` |
| `GP-AI-010` | 🔴 | DSGAI01 | Hardcoded AI provider key or secret in source | all | — |
| `GP-AI-014` | 🔴 | LLM10:2026 | Model-generated SQL/command executed without validation | all | — |
| `GP-MCP-002` | 🔴 | AISVS C10 / ASI05 | MCP tool passes model-provided input to a shell/eval sink | all | `from greypanda import McpServerGuard` |
| `GP-AGT-006` | 🟠 | LLM03:2026 | Agent tool marked as not requiring human approval | team, enterprise | `from greypanda import ToolPermission` |
| `GP-AGT-008` | 🟠 | ASI05 | Shell command executed with shell=True and an interpolated value | all | `from greypanda import McpServerGuard` |
| `GP-AI-007` | 🟠 | LLM04:2026 | Unpinned AI/agent dependency | all | — |
| `GP-AI-008` | 🟠 | LLM08:2026 | System prompt returned in an API response | all | — |
| `GP-AI-009` | 🟠 | LLM09:2026 | Vector store query without a user-scoped filter | team, enterprise | — |
| `GP-AI-011` | 🟠 | DSGAI14 | Raw prompt or model response written to logs | team, enterprise | `from greypanda import AuditLogger` |
| `GP-AI-013` | 🟠 | DSGAI03 | Direct call to an external AI provider endpoint (possible shadow AI) | team, enterprise | — |
| `GP-AI-020` | 🟠 | LLM10:2026 | Unsafe deserialization of untrusted / model-influenced data | all | — |
| `GP-AI-021` | 🟠 | LLM10:2026 | Model output rendered through a server-side template | all | `from greypanda import OutputGuardrail` |
| `GP-AI-023` | 🟠 | LLM04:2026 | Disabled TLS certificate verification on outbound call | all | — |
| `GP-MCP-001` | 🟠 | AISVS C10 / ASI04 | Possible tool-poisoning marker in an MCP tool description/docstring | all | `from greypanda import McpToolManifest, McpServerGuard` |
| `GP-MCP-003` | 🟠 | AISVS C10 | MCP client token forwarded downstream (token passthrough / confused deputy) | team, enterprise | — |
| `GP-MCP-004` | 🟠 | AISVS C10 | Remote MCP endpoint configured over plaintext HTTP | team, enterprise | `from greypanda import McpServerGuard` |
| `GP-AGT-007` | 🟡 | ASI06 | Agent memory write without validation/attribution | enterprise | — |
| `GP-AGT-009` | 🟡 | ASI07 | Inter-agent message handled without authentication | team, enterprise | `from greypanda import Guardian` |
| `GP-AI-003` | 🟡 | LLM02:2026 | LLM call may lack a preceding DLP scan (advisory) | enterprise | `from greypanda import DLPScanner` |
| `GP-AI-012` | 🟡 | LLM06:2026 | Model call without an explicit token/output cap | enterprise | — |
| `GP-AI-017` | 🟡 | LLM01:2026 | External/fetched content sent to the model without trust tagging | team, enterprise | `from greypanda import SecureContextBuilder` |
| `GP-AI-022` | 🟡 | LLM08:2026 | Exception detail or stack trace returned to the caller | team, enterprise | — |
| `GP-MCP-005` | 🟡 | AISVS C10 | Server bound to all network interfaces (0.0.0.0) | team, enterprise | — |

## Remediations

### 🔴 `GP-AGT-005` — Irreversible agent action without a human-in-the-loop gate
*LLM03:2026 · CRITICAL*

- **What:** A tool that sends/deletes/refunds/transfers/executes is defined without any approval gate; one injected instruction could trigger it.
- **Fix:** Wrap tools with AgentSecurityWrapper and set requires_hitl=True on any ToolPermission with side effects.
- **SDK:** `from greypanda import AgentSecurityWrapper, ToolPermission`

### 🔴 `GP-AI-001` — User input interpolated directly into a prompt string
*LLM01:2026 · CRITICAL*

- **What:** Untrusted user input is f-string/format/concat-ed straight into a prompt, collapsing the boundary between instructions and data.
- **Fix:** Build context with SecureContextBuilder.add_user(); never f-string user input into a system/prompt string.
- **SDK:** `from greypanda import SecureContextBuilder`

### 🔴 `GP-AI-002` — System prompt concatenated with user content in one string
*LLM01:2026 · CRITICAL*

- **What:** System instructions and user content are joined into a single string instead of separate typed roles.
- **Fix:** Use separate system and user message roles. Never concatenate system_prompt + user_input.
- **SDK:** `from greypanda import SecureContextBuilder`

### 🔴 `GP-AI-004` — Raw model output rendered as HTML without sanitization
*LLM10:2026 · CRITICAL*

- **What:** Model output flows into mark_safe/|safe/innerHTML/dangerouslySetInnerHTML, enabling XSS from a manipulated response.
- **Fix:** Apply OutputGuardrail.sanitize() and rely on template autoescaping; never mark model output as safe HTML.
- **SDK:** `from greypanda import OutputGuardrail`

### 🔴 `GP-AI-010` — Hardcoded AI provider key or secret in source
*DSGAI01 · CRITICAL*

- **What:** An API key or secret is embedded in source code where it can leak via version control, logs, or model context.
- **Fix:** Load secrets from environment or a secret manager; rotate any exposed key immediately. Never place a secret in model context.

### 🔴 `GP-AI-014` — Model-generated SQL/command executed without validation
*LLM10:2026 · CRITICAL*

- **What:** LLM output is passed to a database or shell executor without an allowlist/validation, enabling injection or destructive operations.
- **Fix:** Validate LLM-generated SQL against an allowlist; require HITL for any DROP/DELETE. Never execute model output directly.

### 🔴 `GP-MCP-002` — MCP tool passes model-provided input to a shell/eval sink
*AISVS C10 / ASI05 · CRITICAL*

- **What:** A tool forwards model/tool arguments into os.system/subprocess/eval/exec without validation — unexpected code execution (RCE).
- **Fix:** Validate arguments against a JSON schema (McpServerGuard.validate_arguments) and never pass raw model input to a shell/eval.
- **SDK:** `from greypanda import McpServerGuard`

### 🟠 `GP-AGT-006` — Agent tool marked as not requiring human approval
*LLM03:2026 · HIGH*

- **What:** A ToolPermission (or similar) explicitly disables the HITL gate. Confirm the tool has no irreversible side effects.
- **Fix:** Set requires_hitl=True for tools that can change state, move money, or touch production data.
- **SDK:** `from greypanda import ToolPermission`

### 🟠 `GP-AGT-008` — Shell command executed with shell=True and an interpolated value
*ASI05 · HIGH*

- **What:** subprocess with shell=True and a variable/f-string command is a classic command-injection sink — acute when the value derives from model or tool output.
- **Fix:** Avoid shell=True; pass an argument list and use shlex.quote; validate any model-provided arguments against a schema/allowlist.
- **SDK:** `from greypanda import McpServerGuard`

### 🟠 `GP-AI-007` — Unpinned AI/agent dependency
*LLM04:2026 · HIGH*

- **What:** An AI framework dependency is declared without an exact version pin, exposing you to malicious or breaking upgrades.
- **Fix:** Pin AI dependencies to exact versions (==) and enable Dependabot/Snyk.

### 🟠 `GP-AI-008` — System prompt returned in an API response
*LLM08:2026 · HIGH*

- **What:** The system prompt / hidden instructions are placed into an outbound response, exposing internal logic and expanding the attack surface.
- **Fix:** Never include system_prompt content in output returned to clients.

### 🟠 `GP-AI-009` — Vector store query without a user-scoped filter
*LLM09:2026 · HIGH*

- **What:** A similarity search/retrieval runs without a per-user filter, risking cross-user data bleed from the vector store.
- **Fix:** Always pass a user-scoped filter (e.g. filter={'accessible_by': user_id}) to retrieval calls.

### 🟠 `GP-AI-011` — Raw prompt or model response written to logs
*DSGAI14 · HIGH*

- **What:** Prompt/response/user_message text is logged directly, turning your telemetry pipeline into a sensitive-data leak channel.
- **Fix:** Use AuditLogger, which emits structured events with no raw text.
- **SDK:** `from greypanda import AuditLogger`

### 🟠 `GP-AI-013` — Direct call to an external AI provider endpoint (possible shadow AI)
*DSGAI03 · HIGH*

- **What:** Code calls a provider API endpoint directly rather than through your approved AI gateway, bypassing central policy, DLP, and audit.
- **Fix:** Route all model calls through your organization's AI gateway; do not use personal keys or direct endpoints in production.

### 🟠 `GP-AI-020` — Unsafe deserialization of untrusted / model-influenced data
*LLM10:2026 · HIGH*

- **What:** pickle.loads / yaml.load / marshal.loads on data that may be attacker- or model-influenced enables arbitrary code execution.
- **Fix:** Use yaml.safe_load; avoid pickle for untrusted data; validate and sign any serialized payload before loading.

### 🟠 `GP-AI-021` — Model output rendered through a server-side template
*LLM10:2026 · HIGH*

- **What:** Model output passed to render_template_string / Template(...).render can enable server-side template injection and XSS.
- **Fix:** Never build templates from model output; render model text as data with autoescaping and OutputGuardrail.sanitize().
- **SDK:** `from greypanda import OutputGuardrail`

### 🟠 `GP-AI-023` — Disabled TLS certificate verification on outbound call
*LLM04:2026 · HIGH*

- **What:** An outbound HTTP/API or MCP client call disables TLS certificate verification (verify=False), exposing prompts, keys, and responses to man-in-the-middle interception.
- **Fix:** Remove verify=False (or set verify=True / pass a trusted CA bundle path) so TLS certificates are validated on all outbound calls.

### 🟠 `GP-MCP-001` — Possible tool-poisoning marker in an MCP tool description/docstring
*AISVS C10 / ASI04 · HIGH*

- **What:** An MCP tool description or docstring contains instruction-like or exfiltration language that could hijack the model (tool poisoning).
- **Fix:** Review the tool description; keep descriptions declarative. Pin + hash manifests with McpToolManifest so later changes (rug pulls) are caught.
- **SDK:** `from greypanda import McpToolManifest, McpServerGuard`

### 🟠 `GP-MCP-003` — MCP client token forwarded downstream (token passthrough / confused deputy)
*AISVS C10 · HIGH*

- **What:** A client/user token is forwarded to a downstream API, breaking audit trails and enabling the confused-deputy pattern.
- **Fix:** Use tokens explicitly issued to the MCP server or an On-Behalf-Of flow; never pass the client token straight through.

### 🟠 `GP-MCP-004` — Remote MCP endpoint configured over plaintext HTTP
*AISVS C10 · HIGH*

- **What:** A non-loopback MCP server URL uses http:// with no TLS, exposing tool traffic and tokens to interception.
- **Fix:** Use HTTPS (TLS 1.2+) for all remote MCP connections; only bind plain HTTP to 127.0.0.1 for local STDIO/loopback use.
- **SDK:** `from greypanda import McpServerGuard`

### 🟡 `GP-AGT-007` — Agent memory write without validation/attribution
*ASI06 · MEDIUM*

- **What:** A value is written into agent long-term memory/vector store with no validation or source attribution (memory poisoning risk).
- **Fix:** Validate every memory update, attach source attribution, and isolate memory by session/user. Consider a TTL on stored entries.

### 🟡 `GP-AGT-009` — Inter-agent message handled without authentication
*ASI07 · MEDIUM*

- **What:** A handler consumes an inter-agent/tool message without verifying its origin or signature — forged instructions can drive lateral movement.
- **Fix:** Authenticate and verify inter-agent messages (signatures/JWT); apply the ACS wire format with signing.
- **SDK:** `from greypanda import Guardian`

### 🟡 `GP-AI-003` — LLM call may lack a preceding DLP scan (advisory)
*LLM02:2026 · MEDIUM*

- **What:** Advisory reminder: no nearby DLPScanner redact/scan was found before this model call. This is a proximity heuristic, not dataflow analysis — it cannot prove whether THIS call's data was redacted, so verify manually. Surfaced only in the enterprise profile and never gates a build.
- **Fix:** Run DLPScanner().redact(text) on inputs (and outputs) before the call, or route calls through a gateway that enforces DLP centrally.
- **SDK:** `from greypanda import DLPScanner`

### 🟡 `GP-AI-012` — Model call without an explicit token/output cap
*LLM06:2026 · MEDIUM*

- **What:** A completion/chat call is made without max_tokens, allowing unbounded output and cost/DoS exposure.
- **Fix:** Set max_tokens on the call and add per-user rate limiting.

### 🟡 `GP-AI-017` — External/fetched content sent to the model without trust tagging
*LLM01:2026 · MEDIUM*

- **What:** Content from requests/httpx/urllib/fetch is passed toward the model without being wrapped as untrusted (indirect prompt injection).
- **Fix:** Wrap external content with SecureContextBuilder.add_external_content() so the model is told to treat it as data, not instructions.
- **SDK:** `from greypanda import SecureContextBuilder`

### 🟡 `GP-AI-022` — Exception detail or stack trace returned to the caller
*LLM08:2026 · MEDIUM*

- **What:** Returning str(exception) or a traceback to clients leaks internal logic, paths, and tool internals, aiding targeted attacks.
- **Fix:** Return a generic error to the caller; log details server-side only. Never expose stack traces or tool internals in responses.

### 🟡 `GP-MCP-005` — Server bound to all network interfaces (0.0.0.0)
*AISVS C10 · MEDIUM*

- **What:** Binding an MCP/dev server to 0.0.0.0 exposes it beyond localhost, widening the attack surface for a tool/agent endpoint.
- **Fix:** Bind local MCP servers to 127.0.0.1; only expose remotely behind TLS + OAuth 2.1 and an explicit allowlist.

