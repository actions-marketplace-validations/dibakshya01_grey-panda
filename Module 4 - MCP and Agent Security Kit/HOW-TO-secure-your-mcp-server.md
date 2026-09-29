# How to secure your MCP server (and third-party MCP tools)

Whether you *build* an MCP server or *consume* third-party ones, Grey Panda gives you
drop-in controls for the two defining MCP risks: **tool poisoning / rug pulls** and
**over-trust**.

## 1. Pin and hash every tool (catch rug pulls)

A rug pull is when a tool you approved is silently changed. Pin its fingerprint at
approval; any later change is detected.

```python
from greypanda.sdk.mcp import McpServerGuard, McpToolManifest

guard = McpServerGuard(
    allowed_origins=["tools.internal.example"],
    granted_scopes=["files:read"],
)

manifest = McpToolManifest(
    name="read_file",
    description="Read a file from the workspace.",
    version="1.0.0",
    input_schema={"type": "object",
                  "properties": {"path": {"type": "string", "maxLength": 256}},
                  "required": ["path"]},
    required_scopes=["files:read"],
)

guard.pin(manifest)                       # record the approved fingerprint

# later, before each use:
verdict = guard.verify_tool(manifest, origin="https://tools.internal.example")
if not verdict.passed:
    raise PermissionError("; ".join(verdict.violations))
```

`verify_tool` fails on: an unpinned tool, a changed fingerprint (**rug pull**),
tool-poisoning markers in the description, a non-HTTPS remote origin, an origin not
on your allowlist, or a required OAuth scope you don't hold.

## 2. Validate tool arguments (treat all input as untrusted)

```python
args_ok = guard.validate_arguments(manifest, {"path": "notes.txt"})
if not args_ok.passed:
    raise ValueError("; ".join(args_ok.violations))
```
A pragmatic JSON-Schema subset (`type`, `required`, `maxLength`,
`additionalProperties`) — enough to make "reject anything that doesn't match the
schema" a one-liner without a dependency.

## 3. Isolate users and sessions

Never store user data in globals/singletons. Instantiate one state object per
session, keyed by session id:

```python
sessions = {}
sessions[session_id] = McpServerGuard.new_session_state()   # isolated per session
```

## 4. The rest of the MCP minimum bar

The OWASP MCP guides define a minimum bar Grey Panda helps you meet:

| Control | How Grey Panda helps |
|---|---|
| OAuth 2.1/OIDC, short-lived scoped tokens, **no token passthrough** | `GP-MCP-003` flags passthrough; enforce OBO flows in your code |
| TLS for remote; loopback-only for local | `GP-MCP-004` flags plaintext remote; `GP-MCP-005` flags `0.0.0.0` binds |
| Schema-validated, size-limited I/O | `McpServerGuard.validate_arguments` |
| No model input → shell/eval | `GP-MCP-002` flags RCE sinks |
| Signed, version-pinned tools | `McpToolManifest.fingerprint()` |
| Secrets in a vault, never exposed to the LLM | `GP-AI-010` flags hardcoded secrets |

Scan your MCP server code for these automatically:
```bash
gp scan path/to/mcp_server --profile enterprise
```

## What this does not do
Marker-based poisoning detection is heuristic — it catches known-bad phrasing, not a
cleverly disguised instruction. Grey Panda does not sandbox your server (use
containers/seccomp) or manage your OAuth. It gives you the checks; you enforce the
result. See [WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
