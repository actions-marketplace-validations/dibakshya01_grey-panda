# 🤖 Module 4 — MCP & Agent Security Kit

> **For:** anyone building **agents** or **MCP** servers/clients — where a single
> injected instruction can trigger a real, irreversible action.
> **Goal:** least privilege by construction, and catch tool poisoning / rug pulls
> before they bite.

This is where AI security gets serious. An agent that can act on the world is only
as safe as the controls around it.

---

## What's in this kit

| Piece | What it does |
|---|---|
| **`AgentSecurityWrapper`** | Least-privilege agent wrapper: Rule of Two, deny-by-default allowlist, HITL, call budgets, kill switch. |
| **`McpServerGuard` / `McpToolManifest`** | Pin + hash tool manifests (rug-pull detection), validate arguments, enforce origin/TLS/scopes, isolate sessions. |
| **`Guardian` (ACS)** | An Agent Control Standard Guardian: `allow / deny / modify / ask / defer` over tool calls. |
| **`agent_bill_of_materials`** | Emit an AgBOM — what your agent is *made of* (tools, models, MCP servers, data). |
| **Grey Panda as an MCP server** | `gp mcp` — call the scanner/advisor from any MCP client. |

## The two big MCP risks

1. **Tool poisoning / rug pulls** — a tool's *description* carries hidden
   instructions, or a trusted tool is silently swapped after you approved it.
2. **Over-trust** — unvalidated tool I/O, and forwarding a client token downstream
   (the "confused deputy").

Grey Panda gives you a drop-in control for each. Start here:
- **[HOW-TO-guard-an-agent.md](HOW-TO-guard-an-agent.md)** — least privilege, HITL, kill switch, ACS.
- **[HOW-TO-secure-your-mcp-server.md](HOW-TO-secure-your-mcp-server.md)** — manifest pinning, schema validation, auth.
- **[HOW-TO-run-the-mcp-server.md](HOW-TO-run-the-mcp-server.md)** — run Grey Panda *as* an MCP server.

## The Rule of Two (say it out loud)

An agent becomes dangerous when it holds **all three** of:
1. access to **private data**, 2. exposure to **untrusted content**, 3. the ability to
**communicate externally**.

Any two may be fine; **all three without a human gate** is how one injected
instruction becomes real damage. `AgentSecurityWrapper` enforces this **at
construction** — it raises before your agent ever runs.

```python
from greypanda import AgentSecurityWrapper, ToolPermission

wrapper = AgentSecurityWrapper(
    agent_id="refund-bot",
    tool_permissions=[ToolPermission("issue_refund", requires_hitl=True)],
    has_private_data_access=True,
    ingests_untrusted_content=True,
    can_communicate_externally=False,     # third property off → respects the Rule of Two
)
```

## ✅ What this kit can do — and ❌ what it can't

**Can:** enforce the Rule of Two at init, deny-by-default tools, gate irreversible
actions with HITL (fail-secure), cap call budgets, kill an agent instantly, detect
manifest rug pulls via hashing, validate tool arguments against a schema, and check
origin/TLS/scopes.

**Cannot:** execute your tools for you (it *validates*; your code enforces the
result), catch a cleverly-disguised poisoned description (marker detection is
heuristic), or provide a full ACS transport with cryptographic signing (the Guardian
here is deterministic and dependency-free, wire-compatible in spirit with ACS
v0.1.0). Full honesty:
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).

## Standards this kit implements
OWASP **Agentic Apps Top 10** (`ASI01`–`ASI10`), OWASP **AISVS C9/C10**, the OWASP
**MCP** security guides, the **Agent Control Standard**, and Meta's **Rule of Two** /
Simon Willison's **lethal trifecta**. Mappings:
[Module 5 → mappings](../Module%205%20-%20Standards%20and%20Governance%20Kit/mappings).
