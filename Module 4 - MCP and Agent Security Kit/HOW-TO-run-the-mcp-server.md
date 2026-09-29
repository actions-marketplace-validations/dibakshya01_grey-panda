# How to run Grey Panda as an MCP server

Grey Panda *secures* MCP — and ships **as** an MCP server, so any MCP-capable client
can call it while you code. It speaks JSON-RPC 2.0 over stdio (the standard local MCP
transport) using only the Python standard library.

## Start it

```bash
gp mcp                      # or: python -m greypanda.mcpserver
```
It reads newline-delimited JSON-RPC on stdin and writes responses on stdout — you
normally don't run it by hand; your MCP client launches it.

## Register it in a client

**Claude Code / Cursor / Windsurf:**
```jsonc
{
  "mcpServers": {
    "grey-panda": { "command": "gp", "args": ["mcp"] }
  }
}
```

**VS Code (MCP-capable extensions)** use the same `command` + `args` shape.

## Tools it exposes

| Tool | What it does |
|---|---|
| `greypanda_scan_path` | Scan a file/dir; returns a Markdown or JSON report. |
| `greypanda_review_snippet` | Review a snippet inline (pass `code` + optional `filename`). |
| `greypanda_explain_risk` | Explain a control by ID (`LLM01:2026`, `ASI02`, `C10`, `ACS-DISPOSITIONS`, …). |
| `greypanda_list_standards` | List every standard + control ID Grey Panda knows. |
| `greypanda_checklist` | Return the AI security checklist. |

## Try it by hand

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"greypanda_explain_risk","arguments":{"control_id":"LLM01:2026"}}}' \
 | gp mcp
```

## What this does not do
The server exposes Grey Panda's **static** scanner + standards knowledge — it does not
run your code, and it inherits the scanner's limits. It's an advisor in your editor,
not an authority. See [WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
