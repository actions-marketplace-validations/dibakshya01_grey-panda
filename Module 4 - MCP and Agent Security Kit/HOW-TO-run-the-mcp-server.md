# How to run Grey Panda as an MCP server

Grey Panda *secures* MCP — and ships **as** an MCP server, so any MCP-capable client
(Claude Code, Cursor, Windsurf, VS Code) can call it while you code. It speaks
JSON-RPC 2.0 over stdio (the standard local MCP transport) using only the Python
standard library — no extra install, no daemon, no network.

Everything it returns comes from Grey Panda's **deterministic** engine (regex + `ast`
+ the standards pack). No model call happens inside the server: the LLM is your
assistant *calling* it, and Grey Panda hands back reproducible, standards-cited ground
truth for it to reason over. That's the whole point — the smart, fuzzy layer stays in
your IDE; the precise, auditable layer stays in Grey Panda.

## Prerequisite

Install Grey Panda so the `gp` command exists on your PATH:

```bash
pipx install grey-panda      # recommended — isolated, always on PATH
# or:  pip install grey-panda
```

Not on PATH? Everywhere below, replace `gp` with `python3 -m greypanda` and `["mcp"]`
with `["-m", "greypanda", "mcp"]`.

## Add it to your editor (one command / one file)

### Claude Code
```bash
claude mcp add grey-panda -- gp mcp
```
That's it — start a session and ask *"review this file with grey panda."* (Add
`--scope project` to share it with your team via `.mcp.json`.)

### Cursor
Create **`.cursor/mcp.json`** in your project (or `~/.cursor/mcp.json` for all projects):
```jsonc
{
  "mcpServers": {
    "grey-panda": { "command": "gp", "args": ["mcp"] }
  }
}
```

### Windsurf
Edit **`~/.codeium/windsurf/mcp_config.json`** (Settings → Cascade → *Manage MCP servers*
→ *View raw config*):
```jsonc
{
  "mcpServers": {
    "grey-panda": { "command": "gp", "args": ["mcp"] }
  }
}
```

### VS Code (Copilot / MCP-capable extensions)
Create **`.vscode/mcp.json`** — note VS Code uses the key `servers`, not `mcpServers`:
```jsonc
{
  "servers": {
    "grey-panda": { "type": "stdio", "command": "gp", "args": ["mcp"] }
  }
}
```

After adding, reload/restart the editor. On start-up the server prints one line to
**stderr** — `grey-panda MCP server vX.Y.Z ready (6 tools, stdio JSON-RPC).` — so you
can confirm it launched in your client's MCP logs. (stdout stays pure protocol.)

## Tools it exposes

| Tool | What it does |
|---|---|
| `greypanda_scan_path` | Scan a file/dir; returns a Markdown or JSON report with OWASP IDs + fixes. |
| `greypanda_review_snippet` | Review a snippet inline (pass `code` + optional `filename`). |
| `greypanda_verify` | AISVS Level 1/2/3 verification report for a path (checked / failed / attest). |
| `greypanda_explain_risk` | Explain a control by ID (`LLM01:2026`, `ASI02`, `C10`, `ACS-DISPOSITIONS`, …). |
| `greypanda_list_standards` | List every standard + control ID Grey Panda knows. |
| `greypanda_checklist` | Return the AI security checklist. |

Good things to ask your assistant once it's wired up:
- *"Scan this repo with grey panda and summarise the criticals."*
- *"Review this function for prompt-injection and MCP risks."*
- *"Are we AISVS Level 2 ready? Run grey panda verify."*
- *"Explain LLM01:2026 and how to fix it here."*

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
not an authority. Semantic, model-powered review (catching paraphrased attacks and
intent) is the job of the assistant calling this server — never baked into Grey Panda's
own deterministic verdict. See
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
