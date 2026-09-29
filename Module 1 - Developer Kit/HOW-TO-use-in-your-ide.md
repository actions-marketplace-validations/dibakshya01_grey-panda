# How to use Grey Panda inside your IDE

Grey Panda meets you where you code, three ways: **inline findings (SARIF)**, an
**MCP server** your AI assistant can call, and a **skill** that turns that assistant
into an AI Security Advisor.

## 1. Inline findings in VS Code (SARIF)

Grey Panda emits SARIF 2.1.0, which VS Code and GitHub render right on the offending
line — no plugin needed beyond the SARIF viewer.

```bash
gp scan . --format sarif --output grey-panda.sarif
```

- **VS Code:** install the "SARIF Viewer" extension, then open `grey-panda.sarif`.
- **GitHub:** the [CI workflow](../Module%203%20-%20Scanner%20and%20CI-CD%20Kit/HOW-TO-add-to-ci.md)
  uploads SARIF to code scanning, so findings appear inline in the PR diff.

## 2. Grey Panda as an MCP server

Grey Panda ships **as** a Model Context Protocol server, so any MCP-capable client
(Claude Code, Cursor, Windsurf, VS Code) can call it while you work.

Register it once:
```jsonc
// Claude Code / Cursor / Windsurf MCP config
{
  "mcpServers": {
    "grey-panda": { "command": "gp", "args": ["mcp"] }
  }
}
```

Now you can ask your assistant things like:
- *"Review this file with grey panda."* → calls `greypanda_review_snippet`
- *"Scan the repo for AI security issues."* → `greypanda_scan_path`
- *"Explain LLM03."* → `greypanda_explain_risk`
- *"Show me the AI security checklist."* → `greypanda_checklist`

Tools exposed: `greypanda_scan_path`, `greypanda_review_snippet`,
`greypanda_explain_risk`, `greypanda_list_standards`, `greypanda_checklist`.

Full details: [Module 4 → HOW-TO-run-the-mcp-server](../Module%204%20-%20MCP%20and%20Agent%20Security%20Kit/HOW-TO-run-the-mcp-server.md).

## 3. The AI Security Advisor skill

The [`skill/SKILL.md`](../skill/SKILL.md) file turns Claude Code / Cursor into an AI
Security Advisor scoped to Grey Panda's standards and remediations.

Install it (Claude Code):
```bash
mkdir -p .claude/skills/grey-panda
cp skill/SKILL.md .claude/skills/grey-panda/SKILL.md
```
Then invoke `/grey-panda` (or `/aisec`) and paste code, or let it scan the current
file. If the MCP server is also registered, the skill uses it for ground-truth
findings and then explains + prioritises them.

## What this does not do
The IDE integration surfaces Grey Panda's **static** findings and advice — it does
not run your code or observe runtime behaviour, and it inherits every limit in
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
Treat AI-assistant suggestions as input to your judgment, not a verdict.
