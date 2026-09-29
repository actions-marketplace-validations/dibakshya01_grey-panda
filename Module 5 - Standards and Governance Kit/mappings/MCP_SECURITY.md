# OWASP MCP Security (Secure MCP Server Development + Third-Party MCP) → Grey Panda mapping

_Version: 1.0 (Feb 2026) / Cheat Sheet 1.0 (Oct 2025) · License: CC BY-SA 4.0 · Source: https://genai.owasp.org/_

How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.

| ID | Title | Grey Panda controls | Scanner rules |
| --- | --- | --- | --- |
| `MCP-ARCH` | Secure MCP Architecture | `McpServerGuard` | `GP-MCP-004` |
| `MCP-TOOL` | Safe Tool Design | `McpToolManifest` | `GP-MCP-001` |
| `MCP-VALIDATE` | Data Validation & Resource Management | `McpServerGuard` | `GP-MCP-002` |
| `MCP-INJECTION` | Prompt Injection Controls | `Guardian`, `SecureContextBuilder` | `GP-MCP-001` |
| `MCP-AUTHZ` | Authentication & Authorization | `McpServerGuard` | `GP-MCP-003`, `GP-MCP-004` |
| `MCP-DEPLOY` | Secure Deployment & Updates | — | `GP-AI-010`, `GP-AI-007` |
| `MCP-GOV` | Governance | `McpToolManifest`, `AuditLogger` | — |
| `MCP-VALIDATE-CONT` | Tools & Continuous Validation | `AISecurityScanner` | — |
| `MCP-3P-TRUST` | Third-Party Trust Minimization | `McpServerGuard`, `McpToolManifest` | `GP-MCP-001`, `GP-MCP-004` |

> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.
