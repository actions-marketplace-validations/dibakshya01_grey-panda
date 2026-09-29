# OWASP Top 10 for Agentic Applications 2026 → Grey Panda mapping

_Version: 2026 · License: CC BY-SA 4.0 · Source: https://genai.owasp.org/_

How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.

| ID | Title | Grey Panda controls | Scanner rules |
| --- | --- | --- | --- |
| `ASI01` | Agent Goal Hijack | `SecureContextBuilder`, `AgentSecurityWrapper`, `Guardian` | — |
| `ASI02` | Tool Misuse and Exploitation | `AgentSecurityWrapper`, `McpServerGuard`, `Guardian` | — |
| `ASI03` | Identity and Privilege Abuse | `AgentSecurityWrapper` | — |
| `ASI04` | Agentic Supply Chain Vulnerabilities | `McpToolManifest`, `McpServerGuard`, `agent_bill_of_materials` | — |
| `ASI05` | Unexpected Code Execution (RCE) | `McpServerGuard` | — |
| `ASI06` | Memory & Context Poisoning | `SecureContextBuilder` | — |
| `ASI07` | Insecure Inter-Agent Communication | `Guardian` | — |
| `ASI08` | Cascading Failures | `AgentSecurityWrapper` | — |
| `ASI09` | Human-Agent Trust Exploitation | `OutputGuardrail` | — |
| `ASI10` | Rogue Agents | `AgentSecurityWrapper`, `Guardian`, `AuditLogger` | — |

> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.
