# OWASP Top 10 for LLM Applications 2026 → Grey Panda mapping

_Version: 2026 v1.0 · License: CC BY-SA 4.0 · Source: https://genai.owasp.org/_

How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.

| ID | Title | Grey Panda controls | Scanner rules |
| --- | --- | --- | --- |
| `LLM01:2026` | Prompt Injection | `PromptGuardrail`, `SecureContextBuilder` | `GP-AI-001`, `GP-AI-002`, `GP-AI-017` |
| `LLM02:2026` | Sensitive Information Disclosure | `DLPScanner`, `AuditLogger`, `OutputGuardrail` | `GP-AI-003`, `GP-AI-010`, `GP-AI-011` |
| `LLM03:2026` | Excessive Agency | `AgentSecurityWrapper`, `ToolPermission`, `Guardian` | `GP-AGT-005`, `GP-AGT-006` |
| `LLM04:2026` | Supply Chain | `agent_bill_of_materials` | `GP-AI-007`, `GP-AI-023` |
| `LLM05:2026` | Data and Model Poisoning | — | — |
| `LLM06:2026` | Unbounded Consumption | `AgentSecurityWrapper`, `ToolPermission` | `GP-AI-012` |
| `LLM07:2026` | Misinformation | `OutputGuardrail` | — |
| `LLM08:2026` | Hidden Context Exposure | `SecureContextBuilder` | `GP-AI-008`, `GP-AI-022` |
| `LLM09:2026` | Vector and Embedding Weaknesses | `SecureContextBuilder` | `GP-AI-009`, `GP-AGT-007` |
| `LLM10:2026` | Improper Output Handling | `OutputGuardrail` | `GP-AI-004`, `GP-AI-014`, `GP-AI-020`, `GP-AI-021` |

> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.
