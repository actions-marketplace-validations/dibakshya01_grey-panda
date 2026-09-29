# OWASP GenAI Data Security Risks and Mitigations 2026 → Grey Panda mapping

_Version: 2026 v1.0 · License: CC BY-SA 4.0 · Source: https://genai.owasp.org/_

How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.

| ID | Title | Grey Panda controls | Scanner rules |
| --- | --- | --- | --- |
| `DSGAI01` | Sensitive Data Leakage | `DLPScanner`, `OutputGuardrail` | `GP-AI-010` |
| `DSGAI02` | Agent Identity & Credential Exposure | `AgentSecurityWrapper` | — |
| `DSGAI03` | Shadow AI & Unsanctioned Data Flows | — | `GP-AI-013` |
| `DSGAI04` | Data, Model & Artifact Poisoning | `agent_bill_of_materials` | — |
| `DSGAI05` | Data Integrity & Validation Failures | `McpServerGuard` | — |
| `DSGAI06` | Tool, Plugin & Agent Data Exchange Risks | `AgentSecurityWrapper`, `McpServerGuard` | — |
| `DSGAI07` | Data Governance, Lifecycle & Classification for AI | `AuditLogger` | — |
| `DSGAI08` | Non-Compliance & Regulatory Violations | — | — |
| `DSGAI09` | Multimodal Capture & Cross-Channel Data Leakage | `DLPScanner` | — |
| `DSGAI10` | Synthetic Data, Anonymization & Transformation Pitfalls | — | — |
| `DSGAI11` | Cross-Context & Multi-User Conversation Bleed | `SecureContextBuilder` | `GP-AI-009` |
| `DSGAI12` | Unsafe Natural-Language Data Gateways (LLM-to-Data) | `OutputGuardrail` | `GP-AI-014` |
| `DSGAI13` | Vector Store Platform Data Security | `SecureContextBuilder` | `GP-AI-009` |
| `DSGAI14` | Excessive Telemetry & Monitoring Leakage | `AuditLogger` | `GP-AI-011` |
| `DSGAI15` | Over-Broad Context Windows & Prompt Over-Sharing | `SecureContextBuilder` | — |
| `DSGAI16` | Endpoint & Browser Assistant Overreach | — | — |
| `DSGAI17` | Data Availability & Resilience Failures in AI Pipelines | — | — |
| `DSGAI18` | Inference & Data Reconstruction | — | — |
| `DSGAI19` | Human-in-the-Loop & Labeler Overexposure | `DLPScanner` | — |
| `DSGAI20` | Model Exfiltration & IP Replication | `AuditLogger` | — |
| `DSGAI21` | Disinformation & Integrity Attacks via Data Poisoning | — | — |

> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.
