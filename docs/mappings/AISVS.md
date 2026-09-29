# OWASP AI Security Verification Standard (AISVS) → Grey Panda mapping

_Version: 1.0 · License: CC BY-SA 4.0 · Source: https://github.com/OWASP/AISVS_

**Levels:** L1 = Essential baseline controls for all AI systems · L2 = Standard controls for production / sensitive-data systems · L3 = Advanced controls for high-assurance / critical environments

> Chapters are the authoritative AISVS taxonomy. The requirements below are a curated, representative subset that Grey Panda verifies or guides on; consult the full AISVS for the complete requirement list.

## C1 — Training Data Integrity & Traceability

_Provenance, integrity, and traceability of training and fine-tuning data._

Grey Panda controls: `agent_bill_of_materials`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C1.1.1` | L1 | manual | Training and fine-tuning data sources are documented with provenance. |
| `C1.2.1` | L2 | manual | Data integrity is verified (hashes/signatures) before training. |

## C2 — Input Validation

_Validation, sanitization, and trust-tagging of all inputs to the model._

Grey Panda controls: `PromptGuardrail`, `SecureContextBuilder`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C2.1.1` | L1 | scanner | Untrusted input is separated from instructions (structural separation). |
| `C2.2.1` | L1 | sdk | Inputs are screened for known injection patterns and invisible Unicode. |
| `C2.3.1` | L2 | scanner | Retrieved and external content is tagged as untrusted before use. |

## C3 — Model Lifecycle Management & Change Control

_Governed lifecycle and change control for models._

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C3.1.1` | L2 | manual | Model versions and changes are tracked and approved. |

## C4 — Infrastructure, Configuration & Deployment Security

_Hardened, least-privilege deployment of AI components._

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C4.1.1` | L1 | scanner | No secrets are hardcoded in source or config. |
| `C4.2.1` | L2 | manual | AI services run containerized, non-root, network-restricted. |

## C5 — Access Control & Identity for AI Components & Users

_Authentication and authorization for AI components and users._

Grey Panda controls: `AgentSecurityWrapper`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C5.1.1` | L1 | manual | AI components authenticate with scoped, least-privilege identities. |
| `C5.2.1` | L2 | scanner | Retrieval is filtered by the requesting user's identity. |

## C6 — Supply Chain Security for Models

_Integrity and provenance of models, datasets, and dependencies._

Grey Panda controls: `agent_bill_of_materials`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C6.1.1` | L1 | scanner | AI dependencies are pinned to exact versions. |
| `C6.2.1` | L2 | sdk | An AIBOM/AgBOM is produced and reviewed. |

## C7 — Model Behavior, Output Control & Safety Assurance

_Control and validation of model outputs before downstream use._

Grey Panda controls: `OutputGuardrail`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C7.1.1` | L1 | scanner | Model output is not rendered as HTML/SQL/code without sanitization/validation. |
| `C7.2.1` | L2 | sdk | Output is scanned for sensitive data before it leaves the system. |

## C8 — Memory, Embeddings & Vector Database Security

_Security of memory, embeddings, and vector stores._

Grey Panda controls: `SecureContextBuilder`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C8.1.1` | L2 | scanner | Vector queries enforce per-user access filters. |
| `C8.2.1` | L2 | scanner | Memory writes are validated and attributed. |

## C9 — Orchestration & Agentic Security

_Security of agent orchestration, tools, and autonomy._

Grey Panda controls: `AgentSecurityWrapper`, `Guardian`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C9.1.1` | L2 | sdk | Tools are deny-by-default with an explicit allowlist. |
| `C9.2.1` | L2 | scanner | Irreversible actions require human-in-the-loop approval. |
| `C9.3.1` | L3 | sdk | Agents do not hold the full lethal trifecta without an approval gate (Rule of Two). |
| `C9.4.1` | L3 | sdk | A kill switch halts agent tool calls within seconds. |

## C10 — Model Context Protocol (MCP) Security

_Security of MCP servers, clients, and tools._

Grey Panda controls: `McpServerGuard`, `McpToolManifest`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C10.1.1` | L2 | sdk | Tool manifests are pinned and hashed; changes (rug pulls) are detected. |
| `C10.2.1` | L2 | sdk | Tool inputs/outputs are schema-validated and treated as untrusted. |
| `C10.3.1` | L2 | scanner | Remote MCP connections use TLS and OAuth 2.1/OIDC; no token passthrough. |
| `C10.4.1` | L3 | scanner | MCP tool descriptions are checked for poisoning markers. |
| `C10.5.1` | L2 | scanner | MCP tools never pass model input to a shell/eval sink. |

## C11 — Adversarial Robustness

_Resistance to adversarial and evasion attacks._

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C11.1.1` | L3 | manual | The system is red-teamed for prompt injection and evasion before launch. |

## C12 — Monitoring, Logging & Anomaly Detection

_Observability without leaking sensitive data._

Grey Panda controls: `AuditLogger`

| Requirement | Level | Verify | Text |
| --- | --- | --- | --- |
| `C12.1.1` | L1 | scanner | Security-relevant AI events are logged with no raw prompt/response text. |
| `C12.2.1` | L2 | manual | Audit events are shipped to a monitored SIEM with alerting. |

