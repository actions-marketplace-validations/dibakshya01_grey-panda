# What Grey Panda Can and Cannot Do

> _"Stop trying to build a model that cannot be fooled. Build the system around it, so that when the model is fooled — and it will be — nothing important breaks."_ — OWASP GenAI Security Project leads

Security tools earn trust by being honest about their limits. This document lists, for every capability, its **confidence level** and the **condition under which it fails**. If a control isn't listed here as "High confidence," don't bet your production system on it alone. Grey Panda is a **strong floor, not a ceiling**, and it is one layer of defense in depth.

---

## ✅ What it CAN do

### Prompt & input security
| Capability | How | Confidence |
|---|---|---|
| Block known injection phrasings | `PromptGuardrail` baseline + your `extra_patterns` | **High** |
| Strip invisible / bidi / tag Unicode (Trojan Source, ASCII smuggling) | Unicode range stripping + NFKC normalisation | **High** |
| Enforce input size limits | length guard | **High** |
| Separate instructions from untrusted data | `SecureContextBuilder` nonce-fenced trust tagging (untrusted content under the `user` role) | **Medium–High** (structural; a single-prompt fence is defence-in-depth, not a guarantee) |
| Catch novel/paraphrased injection | pattern matching | **Low** — see CANNOT |

### Data loss prevention
| Capability | How | Confidence |
|---|---|---|
| Redact structured PII (email, cards w/ Luhn, SSN, phone) | `DLPScanner` `pii` | **High** |
| Redact known secret shapes (AWS/GCP/GitHub/Slack/OpenAI/Anthropic keys, JWTs, private keys) | `DLPScanner` `secrets` | **High** |
| Redact regional IDs (Aadhaar, PAN, IBAN) | opt-in `regional_*` | **Medium** |
| Never log raw matched values | masking + category-only logging | **High** |
| Catch free-text / paraphrased disclosure | regex | **Low** — see CANNOT |

### Agent security
| Capability | How | Confidence |
|---|---|---|
| Enforce the Rule of Two / lethal-trifecta at construction | `AgentSecurityWrapper` init check | **High** |
| Deny-by-default tool allowlist | per-session validation | **High** |
| Human-in-the-loop gate on irreversible tools | `requires_hitl` + fail-secure default | **High** (gate is as strong as its callback) |
| Per-session call budgets | counters | **High** |
| Kill switch | `agent.kill()` | **High** |

### MCP security
| Capability | How | Confidence |
|---|---|---|
| Detect tool rug pulls / manifest tampering | `McpToolManifest` fingerprint pinning | **High** |
| Flag tool-poisoning markers in descriptions | marker scan | **Medium** |
| Validate tool arguments against a schema | `McpServerGuard.validate_arguments` | **High** (for the supported JSON-Schema subset) |
| Enforce origin allowlist, TLS, OAuth scopes | `McpServerGuard.verify_tool` | **High** |

### Static scanner
| Capability | How | Confidence |
|---|---|---|
| Find hardcoded secrets, unsafe output rendering, missing HITL, unpinned deps, shadow AI, RAG-without-filter, MCP RCE sinks | regex rules with suppress guards | **Medium–High** per rule |
| Emit SARIF for IDE / GitHub code scanning | `--format sarif` | **High** |
| Gate CI on severity | `--fail-on` exit code | **High** |

---

## ❌ What it CANNOT do

### Fundamental LLM limitations (cover all four)
- **Cannot prevent all prompt injection.** No reliable prevention mechanism exists (NIST AI 100-2, NCSC, OWASP). *Implication:* assume injection will eventually succeed; design for blast radius, not prevention. That is why Grey Panda invests in data quarantine, least-privilege agents, and audit — not just input filtering.
- **Cannot guarantee a model won't leak training data.** Memorisation in fine-tuned models and LoRA adapters persists; machine unlearning does not fully remove data. *Implication:* data minimisation before training is the only real control.
- **Cannot prevent semantic manipulation.** A response can pass every pattern check while carrying a manipulated recommendation.
- **Cannot detect novel / zero-day injection techniques.** New encodings and phrasings pass regex.

### SDK limitations
- **`OutputGuardrail` is safe by default, but is not a full HTML *sanitiser*.** The default (`escape_html=True`) HTML-escapes the output, which is XSS-safe to render — but it renders model Markdown/HTML as literal text (lossy). The opt-in best-effort regex mode (`escape_html=False`) rewrites external-image URLs and neutralises common XSS constructs and **fails closed** (escapes) on detection, but regex cannot be complete — `passed=True` there means "no *known* dangerous construct seen," not a guarantee. For rich HTML with allow-listed markup, use a vetted sanitiser (bleach / DOMPurify).
- **Trust-tagging fences are defence-in-depth, not a hard boundary.** `SecureContextBuilder` uses a per-call nonce delimiter, strips breakout tokens, and places untrusted content under the `user` role (never `system`) — but a capable model can still be talked past a single-prompt boundary.
- **`PromptGuardrail` cannot detect semantically-equivalent injections** (paraphrasing bypasses).
- **DLP regex is language- and format-specific** — cross-lingual or unusually-formatted PII can slip through.
- **`AgentSecurityWrapper` does not execute tools** — it validates; your caller must respect the approved result and actually enforce it.
- **The HITL gate is only as strong as its callback** — if your callback always returns `True`, the gate is bypassed.
- **Context token counting is approximate** (`len // 4` heuristic).
- **No cross-session memory protection** is provided out of the box — isolate memory yourself.

### Scanner limitations
- **Static analysis only** — cannot observe runtime behaviour.
- **Python-centric** — JavaScript/TypeScript, Java, Go, and others are covered only partially (secrets, HTTP, output-rendering patterns) or not at all.
- **False positives** on benign code that matches trigger keywords.
- **False negatives** on obfuscated or dynamically-constructed patterns (split strings, `getattr`, string building).
- **Only lightweight taint tracking** — a function-scoped (`ast`-based), Python-only pass follows model-tainted variables into the highest-impact Python sinks (SQL/exec and server-side HTML like `mark_safe`). It is not full data-flow analysis: it does not cross function boundaries, and it does not run on JS/TS (a renamed model→`dangerouslySetInnerHTML` in `.tsx` is not caught by taint).
- **`GP-AI-003` ("no DLP before an LLM call") is a proximity heuristic** — it suppresses when a `redact()`/`scan()` appears within a few lines, which models "did you DLP nearby," not true dataflow. Treat it as a reminder, not a proof.

### MCP / ACS limitations
- **Tool-poisoning marker detection is heuristic** — it catches known-bad phrasing, not cleverly disguised instructions.
- **The ACS Guardian here is deterministic and dependency-free** — it is wire-compatible in spirit with ACS v0.1.0 but is not a full ACS transport with cryptographic signing.
- **The JSON-Schema validator is a pragmatic subset** — use a full validator for complex schemas.

### AppSec process limitations
- **`gp verify` automates only what can be automated.** A clean pass is necessary, not sufficient, for AISVS L2/L3 — human review and evidence are required.
- **Threat-model templates are templates**, not your actual architecture.
- **No automated red-teaming** — that requires a dedicated engagement.
- **PR-level cadence**, not continuous runtime monitoring.

---

## 🚫 What Grey Panda does NOT cover at all
- Model-level safety (harmful content, bias, alignment)
- Physical/infra security of inference hardware
- Adversarial ML training attacks (gradient-based, membership inference)
- Differential privacy during training
- Federated-learning security
- OT/ICS or safety-critical deployments
- Compliance certification (GDPR, CCPA, HIPAA, PCI, local data laws) — Grey Panda helps, but certification is yours
- Real-time behavioural monitoring — `AuditLogger` produces events; the SIEM pipeline is yours to build

---

## 🧭 Decision guide

- **Is your feature agentic?** → full threat model + AppSec review + red-team before launch.
- **Does it handle regulated / restricted data?** → mandatory HITL + legal review + semantic DLP (beyond regex).
- **Does it ingest untrusted external content?** → apply the Rule of Two strictly; consider disabling external comms.
- **Is it a fine-tuned or custom-trained model?** → red-team specifically for memorisation.
- **Built by a citizen developer?** → mandatory AppSec review before staging; register it in your AI inventory.
- **Low-stakes, internal-only, read-only, no PII?** → SDK + scanner + checklist self-review may suffice.
