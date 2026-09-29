# Agent Control Standard (ACS) → Grey Panda mapping

_Version: 0.1.0 · License: Apache-2.0 (code/schemas) / CC BY-SA 4.0 (docs) · Source: https://github.com/GenAI-Security-Project/agent-control-standard_

How each control in this standard maps to a Grey Panda SDK control and/or scanner rule.

| ID | Title | Grey Panda controls | Scanner rules |
| --- | --- | --- | --- |
| `ACS-INSTRUMENT` | Instrument (mandatory core) | `Guardian`, `HookContext`, `HookDecision` | — |
| `ACS-DISPOSITIONS` | Five Dispositions | `Disposition` | — |
| `ACS-TRACE` | Trace (optional profile) | `AuditLogger` | — |
| `ACS-INSPECT` | Inspect / AgBOM (optional profile) | `agent_bill_of_materials` | — |
| `ACS-WIRE` | Wire Protocol | `Guardian`, `HookDecision` | — |

> Generated from `src/greypanda/data/standards/`. Run `gp standards <ID>` to explain any control.
