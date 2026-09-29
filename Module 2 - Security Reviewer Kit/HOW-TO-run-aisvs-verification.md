# How to run AISVS verification

The [OWASP AI Security Verification Standard (AISVS)](https://github.com/OWASP/AISVS)
defines 12 chapters (C1–C12) at three assurance levels:

- **Level 1** — essential baseline controls for all AI systems.
- **Level 2** — standard controls for production / sensitive-data systems.
- **Level 3** — advanced controls for high-assurance / critical environments.

`gp verify` runs the scanner, maps findings to AISVS requirements, and produces a
report you can sign.

## Run it

```bash
gp verify <path> --level 2 -o aisvs-l2.md      # Markdown report
gp verify <path> --level 3 --format json       # machine-readable
```

## Reading the report

Each requirement is marked:

| Mark | Meaning |
|---|---|
| ✅ `pass` | Grey Panda automated the check and found no violation. |
| ❌ `fail` | The scanner found a violation mapped to this requirement (evidence is listed). |
| 📝 `attest` | Grey Panda enforces or guides this via an SDK control or it needs human evidence — **you attest**. |

The verdict is **❌ NOT VERIFIED** if any requirement fails automatically. A clean
run reads **🟢 No automated failures — complete attestations to certify.**

## The honest part (important)

A green automated result is **necessary, not sufficient**. AISVS L2/L3 explicitly
require human review and evidence. `gp verify`:

- **Can** deterministically check the subset of requirements that map to scanner
  rules (e.g. "no hardcoded secrets", "retrieval is user-scoped", "no unsafe output
  rendering"), and list the SDK controls that satisfy the `sdk`-verified ones.
- **Cannot** confirm the `attest` requirements for you — those need your review, your
  architecture knowledge, and your evidence. It does **not** certify compliance.

Use it to get to a rigorous, repeatable starting point and a signable report, then
finish the manual review in the [APPSEC_REVIEWER_GUIDE](APPSEC_REVIEWER_GUIDE.md).

## Mapping reference

Which Grey Panda rule/control satisfies which AISVS requirement is documented in
[Module 5 → mappings/AISVS.md](../Module%205%20-%20Standards%20and%20Governance%20Kit/mappings/AISVS.md).
