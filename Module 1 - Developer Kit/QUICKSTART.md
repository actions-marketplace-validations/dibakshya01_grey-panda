# Quick Start

Two five-minute paths: one for **developers**, one for **security reviewers**.

## For developers

### 1. Install
```bash
pip install grey-panda      # or: pipx install grey-panda / uvx grey-panda
```

### 2. Scan your repo
```bash
gp scan .                   # Markdown report to your terminal
gp scan . --format sarif -o grey-panda.sarif   # for VS Code / GitHub code scanning
```

### 3. Add drop-in guardrails (under 2 minutes)
```python
from greypanda import PromptGuardrail, DLPScanner, OutputGuardrail

guard, dlp, out = PromptGuardrail(), DLPScanner(), OutputGuardrail()

safe   = guard.assert_safe(user_input)        # block injection, strip invisible Unicode
clean  = dlp.redact(safe)                       # redact PII & secrets
reply  = call_your_llm(clean)                   # your existing call — unchanged
answer = out.sanitize(reply).sanitized_text     # neutralise exfil URLs / unsafe HTML
```

### 4. Wire it into your IDE (MCP)
```jsonc
{ "mcpServers": { "grey-panda": { "command": "gp", "args": ["mcp"] } } }
```
Now your AI assistant can `review this file with grey panda` or `explain LLM03`.

### 5. Gate your CI
```bash
gp init .                   # writes .github/workflows/grey-panda.yml + config + pre-commit
```

### 6. Complete the checklist
```bash
gp checklist > SECURITY_CHECKLIST.md
```

---

## For security reviewers

### 1. Get the artifact
Pull the JSON/SARIF report from CI, or run it yourself:
```bash
gp scan <service_dir> --profile enterprise --format json -o findings.json
```

### 2. Run AISVS verification
```bash
gp verify <service_dir> --level 2 -o aisvs-l2.md
```

### 3. Follow the reviewer guide
See the [AppSec Reviewer Guide](../Module%202%20-%20Security%20Reviewer%20Kit/APPSEC_REVIEWER_GUIDE.md): scanner review → manual threat-model review → utility checks (injection battery, RAG isolation, DLP output) → OWASP Threat Dragon model → sign-off.

### 4. Import the threat model
Load the [threat-model template](../Module%202%20-%20Security%20Reviewer%20Kit/threat-models/sample-agentic-system.json) into OWASP Threat Dragon and adapt it to the feature's real architecture.

### 5. Sign off
Use the sign-off template in the reviewer guide. Any 🔴 Critical blocks the release.

---

## Retrospective scan of an existing service
```bash
gp scan ./services/payments --profile enterprise --format markdown
gp scan ./services/payments --profile enterprise --format json -o payments.json
```

## Honest limits
Before you rely on any of this, read [WHAT_IT_CAN_AND_CANNOT_DO.md](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
