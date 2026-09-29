# How to add Grey Panda guardrails to an existing LLM call

**Time:** ~2 minutes. **Rule:** you never rewrite your LLM call — you wrap it.

## The idea: a 7-step pipeline

```
1. PromptGuardrail.assert_safe()   # block injection, strip invisible Unicode, size cap
2. DLPScanner.redact()             # remove PII + secrets before the model sees input
3. SecureContextBuilder            # tag trust per segment, enforce a size budget
4. (your LLM call)                 # unchanged
5. DLPScanner.redact()             # scan the response for leaked PII
6. OutputGuardrail.sanitize()      # escape output → XSS-safe by default
7. AuditLogger                     # structured event, zero raw text, SIEM-ready
```

## Step by step

### 1–2. Screen and redact the input
```python
from greypanda import PromptGuardrail, DLPScanner

guard = PromptGuardrail()          # add extra_patterns=[...] for your domain
dlp   = DLPScanner()               # categories=["pii","secrets"] by default

safe  = guard.assert_safe(user_input)   # raises ValueError on a known injection
clean = dlp.redact(safe, context="chat_input")
```
> `assert_safe` raises in strict mode. For a monitor-only rollout, use
> `PromptGuardrail(strict=False)` and inspect `guard.check(text).violations`.

### 3. Build context with trust tags
```python
from greypanda import SecureContextBuilder

messages = (
    SecureContextBuilder(user_id=user_id, max_tokens=8000)
    .add_system("You are a helpful assistant.")
    .add_rag_chunk(doc_text, source="kb")             # wrapped as untrusted data
    .add_external_content(web_text, source="web")     # wrapped as untrusted data
    .add_user(clean)
    .build()                                          # OpenAI-format messages list
)
```

### 4. Your call — unchanged
```python
reply = your_client.chat(messages=messages, max_tokens=512)   # keep an output cap
```

### 5–6. Clean the output
```python
from greypanda import OutputGuardrail

reply = dlp.redact(reply, context="chat_output")
out   = OutputGuardrail(allowed_url_domains=["yourcdn.example"])
answer = out.sanitize(reply).sanitized_text
```

### 7. Audit without leaking
```python
from greypanda import AuditLogger

audit = AuditLogger(agent_id="support-bot", session_id=session_id)
audit.log_prompt_check(user_id, passed=True, metadata={"tokens": len(messages)})
audit.log_output_check(user_id, passed=out.sanitize(reply).passed)
```
`AuditLogger` emits single-line JSON via the standard `logging` module under
`greypanda.ai.audit` (or `<org>.ai.audit`) — point your SIEM at it. It **never**
logs raw prompt/response text.

## Customising for your domain
- **Injection:** `PromptGuardrail(extra_patterns=[r"your-domain-attack"])`
- **DLP:** enable regional packs (`DLPScanner(categories=["pii","secrets","regional_in"])`)
  or add your ID formats via `custom_patterns={"org_pii": [("customer_id", r"CUST-\d{8}")]}`.
- **Output:** set `allowed_url_domains` to your real CDN/domains.

## Verify it worked
Run the scanner on your file — the SDK forms are recognised and pass cleanly:
```bash
gp scan path/to/your_file.py
```
See the full runnable version in [`/examples/example_usage.py`](../examples/example_usage.py)
and the before/after in [`/examples/secure_app/app.py`](../examples/secure_app/app.py).

## What this does not do
Guardrails are a **strong first layer**, not a guarantee. They cannot stop novel or
paraphrased injection, and DLP regex is language-specific. Pair them with the agent
controls ([Module 4](../Module%204%20-%20MCP%20and%20Agent%20Security%20Kit)) and a
review ([Module 2](../Module%202%20-%20Security%20Reviewer%20Kit)) for anything
high-stakes. Full honesty: [WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
