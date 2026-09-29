# How to guard an agent

Wrap any agent executor with least-privilege controls that are enforced from
construction — not hoped for at runtime.

## 1. Declare tools deny-by-default

```python
from greypanda import AgentSecurityWrapper, ToolPermission, AgentSecurityViolation

def human_approves(tool_name, args) -> bool:
    # a real gate prompts a person; return True to approve
    return prompt_the_operator(tool_name, args)

wrapper = AgentSecurityWrapper(
    agent_id="refund-bot",
    tool_permissions=[
        ToolPermission("search_orders", allowed_operations=["read"], max_calls_per_session=20),
        ToolPermission("issue_refund",  allowed_operations=["write"], requires_hitl=True),
    ],
    has_private_data_access=True,
    ingests_untrusted_content=True,
    can_communicate_externally=False,     # keep off unless you must
    hitl_callback=human_approves,
)
```

Anything **not** in `tool_permissions` is denied. `issue_refund` requires a human.

## 2. Use a session to validate calls

```python
with wrapper.session(user_id="u-42", session_id="s-1") as session:
    result = session.call_tool("issue_refund", order_id="A123", amount=10)
    if result["approved"]:
        actually_issue_the_refund(order_id="A123", amount=10)   # YOUR code executes it
```

Grey Panda **validates**; it does not execute your tool. That keeps the trust
boundary explicit — your code runs the tool only after approval.

`call_tool` raises `AgentSecurityViolation` when:
- the tool isn't on the allowlist,
- the per-session call budget is exhausted,
- the HITL gate denies (or no callback is configured — it **fails secure**),
- the agent has been killed.

## 3. The Rule of Two is enforced at init

If you set all three of `has_private_data_access`, `ingests_untrusted_content`,
`can_communicate_externally` **without** a `hitl_callback`, construction raises:

```python
AgentSecurityWrapper(..., has_private_data_access=True,
                     ingests_untrusted_content=True,
                     can_communicate_externally=True)   # → AgentSecurityViolation
```

Remove one capability, or supply a `hitl_callback` so every action is gated.

## 4. The kill switch

```python
wrapper.kill()          # logs CRITICAL; disables all further tool calls & sessions
```

## 5. Add deterministic policy with an ACS Guardian

For cross-cutting rules (deny some tools, always ask on others), compose a Guardian
that returns one of the five ACS dispositions — `allow / deny / modify / ask /
defer`:

```python
from greypanda import Guardian, Disposition
from greypanda.sdk.acs import deny_tools, ask_on_tools, HookContext

guardian = Guardian(policies=[
    deny_tools("delete_database", reason="destructive"),
    ask_on_tools("send_email", reason="external comms"),
], default=Disposition.ALLOW)

decision = guardian.evaluate(HookContext(tool_name="send_email"))
# decision.disposition == Disposition.ASK
```

A `deny` always wins; otherwise the most restrictive decision seen is returned.

## 6. Emit an AgBOM

```python
from greypanda import agent_bill_of_materials

bom = agent_bill_of_materials(
    "refund-bot",
    tools=["search_orders", "issue_refund"],
    models=["gpt-4"],
    mcp_servers=["tools.internal.example"],
    data_sources=["orders_db"],
)
```
An Agent Bill of Materials enumerates what your agent is *made of*, so reviewers can
reason about its blast radius and supply chain.

## What this does not do
The wrapper validates and gates; **your code enforces** the approved result. The HITL
gate is only as strong as your callback. See the full runnable demo in
[`/examples/example_usage.py`](../examples/example_usage.py) and the limits in
[WHAT_IT_CAN_AND_CANNOT_DO](../Module%205%20-%20Standards%20and%20Governance%20Kit/WHAT_IT_CAN_AND_CANNOT_DO.md).
