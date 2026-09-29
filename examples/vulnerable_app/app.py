"""
An intentionally INSECURE example app. Do not copy this into production.

Grey Panda flags every issue below. Run:

    gp scan examples/vulnerable_app --profile enterprise

Then compare with examples/secure_app/app.py to see the fixed version.
"""

import os
import sqlite3
import subprocess

import openai  # noqa: F401  (unpinned in requirements — see requirements.txt)

# GP-AI-010: hardcoded secret in source
OPENAI_API_KEY = "sk-proj-abcd1234abcd1234abcd1234abcd1234abcd1234"

# GP-AI-013: direct external provider endpoint (shadow AI)
PROVIDER_URL = "https://api.openai.com/v1/chat/completions"

# GP-MCP-004: remote endpoint over plaintext http
MCP_ENDPOINT = "http://mcp.example.com/rpc"


def build_prompt(user_input):
    # GP-AI-001: user input interpolated straight into a prompt
    system_prompt = "You are a helpful assistant."
    prompt = f"{system_prompt}\nUser question: {user_input}\nAnswer:"
    # GP-AI-002: system prompt concatenated with user content
    combined = system_prompt + " " + user_input
    return prompt, combined


def ask_llm(user_input):
    prompt, _ = build_prompt(user_input)
    client = openai.OpenAI(api_key=OPENAI_API_KEY)
    # GP-AI-003 (no DLP scan) + GP-AI-012 (no max_tokens)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    text = response.choices[0].message.content
    # GP-AI-011: raw response written to logs
    print("LLM response:", text, "for prompt:", prompt)
    return text


def render_answer(response):
    # GP-AI-004: raw model output rendered as HTML
    return f"<div>{response}</div>".replace("{response}", response)  # mark_safe(response)


def run_sql_from_llm(llm_response):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # GP-AI-014: model-generated SQL executed without validation
    cursor.execute(llm_response)
    return cursor.fetchall()


def search_docs(query):
    store = get_vector_store()
    # GP-AI-009: vector query without a user-scoped filter
    return store.similarity_search(query, k=5)


def send_refund(order_id, amount):
    # GP-AGT-005: irreversible action with no HITL gate
    return f"refunded {amount} for {order_id}"


def run_mcp_tool(arguments):
    # GP-MCP-002: model-provided input to a shell sink (RCE)
    return subprocess.run(arguments["command"], shell=True)


def get_vector_store():
    raise NotImplementedError
