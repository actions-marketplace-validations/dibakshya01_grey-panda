"""
server.py — a minimal, dependency-free MCP server exposing Grey Panda.

Grey Panda secures MCP — and ships *as* an MCP server, so any MCP-capable IDE
(Claude Code, Cursor, Windsurf, VS Code) can call it while you code. It speaks
JSON-RPC 2.0 over stdio (newline-delimited), the standard MCP local transport,
using only the Python standard library.

Run it with ``gp mcp`` (or ``python -m greypanda.mcpserver``) and register it in
your client, e.g. Claude Code::

    {
      "mcpServers": {
        "grey-panda": { "command": "gp", "args": ["mcp"] }
      }
    }

Tools exposed:
    * greypanda_scan_path       — scan a file/directory for AI/agent/MCP issues
    * greypanda_review_snippet  — scan a code snippet inline
    * greypanda_explain_risk    — explain an OWASP/AISVS/ACS control by ID
    * greypanda_list_standards  — list the standards + control IDs Grey Panda knows
    * greypanda_checklist       — return the AI security checklist
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .._version import __version__
from ..data import all_standards, lookup
from ..scanner.engine import AISecurityScanner
from ..scanner.reporters import report_json, report_markdown

PROTOCOL_VERSION = "2025-06-18"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "greypanda_scan_path",
        "description": "Scan a file or directory for AI, agent, and MCP security issues "
                       "(OWASP LLM Top 10 2026, Agentic, DSGAI, AISVS, MCP). Returns a "
                       "Markdown report of findings with OWASP IDs and fixes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File or directory path to scan."},
                "profile": {"type": "string", "enum": ["solo", "team", "enterprise"], "default": "team"},
                "format": {"type": "string", "enum": ["markdown", "json"], "default": "markdown"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "greypanda_review_snippet",
        "description": "Review a snippet of code inline for AI/agent/MCP security issues. "
                       "Provide the code and (optionally) a filename so the right rules apply.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "The source code to review."},
                "filename": {"type": "string", "default": "snippet.py", "description": "Filename (for extension-based rules)."},
                "profile": {"type": "string", "enum": ["solo", "team", "enterprise"], "default": "team"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "greypanda_explain_risk",
        "description": "Explain a security control by ID (e.g. 'LLM01:2026', 'ASI02', "
                       "'DSGAI01', 'C10', 'ACS-DISPOSITIONS') with its remediation and the "
                       "Grey Panda controls that address it.",
        "inputSchema": {
            "type": "object",
            "properties": {"control_id": {"type": "string"}},
            "required": ["control_id"],
        },
    },
    {
        "name": "greypanda_list_standards",
        "description": "List the standards Grey Panda is anchored to and the control IDs in each.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "greypanda_checklist",
        "description": "Return the Grey Panda AI Security Checklist as Markdown.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def _text(content: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": content}]}


def _tool_scan_path(args: dict[str, Any]) -> dict[str, Any]:
    path = args.get("path", ".")
    profile = args.get("profile", "team")
    fmt = args.get("format", "markdown")
    start = time.time()
    scanner = AISecurityScanner(profile=profile)
    findings = scanner.scan_path(Path(path))
    elapsed = time.time() - start
    if fmt == "json":
        return _text(report_json(findings, path, elapsed, profile))
    return _text(report_markdown(findings, path, elapsed, profile))


def _tool_review_snippet(args: dict[str, Any]) -> dict[str, Any]:
    code = args.get("code", "")
    filename = args.get("filename", "snippet.py")
    profile = args.get("profile", "team")
    suffix = Path(filename).suffix or ".py"
    start = time.time()
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / (Path(filename).name if Path(filename).name else f"snippet{suffix}")
        p.write_text(code, encoding="utf-8")
        scanner = AISecurityScanner(profile=profile)
        findings = scanner.scan_file(p)
        for f in findings:
            f.file = filename
    elapsed = time.time() - start
    return _text(report_markdown(findings, filename, elapsed, profile))


def _tool_explain_risk(args: dict[str, Any]) -> dict[str, Any]:
    cid = args.get("control_id", "").strip()
    entry = lookup(cid)
    if not entry:
        return _text(f"No control found for ID '{cid}'. Try greypanda_list_standards to see valid IDs.")
    out = [f"# {entry['id']} — {entry['title']}", "", f"_Standard: {entry.get('_standard','')}_", ""]
    out.append(entry.get("description", ""))
    if entry.get("remediation"):
        out += ["", f"**Remediation:** {entry['remediation']}"]
    if entry.get("grey_panda_controls"):
        out += ["", "**Grey Panda controls:** " + ", ".join(entry["grey_panda_controls"])]
    if entry.get("scanner_rules"):
        out += ["", "**Scanner rules:** " + ", ".join(entry["scanner_rules"])]
    return _text("\n".join(out))


def _tool_list_standards(_args: dict[str, Any]) -> dict[str, Any]:
    out = ["# Standards Grey Panda knows", ""]
    for key, doc in all_standards().items():
        ids = ", ".join(c["id"] for c in doc.get("controls", []))
        out.append(f"## {doc.get('name', key)}")
        out.append(ids)
        out.append("")
    return _text("\n".join(out))


def _tool_checklist(_args: dict[str, Any]) -> dict[str, Any]:
    from ..data import load_checklist

    return _text(load_checklist())


_DISPATCH = {
    "greypanda_scan_path": _tool_scan_path,
    "greypanda_review_snippet": _tool_review_snippet,
    "greypanda_explain_risk": _tool_explain_risk,
    "greypanda_list_standards": _tool_list_standards,
    "greypanda_checklist": _tool_checklist,
}


def _handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method")
    mid = msg.get("id")

    if method == "initialize":
        client_proto = (msg.get("params") or {}).get("protocolVersion", PROTOCOL_VERSION)
        return _ok(mid, {
            "protocolVersion": client_proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "grey-panda", "version": __version__},
        })
    if method in ("notifications/initialized", "initialized"):
        return None  # notification, no response
    if method == "ping":
        return _ok(mid, {})
    if method == "tools/list":
        return _ok(mid, {"tools": TOOLS})
    if method == "tools/call":
        params = msg.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        fn = _DISPATCH.get(name)
        if fn is None:
            return _err(mid, -32602, f"unknown tool: {name}")
        try:
            return _ok(mid, fn(arguments))
        except Exception as exc:  # surface tool errors as MCP tool errors, not crashes
            return _ok(mid, {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True})
    if mid is not None:
        return _err(mid, -32601, f"method not found: {method}")
    return None


def _ok(mid: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def serve_stdio() -> None:
    """Run the MCP server loop over stdin/stdout until EOF."""
    stdin = sys.stdin
    stdout = sys.stdout
    while True:
        line = stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:
            stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve_stdio()
