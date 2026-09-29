"""
Tests for the stdio MCP server (``greypanda.mcpserver.server``).

This is Grey Panda's in-IDE distribution surface, so it gets first-class
coverage: the JSON-RPC handshake, tool discovery, every tool, the error
paths, and the full stdin→stdout loop driven through injected streams.
"""

import io
import json
import unittest

from greypanda._version import __version__
from greypanda.mcpserver import server


def call(method, params=None, mid=1):
    """Drive one request through the handler and return its response dict."""
    msg = {"jsonrpc": "2.0", "id": mid, "method": method}
    if params is not None:
        msg["params"] = params
    return server._handle(msg)


def tool(name, arguments, mid=1):
    return call("tools/call", {"name": name, "arguments": arguments}, mid=mid)


def tool_text(resp):
    """Extract the text payload from a tools/call response."""
    return resp["result"]["content"][0]["text"]


class TestHandshake(unittest.TestCase):
    def test_initialize_reports_server_info(self):
        resp = call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
        result = resp["result"]
        self.assertEqual(result["serverInfo"], {"name": "grey-panda", "version": __version__})
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertIn("tools", result["capabilities"])

    def test_initialize_negotiates_unknown_protocol(self):
        # An unsupported version must fall back to one we actually speak.
        resp = call("initialize", {"protocolVersion": "1999-01-01", "capabilities": {}})
        self.assertEqual(resp["result"]["protocolVersion"], server.PROTOCOL_VERSION)

    def test_initialize_missing_protocol_falls_back(self):
        resp = call("initialize", {})
        self.assertEqual(resp["result"]["protocolVersion"], server.PROTOCOL_VERSION)

    def test_initialized_notification_has_no_response(self):
        self.assertIsNone(call("notifications/initialized", mid=None))
        self.assertIsNone(call("initialized", mid=None))

    def test_ping(self):
        self.assertEqual(call("ping")["result"], {})


class TestToolDiscovery(unittest.TestCase):
    def test_tools_list_shape(self):
        tools = call("tools/list")["result"]["tools"]
        names = {t["name"] for t in tools}
        self.assertEqual(names, {
            "greypanda_scan_path", "greypanda_review_snippet", "greypanda_verify",
            "greypanda_explain_risk", "greypanda_list_standards", "greypanda_checklist",
        })
        for t in tools:  # every advertised tool must be well-formed and dispatchable
            self.assertIn("description", t)
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertIn(t["name"], server._DISPATCH)

    def test_every_tool_has_a_schema_advertised(self):
        advertised = {t["name"] for t in server.TOOLS}
        self.assertEqual(advertised, set(server._DISPATCH))


class TestTools(unittest.TestCase):
    def test_review_snippet_flags_hardcoded_secret(self):
        code = 'api_key = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKK"\n'
        text = tool_text(tool("greypanda_review_snippet", {"code": code, "filename": "bad.py"}))
        self.assertIn("bad.py", text)
        self.assertRegex(text, r"GP-|Critical|High|secret")

    def test_review_snippet_clean_code(self):
        text = tool_text(tool("greypanda_review_snippet", {"code": "x = 1 + 1\n"}))
        self.assertIsInstance(text, str)
        self.assertTrue(len(text) > 0)

    def test_scan_path_runs_on_a_dir(self):
        text = tool_text(tool("greypanda_scan_path", {"path": ".", "profile": "solo"}))
        self.assertIn("Profile", text)

    def test_scan_path_json_format(self):
        text = tool_text(tool("greypanda_scan_path", {"path": ".", "format": "json"}))
        parsed = json.loads(text)  # must be valid JSON when json format is asked
        self.assertIn("findings", parsed)

    def test_verify_returns_report(self):
        text = tool_text(tool("greypanda_verify", {"path": ".", "level": 1}))
        self.assertRegex(text, r"AISVS|Level|checked|attest")

    def test_verify_bad_level_defaults(self):
        # An out-of-range level must not raise; it falls back to 1.
        text = tool_text(tool("greypanda_verify", {"path": ".", "level": 9}))
        self.assertIsInstance(text, str)

    def test_explain_risk_known(self):
        text = tool_text(tool("greypanda_explain_risk", {"control_id": "LLM01:2026"}))
        self.assertIn("LLM01", text)

    def test_explain_risk_unknown_is_graceful(self):
        text = tool_text(tool("greypanda_explain_risk", {"control_id": "NOPE-999"}))
        self.assertIn("No control found", text)

    def test_list_standards(self):
        text = tool_text(tool("greypanda_list_standards", {}))
        self.assertIn("Standards", text)

    def test_checklist(self):
        text = tool_text(tool("greypanda_checklist", {}))
        self.assertTrue(len(text) > 0)


class TestErrorPaths(unittest.TestCase):
    def test_unknown_tool_is_jsonrpc_error(self):
        resp = tool("greypanda_does_not_exist", {})
        self.assertEqual(resp["error"]["code"], -32602)

    def test_unknown_method_is_jsonrpc_error(self):
        resp = call("bananas/list")
        self.assertEqual(resp["error"]["code"], -32601)

    def test_notification_for_unknown_method_is_silent(self):
        # No id => a notification => never answered, even for an unknown method.
        self.assertIsNone(server._handle({"jsonrpc": "2.0", "method": "bananas/list"}))

    def test_tool_exception_surfaces_as_iserror(self):
        # A tool that raises returns an isError result, not a protocol crash.
        text = tool_text(tool("greypanda_scan_path", {"path": "/no/such/path/xyz", "profile": "solo"}))
        self.assertIsInstance(text, str)  # scanner tolerates missing paths -> report
        resp = tool("greypanda_verify", {"path": 12345})  # wrong type -> exception
        self.assertTrue(resp["result"].get("isError"))
        self.assertIn("error", tool_text(resp).lower())

    def test_non_dict_message_is_ignored(self):
        self.assertIsNone(server._handle([1, 2, 3]))  # a batch array
        self.assertIsNone(server._handle(42))
        self.assertIsNone(server._handle("hello"))


class TestServeLoop(unittest.TestCase):
    def _run(self, lines):
        stdin = io.StringIO("".join(ln + "\n" for ln in lines))
        stdout = io.StringIO()
        server.serve_stdio(stdin=stdin, stdout=stdout, banner=False)
        out = [json.loads(ln) for ln in stdout.getvalue().splitlines() if ln.strip()]
        return out

    def test_full_session(self):
        out = self._run([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),  # no reply
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                        "params": {"name": "greypanda_explain_risk",
                                   "arguments": {"control_id": "LLM01:2026"}}}),
        ])
        ids = [m.get("id") for m in out]
        self.assertEqual(ids, [1, 2, 3])  # the notification produced no line
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "grey-panda")
        self.assertEqual(len(out[1]["result"]["tools"]), 6)

    def test_loop_survives_garbage_lines(self):
        out = self._run([
            "this is not json",
            "",
            json.dumps([1, 2, 3]),  # valid JSON, not a request
            json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}),
        ])
        # Only the ping is answered; the garbage neither crashes nor emits output.
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], 7)


if __name__ == "__main__":
    unittest.main()
