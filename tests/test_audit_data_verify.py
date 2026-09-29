import json
import logging
import unittest
from pathlib import Path

from greypanda import AuditLogger
from greypanda.data import all_standards, control_index, lookup
from greypanda.verify.aisvs import verify_aisvs

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class TestAuditLogger(unittest.TestCase):
    def test_events_are_json_with_no_raw_text(self):
        records = []

        class Cap(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        logger = logging.getLogger("acme.ai.audit")
        logger.setLevel(logging.INFO)
        logger.addHandler(Cap())
        audit = AuditLogger("bot", "s1", org="acme")
        ev = audit.log_prompt_check("u1", passed=True, metadata={"token_count": 5})
        self.assertEqual(ev.event_type, "prompt_check")
        self.assertTrue(records)
        payload = json.loads(records[-1])
        self.assertEqual(payload["user_id"], "u1")
        self.assertIn("timestamp", payload)

    def test_tool_call_violation_recorded(self):
        audit = AuditLogger("bot", "s1")
        ev = audit.log_tool_call("u1", "danger", approved=False, call_count=1)
        self.assertIn("hitl_denied", ev.violations)


class TestStandardsData(unittest.TestCase):
    def test_all_standards_load(self):
        docs = all_standards()
        self.assertEqual(len(docs), 6)

    def test_lookup_known_ids(self):
        for cid in ("LLM01:2026", "ASI02", "DSGAI01", "C10", "MCP-TOOL", "ACS-DISPOSITIONS"):
            self.assertIsNotNone(lookup(cid), f"{cid} not found")

    def test_control_index_ids_unique(self):
        idx = control_index()
        self.assertGreater(len(idx), 50)


@unittest.skipUnless(EXAMPLES.exists(), "examples/ not packaged (sdist)")
class TestVerify(unittest.TestCase):
    def test_vulnerable_app_fails_l2(self):
        report = verify_aisvs(EXAMPLES / "vulnerable_app", level=2)
        self.assertGreater(report.failed, 0)

    def test_secure_app_no_scanner_failures(self):
        report = verify_aisvs(EXAMPLES / "secure_app", level=2)
        self.assertEqual(report.failed, 0)


if __name__ == "__main__":
    unittest.main()
