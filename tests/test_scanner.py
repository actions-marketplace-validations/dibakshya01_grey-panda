import json
import unittest
from pathlib import Path

from greypanda.scanner.engine import AISecurityScanner, exceeds_threshold, severity_counts
from greypanda.scanner.reporters import report_json, report_markdown, report_sarif
from greypanda.scanner.rules import RULES, rules_for_profile

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class TestRules(unittest.TestCase):
    def test_rule_ids_unique(self):
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule IDs")

    def test_every_rule_has_owasp_and_remediation(self):
        for r in RULES:
            self.assertTrue(r.owasp_id, f"{r.id} missing owasp_id")
            self.assertTrue(r.remediation, f"{r.id} missing remediation")
            self.assertIn(r.severity, ("CRITICAL", "HIGH", "MEDIUM", "LOW"))

    def test_patterns_compile(self):
        for r in RULES:
            r.compiled()
            r.suppressor()  # must not raise

    def test_profile_filtering(self):
        solo = {r.id for r in rules_for_profile("solo")}
        enterprise = {r.id for r in rules_for_profile("enterprise")}
        self.assertTrue(solo.issubset(enterprise))
        self.assertGreater(len(enterprise), len(solo))


@unittest.skipUnless(EXAMPLES.exists(), "examples/ not packaged (sdist)")
class TestScannerOnExamples(unittest.TestCase):
    def test_vulnerable_app_has_criticals(self):
        s = AISecurityScanner(profile="enterprise")
        findings = s.scan_path(EXAMPLES / "vulnerable_app")
        counts = severity_counts(findings)
        self.assertGreater(counts["CRITICAL"], 0)
        self.assertTrue(exceeds_threshold(findings, "HIGH"))
        rule_ids = {f.rule_id for f in findings}
        for expected in ("GP-AI-001", "GP-AI-010", "GP-AI-004", "GP-AGT-005", "GP-MCP-002", "GP-AI-023"):
            self.assertIn(expected, rule_ids)

    def test_secure_app_is_clean(self):
        s = AISecurityScanner(profile="enterprise")
        findings = s.scan_path(EXAMPLES / "secure_app")
        self.assertEqual(findings, [], f"secure app should be clean, got {[f.rule_id for f in findings]}")

    def test_sorted_by_severity(self):
        s = AISecurityScanner(profile="enterprise")
        findings = s.scan_path(EXAMPLES / "vulnerable_app")
        order = [{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}[f.severity] for f in findings]
        self.assertEqual(order, sorted(order))


@unittest.skipUnless(EXAMPLES.exists(), "examples/ not packaged (sdist)")
class TestReporters(unittest.TestCase):
    def setUp(self):
        self.s = AISecurityScanner(profile="enterprise")
        self.findings = self.s.scan_path(EXAMPLES / "vulnerable_app")

    def test_json_valid(self):
        d = json.loads(report_json(self.findings, "p", 0.1, "enterprise"))
        self.assertEqual(d["total_findings"], len(self.findings))
        self.assertIn("severity_counts", d)

    def test_sarif_valid(self):
        d = json.loads(report_sarif(self.findings, "p", 0.1, "enterprise"))
        self.assertEqual(d["version"], "2.1.0")
        self.assertEqual(len(d["runs"][0]["results"]), len(self.findings))

    def test_markdown_has_header(self):
        md = report_markdown(self.findings, "p", 0.1, "enterprise")
        self.assertIn("Grey Panda", md)
        self.assertIn("OWASP", md)

    def test_markdown_clean_message(self):
        md = report_markdown([], "p", 0.1, "solo")
        self.assertIn("No findings", md)


if __name__ == "__main__":
    unittest.main()
