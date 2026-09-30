import tempfile
import unittest
from pathlib import Path

from greypanda.scanner.engine import AISecurityScanner

BAD_LINE = 'OPENAI_API_KEY = "sk-proj-abcd1234abcd1234abcd1234abcd1234abcd1234"\n'


class TestIgnore(unittest.TestCase):
    def test_inline_ignore_skips_line(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text(BAD_LINE.rstrip() + "  # grey-panda: ignore\n", encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertEqual(findings, [])

    def test_without_ignore_it_flags(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text(BAD_LINE, encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertTrue(any(f.rule_id == "GP-AI-010" for f in findings))

    def test_greypandaignore_excludes_file(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "secrets.py").write_text(BAD_LINE, encoding="utf-8")
            (Path(td) / ".greypandaignore").write_text("secrets.py\n", encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertEqual(findings, [])

    def test_greypandaignore_glob(self):
        with tempfile.TemporaryDirectory() as td:
            sub = Path(td) / "vendored"
            sub.mkdir()
            (sub / "x.py").write_text(BAD_LINE, encoding="utf-8")
            (Path(td) / ".greypandaignore").write_text("vendored/*\n", encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertEqual(findings, [])


class TestRulePrecision(unittest.TestCase):
    def test_re_search_not_flagged_as_vector_query(self):
        # GP-AI-009 must not fire on ordinary `re.search(...)`.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text("import re\nm = re.search(pattern, text)\n", encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertFalse(any(f.rule_id == "GP-AI-009" for f in findings))

    def test_prompt_word_not_matched_inside_identifier(self):
        # GP-AI-011 must not fire on `logger.info("PromptGuardrail ...")`.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text('logger.info("PromptGuardrail flagged input")\n', encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertFalse(any(f.rule_id == "GP-AI-011" for f in findings))

    def test_real_raw_log_still_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text('logger.info("the prompt was %s", prompt)\n', encoding="utf-8")
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertTrue(any(f.rule_id == "GP-AI-011" for f in findings))

    def test_disabled_tls_verify_flagged(self):
        # GP-AI-023 must fire on outbound calls with verify=False.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text(
                "import requests\nresp = requests.post(url, verify=False)\n",
                encoding="utf-8",
            )
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertTrue(any(f.rule_id == "GP-AI-023" for f in findings))

    def test_enabled_tls_verify_not_flagged(self):
        # GP-AI-023 must not fire when TLS verification is enabled (default or verify=True).
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text(
                "import requests\nresp = requests.post(url, verify=True)  # SecureContextBuilder\n",
                encoding="utf-8",
            )
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertFalse(any(f.rule_id == "GP-AI-023" for f in findings))

    def test_unrelated_verify_false_not_flagged(self):
        # GP-AI-023 targets HTTP client calls, not any unrelated `verify=` kwarg,
        # so a non-network `verify=False` (e.g. a config/dataclass flag) is clean.
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.py"
            p.write_text(
                "checker = SignatureChecker(verify=False)  # not a network call\n",
                encoding="utf-8",
            )
            findings = AISecurityScanner(profile="enterprise").scan_path(Path(td))
            self.assertFalse(any(f.rule_id == "GP-AI-023" for f in findings))


if __name__ == "__main__":
    unittest.main()
