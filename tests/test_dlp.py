import unittest

from greypanda import DLPScanner
from greypanda.sdk.dlp import mask


class TestDLPScanner(unittest.TestCase):
    def setUp(self):
        self.dlp = DLPScanner()

    def test_redacts_email(self):
        out = self.dlp.redact("contact me at jane.doe@example.com please")
        self.assertIn("[REDACTED:email]", out)
        self.assertNotIn("jane.doe@example.com", out)

    def test_valid_credit_card_luhn(self):
        r = self.dlp.scan("card 4111 1111 1111 1111")
        self.assertFalse(r.clean)
        self.assertTrue(any(m.pattern_name == "credit_card" for m in r.matches))

    def test_invalid_card_not_flagged(self):
        # fails Luhn -> should not be reported as a card
        r = self.dlp.scan("order 1234 5678 9012 3456 shipped")
        self.assertFalse(any(m.pattern_name == "credit_card" for m in r.matches))

    def test_detects_secrets(self):
        r = self.dlp.scan("key sk-ant-abcdefghijklmnopqrstuvwxyz012345")
        self.assertFalse(r.clean)

    def test_assert_clean_raises(self):
        with self.assertRaises(ValueError):
            self.dlp.assert_clean("my ssn is 123-45-6789")

    def test_mask_never_reveals_full(self):
        self.assertNotIn("supersecretvalue", mask("supersecretvalue"))

    def test_on_violation_hook_called(self):
        calls = []
        dlp = DLPScanner(on_violation=lambda r: calls.append(r))
        dlp.scan("email a@b.com")
        self.assertEqual(len(calls), 1)

    def test_regional_optin(self):
        dlp = DLPScanner(categories=["regional_in"])
        r = dlp.scan("PAN ABCDE1234F")
        self.assertFalse(r.clean)

    def test_masked_snippet_not_raw(self):
        r = self.dlp.scan("email jane.doe@example.com")
        for m in r.matches:
            self.assertNotIn("jane.doe@example.com", m.masked_snippet)


if __name__ == "__main__":
    unittest.main()
