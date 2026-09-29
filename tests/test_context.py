import unittest

from greypanda import SecureContextBuilder, TrustLevel


class TestSecureContextBuilder(unittest.TestCase):
    def test_roles_and_order(self):
        msgs = (
            SecureContextBuilder()
            .add_system("sys")
            .add_user("hi")
            .add_assistant("hello")
            .build()
        )
        self.assertEqual([m["role"] for m in msgs], ["system", "user", "assistant"])

    def test_external_content_is_wrapped(self):
        msgs = SecureContextBuilder().add_external_content("do bad things", source="evil.com").build()
        self.assertIn("UNTRUSTED", msgs[0]["content"])
        self.assertIn("evil.com", msgs[0]["content"])

    def test_rag_wrapped(self):
        msgs = SecureContextBuilder().add_rag_chunk("some doc").build()
        self.assertIn("RETRIEVED CONTENT", msgs[0]["content"])

    def test_tag_untrusted_off(self):
        msgs = SecureContextBuilder(tag_untrusted=False).add_external_content("raw").build()
        self.assertEqual(msgs[0]["content"], "raw")

    def test_truncation_respects_budget(self):
        b = SecureContextBuilder(max_tokens=10)
        b.add_system("x" * 1000)
        msgs = b.build()
        self.assertIn("truncated", msgs[0]["content"])

    def test_audit_snapshot_has_no_raw_content(self):
        b = SecureContextBuilder(user_id="u1").add_user("secret text")
        snap = b.audit_snapshot()
        self.assertNotIn("secret text", str(snap))
        self.assertEqual(snap["user_id"], "u1")
        self.assertEqual(snap["segment_count"], 1)

    def test_trust_levels_enum(self):
        self.assertEqual(TrustLevel.EXTERNAL.value, "external")


if __name__ == "__main__":
    unittest.main()
