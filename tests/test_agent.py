import unittest

from greypanda import (
    AgentSecurityViolation,
    AgentSecurityWrapper,
    ToolPermission,
)


class TestAgentSecurity(unittest.TestCase):
    def _wrapper(self, **kw):
        return AgentSecurityWrapper(
            agent_id="a",
            tool_permissions=[ToolPermission("read_tool", max_calls_per_session=2)],
            **kw,
        )

    def test_trifecta_blocked_at_init(self):
        with self.assertRaises(AgentSecurityViolation):
            self._wrapper(
                has_private_data_access=True,
                ingests_untrusted_content=True,
                can_communicate_externally=True,
            )

    def test_trifecta_allowed_with_hitl(self):
        w = self._wrapper(
            has_private_data_access=True,
            ingests_untrusted_content=True,
            can_communicate_externally=True,
            hitl_callback=lambda t, a: True,
        )
        self.assertTrue(w.active)

    def test_two_of_three_ok(self):
        w = self._wrapper(has_private_data_access=True, can_communicate_externally=True)
        self.assertTrue(w.active)

    def test_deny_by_default(self):
        w = self._wrapper()
        with w.session("u", "s") as sess:
            with self.assertRaises(AgentSecurityViolation):
                sess.call_tool("not_allowed")

    def test_allowlisted_tool_ok(self):
        w = self._wrapper()
        with w.session("u", "s") as sess:
            self.assertTrue(sess.call_tool("read_tool")["approved"])

    def test_call_budget(self):
        w = self._wrapper()
        with w.session("u", "s") as sess:
            sess.call_tool("read_tool")
            sess.call_tool("read_tool")
            with self.assertRaises(AgentSecurityViolation):
                sess.call_tool("read_tool")  # 3rd exceeds budget of 2

    def test_hitl_denied_fails_secure(self):
        w = AgentSecurityWrapper(
            agent_id="a",
            tool_permissions=[ToolPermission("danger", requires_hitl=True)],
        )  # no hitl_callback -> deny
        with w.session("u", "s") as sess:
            with self.assertRaises(AgentSecurityViolation):
                sess.call_tool("danger")

    def test_hitl_approved(self):
        w = AgentSecurityWrapper(
            agent_id="a",
            tool_permissions=[ToolPermission("danger", requires_hitl=True)],
            hitl_callback=lambda t, a: True,
        )
        with w.session("u", "s") as sess:
            self.assertTrue(sess.call_tool("danger")["approved"])

    def test_kill_switch(self):
        w = self._wrapper()
        w.kill()
        self.assertFalse(w.active)
        with self.assertRaises(AgentSecurityViolation):
            w.session("u", "s")


if __name__ == "__main__":
    unittest.main()
