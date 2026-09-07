"""goal 节点只表示已达成的 shell/flag，策略不得冒充 GETSHELL。"""
from __future__ import annotations

import unittest

from atkbrain.graph.model import (
    agent_goal_reserved_error,
    coerce_goal_node_type,
    compute_risk_score,
)


class GoalNodeTypeTests(unittest.TestCase):
    def test_keep_real_shell_and_flag(self):
        self.assertEqual(coerce_goal_node_type("goal:shell", "goal", ["getshell"]), "goal")
        self.assertEqual(coerce_goal_node_type("goal:shell@10.0.1.2", "goal", ["rce"]), "goal")
        self.assertEqual(coerce_goal_node_type("goal:flag:0", "goal", ["flag"]), "goal")
        self.assertEqual(coerce_goal_node_type("x", "goal", ["getflag"]), "goal")

    def test_strategy_goal_becomes_danger(self):
        self.assertEqual(
            coerce_goal_node_type("goal:get-lyme-admin-cleartext", "goal",
                                  ["overdoor-strategy"]),
            "danger",
        )
        self.assertEqual(coerce_goal_node_type("plan:overdoor", "goal", []), "danger")

    def test_other_types_unchanged(self):
        self.assertEqual(coerce_goal_node_type("vuln:x", "vuln", []), "vuln")
        self.assertEqual(coerce_goal_node_type("foothold:x", "foothold", []), "foothold")

    def test_add_node_rejects_reserved_goals(self):
        self.assertIn("report_shell", agent_goal_reserved_error("goal:shell", "goal", []) or "")
        self.assertIn("report_flag", agent_goal_reserved_error("goal:flag:1", "goal", ["flag"]) or "")
        self.assertIsNone(agent_goal_reserved_error("goal:overdoor", "goal", ["overdoor-strategy"]))
        self.assertIsNone(agent_goal_reserved_error("svc:80", "service", []))

    def test_strategy_goal_has_lower_risk_floor(self):
        fake = compute_risk_score("high", "goal", False)
        real = compute_risk_score("high", coerce_goal_node_type("goal:overdoor", "goal"), False)
        self.assertGreaterEqual(fake, 90)
        self.assertLess(real, 90)


if __name__ == "__main__":
    unittest.main()
