"""项目收口：达目标为完成；配置上限触顶记失败。"""
from __future__ import annotations

import unittest

from atkbrain.project_status import (
    HUNT_FAILED_REASONS, final_project_status, hunt_max_turns, hunt_runtime_hard_stop_sec,
)


class FinalProjectStatusTests(unittest.TestCase):
    def test_goal_is_completed(self):
        self.assertEqual(final_project_status(goal=True, exhausted=True, pause_reason="graph_idle"), "completed")

    def test_graph_idle_is_error(self):
        self.assertEqual(final_project_status(goal=False, pause_reason="graph_idle"), "error")

    def test_hard_caps_are_error(self):
        self.assertEqual(final_project_status(goal=False, pause_reason="runtime_cap"), "error")
        self.assertEqual(final_project_status(goal=False, pause_reason="turn_cap"), "error")

    def test_manual_pause_stays_idle(self):
        self.assertEqual(final_project_status(goal=False), "idle")
        self.assertEqual(final_project_status(goal=False, pause_reason="entry_dead"), "idle")

    def test_failed_reasons(self):
        self.assertEqual(
            HUNT_FAILED_REASONS,
            frozenset({"graph_idle", "runtime_cap", "turn_cap"}),
        )

    def test_hunt_max_turns_ctf_only(self):
        self.assertEqual(hunt_max_turns("redteam"), 0)
        self.assertEqual(hunt_max_turns("getshell"), 0)
        self.assertEqual(hunt_max_turns("flag"), 40)
        self.assertEqual(hunt_max_turns("ctf"), 40)
        self.assertEqual(hunt_max_turns("src"), 30)
        self.assertEqual(hunt_max_turns("flag", is_benchmark=True), 40)

    def test_runtime_hard_stop_by_track(self):
        self.assertEqual(hunt_runtime_hard_stop_sec("flag"), 60 * 60)
        self.assertEqual(hunt_runtime_hard_stop_sec("ctf"), 60 * 60)
        self.assertEqual(hunt_runtime_hard_stop_sec("redteam"), 4 * 60 * 60)
        self.assertEqual(hunt_runtime_hard_stop_sec("getshell"), 4 * 60 * 60)

    def test_ctf_clocks_include_benchmark(self):
        from atkbrain.project_status import uses_ctf_hunt_clocks
        self.assertTrue(uses_ctf_hunt_clocks("flag"))
        self.assertTrue(uses_ctf_hunt_clocks("ctf"))
        self.assertFalse(uses_ctf_hunt_clocks("redteam"))
        self.assertFalse(uses_ctf_hunt_clocks("getshell"))
        self.assertFalse(uses_ctf_hunt_clocks("src"))

    def test_runtime_review_stop_is_idle_not_error(self):
        self.assertEqual(final_project_status(goal=False, pause_reason="runtime_review_stop"), "idle")


if __name__ == "__main__":
    unittest.main()
