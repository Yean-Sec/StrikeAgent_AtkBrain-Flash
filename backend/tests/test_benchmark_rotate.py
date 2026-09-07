"""评测 0 flag 让槽：已有分永不轮换；只让给更值得的排队题。"""
from __future__ import annotations

import unittest

from atkbrain.benchmark import is_worthy_rotate_waiter, pick_zero_flag_rotate
from atkbrain.config import settings
from atkbrain.project_status import hunt_max_turns, uses_ctf_hunt_clocks


class ZeroFlagRotateTests(unittest.TestCase):
    def test_defaults_match_policy(self):
        self.assertEqual(int(settings.benchmark_run_budget_sec or 0), 0)
        self.assertEqual(int(settings.benchmark_no_flag_rotate_sec), 0)
        self.assertEqual(int(settings.benchmark_hard_no_flag_rotate_sec), 0)
        self.assertEqual(int(settings.benchmark_min_attempt_sec), 120)
        self.assertEqual(int(settings.benchmark_min_hunt_sec), 180)
        self.assertEqual(int(settings.benchmark_first_pass_dwell_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_dwell_floor_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_grow_grace_sec), 8 * 60)
        self.assertEqual(int(settings.benchmark_entry_down_rebind_sec), 90)
        self.assertEqual(int(settings.benchmark_entry_down_yield_sec), 8 * 60)
        self.assertEqual(int(settings.runtime_hard_stop_sec), 60 * 60)
        self.assertEqual(int(settings.redteam_runtime_hard_stop_sec), 4 * 60 * 60)
        self.assertEqual(int(settings.turn_max_seconds), 0)
        self.assertEqual(int(settings.turn_advisor_yield_sec), 0)
        self.assertEqual(int(settings.turn_hang_sec), 8 * 60)
        self.assertEqual(int(settings.cmd_timeout), 0)
        self.assertEqual(int(settings.graph_idle_pause_sec), 20 * 60)
        self.assertEqual(int(settings.runtime_review_after_sec), 60 * 60)
        self.assertEqual(int(settings.runtime_review_interval_sec), 15 * 60)
        self.assertEqual(int(settings.advisor_min_turn_interval), 3)
        self.assertEqual(int(settings.advisor_hold_turns), 3)
        self.assertEqual(int(settings.loop_supervise_soft_turns), 3)
        self.assertEqual(int(settings.loop_supervise_hard_turns), 6)
        self.assertTrue(uses_ctf_hunt_clocks("flag"))
        self.assertEqual(hunt_max_turns("flag", is_benchmark=True), 40)
        self.assertEqual(hunt_max_turns("redteam"), 0)

    def test_has_flag_never_rotates(self):
        running = [{"id": "a"}, {"id": "b"}]
        progress = {"a": 1, "b": 0}
        elapsed = {"a": 7200, "b": 7200}
        self.assertEqual(
            pick_zero_flag_rotate(running, progress, elapsed, idle_waiting=1, rotate_sec=3600),
            ["b"],
        )

    def test_same_class_hard_zero_does_not_yield_without_worthy_queue(self):
        running = [{"id": "h1"}, {"id": "h2"}]
        progress = {"h1": 0, "h2": 0}
        elapsed = {"h1": 4000, "h2": 4000}
        self.assertEqual(
            pick_zero_flag_rotate(running, progress, elapsed, idle_waiting=0, rotate_sec=3600),
            [],
        )

    def test_worthy_waiters(self):
        self.assertTrue(is_worthy_rotate_waiter(attempts=0, correct_flags=0, easy=False))
        self.assertTrue(is_worthy_rotate_waiter(attempts=2, correct_flags=1, easy=False))
        self.assertTrue(is_worthy_rotate_waiter(attempts=1, correct_flags=0, easy=True))
        self.assertFalse(is_worthy_rotate_waiter(attempts=1, correct_flags=0, easy=False))


if __name__ == "__main__":
    unittest.main()
