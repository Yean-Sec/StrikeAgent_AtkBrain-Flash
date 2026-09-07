"""猎程时钟：后端重启后续跑不得把轮次打回 1。"""
from __future__ import annotations

import unittest

from atkbrain.engine.hunt_clock import (
    empty_hunt,
    graph_idle_pause_due,
    hunt_should_reset,
    parse_hunt,
    reconstruct_hunt,
    snapshot_hunt,
    session_hang_due,
    should_reset_graph_idle,
    workspace_has_fresh_artifact,
)


class HuntClockTests(unittest.TestCase):
    def test_user_stop_and_crash_do_not_reset(self):
        self.assertFalse(hunt_should_reset(hard_restart=False, completion_reason=None))
        self.assertFalse(hunt_should_reset(hard_restart=False, completion_reason=""))

    def test_policy_stop_and_hard_restart_reset(self):
        self.assertTrue(hunt_should_reset(hard_restart=True, completion_reason=None))
        for reason in ("runtime_cap", "turn_cap", "graph_idle", "goal_reached", "entry_dead", "env_closed", "env_unreachable", "runtime_review_stop"):
            self.assertTrue(hunt_should_reset(hard_restart=False, completion_reason=reason), reason)

    def test_entry_dead_with_foothold_does_not_reset(self):
        self.assertFalse(hunt_should_reset(
            hard_restart=False, completion_reason="entry_dead", has_live_foothold=True,
        ))
        self.assertTrue(hunt_should_reset(
            hard_restart=False, completion_reason="entry_dead", has_live_foothold=False,
        ))
        self.assertTrue(hunt_should_reset(
            hard_restart=True, completion_reason="entry_dead", has_live_foothold=True,
        ))

    def test_parse_roundtrips(self):
        snap = snapshot_hunt(
            turn=28, elapsed_sec=3720.5, reviewed_elapsed_sec=3600.0, idle_sec=90.0,
        )
        got = parse_hunt({"hunt": snap})
        self.assertEqual(got["turn"], 28)
        self.assertEqual(got["elapsed_sec"], 3720.5)
        self.assertEqual(got["reviewed_elapsed_sec"], 3600.0)
        self.assertEqual(got["idle_sec"], 90.0)

    def test_parse_missing_is_empty(self):
        self.assertEqual(parse_hunt({}), empty_hunt())
        self.assertEqual(parse_hunt(None)["turn"], 0)

    def test_reconstruct_uses_last_run_only(self):
        last = {"turns": 0, "started_at": 1000.0, "ended_at": 4720.0}
        got = reconstruct_hunt(last_run=last, last_turn=28, now_ts=5000.0)
        self.assertEqual(got["turn"], 28)
        self.assertEqual(got["elapsed_sec"], 3720.0)

    def test_reconstruct_open_run_uses_now(self):
        last = {"turns": 12, "started_at": 100.0, "ended_at": None}
        got = reconstruct_hunt(last_run=last, last_turn=0, now_ts=160.0)
        self.assertEqual(got["turn"], 12)
        self.assertEqual(got["elapsed_sec"], 60.0)

    def test_fill_hunt_recovers_in_progress_turn_zero(self):
        from atkbrain.engine.hunt_clock import fill_hunt_from_last_run
        persisted = {"turn": 0, "elapsed_sec": 8.0, "reviewed_elapsed_sec": None, "idle_sec": 8.0}
        recon = reconstruct_hunt(
            last_run={"turns": 0, "started_at": 1000.0, "ended_at": 1720.0},
            last_turn=1, now_ts=1720.0,
        )
        got = fill_hunt_from_last_run(persisted, reconstructed=recon)
        self.assertEqual(got["turn"], 1)
        self.assertEqual(got["elapsed_sec"], 720.0)

    def test_resume_rewinds_unsupervised_in_progress_turn(self):
        from atkbrain.engine.hunt_clock import resume_completed_turn
        self.assertEqual(
            resume_completed_turn(persisted_turn=13, supervised_turns={1, 2, 4, 12}),
            12,
        )
        self.assertEqual(
            resume_completed_turn(persisted_turn=14, supervised_turns={1, 14}),
            14,
        )
        self.assertEqual(resume_completed_turn(persisted_turn=0, supervised_turns=set()), 0)
        self.assertEqual(
            resume_completed_turn(persisted_turn=0, supervised_turns={1, 2}),
            2,
        )
        self.assertEqual(resume_completed_turn(persisted_turn=1, supervised_turns=set()), 0)
        self.assertEqual(
            resume_completed_turn(persisted_turn=18, supervised_turns={1, 2, 17}),
            17,
        )

    def test_flag_event_resets_graph_idle(self):
        self.assertTrue(should_reset_graph_idle(node_grew=True, new_flag_event=False))
        self.assertTrue(should_reset_graph_idle(node_grew=False, new_flag_event=True))
        self.assertFalse(should_reset_graph_idle(node_grew=False, new_flag_event=False))
        self.assertTrue(should_reset_graph_idle(
            node_grew=False, new_flag_event=False, local_progress=True,
        ))
        self.assertFalse(graph_idle_pause_due(100.0, 0))
        self.assertFalse(graph_idle_pause_due(29 * 60, 30 * 60))
        self.assertTrue(graph_idle_pause_due(30 * 60, 30 * 60))
        self.assertFalse(graph_idle_pause_due(0.0, 30 * 60))

    def test_session_hang_is_silence_not_wall_clock(self):
        self.assertFalse(session_hang_due(idle_for=600, hang_sec=0))
        self.assertFalse(session_hang_due(idle_for=60, hang_sec=480))
        self.assertTrue(session_hang_due(idle_for=480, hang_sec=480))
        self.assertFalse(session_hang_due(idle_for=9999, hang_sec=480, cmd_inflight=1))
        self.assertTrue(session_hang_due(idle_for=480, hang_sec=480, cmd_inflight=0))

    def test_turn_event_idle_ignores_pre_turn_events(self):
        from atkbrain.engine.hunt_clock import turn_event_idle_sec
        started = 1000.0
        now = 1480.0
        self.assertEqual(
            turn_event_idle_sec(now_wall=now, turn_started_wall=started, last_event_ts=None),
            480.0,
        )
        self.assertEqual(
            turn_event_idle_sec(now_wall=now, turn_started_wall=started, last_event_ts=10.0),
            480.0,
        )
        self.assertEqual(
            turn_event_idle_sec(now_wall=now, turn_started_wall=started, last_event_ts=1400.0),
            80.0,
        )

    def test_workspace_fresh_artifact_counts_as_progress(self):
        import os
        import tempfile
        import time
        with tempfile.TemporaryDirectory() as td:
            self.assertFalse(workspace_has_fresh_artifact(td, time.time() + 10))
            fp = os.path.join(td, "solver.py")
            with open(fp, "w", encoding="utf-8") as f:
                f.write("print(1)\n")
            os.utime(fp, None)
            self.assertTrue(workspace_has_fresh_artifact(td, time.time() - 5))
            noise = os.path.join(td, "shells.json")
            with open(noise, "w", encoding="utf-8") as f:
                f.write("{}\n")
            self.assertFalse(workspace_has_fresh_artifact(td, time.time() + 2))


class MinHuntAndKeepAliveTests(unittest.TestCase):
    def test_empty_streak_waits_for_min_hunt(self):
        from atkbrain.engine.hunt_clock import should_end_empty_streak
        self.assertFalse(should_end_empty_streak(
            empty_streak=4, elapsed_sec=10, min_hunt_sec=180,
        ))
        self.assertFalse(should_end_empty_streak(
            empty_streak=5, elapsed_sec=20, min_hunt_sec=180,
        ))
        self.assertTrue(should_end_empty_streak(
            empty_streak=5, elapsed_sec=180, min_hunt_sec=180,
        ))
        self.assertTrue(should_end_empty_streak(
            empty_streak=5, elapsed_sec=10, min_hunt_sec=180, env_closed=True,
        ))
        self.assertTrue(should_end_empty_streak(
            empty_streak=5, elapsed_sec=10, min_hunt_sec=180, goal_reached=True,
        ))
        self.assertTrue(should_end_empty_streak(
            empty_streak=5, elapsed_sec=10, min_hunt_sec=0,
        ))

    def test_api_key_missing_is_narrow(self):
        from atkbrain.engine.hunt_clock import looks_like_api_key_missing
        self.assertTrue(looks_like_api_key_missing("DEEPSEEK_API_KEY missing"))
        self.assertTrue(looks_like_api_key_missing("API key is not configured"))
        self.assertFalse(looks_like_api_key_missing(
            "try authentication; if it fails switch to IDOR",
        ))
        self.assertFalse(looks_like_api_key_missing(
            "login authentication failed", tool_uses=0,
        ))
        self.assertFalse(looks_like_api_key_missing(
            "deepseek_api_key missing", tool_uses=2,
        ))

    def test_hunt_fault_waits_for_min_hunt(self):
        from atkbrain.engine.hunt_clock import should_end_hunt_fault
        self.assertFalse(should_end_hunt_fault(elapsed_sec=20, min_hunt_sec=180))
        self.assertTrue(should_end_hunt_fault(elapsed_sec=180, min_hunt_sec=180))
        self.assertTrue(should_end_hunt_fault(
            elapsed_sec=10, min_hunt_sec=180, env_closed=True,
        ))
        self.assertTrue(should_end_hunt_fault(
            elapsed_sec=10, min_hunt_sec=180, goal_reached=True,
        ))
        self.assertTrue(should_end_hunt_fault(elapsed_sec=10, min_hunt_sec=0))

    def test_parent_keep_alive(self):
        from atkbrain.engine.hunt_clock import parent_keep_alive_status
        self.assertEqual(
            parent_keep_alive_status("completed", env_closed=False, has_unfinished=True),
            "idle",
        )
        self.assertIsNone(
            parent_keep_alive_status("completed", env_closed=True, has_unfinished=True),
        )
        self.assertIsNone(
            parent_keep_alive_status("completed", env_closed=False, has_unfinished=False),
        )
        self.assertIsNone(
            parent_keep_alive_status("running", env_closed=False, has_unfinished=True),
        )

    def test_live_tcp_does_not_halt_on_single_closed_probe(self):
        from atkbrain.engine.hunt_clock import env_probe_halt_reason
        reason, hits = env_probe_halt_reason(
            probe="closed", tcp_ok=True, marked=False, closed_hits=0,
        )
        self.assertIsNone(reason)
        self.assertEqual(hits, 1)
        reason, hits = env_probe_halt_reason(
            probe="closed", tcp_ok=True, marked=False, closed_hits=hits,
        )
        self.assertIsNone(reason)
        self.assertEqual(hits, 2)

    def test_dead_entry_needs_two_closed_probes(self):
        from atkbrain.engine.hunt_clock import env_probe_halt_reason
        reason, hits = env_probe_halt_reason(
            probe="closed", tcp_ok=False, marked=False, closed_hits=0,
        )
        self.assertIsNone(reason)
        self.assertEqual(hits, 1)
        reason, hits = env_probe_halt_reason(
            probe="closed", tcp_ok=False, marked=False, closed_hits=hits,
        )
        self.assertEqual(reason, "env_closed")
        self.assertEqual(hits, 2)

    def test_marked_closed_halts_even_if_tcp_lingers(self):
        from atkbrain.engine.hunt_clock import env_probe_halt_reason
        reason, _hits = env_probe_halt_reason(
            probe="closed", tcp_ok=True, marked=True, closed_hits=0,
        )
        self.assertEqual(reason, "env_closed")

    def test_unreachable_does_not_halt_live_box(self):
        from atkbrain.engine.hunt_clock import env_probe_halt_reason
        reason, hits = env_probe_halt_reason(
            probe="unreachable", tcp_ok=True, marked=False, closed_hits=0,
        )
        self.assertIsNone(reason)
        self.assertEqual(hits, 0)
        reason, _hits = env_probe_halt_reason(
            probe="unreachable", tcp_ok=False, marked=True, closed_hits=0,
        )
        self.assertEqual(reason, "env_unreachable")

    def test_ok_probe_resets_closed_hits(self):
        from atkbrain.engine.hunt_clock import env_probe_halt_reason
        reason, hits = env_probe_halt_reason(
            probe="ok", tcp_ok=False, marked=False, closed_hits=4,
        )
        self.assertIsNone(reason)
        self.assertEqual(hits, 0)

    def test_parent_env_closed_only_on_confirmed_close(self):
        from atkbrain.engine.hunt_clock import (
            autopilot_env_gate_action,
            should_mark_parent_env_closed,
        )
        self.assertTrue(should_mark_parent_env_closed("env_closed"))
        self.assertFalse(should_mark_parent_env_closed("env_unreachable"))
        self.assertFalse(should_mark_parent_env_closed(""))
        self.assertEqual(
            autopilot_env_gate_action(marked_closed=False, probe="closed"),
            "continue",
        )
        self.assertEqual(
            autopilot_env_gate_action(marked_closed=True, probe="ok"),
            "resume",
        )
        self.assertEqual(
            autopilot_env_gate_action(marked_closed=True, probe="closed"),
            "drain",
        )
        self.assertEqual(
            autopilot_env_gate_action(marked_closed=True, probe="unreachable"),
            "drain",
        )

    def test_watchdog_trips_on_empty_slots(self):
        from atkbrain.engine.hunt_clock import note_autopilot_watchdog
        ticks, trip = note_autopilot_watchdog(
            running=0, started=0, remaining_fresh=4, prev_ticks=2, trip_after=3,
        )
        self.assertEqual(ticks, 3)
        self.assertTrue(trip)
        ticks, trip = note_autopilot_watchdog(
            running=1, started=0, remaining_fresh=4, prev_ticks=2, trip_after=3,
        )
        self.assertEqual(ticks, 0)
        self.assertFalse(trip)


if __name__ == "__main__":
    unittest.main()
