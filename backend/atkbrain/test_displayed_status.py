"""活句柄优先于 DB 里残留的 running；人工停止必须 idle。"""
from __future__ import annotations

import unittest

from atkbrain_native import cancel_project_status
from atkbrain_native import displayed_status


class DisplayedStatusTests(unittest.TestCase):
    def test_live_running(self) -> None:
        self.assertEqual(displayed_status("idle", running=True), "running")
        self.assertEqual(displayed_status("running", running=True), "running")

    def test_queued(self) -> None:
        self.assertEqual(displayed_status("running", queued=True), "queued")

    def test_stale_db_running_is_idle(self) -> None:
        self.assertEqual(displayed_status("running", running=False), "idle")

    def test_keeps_terminal(self) -> None:
        self.assertEqual(displayed_status("completed"), "completed")
        self.assertEqual(displayed_status("error"), "error")
        self.assertEqual(displayed_status("idle"), "idle")
        self.assertEqual(displayed_status("goal_reached"), "completed")

    def test_anchor_keeps_ticking_only_while_running(self) -> None:
        from atkbrain_native import anchor_hunt_elapsed

        parked = anchor_hunt_elapsed(
            {"elapsed_sec": 90, "elapsed_as_of": 1_000},
            running=False,
            now_ts=1_100,
        )
        self.assertEqual(parked["elapsed_sec"], 90)
        self.assertNotIn("elapsed_as_of", parked)
        live = anchor_hunt_elapsed(
            {"elapsed_sec": 90, "elapsed_as_of": 1_000},
            running=True,
            now_ts=1_040,
        )
        self.assertEqual(live["elapsed_sec"], 130)
        self.assertEqual(live["elapsed_as_of"], 1_040)
        fresh = anchor_hunt_elapsed(
            {"elapsed_sec": 0},
            running=True,
            run_started_at=1_000,
            now_ts=1_075,
        )
        self.assertEqual(fresh["elapsed_sec"], 75)

    def test_user_stop_is_idle(self) -> None:
        self.assertEqual(
            cancel_project_status(user_stop=True, handle_status="running", slot_held=True),
            "idle",
        )
        self.assertEqual(
            cancel_project_status(user_stop=True, handle_status="stopping", slot_held=True),
            "idle",
        )

    def test_restart_keeps_running_only_if_slot_held(self) -> None:
        self.assertEqual(
            cancel_project_status(user_stop=False, handle_status="running", slot_held=True),
            "running",
        )
        self.assertIsNone(
            cancel_project_status(user_stop=False, handle_status="starting", slot_held=False),
        )


class ProjectTrackTests(unittest.TestCase):
    def test_explicit_and_backfill(self) -> None:
        from atkbrain_native import project_track
        self.assertEqual(project_track("single", {"track": "src"}), "agent")
        self.assertEqual(project_track("single", {"track": "redteam"}), "agent")
        self.assertEqual(project_track("single", {"track": "ctf"}), "ctf")
        self.assertEqual(project_track("single", {"objective": "src"}), "agent")
        self.assertEqual(project_track("benchmark", {}), "ctf")
        self.assertEqual(project_track("single", {}), "agent")


if __name__ == "__main__":
    unittest.main()
