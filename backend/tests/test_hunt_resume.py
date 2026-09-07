"""后端重启只续占槽项目，不把集群排队整表拉起来。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atkbrain.engine.hunt_resume import (
    cancel_project_status,
    forget_resume,
    pick_resume_ids,
    remember_resume,
    save_resume_ids,
    should_autoresume,
    take_resume_ids,
)


class HuntResumeTests(unittest.TestCase):
    def test_pick_prefers_saved_then_caps(self):
        got = pick_resume_ids(
            db_running=["a", "b", "c", "d"],
            saved=["c", "e"],
            cap=3,
        )
        self.assertEqual(got, ["c", "e", "a"])
        self.assertEqual(
            pick_resume_ids(db_running=["a", "b"], saved=["b"], cap=0),
            ["b", "a"],
        )

    def test_should_skip_failed_and_parents(self):
        self.assertFalse(should_autoresume(None))
        self.assertFalse(should_autoresume({"kind": "cluster", "status": "idle"}))
        self.assertFalse(should_autoresume({"kind": "project", "status": "error"}))
        self.assertFalse(should_autoresume({
            "kind": "project", "status": "idle",
            "config": {"completion_reason": "turn_cap"},
        }))
        self.assertFalse(should_autoresume({
            "kind": "single", "status": "running",
            "config": {
                "objective": "flag", "flag_count": 1,
                "total_score": 300,
                "benchmark": {"correct_flag_count": 1, "cumulative_score": 270},
            },
        }))
        self.assertTrue(should_autoresume({
            "kind": "single", "status": "running",
            "config": {
                "objective": "flag", "flag_count": 2,
                "benchmark": {"correct_flag_count": 1},
            },
        }))
        self.assertTrue(should_autoresume({"kind": "project", "status": "idle", "config": {}}))
        self.assertTrue(should_autoresume({"kind": "project", "status": "running"}))
        self.assertFalse(should_autoresume({
            "kind": "project", "status": "idle",
            "config": {"completion_reason": "runtime_review_stop"},
        }))
        self.assertFalse(should_autoresume({
            "kind": "single", "status": "running",
            "config": {"env_closed": True},
        }))
        self.assertFalse(should_autoresume({
            "kind": "single", "status": "running",
            "config": {"completion_reason": "env_closed"},
        }))

    def test_cancel_status(self):
        self.assertEqual(
            cancel_project_status(user_stop=True, handle_status="stopping", slot_held=True),
            "idle",
        )
        self.assertIsNone(
            cancel_project_status(user_stop=False, handle_status="zombie", slot_held=True),
        )
        self.assertEqual(
            cancel_project_status(user_stop=False, handle_status="running", slot_held=True),
            "running",
        )
        self.assertIsNone(
            cancel_project_status(user_stop=False, handle_status="starting", slot_held=False),
        )

    def test_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "hunt_resume.json"
            with patch("atkbrain.engine.hunt_resume.resume_path", return_value=path):
                remember_resume("p1")
                remember_resume("p2")
                remember_resume("p1")
                forget_resume("p2")
                save_resume_ids(["p1", "p3"])
                self.assertEqual(take_resume_ids(), ["p1", "p3"])
                self.assertEqual(take_resume_ids(), [])
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
