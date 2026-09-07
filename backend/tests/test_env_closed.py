"""评测环境到期：停测、停验、禁止当瞬时错误重试。"""
from __future__ import annotations

import asyncio
import unittest

from atkbrain.benchmark import (
    BenchmarkError,
    is_capacity_error,
    is_environment_closed_error,
    is_transient_platform_error,
    parent_env_closed,
)


class EnvClosedClassifierTests(unittest.TestCase):
    def test_already_finished_is_closed_not_transient(self):
        e = BenchmarkError("invalid_state", "task already finished", 409)
        self.assertTrue(is_environment_closed_error(e))
        self.assertFalse(is_transient_platform_error(e))
        self.assertFalse(is_capacity_error(e))

    def test_chinese_ended_is_closed(self):
        e = BenchmarkError("invalid_state", "任务已结束", 409)
        self.assertTrue(is_environment_closed_error(e))
        self.assertFalse(is_transient_platform_error(e))

    def test_expired_is_closed(self):
        e = BenchmarkError("invalid_state", "environment expired", 409)
        self.assertTrue(is_environment_closed_error(e))

    def test_task_not_found_is_closed(self):
        e = BenchmarkError("task_not_found", "not found", 404)
        self.assertTrue(is_environment_closed_error(e))
        self.assertFalse(is_transient_platform_error(e))

    def test_session_ended_is_not_closed(self):
        e = BenchmarkError("invalid_state", "session ended", 409)
        self.assertFalse(is_environment_closed_error(e))
        e2 = BenchmarkError("invalid_state", "stream ended unexpectedly", 500)
        self.assertFalse(is_environment_closed_error(e2))
        e3 = BenchmarkError("invalid_state", "container ended", 409)
        self.assertFalse(is_environment_closed_error(e3))

    def test_capacity_still_transient(self):
        e = BenchmarkError("invalid_state", "max active challenges reached", 409)
        self.assertTrue(is_capacity_error(e))
        self.assertFalse(is_environment_closed_error(e))
        self.assertTrue(is_transient_platform_error(e))

    def test_network_still_transient(self):
        e = BenchmarkError("network_error", "connection timeout")
        self.assertFalse(is_environment_closed_error(e))
        self.assertTrue(is_transient_platform_error(e))

    def test_parent_env_closed_reads_self_config(self):
        closed = {"id": "p1", "config": {"env_closed": True}}
        open_p = {"id": "p1", "config": {}}
        self.assertTrue(asyncio.run(parent_env_closed(closed)))
        self.assertFalse(asyncio.run(parent_env_closed(open_p)))
        self.assertFalse(asyncio.run(parent_env_closed(None)))


class EnvClosedStopsLiveRunsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import os
        import tempfile
        from atkbrain.db import Database, now
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        import atkbrain.db as db_mod
        import atkbrain.benchmark as bmk
        import atkbrain.projects as projects
        import atkbrain.engine.scheduler as sched
        self._old_db = db_mod.db
        self._old_bmk_db = bmk.db
        self._old_proj_db = projects.db
        self._old_mgr = sched.manager
        db_mod.db = self.db
        bmk.db = self.db
        projects.db = self.db
        self.bmk = bmk
        self.sched = sched
        self._os = os
        self.now = now
        ts = now()
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("parent", "TSec", "benchmark", "", "[]", "{}",
             '{"env_closed": true, "autopilot": true}', "idle", ts, ts),
        )
        for pid, status in (("d02", "running"), ("d03", "queued"), ("f101", "queued")):
            await self.db.execute(
                "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,parent_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (pid, pid, "single", "10.0.0.1", "[]", "{}", "{}", status, "parent", ts, ts),
            )

        class FakeMgr:
            def __init__(self):
                self.live = {"d02", "d03", "f101"}
                self.stopped = []

            def is_running(self, pid):
                return pid in self.live

            def is_queued(self, pid):
                return pid in {"d03", "f101"} and pid in self.live

            async def stop(self, pid):
                self.stopped.append(pid)
                self.live.discard(pid)
                return True

        self.mgr = FakeMgr()
        sched.manager = self.mgr

    async def asyncTearDown(self):
        import atkbrain.db as db_mod
        import atkbrain.projects as projects
        db_mod.db = self._old_db
        self.bmk.db = self._old_bmk_db
        projects.db = self._old_proj_db
        self.sched.manager = self._old_mgr
        await self.db.close()
        self._os.unlink(self.tmp.name)

    async def test_stop_parent_child_runs_idles_running_and_queued(self):
        stopped = await self.bmk.stop_parent_child_runs("parent")
        self.assertEqual(set(stopped), {"d02", "d03", "f101"})
        self.assertEqual(self.mgr.live, set())
        rows = await self.db.fetchall("SELECT id, status FROM projects WHERE parent_id='parent'")
        self.assertEqual({r["id"]: r["status"] for r in rows}, {
            "d02": "idle", "d03": "idle", "f101": "idle",
        })

    async def test_autopilot_tick_drains_when_env_closed(self):
        got = await self.bmk.autopilot_tick("parent")
        self.assertEqual(got.get("skipped"), "env_closed")
        self.assertEqual(set(got.get("stopped") or []), {"d02", "d03", "f101"})
        self.assertEqual(self.mgr.live, set())

    async def test_mark_environment_closed_turns_off_autopilot(self):
        child = {"id": "d02", "parent_id": "parent", "kind": "single"}
        await self.bmk.mark_environment_closed(child, "env_closed: already finished")
        row = await self.db.fetchone("SELECT config FROM projects WHERE id='parent'")
        import json
        cfg = json.loads(row["config"])
        self.assertTrue(cfg.get("env_closed"))
        self.assertFalse(cfg.get("autopilot"))

    async def test_clear_environment_closed_restores_autopilot(self):
        child = {"id": "d02", "parent_id": "parent", "kind": "single"}
        await self.bmk.mark_environment_closed(child, "env_closed: already finished")
        await self.bmk.clear_environment_closed("parent")
        row = await self.db.fetchone("SELECT config FROM projects WHERE id='parent'")
        import json
        cfg = json.loads(row["config"])
        self.assertFalse(cfg.get("env_closed"))
        self.assertTrue(cfg.get("autopilot"))

    async def test_autopilot_tick_resumes_when_probe_ok(self):
        async def _ok(_project):
            return "ok"
        self.bmk.probe_environment = _ok
        got = await self.bmk.autopilot_tick("parent")
        self.assertNotEqual(got.get("skipped"), "env_closed")
        row = await self.db.fetchone("SELECT config FROM projects WHERE id='parent'")
        import json
        cfg = json.loads(row["config"])
        self.assertFalse(cfg.get("env_closed"))
        self.assertTrue(cfg.get("autopilot"))


if __name__ == "__main__":
    unittest.main()
