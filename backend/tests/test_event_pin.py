"""纠偏事件必须钉在事件窗口里，不能被 tool 洪水挤掉。"""
from __future__ import annotations

import unittest

from atkbrain.db import Database, now


class PinnedSteerEventsTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import os
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        import atkbrain.db as db_mod
        import atkbrain.api.routes as routes
        self._old = db_mod.db
        self._old_routes = routes.db
        db_mod.db = self.db
        routes.db = self.db
        self._os = os
        self._routes = routes

    async def asyncTearDown(self):
        import atkbrain.db as db_mod
        db_mod.db = self._old
        self._routes.db = self._old_routes
        await self.db.close()
        self._os.unlink(self.tmp.name)

    async def test_steer_survives_tool_flood(self):
        from atkbrain.api.routes import fetch_project_event_rows
        ts = now()
        await self.db.execute(
            "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
            ("p1", "r1", ts, "steer", '{"content":"【监督·入口不可达】","source":"supervisor"}'),
        )
        for i in range(1200):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                ("p1", "r1", ts + i * 0.001, "tool_result", '{"preview":"x"}'),
            )
        for i in range(600):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                ("p1", "r1", ts + i * 0.001, "thought", '{"text":"思考"}'),
            )
        rows = await fetch_project_event_rows("p1", 0)
        types = {r["type"] for r in rows}
        self.assertIn("steer", types)

    async def test_supervisor_survives_tool_flood(self):
        from atkbrain.api.routes import fetch_project_event_rows
        ts = now()
        await self.db.execute(
            "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
            ("p1", "r1", ts, "supervisor", '{"kind":"plan","turn":1,"pivot":1,"next_plan":"打登录"}'),
        )
        for i in range(1200):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                ("p1", "r1", ts + i * 0.001, "tool_result", '{"preview":"x"}'),
            )
        rows = await fetch_project_event_rows("p1", 0)
        types = {r["type"] for r in rows}
        self.assertIn("supervisor", types)
        sup = [r for r in rows if r["type"] == "supervisor"]
        self.assertEqual(len(sup), 1)


if __name__ == "__main__":
    unittest.main()
