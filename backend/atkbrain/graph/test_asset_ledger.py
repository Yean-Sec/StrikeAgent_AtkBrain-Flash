"""厂商资产库、范围、留痕、复测和模型链。"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from atkbrain_native import hard_stop_exempt
from atkbrain_native import Scope, unauthorized_public_host


class ScopeGateTests(unittest.TestCase):
    def test_written_host_only(self):
        scope = Scope(targets=["app.example.com"], ips=["203.0.113.10"], allow_subdomains=False)
        self.assertIsNone(unauthorized_public_host("app.example.com", scope))
        self.assertIsNotNone(unauthorized_public_host("example.com", scope))
        self.assertIsNotNone(unauthorized_public_host("www.app.example.com", scope))
        self.assertNotIn("www.app.example.com", scope.identity_hosts())
        self.assertTrue(scope.host_in_scope("203.0.113.10"))
        self.assertFalse(scope.host_in_scope("203.0.113.11"))

    def test_confirmed_cidr_only(self):
        scope = Scope(targets=["app.example.com"], cidrs=["203.0.113.0/24"])
        self.assertTrue(scope.host_in_scope("203.0.113.11"))
        bare = Scope(targets=["app.example.com"], ips=["203.0.113.10"])
        self.assertFalse(bare.host_in_scope("203.0.113.11"))

    def test_src_high_does_not_close_untested_types(self):
        self.assertFalse(hard_stop_exempt("src", verified_high=1, untested_types=2))
        self.assertTrue(hard_stop_exempt("agent", verified_high=1, untested_types=0))
        self.assertFalse(hard_stop_exempt("redteam", achievements=["getshell"], untested_types=3))
        self.assertFalse(hard_stop_exempt("getshell", achievements=["getshell"], untested_types=0))


class LedgerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from ..db import db

        from ..config import settings

        self.db = db
        self.td = tempfile.TemporaryDirectory()
        self.old_path = db.path
        self.old_conn = db._conn
        self.old_db_path = settings.db_path
        db._conn = None
        db.path = os.path.join(self.td.name, "ledger.db")
        settings.db_path = Path(db.path)
        await db.connect()

    async def asyncTearDown(self):
        from ..config import settings

        await self.db.close()
        self.db.path = self.old_path
        self.db._conn = self.old_conn
        settings.db_path = self.old_db_path
        self.td.cleanup()

    async def _project(self, pid="p_test", target="app.example.com"):
        from ..db import now
        ts = now()
        await self.db.execute(
            """INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (pid, "t", "single", target, None,
             '{"targets":["app.example.com"],"ips":[],"cidrs":[],"allow_subdomains":false,"mode":"strict"}',
             '{"objective":"redteam","track":"redteam"}', "idle", None, ts, ts),
        )

    async def test_merge_and_deny_and_apex(self):
        from ..assets import import_text, seed_declared, untested_in_scope_count

        await self._project()
        await seed_declared("p_test", ["app.example.com"], ["203.0.113.10"], vendor_name="甲")
        again = await import_text("app.example.com\napp.example.com\n", vendor_name="甲", project_id="p_test")
        self.assertGreaterEqual(again["stored"], 1)
        rows = await self.db.fetchall(
            "SELECT kind, identity FROM assets WHERE identity='app.example.com'"
        )
        self.assertEqual(len(rows), 1)
        apex = await self.db.fetchone(
            """SELECT pa.in_scope FROM assets a
               JOIN project_assets pa ON pa.asset_id=a.id
               WHERE a.identity='example.com' AND pa.project_id='p_test'"""
        )
        self.assertIsNotNone(apex)
        self.assertEqual(int(apex["in_scope"]), 0)
        host = await self.db.fetchone(
            """SELECT pa.in_scope FROM assets a
               JOIN project_assets pa ON pa.asset_id=a.id
               WHERE a.identity='app.example.com' AND pa.project_id='p_test'"""
        )
        self.assertEqual(int(host["in_scope"]), 1)
        denied = await import_text("agency.gov\n", vendor_name="甲", project_id="p_test")
        self.assertGreaterEqual(denied["denied"], 1)
        gone = await self.db.fetchone("SELECT id FROM assets WHERE identity='agency.gov'")
        self.assertIsNone(gone)
        self.assertGreaterEqual(await untested_in_scope_count("p_test"), 1)

    async def test_neighbor_not_authorized(self):
        from ..assets import remember_host

        await self._project()
        await remember_host("p_test", "203.0.113.10", in_scope=True, own_ip=True, vendor_name="甲")
        await remember_host("p_test", "203.0.113.11", in_scope=True, vendor_name="甲")
        row = await self.db.fetchone(
            """SELECT pa.in_scope FROM assets a
               JOIN project_assets pa ON pa.asset_id=a.id
               WHERE a.identity='203.0.113.11'"""
        )
        self.assertIsNotNone(row)
        self.assertEqual(int(row["in_scope"]), 0)

    async def test_confirm_requires_basis(self):
        from ..assets import confirm_expansion

        await self._project()
        with self.assertRaises(ValueError):
            await confirm_expansion("p_test", mode="domain", basis="  ", value="example.com")

    async def test_http_bind_must_match(self):
        from atkbrain_native import bind_finding, record_exchange

        await self._project()
        eid = record_exchange(
            "p_test", run_id=None, method="GET", url="https://app.example.com/a",
            status=200, response_body="ok marker",
        )
        fid = "f_test"
        from ..db import now
        ts = now()
        await self.db.execute(
            """INSERT INTO findings(id, project_id, severity, category, title, created_at)
               VALUES(?,?,?,?,?,?)""",
            (fid, "p_test", "low", "info", "t", ts),
        )
        bad = bind_finding(fid, [{
            "id": eid, "role": "证明", "method": "POST", "url": "https://app.example.com/a",
            "status": 200, "summary": "ok marker",
        }])
        self.assertEqual(bad["bound"], [])
        good = bind_finding(fid, [{
            "id": eid, "role": "证明", "method": "GET", "url": "https://app.example.com/a",
            "status": 200, "summary": "ok marker",
        }])
        self.assertEqual(good["bound"], [eid])

    async def test_pending_cannot_be_high(self):
        from atkbrain_native import add_finding

        await self._project()
        row = add_finding("p_test", {
            "severity": "high", "category": "info", "title": "版本对应 nginx",
            "evidence": "nginx 1.18 版本对应", "redteam_rating": "high", "cvss": 9.8,
        })
        self.assertEqual(row["verification_status"], "pending")
        self.assertNotIn(row["severity"], ("high", "critical"))
        self.assertNotIn((row.get("redteam_rating") or ""), ("high", "critical"))
        self.assertIsNone(row.get("cvss"))

    async def test_retest_without_traffic_does_not_change_evidence(self):
        from ..db import now
        from ..retest import retest_finding

        await self._project()
        ts = now()
        await self.db.execute(
            """INSERT INTO findings(id, project_id, severity, category, title, evidence, created_at)
               VALUES(?,?,?,?,?,?,?)""",
            ("f1", "p_test", "medium", "xss", "x", "orig", ts),
        )
        out = await retest_finding("p_test", "f1")
        self.assertEqual(out["conclusion"], "inconclusive")
        self.assertTrue(out["evidence_unchanged"])
        self.assertIsNone(out["disposition"])

    async def test_webhook_failure_keeps_finding(self):
        from ..notify import enqueue_finding

        await self._project()
        with patch("atkbrain.notify.get_webhook", return_value={
            "url": "http://127.0.0.1:9/hook", "severities": [], "projects": [], "assets": [],
        }), patch("atkbrain.notify._post", new=AsyncMock(side_effect=RuntimeError("down"))):
            await enqueue_finding("p_test", {"id": "f9", "title": "t", "severity": "low", "category": "info"})
        box = await self.db.fetchall("SELECT id FROM webhook_outbox")
        self.assertEqual(len(box), 1)

    async def test_model_chain_keeps_intent(self):
        from ..db import now
        from atkbrain_native import advance_model_chain

        await self._project()
        ts = now()
        await self.db.execute(
            "UPDATE projects SET config=? WHERE id=?",
            ('{"objective":"src","track":"src","model":"a","model_chain":["a","b"],"model_chain_index":0}', "p_test"),
        )
        await self.db.execute(
            """INSERT INTO intents(id, project_id, description, est_success, status, priority, attempt_count, created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            ("i1", "p_test", "sqli", 0.5, "active", 0.5, 1, ts),
        )
        nxt = advance_model_chain("p_test")
        self.assertEqual(nxt, "b")
        intent = await self.db.fetchone("SELECT status FROM intents WHERE id='i1'")
        self.assertEqual(intent["status"], "active")

    async def test_dependency_not_dispatched(self):
        from ..db import now
        from atkbrain_native import add_intent, list_open_intents

        await self._project()
        ts = now()
        await self.db.execute(
            """INSERT INTO intents(id, project_id, description, est_success, status, priority, attempt_count, created_at, from_keys)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("i_pre", "p_test", "先看入口", 0.5, "open", 0.5, 0, ts, "[]"),
        )
        add_intent("p_test", {"description": "再打注入", "depends_on": ["i_pre"]})
        open_rows = list_open_intents("p_test")
        descs = [r["description"] for r in open_rows]
        self.assertIn("先看入口", descs)
        self.assertNotIn("再打注入", descs)


if __name__ == "__main__":
    unittest.main()
