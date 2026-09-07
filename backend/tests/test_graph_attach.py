"""攻击链挂边：漏洞应经 service/info，而不是 target 直连。"""
from __future__ import annotations

import unittest

import networkx as nx

from atkbrain.graph.store import _mentions_host, _pick_attack_chain, _prefer_chain_parent


class PreferChainParentTests(unittest.TestCase):
    def test_vuln_prefers_same_host_service(self):
        by_key = {
            "target:10.0.0.1": {"key": "target:10.0.0.1", "type": "target", "created_at": 1, "tags": "[]"},
            "svc:80/http": {
                "key": "svc:80/http", "type": "service", "created_at": 2,
                "tags": '["host:10.0.0.1"]',
            },
            "info:banner": {
                "key": "info:banner", "type": "info", "created_at": 3,
                "tags": '["host:10.0.0.1"]',
            },
            "vuln:sqli": {
                "key": "vuln:sqli", "type": "vuln", "created_at": 4,
                "tags": '["host:10.0.0.1"]',
            },
        }
        got = _prefer_chain_parent(
            root_key="vuln:sqli",
            root_type="vuln",
            root_tags=["host:10.0.0.1"],
            primary="target:10.0.0.1",
            reachable={"target:10.0.0.1", "svc:80/http", "info:banner"},
            by_key=by_key,
        )
        self.assertEqual(got, ("svc:80/http", "LEADS_TO"))

    def test_no_parent_returns_none(self):
        by_key = {
            "target:10.0.0.1": {"key": "target:10.0.0.1", "type": "target", "created_at": 1, "tags": "[]"},
            "vuln:sqli": {"key": "vuln:sqli", "type": "vuln", "created_at": 2, "tags": "[]"},
        }
        got = _prefer_chain_parent(
            root_key="vuln:sqli",
            root_type="vuln",
            root_tags=[],
            primary="target:10.0.0.1",
            reachable={"target:10.0.0.1"},
            by_key=by_key,
        )
        self.assertIsNone(got)

    def test_danger_not_preferred_parent(self):
        by_key = {
            "target:10.0.0.1": {"key": "target:10.0.0.1", "type": "target", "created_at": 1, "tags": "[]"},
            "svc:80/http": {
                "key": "svc:80/http", "type": "service", "created_at": 2,
                "tags": '["host:10.0.0.1"]',
            },
            "danger:write": {
                "key": "danger:write", "type": "danger", "created_at": 3,
                "tags": '["host:10.0.0.1"]',
            },
            "vuln:rce": {
                "key": "vuln:rce", "type": "vuln", "created_at": 4,
                "tags": '["host:10.0.0.1"]',
            },
        }
        got = _prefer_chain_parent(
            root_key="vuln:rce",
            root_type="vuln",
            root_tags=["host:10.0.0.1"],
            primary="target:10.0.0.1",
            reachable={"target:10.0.0.1", "svc:80/http", "danger:write"},
            by_key=by_key,
        )
        self.assertEqual(got, ("svc:80/http", "LEADS_TO"))

    def test_service_orphan_not_rewritten(self):
        got = _prefer_chain_parent(
            root_key="svc:80/http",
            root_type="service",
            root_tags=["host:10.0.0.1"],
            primary="target:10.0.0.1",
            reachable={"target:10.0.0.1"},
            by_key={},
        )
        self.assertIsNone(got)


class PickAttackChainTests(unittest.TestCase):
    def test_prefers_vuln_rce_over_danger_is_rce(self):
        """橙线终点应落在真正的 vuln RCE，而不是中间标了 is_rce 的 danger。"""
        g = nx.DiGraph()
        keys = [
            "target:10.0.0.1",
            "svc:80/http",
            "info:api-export",
            "danger:export-write",
            "vuln:rce-export",
        ]
        for k in keys:
            g.add_node(k)
        g.add_edge("target:10.0.0.1", "svc:80/http", cost=0.01, w=1.0)
        g.add_edge("svc:80/http", "info:api-export", cost=0.1, w=0.9)
        g.add_edge("info:api-export", "danger:export-write", cost=0.35, w=0.7)
        g.add_edge("svc:80/http", "danger:export-write", cost=0.35, w=0.7)
        g.add_edge("svc:80/http", "vuln:rce-export", cost=0.05, w=0.95)
        by_key = {
            "target:10.0.0.1": {"key": "target:10.0.0.1", "type": "target", "is_rce": 0},
            "svc:80/http": {"key": "svc:80/http", "type": "service", "is_rce": 0},
            "info:api-export": {"key": "info:api-export", "type": "info", "is_rce": 0},
            "danger:export-write": {"key": "danger:export-write", "type": "danger", "is_rce": 1},
            "vuln:rce-export": {"key": "vuln:rce-export", "type": "vuln", "is_rce": 1},
        }
        path = _pick_attack_chain(
            g,
            ["target:10.0.0.1"],
            ["danger:export-write", "vuln:rce-export"],
            by_key,
        )
        self.assertEqual(path[-1], "vuln:rce-export")

    def test_verified_closeable_beats_unfinished_foothold_and_info(self):
        g = nx.DiGraph()
        keys = ["target:1", "svc:80", "vuln:cve", "foothold:shell", "info:banner"]
        for k in keys:
            g.add_node(k)
        g.add_edge("target:1", "svc:80", cost=0.01, w=1.0)
        g.add_edge("svc:80", "vuln:cve", cost=0.1, w=0.9)
        g.add_edge("svc:80", "foothold:shell", cost=0.05, w=0.95)
        g.add_edge("svc:80", "info:banner", cost=0.02, w=0.99)
        by_key = {
            "target:1": {"key": "target:1", "type": "target", "is_rce": 0, "tags": []},
            "svc:80": {"key": "svc:80", "type": "service", "is_rce": 0, "tags": []},
            "vuln:cve": {"key": "vuln:cve", "type": "vuln", "is_rce": 0,
                         "tags": ["verified", "rce"]},
            "foothold:shell": {"key": "foothold:shell", "type": "foothold",
                               "is_rce": 0, "tags": []},
            "info:banner": {"key": "info:banner", "type": "info", "is_rce": 0, "tags": []},
        }
        findings = {
            "vuln:cve": [{
                "verification_status": "verified", "category": "rce",
                "severity": "critical",
            }],
        }
        path = _pick_attack_chain(
            g, ["target:1"],
            ["vuln:cve", "foothold:shell", "info:banner"],
            by_key, findings,
        )
        self.assertEqual(path[-1], "vuln:cve")
        self.assertNotEqual(path[-1], "info:banner")
        self.assertNotEqual(path[-1], "foothold:shell")


class MentionsHostTests(unittest.TestCase):
    def test_full_ip_not_shared_prefix(self):
        blob = "0-10-189-58-target::fingerprint 侦察 10.0.189.58"
        self.assertTrue(_mentions_host(blob, "10.0.189.58"))
        self.assertFalse(_mentions_host(blob, "10.0.189.56"))
        self.assertFalse(_mentions_host(blob, "10.0.189"))
        self.assertFalse(_mentions_host("http://10.0.189.58/login", "10.0.189.5"))

    def test_sorted_dash_strategy_key(self):
        self.assertTrue(_mentions_host("0-10-189-56-target::auth_surface", "10.0.189.56"))
        self.assertFalse(_mentions_host("0-10-189-56-target::auth_surface", "10.0.189.58"))

    def test_octet_shorthand_only_when_enabled(self):
        blob = "把 .58 与 .56 为同一应用（指纹一致）"
        self.assertFalse(_mentions_host(blob, "10.0.189.58"))
        self.assertTrue(_mentions_host(blob, "10.0.189.58", allow_octet_shorthand=True))
        self.assertFalse(_mentions_host(blob, "10.0.189.5", allow_octet_shorthand=True))


class ScrubCandidateRceTests(unittest.TestCase):
    def test_strips_paren_label_from_title(self):
        from atkbrain.graph.model import NodeIn, FindingIn, scrub_candidate_rce_label
        self.assertEqual(
            scrub_candidate_rce_label("JDWP 5005 未授权调试 (候选 RCE)"),
            "JDWP 5005 未授权调试",
        )
        self.assertEqual(
            NodeIn(key="vuln:jdwp", type="vuln", title="JDWP 5005 未授权调试 (候选 RCE)").title,
            "JDWP 5005 未授权调试",
        )
        self.assertEqual(
            FindingIn(title="未授权调试（候选RCE）", category="rce").title,
            "未授权调试",
        )
        self.assertEqual(scrub_candidate_rce_label("GeoServer 2.23.2 RCE"), "GeoServer 2.23.2 RCE")


class AttachPrimaryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import os
        import tempfile
        from atkbrain.db import Database, now
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        import atkbrain.graph.store as store_mod
        import atkbrain.db as db_mod
        import atkbrain.events as ev_mod
        import atkbrain.scope_pivot as sp_mod
        self._old = db_mod.db
        db_mod.db = self.db
        store_mod.db = self.db
        ev_mod.db = self.db
        sp_mod.db = getattr(sp_mod, "db", None)
        self.store = store_mod
        self.db_mod = db_mod
        ts = now()
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("p_parent", "bench", "benchmark", "", "[]", "{}", "{}", "idle", ts, ts),
        )
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,parent_id,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("p_sib", "f2-07", "single", "10.0.182.80", "[9107]", "{}",
             '{"benchmark":{"unique_code":"f2-07","container_addr":["10.0.182.80:9107"]}}',
             "idle", "p_parent", ts, ts),
        )
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,parent_id,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("p_cur", "f2-05", "single", "10.0.182.81", "[9105]", "{}",
             '{"benchmark":{"unique_code":"f2-05","container_addr":["10.0.182.81:9105"]}}',
             "idle", "p_parent", ts, ts),
        )
        self.pid = "p_cur"

    async def asyncTearDown(self):
        import os
        import atkbrain.db as db_mod
        db_mod.db = self._old
        self.store.db = self._old
        await self.db.close()
        os.unlink(self.tmp.name)

    async def test_orphan_attaches_to_current_entry_not_older_peer_target(self):
        from atkbrain.graph.model import NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.80", type="target", title="邻题",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:local-bin", type="info", title="本题可执行文件",
            tags=["host:10.0.182.81", "port:9105"],
        ))
        rows = await self.db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND dst='info:local-bin'",
            (self.pid,),
        )
        srcs = {r["src"] for r in rows}
        self.assertIn("target:10.0.182.81", srcs)
        self.assertNotIn("target:10.0.182.80", srcs)

    async def test_rehang_moves_current_nodes_off_peer_target(self):
        from atkbrain.graph.model import NodeIn, EdgeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.80", type="target", title="邻题",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:local-bin", type="info", title="本题可执行文件",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="cred:9107-valid-key", type="credential", title="邻题密钥",
        ))
        await self.db.execute("DELETE FROM edges WHERE project_id=?", (self.pid,))
        await self.store.add_edge(self.pid, EdgeIn(
            src="target:10.0.182.80", dst="info:local-bin", relation="CONTAINS",
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="target:10.0.182.80", dst="cred:9107-valid-key", relation="CONTAINS",
        ))
        await self.store.ensure_target_attachments(self.pid)
        rows = await self.db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND relation='CONTAINS'",
            (self.pid,),
        )
        pairs = {(r["src"], r["dst"]) for r in rows}
        self.assertIn(("target:10.0.182.81", "info:local-bin"), pairs)
        self.assertNotIn(("target:10.0.182.80", "info:local-bin"), pairs)
        self.assertIn(("target:10.0.182.80", "cred:9107-valid-key"), pairs)

    async def test_intranet_ip_is_asset_not_second_target(self):
        from atkbrain.graph.model import NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题",
        ))
        key = await self.store.ensure_host_target(self.pid, "172.19.0.4", title="内网主机")
        self.assertEqual(key, "info:host:172.19.0.4")
        rows = await self.db.fetchall(
            "SELECT key, type FROM nodes WHERE project_id=?", (self.pid,)
        )
        by = {r["key"]: r["type"] for r in rows}
        self.assertEqual(by.get("target:10.0.182.81"), "target")
        self.assertNotIn("target:172.19.0.4", by)
        self.assertEqual(by.get("info:host:172.19.0.4"), "info")
        edges = await self.db.fetchall(
            "SELECT src, dst, relation FROM edges WHERE project_id=?", (self.pid,)
        )
        pairs = {(r["src"], r["dst"], r["relation"]) for r in edges}
        self.assertIn(("target:10.0.182.81", "info:host:172.19.0.4", "CONTAINS"), pairs)

    async def test_fold_heals_extra_black_target(self):
        from atkbrain.db import now
        from atkbrain.graph.model import NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题",
        ))
        ts = now()
        await self.db.execute(
            """INSERT INTO nodes(id, project_id, key, type, title, detail, severity,
                   is_rce, risk_score, tags, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("n_extra", self.pid, "target:172.19.0.5", "target", "内网 172.19.0.5",
             "", "info", 0, 0, '["lateral","pivot","host:172.19.0.5"]', "open", ts, ts),
        )
        await self.store.fold_intranet_targets(self.pid)
        rows = await self.db.fetchall(
            "SELECT key, type FROM nodes WHERE project_id=?", (self.pid,)
        )
        by = {r["key"]: r["type"] for r in rows}
        self.assertEqual(by.get("target:10.0.182.81"), "target")
        self.assertNotIn("target:172.19.0.5", by)
        self.assertEqual(by.get("info:host:172.19.0.5"), "info")

    async def test_upsert_coerces_intranet_target_key(self):
        from atkbrain.graph.model import NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题",
        ))
        row = await self.store.upsert_node(self.pid, NodeIn(
            key="target:172.19.0.2", type="target", title="内网应用",
            tags=["host:172.19.0.2"],
        ))
        self.assertEqual(row["key"], "info:host:172.19.0.2")
        self.assertEqual(row["type"], "info")

    async def test_peer_entry_stays_independent_target(self):
        from atkbrain.graph.model import NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.80", type="target", title="邻题",
        ))
        row = await self.db.fetchone(
            "SELECT key, type FROM nodes WHERE project_id=? AND key=?",
            (self.pid, "target:10.0.182.80"),
        )
        self.assertEqual(row["type"], "target")

    async def test_frontier_picks_one_hop_auth_then_orthogonal(self):
        from atkbrain.engine.supervise import CHAIN_NEXT
        from atkbrain.graph.model import IntentIn, NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题", tags=["entry"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:shell", type="foothold", title="shell",
            tags=["host:10.0.182.81"], is_rce=True, severity="critical",
        ))
        for ip in ("172.19.0.2", "172.19.0.3", "172.19.0.4"):
            await self.store.upsert_node(self.pid, NodeIn(
                key=f"info:host:{ip}", type="info", title=f"内网主机 {ip}",
                tags=["internal", "pivot", f"host:{ip}"],
            ))
        await self.store.add_intent(self.pid, IntentIn(
            **{"from": ["svc:172.19.0.2-ssh"]},
            description="对跳板 SSH 做有节制弱口令",
            rationale="22 与 Web 正交",
            strategy_key="22-inner::svc_auth_bruteforce",
            est_success=0.5, priority=0.8,
        ))
        picked = await self.store.list_frontier_intents(
            self.pid, limit=3, prefer_tactics=CHAIN_NEXT,
        )
        tacs = [(p.get("strategy_key") or "").split("::")[-1] for p in picked]
        self.assertEqual(tacs.count("hop_auth"), 1)
        self.assertGreaterEqual(len(set(tacs)), 2)
        self.assertIn("svc_auth_bruteforce", tacs)

    async def test_defer_local_closeout_when_hops_remain(self):
        from atkbrain.graph.model import IntentIn, NodeIn
        await self.db.execute(
            "UPDATE projects SET config=? WHERE id=?",
            ('{"flag_count":6}', self.pid),
        )
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题", tags=["entry"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:host:172.19.0.2", type="info", title="内网应用",
            tags=["internal", "pivot", "host:172.19.0.2"],
        ))
        await self.store.add_intent(self.pid, IntentIn(
            **{"from": ["foothold:shell"]},
            description="在立足点定位 flag",
            rationale="local",
            strategy_key="shell::flag_hunt",
            est_success=0.9, priority=0.99,
        ))
        ts = __import__("atkbrain.db", fromlist=["now"]).now()
        await self.db.execute(
            "INSERT INTO flags(id, project_id, value, correct, created_at) VALUES(?,?,?,?,?)",
            ("fl_1", self.pid, "flag{local-one}", 1, ts),
        )
        n = await self.store.defer_local_closeout_for_remaining_flags(self.pid)
        self.assertGreaterEqual(n, 1)
        row = await self.db.fetchone(
            "SELECT status FROM intents WHERE project_id=? AND strategy_key=?",
            (self.pid, "shell::flag_hunt"),
        )
        self.assertEqual(row["status"], "deferred")

    async def test_heals_pivots_to_when_entry_shell_missing_host_tag(self):
        from atkbrain.graph.model import EdgeIn, NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题", tags=["entry"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:host:10.0.182.81", type="info", title="入口站",
            tags=["host:10.0.182.81"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:web-shell", type="foothold", title="入口 shell",
            is_rce=True, severity="critical",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:shell", type="foothold", title="邻机 shell",
            tags=["host:172.19.0.2"], is_rce=True, severity="critical",
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="target:10.0.182.81", dst="info:host:10.0.182.81", relation="CONTAINS",
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="info:host:10.0.182.81", dst="foothold:web-shell", relation="CONTAINS",
        ))
        await self.store.ensure_lateral_pivots(self.pid)
        rows = await self.db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND relation='PIVOTS_TO'",
            (self.pid,),
        )
        pairs = {(r["src"], r["dst"]) for r in rows}
        self.assertIn(("foothold:web-shell", "foothold:shell"), pairs)
        tagged = await self.db.fetchone(
            "SELECT tags FROM nodes WHERE project_id=? AND key=?",
            (self.pid, "foothold:web-shell"),
        )
        self.assertIn("host:10.0.182.81", tagged["tags"] or "")

    async def test_ssrf_reachability_stays_leads_to(self):
        from atkbrain.graph.model import EdgeIn, NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题", tags=["entry"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:shell", type="foothold", title="入口 shell",
            tags=["host:10.0.182.81"], is_rce=True, severity="critical",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:host:172.19.0.2", type="info", title="内网主机",
            tags=["internal", "pivot", "host:172.19.0.2"],
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="foothold:shell", dst="info:host:172.19.0.2", relation="LEADS_TO",
            rationale="pivot_capability ssrf_direct: 邻机 HTTP 200",
        ))
        await self.store.ensure_lateral_pivots(self.pid)
        rows = await self.db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND relation='PIVOTS_TO'",
            (self.pid,),
        )
        self.assertEqual(list(rows), [])

    async def test_pivot_src_is_shell_not_target_when_entry_ip_differs(self):
        from atkbrain.graph.model import EdgeIn, NodeIn
        await self.store.upsert_node(self.pid, NodeIn(
            key="target:10.0.182.81", type="target", title="本题", tags=["entry"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="info:host:10.0.182.89", type="info", title="入口容器",
            tags=["host:10.0.182.89"],
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:web-shell", type="foothold", title="入口 shell",
            is_rce=True, severity="critical",
        ))
        await self.store.upsert_node(self.pid, NodeIn(
            key="foothold:shell", type="foothold", title="邻机 shell",
            tags=["host:172.19.0.2"], is_rce=True, severity="critical",
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="target:10.0.182.81", dst="info:host:10.0.182.89", relation="CONTAINS",
        ))
        await self.store.add_edge(self.pid, EdgeIn(
            src="info:host:10.0.182.89", dst="foothold:web-shell", relation="CONTAINS",
        ))
        await self.store.ensure_lateral_pivots(self.pid)
        rows = await self.db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND relation='PIVOTS_TO'",
            (self.pid,),
        )
        pairs = {(r["src"], r["dst"]) for r in rows}
        self.assertTrue(pairs)
        for src, dst in pairs:
            self.assertFalse(src.startswith("target:"), msg=pairs)
            self.assertTrue(src.startswith("foothold:"), msg=pairs)
            self.assertTrue(dst.startswith("foothold:"), msg=pairs)


class HostOfNodeTests(unittest.TestCase):
    def test_embedded_ipv4_in_foothold_key(self):
        from atkbrain.graph.store import _host_of_node
        self.assertEqual(_host_of_node("foothold:webshell-172.19.0.5", []), "172.19.0.5")
        self.assertEqual(_host_of_node("foothold:shell", ["host:172.18.0.2"]), "172.18.0.2")
        self.assertEqual(_host_of_node("foothold:web-shell", []), "")


if __name__ == "__main__":
    unittest.main()
