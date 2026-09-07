"""推理前沿：假设派生、去重、关闭与排序。"""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest

from atkbrain.db import Database, new_id, now
from atkbrain.graph.hypothesize import hypotheses_for_node, hypotheses_for_finding, strategy_key
from atkbrain.graph.model import FindingIn, IntentIn, NodeIn
from atkbrain.graph import store as gstore
from atkbrain.engine.supervise import LoopSupervisor


class FrontierTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        # patch global db used by store
        import atkbrain.graph.store as store_mod
        import atkbrain.db as db_mod
        self._old_db = db_mod.db
        db_mod.db = self.db
        store_mod.db = self.db
        self.pid = "p_frontier_test"
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.pid, "t", "single", "1.2.3.4", "[]", "{}", "{}", "idle", now(), now()),
        )

    async def asyncTearDown(self):
        import atkbrain.graph.store as store_mod
        import atkbrain.db as db_mod
        db_mod.db = self._old_db
        store_mod.db = self._old_db
        await self.db.close()
        os.unlink(self.tmp.name)

    async def test_service_derives_multiple_hypotheses(self):
        hyps = hypotheses_for_node({
            "key": "svc:80/http", "type": "service", "title": "Apache/PHP",
            "severity": "info", "tags": ["http", "php"], "detail": "Apache httpd",
        })
        tactics = {h.strategy_key.split("::")[-1] for h in hyps}
        self.assertIn("fingerprint", tactics)
        self.assertIn("auth_surface", tactics)
        self.assertGreaterEqual(len(hyps), 3)

    def test_uniform_error_danger_derives_channel_oracle(self):
        hyps = hypotheses_for_node({
            "key": "danger:login-500-fault", "type": "danger",
            "title": "/login 视图持续 500(GET/POST)",
            "severity": "high", "tags": [], "detail": "GET/POST 无 Set-Cookie 无差异",
        })
        tactics = {h.strategy_key.split("::")[-1] for h in hyps}
        self.assertIn("channel_oracle", tactics)
        self.assertIn("input_abuse", tactics)
        ch = next(h for h in hyps if (h.strategy_key or "").endswith("channel_oracle"))
        self.assertGreaterEqual(ch.priority or 0, 0.7)
        blob = " ".join(h.description or "" for h in hyps if (h.strategy_key or "").endswith("channel_oracle"))
        self.assertIn("观测通道", blob)
        self.assertNotIn("flask-unsign", blob)

    def test_crash_vuln_derives_oracle_not_weaponize(self):
        hyps = hypotheses_for_node({
            "key": "vuln:login-crash", "type": "vuln",
            "title": "登录渲染层崩溃",
            "severity": "medium", "tags": ["verified", "availability", "crash"],
            "detail": "恒定 500 统一错误页 无 Set-Cookie",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("channel_oracle", tactics)
        self.assertIn("input_abuse", tactics)
        self.assertNotIn("weaponize", tactics)
        blob = " ".join((h.description or "") + " " + (h.rationale or "") for h in hyps)
        self.assertNotIn("推进到稳定利用", blob)
        from atkbrain.graph.hypothesize import needs_channel_oracle
        self.assertTrue(needs_channel_oracle({
            "nodes": [{
                "type": "danger", "title": "统一错误页",
                "detail": "always 500 无 Set-Cookie",
            }],
        }))
        self.assertFalse(needs_channel_oracle({
            "nodes": [{
                "type": "danger", "title": "统一错误页",
                "detail": "always 500 时间差已验证",
            }],
        }))
        self.assertTrue(needs_channel_oracle({
            "nodes": [{
                "type": "danger", "title": "无条件 500 已闭合",
                "detail": "零翻面 恒 +13ms 与输入无关",
            }],
        }))
        self.assertFalse(needs_channel_oracle({
            "nodes": [
                {
                    "type": "danger", "title": "无条件 500 已闭合",
                    "detail": "零翻面 恒定 500 与输入无关",
                },
                {
                    "type": "vuln", "title": "登录注入",
                    "detail": "POST 参数时间差已验证",
                },
            ],
        }))
        self.assertTrue(needs_channel_oracle({
            "nodes": [{
                "type": "info", "title": "口令面关闭",
                "detail": "无条件 500 统一错误页",
            }],
        }))
        self.assertFalse(needs_channel_oracle({
            "nodes": [{
                "type": "info", "title": "通道否证：导入面恒定 400",
                "detail": "同体 400，错误正文点名缺字段",
            }],
        }))
        hyps_info = hypotheses_for_node({
            "key": "info:login-500-closed", "type": "info",
            "title": "口令面关闭",
            "severity": "info", "tags": [],
            "detail": "无条件 500 统一错误页",
        })
        info_tacs = {(h.strategy_key or "").split("::")[-1] for h in hyps_info}
        self.assertIn("channel_oracle", info_tacs)
        self.assertIn("input_abuse", info_tacs)
        self.assertNotIn("info_to_cred", info_tacs)

    async def test_upsert_node_creates_deduped_intents(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:80/http", type="service", title="Web", tags=["http"],
        ))
        intents1 = await gstore.list_open_intents(self.pid)
        self.assertGreaterEqual(len(intents1), 3)
        # 再次 upsert 不应膨胀
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:80/http", type="service", title="Web", tags=["http"],
        ))
        intents2 = await gstore.list_open_intents(self.pid)
        self.assertEqual(len(intents1), len(intents2))

    async def test_file_read_finding_priority_chain(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="vuln:lfi", type="vuln", title="LFI", severity="high", tags=["lfi", "file_read"],
        ))
        node = await self.db.fetchone(
            "SELECT * FROM nodes WHERE project_id=? AND key=?", (self.pid, "vuln:lfi")
        )
        hyps = hypotheses_for_finding(
            FindingIn(node_key="vuln:lfi", severity="high", category="file_read", title="path traversal"),
            node,
        )
        self.assertTrue(any("read" in (h.strategy_key or "") for h in hyps))
        self.assertGreaterEqual(max(h.priority or 0 for h in hyps), 0.7)

    async def test_resolve_intent_blocks_same_evidence(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="danger:upload", type="danger", title="upload", severity="medium", tags=["upload"],
        ))
        open_i = await gstore.list_open_intents(self.pid)
        target = next(i for i in open_i if i.get("strategy_key") and "upload" in i["strategy_key"])
        await gstore.resolve_intent(
            self.pid, target["id"], verified=False, summary="blocked by filter",
            failure_fingerprint="upload:ext=php",
        )
        # 同 evidence 再派生不会复开为 open（仍 disproved）
        await gstore.derive_intents_for_node(self.pid, {
            "key": "danger:upload", "type": "danger", "title": "upload",
            "severity": "medium", "tags": '["upload"]',
        })
        row = await self.db.fetchone("SELECT status FROM intents WHERE id=?", (target["id"],))
        self.assertEqual(row["status"], "disproved")

    async def test_frontier_picks_orthogonal_strategies(self):
        await gstore.upsert_node(self.pid, NodeIn(key="svc:80/http", type="service", title="web", tags=["http"]))
        await gstore.upsert_node(self.pid, NodeIn(key="cred:admin", type="credential", title="admin/admin", severity="high"))
        picked = await gstore.list_frontier_intents(self.pid, limit=3)
        self.assertGreaterEqual(len(picked), 2)
        tactics = {(p.get("strategy_key") or "").split("::")[-1] for p in picked}
        self.assertGreaterEqual(len(tactics), 2)

    async def test_frontier_prefers_chain_tactics(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:80/http", type="service", title="web", tags=["http"],
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="vuln:ssrf", type="vuln", title="ssrf", severity="critical", tags=["ssrf"],
            detail="ssrf file://",
        ))
        from atkbrain.engine.supervise import CHAIN_NEXT
        picked = await gstore.list_frontier_intents(self.pid, limit=3, prefer_tactics=CHAIN_NEXT)
        self.assertTrue(picked)
        first = (picked[0].get("strategy_key") or "").split("::")[-1]
        self.assertIn(first, CHAIN_NEXT)

    async def test_frontier_defers_enum_when_live_surface(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:80/http", type="service", title="web",
            tags=["http", "graphql"],
        ))
        picked = await gstore.list_frontier_intents(
            self.pid, limit=5,
            prefer_tactics={"graphql_contract"},
            exclude_strategies={"content_enum"},
        )
        tactics = {(p.get("strategy_key") or "").split("::")[-1] for p in picked}
        self.assertIn("graphql_contract", tactics)
        self.assertNotIn("content_enum", tactics)

    async def test_oracle_prefer_outranks_leftover_file_read(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="danger:uniform-error", type="danger",
            title="统一错误页", severity="medium", tags=[],
            detail="always 500 无 Set-Cookie",
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="danger:download-side", type="danger",
            title="下载面", severity="medium", tags=["lfi", "download"],
            detail="缺文件确定性 500 文件读取/穿越",
        ))
        picked = await gstore.list_frontier_intents(
            self.pid, limit=3,
            prefer_tactics={"channel_oracle", "input_abuse"},
            exclude_strategies={"file_read_chain", "upload_bypass", "content_enum", "weaponize"},
        )
        tactics = [(p.get("strategy_key") or "").split("::")[-1] for p in picked]
        self.assertTrue(tactics)
        self.assertIn(tactics[0], {"channel_oracle", "input_abuse"})
        self.assertNotIn("file_read_chain", tactics)
        self.assertNotIn("upload_bypass", tactics)

    async def test_frontier_ranks_reverse_binary_ahead_of_access_control(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:9105/http", type="service", title="HTTP :9105",
            tags=["http"], detail="octet-stream",
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="danger:gate", type="danger", title="obfuscated gate",
            severity="high",
        ))
        picked = await gstore.list_frontier_intents(
            self.pid, limit=3,
            prefer_tactics={"reverse_binary", "protocol_model", "access_control"},
        )
        tactics = [(p.get("strategy_key") or "").split("::")[-1] for p in picked]
        self.assertTrue(tactics)
        self.assertEqual(tactics[0], "reverse_binary")

    async def test_supervisor_quality_and_exec_fault(self):
        s = LoopSupervisor(self.pid, "run_x", objective="flag")
        self.assertFalse(s.note_progress(nodes=1, edges=0, findings=0, flags=0, quality="none"))
        self.assertTrue(s.note_progress(nodes=2, edges=1, findings=1, flags=0, quality="finding"))
        self.assertEqual(s.no_progress, 0)
        self.assertTrue(s.note_exec_fault("Cannot write to terminated process (exit code: 143)"))
        self.assertTrue(s.note_exec_fault("Control request timeout: initialize"))
        self.assertFalse(s.note_exec_fault("sql syntax error near SELECT"))

    async def test_refresh_backfills_secret_mount_and_defers_ssrf_weaponize(self):
        from atkbrain.graph.hypothesize import strategy_key

        await gstore.upsert_node(self.pid, NodeIn(
            key="vuln:ssrf", type="vuln", title="ssrf probe", severity="high", tags=["ssrf"],
            detail="ssrf http only",
        ))
        await gstore.add_intent(self.pid, IntentIn(
            **{"from": ["vuln:ssrf"]},
            description="legacy weaponize",
            rationale="old rule",
            est_success=0.7,
            strategy_key=strategy_key("vuln:ssrf", "weaponize"),
            status="open",
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="cred:svc-token", type="credential", title="internal admin_token",
            severity="high", tags=["token"],
            detail="admin_token=internal_example_token",
        ))
        await gstore.add_intent(self.pid, IntentIn(
            **{"from": ["cred:svc-token"]},
            description="legacy login reuse",
            rationale="old rule",
            est_success=0.7,
            strategy_key=strategy_key("cred:svc-token", "auth_reuse"),
            status="open",
        ))
        stats = await gstore.refresh_derived_intents(self.pid)
        self.assertGreaterEqual(stats["stale_deferred"], 1)
        rows = await self.db.fetchall(
            "SELECT strategy_key, status FROM intents WHERE project_id=?", (self.pid,),
        )
        by_tac: dict[str, list[str]] = {}
        for r in rows:
            tac = (r["strategy_key"] or "").split("::")[-1]
            by_tac.setdefault(tac, []).append(r["status"])
        self.assertIn("open", by_tac.get("secret_mount") or [])
        self.assertIn("deferred", by_tac.get("weaponize") or [])
        self.assertNotIn("open", by_tac.get("weaponize") or [])
        self.assertIn("deferred", by_tac.get("auth_reuse") or [])

    async def test_adopt_entry_defers_old_ip_intents(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="target:10.0.189.58", type="target", title="旧入口", tags=["entry"],
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="target:10.0.189.99", type="target", title="跳板",
            tags=["lateral", "pivot", "host:10.0.189.99"],
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="侦察 10.0.189.58", rationale="old entry",
            strategy_key="0-10-189-58-target::fingerprint", est_success=0.5,
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="打当前入口 10.0.189.56 /login", rationale="now",
            strategy_key="0-10-189-56-target::auth_surface", est_success=0.6,
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="目录枚举", rationale="generic",
            strategy_key="80-http-svc::content_enum", est_success=0.4,
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="横向 10.0.189.99", rationale="pivot",
            strategy_key="0-10-189-99-target::hop_auth", est_success=0.7,
        ))
        out = await gstore.adopt_entry_host(self.pid, "10.0.189.56")
        self.assertIn("target:10.0.189.58", out.get("retired") or [])
        self.assertGreaterEqual(out.get("deferred") or 0, 1)
        rows = await self.db.fetchall(
            "SELECT strategy_key, status FROM intents WHERE project_id=?", (self.pid,),
        )
        by_sk = {r["strategy_key"]: r["status"] for r in rows}
        self.assertEqual(by_sk["0-10-189-58-target::fingerprint"], "deferred")
        self.assertEqual(by_sk["0-10-189-56-target::auth_surface"], "open")
        self.assertEqual(by_sk["80-http-svc::content_enum"], "open")
        self.assertEqual(by_sk["0-10-189-99-target::hop_auth"], "open")

    async def test_adopt_defers_stale_intents_after_merge(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="target:10.0.189.56", type="target", title="入口", tags=["entry"],
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="svc:80/http@10.0.189.58", type="service", title="残留旧址 HTTP",
            tags=["http", "host:10.0.189.58"],
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="监控旧容器 10.0.189.58", rationale="stale",
            strategy_key="0-10-189-58-target::fingerprint", est_success=0.5,
        ))
        await gstore.add_intent(self.pid, IntentIn(
            description="把 .58 与 .56 为同一应用（指纹一致）", rationale="stale",
            strategy_key="56-58-app-same-vs::info_to_danger", est_success=0.5,
        ))
        out = await gstore.adopt_entry_host(self.pid, "10.0.189.56")
        self.assertEqual(out.get("retired") or [], [])
        self.assertGreaterEqual(out.get("deferred") or 0, 2)
        for sk in ("0-10-189-58-target::fingerprint", "56-58-app-same-vs::info_to_danger"):
            row = await self.db.fetchone(
                "SELECT status FROM intents WHERE project_id=? AND strategy_key=?",
                (self.pid, sk),
            )
            self.assertIsNotNone(row, sk)
            self.assertEqual(row["status"], "deferred", sk)

    async def test_adopt_keeps_live_second_entry_host(self):
        await gstore.upsert_node(self.pid, NodeIn(
            key="target:10.0.0.8", type="target", title="入口 A", tags=["entry"],
        ))
        await gstore.upsert_node(self.pid, NodeIn(
            key="target:10.0.0.9", type="target", title="入口 B", tags=["entry"],
        ))
        out = await gstore.adopt_entry_host(
            self.pid, "10.0.0.8", keep_hosts={"10.0.0.8", "10.0.0.9"},
        )
        self.assertNotIn("target:10.0.0.9", out.get("retired") or [])
        row = await self.db.fetchone(
            "SELECT key FROM nodes WHERE project_id=? AND key=?",
            (self.pid, "target:10.0.0.9"),
        )
        self.assertIsNotNone(row)

    async def test_reopen_false_closed_oracle_when_surface_still_open(self):
        from atkbrain.graph.store import add_intent, reopen_false_closed_oracle, set_intent_status
        from atkbrain.graph.model import IntentIn
        it = await add_intent(self.pid, IntentIn(
            description="换观测通道",
            strategy_key="500::channel_oracle",
            status="open",
        ))
        await set_intent_status(self.pid, it["id"], "disproved", result_summary="无差分")
        n = await reopen_false_closed_oracle(self.pid, needs_oracle=True)
        self.assertEqual(n, 1)
        row = await self.db.fetchone("SELECT status FROM intents WHERE id=?", (it["id"],))
        self.assertEqual(row["status"], "open")
        self.assertEqual(await reopen_false_closed_oracle(self.pid, needs_oracle=False), 0)


class SqliWeaponizeTests(unittest.TestCase):
    def test_finding_sqli_chain_prefers_control_flow(self):
        hyps = hypotheses_for_finding(
            FindingIn(node_key="vuln:sqli", severity="critical", category="sqli",
                      title="/login username 时间盲注"),
            {"key": "vuln:sqli", "type": "vuln", "title": "sqli", "tags": ["sqli"]},
        )
        blob = " ".join(h.description or "" for h in hyps)
        self.assertTrue(any("sqli" in (h.strategy_key or "") for h in hyps))
        self.assertIn("控制流", blob)
        self.assertIn("dump", blob.lower())
        self.assertNotIn("拖库/读文件/RCE", blob)
        self.assertNotIn("LOAD_FILE", blob)

    def test_vuln_sqli_weaponize_stops_session_brute(self):
        hyps = hypotheses_for_node({
            "key": "vuln:sqli-login", "type": "vuln", "title": "login sqli",
            "severity": "critical", "tags": ["sqli"], "detail": "time-based mysql",
        })
        w = next(h for h in hyps if (h.strategy_key or "").endswith("weaponize"))
        self.assertIn("控制流", w.description or "")
        self.assertIn("身份伪造", w.description or "")
        self.assertNotIn("会话密钥", w.description or "")
        self.assertNotIn("flask", (w.description or "").lower())

    def test_token_vuln_weaponize_is_crypto_class_not_ui_role(self):
        hyps = hypotheses_for_node({
            "key": "vuln:jwt", "type": "vuln", "title": "JWT role bypass",
            "severity": "high", "tags": ["verified", "auth_bypass"],
            "detail": "HS256 signed token, weak alg variants failed",
        })
        w = next(h for h in hyps if (h.strategy_key or "").endswith("weaponize"))
        self.assertIn("服务端校验", w.description or "")
        self.assertIn("不关闭整类", w.description or "")
        self.assertNotIn("prod.key", (w.description or "").lower())
        self.assertNotIn("jquery", (w.description or "").lower())


class HopAuthHypothesisTests(unittest.TestCase):
    def test_lateral_target_emits_hop_auth(self):
        hyps = hypotheses_for_node({
            "key": "target:172.20.0.4", "type": "target", "title": "内网主机 172.20.0.4",
            "severity": "info", "tags": ["lateral", "pivot"],
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("hop_auth", tactics)
        blob = " ".join(h.description or "" for h in hyps)
        self.assertIn("身份边界", blob)
        self.assertIn("只是候选", blob)
        self.assertNotIn("Weaver", blob)

    def test_intranet_info_host_emits_hop_auth(self):
        hyps = hypotheses_for_node({
            "key": "info:host:172.20.0.4", "type": "info", "title": "内网主机 172.20.0.4",
            "severity": "info", "tags": ["internal", "pivot", "host:172.20.0.4"],
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("hop_auth", tactics)

    def test_same_container_host_skips_hop_auth(self):
        hyps = hypotheses_for_node({
            "key": "info:host:172.20.0.5", "type": "info",
            "title": "172.20.0.5 官网（与 10.0.1.8 同一容器）",
            "severity": "info", "tags": ["internal", "pivot", "host:172.20.0.5"],
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertNotIn("hop_auth", tactics)

    def test_entry_target_does_not_emit_hop_auth(self):
        hyps = hypotheses_for_node({
            "key": "target:10.0.171.186", "type": "target", "title": "评测入口",
            "severity": "info", "tags": [],
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertNotIn("hop_auth", tactics)

    def test_login_cred_reuse_stays_on_same_app(self):
        hyps = hypotheses_for_node({
            "key": "cred:admin", "type": "credential",
            "title": "admin/example",
            "severity": "high", "tags": ["login"],
            "detail": "password from this app login",
        })
        reuse = next(h for h in hyps if (h.strategy_key or "").endswith("auth_reuse"))
        self.assertIn("签发它的那一跳", reuse.description or "")
        self.assertIn("不要当其它 hop 的万能钥匙", reuse.description or "")

    def test_negative_login_info_does_not_spawn_cred(self):
        from atkbrain.graph.hypothesize import is_negative_conclusion
        self.assertTrue(is_negative_conclusion(
            "累计 106 组登录口令空间全负", "登录门 106 组口令空间全负（穷尽）"
        ))
        self.assertTrue(is_negative_conclusion(
            "登录门突破尝试全部失败（邻机 Web / 应用后台 / 文件服务）",
            "登录门突破尝试全部失败",
        ))
        hyps = hypotheses_for_node({
            "key": "info:login-106-neg", "type": "info",
            "title": "登录门 106 组口令空间全负（穷尽）",
            "severity": "info", "tags": [],
            "detail": "POST 登录门累计 106 组口令空间全负",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertNotIn("info_to_cred", tactics)
        self.assertNotIn("info_to_danger", tactics)

    def test_channel_negation_keeps_ssrf_gateway(self):
        from atkbrain.graph.hypothesize import (
            is_negative_conclusion, live_gadget_tactics,
        )
        self.assertFalse(is_negative_conclusion(
            "导入面恒定 400 同体错误", "通道否证：一种契约失败",
        ))
        hyps = hypotheses_for_node({
            "key": "info:import-channel-neg", "type": "info",
            "title": "通道否证：导入面恒定 400",
            "severity": "info", "tags": ["ssrf", "import"],
            "detail": "同体 400，错误正文点名缺字段。不要当钥匙。",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("ssrf_as_gateway", tactics)
        self.assertNotIn("info_to_cred", tactics)
        got = live_gadget_tactics({
            "nodes": [{
                "type": "service", "key": "svc:import",
                "title": "导入接口",
                "tags": ["ssrf", "import"],
                "detail": "HTTP 导入面，错误点名缺字段",
            }],
        })
        self.assertIn("ssrf_as_gateway", got)

    def test_gadget_skips_entry_filter_bypass_and_process_notes(self):
        hyps = hypotheses_for_node({
            "key": "vuln:ssrf-probe", "type": "vuln",
            "title": "回显 SSRF",
            "severity": "high", "tags": ["ssrf", "verified"],
            "detail": "blocked forbidden filter",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("ssrf_as_gateway", tactics)
        self.assertNotIn("filter_bypass", tactics)
        blob = " ".join(
            (h.description or "") + " " + (h.rationale or "")
            for h in hyps
            if (h.strategy_key or "").endswith(("ssrf_as_gateway", "ssrf_local_svc"))
        )
        self.assertNotIn("gopher", blob.lower())
        self.assertNotIn("file://", blob.lower())
        notes = hypotheses_for_node({
            "key": "info:exec:round9", "type": "info",
            "title": "探测失败：仍被阻止",
            "severity": "info", "tags": ["ssrf"],
            "detail": "变体失败，通道否证",
        })
        note_tacs = {(h.strategy_key or "").split("::")[-1] for h in notes}
        self.assertNotIn("ssrf_as_gateway", note_tacs)
        self.assertNotIn("filter_bypass", note_tacs)

    def test_failed_secret_probe_does_not_mount(self):
        hyps = hypotheses_for_node({
            "key": "info:session-forge-dead", "type": "info",
            "title": "Flask SECRET_KEY 爆破失败（强随机）",
            "severity": "info", "tags": [],
            "detail": "会话密钥爆破失败，强随机不可爆破",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertNotIn("secret_mount", tactics)
        self.assertNotIn("info_to_cred", tactics)

    def test_form_structure_is_not_a_credential(self):
        hyps = hypotheses_for_node({
            "key": "info:login-form-structure", "type": "info",
            "title": "登录表单结构:POST /login,字段 username/password,无CSRF",
            "severity": "info", "tags": [],
            "detail": "表单结构 username/password",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertNotIn("info_to_cred", tactics)
        self.assertNotIn("secret_mount", tactics)

    def test_inflight_enum_is_not_a_credential(self):
        hyps = hypotheses_for_node({
            "key": "info:round3-inflight", "type": "info",
            "title": "第3轮参数矩阵/SSRF 枚举进行中",
            "severity": "info", "tags": [],
            "detail": "inflight recon 枚举进行中",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertNotIn("info_to_cred", tactics)
        self.assertNotIn("secret_mount", tactics)

    def test_frontend_no_logic_is_not_a_secret(self):
        hyps = hypotheses_for_node({
            "key": "recon:bundle-js-nature", "type": "info",
            "title": "bundle.js 判定:webpack 打包的 Tailwind/Alpine 模板 UI 层,零业务逻辑",
            "severity": "info", "tags": [],
            "detail": "无业务逻辑 模板 UI",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertNotIn("secret_mount", tactics)
        self.assertNotIn("info_to_cred", tactics)

    def test_comment_leaked_account_still_info_to_cred(self):
        hyps = hypotheses_for_node({
            "key": "info:leak-test-account-comment", "type": "info",
            "title": "登录页 HTML 注释泄露测试账号 test:test",
            "severity": "medium", "tags": [],
            "detail": "HTML 注释泄露测试账号",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("info_to_cred", tactics)

    def test_real_token_credential_still_secret_mount(self):
        hyps = hypotheses_for_node({
            "key": "cred:svc-token", "type": "credential",
            "title": "internal admin_token",
            "severity": "high", "tags": ["token"],
            "detail": "admin_token=internal_example_token",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("secret_mount", tactics)

    def test_password_blob_with_secret_field_stays_auth_reuse(self):
        hyps = hypotheses_for_node({
            "key": "cred:corporate-admins", "type": "credential",
            "title": "corporate_site 管理员账密（admin:example / editor:example）",
            "severity": "high", "tags": ["login"],
            "detail": "admins 表明文口令。site_config.system_secret=already-submitted，api_key=dk_live_example",
        })
        tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
        self.assertIn("auth_reuse", tactics)
        self.assertNotIn("secret_mount", tactics)

    def test_new_hop_auth_unauth_pair_ignores_stack_fingerprint(self):
        """新 hop 的下一事件是身份对偶，不靠 nginx/22/OpenSSH 白名单分流。"""
        for detail in ("", "gunicorn /login", "仅开放 22 OpenSSH", "unknown daemon :9000"):
            hyps = hypotheses_for_node({
                "key": "info:host:172.19.0.2", "type": "info",
                "title": "内网主机 172.19.0.2",
                "severity": "info", "tags": ["scope-expanded"],
                "detail": detail,
            })
            tactics = {(h.strategy_key or "").split("::")[-1] for h in hyps}
            self.assertEqual(tactics, {"hop_auth", "access_control"}, msg=detail)
            ests = {(h.strategy_key or "").split("::")[-1]: h.est_success for h in hyps}
            self.assertEqual(ests["hop_auth"], ests["access_control"], msg=detail)
            blob = " ".join(h.description or "" for h in hyps)
            self.assertNotIn("/api", blob)
            self.assertNotIn("SSH/FTP", blob)
            self.assertNotIn("gunicorn", blob)


class PortableTacticHypothesisTests(unittest.TestCase):
    def test_interactive_service_derives_protocol_model(self):
        hyps = hypotheses_for_node({
            "key": "svc:81/tcp@10.0.0.9", "type": "service",
            "title": "交互服务 10.0.0.9:81",
            "severity": "info", "tags": ["tcp", "interactive"],
            "detail": "banner menu",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("protocol_model", tactics)
        self.assertNotIn("web_inject", tactics)
        self.assertNotIn("content_enum", tactics)
        blob = " ".join(h.description or "" for h in hyps)
        self.assertNotIn("SPN", blob)
        self.assertNotIn("背包", blob)

    def test_http_service_still_web_inject(self):
        hyps = hypotheses_for_node({
            "key": "svc:80/http", "type": "service", "title": "Apache/PHP",
            "severity": "info", "tags": ["http", "php"], "detail": "Apache httpd",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("web_inject", tactics)
        self.assertNotIn("protocol_model", tactics)

    def test_http_tag_without_stack_name_still_web_inject(self):
        hyps = hypotheses_for_node({
            "key": "svc:9000/unknown", "type": "service", "title": "unknown :9000",
            "severity": "info", "tags": ["http"], "detail": "",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("web_inject", tactics)
        self.assertNotIn("protocol_model", tactics)
        self.assertNotIn("svc_auth_bruteforce", tactics)

    def test_http_mentioning_port_22_is_not_ssh_brute(self):
        hyps = hypotheses_for_node({
            "key": "svc:80/http", "type": "service", "title": "web",
            "severity": "info", "tags": ["http"], "detail": "build 22 apache",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertNotIn("svc_auth_bruteforce", tactics)

    def test_redis_is_not_web_enum(self):
        hyps = hypotheses_for_node({
            "key": "svc:6379/redis", "type": "service",
            "title": "Redis(需AUTH) 172.20.0.2:6379",
            "severity": "info", "tags": ["redis", "tcp"],
            "detail": "Redis 需AUTH",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("svc_auth_bruteforce", tactics)
        self.assertIn("protocol_model", tactics)
        self.assertNotIn("content_enum", tactics)
        self.assertNotIn("web_inject", tactics)
        self.assertNotIn("auth_surface", tactics)

    def test_ssh_is_not_web_enum(self):
        hyps = hypotheses_for_node({
            "key": "svc:22/ssh", "type": "service",
            "title": "SSH OpenSSH_9.3",
            "severity": "info", "tags": ["ssh"],
            "detail": "OpenSSH_9.3",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("svc_auth_bruteforce", tactics)
        self.assertNotIn("content_enum", tactics)
        self.assertNotIn("web_inject", tactics)

    def test_filter_danger_derives_filter_bypass(self):
        hyps = hypotheses_for_node({
            "key": "danger:blocked", "type": "danger",
            "title": "入口 403 拦截页",
            "severity": "medium", "tags": ["http"], "detail": "forbidden filter",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("filter_bypass", tactics)

    def test_restricted_deserialize_on_whitelist_surface(self):
        hyps = hypotheses_for_node({
            "key": "danger:deser", "type": "danger",
            "title": "受限 pickle 入口",
            "severity": "high", "tags": ["pickle"],
            "detail": "unserialize allowlist gadget",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("restricted_deserialize", tactics)
        blob = " ".join(h.description or "" for h in hyps)
        self.assertIn("gadget", blob)
        self.assertNotIn("os.system", blob)

    def test_live_http_surface_derives_portable_tactics(self):
        hyps = hypotheses_for_node({
            "key": "svc:80/http@10.0.0.8", "type": "service",
            "title": "HTTP 10.0.0.8:80",
            "severity": "info", "tags": ["http", "graphql"],
            "detail": "入口指纹=http 表面=graphql",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("graphql_contract", tactics)
        blob = " ".join(h.description or "" for h in hyps)
        self.assertIn("契约", blob)
        self.assertNotIn("introspection payload", blob.lower())
        hyps = hypotheses_for_node({
            "key": "svc:80/http@10.0.0.8", "type": "service",
            "title": "HTTP 10.0.0.8:80",
            "severity": "info", "tags": ["http", "soap", "xml"],
            "detail": "wsdl",
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("soap_contract", tactics)
        self.assertIn("xml_parse", tactics)


class LiveSurfaceBiasTests(unittest.TestCase):
    def test_surface_prefer_and_needs_cycle(self):
        from atkbrain.graph.hypothesize import (
            live_surface_needs_cycle, plan_blocks_live_surface, surface_prefer_tactics,
            surfaces_from_graph_nodes,
        )
        self.assertEqual(surface_prefer_tactics(["graphql"]), {"graphql_contract"})
        self.assertTrue(live_surface_needs_cycle(["graphql"]))
        self.assertFalse(live_surface_needs_cycle(
            ["graphql"], resolved_tactics={"graphql_contract"},
        ))
        self.assertFalse(live_surface_needs_cycle([]))
        self.assertTrue(plan_blocks_live_surface(
            "继续 content_enum 扫目录", surfaces=["graphql"],
        ))
        self.assertFalse(plan_blocks_live_surface(
            "继续 content_enum 扫目录", surfaces=[],
        ))
        graph = {
            "nodes": [{
                "key": "svc:80/http", "tags": ["http", "soap"],
                "title": "HTTP", "detail": "",
            }],
        }
        self.assertIn("soap", surfaces_from_graph_nodes(graph))

    def test_object_store_and_sink_prefer_tactics(self):
        from atkbrain.graph.hypothesize import (
            hypotheses_for_node, live_surfaces_from_node, plan_blocks_live_surface,
            surface_defer_tactics, surface_prefer_tactics,
        )
        s3_blob = (
            '<?xml version="1.0"?>'
            '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            "<Name>demo</Name></ListBucketResult>"
        )
        surf = live_surfaces_from_node(s3_blob, {"http"})
        self.assertIn("object_store", surf)
        self.assertNotIn("xml", surf)
        self.assertEqual(surface_prefer_tactics(surf), {"object_write"})
        self.assertEqual(surface_prefer_tactics(["html_sink"]), {"html_sink"})
        self.assertEqual(surface_prefer_tactics(["php_serial"]), {"restricted_deserialize"})
        self.assertEqual(surface_prefer_tactics(["expr_eval"]), {"expr_eval"})
        self.assertEqual(surface_prefer_tactics(["race_window"]), {"race_window"})
        self.assertTrue(plan_blocks_live_surface(
            "继续方法矩阵", surfaces=["object_store"],
        ))
        self.assertIn(
            "filter_bypass",
            surface_defer_tactics(["object_store"], has_verified=True),
        )
        self.assertNotIn(
            "filter_bypass",
            surface_defer_tactics(["object_store"], has_verified=False),
        )
        hyps = hypotheses_for_node({
            "key": "svc:80/http@10.0.0.8", "type": "service",
            "title": "HTTP 10.0.0.8:80",
            "severity": "info", "tags": ["http", "object_store"],
            "detail": s3_blob,
        })
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("object_write", tactics)
        self.assertNotIn("xml_parse", tactics)
        ow = " ".join(
            h.description or "" for h in hyps
            if (h.strategy_key or "").endswith("object_write")
        )
        self.assertIn("键级", ow)
        self.assertNotIn("XXE", ow)
        self.assertNotIn("TRACE", ow)
        cred = hypotheses_for_node({
            "key": "cred:user", "type": "credential",
            "title": "user/pass",
            "severity": "medium", "tags": ["credential", "object_store"],
            "detail": "username=user password=pass",
        })
        cred_tacs = {((h.strategy_key or "").split("::")[-1]) for h in cred}
        self.assertIn("auth_reuse", cred_tacs)
        self.assertIn("object_write", cred_tacs)
        cred_blob = " ".join(h.description or "" for h in cred)
        self.assertNotIn("隐写", cred_blob)
        self.assertNotIn("169.254", cred_blob)

    def test_chain_next_includes_surface_tactics(self):
        from atkbrain.engine.supervise import CHAIN_NEXT
        self.assertIn("graphql_contract", CHAIN_NEXT)
        self.assertIn("upload_bypass", CHAIN_NEXT)
        self.assertIn("object_write", CHAIN_NEXT)
        self.assertIn("html_sink", CHAIN_NEXT)
        self.assertIn("expr_eval", CHAIN_NEXT)
        self.assertIn("race_window", CHAIN_NEXT)

    def test_chain_next_tactics_drops_sidetrack_after_verified_sqli(self):
        from atkbrain.engine.supervise import CHAIN_NEXT, chain_next_tactics
        nxt = chain_next_tactics({"sqli"})
        self.assertIn("finding_sqli_chain", nxt)
        self.assertIn("weaponize", nxt)
        self.assertNotIn("channel_oracle", nxt)
        self.assertNotIn("api_contract", nxt)
        self.assertNotIn("fingerprint", nxt)
        self.assertNotIn("file_read_chain", nxt)
        self.assertIn("channel_oracle", CHAIN_NEXT)

    def test_chain_next_tactics_drops_filter_bypass_after_verified_ssrf(self):
        from atkbrain.engine.supervise import chain_next_tactics
        nxt = chain_next_tactics({"ssrf"})
        self.assertIn("ssrf_as_gateway", nxt)
        self.assertNotIn("filter_bypass", nxt)
        self.assertNotIn("file_read_chain", nxt)
        self.assertNotIn("access_control", nxt)

    def test_verified_finding_categories_from_sqli_node(self):
        from atkbrain.engine.supervise import verified_finding_categories
        cats = verified_finding_categories({
            "nodes": [{
                "type": "vuln", "key": "vuln:login-sqli", "title": "login sqli",
                "tags": ["verified", "sqli"],
            }],
            "findings": [{
                "category": "sqli", "verification_status": "verified", "title": "time blind",
            }],
        })
        self.assertIn("sqli", cats)

    def test_verified_finding_categories_token_from_detail(self):
        from atkbrain.engine.supervise import verified_finding_categories
        cats = verified_finding_categories({
            "nodes": [{
                "type": "vuln", "key": "vuln:role", "title": "role bypass",
                "tags": ["verified", "auth_bypass"],
                "detail": "JWT HS256 signed session",
            }],
            "findings": [],
        })
        self.assertIn("token", cats)
        self.assertIn("auth_bypass", cats)

    def test_http_binary_brief_derives_reverse_not_web_enum(self):
        hyps = hypotheses_for_node({
            "key": "svc:9105/http", "type": "service", "title": "HTTP :9105",
            "severity": "info", "tags": ["http"], "detail": "octet-stream download",
        }, brief="请分析该可执行文件，理解内部执行机制并取得凭据。")
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("reverse_binary", tactics)
        self.assertIn("protocol_model", tactics)
        self.assertNotIn("content_enum", tactics)
        self.assertNotIn("web_inject", tactics)
        self.assertNotIn("auth_surface", tactics)

    def test_plain_http_without_binary_brief_stays_web(self):
        hyps = hypotheses_for_node({
            "key": "svc:80/http", "type": "service", "title": "web",
            "severity": "info", "tags": ["http"], "detail": "login form",
        }, brief="评估该资产管理系统的安全性。")
        tactics = {((h.strategy_key or "").split("::")[-1]) for h in hyps}
        self.assertIn("web_inject", tactics)
        self.assertNotIn("reverse_binary", tactics)

    def test_weaponize_prefer_and_enum_sidetrack_on_verified_ssrf(self):
        from atkbrain.graph.hypothesize import (
            enum_sidetrack_when_weaponizable, live_gadget_tactics,
            weaponize_prefer_tactics,
        )
        graph = {
            "nodes": [{
                "type": "vuln", "key": "vuln:proxy", "title": "open proxy",
                "tags": ["verified", "ssrf"], "detail": "unauth proxy",
            }],
            "findings": [{
                "category": "ssrf", "verification_status": "verified",
                "severity": "high", "title": "proxy ssrf",
            }],
        }
        self.assertIn("ssrf_as_gateway", live_gadget_tactics(graph))
        prefer = weaponize_prefer_tactics(graph)
        self.assertIn("ssrf_as_gateway", prefer)
        self.assertEqual(
            enum_sidetrack_when_weaponizable(graph),
            frozenset({"content_enum", "fingerprint"}),
        )

    def test_stale_web_enum_on_binary_http(self):
        from atkbrain.graph.hypothesize import stale_tactics_for_node
        stale = stale_tactics_for_node({
            "key": "svc:9105/http", "type": "service", "title": "HTTP",
            "tags": ["http"], "detail": "",
        }, brief="分析可执行文件")
        self.assertIn("content_enum", stale)
        self.assertIn("web_inject", stale)


if __name__ == "__main__":
    unittest.main()
