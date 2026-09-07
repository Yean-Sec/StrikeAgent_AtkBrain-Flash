"""TSecBench 网关改写与托管自动开打。"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from atkbrain.llm_gateway import (
    apply_llm_gateway,
    apply_platform_env_aliases,
    gateway_enabled,
    hosted_enabled,
    rewrite_llm_url_for_gateway,
)


class RewriteUrlTests(unittest.TestCase):
    def test_deepseek_example(self):
        self.assertEqual(
            rewrite_llm_url_for_gateway("https://api.deepseek.com/v1"),
            "http://api.deepseek.com.tsecbench.gw/v1",
        )

    def test_deepseek_anthropic_compat(self):
        self.assertEqual(
            rewrite_llm_url_for_gateway("https://api.deepseek.com/anthropic"),
            "http://api.deepseek.com.tsecbench.gw/anthropic",
        )

    def test_kimi_example(self):
        self.assertEqual(
            rewrite_llm_url_for_gateway("https://api.moonshot.cn/v1"),
            "http://api.moonshot.cn.tsecbench.gw/v1",
        )

    def test_https_to_http_keeps_path_query(self):
        self.assertEqual(
            rewrite_llm_url_for_gateway(
                "https://dashscope.aliyuncs.com/compatible-mode/v1?foo=1"
            ),
            "http://dashscope.aliyuncs.com.tsecbench.gw/compatible-mode/v1?foo=1",
        )

    def test_maas_wildcard(self):
        self.assertEqual(
            rewrite_llm_url_for_gateway(
                "https://foo.maas.aliyuncs.com/compatible-mode/v1"
            ),
            "http://foo.maas.aliyuncs.com.tsecbench.gw/compatible-mode/v1",
        )

    def test_idempotent_and_forces_http(self):
        gw = "http://api.deepseek.com.tsecbench.gw/anthropic"
        self.assertEqual(rewrite_llm_url_for_gateway(gw), gw)
        self.assertEqual(
            rewrite_llm_url_for_gateway("https://api.deepseek.com.tsecbench.gw/anthropic"),
            gw,
        )

    def test_non_whitelist_untouched(self):
        url = "https://tsecbench.zc.tencent.com/openapi/v1"
        self.assertEqual(rewrite_llm_url_for_gateway(url), url)

    def test_empty(self):
        self.assertEqual(rewrite_llm_url_for_gateway(""), "")


class ApplyGatewayEnvTests(unittest.TestCase):
    def test_rewrites_anthropic_skips_benchmark(self):
        env = {
            "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
            "BENCHMARK_BASE_URL": "https://tsecbench.zc.tencent.com",
            "ATKBRAIN_BENCHMARK_BASE_URL": "https://tsecbench.zc.tencent.com",
            "OPENAI_API_BASE": "https://api.moonshot.cn/v1",
        }
        changed = apply_llm_gateway(env)
        self.assertIn("ANTHROPIC_BASE_URL", changed)
        self.assertEqual(
            env["ANTHROPIC_BASE_URL"],
            "http://api.deepseek.com.tsecbench.gw/anthropic",
        )
        self.assertEqual(env["BENCHMARK_BASE_URL"], "https://tsecbench.zc.tencent.com")
        self.assertEqual(
            env["ATKBRAIN_BENCHMARK_BASE_URL"], "https://tsecbench.zc.tencent.com"
        )
        self.assertEqual(
            env["OPENAI_API_BASE"], "http://api.moonshot.cn.tsecbench.gw/v1"
        )


class AliasTests(unittest.TestCase):
    def test_benchmark_unprefixed(self):
        env = {
            "BENCHMARK_BASE_URL": "https://bm.example",
            "BENCHMARK_TOKEN": "tok-1",
        }
        mapped = apply_platform_env_aliases(env)
        self.assertEqual(env["ATKBRAIN_BENCHMARK_BASE_URL"], "https://bm.example")
        self.assertEqual(env["ATKBRAIN_BENCHMARK_TOKEN"], "tok-1")
        self.assertEqual(mapped["ATKBRAIN_BENCHMARK_BASE_URL"], "BENCHMARK_BASE_URL")

    def test_does_not_override_existing(self):
        env = {
            "BENCHMARK_TOKEN": "platform",
            "ATKBRAIN_BENCHMARK_TOKEN": "already",
        }
        apply_platform_env_aliases(env)
        self.assertEqual(env["ATKBRAIN_BENCHMARK_TOKEN"], "already")

    def test_focus_codes_alias(self):
        env = {"FOCUS_CODES": "web-2,web-10"}
        mapped = apply_platform_env_aliases(env)
        self.assertEqual(env["ATKBRAIN_BENCHMARK_FOCUS_CODES"], "web-2,web-10")
        self.assertEqual(mapped["ATKBRAIN_BENCHMARK_FOCUS_CODES"], "FOCUS_CODES")

    def test_deepseek_key_alias(self):
        env = {"DEEPSEEK_API_KEY": "sk-x"}
        apply_platform_env_aliases(env)
        self.assertEqual(env["ANTHROPIC_AUTH_TOKEN"], "sk-x")


class FlagTests(unittest.TestCase):
    def test_hosted_and_gateway_flags(self):
        self.assertTrue(hosted_enabled({"ATKBRAIN_HOSTED": "1"}))
        self.assertFalse(hosted_enabled({"ATKBRAIN_HOSTED": "0"}))
        self.assertTrue(gateway_enabled({"ATKBRAIN_LLM_GATEWAY": "true"}))
        self.assertTrue(gateway_enabled({"ATKBRAIN_HOSTED": "yes"}))
        self.assertFalse(gateway_enabled({}))


class HostedBootstrapTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from atkbrain.db import Database, now
        import atkbrain.db as db_mod
        import atkbrain.projects as projects
        import atkbrain.hosted as hosted

        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        self._old_db = db_mod.db
        self._old_proj_db = projects.db
        db_mod.db = self.db
        projects.db = self.db
        self.hosted = hosted
        self.db_mod = db_mod
        self.projects = projects
        self.now = now
        self._os = os

    async def asyncTearDown(self):
        self.db_mod.db = self._old_db
        self.projects.db = self._old_proj_db
        await self.db.close()
        self._os.unlink(self.tmp.name)

    async def test_noop_when_not_hosted(self):
        with patch.object(self.hosted, "hosted_enabled", return_value=False):
            got = await self.hosted.ensure_hosted_benchmark()
        self.assertIsNone(got)
        rows = await self.db.fetchall("SELECT id FROM projects")
        self.assertEqual(rows, [])

    async def test_creates_benchmark_parent(self):
        from atkbrain.config import settings

        with patch.object(self.hosted, "hosted_enabled", return_value=True), \
             patch.object(settings, "benchmark_base_url", "http://bm.example"), \
             patch.object(settings, "benchmark_token", "tok-hosted"):
            got = await self.hosted.ensure_hosted_benchmark()
        self.assertIsNotNone(got)
        self.assertEqual(got["kind"], "benchmark")
        self.assertTrue((got.get("config") or {}).get("autopilot"))
        self.assertEqual((got.get("config") or {}).get("benchmark", {}).get("base_url"), "http://bm.example")

        with patch.object(self.hosted, "hosted_enabled", return_value=True), \
             patch.object(settings, "benchmark_base_url", "http://bm.example"), \
             patch.object(settings, "benchmark_token", "tok-hosted"):
            again = await self.hosted.ensure_hosted_benchmark()
        self.assertIsNone(again)
        rows = await self.db.fetchall("SELECT id FROM projects WHERE kind='benchmark'")
        self.assertEqual(len(rows), 1)

    async def test_creates_parent_with_focus_codes(self):
        from atkbrain.config import settings

        with patch.object(self.hosted, "hosted_enabled", return_value=True), \
             patch.object(settings, "benchmark_base_url", "http://bm.example"), \
             patch.object(settings, "benchmark_token", "tok-hosted"), \
             patch.object(settings, "benchmark_focus_codes", "web-2, web-10"):
            got = await self.hosted.ensure_hosted_benchmark()
        self.assertEqual((got.get("config") or {}).get("focus_codes"), ["web-2", "web-10"])

    async def test_reuse_writes_focus_codes(self):
        from atkbrain.config import settings

        with patch.object(self.hosted, "hosted_enabled", return_value=True), \
             patch.object(settings, "benchmark_base_url", "http://bm.example"), \
             patch.object(settings, "benchmark_token", "tok-hosted"), \
             patch.object(settings, "benchmark_focus_codes", ""):
            first = await self.hosted.ensure_hosted_benchmark()
        self.assertFalse((first.get("config") or {}).get("focus_codes"))

        with patch.object(self.hosted, "hosted_enabled", return_value=True), \
             patch.object(settings, "benchmark_base_url", "http://bm.example"), \
             patch.object(settings, "benchmark_token", "tok-hosted"), \
             patch.object(settings, "benchmark_focus_codes", "web-2"):
            again = await self.hosted.ensure_hosted_benchmark()
        self.assertIsNone(again)
        row = await self.db.fetchone("SELECT config FROM projects WHERE id=?", (first["id"],))
        import json
        cfg = json.loads(row["config"]) if isinstance(row["config"], str) else row["config"]
        self.assertEqual(cfg.get("focus_codes"), ["web-2"])


class AutopilotImportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from atkbrain.db import Database, now
        import atkbrain.db as db_mod
        import atkbrain.benchmark as bmk
        import atkbrain.projects as projects
        import atkbrain.engine.scheduler as sched

        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        self._old_db = db_mod.db
        self._old_bmk_db = bmk.db
        self._old_proj_db = projects.db
        self._old_mgr = sched.manager
        db_mod.db = self.db
        bmk.db = self.db
        projects.db = self.db
        self.bmk = bmk
        self.sched = sched
        self.db_mod = db_mod
        self.projects = projects
        self._os = os
        ts = now()
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("parent", "TSec", "benchmark", "", "[]", "{}",
             '{"autopilot": true}', "idle", ts, ts),
        )

        class FakeMgr:
            def is_running(self, pid):
                return False

            def is_queued(self, pid):
                return False

            def get(self, pid):
                return None

            def start(self, pid):
                self.started = getattr(self, "started", [])
                self.started.append(pid)

        self.mgr = FakeMgr()
        sched.manager = self.mgr

    async def asyncTearDown(self):
        self.db_mod.db = self._old_db
        self.bmk.db = self._old_bmk_db
        self.projects.db = self._old_proj_db
        self.sched.manager = self._old_mgr
        await self.db.close()
        self._os.unlink(self.tmp.name)

    async def test_empty_parent_imports_then_starts(self):
        async def fake_import(pid):
            ts = self.bmk.__dict__.get("_")  # noqa: unused
            from atkbrain.db import now
            t = now()
            await self.db.execute(
                "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,parent_id,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                ("child1", "web-1", "single", "", "[]", "{}",
                 '{"benchmark":{"unique_code":"web-1"},"flag_count":1}',
                 "idle", "parent", t, t),
            )
            return {"total": 1, "created": 1}

        with patch.object(self.bmk, "import_challenges", fake_import), \
             patch.object(self.bmk, "reconcile_orphan_containers", return_value={"closed": 0}), \
             patch.object(self.bmk, "_completed_sub_ids", return_value=set()), \
             patch.object(self.bmk, "_flag_progress_map", return_value={}):
            got = await self.bmk.autopilot_tick("parent")
        self.assertEqual(got.get("started"), 1)
        self.assertEqual(got.get("picked"), ["web-1"])


if __name__ == "__main__":
    unittest.main()
