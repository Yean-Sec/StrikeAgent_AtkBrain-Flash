"""Pi 进程闸：fanout 截断、cmdline 识别、health 数字不再写死 0。"""
from __future__ import annotations

import inspect
import unittest

from atkbrain_native import (
    cap_hunt_workers,
    hunt_manager,
    is_backend_cmd,
    is_protected_cmd,
    pi_max_live_limit,
    pi_per_project_limit,
)


class CapHelpersTests(unittest.TestCase):
    def test_defaults_are_capped(self) -> None:
        self.assertEqual(pi_per_project_limit(), 4)
        self.assertEqual(pi_max_live_limit(), 32)

    def test_cap_hunt_workers_reserves_lead(self) -> None:
        roles = ["web-exploit", "recon", "rce-hunt", "privesc", "lateral"]
        self.assertEqual(cap_hunt_workers(roles, per_project=4), ["web-exploit", "recon", "rce-hunt"])
        self.assertEqual(cap_hunt_workers(roles, per_project=1), [])
        self.assertEqual(cap_hunt_workers(roles, per_project=2), ["web-exploit"])

    def test_cap_drops_review_and_oneshot(self) -> None:
        roles = ["finding-review", "supervisor", "web-exploit", "recon"]
        self.assertEqual(cap_hunt_workers(roles, per_project=4), ["web-exploit", "recon"])

    def test_backend_and_proxy_are_protected(self) -> None:
        self.assertTrue(is_backend_cmd(b"python3\0-m\0atkbrain.main"))
        self.assertTrue(is_protected_cmd(b"caddy\0run"))
        self.assertFalse(is_protected_cmd(b"dsh\0--profile\0sdk"))


class FanoutAndPoolTests(unittest.TestCase):
    def _engine(self) -> str:
        from pathlib import Path
        return (Path(__file__).resolve().parents[3] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")

    def test_fanout_calls_cap(self) -> None:
        self.assertIn("fn acquire", self._engine())

    def test_acquire_uses_role_lock(self) -> None:
        text = self._engine()
        self.assertIn("fn role_lock", text)
        self.assertIn("fn acquire", text)

    def test_recover_kills_orphans(self) -> None:
        self.assertIn("kill_live_for_project", self._engine())

    def test_idle_reap_keeps_lead(self) -> None:
        self.assertIn("is_review_role", self._engine())

    def test_close_does_not_untrack_before_death(self) -> None:
        from pathlib import Path

        text = (Path(__file__).resolve().parents[3] / "rust" / "atkbrain-core" / "src" / "pi.rs").read_text(encoding="utf-8")
        close = text.split("pub fn close", 1)[1].split("pub fn query_text", 1)[0]
        self.assertIn("untrack_dead", close)
        self.assertLess(close.find("pid_alive"), close.find("untrack_dead"))

    def test_set_claude_per_project_sticks(self) -> None:
        mgr = hunt_manager
        self.addCleanup(lambda: mgr.set_claude_per_project(4))
        n = mgr.set_claude_per_project(6)
        self.assertEqual(n, 6)
        self.assertEqual(mgr.snapshot()["claude"]["per_project"], 6)
        self.assertEqual(mgr.set_claude_per_project(99), 8)


class SnapshotTests(unittest.TestCase):
    def test_health_claude_limits_nonzero(self) -> None:
        mgr = hunt_manager
        snap = mgr.snapshot()
        self.assertEqual(snap["claude"]["limit"], 32)
        self.assertGreater(snap["claude"]["cap"], 0)
        self.assertGreaterEqual(snap["claude"]["per_project"], 1)


class HaltTests(unittest.TestCase):
    def test_halt_unknown_project(self) -> None:
        self.assertTrue(hunt_manager.halt("missing-hunt-project", reason="user_stop"))


class PiLaunchTests(unittest.TestCase):
    def test_launch_uses_pi_rpc(self) -> None:
        import tempfile
        from atkbrain_native import PiSession
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        s = PiSession(cwd=td.name, system_prompt="x", tools=True, role="lead")
        cmd = s.command_line()
        self.assertIn("--mode", cmd)
        self.assertIn("rpc", cmd)
        self.assertIn("--no-session", cmd)
        self.assertIn("--no-skills", cmd)
        self.assertIn("--no-builtin-tools", cmd)
        self.assertNotIn("--skill", cmd)
        joined = " ".join(cmd)
        self.assertNotIn("deepseek_harness", joined)

    def test_tools_base_includes_entry(self) -> None:
        from unittest.mock import patch
        from atkbrain_native import tools_base_url
        with patch("atkbrain.auth.entry.entry_prefix", return_value="/AbCdef12"):
            url = tools_base_url()
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        self.assertTrue(url.endswith("/AbCdef12"))


class OneshotSettleTests(unittest.IsolatedAsyncioTestCase):
    async def test_user_message_does_not_settle_oneshot(self) -> None:
        from atkbrain_native import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        s.on_event({"type": "message_end", "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]}})
        self.assertFalse(s.is_settled())

    async def test_assistant_message_settles_oneshot(self) -> None:
        from atkbrain_native import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        s.on_event({
            "type": "message_end",
            "message": {"role": "assistant", "content": [{"type": "text", "text": '{"diagnosis":"ok"}'}]},
        })
        self.assertTrue(s.is_settled())
        self.assertIn('{"diagnosis":"ok"}', "".join(s.texts))

    async def test_interrupted_assistant_does_not_settle(self) -> None:
        from atkbrain_native import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        s.on_event({
            "type": "message_end",
            "message": {"role": "assistant", "stopReason": "aborted", "content": []},
        })
        self.assertFalse(s.is_settled())

    async def test_assistant_message_does_not_settle_tools_session(self) -> None:
        from atkbrain_native import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=True, role="lead")
        s.on_event({
            "type": "message_end",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "still working"}]},
        })
        self.assertFalse(s.is_settled())
        s.on_event({"type": "agent_settled"})
        self.assertTrue(s.is_settled())


class GrindCorrectionTests(unittest.TestCase):
    def test_http_agent_keeps_src_hunt_ahead_of_rce(self) -> None:
        from atkbrain_native import ensure_live_page_reader
        roles = ensure_live_page_reader(
            ["web-exploit", "rce-hunt", "recon", "src-hunt"], "agent", http=True, keep_rce=True,
        )
        self.assertEqual(roles[:3], ["web-exploit", "rce-hunt", "recon"])
        self.assertEqual(cap_hunt_workers(roles, per_project=4), ["web-exploit", "rce-hunt", "recon"])

    def test_disproven_chain_binding_reopens(self) -> None:
        from atkbrain_native import AdvisorBinding, should_refresh_stale_binding
        stuck = AdvisorBinding(
            stall="chain", misses=3,
            ban_repeats=["/login.action?debug=command 已否证"],
        )
        self.assertTrue(should_refresh_stale_binding(stuck, misses_limit=3))
        fresh = AdvisorBinding(stall="chain", misses=3, ban_repeats=["换观测通道"])
        self.assertFalse(should_refresh_stale_binding(fresh, misses_limit=3))

    def test_stack_trace_path_is_not_a_file_surface(self) -> None:
        from atkbrain_native import looks_like_file_delivery
        stack = "java.nio.file.Path at org.apache.struts2.dispatcher.ServletActionContext"
        self.assertFalse(looks_like_file_delivery(stack, "/login.action 500"))
        self.assertTrue(looks_like_file_delivery("fileName localfile", "gif 入口"))

    def test_homepage_wildcard_keeps_path_enum(self) -> None:
        from types import SimpleNamespace
        from atkbrain_native import compile_binding
        plan = SimpleNamespace(
            next_plan="", diagnosis="", prefer_tactics=[], defer_families=["content_enum"],
            ban_repeats=[], must_intents=[], subagents=["web-exploit", "recon"],
        )
        graph = {"nodes": [{
            "type": "info", "key": "info:wild",
            "title": "通配映射假阳性",
            "detail": "未知 action 返回首页 85317B",
        }]}
        binding = compile_binding(
            plan, has_verified_asset=True, has_http_service=True, graph=graph,
        )
        self.assertNotIn("content_enum", binding.deny_tactics)
        closed = {"nodes": graph["nodes"] + [{
            "type": "info", "key": "info:file",
            "title": "文件下载", "detail": "filename 参数",
        }]}
        binding2 = compile_binding(
            plan, has_verified_asset=True, has_http_service=True, graph=closed,
        )
        self.assertIn("content_enum", binding2.deny_tactics)

    def test_frontend_list_and_static_traversal_do_not_finish_enum(self) -> None:
        from types import SimpleNamespace
        from atkbrain_native import compile_binding
        from atkbrain_native import action_surface_incomplete
        graph = {"nodes": [
            {"type": "info", "key": "info:inventory",
             "title": "仅 8 个 .action 被前端引用",
             "detail": "端点全集来自 JS。继续目录枚举收益低，映射面很窄。"},
            {"type": "info", "key": "info:lfi-neg",
             "title": "读文件面全否证",
             "detail": "静态目录穿越失败，文件面封死。"},
            {"type": "info", "key": "info:ognl-file",
             "title": "S2-046 的 filename 位置",
             "detail": "multipart 字段名不是文件参数入口，否证。"},
        ]}
        self.assertTrue(action_surface_incomplete(graph))
        plan = SimpleNamespace(
            next_plan="", diagnosis="", prefer_tactics=[], defer_families=["content_enum"],
            ban_repeats=[], must_intents=[], subagents=["web-exploit", "recon"],
        )
        binding = compile_binding(
            plan, has_verified_asset=True, has_http_service=True, graph=graph,
        )
        self.assertNotIn("content_enum", binding.deny_tactics)
        self.assertTrue(binding.keep_path_enum)
        done = {"nodes": graph["nodes"] + [
            {"type": "info", "key": "info:path-enum-pass", "title": "路径对比已完成", "detail": "程序已请求"},
            {"type": "info", "key": "info:file-param-pass", "title": "文件参数对比已完成", "detail": "程序已请求"},
        ]}
        self.assertFalse(action_surface_incomplete(done))
        only_paths = {"nodes": graph["nodes"] + [
            {"type": "info", "key": "info:path-enum-pass", "title": "路径对比已完成", "detail": "还没有文件参数对比"},
        ]}
        self.assertTrue(action_surface_incomplete(only_paths))
        prose = {"nodes": graph["nodes"] + [{
            "type": "info", "key": "info:said-done",
            "title": "词表结果",
            "detail": "差异路径已入库",
        }]}
        self.assertTrue(action_surface_incomplete(prose))

    def test_other_host_and_other_param_names_use_the_same_rule(self) -> None:
        from types import SimpleNamespace
        from atkbrain_native import compile_binding
        from atkbrain_native import action_surface_incomplete
        graph = {"nodes": [
            {"type": "service", "key": "svc:app", "title": "app.example:443",
             "detail": "HTTPS 登录页，页面上只有 /login.php 和 /home.php。"},
            {"type": "info", "key": "info:crawl",
             "title": "crawled pages only",
             "detail": "JS 里看到的路由先记下。没有再列未出现的路径。"},
        ]}
        self.assertTrue(action_surface_incomplete(graph, http=True))
        plan = SimpleNamespace(
            next_plan="", diagnosis="", prefer_tactics=[], defer_families=["content_enum"],
            ban_repeats=[], must_intents=[], subagents=["web-exploit", "recon"],
        )
        binding = compile_binding(
            plan, has_verified_asset=True, has_http_service=True, graph=graph,
        )
        self.assertNotIn("content_enum", binding.deny_tactics)
        self.assertTrue(binding.keep_path_enum)
        self.assertIn("内容页", binding.situation)
        named = {"nodes": graph["nodes"] + [{
            "type": "endpoint", "key": "ep:doc",
            "title": "/export.php", "detail": "download 参数接收服务端路径",
        }]}
        self.assertFalse(action_surface_incomplete(named, http=True))
        prose = {"nodes": graph["nodes"] + [{
            "type": "info", "key": "info:not-yet",
            "title": "穿越被拒",
            "detail": "尚未测下载/上传接口",
        }]}
        self.assertTrue(action_surface_incomplete(prose, http=True))
        listed = {"nodes": graph["nodes"] + [
            {"type": "info", "key": "info:path-enum-pass", "title": "路径对比已完成", "detail": "和首页不同的路径已入库"},
            {"type": "info", "key": "info:file-param-pass", "title": "文件参数对比已完成", "detail": "文件参数已对比"},
        ]}
        self.assertFalse(action_surface_incomplete(listed, http=True))
        mention = {"nodes": graph["nodes"] + [{
            "type": "service", "key": "svc:tool",
            "title": "入口", "detail": "准备用 ffuf，还没有结果",
        }]}
        self.assertTrue(action_surface_incomplete(mention, http=True))

    def test_narrow_route_reuses_a_form_already_seen_on_a_sibling(self) -> None:
        from types import SimpleNamespace
        from atkbrain_native import compile_binding
        from atkbrain_native import hypotheses_for_node, request_form_gaps
        graph = {"nodes": [
            {"type": "danger", "key": "http://example.test/alpha.action",
             "title": "/alpha.action 500", "detail": "空指针"},
            {"type": "danger", "key": "http://example.test/beta.action",
             "title": "/beta.action 500", "detail": "堆栈"},
            {"type": "info", "key": "http://example.test/beta!run.action",
             "title": "/beta!run.action 200", "detail": "和首页不同"},
            {"type": "info", "key": "info:wild", "title": "通配回首页",
             "detail": "/gamma.action 不是真实动作"},
            {"type": "danger", "key": "http://example.test/gamma.action",
             "title": "/gamma.action 500", "detail": "堆栈"},
        ]}
        gaps = request_form_gaps(graph)
        stems = [gap["stem"] for gap in gaps]
        self.assertIn("alpha", stems)
        self.assertNotIn("beta", stems)
        self.assertNotIn("gamma", stems)
        hyps = hypotheses_for_node(graph["nodes"][0], allows_flag=False, objective="agent", graph=graph)
        text = " ".join(item.description for item in hyps)
        self.assertIn("alpha", text)
        self.assertIn("beta", text)
        self.assertNotIn("alpha!run", text)
        self.assertNotIn("!", text)
        plan = SimpleNamespace(
            next_plan="", diagnosis="", prefer_tactics=[], defer_families=[],
            ban_repeats=[], must_intents=[], subagents=["web-exploit", "recon"],
        )
        binding = compile_binding(plan, has_http_service=True, graph=graph)
        self.assertIn("alpha", binding.situation)
        self.assertNotIn("!", binding.situation)


if __name__ == "__main__":
    unittest.main()
