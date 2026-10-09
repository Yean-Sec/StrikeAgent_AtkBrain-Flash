"""猎面加速：复核不挡御主、Pi 保活、无图变化跳过、热路径 TTL。"""
from __future__ import annotations

import inspect
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OverlapReviewTests(unittest.TestCase):
    def test_run_turn_does_not_await_review_or_pages(self) -> None:
        from ..agents.session import ProjectAgent

        src = inspect.getsource(ProjectAgent.run_turn)
        self.assertIn("_kick_review", src)
        self.assertNotIn("await self._run_finding_review", src)
        self.assertNotIn("fill_missing_pi_pages", src)

    def test_begin_fresh_keeps_review_pi(self) -> None:
        from ..agents.session import ProjectAgent

        src = inspect.getsource(ProjectAgent.begin_fresh_session)
        self.assertIn("_abort_hunt_prompts", src)
        self.assertNotIn("_close_sessions", src)

    def test_timeout_interrupt_does_not_halt_review(self) -> None:
        from ..agents.session import ProjectAgent

        src = inspect.getsource(ProjectAgent.run_turn)
        self.assertIn("interrupt(halt=False)", src)

    def test_turn_guard_does_not_halt_review(self) -> None:
        from ..engine.loop import _run_turn_guarded

        src = inspect.getsource(_run_turn_guarded)
        self.assertIn("interrupt(halt=False)", src)

    def test_halt_still_closes_review(self) -> None:
        from ..agents.session import ProjectAgent

        close_src = inspect.getsource(ProjectAgent.close)
        halt_src = inspect.getsource(ProjectAgent.interrupt)
        self.assertIn("keep_review=False", close_src)
        self.assertIn("halt: bool = True", halt_src)
        self.assertIn("_stop_background", halt_src)


class LessDuplicateSpawnTests(unittest.TestCase):
    def test_pi_pool_reuses_alive_process(self) -> None:
        from ..agents.session import ProjectAgent

        src = inspect.getsource(ProjectAgent._acquire_pi)
        self.assertIn("_pi_pool", src)
        self.assertIn("sess.alive()", src)
        head, _, _ = inspect.getsource(ProjectAgent._run_one).partition("except")
        self.assertNotIn("await sess.close()", head)

    def test_no_session_and_role_env(self) -> None:
        text = (ROOT / "agents" / "pi_runtime.py").read_text(encoding="utf-8")
        self.assertIn("--no-session", text)
        self.assertIn("ATKBRAIN_PI_ROLE", text)
        self.assertIn("def alive(", text)

    def test_lead_http_blocked(self) -> None:
        mcp = (ROOT / "agents" / "mcp_http.py").read_text(encoding="utf-8")
        self.assertIn('role == "lead"', mcp)
        self.assertIn("http_request", mcp)
        self.assertIn("x-atkbrain-role", mcp)
        ext = (ROOT.parent.parent / "pi" / "extensions" / "atkbrain-tools.ts").read_text(encoding="utf-8")
        self.assertIn("x-atkbrain-role", ext)
        dsh = (ROOT / "dsh" / "atkbrain-tools.js").read_text(encoding="utf-8")
        self.assertIn("x-atkbrain-role", dsh)

    def test_lead_prompt_forbids_http_request(self) -> None:
        text = (ROOT / "agents" / "prompts.py").read_text(encoding="utf-8")
        self.assertIn("不要自己 http_request 打目标，打洞交给工人。", text)


class AdvisorSkipSlimPromptTests(unittest.TestCase):
    def test_no_graph_change_skip_path(self) -> None:
        text = (ROOT / "engine" / "supervise.py").read_text(encoding="utf-8")
        self.assertIn('"no_graph_change"', text)
        self.assertIn('(quality or "none") == "none"', text)

    def test_worker_goal_omits_full_policy_briefs(self) -> None:
        from ..agents.prompts import _GOAL_BLOCKS
        from ..objective import BUSINESS_SAFE_WRITE_BRIEF, SRC_POLICY_BRIEF

        for key in ("redteam", "src"):
            block = _GOAL_BLOCKS[key]
            self.assertIn("平台硬拦", block)
            self.assertNotIn(SRC_POLICY_BRIEF[:32], block)
            self.assertNotIn(BUSINESS_SAFE_WRITE_BRIEF[:32], block)
            self.assertLess(len(block), 500)


class HotpathTtlTests(unittest.IsolatedAsyncioTestCase):
    def test_timeouts_and_ttls(self) -> None:
        from ..agents.context import _HTTP_TIMEOUT
        from ..graph.store import _GRAPH_TTL_SEC, _INTENT_TTL_SEC

        self.assertEqual(float(_HTTP_TIMEOUT.connect), 5.0)
        self.assertEqual(float(_HTTP_TIMEOUT.read), 12.0)
        self.assertLessEqual(_GRAPH_TTL_SEC, 4.0)
        self.assertEqual(_INTENT_TTL_SEC, 20.0)

    async def test_intent_refresh_ttl_skips(self) -> None:
        from ..graph import store as gstore

        pid = "p_speed_ttl"
        gstore._INTENT_AT[pid] = time.monotonic()
        out = await gstore.refresh_derived_intents(pid)
        self.assertTrue(out.get("skipped"))
        gstore._INTENT_AT.pop(pid, None)

    async def test_get_graph_short_ttl_cache(self) -> None:
        from ..graph import store as gstore

        pid = "p_speed_graph"
        payload = {"cached": True, "stats": {}}
        gstore._GRAPH_CACHE[pid] = (time.monotonic(), payload)
        out = await gstore.get_graph(pid)
        self.assertIs(out, payload)
        gstore.invalidate_graph_cache(pid)
        self.assertNotIn(pid, gstore._GRAPH_CACHE)


if __name__ == "__main__":
    unittest.main()
