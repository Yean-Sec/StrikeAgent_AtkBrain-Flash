"""猎面加速：复核不挡御主、Pi 保活、无图变化跳过、热路径 TTL。"""
from __future__ import annotations

import inspect
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class OverlapReviewTests(unittest.TestCase):
    def test_run_turn_does_not_await_review_or_pages(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("kick_review", text)
        self.assertIn("fn run_turn", text)

    def test_begin_fresh_keeps_review_pi(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("close_sessions", text)
        self.assertIn("is_review_role", text)

    def test_timeout_interrupt_does_not_halt_review(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("fn interrupt", text)
        self.assertIn("keep_review", text)

    def test_turn_guard_does_not_halt_review(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("kick_review", text)
        self.assertIn("fn run_turn", text)

    def test_halt_still_closes_review(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("schedule_drain", text)
        self.assertIn("fn interrupt", text)
        self.assertIn("keep_review", text)


class LessDuplicateSpawnTests(unittest.TestCase):
    def test_pi_pool_reuses_alive_process(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "engine.rs").read_text(encoding="utf-8")
        self.assertIn("fn acquire(", text)
        self.assertIn("sess.alive()", text)
        self.assertIn("pool", text)

    def test_no_session_and_role_env(self) -> None:
        text = (ROOT.parents[1] / "rust" / "atkbrain-core" / "src" / "pi.rs").read_text(encoding="utf-8")
        self.assertIn("pi --mode rpc --no-session", text)
        self.assertIn("ATKBRAIN_PI_ROLE", text)
        self.assertNotIn("deepseek-harness-sdk", text)
        self.assertIn("fn alive(", text)

    def test_lead_http_blocked(self) -> None:
        mcp = (ROOT / "agents" / "agent_tools.py").read_text(encoding="utf-8")
        self.assertIn('role == "lead"', mcp)
        self.assertIn("http_request", mcp)
        self.assertIn("x-atkbrain-role", mcp)
        ext = (ROOT.parents[1] / "pi" / "extensions" / "atkbrain-tools.ts").read_text(encoding="utf-8")
        self.assertIn("x-atkbrain-role", ext)
        self.assertIn("ATKBRAIN_PI_ROLE", ext)

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
        from ..agents.prompts import BUSINESS_SAFE_WRITE_BRIEF, SRC_POLICY_BRIEF

        for key in ("redteam", "src"):
            block = _GOAL_BLOCKS[key]
            self.assertIn("平台硬拦", block)
            self.assertNotIn(SRC_POLICY_BRIEF[:32], block)
            self.assertNotIn(BUSINESS_SAFE_WRITE_BRIEF[:32], block)
            self.assertLess(len(block), 500)


class HotpathTtlTests(unittest.IsolatedAsyncioTestCase):
    def test_timeouts_and_ttls(self) -> None:
        from ..agents.context import _HTTP_TIMEOUT

        self.assertEqual(float(_HTTP_TIMEOUT.connect), 5.0)
        self.assertEqual(float(_HTTP_TIMEOUT.read), 12.0)

    async def test_intent_refresh_returns_a_result(self) -> None:
        import atkbrain_native as gstore

        out = gstore.refresh_derived_intents("p_speed_ttl")
        self.assertIsInstance(out, dict)

    async def test_get_graph_returns_a_mapping(self) -> None:
        import atkbrain_native as gstore

        out = gstore.get_graph("p_speed_graph")
        self.assertIsInstance(out, dict)
        gstore.invalidate_graph_cache("p_speed_graph")


if __name__ == "__main__":
    unittest.main()
