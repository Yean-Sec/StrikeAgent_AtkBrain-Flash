"""指挥官每轮必须是全新 Claude Code，不得 resume 旧对话。"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from atkbrain.scope import Scope


def _agent():
    from atkbrain.agents.session import ProjectAgent

    with patch("atkbrain.agents.session.ClaudeSDKClient") as cli:
        cli.return_value = MagicMock()
        return ProjectAgent(
            {
                "id": "p_test_fresh_claude",
                "name": "fresh",
                "target": "10.0.0.1",
                "config": {"objective": "flag"},
            },
            Scope(targets=["10.0.0.1"]),
        )


class FreshClaudeSessionTests(unittest.IsolatedAsyncioTestCase):
    def test_default_options_do_not_resume(self):
        agent = _agent()
        opts = agent._build_options()
        self.assertFalse(bool(getattr(opts, "resume", None)))
        self.assertFalse(bool(getattr(opts, "continue_conversation", False)))

    async def test_begin_fresh_drops_old_session_id(self):
        agent = _agent()
        agent.last_session_id = "old-dirty-session"
        agent._connected = False
        agent.connect = AsyncMock()
        agent.interrupt = AsyncMock()
        old = agent.client
        await agent.begin_fresh_session(connect=True)
        self.assertIsNone(agent.last_session_id)
        self.assertIsNot(agent.client, old)
        agent.connect.assert_awaited()
        opts = agent.options
        self.assertFalse(bool(getattr(opts, "resume", None)))

    async def test_resume_session_never_returns_true(self):
        agent = _agent()
        agent.last_session_id = "old-dirty-session"
        agent.connect = AsyncMock()
        agent.interrupt = AsyncMock()
        ok = await agent.resume_session()
        self.assertFalse(ok)
        self.assertIsNone(agent.last_session_id)

    async def test_run_turn_opens_fresh_session(self):
        agent = _agent()
        agent.last_session_id = "old-dirty-session"
        agent.begin_fresh_session = AsyncMock()
        agent.client.query = AsyncMock()

        async def _empty():
            if False:
                yield None

        agent.client.receive_response = lambda: _empty()
        out = await agent.run_turn("go")
        agent.begin_fresh_session.assert_awaited()
        self.assertEqual(out.get("tool_uses"), 0)


class WarmSessionReuseTests(unittest.IsolatedAsyncioTestCase):
    """暖会话复用：连续 K 轮复用同一条已连接会话；满 K 轮/污染事件才开新会话。"""

    def _connected_agent(self):
        agent = _agent()
        # 模拟已连接的暖会话
        agent._connected = True
        fresh_calls = {"n": 0}

        async def _fake_fresh(*_a, **_k):
            fresh_calls["n"] += 1
            agent._connected = True
            agent._session_turns = 0
            agent._force_fresh = False

        agent.begin_fresh_session = AsyncMock(side_effect=_fake_fresh)
        agent.client.query = AsyncMock()

        async def _empty():
            if False:
                yield None

        agent.client.receive_response = lambda: _empty()
        return agent, fresh_calls

    async def test_reuse_within_cap_then_fresh_at_cap(self):
        from atkbrain.config import settings

        agent, fresh_calls = self._connected_agent()
        cap = int(settings.claude_session_max_turns)
        # 前 cap 轮复用同一会话，不开新会话
        for _ in range(cap):
            await agent.run_turn("go")
        self.assertEqual(fresh_calls["n"], 0)
        self.assertEqual(agent._session_turns, cap)
        # 第 cap+1 轮达到上限，强制开新会话
        await agent.run_turn("go")
        self.assertEqual(fresh_calls["n"], 1)
        self.assertEqual(agent._session_turns, 1)

    async def test_force_fresh_triggers_new_session_next_turn(self):
        agent, fresh_calls = self._connected_agent()
        await agent.run_turn("go")
        self.assertEqual(fresh_calls["n"], 0)
        agent.force_fresh_session()
        self.assertTrue(agent._force_fresh)
        await agent.run_turn("go")
        self.assertEqual(fresh_calls["n"], 1)
        self.assertFalse(agent._force_fresh)


class ConnectRetryTests(unittest.IsolatedAsyncioTestCase):
    def test_initialize_timeout_is_retryable_not_dead(self):
        from atkbrain.agents.session import is_dead_cli_error, is_retryable_connect_error

        msg = "Control request timeout: initialize"
        self.assertFalse(is_dead_cli_error(msg))
        self.assertTrue(is_retryable_connect_error(msg))
        self.assertTrue(is_retryable_connect_error("Cannot write to terminated process"))

    async def test_connect_retries_initialize_timeout(self):
        from atkbrain.agents.session import ProjectAgent
        from atkbrain.scope import Scope

        n = {"i": 0}

        async def _flaky(*_a, **_k):
            n["i"] += 1
            if n["i"] < 3:
                raise Exception("Control request timeout: initialize")

        with patch("atkbrain.agents.session.ClaudeSDKClient") as cli:
            inst = MagicMock()
            inst.connect = _flaky
            cli.return_value = inst
            agent = ProjectAgent(
                {
                    "id": "p_test_retry_init",
                    "name": "retry",
                    "target": "10.0.0.1",
                    "config": {"objective": "flag"},
                },
                Scope(targets=["10.0.0.1"]),
            )
            agent._kill_workspace_cli = lambda: 0
            with patch("atkbrain.agents.session.asyncio.sleep", new=AsyncMock()):
                await agent.connect(jitter=False)
        self.assertEqual(n["i"], 3)
        self.assertTrue(agent._connected)
