"""Pi 进程闸：fanout 截断、cmdline 识别、health 数字不再写死 0。"""
from __future__ import annotations

import inspect
import unittest

from ..agents.pi_runtime import (
    _is_backend_cmd,
    _is_pi_cmdline,
    _is_protected_cmd,
    cap_hunt_workers,
    pi_max_live_limit,
    pi_per_project_limit,
)
from ..engine.scheduler import RunManager


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

    def test_pi_cmdline(self) -> None:
        self.assertTrue(_is_pi_cmdline(b"pi\0--mode\0rpc\0"))
        self.assertTrue(_is_pi_cmdline(b"/usr/local/bin/pi\0--mode\0rpc"))
        self.assertTrue(_is_pi_cmdline(b"node\0/usr/lib/node_modules/@earendil-works/pi-coding-agent/dist/cli.js\0--mode\0rpc"))
        self.assertFalse(_is_pi_cmdline(b"python3\0-m\0atkbrain.main"))
        self.assertTrue(_is_backend_cmd(b"python3\0-m\0atkbrain.main"))
        self.assertTrue(_is_protected_cmd(b"caddy\0run"))
        self.assertFalse(_is_protected_cmd(b"pi\0--mode\0rpc"))


class FanoutAndPoolTests(unittest.TestCase):
    def test_fanout_calls_cap(self) -> None:
        from ..agents.session import ProjectAgent
        src = inspect.getsource(ProjectAgent._fanout_roles)
        self.assertIn("cap_hunt_workers", src)

    def test_acquire_uses_role_lock(self) -> None:
        from ..agents.session import ProjectAgent
        src = inspect.getsource(ProjectAgent._acquire_pi)
        self.assertIn("_pi_lock", src)
        self.assertIn("async with", src)

    def test_recover_kills_orphans(self) -> None:
        from ..agents.session import ProjectAgent
        src = inspect.getsource(ProjectAgent.recover_dead_cli)
        self.assertIn("kill_live_for_project", src)

    def test_idle_reap_keeps_lead(self) -> None:
        from ..agents.session import ProjectAgent
        src = inspect.getsource(ProjectAgent._reap_idle_workers)
        self.assertIn("is_review_role(role)", src)

    def test_close_does_not_untrack_before_death(self) -> None:
        from ..agents.pi_runtime import PiSession

        text = inspect.getsource(PiSession.close)
        self.assertIn("_untrack_dead", text)
        self.assertNotIn("_LIVE.pop(pid, None)", text)

    def test_set_claude_per_project_sticks(self) -> None:
        mgr = RunManager()
        self.addCleanup(lambda: mgr.set_claude_per_project(4))
        n = mgr.set_claude_per_project(6)
        self.assertEqual(n, 6)
        self.assertEqual(mgr.snapshot()["claude"]["per_project"], 6)
        self.assertEqual(mgr.set_claude_per_project(99), 8)


class SnapshotTests(unittest.TestCase):
    def test_health_claude_limits_nonzero(self) -> None:
        mgr = RunManager()
        snap = mgr.snapshot()
        self.assertEqual(snap["claude"]["limit"], 32)
        self.assertGreater(snap["claude"]["cap"], 0)
        self.assertGreaterEqual(snap["claude"]["per_project"], 1)


class HaltTests(unittest.IsolatedAsyncioTestCase):
    async def test_halt_survives_stop_error(self) -> None:
        from unittest.mock import patch
        from ..engine.scheduler import RunHandle, RunManager
        mgr = RunManager()
        h = RunHandle(project_id="p1")
        h.status = "zombie"
        mgr.handles["p1"] = h

        async def boom(_pid: str) -> bool:
            raise RuntimeError("stop exploded")

        with patch.object(mgr, "stop", side_effect=boom):
            ok = await mgr.halt("p1")
        self.assertTrue(ok)

    async def test_halt_swallows_child_cancelled_error(self) -> None:
        import asyncio
        from unittest.mock import patch
        from ..engine.scheduler import RunHandle, RunManager
        mgr = RunManager()
        h = RunHandle(project_id="p1")
        h.status = "running"
        mgr.handles["p1"] = h

        async def boom(_pid: str) -> bool:
            raise asyncio.CancelledError()

        with patch.object(mgr, "stop", side_effect=boom):
            ok = await mgr.halt("p1")
        self.assertTrue(ok)
        task = asyncio.current_task()
        self.assertTrue(task is None or int(getattr(task, "cancelling", lambda: 0)()) == 0)


class PiCmdTests(unittest.TestCase):
    def test_rpc_flags_match_pi_074(self) -> None:
        import tempfile
        from ..agents.pi_runtime import PiSession
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        s = PiSession(cwd=td.name, system_prompt="x", tools=True)
        cmd = s._cmd()
        self.assertNotIn("-a", cmd)
        self.assertNotIn("--exclude-tools", cmd)
        self.assertIn("--no-builtin-tools", cmd)
        self.assertIn("--mode", cmd)

    def test_tools_base_includes_entry(self) -> None:
        from unittest.mock import patch
        from ..agents import pi_runtime
        with patch("atkbrain.auth.entry.entry_prefix", return_value="/AbCdef12"):
            url = pi_runtime.tools_base_url()
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        self.assertTrue(url.endswith("/AbCdef12"))


class OneshotSettleTests(unittest.IsolatedAsyncioTestCase):
    async def test_user_message_end_does_not_settle_oneshot(self) -> None:
        from ..agents.pi_runtime import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        await s._on_event({
            "type": "message_end",
            "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]},
        })
        self.assertFalse(s._settled.is_set())

    async def test_assistant_message_end_settles_oneshot(self) -> None:
        from ..agents.pi_runtime import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        await s._on_event({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": '{"diagnosis":"ok"}'}],
                "stopReason": "stop",
            },
        })
        self.assertTrue(s._settled.is_set())
        self.assertIn('{"diagnosis":"ok"}', "".join(s.texts))

    async def test_aborted_assistant_does_not_settle(self) -> None:
        from ..agents.pi_runtime import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=False, role="supervisor")
        await s._on_event({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [],
                "stopReason": "aborted",
                "errorMessage": "Request was aborted.",
            },
        })
        self.assertFalse(s._settled.is_set())

    async def test_message_end_does_not_settle_tools_session(self) -> None:
        from ..agents.pi_runtime import PiSession
        s = PiSession(cwd="/tmp", system_prompt="x", tools=True, role="lead")
        await s._on_event({"type": "message_end", "message": {"role": "assistant", "content": [], "stopReason": "stop"}})
        self.assertFalse(s._settled.is_set())
        await s._on_event({"type": "agent_settled"})
        self.assertTrue(s._settled.is_set())


if __name__ == "__main__":
    unittest.main()
