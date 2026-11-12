"""设置页撞墙钟钳制与红队轮次可读。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class HuntClockSettingsTests(unittest.TestCase):
    def test_clamp(self):
        from atkbrain_native import MAX_WALL_SEC, _normalize
        got = _normalize({
            "redteam_runtime_hard_stop_sec": 99 * 3600,
            "loop_max_turns_redteam": 99999,
            "graph_idle_empty_plans": 0,
        })
        self.assertEqual(got["agent_runtime_hard_stop_sec"], MAX_WALL_SEC)
        self.assertEqual(got["redteam_runtime_hard_stop_sec"], MAX_WALL_SEC)
        self.assertEqual(got["src_runtime_hard_stop_sec"], MAX_WALL_SEC)
        self.assertEqual(got["loop_max_turns_agent"], 9999)
        self.assertEqual(got["graph_idle_empty_plans"], 1)

    def test_persist_and_apply(self):
        from atkbrain.config import settings
        import atkbrain_native as hc
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "proxy-settings.json"
        old = {k: getattr(settings, k) for k in hc.CLOCK_KEYS}
        self.addCleanup(lambda: [setattr(settings, k, v) for k, v in old.items()])
        with patch("atkbrain.proxy.pool._settings_path", lambda: p):
            out = hc.set_hunt_clocks({
                "src_runtime_hard_stop_sec": 3600,
                "loop_max_turns_src": 3,
            })
            self.assertEqual(out["agent_runtime_hard_stop_sec"], 3600)
            self.assertEqual(out["src_runtime_hard_stop_sec"], 3600)
            self.assertEqual(out["redteam_runtime_hard_stop_sec"], 3600)
            self.assertEqual(out["loop_max_turns_agent"], 3)
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["loop_max_turns_agent"], 3)

    def test_redteam_max_turns(self):
        from atkbrain_native import hunt_max_turns
        from atkbrain.config import settings
        old = settings.loop_max_turns_agent
        settings.loop_max_turns_agent = 7
        try:
            self.assertEqual(hunt_max_turns("redteam"), 7)
            self.assertEqual(hunt_max_turns("src"), 7)
            self.assertEqual(hunt_max_turns("agent"), 7)
            self.assertEqual(hunt_max_turns("flag"), settings.loop_max_turns)
        finally:
            settings.loop_max_turns_agent = old


if __name__ == "__main__":
    unittest.main()
