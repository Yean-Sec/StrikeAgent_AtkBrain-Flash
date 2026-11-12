"""硬停说明跟请求语言走。"""
from __future__ import annotations

import unittest

from atkbrain_native import format_duration, hunt_hard_stop_info


class HardStopI18nTests(unittest.TestCase):
    def test_duration_en(self):
        self.assertEqual(format_duration(12 * 3600, "en"), "12 hours")
        self.assertEqual(format_duration(8 * 60, "en"), "8 minutes")
        self.assertEqual(format_duration(0, "en"), "unlimited")

    def test_duration_zh(self):
        self.assertEqual(format_duration(12 * 3600, "zh"), "12 小时")
        self.assertEqual(format_duration(0, "zh"), "不限")

    def test_redteam_en(self):
        info = hunt_hard_stop_info("redteam", lang="en")
        self.assertIn("Hard stop", info["label"])
        self.assertNotIn("硬停", info["label"])
        self.assertTrue(any("Wall clock" in c for c in info["conditions"]))

    def test_redteam_zh(self):
        info = hunt_hard_stop_info("redteam", lang="zh")
        self.assertIn("硬停", info["label"])
        self.assertIn("墙钟", info["label"])
