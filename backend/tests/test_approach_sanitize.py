"""跨目标学习只留可迁移思路，不把单题 writeup 写进记忆。"""
from __future__ import annotations

import unittest

from atkbrain.memory.store import is_transferable_approach, sanitize_approach, _build_milestone_payload


class SanitizeTests(unittest.TestCase):
    def test_strips_single_segment_php_path(self):
        out = sanitize_approach("读 /proxy.php 再打内网")
        self.assertNotIn("proxy.php", out)
        self.assertIn("<path>", out)

    def test_strips_intent_id_and_banner(self):
        out = sanitize_approach("解 i_ccb417437a75 nginx/1.18.0 PHP/7.4.33")
        self.assertNotIn("i_ccb417437a75", out)
        self.assertNotIn("1.18.0", out)


class TransferableTests(unittest.TestCase):
    def test_keeps_tactic_cue_chain(self):
        text = "手法 ssrf；线索：file_read_surface；避免：fingerprint；entry → vuln(ssrf)"
        self.assertTrue(is_transferable_approach(text))

    def test_rejects_writeup_specifics(self):
        text = (
            "确认 80/tcp nginx/1.18.0 + PHP/7.4.33 某信息官网 的产品/版本指纹；"
            "/proxy.php 读目标本机文件这条链可直接解 i_ccb417437a75"
        )
        self.assertFalse(is_transferable_approach(text))

    def test_rejects_preset_creds_playbyplay(self):
        text = (
            "主攻仍在 nmap 全端口扫描，尚未使用题面唯一预置凭证 2001/Sys@Oa123 登录"
        )
        self.assertFalse(is_transferable_approach(text))

    def test_rejects_console_writeup(self):
        text = "未走题面核心：登录后 /control.php 控制台，admin@example.com 精确匹配"
        self.assertFalse(is_transferable_approach(text))


class MilestoneApproachTests(unittest.TestCase):
    def test_keeps_tactic_not_writeup(self):
        p = _build_milestone_payload(
            {"id": "p_x", "config": {"objective": "flag"}},
            {"nodes": [], "findings": [{"category": "ssrf"}], "rce_path": {"path": ["entry", "vuln"]}},
            "getflag",
            {"category": "ssrf", "title": "ssrf"},
        )
        ap = p.get("approach") or ""
        self.assertIn("ssrf", ap.lower())
        self.assertEqual(p.get("winning_path"), "")
        self.assertNotIn("title", (p.get("findings") or [{}])[0])


if __name__ == "__main__":
    unittest.main()
