"""里程碑识别与 episode 回退。"""
from __future__ import annotations

import os
import tempfile
import unittest

from atkbrain.db import Database, now
from atkbrain.memory.achievements import (
    detect_achievements, achievements_of_episode, FIRST_CLASS,
)


class AchievementDetectTests(unittest.TestCase):
    def test_detect_from_live_graph(self):
        graph = {
            "nodes": [{"key": "n1", "type": "vuln", "tags": [], "is_rce": False}],
            "edges": [{"from": "a", "to": "b", "relation": "ESCALATES_TO"}],
            "findings": [
                {"category": "db_dump"}, {"category": "auth_bypass"},
            ],
        }
        got = set(detect_achievements(graph))
        # db_dump -> data_access, auth_bypass -> admin_access, ESCALATES_TO -> privesc（手段）
        self.assertIn("data_access", got)
        self.assertIn("admin_access", got)
        self.assertIn("privesc", got)

    def test_sqli_point_is_not_mass_data(self):
        graph = {
            "nodes": [], "edges": [],
            "findings": [{"category": "sqli", "verification_status": "verified"}],
        }
        self.assertNotIn("data_access", detect_achievements(graph))

    def test_getshell_from_shell_goal_node(self):
        graph = {
            "nodes": [{"key": "goal:shell", "type": "goal", "tags": ["getshell"], "is_rce": True}],
            "edges": [], "findings": [],
        }
        self.assertIn("getshell", detect_achievements(graph))

    def test_rce_vuln_alone_is_not_getshell(self):
        graph = {
            "nodes": [{"key": "vuln:rce", "type": "vuln", "tags": ["rce"], "is_rce": True}],
            "edges": [],
            "findings": [{"category": "rce", "verification_status": "verified"}],
        }
        self.assertNotIn("getshell", detect_achievements(graph))

    def test_pending_finding_not_achievement(self):
        graph = {
            "nodes": [], "edges": [],
            "findings": [{"category": "sqli", "verification_status": "pending"}],
        }
        self.assertNotIn("data_access", detect_achievements(graph))

    def test_phpinfo_not_key_leak_or_data_access(self):
        graph = {
            "nodes": [], "edges": [],
            "findings": [{
                "category": "info_disclosure", "title": "phpinfo",
                "verification_status": "verified",
            }],
        }
        got = detect_achievements(graph)
        self.assertNotIn("key_leak", got)
        self.assertNotIn("data_access", got)

    def test_admin_and_key_requires_both(self):
        admin_only = {
            "nodes": [], "edges": [],
            "findings": [{"category": "auth_bypass", "verification_status": "verified"}],
        }
        self.assertIn("admin_access", detect_achievements(admin_only))
        self.assertNotIn("admin_and_key", detect_achievements(admin_only))
        leak_only = {
            "nodes": [], "edges": [],
            "findings": [{"category": "key_leak", "verification_status": "verified"}],
        }
        self.assertIn("key_leak", detect_achievements(leak_only))
        self.assertNotIn("admin_and_key", detect_achievements(leak_only))
        both = {
            "nodes": [], "edges": [],
            "findings": [
                {"category": "admin_access", "verification_status": "verified"},
                {"category": "source_leak", "verification_status": "verified"},
            ],
        }
        got = detect_achievements(both)
        self.assertIn("admin_access", got)
        self.assertIn("key_leak", got)
        self.assertIn("admin_and_key", got)
        pending_half = {
            "nodes": [], "edges": [],
            "findings": [
                {"category": "admin_access", "verification_status": "verified"},
                {"category": "key_leak", "verification_status": "pending"},
            ],
        }
        self.assertNotIn("admin_and_key", detect_achievements(pending_half))

    def test_privesc_is_means_not_in_ultimates(self):
        from atkbrain.memory.achievements import ULTIMATE_ACHIEVEMENTS
        self.assertNotIn("privesc", ULTIMATE_ACHIEVEMENTS)
        self.assertNotIn("lateral", ULTIMATE_ACHIEVEMENTS)

    def test_episode_fallback_flag_outcome(self):
        # 历史 episode:无 achievements 字段,靠 outcome=flag 回退推断 getflag
        self.assertIn("getflag", achievements_of_episode({"techniques": []}, "flag"))

    def test_episode_fallback_from_categories(self):
        content = {"findings": [{"category": "db_access"}], "techniques": ["sqli"]}
        got = achievements_of_episode(content, "partial")
        self.assertIn("data_access", got)

    def test_stored_achievements_take_priority(self):
        content = {"achievements": ["db_access", "privesc"]}
        self.assertEqual(set(achievements_of_episode(content, "fail")),
                         {"data_access", "privesc"})

    def test_no_achievement_returns_empty(self):
        self.assertEqual(achievements_of_episode({"techniques": ["recon"]}, "fail"), [])


if __name__ == "__main__":
    unittest.main()
