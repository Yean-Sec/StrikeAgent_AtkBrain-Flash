"""红队 / CTF 目标契约：满分停机、可见发现、类别门槛。"""
from __future__ import annotations

import unittest

from atkbrain.objective import (
    ctf_full_score,
    is_run_complete,
    listed_finding_rows,
    normalize_objective,
    objective_allows_flag,
    redteam_new_ultimate,
    user_visible_finding,
)


class NormalizeTests(unittest.TestCase):
    def test_flag_aliases(self):
        self.assertEqual(normalize_objective("flag"), "flag")
        self.assertEqual(normalize_objective("ctf"), "flag")
        self.assertTrue(objective_allows_flag("flag"))

    def test_unknown_is_redteam(self):
        self.assertEqual(normalize_objective("src"), "redteam")
        self.assertEqual(normalize_objective("getshell"), "redteam")
        self.assertFalse(objective_allows_flag("redteam"))


class CtfFullScoreTests(unittest.TestCase):
    def test_single_flag_is_full(self):
        self.assertTrue(ctf_full_score(flags_correct=1, flag_count=1))
        self.assertTrue(ctf_full_score(flags_correct=1))

    def test_multi_flag_one_of_three_continues(self):
        self.assertFalse(ctf_full_score(flags_correct=1, flags_needed=3, flag_count=3))
        self.assertFalse(is_run_complete("flag", flags_correct=1, flags_needed=3))

    def test_multi_flag_three_of_three_stops(self):
        self.assertTrue(ctf_full_score(flags_correct=3, flags_needed=3, flag_count=3))
        self.assertTrue(is_run_complete("flag", flags_correct=3, flags_needed=3))

    def test_all_flags_complete_even_if_score_below_cap(self):
        """平台满分常含时间衰减；flag 数齐就收工，不要为分差占槽。"""
        self.assertTrue(ctf_full_score(
            flags_correct=1, flag_count=1, flags_score=270, total_score=300,
        ))
        self.assertFalse(ctf_full_score(
            flags_correct=1, flag_count=2, flags_score=270, total_score=300,
        ))

    def test_redteam_never_complete_from_flag_count(self):
        self.assertFalse(is_run_complete("redteam", flags_correct=1))


class FindingVisibilityTests(unittest.TestCase):
    def test_high_is_visible(self):
        self.assertTrue(user_visible_finding(severity="high", category="rce"))

    def test_listed_rows_keep_high(self):
        rows = [
            {"severity": "high", "category": "rce", "title": "rce"},
            {"severity": "low", "category": "info", "title": "banner"},
        ]
        listed = listed_finding_rows(rows)
        self.assertTrue(any(r.get("severity") == "high" for r in listed))


class RedteamUltimateTests(unittest.TestCase):
    def test_new_getshell(self):
        self.assertTrue(redteam_new_ultimate(["getshell"], []))


if __name__ == "__main__":
    unittest.main()
