"""CTF 题型提示要进简报，附件名要挡住路径。"""
from __future__ import annotations

import unittest


class CtfPromptTests(unittest.TestCase):
    def test_each_category_has_a_prompt(self):
        from atkbrain_native import CTF_CATEGORIES, ctf_category_prompt

        for key in CTF_CATEGORIES:
            text = ctf_category_prompt(key)
            self.assertIn("report_flag", text)
            self.assertGreater(len(text), 80)

    def test_brief_includes_category_and_files(self):
        from atkbrain_native import build_brief

        text = build_brief({
            "config": {
                "objective": "flag",
                "ctf_category": "crypto",
                "hint": "已知 n 与 c",
                "attachments": ["task.py"],
                "offline": True,
            },
        })
        self.assertIn("密码学", text)
        self.assertIn("已知 n 与 c", text)
        self.assertIn("task.py", text)
        self.assertIn("没有远程入口", text)

    def test_reverse_alias(self):
        from atkbrain_native import normalize_ctf_category
        self.assertEqual(normalize_ctf_category("逆向"), "reverse")
        self.assertEqual(normalize_ctf_category("nope"), "")


class ChallengeNameTests(unittest.TestCase):
    def test_basename_only(self):
        from atkbrain.challenge_files import safe_challenge_name
        self.assertEqual(safe_challenge_name("../../etc/passwd"), "passwd")
        self.assertEqual(safe_challenge_name("libc.so.6"), "libc.so.6")
        with self.assertRaises(ValueError):
            safe_challenge_name("notes.bat")


if __name__ == "__main__":
    unittest.main()
