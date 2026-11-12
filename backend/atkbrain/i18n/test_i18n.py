"""Locale, cache isolation, output-language contract, English report chrome."""
from __future__ import annotations

import unittest


class LocaleTests(unittest.TestCase):
    def test_normalize_locale(self) -> None:
        from atkbrain_native import normalize_locale
        self.assertEqual(normalize_locale("en-US"), "en")
        self.assertEqual(normalize_locale("EN"), "en")
        self.assertEqual(normalize_locale("zh-CN"), "zh")
        self.assertEqual(normalize_locale(""), "zh")
        self.assertEqual(normalize_locale(None), "zh")

    def test_config_output_lang(self) -> None:
        from atkbrain_native import config_output_lang
        self.assertEqual(config_output_lang({"output_lang": "en"}), "zh")
        self.assertEqual(config_output_lang('{"output_lang":"en-GB"}'), "zh")
        self.assertEqual(config_output_lang({}), "zh")


class PromptContractTests(unittest.TestCase):
    def test_english_contract_on_system_prompt(self) -> None:
        from atkbrain_native import Scope
        from ..agents.prompts import build_system_prompt
        text = build_system_prompt(
            Scope(targets=["example.com"]), "/tmp/ws", "redteam", "",
            output_lang="en",
        )
        self.assertIn("All human-visible text MUST be in English", text)
        self.assertIn("This system prompt remains Chinese", text)
        self.assertIn("report_finding", text)

    def test_chinese_contract_default(self) -> None:
        from atkbrain_native import Scope
        from ..agents.prompts import build_system_prompt
        text = build_system_prompt(
            Scope(targets=["example.com"]), "/tmp/ws", "redteam", "",
        )
        self.assertIn("人可见文本必须用中文", text)


class ReportLangTests(unittest.TestCase):
    def test_cache_stem_isolated(self) -> None:
        from ..report.slots import cache_stem
        digest = "a" * 64
        pid = "projid1234567890abcdef"
        zh = cache_stem(pid, digest, "zh")
        en = cache_stem(pid, digest, "en")
        self.assertNotEqual(zh, en)
        self.assertTrue(zh.endswith("-zh"))
        self.assertTrue(en.endswith("-en"))

    def test_assemble_html_lang_en(self) -> None:
        from ..report.slots import assemble_deliverable
        html = assemble_deliverable(
            {
                "project": {"id": "p1", "name": "Lab", "target": "example.com"},
                "findings": [],
                "has_shell": False,
                "generated_at": "2026-09-18T00:00:00",
                "graph": {"nodes": [], "edges": [], "stats": {}, "rce_path": {"path": []}},
                "sections": [],
            },
            lang="en",
        )
        self.assertIn('lang="en"', html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Authorized Penetration Test Report", html)
        self.assertNotIn("<h2>执行摘要</h2>", html)

    def test_export_system_english(self) -> None:
        from atkbrain_native import export_system_prompt
        en = export_system_prompt("en", "CHINESE_SYSTEM")
        self.assertIn("Not collected", en)
        self.assertIn("All prose in the JSON values MUST be English", en)
        self.assertEqual(export_system_prompt("zh", "CHINESE_SYSTEM"), "CHINESE_SYSTEM")

    def test_hunt_hard_stop_info_en_not_chinese(self) -> None:
        from atkbrain_native import set_locale
        from atkbrain_native import hunt_hard_stop_info
        set_locale("en")
        try:
            info = hunt_hard_stop_info("src", lang="en")
            self.assertIn("Hard stop", info["label"])
            self.assertNotIn("硬停", info["label"])
        finally:
            set_locale("zh")


if __name__ == "__main__":
    unittest.main()
