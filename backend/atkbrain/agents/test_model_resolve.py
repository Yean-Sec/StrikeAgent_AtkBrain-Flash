"""控制台 defaultModel 必须盖过写死的 deepseek-flash。"""
from __future__ import annotations

import unittest
from unittest.mock import patch


class ModelResolveTests(unittest.TestCase):
    def test_unset_project_uses_console_model(self) -> None:
        from .pi_runtime import project_model, role_model

        with patch("atkbrain.agents.pi_runtime.pi_model", return_value="grok-4.6"):
            self.assertEqual(project_model(None), "grok-4.6")
            self.assertEqual(project_model(""), "grok-4.6")
            self.assertEqual(project_model("claude-sonnet"), "grok-4.6")
            self.assertEqual(project_model("haiku"), "grok-4.6")
            self.assertEqual(project_model("custom-explicit"), "custom-explicit")

    def test_builtin_default_does_not_hide_console_model(self) -> None:
        from .pi_runtime import role_model

        with patch("atkbrain.agents.pi_runtime.pi_model", return_value="grok-4.6"):
            self.assertEqual(role_model("deepseek-flash", "deepseek-flash"), "grok-4.6")
            self.assertEqual(role_model("", "deepseek-flash"), "grok-4.6")
            self.assertEqual(role_model("gpt-export"), "gpt-export")

    def test_builtin_stays_when_console_matches(self) -> None:
        from .pi_runtime import role_model

        with patch("atkbrain.agents.pi_runtime.pi_model", return_value="deepseek-flash"):
            self.assertEqual(role_model("deepseek-flash"), "deepseek-flash")

    def test_claude_env_seeds_when_pi_env_is_builtin(self) -> None:
        from . import pi_runtime

        with patch.object(pi_runtime.settings, "pi_model", "deepseek-flash"), \
             patch.object(pi_runtime.settings, "claude_model", "grok-4.6"):
            self.assertEqual(pi_runtime._env_pi_model(), "grok-4.6")


class ExportHeaderTests(unittest.TestCase):
    def test_chinese_filename_header_is_latin1(self) -> None:
        from ..report.claude_export import content_disposition

        header = content_disposition("attachment", "渗透报告.pdf")
        header.encode("latin-1")
        self.assertIn("filename*=UTF-8''", header)
        self.assertIn("%", header)


if __name__ == "__main__":
    unittest.main()
