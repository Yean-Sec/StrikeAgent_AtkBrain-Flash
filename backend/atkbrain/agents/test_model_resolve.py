"""控制台 defaultModel 必须盖过写死的 deepseek-flash。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path


def _with_model(model: str):
    from atkbrain.config import settings

    folder = tempfile.TemporaryDirectory()
    path = Path(folder.name) / "pi-models.json"
    path.write_text(json.dumps({
        "defaultProvider": "deepseek",
        "defaultModel": model,
        "providers": {
            "deepseek": {
                "baseUrl": "https://api.deepseek.com",
                "api": "openai-completions",
                "apiKey": "$DEEPSEEK_API_KEY",
                "models": [{"id": model, "name": model}],
            }
        },
    }), encoding="utf-8")
    old = settings.data_dir
    settings.data_dir = Path(folder.name)
    return folder, old


class ModelResolveTests(unittest.TestCase):
    def test_unset_project_uses_console_model(self) -> None:
        from atkbrain.config import settings
        from atkbrain_native import project_model

        folder, old = _with_model("grok-4.6")
        try:
            self.assertEqual(project_model(None), "grok-4.6")
            self.assertEqual(project_model(""), "grok-4.6")
            self.assertEqual(project_model("claude-sonnet"), "grok-4.6")
            self.assertEqual(project_model("haiku"), "grok-4.6")
            self.assertEqual(project_model("custom-explicit"), "custom-explicit")
        finally:
            settings.data_dir = old
            folder.cleanup()

    def test_builtin_default_does_not_hide_console_model(self) -> None:
        from atkbrain.config import settings
        from atkbrain_native import role_model

        folder, old = _with_model("grok-4.6")
        try:
            self.assertEqual(role_model("deepseek-flash", "deepseek-flash"), "grok-4.6")
            self.assertEqual(role_model("", "deepseek-flash"), "grok-4.6")
            self.assertEqual(role_model("gpt-export"), "gpt-export")
        finally:
            settings.data_dir = old
            folder.cleanup()

    def test_builtin_stays_when_console_matches(self) -> None:
        from atkbrain.config import settings
        from atkbrain_native import role_model

        folder, old = _with_model("deepseek-flash")
        try:
            self.assertEqual(role_model("deepseek-flash"), "deepseek-flash")
        finally:
            settings.data_dir = old
            folder.cleanup()

    def test_claude_env_seeds_when_pi_env_is_builtin(self) -> None:
        from atkbrain.config import settings
        from atkbrain_native import env_pi_model

        old_pi, old_claude = settings.pi_model, settings.claude_model
        settings.pi_model = "deepseek-flash"
        settings.claude_model = "grok-4.6"
        try:
            self.assertEqual(env_pi_model(), "grok-4.6")
        finally:
            settings.pi_model = old_pi
            settings.claude_model = old_claude


class ExportHeaderTests(unittest.TestCase):
    def test_chinese_filename_header_is_latin1(self) -> None:
        from ..report.claude_export import content_disposition

        header = content_disposition("attachment", "渗透报告.pdf")
        header.encode("latin-1")
        self.assertIn("filename*=UTF-8''", header)
        self.assertIn("%", header)


if __name__ == "__main__":
    unittest.main()
