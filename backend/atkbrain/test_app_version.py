"""版本比较：无 packaging 时也能解析数字版本。"""
from __future__ import annotations

import builtins
import unittest
from unittest.mock import patch


class ParseTests(unittest.TestCase):
    def test_parse_with_stdlib_fallback(self):
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "packaging" or name.startswith("packaging."):
                raise ImportError("no packaging")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", blocked):
            from atkbrain.app_version import _parse, _status_for
            self.assertEqual(_parse("0.5.0"), (0, 5, 0))
            self.assertEqual(_parse("v1.2.3-beta.1"), (1, 2, 3))
            st, _, latest = _status_for("0.5.0", "0.6.0")
            self.assertEqual(st, "update_available")
            self.assertFalse(latest)
            st, _, latest = _status_for("0.6.0", "0.5.0")
            self.assertEqual(st, "latest")
            self.assertTrue(latest)


class LlmKeyTests(unittest.TestCase):
    def test_configured(self):
        import tempfile
        from pathlib import Path
        from atkbrain.config import settings
        from atkbrain_native import llm_api_key_configured

        old = settings.data_dir
        with tempfile.TemporaryDirectory() as directory:
            settings.data_dir = Path(directory)
            try:
                with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}, clear=False):
                    self.assertFalse(llm_api_key_configured())
                with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test", "ANTHROPIC_AUTH_TOKEN": ""}, clear=False):
                    self.assertTrue(llm_api_key_configured())
            finally:
                settings.data_dir = old

    def test_settings_json_key_counts(self):
        import json
        import tempfile
        from pathlib import Path
        from atkbrain.config import settings
        from atkbrain_native import llm_api_key_configured, usable_api_key

        self.assertEqual(usable_api_key("$DEEPSEEK_API_KEY"), "")
        self.assertEqual(usable_api_key(""), "")
        self.assertTrue(usable_api_key("sk-from-settings"))
        old = settings.data_dir
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            settings.data_dir = folder
            (folder / "pi-models.json").write_text(json.dumps({
                "defaultProvider": "deepseek",
                "defaultModel": "deepseek-flash",
                "providers": {"deepseek": {"apiKey": "sk-from-settings"}},
            }), encoding="utf-8")
            try:
                with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}, clear=False):
                    self.assertTrue(llm_api_key_configured())
            finally:
                settings.data_dir = old


if __name__ == "__main__":
    unittest.main()
