"""设置页的模型表单写入 pi-models.json，测试请求不能带出密钥。"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class LlmProfileTests(unittest.TestCase):
    def _use(self, directory: str):
        from atkbrain.config import settings

        old_dir = settings.data_dir
        old_home = os.environ.get("HOME")
        settings.data_dir = Path(directory)
        os.environ["HOME"] = directory
        self.addCleanup(self._restore, old_dir, old_home)
        return Path(directory) / "pi-models.json"

    def _restore(self, old_dir, old_home) -> None:
        from atkbrain.config import settings
        from atkbrain_native import set_llm_http_hook

        settings.data_dir = old_dir
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home
        set_llm_http_hook(None)

    def test_form_round_trip_keeps_blank_key(self) -> None:
        from atkbrain_native import llm_profile, save_llm_profile

        with tempfile.TemporaryDirectory() as directory:
            path = self._use(directory)
            path.write_text(json.dumps({
                "defaultProvider": "deepseek",
                "defaultModel": "deepseek-flash",
                "providers": {
                    "deepseek": {
                        "baseUrl": "https://api.deepseek.com",
                        "api": "openai-completions",
                        "apiKey": "$DEEPSEEK_API_KEY",
                        "models": [{"id": "deepseek-flash", "name": "deepseek-flash"}],
                    }
                },
            }), encoding="utf-8")
            with mock.patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test-key-1234"}, clear=False):
                view = llm_profile()
                self.assertEqual(view["model"], "deepseek-flash")
                self.assertTrue(view["api_key_set"])
                self.assertNotIn("sk-test", json.dumps(view))
                saved = save_llm_profile(
                    model="deepseek-v4-flash",
                    base_url="https://api.deepseek.com",
                    api_key="",
                )
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["defaultProvider"], "deepseek")
            self.assertEqual(data["defaultModel"], "deepseek-v4-flash")
            self.assertEqual(data["providers"]["deepseek"]["baseUrl"], "https://api.deepseek.com")
            self.assertEqual(data["providers"]["deepseek"]["apiKey"], "$DEEPSEEK_API_KEY")
            self.assertEqual(saved["model"], "deepseek-v4-flash")

    def test_legacy_harness_file_is_read_once(self) -> None:
        from atkbrain_native import load_pi_models

        with tempfile.TemporaryDirectory() as directory:
            self._use(directory)
            legacy = Path(directory) / "harness-models.json"
            legacy.write_text(json.dumps({
                "model": "deepseek-flash",
                "base_url": "https://api.deepseek.com",
                "api_key": "$DEEPSEEK_API_KEY",
            }), encoding="utf-8")
            data = load_pi_models()
            self.assertEqual(data["defaultModel"], "deepseek-flash")
            self.assertEqual(data["providers"]["deepseek"]["baseUrl"], "https://api.deepseek.com")
            self.assertEqual(data["providers"]["deepseek"]["apiKey"], "$DEEPSEEK_API_KEY")

    def test_anthropic_format_is_rejected(self) -> None:
        from atkbrain_native import save_llm_profile

        with tempfile.TemporaryDirectory() as directory:
            self._use(directory)
            with self.assertRaises(ValueError):
                save_llm_profile(
                    fmt="anthropic",
                    model="claude-sonnet-4-5",
                    base_url="https://api.anthropic.com",
                    api_key="sk-ant-secret",
                )

    def test_probe_url_is_chat_completions(self) -> None:
        from atkbrain_native import llm_probe_url

        self.assertEqual(
            llm_probe_url("openai", "https://api.deepseek.com"),
            "https://api.deepseek.com/chat/completions",
        )
        self.assertEqual(
            llm_probe_url("openai", "https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1/chat/completions",
        )

    def test_probe_uses_typed_key_and_hides_it(self) -> None:
        from atkbrain_native import probe_llm, set_llm_http_hook

        calls = []

        def hook(url, headers, body):
            calls.append({"url": url, "headers": dict(headers), "body": body})
            return 200, json.dumps({"choices": [{"message": {"content": "OK"}}]})

        with tempfile.TemporaryDirectory() as directory:
            self._use(directory)
            set_llm_http_hook(hook)
            result = probe_llm(
                model="deepseek-v4-flash",
                base_url="https://example.test/v1",
                api_key="sk-live-secret",
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["reply"], "OK")
        self.assertNotIn("sk-live-secret", json.dumps(result))
        self.assertEqual(calls[0]["url"], "https://example.test/v1/chat/completions")
        self.assertEqual(calls[0]["headers"]["Authorization"], "Bearer sk-live-secret")

    def test_probe_rejects_missing_key(self) -> None:
        from atkbrain_native import probe_llm

        with tempfile.TemporaryDirectory() as directory:
            path = self._use(directory)
            path.write_text(json.dumps({
                "defaultProvider": "deepseek",
                "defaultModel": "deepseek-flash",
                "providers": {"deepseek": {"baseUrl": "https://api.deepseek.com", "apiKey": ""}},
            }), encoding="utf-8")
            with mock.patch.dict("os.environ", {"DEEPSEEK_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}, clear=False):
                result = probe_llm(
                    model="deepseek-flash",
                    base_url="https://api.deepseek.com",
                    api_key="",
                )
        self.assertFalse(result["ok"])
        self.assertIn("API Key", result["error"])

    def test_empty_error_body_reports_status(self) -> None:
        from atkbrain_native import probe_llm, set_llm_http_hook

        def hook(url, headers, body):
            return 502, ""

        with tempfile.TemporaryDirectory() as directory:
            self._use(directory)
            set_llm_http_hook(hook)
            result = probe_llm(
                model="deepseek-flash",
                base_url="https://example.test/v1",
                api_key="sk-live-secret",
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "HTTP 502")


if __name__ == "__main__":
    unittest.main()
