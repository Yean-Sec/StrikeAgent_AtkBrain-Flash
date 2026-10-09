"""设置页的 OpenAI / Anthropic 表单要写回 Pi models.json，测试请求不能带出密钥。"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class _Resp:
    def __init__(self, status: int, body: dict):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


class _Client:
    calls: list[dict] = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url, headers=None, json=None):
        self.calls.append({"url": url, "headers": headers or {}, "json": json or {}})
        if json and "max_tokens" in json and "retry" in url:
            return _Resp(400, {"error": {"message": "use max_completion_tokens instead of max_tokens"}})
        if "anthropic" in url:
            return _Resp(200, {"content": [{"type": "text", "text": "OK"}]})
        return _Resp(200, {"choices": [{"message": {"content": "OK"}}]})


class LlmProfileTests(unittest.TestCase):
    def _patch(self, directory: str):
        from . import pi_runtime

        path = Path(directory) / "pi-models.json"
        return (
            path,
            patch.object(pi_runtime, "pi_models_file", lambda: path),
            patch.object(pi_runtime, "ensure_pi_agent_dir", lambda **kwargs: path),
        )

    def test_openai_form_round_trip_keeps_blank_key(self) -> None:
        from . import pi_runtime

        with tempfile.TemporaryDirectory() as directory:
            path, file_patch, agent_patch = self._patch(directory)
            path.write_text(json.dumps({
                "defaultProvider": "deepseek",
                "defaultModel": "deepseek-flash",
                "providers": {
                    "deepseek": {
                        "baseUrl": "https://api.deepseek.com",
                        "api": "openai-completions",
                        "apiKey": "$DEEPSEEK_API_KEY",
                        "models": [{"id": "deepseek-flash", "contextWindow": 1000000, "maxTokens": 384000}],
                    }
                },
            }), encoding="utf-8")
            with file_patch, agent_patch, patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test-key-1234"}, clear=False):
                view = pi_runtime.llm_profile()
                self.assertEqual(view["format"], "openai")
                self.assertEqual(view["model"], "deepseek-flash")
                self.assertTrue(view["api_key_set"])
                self.assertNotIn("sk-test", json.dumps(view))
                saved = pi_runtime.save_llm_profile(
                    fmt="openai",
                    model="gpt-4.1",
                    base_url="https://api.openai.com/v1",
                    api_key="",
                )
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["defaultProvider"], "openai")
            self.assertEqual(data["defaultModel"], "gpt-4.1")
            self.assertEqual(data["providers"]["openai"]["api"], "openai-completions")
            self.assertEqual(data["providers"]["openai"]["apiKey"], "$DEEPSEEK_API_KEY")
            self.assertEqual(saved["model"], "gpt-4.1")
            self.assertNotIn("deepseek", data["providers"])

    def test_anthropic_replaces_key_and_probe_url(self) -> None:
        from . import pi_runtime

        self.assertEqual(
            pi_runtime.llm_probe_url("anthropic", "https://api.anthropic.com"),
            "https://api.anthropic.com/v1/messages",
        )
        self.assertEqual(
            pi_runtime.llm_probe_url("openai", "https://api.openai.com/v1"),
            "https://api.openai.com/v1/chat/completions",
        )
        with tempfile.TemporaryDirectory() as directory:
            path, file_patch, agent_patch = self._patch(directory)
            with file_patch, agent_patch:
                pi_runtime.save_llm_profile(
                    fmt="anthropic",
                    model="claude-sonnet-4-5",
                    base_url="https://api.anthropic.com/",
                    api_key="sk-ant-secret",
                )
            data = json.loads(path.read_text(encoding="utf-8"))
            prov = data["providers"]["anthropic"]
            self.assertEqual(prov["api"], "anthropic-messages")
            self.assertEqual(prov["baseUrl"], "https://api.anthropic.com")
            self.assertEqual(prov["apiKey"], "sk-ant-secret")
            self.assertEqual(data["defaultModel"], "claude-sonnet-4-5")

    def test_probe_uses_typed_key_and_hides_it(self) -> None:
        from . import pi_runtime

        _Client.calls = []
        with tempfile.TemporaryDirectory() as directory:
            _path, file_patch, agent_patch = self._patch(directory)
            with file_patch, agent_patch, patch("httpx.AsyncClient", _Client):
                result = asyncio.run(pi_runtime.probe_llm(
                    fmt="openai",
                    model="gpt-4.1",
                    base_url="https://example.test/v1",
                    api_key="sk-live-secret",
                ))
        self.assertTrue(result["ok"])
        self.assertEqual(result["reply"], "OK")
        self.assertNotIn("sk-live-secret", json.dumps(result))
        self.assertEqual(_Client.calls[0]["url"], "https://example.test/v1/chat/completions")
        self.assertEqual(_Client.calls[0]["headers"]["Authorization"], "Bearer sk-live-secret")

    def test_probe_rejects_missing_key(self) -> None:
        from . import pi_runtime

        with tempfile.TemporaryDirectory() as directory:
            path, file_patch, agent_patch = self._patch(directory)
            path.write_text(json.dumps({
                "defaultProvider": "openai",
                "defaultModel": "gpt-4.1",
                "providers": {"openai": {"baseUrl": "https://api.openai.com/v1", "api": "openai-completions", "apiKey": ""}},
            }), encoding="utf-8")
            with file_patch, agent_patch, patch.dict("os.environ", {"DEEPSEEK_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}, clear=False):
                result = asyncio.run(pi_runtime.probe_llm(
                    fmt="anthropic",
                    model="claude-sonnet-4-5",
                    base_url="https://api.anthropic.com",
                    api_key="",
                ))
        self.assertFalse(result["ok"])
        self.assertIn("API Key", result["error"])

    def test_empty_error_body_reports_status(self) -> None:
        from . import pi_runtime

        seen: dict = {}

        class Empty:
            status_code = 502
            text = ""

            def json(self):
                raise ValueError("no json")

        class Client:
            def __init__(self, *args, **kwargs):
                seen.update(kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def post(self, url, headers=None, json=None):
                return Empty()

        with tempfile.TemporaryDirectory() as directory:
            _path, file_patch, agent_patch = self._patch(directory)
            with file_patch, agent_patch, patch("httpx.AsyncClient", Client):
                result = asyncio.run(pi_runtime.probe_llm(
                    fmt="openai",
                    model="gpt-4.1",
                    base_url="https://example.test/v1",
                    api_key="sk-live-secret",
                ))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "HTTP 502")
        self.assertIs(seen.get("trust_env"), False)
