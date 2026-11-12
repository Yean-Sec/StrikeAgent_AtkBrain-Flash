"""自定义拦截只追加拒绝；未登录的规则接口仍是 401。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from atkbrain.auth.gate import auth_public_path
from atkbrain.config import settings
from atkbrain_native import Guard, Scope, guard_create_rule, guard_delete_rule, guard_set_enabled


class CustomRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self._old = settings.data_dir
        settings.data_dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        settings.data_dir = self._old
        self.tmp.cleanup()

    def test_invalid_regex_rejected(self) -> None:
        with self.assertRaises(ValueError):
            guard_create_rule(name="坏正则", pattern="(", reason="")

    def test_custom_denies_after_builtin_allows(self) -> None:
        guard_create_rule(name="标记", pattern="ZZZBLOCK", reason="测试拦截", enabled=True)
        scope = Scope(targets=["example.com"], allow_subdomains=False, mode="strict")
        denied = Guard(scope, objective="src").check_command("echo ZZZBLOCK")
        self.assertFalse(denied.allow)
        self.assertIn("测试拦截", denied.reason)
        allowed = Guard(scope, objective="src").check_command("echo hello-example")
        self.assertTrue(allowed.allow)

    def test_disabled_custom_does_not_deny(self) -> None:
        row = guard_create_rule(name="标记", pattern="ZZZBLOCK", reason="测试拦截")
        guard_set_enabled(row["id"], False)
        scope = Scope(targets=["example.com"], allow_subdomains=False, mode="strict")
        allowed = Guard(scope, objective="src").check_command("echo ZZZBLOCK")
        self.assertTrue(allowed.allow)

    def test_builtin_still_denies(self) -> None:
        scope = Scope(targets=["example.com"], allow_subdomains=False, mode="strict")
        denied = Guard(scope, objective="src").check_command("rm -rf /")
        self.assertFalse(denied.allow)

    def test_delete_builtin_is_forbidden(self) -> None:
        with self.assertRaises(PermissionError):
            guard_delete_rule("builtin-rm-root")

    def test_guard_paths_are_not_public(self) -> None:
        self.assertFalse(auth_public_path("/api/guard/rules"))
        self.assertFalse(auth_public_path("/api/projects/p1/tool-explain"))
        text = Path(__file__).resolve().parents[1].joinpath("atkbrain/main.py").read_text(encoding="utf-8")
        self.assertIn('return JSONResponse({"detail": "login-required"}, status_code=401)', text)


if __name__ == "__main__":
    unittest.main()
