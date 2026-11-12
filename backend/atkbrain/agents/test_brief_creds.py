"""题面/人工句摘账密与 token；授权身份进简报与 allowed_secrets。"""
from __future__ import annotations

import unittest

from atkbrain_native import (
    credential_candidates_from_brief,
    extract_supplied_auth,
    format_supplied_auth_brief,
    merge_steering_supplied_auth,
    password_values,
)
from atkbrain_native import build_brief
from atkbrain_native import apply_gate_to_guard


class BriefTokenTests(unittest.TestCase):
    def test_bearer_from_brief(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaa.bbb"
        cands = credential_candidates_from_brief(f"Authorization: Bearer {jwt}")
        blob = " ".join(cands).lower()
        self.assertIn("bearer", blob)
        self.assertIn("eyj", blob)
        secrets = password_values(cands)
        self.assertIn(jwt.lower(), secrets)

    def test_cookie_from_brief(self) -> None:
        cands = credential_candidates_from_brief("Cookie: session=abc123; path=/")
        self.assertTrue(any("session=abc123" in x for x in cands))

    def test_steering_user_pass(self) -> None:
        got = extract_supplied_auth("账号 admin 密码 P@ssw0rd")
        self.assertEqual(got.get("user"), "admin")
        self.assertEqual(got.get("password"), "P@ssw0rd")

    def test_steering_bearer_not_bench_token(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"
        got = extract_supplied_auth(f"Authorization: Bearer {jwt}")
        self.assertEqual(got.get("token"), jwt)
        merged = merge_steering_supplied_auth({}, [f"Authorization: Bearer {jwt}"])
        self.assertEqual(merged.get("token"), jwt)
        self.assertNotIn("benchmark", merged)

    def test_bench_token_line_not_swallowed(self) -> None:
        got = extract_supplied_auth("BENCHMARK_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        self.assertFalse(got.get("token"))

    def test_build_brief_includes_supplied_auth(self) -> None:
        brief = build_brief({
            "config": {
                "track": "redteam",
                "objective": "getshell",
                "supplied_auth": {"user": "alice", "password": "S3cret!"},
            },
            "target": "example.com",
        })
        self.assertIn("alice", brief)
        self.assertIn("S3cret!", brief)
        self.assertIn("必须先登录", brief)
        self.assertIn("禁止 hydra", brief)

    def test_src_brief_forbids_getshell(self) -> None:
        brief = build_brief({
            "config": {
                "track": "src",
                "objective": "src",
                "supplied_auth": {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aa.bb"},
            },
        })
        self.assertIn("Bearer", brief)
        self.assertIn("禁止 getshell", brief)

    def test_allowed_secrets_union_supplied(self) -> None:
        class G:
            scope = None
        g = G()
        apply_gate_to_guard(
            g, {"nodes": []}, brief="",
            supplied_auth={"user": "bob", "password": "hunter2", "token": "tok_ABC"},
        )
        secrets = set(getattr(g, "allowed_secrets", ()) or ())
        self.assertIn("hunter2", secrets)
        self.assertIn("tok_abc", secrets)
        self.assertIn("bob/hunter2", secrets)

    def test_format_cookie_token(self) -> None:
        text = format_supplied_auth_brief({"token": "Cookie: sid=1"})
        self.assertIn("Cookie: sid=1", text)
        self.assertNotIn("Authorization: Bearer Cookie", text)


class HuntHardStopCopyTests(unittest.TestCase):
    def test_src_label_english(self) -> None:
        from atkbrain_native import set_locale
        from atkbrain_native import hunt_hard_stop_info
        prev = set_locale("en")
        try:
            info = hunt_hard_stop_info("src", lang="en")
            self.assertIn("Hard stop", info["label"])
            self.assertNotIn("硬停", info["label"])
            for c in info["conditions"]:
                self.assertNotIn("硬停", c)
                self.assertNotIn("记失败", c)
        finally:
            set_locale(prev or "zh")


if __name__ == "__main__":
    unittest.main()
