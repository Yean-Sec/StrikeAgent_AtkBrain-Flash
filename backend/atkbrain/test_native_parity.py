"""已删掉的 Python 判断，直接对 Rust 扩展断言。"""
from __future__ import annotations

import unittest
from decimal import Decimal

import atkbrain_native as native


class NativeParityTests(unittest.TestCase):
    def test_cvss(self) -> None:
        self.assertEqual(Decimal(str(native.roundup(Decimal("4.02")))), Decimal("4.1"))
        got = native.base_score(native.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertEqual(got.score, 9.8)
        self.assertEqual(got.rating, "critical")

    def test_scope_and_guard(self) -> None:
        from atkbrain_native import Guard, Scope
        self.assertIsNotNone(native.sensitive_domain_reason("a.gov.cn"))
        self.assertIsNone(native.sensitive_domain_reason("example.com"))
        scope = Scope(targets=["example.com"], allow_subdomains=True)
        self.assertTrue(scope.host_in_scope("a.example.com"))
        self.assertFalse(scope.host_in_scope("other.com"))
        decision = Guard(scope, objective="src").check_command("curl -s https://www.mit.edu/")
        self.assertFalse(decision.allow)

    def test_clocks_status_objective(self) -> None:
        self.assertFalse(native.hunt_should_reset(hard_restart=False, completion_reason="entry_dead", has_live_foothold=True))
        self.assertEqual(native.displayed_status("running", running=False), "idle")
        self.assertEqual(native.format_duration(0, "en"), "unlimited")
        self.assertEqual(native.normalize_objective("src"), "agent")
        self.assertTrue(native.ctf_full_score(flags_correct=1, flags_needed=1))
        self.assertTrue(native.is_ssrf_canary_host("169.254.169.254"))
        self.assertFalse(native.is_ssrf_canary_host("10.1.2.3"))

    def test_password_and_turn_close(self) -> None:
        self.assertEqual(native.password_policy_code("short"), "len")
        self.assertIsNone(native.password_policy_code("GoodPass1"))
        pw = native.generate_bootstrap_password(8)
        self.assertEqual(len(pw), 8)
        self.assertTrue(native.role_wrote_turn_done("本轮完成。", role="lead"))
        self.assertFalse(native.role_wrote_turn_done("本轮完成。", role="finding-review"))
        self.assertTrue(native.turn_must_close(900, 900))
