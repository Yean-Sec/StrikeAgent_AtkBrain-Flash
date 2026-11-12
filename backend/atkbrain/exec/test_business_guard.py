"""红队/SRC 禁止把写操作落到真实用户、资金、库存；http 与 https 同一套。"""
from __future__ import annotations

import unittest

from ..agents.context import AgentContext
from atkbrain_native import Guard, target_destructive_reason
from atkbrain_native import assert_safe_project_target
from atkbrain_native import Scope, sensitive_attack_reason, sensitive_domain_reason


def _scope() -> Scope:
    return Scope(targets=["example.com"], allow_subdomains=False, mode="strict")


class SqlWriteAllTracksTests(unittest.TestCase):
    def test_drop_blocked_everywhere(self) -> None:
        cmd = "curl -s 'https://example.com/q?id=1;DROP TABLE users--'"
        for obj in ("src", "getshell", "flag"):
            self.assertIsNotNone(target_destructive_reason(cmd, objective=obj), obj)

    def test_insert_and_outfile_all_tracks(self) -> None:
        ins = "POST https://example.com/q data=INSERT INTO users VALUES(1)"
        outf = "id=1 UNION SELECT 1 INTO OUTFILE '/tmp/x'"
        for obj in ("src", "getshell", "flag"):
            self.assertIsNotNone(target_destructive_reason(ins, objective=obj), obj)
            self.assertIsNotNone(target_destructive_reason(outf, objective=obj), obj)

    def test_update_in_http_body(self) -> None:
        blob = "POST https://example.com/api UPDATE users SET password='x'"
        self.assertIsNotNone(target_destructive_reason(blob, objective="src"))


class IdentityMoneyFloodTests(unittest.TestCase):
    def test_https_reset_admin_blocked_src(self) -> None:
        blob = (
            "POST https://example.com/reset-password "
            "username=admin&new_password=Hacked1"
        )
        why = target_destructive_reason(blob, objective="src")
        self.assertIsNotNone(why)
        self.assertIn("口令", why or "")

    def test_https_reset_admin_blocked_redteam(self) -> None:
        blob = (
            "POST https://example.com/reset-password "
            "username=admin&new_password=Hacked1"
        )
        self.assertIsNotNone(target_destructive_reason(blob, objective="getshell"))

    def test_login_password_allowed(self) -> None:
        blob = "POST https://example.com/login username=admin&password=secret"
        self.assertIsNone(target_destructive_reason(blob, objective="src"))

    def test_pay_submit_blocked(self) -> None:
        blob = "POST https://example.com/pay amount=0.01&order_id=9"
        why = target_destructive_reason(blob, objective="src")
        self.assertIsNotNone(why)
        self.assertIn("支付", why or "")

    def test_sms_loop_blocked(self) -> None:
        blob = "for i in {1..50}; do curl -s https://example.com/sms/send-code; done"
        why = target_destructive_reason(blob, objective="src")
        self.assertIsNotNone(why)

    def test_ab_blocked(self) -> None:
        blob = "ab -n 100 -c 20 https://example.com/checkout"
        self.assertIsNotNone(target_destructive_reason(blob, objective="src"))

    def test_xargs_p20_blocked(self) -> None:
        blob = "seq 1 20 | xargs -P 20 -I{} curl -s https://example.com/pay"
        self.assertIsNotNone(target_destructive_reason(blob, objective="src"))

    def test_ctf_skips_business_rules(self) -> None:
        reset = (
            "POST https://example.com/reset-password "
            "username=admin&new_password=Hacked1"
        )
        self.assertIsNone(target_destructive_reason(reset, objective="flag"))
        self.assertIsNone(target_destructive_reason("ab -n 100 https://example.com/", objective="flag"))
        pay = "POST https://example.com/pay amount=1"
        self.assertIsNone(target_destructive_reason(pay, objective="flag"))

    def test_guard_curl_https_reset(self) -> None:
        g = Guard(_scope(), objective="src")
        d = g.check_command(
            "curl -s -X POST https://example.com/reset-password "
            "-d 'username=admin&new_password=x'"
        )
        self.assertFalse(d.allow, d.reason)


class HttpRequestHttpsTests(unittest.IsolatedAsyncioTestCase):
    async def test_https_reset_body_blocked(self) -> None:
        sc = _scope()
        ctx = AgentContext(
            project_id="p_test",
            workspace_dir="/tmp",
            loot_dir="/tmp",
            scope=sc,
            guard=Guard(sc, objective="src"),
            objective="src",
        )
        res = await ctx.http(
            "https://example.com/reset-password",
            method="POST",
            data="username=admin&new_password=Hacked1",
        )
        self.assertTrue(res.get("blocked"), res)
        self.assertIn("口令", str(res.get("error") or ""))

    async def test_https_sql_body_blocked(self) -> None:
        sc = _scope()
        ctx = AgentContext(
            project_id="p_test",
            workspace_dir="/tmp",
            loot_dir="/tmp",
            scope=sc,
            guard=Guard(sc, objective="src"),
            objective="src",
        )
        res = await ctx.http(
            "https://example.com/q",
            method="POST",
            data="id=1; DROP TABLE users--",
        )
        self.assertTrue(res.get("blocked"), res)
        self.assertIn("DROP", str(res.get("error") or ""))

    async def test_https_login_allowed_by_destructive_gate(self) -> None:
        why = target_destructive_reason(
            "POST https://example.com/login username=admin&password=secret",
            objective="src",
        )
        self.assertIsNone(why)


class SensitiveDomainTests(unittest.TestCase):
    def test_protected_suffixes(self) -> None:
        for host in (
            "www.mit.edu", "library.edu.cn", "agency.gov", "ministry.gov.cn",
            "cam.ac.uk", "www.kantei.go.jp", "army.mil", "school.edu.au",
        ):
            self.assertIsNotNone(sensitive_domain_reason(host), host)

    def test_ordinary_names_pass(self) -> None:
        for host in ("example.com", "education.com", "governor.io", "go.com", "gov.example.com"):
            self.assertIsNone(sensitive_domain_reason(host), host)

    def test_doc_host_can_be_read_but_not_hunted(self) -> None:
        self.assertIsNotNone(sensitive_domain_reason("nvd.nist.gov"))
        self.assertIsNone(sensitive_attack_reason("nvd.nist.gov"))
        with self.assertRaises(ValueError):
            assert_safe_project_target("https://www.mit.edu/admissions")

    def test_scope_cannot_override(self) -> None:
        g = Guard(Scope(targets=["www.mit.edu"], mode="strict"), objective="src")
        d = g.check_command("curl -s https://www.mit.edu/")
        self.assertFalse(d.allow, d.reason)
        g_ctf = Guard(Scope(targets=["agency.gov"], mode="strict"), objective="flag")
        d2 = g_ctf.check_command("curl -s https://agency.gov/")
        self.assertFalse(d2.allow, d2.reason)

    def test_ssrf_payload_to_edu_blocked(self) -> None:
        g = Guard(Scope(targets=["example.com"], mode="strict"), objective="src")
        d = g.check_command(
            "curl -s https://example.com/fetch -d 'url=http://library.edu.cn/'"
        )
        self.assertFalse(d.allow, d.reason)


class RedteamTightenTests(unittest.TestCase):
    def test_hydra_blocked_on_src_and_redteam(self) -> None:
        cmd = "hydra -L users.txt -P pass.txt https://example.com/login"
        self.assertIsNotNone(target_destructive_reason(cmd, objective="src"))
        self.assertIsNotNone(target_destructive_reason(cmd, objective="getshell"))
        self.assertIsNone(target_destructive_reason(cmd, objective="flag"))

    def test_persistence_blocked(self) -> None:
        self.assertIsNotNone(target_destructive_reason(
            "echo x >> /root/.ssh/authorized_keys", objective="src",
        ))
        self.assertIsNotNone(target_destructive_reason(
            "crontab -l", objective="redteam",
        ))
        self.assertIsNone(target_destructive_reason("crontab -l", objective="flag"))


if __name__ == "__main__":
    unittest.main()
