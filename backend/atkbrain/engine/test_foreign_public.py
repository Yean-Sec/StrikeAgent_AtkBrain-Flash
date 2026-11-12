"""作业对象是填写主机的注册域；同品牌其它 TLD 不能当第一跳。"""
from __future__ import annotations

import unittest

from atkbrain_native import Guard
from atkbrain_native import Scope, unauthorized_public_host


class ForeignPublicHostTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = Scope(targets=["zenn.dev"], allow_subdomains=False, mode="strict")

    def test_embed_zenn_studio_blocked(self) -> None:
        why = unauthorized_public_host("embed.zenn.studio", self.scope, primary="zenn.dev")
        self.assertIsNotNone(why)
        self.assertIn("zenn.dev", why or "")

    def test_static_zenn_studio_blocked(self) -> None:
        self.assertIsNotNone(
            unauthorized_public_host("static.zenn.studio", self.scope, primary="zenn.dev")
        )

    def test_only_written_host_allowed(self) -> None:
        self.assertIsNone(unauthorized_public_host("zenn.dev", self.scope, primary="zenn.dev"))
        for h in ("www.zenn.dev", "info.zenn.dev"):
            self.assertIsNotNone(
                unauthorized_public_host(h, self.scope, primary="zenn.dev"), h,
            )

    def test_infra_and_oob_allowed(self) -> None:
        for h in (
            "github.com",
            "gist.github.com",
            "nvd.nist.gov",
            "abc.interact.sh",
            "ipv4.icanhazip.com",
        ):
            self.assertIsNone(
                unauthorized_public_host(h, self.scope, primary="zenn.dev"), h,
            )

    def test_code_attribute_not_host(self) -> None:
        from atkbrain_native import public_hosts_in_text
        got = public_hosts_in_text("data = json.load(sys.stdin)")
        self.assertNotIn("json.load", got)
        self.assertNotIn("sys.stdin", got)
        self.assertIn("example.com", public_hosts_in_text("curl https://example.com/"))

    def test_path_suffix_not_host(self) -> None:
        from atkbrain_native import public_hosts_in_text
        got = public_hosts_in_text("http:zenn.dev:443/robots.txt")
        self.assertIn("zenn.dev", got)
        self.assertNotIn("robots.txt", got)
        self.assertIsNone(
            unauthorized_public_host("zenn.dev", self.scope, primary="zenn.dev")
        )

    def test_embed_key_extracted(self) -> None:
        from atkbrain_native import public_hosts_in_text
        got = public_hosts_in_text("svc:443/http@embed.zenn.studio")
        self.assertIn("embed.zenn.studio", got)

    def test_private_ip_skipped(self) -> None:
        self.assertIsNone(
            unauthorized_public_host("10.0.166.106", self.scope, primary="zenn.dev")
        )

    def test_other_job_object_same_rule(self) -> None:
        s = Scope(targets=["hjkgaming.com"], allow_subdomains=False, mode="strict")
        self.assertIsNotNone(
            unauthorized_public_host("www.hjkgaming.com", s, primary="hjkgaming.com")
        )
        for h in ("embed.zenn.studio", "evil.example.net", "cdn.other.io"):
            self.assertIsNotNone(
                unauthorized_public_host(h, s, primary="hjkgaming.com"), h,
            )
        s = Scope(targets=["zenn.dev"], allow_subdomains=True, mode="strict")
        self.assertIsNone(unauthorized_public_host("api.zenn.dev", s, primary="zenn.dev"))
        self.assertIsNotNone(
            unauthorized_public_host("embed.zenn.studio", s, primary="zenn.dev")
        )


class GuardForeignPublicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.guard = Guard(
            Scope(targets=["zenn.dev"], allow_subdomains=False, mode="strict"),
            objective="getshell",
        )

    def test_curl_embed_blocked(self) -> None:
        d = self.guard.check_command(
            "curl -s https://embed.zenn.studio/api/link-data?url=http://169.254.169.254/"
        )
        self.assertFalse(d.allow)
        self.assertIn("embed.zenn.studio", d.reason)

    def test_curl_zenn_dev_allowed(self) -> None:
        d = self.guard.check_command("curl -s https://zenn.dev/")
        self.assertTrue(d.allow, d.reason)


if __name__ == "__main__":
    unittest.main()
