"""SSRF 探测面按地址类拒绝；超时 oracle 不能 hop_auth。不拉黑 RFC1918 常见网关。"""
from __future__ import annotations

import unittest

from atkbrain_native import (
    hop_auth_eligible,
    hosts_from_capability_observation,
    is_ssrf_canary_host,
    junk_hop_auth_host,
    node_is_live_intranet,
    ssrf_evidence_is_oracle_only,
)


class SsrfCanaryHostTests(unittest.TestCase):
    def test_metadata_and_link_local(self) -> None:
        for h in (
            "169.254.169.254",
            "169.254.169.253",
            "metadata.google.internal",
            "100.100.100.200",
        ):
            self.assertTrue(is_ssrf_canary_host(h), h)

    def test_rfc1918_gateway_not_canary(self) -> None:
        for h in ("10.0.0.1", "10.255.255.1", "172.17.0.1", "192.168.1.1"):
            self.assertFalse(is_ssrf_canary_host(h), h)

    def test_documentation_testnet(self) -> None:
        for h in ("192.0.2.1", "198.51.100.5", "203.0.113.9"):
            self.assertTrue(is_ssrf_canary_host(h), h)

    def test_nip_io_unwrap(self) -> None:
        self.assertTrue(is_ssrf_canary_host("169.254.169.254.nip.io"))
        self.assertTrue(is_ssrf_canary_host("169-254-169-254.nip.io"))

    def test_real_intranet_not_canary(self) -> None:
        for h in ("10.0.166.106", "10.12.34.56", "192.168.10.25", "172.16.8.9"):
            self.assertFalse(is_ssrf_canary_host(h), h)


class OracleOnlyTests(unittest.TestCase):
    def test_timeout_is_oracle(self) -> None:
        self.assertTrue(ssrf_evidence_is_oracle_only(
            '422 profile_unreachable "Connection timeout" fetch;dur=3003ms'
        ))
        self.assertTrue(ssrf_evidence_is_oracle_only(
            '{"shouldNofollow":true}'
        ))
        self.assertTrue(ssrf_evidence_is_oracle_only(""))
        self.assertTrue(ssrf_evidence_is_oracle_only("via verified capability output"))

    def test_login_page_is_live(self) -> None:
        self.assertFalse(ssrf_evidence_is_oracle_only(
            "<html><title>Login</title><form>username password</form></html>"
        ))


class AbsorbAndHopTests(unittest.TestCase):
    def test_absorb_skips_imds_in_ssrf_url(self) -> None:
        got = hosts_from_capability_observation(
            url="https://shop.example/api",
            data='{"profile":"https://169.254.169.254/latest/meta-data/"}',
            output="<html><title>Login</title><form>username</form></html>" * 2,
        )
        self.assertNotIn("169.254.169.254", got)

    def test_probe_payload_without_live_inner_not_absorbed(self) -> None:
        got = hosts_from_capability_observation(
            url="https://shop.example/api",
            data='{"profile":"https://10.12.34.56/"}',
            output='{"error":"profile_malformed"}',
        )
        self.assertNotIn("10.12.34.56", got)

    def test_live_inner_rfc1918_is_absorbed(self) -> None:
        got = hosts_from_capability_observation(
            url="https://shop.example/api",
            data='{"profile":"https://10.12.34.56/admin"}',
            output="<html><title>Login</title><form>username password</form></html>" * 2,
        )
        self.assertIn("10.12.34.56", got)

    def test_hop_auth_skips_canary_even_if_via_live(self) -> None:
        node = {
            "key": "info:scope-expanded:169.254.169.254",
            "type": "info",
            "title": "内网资产 169.254.169.254 加入 Scope",
            "tags": ["via-live", "ssrf", "scope-expanded", "host:169.254.169.254"],
        }
        self.assertTrue(junk_hop_auth_host("169.254.169.254", None))
        self.assertFalse(hop_auth_eligible(node, None))
        self.assertFalse(node_is_live_intranet(node))

    def test_gadget_ignores_search_page_ssrf_word(self) -> None:
        from atkbrain_native import _node_looks_like_gadget
        blob = (
            "auto from http_request https://html.duckduckgo.com/html/"
            "?q=Shopify+UCP+MCP+ucp-agent+profile+SSRF status=0"
        )
        self.assertFalse(_node_looks_like_gadget(blob, set(), "HTTP 443"))
        self.assertTrue(_node_looks_like_gadget("UCP profile SSRF", {"ssrf"}, "mcp ssrf"))


if __name__ == "__main__":
    unittest.main()
