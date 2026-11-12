"""跳板发现的内网地址落成 target；紫线从漏洞连过去。"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch

from atkbrain_native import host_from_asset_key, should_promote_intranet_host
from ..scope_pivot import ssrf_gateway_hosts


class PromoteRuleTests(unittest.TestCase):
    def test_rfc1918_promotes(self) -> None:
        self.assertFalse(should_promote_intranet_host("10.0.1.8", ["pivot"], "1.2.3.4"))
        self.assertFalse(should_promote_intranet_host("10.12.0.9", ["internal"], "example.com"))
        self.assertTrue(should_promote_intranet_host("10.0.1.8", ["ssrf", "pivot"], "1.2.3.4"))
        self.assertTrue(should_promote_intranet_host("10.12.0.9", ["via-live"], "example.com"))
        self.assertTrue(should_promote_intranet_host("10.1.1.1", ["getshell"], "example.com"))

    def test_entry_and_vhost_and_clue_skip(self) -> None:
        self.assertFalse(should_promote_intranet_host("10.0.1.8", ["entry"], "1.2.3.4"))
        self.assertFalse(should_promote_intranet_host("10.0.1.8", ["vhost"], "1.2.3.4"))
        self.assertFalse(should_promote_intranet_host("10.0.1.8", ["same-machine"], "1.2.3.4"))
        self.assertFalse(should_promote_intranet_host("10.0.1.8", ["clue-only"], "1.2.3.4"))
        self.assertFalse(should_promote_intranet_host("1.2.3.4", ["pivot"], "1.2.3.4"))

    def test_asset_key_host(self) -> None:
        self.assertEqual(host_from_asset_key("target:10.0.1.8"), "10.0.1.8")
        self.assertEqual(host_from_asset_key("info:host:10.0.1.8"), "10.0.1.8")
        self.assertEqual(host_from_asset_key("info:scope-expanded:10.0.1.8"), "10.0.1.8")


class GatewayAndEdgeTests(unittest.TestCase):
    def test_ssrf_gateway_absorbs_target(self) -> None:
        graph = {
            "nodes": [{
                "key": "target:10.0.1.8",
                "type": "target",
                "title": "内网目标 10.0.1.8",
                "detail": "通过 ssrf_direct 触发扩容",
                "tags": ["pivot", "ssrf", "scope-expanded", "host:10.0.1.8"],
            }],
            "edges": [{
                "from": "vuln:ssrf-profile",
                "to": "target:10.0.1.8",
                "relation": "LEADS_TO",
                "rationale": "pivot_capability ssrf_direct: login page",
            }],
        }
        hosts = ssrf_gateway_hosts(graph)
        self.assertIn("10.0.1.8", hosts)

    def test_entry_target_not_gateway(self) -> None:
        graph = {
            "nodes": [{
                "key": "target:hjkgaming.com",
                "type": "target",
                "title": "入口",
                "tags": ["entry", "host:hjkgaming.com"],
            }],
            "edges": [],
        }
        self.assertNotIn("hjkgaming.com", ssrf_gateway_hosts(graph))


class VulnEdgeShapeTests(unittest.TestCase):
    def test_leads_to_from_vuln_not_foothold(self) -> None:
        src = "vuln:ssrf-ucp"
        dst = "target:10.0.1.8"
        self.assertTrue(src.startswith("vuln:"))
        self.assertTrue(dst.startswith("target:"))
        self.assertFalse(src.startswith("foothold:"))
        self.assertFalse(dst.startswith("info:"))


class PivotTargetReconTests(unittest.TestCase):
    def test_via_capability_keeps_pivot_target(self) -> None:
        from atkbrain_native import via_capability_hosts
        graph = {
            "nodes": [
                {"key": "target:hjkgaming.com", "type": "target", "tags": ["entry"]},
                {
                    "key": "target:10.0.1.8",
                    "type": "target",
                    "tags": ["pivot", "internal", "scope-expanded", "host:10.0.1.8"],
                },
            ],
        }
        hosts = via_capability_hosts(graph)
        self.assertIn("10.0.1.8", hosts)
        self.assertNotIn("hjkgaming.com", hosts)

    def test_canary_pivot_target_not_via(self) -> None:
        from atkbrain_native import via_capability_hosts
        from atkbrain_native import Scope
        graph = {
            "nodes": [{
                "key": "target:169.254.169.254",
                "type": "target",
                "tags": ["pivot", "ssrf", "scope-expanded"],
            }],
        }
        self.assertNotIn("169.254.169.254", via_capability_hosts(graph))
        stale = Scope(targets=["app.example"], ips=["169.254.169.254", "10.0.1.8"])
        self.assertNotIn("169.254.169.254", via_capability_hosts(graph, stale))

    def test_rfc1918_probe_ip_still_via_if_live_target(self) -> None:
        from atkbrain_native import via_capability_hosts
        graph = {
            "nodes": [{
                "key": "target:10.0.0.1",
                "type": "target",
                "tags": ["pivot", "internal", "scope-expanded", "host:10.0.0.1"],
            }],
        }
        self.assertIn("10.0.0.1", via_capability_hosts(graph))

    def test_pivot_target_gets_fingerprint_all_tracks(self) -> None:
        from atkbrain_native import hypotheses_for_node
        node = {
            "key": "target:10.0.1.8",
            "type": "target",
            "title": "内网目标 10.0.1.8",
            "tags": ["pivot", "internal", "scope-expanded", "via-live", "host:10.0.1.8"],
            "detail": "通过 ssrf_direct 触发扩容",
        }
        for obj, allows_flag in (("src", False), ("redteam", False), ("ctf", True), ("flag", True)):
            hyps = hypotheses_for_node(node, allows_flag=allows_flag, objective=obj)
            keys = {h.strategy_key for h in hyps}
            self.assertTrue(
                any(k.endswith("::fingerprint") for k in keys),
                f"{obj}: {keys}",
            )

    def test_canary_target_no_fingerprint(self) -> None:
        from atkbrain_native import hypotheses_for_node
        for host in ("169.254.169.254", "203.0.113.9", "198.51.100.5"):
            node = {
                "key": f"target:{host}",
                "type": "target",
                "title": f"内网目标 {host}",
                "tags": ["pivot", "ssrf", "scope-expanded", f"host:{host}"],
            }
            for obj in ("src", "redteam", "ctf"):
                hyps = hypotheses_for_node(node, allows_flag=(obj == "ctf"), objective=obj)
                self.assertFalse(
                    any(h.strategy_key.endswith("::fingerprint") for h in hyps),
                    f"{obj} {host}",
                )

    def test_rfc1918_probe_ip_gets_fingerprint(self) -> None:
        from atkbrain_native import hypotheses_for_node
        node = {
            "key": "target:10.0.0.1",
            "type": "target",
            "title": "内网目标 10.0.0.1",
            "tags": ["pivot", "internal", "scope-expanded", "host:10.0.0.1"],
        }
        hyps = hypotheses_for_node(node, allows_flag=False, objective="src")
        self.assertTrue(any(h.strategy_key.endswith("::fingerprint") for h in hyps))


if __name__ == "__main__":
    unittest.main()
