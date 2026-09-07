"""当前入口以外的私网 IP 视为越界；邻题优先于误入 Scope 的同网段地址。"""
from __future__ import annotations

import unittest

from atkbrain.scope import Scope, is_private_ip, unauthorized_peer_endpoint, unauthorized_private_host


class UnauthorizedPrivateHostTests(unittest.TestCase):
    def test_current_entry_allowed(self):
        scope = Scope(targets=["10.0.189.56"], ips=["10.0.189.56"])
        self.assertIsNone(unauthorized_private_host(
            "10.0.189.56", scope, primary="10.0.189.56", peers={"10.0.189.57"},
        ))

    def test_peer_blocked_even_if_listed_in_scope(self):
        scope = Scope(targets=["10.0.189.56"], ips=["10.0.189.56", "10.0.189.57"])
        why = unauthorized_private_host(
            "10.0.189.57", scope, primary="10.0.189.56", peers={"10.0.189.57"},
        )
        self.assertIsNotNone(why)
        self.assertIn("其它题目", why)

    def test_unrelated_private_blocked(self):
        scope = Scope(targets=["10.0.189.56"], ips=["10.0.189.56"])
        why = unauthorized_private_host("10.0.189.58", scope, primary="10.0.189.56")
        self.assertIsNotNone(why)
        self.assertIn("当前入口", why)

    def test_public_and_infra_hosts_not_blocked(self):
        scope = Scope(targets=["10.0.189.56"])
        self.assertIsNone(unauthorized_private_host("pypi.org", scope, primary="10.0.189.56"))
        self.assertIsNone(unauthorized_private_host("github.com", scope, primary="10.0.189.56"))
        self.assertTrue(is_private_ip("10.0.189.56"))
        self.assertFalse(is_private_ip("pypi.org"))

    def test_verified_pivot_in_scope_allowed_when_not_peer(self):
        scope = Scope(targets=["10.0.189.56"], ips=["10.0.189.56", "10.0.189.10"])
        self.assertIsNone(unauthorized_private_host(
            "10.0.189.10", scope, primary="10.0.189.56", peers={"10.0.189.57"},
        ))


class PivotExpandTests(unittest.IsolatedAsyncioTestCase):
    async def test_ssrf_expand_docker_bridge_not_treated_as_peer(self):
        from atkbrain.scope_pivot import try_expand_scope, ssrf_gateway_hosts
        scope = Scope(targets=["10.0.167.89"], ips=["10.0.167.89"])
        res = await try_expand_scope(
            "", scope,
            from_host="10.0.167.89", to_host="172.19.0.2",
            mechanism="ssrf_direct",
            evidence="open proxy returned 200 for neighbor http",
            verified=True,
        )
        self.assertTrue(res.get("expanded"), res)
        self.assertIn("172.19.0.2", list(scope.ips))
        self.assertIsNone(unauthorized_private_host(
            "172.19.0.2", scope, primary="10.0.167.89", peers={"10.0.167.88"},
        ))
        hosts = ssrf_gateway_hosts({
            "nodes": [{
                "key": "info:scope-expanded:172.19.0.2",
                "title": "内网资产",
                "detail": "ssrf_direct via entry",
                "tags": ["ssrf", "host:172.19.0.2"],
            }],
        })
        self.assertIn("172.19.0.2", hosts)

    async def test_expand_rejects_public_and_unknown_mechanism(self):
        from atkbrain.scope_pivot import try_expand_scope
        scope = Scope(targets=["10.0.167.89"], ips=["10.0.167.89"])
        pub = await try_expand_scope(
            "", scope, from_host="10.0.167.89", to_host="8.8.8.8",
            mechanism="ssrf_direct", evidence="x", verified=True,
        )
        self.assertFalse(pub.get("expanded"))
        bad = await try_expand_scope(
            "", scope, from_host="10.0.167.89", to_host="172.19.0.3",
            mechanism="guess", evidence="x", verified=True,
        )
        self.assertFalse(bad.get("expanded"))


class PeerEndpointTests(unittest.TestCase):
    def test_sibling_port_on_same_ip_blocked(self):
        why = unauthorized_peer_endpoint(
            "10.0.182.81", 9104,
            primary="10.0.182.81", primary_port=9105,
            peer_addrs={"10.0.182.81:9104", "10.0.182.80:9107"},
        )
        self.assertIsNotNone(why)
        self.assertIn("其它题目", why)

    def test_assigned_port_on_same_ip_allowed(self):
        why = unauthorized_peer_endpoint(
            "10.0.182.81", 9105,
            primary="10.0.182.81", primary_port=9105,
            peer_addrs={"10.0.182.81:9104", "10.0.182.80:9107"},
        )
        self.assertIsNone(why)

    def test_sibling_ip_blocked(self):
        why = unauthorized_peer_endpoint(
            "10.0.182.80", 9107,
            primary="10.0.182.81", primary_port=9105,
            peer_addrs={"10.0.182.80:9107"},
            peers={"10.0.182.80"},
        )
        self.assertIsNotNone(why)

    def test_own_second_addr_allowed_even_if_listed_as_peer(self):
        why = unauthorized_peer_endpoint(
            "10.0.182.90", 81,
            primary="10.0.182.81", primary_port=80,
            peer_addrs={"10.0.182.90:81"},
            peers={"10.0.182.90"},
            own_addrs={"10.0.182.81:80", "10.0.182.90:81"},
        )
        self.assertIsNone(why)

    def test_own_second_host_allowed_by_private_host_gate(self):
        scope = Scope(targets=["10.0.182.81"], ips=["10.0.182.81", "10.0.182.90"])
        self.assertIsNone(unauthorized_private_host(
            "10.0.182.90", scope, primary="10.0.182.81",
            peers={"10.0.182.90"},
            own_hosts={"10.0.182.81", "10.0.182.90"},
        ))


class SsrfEncodeGuardTests(unittest.TestCase):
    def setUp(self):
        from atkbrain.exec.guard import Guard
        self.g = Guard(Scope(targets=["10.0.167.89"], ips=["10.0.167.89"]))
        self.g.peer_hosts = {"10.0.167.88"}

    def test_python_quote_helper_then_curl_entry_allowed(self):
        cmd = (
            'python3 -c \'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))\' '
            '"http://172.19.0.3:8080/"; '
            'curl -s --max-time 4 "http://10.0.167.89/proxy.php?url=x"'
        )
        d = self.g.check_command(cmd)
        self.assertTrue(d.allow, d.reason)

    def test_direct_curl_neighbor_still_blocked(self):
        d = self.g.check_command("curl -s http://172.19.0.3:8080/")
        self.assertFalse(d.allow)
        self.assertIn("越界", d.reason)

    def test_peer_entry_still_blocked(self):
        d = self.g.check_command("curl -s http://10.0.167.88/")
        self.assertFalse(d.allow)


class CtfMegaDictGuardTests(unittest.TestCase):
    def setUp(self):
        from atkbrain.exec.guard import Guard
        self.scope = Scope(targets=["10.0.165.64"], ips=["10.0.165.64"])
        self.ctf = Guard(self.scope, "", objective="flag")
        self.rt = Guard(self.scope, "", objective="redteam")

    def test_ctf_blocks_rockyou_hash_crack(self):
        d = self.ctf.check_command(
            "python3 - <<'EOF'\nopen('/usr/share/wordlists/rockyou.txt')\nEOF"
        )
        self.assertFalse(d.allow)
        self.assertIn("超级大字典", d.reason)

    def test_ctf_blocks_hashcat(self):
        d = self.ctf.check_command("hashcat -m 1400 hash.txt rockyou.txt")
        self.assertFalse(d.allow)

    def test_ctf_allows_medium_path_wordlist(self):
        d = self.ctf.check_command(
            "ffuf -u http://10.0.165.64/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
        )
        self.assertTrue(d.allow, d.reason)

    def test_ctf_allows_tiny_default_creds(self):
        d = self.ctf.check_command(
            "python3 -c 'print(\"admin\",\"admin\")'"
        )
        self.assertTrue(d.allow, d.reason)

    def test_redteam_still_allows_rockyou(self):
        d = self.rt.check_command(
            "python3 - <<'EOF'\nopen('/usr/share/wordlists/rockyou.txt')\nEOF"
        )
        self.assertTrue(d.allow, d.reason)


if __name__ == "__main__":
    unittest.main()
