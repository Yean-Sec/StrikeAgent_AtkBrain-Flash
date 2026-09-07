"""集群批量导入：按 host 去重 + 进度快照。"""
from __future__ import annotations

import unittest

from atkbrain.cluster import _hosts_from_assets, import_snapshot


class HostDedupTests(unittest.TestCase):
    def test_same_host_merges(self):
        by, ports = _hosts_from_assets([
            "https://zz26855.com/",
            "zz26855.com",
            "https://zz88442.com/",
        ])
        self.assertEqual(set(by), {"zz26855.com", "zz88442.com"})
        self.assertIn(443, ports["zz26855.com"])

    def test_empty_snapshot_is_idle(self):
        snap = import_snapshot("p_missing")
        self.assertEqual(snap.get("phase"), "idle")
        self.assertEqual(snap.get("done"), 0)

    def test_orphaned_spawn_reads_as_paused(self):
        import asyncio
        from atkbrain import cluster
        pid = "p_test_pause_orphan"
        cluster._IMPORT[pid] = {"phase": "spawn", "done": 10, "total": 100, "message": "已创建 a"}
        cluster._IMPORT_TASKS.pop(pid, None)
        try:
            snap = asyncio.run(cluster.import_progress_for(pid))
            self.assertEqual(snap.get("phase"), "paused")
            self.assertFalse(snap.get("importing"))
        finally:
            cluster._IMPORT.pop(pid, None)

    def test_fold_www_and_scheme_and_path(self):
        from atkbrain.cluster import compact_assets_by_host, fold_host_keys, preferred_host
        self.assertEqual(preferred_host("www.zz26855.com"), "zz26855.com")
        self.assertIn("zz26855.com", fold_host_keys("www.zz26855.com"))
        kept, skipped = compact_assets_by_host([
            "https://zz26855.com/",
            "http://zz26855.com/login",
            "https://www.zz26855.com/admin",
            "zz26855.com",
            "https://zz88442.com/",
        ])
        # 同 FQDN 的 443 与 80 都保留；www/路径重复丢掉
        self.assertEqual(len(kept), 3)
        self.assertGreaterEqual(len(skipped), 2)
        by, ports = _hosts_from_assets(kept)
        self.assertEqual(set(by), {"zz26855.com", "zz88442.com"})
        self.assertEqual(ports["zz26855.com"], {80, 443})

    def test_same_host_keeps_distinct_ports(self):
        from atkbrain.cluster import compact_assets_by_host
        kept, skipped = compact_assets_by_host([
            "a.example.com:80",
            "a.example.com:8080",
            "http://a.example.com/",
            "https://www.a.example.com/",
        ])
        self.assertEqual(len(kept), 3)  # 80, 8080, 443
        self.assertGreaterEqual(len(skipped), 1)
        by, ports = _hosts_from_assets(kept)
        self.assertEqual(set(by), {"a.example.com"})
        self.assertEqual(ports["a.example.com"], {80, 8080, 443})

    def test_group_same_origin_ip(self):
        from atkbrain.cluster import _hosts_from_assets, group_hosts_by_origin_ips
        by, ports = _hosts_from_assets([
            "https://a.example.com/",
            "https://b.example.com:8443/",
            "10.0.0.8:8080",
        ])
        groups = group_hosts_by_origin_ips(by, ports, {
            "a.example.com": {"10.0.0.8"},
            "b.example.com": {"10.0.0.8"},
            "10.0.0.8": {"10.0.0.8"},
        })
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g.primary, "a.example.com")
        self.assertEqual(set(g.vhosts), {"a.example.com", "b.example.com", "10.0.0.8"})
        self.assertEqual(set(g.ips), {"10.0.0.8"})
        self.assertEqual(set(g.ports), {443, 8443, 8080})

    def test_group_cdn_only_not_merged(self):
        from atkbrain.cluster import _hosts_from_assets, group_hosts_by_origin_ips
        by, ports = _hosts_from_assets([
            "https://cdn-a.example.com/",
            "https://cdn-b.example.com/",
        ])
        groups = group_hosts_by_origin_ips(by, ports, {
            "cdn-a.example.com": set(),
            "cdn-b.example.com": set(),
        })
        self.assertEqual(len(groups), 2)
        primaries = {g.primary for g in groups}
        self.assertEqual(primaries, {"cdn-a.example.com", "cdn-b.example.com"})

    def test_group_literal_ip_with_domain(self):
        from atkbrain.cluster import _hosts_from_assets, group_hosts_by_origin_ips
        by, ports = _hosts_from_assets(["1.2.3.4:80", "foo.internal:443"])
        groups = group_hosts_by_origin_ips(by, ports, {
            "1.2.3.4": {"1.2.3.4"},
            "foo.internal": {"1.2.3.4"},
        })
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].primary, "foo.internal")
        self.assertIn("1.2.3.4", groups[0].vhosts)

    def test_parse_skips_comments_and_bom(self):
        from atkbrain.cluster import parse_asset_lines
        lines = parse_asset_lines("\ufeff# header\nhttps://a.com/\n; skip\nhttps://b.com")
        self.assertEqual(lines, ["https://a.com/", "https://b.com"])

    def test_parse_keeps_url_query_comma(self):
        from atkbrain.cluster import parse_asset_lines
        lines = parse_asset_lines("https://a.com/x?a=1,b=2\nhost1.com,host2.com")
        self.assertEqual(lines[0], "https://a.com/x?a=1,b=2")
        self.assertEqual(lines[1:], ["host1.com", "host2.com"])

    def test_import_skips_existing_host_variants(self):
        from atkbrain.cluster import fold_host_keys, _normalize_asset
        known: set[str] = set()
        for t in ["zz26855.com", "www.already.com"]:
            known |= fold_host_keys(t)
        incoming = [
            "https://www.zz26855.com/path",
            "http://zz26855.com",
            "https://already.com/login",
            "https://brand-new.example/",
        ]
        added, skipped = [], []
        for raw in incoming:
            keys = fold_host_keys(_normalize_asset(raw)["host"])
            if keys & known:
                skipped.append(raw)
            else:
                known |= keys
                added.append(raw)
        self.assertEqual(added, ["https://brand-new.example/"])
        self.assertEqual(len(skipped), 3)

    def test_ip_not_merged_with_domain(self):
        from atkbrain.cluster import compact_assets_by_host
        kept, _ = compact_assets_by_host(["https://10.0.0.8/", "10.0.0.8.example.com"])
        self.assertEqual(len(kept), 2)


if __name__ == "__main__":
    unittest.main()
