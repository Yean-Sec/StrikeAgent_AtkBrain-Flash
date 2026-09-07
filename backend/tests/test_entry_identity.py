"""入口身份：题面/图预期栈 vs 当前首页栈。与具体题目路径无关。"""
from __future__ import annotations

import unittest

from atkbrain.engine.entry_identity import (
    classify_entry_identity,
    infer_families,
    parse_http_identity,
)


class FamilyInferenceTests(unittest.TestCase):
    def test_werkzeug_is_python_web(self):
        self.assertEqual(infer_families("Server: Werkzeug/3.0 Flask"), {"python-web"})

    def test_php_paths_and_powered_by(self):
        self.assertIn("php", infer_families("X-Powered-By: PHP/8.1 /login.php Apache"))

    def test_no_false_philosophy(self):
        self.assertNotIn("php", infer_families("a philosophy of logistics"))


class IdentityClassifyTests(unittest.TestCase):
    def test_php_graph_vs_flask_live_mismatch(self):
        graph = {
            "nodes": [
                {"key": "danger:proxy.php", "title": "proxy.php", "type": "danger", "tags": ["php", "ssrf"]},
                {"key": "cred:admin", "title": "admin/1qaz", "type": "credential", "tags": ["login"]},
            ],
        }
        live = parse_http_identity(
            b"<html><title>Smart Logistics</title></html>",
            {"Server": "Werkzeug/3.0.3 Python/3.11"},
            200,
        )
        r = classify_entry_identity(brief="企业官网多层", graph=graph, live=live)
        self.assertTrue(r["mismatch"])
        self.assertIn("php", r["expected"])
        self.assertIn("python-web", r["live"])

    def test_contaminated_php_neighbor_does_not_mismatch_flask_entry(self):
        graph = {
            "nodes": [
                {"key": "vuln:ssrf", "title": "flask probe ssrf", "type": "vuln", "tags": ["ssrf", "flask"]},
                {"key": "danger:imghub.php", "title": "neighbor php xxe", "type": "danger", "tags": ["php", "xxe"]},
            ],
        }
        live = parse_http_identity(
            b"<html><title>Asset Probe</title></html>",
            {"Server": "Werkzeug/2.3"},
            200,
        )
        r = classify_entry_identity(brief="internal flask probe", graph=graph, live=live)
        self.assertFalse(r["mismatch"])

    def test_unknown_live_is_not_mismatch(self):
        r = classify_entry_identity(
            brief="corporate site",
            graph={"nodes": [{"key": "svc:80", "title": "Apache/PHP", "type": "service", "tags": ["php"]}]},
            live={"status": 200, "headers": {}, "server": "", "title": "Welcome", "body": "ok"},
        )
        self.assertFalse(r["mismatch"])


if __name__ == "__main__":
    unittest.main()
