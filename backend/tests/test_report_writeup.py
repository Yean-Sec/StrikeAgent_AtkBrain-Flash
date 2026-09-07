"""漏洞详报：全严重度可导出；章节含成因/危害/手动复现；不截断描述。"""
from __future__ import annotations

import unittest

from atkbrain.report.finding_report import (
    is_reportable_finding,
    prepare_finding_report,
    render_finding_markdown,
)
from atkbrain.report.generator import render_html, render_markdown
from atkbrain.report.writeup import (
    apply_deterministic_writeup,
    finding_from_vuln_node,
    manual_reproduction_steps,
    parse_curl_command,
    parse_writeups_payload,
    real_poc_text,
)


def _finding(**kw):
    base = {
        "id": "f-medium",
        "project_id": "p1",
        "node_key": "vuln:sqli",
        "severity": "medium",
        "category": "sqli",
        "title": "id 参数报错注入",
        "description": "登录后的商品详情 id 参数触发 SQL 报错。" + ("详" * 200),
        "evidence": "GET /item?id=1' → 500\nYou have an error in your SQL syntax; check the MySQL",
        "poc_curl": "curl -sk -X GET 'http://shop.example/item?id=1%27' -H 'Cookie: sid=abc'",
        "poc_python": None,
        "cvss": None,
        "verification_status": "pending",
        "related_node": {
            "key": "vuln:sqli",
            "type": "vuln",
            "title": "item id SQLi",
            "detail": "参数 id 拼进 SELECT * FROM items WHERE id=",
            "severity": "medium",
            "risk_score": 45,
            "tags": ["sqli"],
        },
        "related_edges": [
            {"from": "service:80", "to": "vuln:sqli", "relation": "LEADS_TO", "rationale": "HTTP 入口"},
        ],
    }
    base.update(kw)
    return base


class TestReportWriteup(unittest.TestCase):
    def test_parse_curl(self):
        p = parse_curl_command(
            "curl -sk -X POST 'http://t.example/login' -H 'Content-Type: application/json' "
            "-d '{\"user\":\"a\"}'"
        )
        self.assertIsNotNone(p)
        self.assertEqual(p["method"], "POST")
        self.assertIn("t.example/login", p["url"])
        self.assertTrue(any("Content-Type" in h for h in p["headers"]))
        self.assertIn("user", p["body"])

    def test_real_poc_strips_synth(self):
        self.assertEqual(real_poc_text("# 无人工复现 PoC（高危/严重禁止使用合成模板）。\n# x"), "")
        self.assertTrue(real_poc_text("curl -sk http://t.example/").startswith("curl"))

    def test_medium_low_reportable(self):
        self.assertTrue(is_reportable_finding({"verification_status": "pending", "severity": "low"}))
        self.assertFalse(is_reportable_finding({"verification_status": "rejected", "severity": "high"}))

    def test_markdown_has_chapters_and_full_description(self):
        f = prepare_finding_report(_finding())
        md = render_finding_markdown({"name": "shop", "id": "p1", "target": "shop.example"}, f)
        self.assertIn("漏洞原理", md)
        self.assertIn("手动复现", md)
        self.assertIn("危害与影响", md)
        self.assertIn("漏洞说明", md)
        self.assertIn("原始 HTTP", md)
        self.assertIn("Host: shop.example", md)
        self.assertIn("基线对照", md)
        self.assertIn("`id`", md)
        desc = "详" * 200
        self.assertIn(desc, md)
        self.assertNotIn(desc[:400] + "\n  -", md)
        self.assertIn("item?id=1", md)
        self.assertIn("Burp", md)
        self.assertIn("You have an error in your SQL syntax", md)
        self.assertIn("SQL syntax", md)
        self.assertIn("service:80", md)
        self.assertGreater(len(md), 2500)

    def test_high_without_poc_does_not_invent_payload(self):
        f = _finding(
            severity="critical",
            category="rce",
            title="rce",
            description="未给 PoC",
            evidence="uid=33(www-data)",
            poc_curl=None,
            poc_python=None,
        )
        steps = "\n".join(manual_reproduction_steps(f))
        self.assertNotIn("?cmd=id", steps)
        self.assertIn("未提供独立 poc_curl", steps)
        md = render_finding_markdown({"name": "x", "id": "p", "target": "t"}, prepare_finding_report(f))
        self.assertIn("未采集可执行 PoC", md)

    def test_node_only_finding(self):
        syn = finding_from_vuln_node({
            "key": "vuln:xss",
            "type": "vuln",
            "title": "反射 XSS",
            "detail": "q 参数回显未编码",
            "severity": "low",
            "tags": ["xss"],
            "risk_score": 20,
        })
        self.assertTrue(str(syn["id"]).startswith("node:"))
        self.assertEqual(syn["verification_status"], "pending")
        self.assertIn("q 参数", syn["root_cause"])

    def test_project_md_and_html_not_clipped(self):
        f = prepare_finding_report(_finding())
        data = {
            "project": {"name": "shop", "id": "p1", "target": "shop.example"},
            "graph": {"stats": {"findings": 1, "critical": 0, "high": 0}},
            "findings": [f],
            "criticals": [],
            "generated_at": "2026-08-30 00:00:00",
            "has_shell": False,
            "objective": "getshell",
            "flags_correct": 0,
            "flags_score": 0,
            "flags_needed": 1,
            "sections": [{
                "name": "shop",
                "target": "shop.example",
                "ports": [80],
                "assets": [{"key": "target:shop.example", "kind": "target", "title": "shop.example", "detail": ""}],
                "findings": [f],
                "criticals": [],
                "vuln_groups": [{
                    "asset": {"key": "target:shop.example", "title": "shop.example", "kind": "target", "detail": ""},
                    "findings": [f],
                }],
                "has_shell": False,
                "project": {"name": "shop", "id": "p1", "target": "shop.example"},
            }],
            "is_cluster": False,
        }
        md = render_markdown(data)
        self.assertIn("手动复现", md)
        self.assertIn("危害与影响", md)
        self.assertIn("详" * 200, md)
        html = render_html(data)
        self.assertIn("手动复现", html)
        self.assertIn("危害与影响", html)
        self.assertIn("漏洞原理", html)
        self.assertIn("Host: shop.example", html)
        self.assertIn("You have an error in your SQL syntax", html)
        self.assertNotIn("f.evidence[:1500]", html)

    def test_parse_writeups_and_ai_off_structure(self):
        specs = parse_writeups_payload(
            '{"writeups":[{"id":"f-medium","root_cause":"拼接 SQL","impact_detail":"读库","affected_scope":"item","reproduction_notes":["只用已有 curl"]}]}'
        )
        self.assertEqual(specs[0]["root_cause"], "拼接 SQL")
        out = apply_deterministic_writeup(_finding())
        self.assertTrue(out["root_cause"])
        self.assertTrue(out["impact_detail"])
        self.assertTrue(out["manual_steps"])


if __name__ == "__main__":
    unittest.main()
