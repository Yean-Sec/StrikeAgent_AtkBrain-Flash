"""交付母版填槽：骨架稳定、PDF 适配不改 HTML、项目总报告无 MD。"""
from __future__ import annotations

import re
import unittest

from atkbrain.report.claude_export import (
    ProjectReportMdGone,
    parse_claude_docs,
    wrap_html,
    wrap_markdown,
    _enrich_usable,
)
from atkbrain.report.illustrate import NODE_FILL, THEME, graph_svg, report_css, severity_bar_svg
from atkbrain.report.pdf_print import adapt_html_for_pdf
from atkbrain.report.slots import (
    assemble_deliverable,
    fill_slot,
    gate_html,
    load_shell,
    parse_claude_enrich,
    render_vf_card,
)


def _sample_data():
    finding = {
        "id": "f-internal-should-not-leak",
        "title": "后台默认口令可进入管理面",
        "severity": "critical",
        "category": "弱口令",
        "description": "管理入口使用默认口令。",
        "mechanism": "登录接口接受出厂口令。",
        "root_cause": "未强制改密。",
        "impact_detail": "可接管后台。",
        "manual_steps": ["打开登录页。", "使用已采集口令提交。", "确认进入工作台。"],
        "evidence": "POST /login → 302 /workspace",
        "poc_curl": "curl -sk -X POST 'http://shop.example/login' -d 'u=admin'",
        "verification_status": "verified",
    }
    return {
        "project": {"name": "shop", "id": "p1", "target": "shop.example"},
        "graph": {
            "nodes": [
                {"key": "t", "type": "target", "title": "shop.example"},
                {"key": "v", "type": "vuln", "title": "默认口令"},
            ],
            "edges": [],
            "stats": {"nodes": 2, "critical": 1, "high": 0},
            "rce_path": {"path": ["t", "v"]},
        },
        "findings": [finding],
        "generated_at": "2026-08-31 12:00:00",
        "has_shell": False,
        "sections": [{
            "assets": [{"title": "shop.example", "kind": "target", "detail": "授权主目标"}],
            "findings": [finding],
        }],
    }


def _style(html: str) -> str:
    m = re.search(r"<style>.*?</style>", html, re.S)
    assert m, "missing style"
    return m.group(0)


class TestDeliverableSlots(unittest.TestCase):
    def test_shell_has_cover_grain_path_board_slots(self):
        shell = load_shell()
        self.assertIn('class="cover"', shell)
        self.assertIn('class="grain"', shell)
        self.assertIn("sec-head", shell)
        self.assertIn("path-board", shell)
        self.assertIn("<!-- SLOT:title -->", shell)
        self.assertIn("<!-- SLOT:findings-critical -->", shell)

    def test_sample_vuln_has_123_and_no_vbar(self):
        from pathlib import Path
        from atkbrain.report.slots import TEMPLATES_DIR
        sample = (TEMPLATES_DIR / "SAMPLE_VULN.html").read_text(encoding="utf-8")
        self.assertIn('class="vf', sample)
        self.assertIn("简介 / 技术成因", sample)
        self.assertIn("利用方式", sample)
        self.assertIn("修复方式", sample)
        self.assertIn('class="now"', sample)
        self.assertIn('class="ev"', sample)
        self.assertNotIn('class="vbar"', sample)
        self.assertNotIn("duo-card", sample)

    def test_two_assembles_same_skeleton(self):
        data = _sample_data()
        a = assemble_deliverable(data)
        b = assemble_deliverable(data)
        self.assertEqual(_style(a), _style(b))
        self.assertEqual(_style(a), _style(load_shell()))
        self.assertIn('class="cover"', a)
        self.assertIn("<header class=\"cover\"", a)
        self.assertIn("path-board", a)
        self.assertIn("path-row", a)
        self.assertIn('class="pn ', a)
        self.assertIn("sum-grid", a)
        self.assertIn("verify-panel", a)
        self.assertIn('class="vf', a)
        self.assertIn("简介 / 技术成因", a)
        self.assertIn("利用方式", a)
        self.assertIn("修复方式", a)
        self.assertIn('id="vuln-01"', a)
        self.assertNotIn("summary-grid", a)
        self.assertNotIn("path-step", a)
        self.assertNotIn("cover-title", a)
        self.assertNotIn('id="remediation"', a)
        self.assertNotIn("f-internal-should-not-leak", a)

    def test_fill_slot_does_not_rewrite_style(self):
        shell = load_shell()
        filled = fill_slot(shell, "title", "仅改标题")
        self.assertEqual(_style(shell), _style(filled))
        self.assertIn("仅改标题", filled)

    def test_gate_and_no_product_leak(self):
        html = assemble_deliverable(_sample_data())
        self.assertEqual(gate_html(html, has_findings=True), [])
        body = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
        self.assertNotIn("StrikeAgent", body)
        self.assertNotIn("AtkBrain", body)
        self.assertNotIn("时间线", body)
        self.assertNotIn("附录", body)

    def test_pdf_adapt_opens_details_html_file_untouched(self):
        html = assemble_deliverable(_sample_data())
        self.assertIn("（点击展开）", html)
        self.assertIn("<details class=\"ev\">", html)
        pdf_html = adapt_html_for_pdf(html)
        self.assertIn("（点击展开）", html)
        self.assertNotIn("（点击展开）", pdf_html)
        self.assertIn("<details open", pdf_html)
        self.assertIn("1280px 1810px", pdf_html)
        self.assertIn("print-color-adjust: exact", pdf_html)
        self.assertIn("flex-wrap: nowrap", pdf_html)

    def test_vf_card_matches_sample_contract(self):
        card = render_vf_card(_sample_data()["findings"][0], n=1)
        self.assertIn('class="vf crit"', card)
        self.assertIn("简介 / 技术成因", card)
        self.assertIn("利用方式", card)
        self.assertIn("修复方式", card)
        self.assertIn('h5 class="now"', card)
        self.assertIn('h5 class="root"', card)
        self.assertIn("<details class=\"ev\">", card)
        self.assertIn("证据 / PoC 复现", card)
        self.assertNotIn("vbar", card)
        self.assertNotIn("duo-card", card)
        self.assertNotIn("border-left:5px", card)

    def test_parse_claude_enrich_and_docs(self):
        d = parse_claude_enrich('```json\n{"title_line":"交大","findings":{"vuln-01":{"intro":"沙箱"}}\n}\n```')
        self.assertEqual(d.get("title_line"), "交大")
        html_body, md = parse_claude_docs('{"html_body":"<p>x</p>","markdown":"# y"}')
        self.assertIn("x", html_body)
        self.assertIn("y", md)

    def test_project_md_gone(self):
        with self.assertRaises(ProjectReportMdGone):
            wrap_markdown(_sample_data())

    def test_wrap_html_uses_shell(self):
        html = wrap_html(_sample_data())
        self.assertIn("--canvas:#faf9f5", html.replace(" ", ""))
        self.assertIn("#cc785c", html)
        self.assertIn("path-board", html)
        self.assertIn("sum-grid", html)
        self.assertIn("verify-panel", html)

    def test_enrich_usable(self):
        self.assertFalse(_enrich_usable(None))
        self.assertFalse(_enrich_usable({}))
        self.assertTrue(_enrich_usable({"title_line": "交大"}))
        self.assertTrue(_enrich_usable({"findings": {"vuln-01": {"intro": "x"}}}))


class TestIllustrateStillThemed(unittest.TestCase):
    def test_theme_matches_console(self):
        self.assertEqual(THEME["canvas"], "#faf9f5")
        self.assertEqual(THEME["primary"], "#cc785c")
        self.assertEqual(NODE_FILL["goal"], "#f23636")
        css = report_css()
        self.assertIn("#faf9f5", css)

    def test_graph_svg_uses_node_theme_colors(self):
        svg = graph_svg({
            "nodes": [
                {"key": "t", "type": "target", "title": "shop.example"},
                {"key": "v", "type": "vuln", "title": "SQLi", "risk_score": 80},
                {"key": "g", "type": "goal", "title": "shell"},
            ],
            "edges": [{"from": "v", "to": "g", "relation": "ESCALATES_TO"}],
        })
        self.assertIn("#faf9f5", svg)
        self.assertIn("#c64545", svg)
        self.assertIn("#f23636", svg)

    def test_severity_bar_counts(self):
        svg = severity_bar_svg([{"severity": "critical"}, {"severity": "high"}])
        self.assertIn("#c64545", svg)


if __name__ == "__main__":
    unittest.main()
