"""漏洞页不能停在「正在撰写」：任务引用要保住，写失败要落到 failed。"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch


class ParsePiPageTests(unittest.TestCase):
    def test_braces_inside_strings_stay_in_the_page(self):
        from atkbrain.report.finding_page import parse_page

        raw = (
            '按事实写：\n'
            '{"summary": "入口 a {b} c", "impact": "已证明读到配置", '
            '"rating": "高 critical，二次验证打到了文件", '
            '"repro": "1. 打开入口\\n2. 提交参数\\n3. 看到文件\\n4. 判定成功", '
            '"fix": "收紧该接口鉴权"}'
        )
        spec = parse_page(raw)
        self.assertEqual(spec["report_summary"], "入口 a {b} c")
        self.assertIn("收紧", spec["report_fix"])


class PageProgressTests(unittest.TestCase):
    def test_failed_progress_is_not_still_writing(self):
        from atkbrain.report.finding_report import prepare_finding_report

        out = prepare_finding_report(
            {"secondary_verified": 1, "title": "t", "severity": "high", "category": "rce"},
            progress="failed",
        )
        self.assertEqual(out["report_state"], "failed")
        self.assertNotIn("正在撰写", out["impact"])

    def test_failed_secondary_keeps_the_page_and_the_reason(self):
        from atkbrain.report.finding_report import prepare_finding_report, render_finding_markdown

        why = "换通道重放后没有再看到同样的响应差异，二次验证失败。失败只表示本条没被二次证明。"
        row = {
            "verification_status": "excluded",
            "secondary_verified": 0,
            "title": "缺安全头",
            "severity": "medium",
            "category": "vuln",
            "id": "f1",
            "redteam_rating_rationale": why,
            "report_summary": "入口返回的响应头里没有这些安全头。",
            "report_impact": "页面可以被其他站点嵌入，点击劫持尚未证明。",
            "report_rating": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "report_repro": "1. 请求首页\n2. 看响应头\n3. 未见 CSP\n4. 二次没有复现嵌入",
            "report_fix": "补上 CSP 与 X-Frame-Options。",
        }
        out = prepare_finding_report(row)
        self.assertEqual(out["report_state"], "ready")
        self.assertEqual(out["exclusion_reason"], why)
        md = render_finding_markdown({}, row, lang="zh")
        self.assertIn("漏洞简介", md)
        self.assertIn("二次验证失败原因", md)
        self.assertIn(why, md)
        self.assertIn("入口返回的响应头", md)
        self.assertNotIn("排除", md)

    def test_verified_body_is_the_page_before_the_formal_sections(self) -> None:
        from atkbrain.report.finding_report import prepare_finding_report

        out = prepare_finding_report({
            "verification_status": "verified",
            "secondary_verified": 1,
            "title": "参数回显",
            "description": "参数原样出现在响应里。",
            "evidence": "二次请求再次看到同一处回显。",
            "proof_detail": "复核时复现了这一处回显。",
            "redteam_rating": "6.1",
            "redteam_rating_rationale": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            "poc_curl": "curl https://example.test/login",
        })
        self.assertEqual(out["report_state"], "ready")
        self.assertIn("参数原样出现", out["report_summary"])
        self.assertIn("再次看到", out["report_impact"])
        self.assertIn("CVSS:3.1", out["report_rating"])
        self.assertIn("复核时复现", out["report_repro"])
        self.assertNotIn("正在撰写", out.get("impact") or "")

    def test_schedule_holds_the_task_and_records_failure(self):
        from atkbrain.report import finding_page as page

        async def go():
            page._SCHEDULED.clear()
            page._FAILED.clear()
            page._PAGE_TASKS.clear()
            row = {"id": "f1", "project_id": "p1", "secondary_verified": 1}
            with patch.object(page.db, "fetchone", new=AsyncMock(return_value=row)), \
                 patch("atkbrain_native.get_project", return_value={"id": "p1"}), \
                 patch.object(page, "ensure_page", new=AsyncMock(return_value=row)):
                page.schedule_page("p1", "f1")
                self.assertTrue(page._PAGE_TASKS, "撰写任务必须被强引用，避免事件循环提前回收")
                self.assertEqual(page.page_activity("f1"), "writing")
                await next(iter(page._PAGE_TASKS))
            self.assertEqual(page.page_activity("f1"), "failed")
            self.assertNotIn("f1", page._SCHEDULED)
            page.clear_page_failure("f1")
            self.assertEqual(page.page_activity("f1"), "idle")

        asyncio.run(go())


if __name__ == "__main__":
    unittest.main()
