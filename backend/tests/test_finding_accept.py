"""发现入库：有真实性证据才标已验证。"""
from __future__ import annotations

import asyncio
import unittest

from atkbrain.graph.model import FindingIn, display_finding_severity, normalize_redteam_rating
from atkbrain.graph import verify as V
from atkbrain.report.finding_report import _verify_label, is_reportable_finding


class TestFindingAccept(unittest.TestCase):
    def test_report_with_evidence_is_verified(self):
        f = FindingIn(
            severity="critical",
            category="rce",
            title="rce",
            evidence="uid=33(www-data)",
        )
        vr = asyncio.run(V.verify_finding(f))
        self.assertEqual(vr.status, "verified")
        self.assertEqual(vr.reason, "accepted")

    def test_no_proof_is_pending(self):
        f = FindingIn(severity="info", category="info", title="banner")
        vr = asyncio.run(V.verify_finding(f))
        self.assertEqual(vr.status, "pending")
        self.assertEqual(vr.reason, "no_proof")

    def test_availability_is_pending_not_exploit(self):
        f = FindingIn(
            severity="medium", category="availability", title="恒定错误页",
        )
        vr = asyncio.run(V.verify_finding(f))
        self.assertEqual(vr.status, "pending")
        self.assertEqual(vr.reason, "availability_not_exploit")
        sqli = FindingIn(severity="high", category="sqli", title="注入", evidence="SLEEP(3) 延迟 3.1s")
        self.assertEqual(asyncio.run(V.verify_finding(sqli)).status, "verified")
        self.assertTrue(V.is_non_exploit_finding_category("crash"))
        self.assertFalse(V.is_non_exploit_finding_category("info_disclosure"))
        self.assertFalse(V.is_non_exploit_finding_category("sqli"))

    def test_visible_and_reportable(self):
        self.assertTrue(V.is_visible_finding({"verification_status": "verified", "severity": "high"}))
        self.assertTrue(V.is_visible_finding({"verification_status": "pending", "severity": "high"}))
        self.assertFalse(V.is_visible_finding({"verification_status": "rejected"}))
        self.assertTrue(
            is_reportable_finding(
                {"verification_status": "verified", "severity": "high", "category": "lfi"}
            )
        )
        self.assertTrue(
            is_reportable_finding(
                {"verification_status": "pending", "severity": "medium", "category": "xss"}
            )
        )
        self.assertTrue(
            is_reportable_finding(
                {"verification_status": "verified", "severity": "low", "category": "info_disclosure"}
            )
        )
        self.assertFalse(
            is_reportable_finding(
                {"verification_status": "rejected", "severity": "critical", "category": "rce"}
            )
        )

    def test_high_severity_for_poc(self):
        self.assertTrue(V.is_high_severity("critical", "rce"))
        self.assertFalse(V.is_high_severity("info", "info"))

    def test_verified_label_is_not_catalogued(self):
        self.assertEqual(_verify_label("verified"), "已验证")
        self.assertNotEqual(_verify_label("verified"), "已收录")

    def test_redteam_rating_normalize(self):
        self.assertEqual(normalize_redteam_rating("高危"), "high")
        self.assertEqual(normalize_redteam_rating("CRITICAL"), "critical")
        self.assertIsNone(normalize_redteam_rating(""))
        self.assertIsNone(normalize_redteam_rating("候选"))

    def test_display_severity_prefers_redteam(self):
        self.assertEqual(
            display_finding_severity({"severity": "low", "redteam_rating": "high"}),
            "high",
        )
        self.assertEqual(
            display_finding_severity({"severity": "critical", "redteam_rating": ""}),
            "critical",
        )
        self.assertEqual(
            display_finding_severity({"severity": "medium", "redteam_rating": "低危"}),
            "low",
        )

    def test_secondary_flag_on_model(self):
        f = FindingIn(
            severity="high", category="sqli", title="注入",
            evidence="SLEEP", secondary_verified=True,
            redteam_rating="high",
            redteam_rating_rationale="未授权可注，延迟稳定，可抽库通向敏感数据。",
        )
        self.assertTrue(f.secondary_verified)
        self.assertEqual(f.redteam_rating, "high")

    def test_markdown_says_verified_not_catalogued(self):
        from atkbrain.report.finding_report import render_finding_markdown
        md = render_finding_markdown(
            {"name": "p", "id": "p1", "target": "10.0.0.8"},
            {
                "id": "f1", "title": "注入", "severity": "low", "category": "sqli",
                "verification_status": "verified", "secondary_verified": True,
                "redteam_rating": "high",
                "redteam_rating_rationale": "未授权可注，可抽数据，勿因只读低估。",
            },
        )
        self.assertIn("已验证", md)
        self.assertNotIn("已收录", md)
        self.assertIn("二次验证", md)
        self.assertIn("已做", md)
        self.assertIn("红队评级", md)
        self.assertIn("勿因只读低估", md)
        self.assertIn("[HIGH]", md)
        self.assertIn("以红队二次验证评级为准", md)


if __name__ == "__main__":
    unittest.main()
