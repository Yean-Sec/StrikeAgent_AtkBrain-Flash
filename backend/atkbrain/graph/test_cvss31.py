"""NVD CVSS v3.1 基础分。方程与 NVD 计算器一致，定性分档用 NVD 的 v3.x 表。"""
from __future__ import annotations

import unittest
from decimal import Decimal

from atkbrain_native import base_score, metrics_from_args, nvd_reject_reason, parse_vector, qualitative, roundup


class FormulaTests(unittest.TestCase):
    def test_roundup_spec_examples(self) -> None:
        self.assertEqual(Decimal(str(roundup(Decimal("4.02")))), Decimal("4.1"))
        self.assertEqual(Decimal(str(roundup(Decimal("4.00")))), Decimal("4.0"))

    def test_spec_vector_is_3_8(self) -> None:
        got = base_score(parse_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N") or {})
        self.assertEqual(got.score, 3.8)
        self.assertEqual(got.rating, "low")
        self.assertEqual(got.band_zh, "低危")
        self.assertEqual(got.vector, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N")

    def test_full_impact_network_is_9_8(self) -> None:
        got = base_score({
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
            "C": "H", "I": "H", "A": "H",
        })
        self.assertEqual(got.score, 9.8)
        self.assertEqual(got.rating, "critical")

    def test_reflected_xss_shape_is_6_1(self) -> None:
        got = base_score({
            "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C",
            "C": "L", "I": "L", "A": "N",
        })
        self.assertEqual(got.score, 6.1)
        self.assertEqual(got.rating, "medium")

    def test_nvd_does_not_score_zero_impact(self) -> None:
        metrics = {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
            "C": "N", "I": "N", "A": "N",
        }
        self.assertEqual(base_score(metrics).score, 0.0)
        self.assertIsNotNone(nvd_reject_reason(metrics))
        self.assertIsNone(nvd_reject_reason({**metrics, "C": "L"}))

    def test_no_impact_is_none(self) -> None:
        got = base_score({
            "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C",
            "C": "N", "I": "N", "A": "N",
        })
        self.assertEqual(got.score, 0.0)
        self.assertEqual(qualitative(Decimal("0.0")), "info")
        self.assertEqual(got.band_zh, "无")

    def test_bands(self) -> None:
        self.assertEqual(qualitative(Decimal("0.1")), "low")
        self.assertEqual(qualitative(Decimal("3.9")), "low")
        self.assertEqual(qualitative(Decimal("4.0")), "medium")
        self.assertEqual(qualitative(Decimal("6.9")), "medium")
        self.assertEqual(qualitative(Decimal("7.0")), "high")
        self.assertEqual(qualitative(Decimal("8.9")), "high")
        self.assertEqual(qualitative(Decimal("9.0")), "critical")
        self.assertEqual(qualitative(Decimal("10.0")), "critical")


class ArgTests(unittest.TestCase):
    def test_ingest_without_metrics_is_not_a_rating(self) -> None:
        metrics, attempted = metrics_from_args({"severity": "high"})
        self.assertIsNone(metrics)
        self.assertFalse(attempted)

    def test_rating_without_metrics_is_rejected(self) -> None:
        metrics, attempted = metrics_from_args({"redteam_rating": "high"})
        self.assertIsNone(metrics)
        self.assertTrue(attempted)

    def test_vector_sets_the_rating(self) -> None:
        metrics, attempted = metrics_from_args({
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        })
        self.assertTrue(attempted)
        self.assertIsNotNone(metrics)
        self.assertEqual(base_score(metrics or {}).score, 9.8)
