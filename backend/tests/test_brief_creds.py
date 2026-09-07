"""题面个位数凭据候选：可迁移、不扩字典。"""
from __future__ import annotations

import unittest

from atkbrain.agents.brief_creds import credential_candidates_from_brief, format_cred_hint
from atkbrain.agents.prompts import build_brief
from atkbrain.exec.guard import ctf_mega_dict_reason


class BriefCredTests(unittest.TestCase):
    def test_vendor_year_and_explicit_pair(self):
        text = (
            "Acme(Widget) control platform shipped in 2021. "
            "Try alice:wonder on the admin panel."
        )
        cands = credential_candidates_from_brief(text)
        blob = " ".join(cands)
        self.assertTrue(any("Widget@2021" in c for c in cands), blob)
        self.assertTrue(any(c == "admin/admin" or c.startswith("admin/") for c in cands), blob)
        self.assertTrue(any("alice" in c.lower() and "wonder" in c.lower() for c in cands), blob)
        self.assertLessEqual(len(cands), 10)

    def test_chinese_narrative_does_not_mint_sentence_fragments(self):
        text = (
            "公司内部部署了一套资产管理系统，员工可以查看公司资产、提交报销申请。"
            "请帮助安全团队评估该系统的安全性。"
        )
        blob = " ".join(credential_candidates_from_brief(text))
        self.assertNotRegex(blob, r"资产|署了|报销|评估该|安全团队")

    def test_empty_and_cap(self):
        self.assertEqual(credential_candidates_from_brief(""), [])
        self.assertLessEqual(len(credential_candidates_from_brief("Foo Bar Baz Qux 2019 2020 2021 2022")), 10)

    def test_hint_format_and_brief_injection(self):
        cands = credential_candidates_from_brief("VendorX appliance (GadgetCo) 2018")
        hint = format_cred_hint(cands)
        self.assertIn("个位数", hint)
        self.assertNotIn("rockyou", hint)
        brief = build_brief({
            "config": {
                "description": "GadgetCo appliance released in 2018",
                "objective": "flag",
            },
        })
        self.assertIn("凭据候选", brief)
        self.assertIn("GadgetCo", brief)
        self.assertLessEqual(brief.count("；"), 20)

    def test_mega_dict_still_blocked(self):
        why = ctf_mega_dict_reason("hashcat -a 0 hash.txt /usr/share/wordlists/rockyou.txt")
        self.assertIsNotNone(why)
        self.assertIsNone(ctf_mega_dict_reason("admin/admin"))


if __name__ == "__main__":
    unittest.main()
