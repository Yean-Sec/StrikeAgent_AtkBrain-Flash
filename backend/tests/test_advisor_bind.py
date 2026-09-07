"""顾问绑定：方案编译成硬约束，未执行则收紧，不换散文。"""
from __future__ import annotations

import inspect
import unittest

from atkbrain.engine.advisor_bind import (
    AdvisorBinding,
    CLOSEOUT_OVERRIDE,
    binding_compliance,
    binding_is_locked,
    binding_reserve_tactics,
    closeout_sidetrack_tactics,
    compile_binding,
    ensure_postex_orthogonal,
    format_binding_block,
    in_flight_blocks_new_direction,
    pick_bound_assigned,
    postex_reserve_tactics,
    protected_tactics,
    starves_chain_close,
    tighten_binding,
)
from atkbrain.engine.ai_supervisor import SupervisorPlan


class CompileBindingTests(unittest.TestCase):
    def test_foothold_remaining_denies_entry_enum(self):
        plan = SupervisorPlan(diagnosis="去横向", next_plan="从壳打邻机", stall="postex")
        b = compile_binding(
            plan,
            open_intents=[
                {"id": "i_hop", "strategy_key": "t:172.20.0.4::hop_auth", "status": "open"},
                {"id": "i_dir", "strategy_key": "svc:80::content_enum", "status": "open"},
            ],
            has_foothold=True,
            remaining_goals=True,
            has_verified_asset=True,
            has_internal_hops=True,
        )
        self.assertIn("content_enum", b.deny_tactics)
        self.assertIn("hop_auth", b.prefer_tactics)
        self.assertEqual(b.must_intents, ["i_hop"])
        self.assertNotIn("i_dir", b.must_intents)

    def test_verified_vuln_without_shell_drops_content_enum(self):
        plan = SupervisorPlan(
            diagnosis="打 LFI", next_plan="武器化",
            prefer_tactics=["weaponize"],
            defer_families=["content_enum"],
        )
        b = compile_binding(plan, has_verified_asset=True, has_foothold=False)
        self.assertIn("content_enum", b.deny_tactics)
        self.assertIn("weaponize", b.prefer_tactics)
        self.assertNotIn("content_enum", b.prefer_tactics)

    def test_plan_prefer_entry_loses_to_postex_deny(self):
        plan = SupervisorPlan(prefer_tactics=["content_enum"], next_plan="再扫目录")
        b = compile_binding(plan, has_foothold=True, remaining_goals=True)
        self.assertIn("content_enum", b.deny_tactics)
        self.assertNotIn("content_enum", b.prefer_tactics)

    def test_no_graph_flags_keeps_llm_fields(self):
        plan = SupervisorPlan(
            prefer_tactics=["content_enum"], next_plan="扫目录", stall="method",
        )
        b = compile_binding(plan)
        self.assertEqual(b.prefer_tactics, ["content_enum"])
        self.assertNotIn("content_enum", b.deny_tactics)

    def test_postex_reserves_access_control_when_advisor_fills_hop_auth(self):
        plan = SupervisorPlan(
            diagnosis="过门", next_plan="打 hop_auth",
            must_intents=["i_h1", "i_h2", "i_h3"],
            prefer_tactics=["hop_auth", "privesc_lateral", "weaponize"],
        )
        opens = [
            {"id": "i_h1", "strategy_key": "a::hop_auth", "status": "open"},
            {"id": "i_h2", "strategy_key": "b::hop_auth", "status": "open"},
            {"id": "i_h3", "strategy_key": "c::hop_auth", "status": "open"},
            {"id": "i_ac", "strategy_key": "a::access_control", "status": "open"},
            {"id": "i_priv", "strategy_key": "s::privesc_lateral", "status": "open"},
            {"id": "i_w", "strategy_key": "s::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_foothold=True, remaining_goals=True,
            has_verified_asset=True, has_internal_hops=True,
        )
        self.assertIn("i_ac", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_ac")
        by = {i["id"]: i["strategy_key"].split("::")[-1] for i in opens}
        tacs = [by[i] for i in b.must_intents]
        self.assertEqual(len(tacs), len(set(tacs)))
        self.assertIn("access_control", tacs)
        self.assertIn("hop_auth", tacs)
        self.assertLessEqual(
            b.prefer_tactics.index("access_control"),
            b.prefer_tactics.index("hop_auth"),
        )

    def test_postex_prefer_order_picks_file_read_before_hop_auth(self):
        plan = SupervisorPlan(next_plan="横向")
        b = compile_binding(
            plan,
            open_intents=[
                {"id": "i_hop", "strategy_key": "t::hop_auth", "status": "open"},
                {"id": "i_fr", "strategy_key": "t::file_read_chain", "status": "open"},
            ],
            has_foothold=True, remaining_goals=True, has_verified_asset=True,
        )
        self.assertEqual(b.must_intents[0], "i_fr")
        self.assertIn("i_hop", b.must_intents)

    def test_pinned_binding_gains_orthogonal_without_new_plan(self):
        pinned = AdvisorBinding(
            next_plan="打 hop_auth",
            must_intents=["i_hop"],
            prefer_tactics=["hop_auth"],
            stall="postex",
        )
        opens = [
            {"id": "i_hop", "strategy_key": "t::hop_auth", "status": "open"},
            {"id": "i_ac", "strategy_key": "t::access_control", "status": "open"},
            {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"},
        ]
        got = ensure_postex_orthogonal(
            pinned, opens, has_foothold=True, remaining_goals=True,
        )
        self.assertIsNot(got, pinned)
        self.assertEqual(got.must_intents[0], "i_ac")
        self.assertIn("i_hop", got.must_intents)
        self.assertNotIn("i_dir", got.must_intents)
        same = ensure_postex_orthogonal(
            pinned, opens, has_foothold=False, remaining_goals=True,
        )
        self.assertIs(same, pinned)

    def test_verified_no_shell_strips_weaponize_defer_and_reserves_slot(self):
        plan = SupervisorPlan(
            diagnosis="继续读文件", next_plan="换路径读",
            stall="method",
            must_intents=["i_fr", "i_fb", "i_loot"],
            prefer_tactics=["file_read_chain", "filter_bypass", "finding_read_loot"],
            defer_families=["weaponize", "content_enum"],
        )
        opens = [
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_fb", "strategy_key": "v::filter_bypass", "status": "open"},
            {"id": "i_loot", "strategy_key": "v::finding_read_loot", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False, remaining_goals=True,
        )
        self.assertNotIn("weaponize", b.deny_tactics)
        self.assertIn("content_enum", b.deny_tactics)
        self.assertEqual(b.stall, "chain")
        self.assertEqual(b.must_intents, ["i_w"])
        self.assertNotIn("i_fr", b.must_intents)
        self.assertNotIn("i_loot", b.must_intents)

    def test_pinned_loot_binding_gains_weaponize_without_new_plan(self):
        pinned = AdvisorBinding(
            next_plan="继续读",
            must_intents=["i_fr", "i_fb", "i_loot"],
            prefer_tactics=["file_read_chain", "filter_bypass", "finding_read_loot"],
            deny_tactics=["weaponize", "content_enum"],
            stall="method",
        )
        opens = [
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_fb", "strategy_key": "v::filter_bypass", "status": "open"},
            {"id": "i_loot", "strategy_key": "v::finding_read_loot", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        got = ensure_postex_orthogonal(
            pinned, opens, has_verified_asset=True, has_foothold=False,
        )
        self.assertIsNot(got, pinned)
        self.assertEqual(got.must_intents[0], "i_w")
        self.assertNotIn("i_fr", got.must_intents)
        self.assertNotIn("weaponize", got.deny_tactics)
        self.assertFalse(starves_chain_close(
            got, opens, has_verified_asset=True, has_foothold=False,
        ))
        self.assertTrue(starves_chain_close(
            pinned, opens, has_verified_asset=True, has_foothold=False,
        ))


class ComplianceTests(unittest.TestCase):
    def test_oracle_quality_wins(self):
        b = AdvisorBinding(deny_tactics=["content_enum"], must_intents=["i1"])
        self.assertEqual(
            binding_compliance(b, last_tool_uses=3, quality="flag", last_turn_text="目录枚举"),
            "oracle",
        )

    def test_empty_tools(self):
        b = AdvisorBinding(deny_tactics=["content_enum"])
        self.assertEqual(binding_compliance(b, last_tool_uses=0), "empty")

    def test_ignored_when_text_hits_denied_entry_enum(self):
        b = AdvisorBinding(
            deny_tactics=["content_enum", "fingerprint"],
            must_intents=["i_hop"],
        )
        self.assertEqual(
            binding_compliance(
                b,
                assigned=[{"id": "i_hop", "strategy_key": "t::hop_auth"}],
                open_intents=[{"id": "i_hop", "status": "open"}],
                last_turn_text="继续目录枚举 /news.php",
                last_tool_uses=12,
            ),
            "ignored",
        )

    def test_executed_when_must_closed(self):
        b = AdvisorBinding(must_intents=["i_hop"], deny_tactics=["content_enum"])
        self.assertEqual(
            binding_compliance(
                b,
                open_intents=[{"id": "i_other", "status": "open"}],
                last_turn_text="过了 hop 登录门",
                last_tool_uses=4,
            ),
            "executed",
        )

    def test_ignored_without_must_if_reflux(self):
        b = AdvisorBinding(deny_tactics=["content_enum"])
        self.assertEqual(
            binding_compliance(
                b, last_turn_text="回头打入口继续目录爆破", last_tool_uses=5,
            ),
            "ignored",
        )


class TightenTests(unittest.TestCase):
    def test_tighten_adds_entry_deny_and_does_not_replace_story(self):
        b = AdvisorBinding(next_plan="从壳打邻机", stall="postex", prefer_tactics=["hop_auth"])
        t = tighten_binding(b)
        self.assertGreater(t.misses, b.misses)
        self.assertTrue(t.tightened)
        self.assertIn("content_enum", t.deny_tactics)
        self.assertIn("约束收紧", t.next_plan)
        self.assertIn("从壳打邻机", t.next_plan)
        t2 = tighten_binding(t)
        self.assertEqual(t2.next_plan.count("约束收紧"), 1)

    def test_format_block_is_mandatory(self):
        b = AdvisorBinding(
            must_intents=["i1"], prefer_tactics=["hop_auth"],
            deny_tactics=["content_enum"], tightened=True, misses=2,
        )
        text = format_binding_block(b)
        self.assertIn("不是评语", text)
        self.assertIn("强制执行", text)
        self.assertIn("过门与未授权可达并行", text)
        self.assertIn("抽取或投递", text)
        self.assertIn("其它活体面", text)
        self.assertIn("禁止战术", text)
        self.assertIn("hop_auth", text)
        self.assertTrue(binding_is_locked(b))
        self.assertFalse(binding_is_locked(None))

    def test_lock_does_not_pad_unrelated_frontier(self):
        must = {"id": "i_hop", "strategy_key": "t::hop_auth", "status": "open"}
        other = {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"}
        got = pick_bound_assigned(
            open_intents=[must, other],
            want_ids=["i_hop"],
            extras=[other],
            prefer={"hop_auth"},
            deny={"content_enum"},
            lock=True,
        )
        self.assertEqual([i["id"] for i in got], ["i_hop"])

    def test_lock_still_reserves_unauth_slot(self):
        hop = {"id": "i_hop", "strategy_key": "t::hop_auth", "status": "open"}
        ac = {"id": "i_ac", "strategy_key": "t::access_control", "status": "open"}
        other = {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"}
        got = pick_bound_assigned(
            open_intents=[hop, ac, other],
            want_ids=["i_hop"],
            extras=[other],
            prefer={"hop_auth"},
            deny={"content_enum"},
            lock=True,
            reserve=postex_reserve_tactics(has_foothold=True, remaining_goals=True),
        )
        self.assertEqual([i["id"] for i in got][0], "i_ac")
        self.assertIn("i_hop", [i["id"] for i in got])
        self.assertNotIn("i_dir", [i["id"] for i in got])

    def test_lock_still_reserves_weaponize_before_shell(self):
        fr = {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"}
        w = {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"}
        other = {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"}
        got = pick_bound_assigned(
            open_intents=[fr, w, other],
            want_ids=["i_fr"],
            extras=[other],
            prefer={"file_read_chain"},
            deny={"content_enum", "weaponize"},
            lock=True,
            reserve=binding_reserve_tactics(has_verified_asset=True, has_foothold=False),
            exclusive=True,
        )
        self.assertEqual([i["id"] for i in got], ["i_w"])
        self.assertNotIn("i_fr", [i["id"] for i in got])
        self.assertNotIn("i_dir", [i["id"] for i in got])

    def test_lock_fills_prefer_when_must_missing(self):
        hop = {"id": "i_lat", "strategy_key": "t::privesc_lateral", "status": "open"}
        other = {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"}
        got = pick_bound_assigned(
            open_intents=[hop, other],
            want_ids=["i_gone"],
            extras=[other, hop],
            prefer={"privesc_lateral"},
            deny={"content_enum"},
            lock=True,
        )
        self.assertEqual([i["id"] for i in got], ["i_lat"])

    def test_unlocked_pads_extras(self):
        a = {"id": "i1", "strategy_key": "t::hop_auth", "status": "open"}
        b = {"id": "i2", "strategy_key": "t::weaponize", "status": "open"}
        got = pick_bound_assigned(
            open_intents=[a, b],
            want_ids=["i1"],
            extras=[b],
            lock=False,
        )
        self.assertEqual([i["id"] for i in got], ["i1", "i2"])

    def test_lock_hides_open_frontier_in_turn_text(self):
        from atkbrain.engine.loop import _intents_text
        assigned = [{"id": "i_hop", "priority": 0.9, "description": "打邻机", "strategy_key": "t::hop_auth"}]
        open_i = assigned + [{"id": "i_dir", "priority": 0.2, "description": "扫目录", "strategy_key": "svc::content_enum", "status": "open"}]
        locked = _intents_text(open_i, assigned=assigned, lock=True)
        self.assertIn("本轮必须推进", locked)
        self.assertNotIn("开放前沿", locked)
        unlocked = _intents_text(open_i, assigned=assigned, lock=False)
        self.assertIn("开放前沿", unlocked)

    def test_verified_sqli_denies_oracle_and_file_read_close(self):
        plan = SupervisorPlan(
            diagnosis="时间盲注已通", next_plan="dump",
            prefer_tactics=["channel_oracle", "file_read_chain"],
        )
        opens = [
            {"id": "i_ch", "strategy_key": "v::channel_oracle", "status": "open"},
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_sql", "strategy_key": "v::finding_sqli_chain", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
            {"id": "i_api", "strategy_key": "v::api_contract", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["sqli"],
        )
        self.assertEqual(b.stall, "chain")
        self.assertIn("channel_oracle", b.deny_tactics)
        self.assertIn("file_read_chain", b.deny_tactics)
        self.assertIn("api_contract", b.deny_tactics)
        self.assertNotIn("channel_oracle", b.prefer_tactics)
        self.assertNotIn("file_read_chain", b.prefer_tactics)
        self.assertIn("i_sql", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_sql")
        self.assertNotIn("i_ch", b.must_intents)
        self.assertNotIn("i_api", b.must_intents)

    def test_uniform_error_does_not_closeout_or_defer_oracle(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        plan = SupervisorPlan(
            diagnosis="恒定错误页", next_plan="weaponize 崩溃节点",
            prefer_tactics=["weaponize"],
            defer_families=["channel_oracle"],
        )
        opens = [
            {"id": "i_ch", "strategy_key": "v::channel_oracle", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=False, has_foothold=False,
            verified_categories=["availability"],
            needs_channel_oracle=True,
        )
        self.assertNotEqual(b.stall, "chain")
        self.assertNotIn("channel_oracle", b.deny_tactics)
        self.assertNotIn("channel_oracle", plan.defer_families)
        self.assertNotIn(CLOSEOUT_OVERRIDE, b.next_plan)
        sqli = compile_binding(
            SupervisorPlan(
                diagnosis="注入已通", next_plan="dump",
                prefer_tactics=["channel_oracle"],
            ),
            open_intents=opens + [
                {"id": "i_sql", "strategy_key": "v::finding_sqli_chain", "status": "open"},
            ],
            has_verified_asset=True, has_foothold=False,
            verified_categories=["sqli"],
            needs_channel_oracle=True,
        )
        self.assertIn("channel_oracle", sqli.deny_tactics)
        self.assertIn(CLOSEOUT_OVERRIDE, sqli.next_plan)

    def test_verified_ssrf_denies_stale_client_contract(self):
        plan = SupervisorPlan(diagnosis="SSRF 已通", next_plan="当跳板")
        opens = [
            {"id": "i_api", "strategy_key": "v::api_contract", "status": "open"},
            {"id": "i_fp", "strategy_key": "v::fingerprint", "status": "open"},
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["ssrf"],
        )
        self.assertIn("api_contract", b.deny_tactics)
        self.assertIn("fingerprint", b.deny_tactics)
        self.assertEqual(b.must_intents[0], "i_gw")

    def test_verified_write_reserves_rce_close(self):
        plan = SupervisorPlan(diagnosis="写入已验证", next_plan="投递")
        opens = [
            {"id": "i_ch", "strategy_key": "v::channel_oracle", "status": "open"},
            {"id": "i_rce", "strategy_key": "v::finding_rce_close", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["deserialization"],
        )
        self.assertIn("channel_oracle", b.deny_tactics)
        self.assertEqual(b.must_intents[0], "i_rce")

    def test_closeout_sidetrack_sqli_keeps_file_read_when_also_lfi(self):
        both = closeout_sidetrack_tactics(["sqli", "file_read"])
        self.assertIn("channel_oracle", both)
        self.assertNotIn("file_read_chain", both)
        only_sql = closeout_sidetrack_tactics(["sqli"])
        self.assertIn("file_read_chain", only_sql)
        self.assertIn("input_abuse", only_sql)
        self.assertIn("access_control", only_sql)

    def test_token_sidetrack_denies_file_read_and_html_sink(self):
        tok = closeout_sidetrack_tactics(["token"])
        self.assertIn("file_read_chain", tok)
        self.assertIn("html_sink", tok)
        self.assertIn("flag_hunt", tok)
        both = closeout_sidetrack_tactics(["token", "file_read"])
        self.assertNotIn("file_read_chain", both)

    def test_token_reserve_prefers_weaponize_over_ui_role(self):
        got = binding_reserve_tactics(
            has_verified_asset=True, has_foothold=False,
            verified_categories=["token", "auth_bypass"],
        )
        self.assertEqual(got[0], "weaponize")
        self.assertIn("finding_authz_expand", got)

    def test_sanitize_strips_reprove_and_false_close(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE, sanitize_closeout_plan
        plan = SupervisorPlan(
            diagnosis="伪造面已关闭",
            next_plan="用 LOAD_FILE 读盘并校准耗时。然后 dump 用户表。",
            prefer_tactics=["channel_oracle", "finding_sqli_chain"],
            hold=True,
        )
        sanitize_closeout_plan(
            plan, has_verified_asset=True, has_foothold=False,
            verified_categories=["sqli"],
        )
        self.assertFalse(plan.hold)
        self.assertEqual(plan.stall, "chain")
        self.assertEqual(plan.next_plan, CLOSEOUT_OVERRIDE)
        self.assertNotIn("LOAD_FILE", plan.next_plan)
        self.assertNotIn("校准耗时", plan.next_plan)
        self.assertNotIn("dump 用户表", plan.next_plan)
        self.assertNotIn("channel_oracle", plan.prefer_tactics)
        self.assertIn("不等于攻击面关闭", plan.diagnosis)

    def test_compile_rewrites_leave_bridge_prose(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        plan = SupervisorPlan(
            diagnosis="导入是存根",
            next_plan="判定为存根。改从攻击机直连内网 admin 口。",
            prefer_tactics=["api_contract", "fingerprint"],
        )
        opens = [
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
            {"id": "i_api", "strategy_key": "v::api_contract", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["ssrf"],
        )
        self.assertIn(CLOSEOUT_OVERRIDE, b.next_plan)
        self.assertNotIn("改从攻击机", b.next_plan)
        self.assertNotIn("判定为存根", b.next_plan)
        self.assertNotIn("api_contract", b.prefer_tactics)
        self.assertEqual(b.must_intents[0], "i_gw")

    def test_token_plan_drops_sidetrack_tail(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        plan = SupervisorPlan(
            diagnosis="令牌面还活着",
            next_plan="把签名对象继续打。先跟 autoindex 和 README，把读文件原语当第一步。",
            prefer_tactics=["html_sink", "content_enum", "weaponize"],
            must_intents=["i_w"],
        )
        opens = [
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_html", "strategy_key": "v::html_sink", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["token"],
        )
        self.assertIn(CLOSEOUT_OVERRIDE, b.next_plan)
        self.assertNotIn("换面", b.next_plan)
        self.assertNotIn("静态", b.next_plan)
        self.assertNotIn("扫", b.next_plan)
        self.assertNotIn("autoindex", b.next_plan)
        self.assertNotIn("README", b.next_plan)
        self.assertNotIn("读文件", b.next_plan)
        self.assertIn("`weaponize`", b.next_plan)
        self.assertIn("file_read_chain", b.deny_tactics)
        self.assertIn("html_sink", b.deny_tactics)
        self.assertNotIn("i_fr", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_w")

    def test_live_gadget_strips_leave_bridge_without_verified(self):
        from atkbrain.engine.advisor_bind import GADGET_KEEP
        plan = SupervisorPlan(
            diagnosis="通道否证",
            next_plan="判定为存根。改从攻击机直连内网管理口。顺手读文件。",
            prefer_tactics=["file_read_chain", "fingerprint"],
        )
        opens = [
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_ac", "strategy_key": "v::access_control", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=False, has_foothold=False,
            has_live_gadget=True,
        )
        self.assertIn(GADGET_KEEP, b.next_plan)
        self.assertNotIn("改从攻击机", b.next_plan)
        self.assertNotIn("判定为存根", b.next_plan)
        self.assertNotIn("读文件", b.next_plan)
        self.assertIn("ssrf_as_gateway", b.prefer_tactics)
        self.assertIn("file_read_chain", b.deny_tactics)
        self.assertIn("access_control", b.deny_tactics)
        self.assertEqual(b.must_intents, ["i_gw"])
        self.assertIn("`ssrf_as_gateway`", b.next_plan)

    def test_sqli_must_rejects_flag_or_privesc(self):
        plan = SupervisorPlan(
            next_plan="dump 完去提权找旗",
            prefer_tactics=["finding_sqli_chain", "flag_or_privesc"],
            must_intents=["i_sql", "i_flag"],
        )
        opens = [
            {"id": "i_sql", "strategy_key": "v::finding_sqli_chain", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
            {"id": "i_flag", "strategy_key": "v::flag_or_privesc", "status": "open"},
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["sqli"],
        )
        self.assertIn("flag_or_privesc", b.deny_tactics)
        self.assertIn("file_read_chain", b.deny_tactics)
        self.assertNotIn("i_flag", b.must_intents)
        self.assertNotIn("i_fr", b.must_intents)
        self.assertTrue(set(b.must_intents) <= {"i_sql", "i_w"})
        self.assertNotIn("flag_or_privesc", b.prefer_tactics)

    def test_ssrf_must_rejects_file_read_and_access_control(self):
        plan = SupervisorPlan(
            next_plan="跳板通了，本机去读内网文件并打未授权",
            prefer_tactics=["ssrf_as_gateway", "file_read_chain", "access_control"],
            must_intents=["i_gw", "i_fr", "i_ac"],
        )
        opens = [
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
            {"id": "i_fr", "strategy_key": "v::file_read_chain", "status": "open"},
            {"id": "i_ac", "strategy_key": "v::access_control", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["ssrf"],
        )
        self.assertIn("file_read_chain", b.deny_tactics)
        self.assertIn("access_control", b.deny_tactics)
        self.assertNotIn("i_fr", b.must_intents)
        self.assertNotIn("i_ac", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_gw")
        self.assertNotIn("file_read_chain", b.prefer_tactics)
        self.assertNotIn("access_control", b.prefer_tactics)
        self.assertIn("filter_bypass", b.deny_tactics)
        self.assertNotIn("filter_bypass", b.prefer_tactics)

    def test_verified_gadget_denies_filter_bypass_not_wrap_same_form(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        plan = SupervisorPlan(
            diagnosis="跳板已通",
            next_plan="继续对同一形态做编码变体",
            prefer_tactics=["ssrf_as_gateway", "filter_bypass"],
            must_intents=["i_gw", "i_fb"],
        )
        opens = [
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
            {"id": "i_fb", "strategy_key": "v::filter_bypass", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["ssrf"],
        )
        self.assertIn(CLOSEOUT_OVERRIDE, b.next_plan)
        self.assertIn("同一形态", b.next_plan)
        self.assertIn("filter_bypass", b.deny_tactics)
        self.assertNotIn("i_fb", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_gw")
        self.assertEqual(
            binding_compliance(
                b,
                last_turn_text="对已拦截字面量做同族变体和编码变体",
                last_tool_uses=6,
            ),
            "ignored",
        )
        self.assertEqual(
            binding_compliance(
                b,
                last_turn_text="经已验证跳板参数提交题面已点名的内网 URL",
                last_tool_uses=6,
            ),
            "executed",
        )

    def test_load_file_turn_ignored_on_chain_even_without_must(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        b = AdvisorBinding(
            stall="chain",
            next_plan=CLOSEOUT_OVERRIDE + "\n只推进：`finding_sqli_chain`",
            deny_tactics=["file_read_chain"],
            must_intents=[],
        )
        self.assertEqual(
            binding_compliance(
                b,
                last_turn_text="SELECT LOAD_FILE('/etc/passwd') 试读盘",
                last_tool_uses=8,
            ),
            "ignored",
        )
        self.assertEqual(
            binding_compliance(
                b,
                last_turn_text='grep -rniE "SLEEP\\(|IF\\(|LOAD_FILE|username" /tmp/notes',
                last_tool_uses=8,
            ),
            "executed",
        )

    def test_tighten_chain_does_not_reopen_file_read(self):
        b = AdvisorBinding(
            stall="chain",
            next_plan="只推进：`finding_sqli_chain`",
            prefer_tactics=["finding_sqli_chain", "weaponize"],
            deny_tactics=["file_read_chain", "flag_or_privesc", "content_enum"],
        )
        t = tighten_binding(b)
        self.assertNotIn("file_read_chain", t.prefer_tactics)
        self.assertNotIn("access_control", t.prefer_tactics)
        self.assertIn("file_read_chain", t.deny_tactics)
        self.assertIn("finding_sqli_chain", t.prefer_tactics)

    def test_force_review_when_verified_unused(self):
        from atkbrain.engine.advisor_bind import should_force_chain_close_review
        self.assertTrue(should_force_chain_close_review(
            chain_live=True, has_plan=False,
        ))
        self.assertTrue(should_force_chain_close_review(
            chain_live=True, has_plan=True,
            assigned_tactics={"channel_oracle", "fingerprint"},
            verified_categories=["sqli"],
        ))
        self.assertFalse(should_force_chain_close_review(
            chain_live=True, has_plan=True,
            assigned_tactics={"finding_sqli_chain"},
            verified_categories=["sqli"],
        ))
        self.assertFalse(should_force_chain_close_review(
            chain_live=False, has_plan=False,
        ))
        self.assertTrue(should_force_chain_close_review(
            chain_live=True, has_plan=True,
            assigned_tactics={"web_inject", "fingerprint", "secret_mount"},
            verified_categories=["availability"],
        ))
        self.assertIn("content_enum", closeout_sidetrack_tactics(["availability"]))
        self.assertNotIn("web_inject", closeout_sidetrack_tactics(["sqli"]))
        self.assertIn("content_enum", closeout_sidetrack_tactics(["sqli"]))
        self.assertTrue(should_force_chain_close_review(
            chain_live=True, has_plan=True,
            assigned_tactics={"channel_oracle", "input_abuse", "access_control"},
            verified_categories=["sqli"],
        ))

    def test_steer_uses_binding_prefer_not_llm_oracle(self):
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        from atkbrain.engine.supervise import LoopSupervisor
        sup = LoopSupervisor(project_id="p", run_id="r", objective="flag")
        plan = SupervisorPlan(
            diagnosis="时间盲注已通",
            next_plan="用 LOAD_FILE 读 /etc/passwd。",
            prefer_tactics=["channel_oracle"],
        )
        opens = [
            {"id": "i_sql", "strategy_key": "v::finding_sqli_chain", "status": "open"},
            {"id": "i_ch", "strategy_key": "v::channel_oracle", "status": "open"},
            {"id": "i_w", "strategy_key": "v::weaponize", "status": "open"},
        ]
        sup._apply_plan(
            plan, repeats=[], open_intents=opens,
            bind_flags={
                "has_verified_asset": True, "has_foothold": False,
                "verified_categories": ["sqli"],
            },
        )
        steer = sup.active_steer or ""
        self.assertIn(CLOSEOUT_OVERRIDE, steer)
        self.assertNotIn("LOAD_FILE", steer)
        allow_lines = [ln for ln in steer.splitlines() if "只允许战术" in ln]
        self.assertTrue(allow_lines)
        self.assertTrue(all("channel_oracle" not in ln for ln in allow_lines))
        self.assertIn("`finding_sqli_chain`", steer)
        self.assertEqual(plan.prefer_tactics, list(sup.binding.prefer_tactics))

    def test_module_is_track_agnostic(self):
        from atkbrain.engine.advisor_bind import (
            sanitize_closeout_plan, should_force_chain_close_review,
            should_force_oracle_review, should_refresh_stale_binding,
        )
        for fn in (
            compile_binding, binding_compliance, tighten_binding, format_binding_block,
            binding_is_locked, pick_bound_assigned, ensure_postex_orthogonal,
            postex_reserve_tactics, binding_reserve_tactics, protected_tactics,
            starves_chain_close, closeout_sidetrack_tactics,
            sanitize_closeout_plan, should_force_chain_close_review,
            should_force_oracle_review, should_refresh_stale_binding,
            in_flight_blocks_new_direction,
        ):
            names = set(inspect.signature(fn).parameters)
            self.assertFalse(names & {"objective", "src", "flag", "redteam", "is_benchmark"}, fn.__name__)


class ExploreBundleTests(unittest.TestCase):
    def test_explore_fills_orthogonal_routes_not_synonyms(self):
        plan = SupervisorPlan(
            diagnosis="500 面", next_plan="升级危险点",
            prefer_tactics=["info_to_danger"],
            must_intents=["i_d"],
        )
        opens = [
            {"id": "i_d", "strategy_key": "500::info_to_danger", "status": "open"},
            {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
            {"id": "i_in", "strategy_key": "500::input_abuse", "status": "open"},
            {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"},
        ]
        b = compile_binding(plan, open_intents=opens, needs_channel_oracle=True)
        self.assertIn("i_ch", b.must_intents)
        self.assertGreaterEqual(len(b.must_intents), 2)
        tacs = {
            next(i["strategy_key"] for i in opens if i["id"] == mid).split("::")[-1]
            for mid in b.must_intents
        }
        self.assertEqual(len(tacs), len(b.must_intents))
        self.assertNotIn("i_dir", b.must_intents)
        self.assertIn("content_enum", b.deny_tactics)
        self.assertIn("web-exploit", b.subagents)
        text = format_binding_block(b)
        self.assertIn("路线包", text)
        self.assertIn("并行", text)
        self.assertIn("失败后才打", text)

    def test_oracle_crowd_out_keeps_competing_hypothesis(self):
        plan = SupervisorPlan(
            diagnosis="500 面取证已收口，主线改打其它功能面",
            next_plan="路线 A 主：认证后下载。路线 C 仅当 A/B 均无果才回输入面。",
            prefer_tactics=["web_inject", "weaponize"],
            must_intents=["i_web", "i_wpn", "i_in"],
        )
        opens = [
            {"id": "i_web", "strategy_key": "svc::web_inject", "status": "open"},
            {"id": "i_wpn", "strategy_key": "500::weaponize", "status": "open"},
            {"id": "i_in", "strategy_key": "500::input_abuse", "status": "open"},
            {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
        ]
        b = compile_binding(plan, open_intents=opens, needs_channel_oracle=True)
        self.assertIn("i_ch", b.must_intents)
        self.assertIn("i_in", b.must_intents)
        self.assertNotIn("i_wpn", b.must_intents)
        from atkbrain.engine.advisor_bind import ORACLE_DIAG, ORACLE_KEEP, surface_false_close
        self.assertIn("输入面未关", b.next_plan)
        self.assertNotIn("仅当 A/B 均无果", b.next_plan)
        self.assertTrue(ORACLE_KEEP in b.next_plan)
        self.assertIn("输入面关闭", plan.diagnosis)
        self.assertNotIn("主线改打", plan.diagnosis)
        self.assertNotIn("已收口", plan.diagnosis)
        self.assertEqual(b.diagnosis, plan.diagnosis)
        self.assertEqual(plan.diagnosis, ORACLE_DIAG)
        self.assertNotIn("仅当其它路线无果", format_binding_block(b))
        self.assertTrue(surface_false_close("恒定错误页已闭合"))
        self.assertIn("同一状态码再采样", b.next_plan)
        self.assertNotIn("413", b.next_plan)
        self.assertNotIn("file_read_chain", b.deny_tactics)

    def test_oracle_drops_loot_prefer_and_defers_enum(self):
        plan = SupervisorPlan(
            diagnosis="口令面关闭", next_plan="改打静态目录",
            prefer_tactics=["file_read_chain", "fingerprint", "content_enum"],
            must_intents=["i_fp", "i_dir"],
        )
        opens = [
            {"id": "i_fp", "strategy_key": "svc::fingerprint", "status": "open"},
            {"id": "i_dir", "strategy_key": "svc::content_enum", "status": "open"},
            {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
            {"id": "i_in", "strategy_key": "500::input_abuse", "status": "open"},
        ]
        b = compile_binding(plan, open_intents=opens, needs_channel_oracle=True)
        self.assertIn("i_ch", b.must_intents)
        self.assertIn("i_in", b.must_intents)
        self.assertNotIn("i_dir", b.must_intents)
        self.assertIn("content_enum", b.deny_tactics)
        self.assertNotIn("file_read_chain", b.prefer_tactics)
        from atkbrain.engine.advisor_bind import ORACLE_DIAG, surface_false_close
        self.assertTrue(surface_false_close("口令面关闭"))
        self.assertEqual(plan.diagnosis, ORACLE_DIAG)

    def test_yield_turn_is_not_binding_miss(self):
        b = AdvisorBinding(
            stall="method",
            next_plan="换通道",
            prefer_tactics=["channel_oracle", "input_abuse"],
            must_intents=["i_ch", "i_in"],
            deny_tactics=["content_enum"],
        )
        opens = [
            {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
            {"id": "i_in", "strategy_key": "500::input_abuse", "status": "open"},
        ]
        self.assertEqual(
            binding_compliance(
                b, assigned=opens, open_intents=opens,
                last_turn_text="本回合满 180s，让出给顾问。", last_tool_uses=1,
            ),
            "executed",
        )

    def test_force_oracle_review_on_unsettled_channel(self):
        from atkbrain.engine.advisor_bind import should_force_oracle_review
        self.assertTrue(should_force_oracle_review(
            needs_oracle=True, has_plan=False,
        ))
        self.assertTrue(should_force_oracle_review(
            needs_oracle=True, has_plan=True,
            assigned_tactics={"fingerprint", "content_enum"},
        ))
        self.assertFalse(should_force_oracle_review(
            needs_oracle=True, has_plan=True,
            assigned_tactics={"web_inject", "fingerprint"},
        ))
        self.assertFalse(should_force_oracle_review(
            needs_oracle=False, has_plan=False,
        ))

    def test_tighten_keeps_bundle_tactics(self):
        b = AdvisorBinding(
            stall="method",
            next_plan="取证+注入差分",
            prefer_tactics=["info_to_danger", "fingerprint", "web_inject"],
            deny_tactics=["content_enum"],
        )
        t = tighten_binding(b)
        self.assertNotIn("fingerprint", t.deny_tactics)
        self.assertNotIn("web_inject", t.deny_tactics)
        self.assertIn("content_enum", t.deny_tactics)
        self.assertIn("fingerprint", t.prefer_tactics)
        self.assertIn("web_inject", t.prefer_tactics)

    def test_refresh_method_not_closeout(self):
        from atkbrain.engine.advisor_bind import should_refresh_stale_binding
        method = AdvisorBinding(stall="method", misses=3)
        self.assertTrue(should_refresh_stale_binding(method, misses_limit=3))
        self.assertFalse(should_refresh_stale_binding(
            AdvisorBinding(stall="method", misses=2), misses_limit=3,
        ))
        self.assertFalse(should_refresh_stale_binding(
            AdvisorBinding(stall="postex", misses=9), misses_limit=3,
        ))
        self.assertFalse(should_refresh_stale_binding(
            AdvisorBinding(stall="chain", misses=9), misses_limit=3,
        ))

    def test_compile_drops_bans_named_in_plan(self):
        plan = SupervisorPlan(
            diagnosis="500 面",
            next_plan="对 /login、/admin 与随机 404 对照",
            ban_repeats=["/login", "/admin", "/user/1"],
        )
        b = compile_binding(plan)
        self.assertNotIn("/login", b.ban_repeats)
        self.assertNotIn("/admin", b.ban_repeats)
        self.assertIn("/user/1", b.ban_repeats)

    def test_compliance_allows_plan_ordered_path(self):
        b = AdvisorBinding(
            stall="method",
            next_plan="对 /login、/admin 与随机 404 对照",
            prefer_tactics=["info_to_danger"],
            ban_repeats=["/login", "/admin", "/user/1"],
            must_intents=["i_d"],
        )
        opens = [{"id": "i_d", "strategy_key": "x::info_to_danger", "status": "open"}]
        self.assertEqual(
            binding_compliance(
                b, assigned=opens, open_intents=opens,
                last_turn_text="GET /login 500, delay 13ms", last_tool_uses=6,
            ),
            "executed",
        )
        self.assertEqual(
            binding_compliance(
                b, assigned=opens, open_intents=opens,
                last_turn_text="继续扫 /user/1", last_tool_uses=6,
            ),
            "ignored",
        )

    def test_closeout_keeps_consume_and_other_live_surface(self):
        plan = SupervisorPlan(prefer_tactics=["ssrf_as_gateway", "web_inject"])
        opens = [
            {"id": "i_gw", "strategy_key": "v::ssrf_as_gateway", "status": "open"},
            {"id": "i_web", "strategy_key": "v::web_inject", "status": "open"},
            {"id": "i_ch", "strategy_key": "v::channel_oracle", "status": "open"},
        ]
        b = compile_binding(
            plan, open_intents=opens,
            has_verified_asset=True, has_foothold=False,
            verified_categories=["ssrf"],
        )
        self.assertEqual(b.stall, "chain")
        self.assertIn("i_gw", b.must_intents)
        self.assertEqual(b.must_intents[0], "i_gw")
        self.assertIn("i_web", b.must_intents)
        self.assertNotIn("i_ch", b.must_intents)
        self.assertNotIn("web_inject", b.deny_tactics)
        self.assertIn("channel_oracle", b.deny_tactics)


class MustLockTests(unittest.TestCase):
    def test_refuse_disprove_bound_must(self):
        from types import SimpleNamespace
        from atkbrain.agents.tools import MUST_DISPROVE_REFUSE, refuse_disprove_bound_must
        ctx = SimpleNamespace(bound_must_intents=frozenset({"i_must"}))
        self.assertEqual(
            refuse_disprove_bound_must(ctx, "i_must", False),
            MUST_DISPROVE_REFUSE,
        )
        self.assertIsNone(refuse_disprove_bound_must(ctx, "i_must", True))
        self.assertIsNone(refuse_disprove_bound_must(ctx, "i_other", False))
        self.assertIsNone(refuse_disprove_bound_must(
            SimpleNamespace(bound_must_intents=frozenset()), "i_must", False,
        ))


class InFlightCloseoutTests(unittest.TestCase):
    def test_unverified_oracle_still_blocks(self):
        assigned = [{"id": "i_ch", "strategy_key": "x::channel_oracle"}]
        opens = [{"id": "i_ch", "strategy_key": "x::channel_oracle", "status": "open"}]
        self.assertTrue(in_flight_blocks_new_direction(assigned, opens))

    def test_verified_oracle_leftover_does_not_block(self):
        assigned = [
            {"id": "i_ch", "strategy_key": "x::channel_oracle"},
            {"id": "i_ac", "strategy_key": "x::access_control"},
        ]
        opens = [
            {"id": "i_ch", "strategy_key": "x::channel_oracle", "status": "open"},
            {"id": "i_ac", "strategy_key": "x::access_control", "status": "open"},
        ]
        self.assertFalse(in_flight_blocks_new_direction(
            assigned, opens, has_verified_asset=True, verified_categories=["sqli"],
        ))

    def test_verified_sqli_chain_still_blocks(self):
        assigned = [{"id": "i_sql", "strategy_key": "x::finding_sqli_chain"}]
        opens = [{"id": "i_sql", "strategy_key": "x::finding_sqli_chain", "status": "open"}]
        self.assertTrue(in_flight_blocks_new_direction(
            assigned, opens, has_verified_asset=True, verified_categories=["sqli"],
        ))

    def test_closeout_text_escalates_proof_class(self):
        self.assertIn("更快证明类", CLOSEOUT_OVERRIDE)
        self.assertIn("按位抽取", CLOSEOUT_OVERRIDE)


if __name__ == "__main__":
    unittest.main()
