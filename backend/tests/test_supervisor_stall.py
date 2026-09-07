"""AI 监督：信号采集仍泛化；方案由监督模型产出，测试里 mock consult。"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from atkbrain.db import Database, now
from atkbrain.engine.ai_supervisor import (
    SupervisorPlan,
    await_supervisor_plan,
    format_ai_steer,
    is_oneshot_prompt_config_error,
    parse_runtime_review,
    parse_supervisor_plan,
    plan_is_entry_enum,
    plan_is_fake_key_loop,
    refine_supervisor_plan,
    supervisor_query_options,
)
from atkbrain.engine.supervise import (
    LoopSupervisor,
    classify_probe_payload,
    graph_has_getshell,
    has_injected_supervisor_plan,
    has_verified_asset,
    infra_from_probes,
    is_noise_repeat,
    should_consult_after_exec_fault,
    should_consult_supervisor,
    should_hold_active_plan,
    verified_chain_paths,
)
from atkbrain.engine.supervisor_brief import (
    SupervisorFacts,
    assemble_supervisor_brief,
    claimed_secret_disproved,
    flag_submission_stats,
    intent_claims_obtained_secret,
    plan_cites_peer_entry,
)
from atkbrain.graph.model import IntentIn
from atkbrain.graph import store as gstore


class ClassifyProbeTests(unittest.TestCase):
    def test_http_timeout_is_transport(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "http_request", "url": "http://10.1.2.3/",
                "status": None, "error": "timed out",
            }),
            "transport",
        )

    def test_http_403_is_app_layer(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "http_request", "url": "http://10.1.2.3/admin",
                "status": 403,
            }),
            "app",
        )

    def test_curl_000_is_transport(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "run_cmd",
                "command": "curl -m 5 -o /dev/null -w 'code=%{http_code}' http://10.1.2.3/",
                "preview": "code=000 t=5.00 curl: (28) Connection timed out",
            }),
            "transport",
        )

    def test_probe_blocked_is_app_layer(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "run_cmd",
                "preview": "探测失败：访问被阻止 / 禁止访问内网地址 HTTP/1.1 200",
            }),
            "app",
        )

    def test_port_down_is_transport(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "run_cmd",
                "command": "timeout 3 bash -c 'echo >/dev/tcp/10.0.176.112/8188' && echo up || echo down",
                "preview": "8188 down",
            }),
            "transport",
        )

    def test_probe_fail_without_http_is_transport(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "run_cmd",
                "preview": "探测失败：connect: Connection refused",
            }),
            "transport",
        )

    def test_timeout_wrapper_alone_is_ignore(self):
        self.assertEqual(
            classify_probe_payload({
                "tool": "run_cmd",
                "command": "timeout 30 nmap -sV 10.1.2.3",
                "preview": "Host is up. 80/tcp open http",
            }),
            "ignore",
        )


class InfraFromProbesTests(unittest.TestCase):
    def test_verified_asset_timeouts_are_not_infra(self):
        self.assertFalse(infra_from_probes(
            ["transport", "transport", "transport"],
            has_verified_asset=True,
        ))

    def test_bare_connect_timeouts_are_infra(self):
        self.assertTrue(infra_from_probes(
            ["transport", "transport", "transport"],
            has_verified_asset=False,
        ))

    def test_app_anywhere_in_window_keeps_entry_alive(self):
        self.assertFalse(infra_from_probes(
            ["app", "transport", "transport", "transport"],
            has_verified_asset=False,
        ))
        self.assertFalse(infra_from_probes(
            ["transport", "transport", "app", "transport"],
            has_verified_asset=False,
        ))

    def test_tcp_alive_timeouts_are_not_infra(self):
        self.assertFalse(infra_from_probes(
            ["transport", "transport", "transport"],
            has_verified_asset=False,
            entry_tcp_alive=True,
        ))


class PathProtectTests(unittest.TestCase):
    def test_noise_repeats_filtered(self):
        self.assertTrue(is_noise_repeat("/tmp/ssrf_out.log"))
        self.assertTrue(is_noise_repeat("cmd:cd /home/kali/atkbrain-src-20260810/backend/data/workspaces/p_x"))
        self.assertTrue(is_noise_repeat("/dev/null"))
        self.assertTrue(is_noise_repeat("/home/kali/"))
        self.assertTrue(is_noise_repeat("sqlite3 /home/kali/桌面/StrikeAgent_AtkBrain-Flash/backend/data/atkbrain.db"))
        self.assertFalse(is_noise_repeat("/probe"))
        self.assertFalse(is_noise_repeat("/debug/config"))

    def test_verified_paths_extracted(self):
        graph = {
            "nodes": [{
                "type": "vuln", "key": "vuln:ssrf", "title": "/probe SSRF 可达 /debug/config",
                "detail": "POST /probe target_url=http://internal/debug/config",
                "tags": ["ssrf", "verified"], "severity": "high",
            }],
            "findings": [],
        }
        paths = verified_chain_paths(graph)
        self.assertTrue(any("probe" in p for p in paths) or "/probe" in paths)
        self.assertTrue(has_verified_asset(graph))

        self.assertFalse(has_verified_asset({"nodes": [], "findings": []}))

    def test_hypothesized_high_vuln_is_not_verified_asset(self):
        """未验证高危假设不能进 chain，否则会禁止过登录门。"""
        self.assertFalse(has_verified_asset({
            "nodes": [{
                "type": "vuln", "key": "vuln:unauth-upload",
                "title": "未授权上传", "status": "open",
                "severity": "critical", "tags": ["rce"],
            }],
            "findings": [{
                "title": "发现后台登录", "category": "admin_access",
                "severity": "high", "verification_status": "verified",
            }],
        }))
        self.assertFalse(has_verified_asset({
            "nodes": [{
                "type": "vuln", "key": "vuln:guess",
                "title": "猜测未授权", "status": "open",
                "severity": "high", "tags": [],
            }],
            "findings": [{
                "title": "pending rce", "category": "rce",
                "severity": "critical", "verification_status": "pending",
            }],
        }))

    def test_verified_vuln_or_foothold_is_asset(self):
        self.assertTrue(has_verified_asset({
            "nodes": [{
                "type": "vuln", "key": "vuln:ssrf", "title": "SSRF",
                "tags": ["verified"], "severity": "high",
            }],
            "findings": [],
        }))
        self.assertFalse(has_verified_asset({
            "nodes": [{
                "type": "foothold", "key": "foothold:shell:www-data",
                "title": "www-data 进行中", "tags": [],
            }],
            "findings": [],
        }))
        self.assertTrue(has_verified_asset({
            "nodes": [{
                "type": "foothold", "key": "foothold:shell:www-data",
                "title": "www-data", "tags": ["getshell"], "is_rce": True,
            }],
            "findings": [],
        }))
        self.assertTrue(graph_has_getshell({
            "nodes": [{
                "type": "foothold", "key": "foothold:shell",
                "title": "www-data", "tags": ["getshell"], "is_rce": True,
            }],
        }))
        self.assertFalse(graph_has_getshell({
            "nodes": [{
                "type": "vuln", "key": "vuln:ssrf", "tags": ["verified"], "severity": "high",
            }],
        }))
        self.assertTrue(has_verified_asset({
            "nodes": [],
            "findings": [{
                "title": "RCE canary", "category": "rce",
                "severity": "critical", "verification_status": "verified",
            }],
        }))

    def test_availability_and_crash_are_not_verified_assets(self):
        from atkbrain.engine.supervise import verified_finding_categories
        crash = {
            "nodes": [{
                "type": "vuln", "key": "vuln:login-crash",
                "title": "登录渲染层崩溃", "tags": ["verified", "availability", "crash"],
                "detail": "恒定 500 统一错误页 无 Set-Cookie",
            }],
            "findings": [{
                "title": "确定性 500", "category": "availability",
                "severity": "medium", "verification_status": "verified",
            }],
        }
        self.assertFalse(has_verified_asset(crash))
        self.assertNotIn("availability", verified_finding_categories(crash))
        self.assertTrue(has_verified_asset({
            "nodes": [{
                "type": "vuln", "key": "vuln:sqli", "title": "注入",
                "tags": ["verified", "sqli"], "severity": "high",
            }],
            "findings": [],
        }))
        self.assertIn("sqli", verified_finding_categories({
            "nodes": [{
                "type": "vuln", "key": "vuln:sqli", "title": "注入",
                "tags": ["verified", "sqli"],
            }],
            "findings": [{
                "title": "sqli", "category": "sqli",
                "severity": "high", "verification_status": "verified",
            }],
        }))

    def test_refine_strips_channel_oracle_defer_on_uniform_page(self):
        graph = {
            "nodes": [{
                "type": "danger", "key": "danger:login",
                "title": "统一错误页",
                "detail": "always 500 无 Set-Cookie",
            }],
        }
        plan = SupervisorPlan(
            diagnosis="崩溃", hold=True, stall="chain",
            next_plan="weaponize 崩溃节点",
            defer_families=["channel_oracle"],
            prefer_tactics=["weaponize"],
        )
        refine_supervisor_plan(plan, graph=graph, no_progress=0, quality="finding")
        self.assertFalse(plan.hold)
        self.assertEqual(plan.stall, "method")
        self.assertNotIn("channel_oracle", plan.defer_families)


class ParsePlanTests(unittest.TestCase):
    def test_json_object(self):
        plan = parse_supervisor_plan(
            '{"diagnosis":"该打利用链","stall":"chain","rebind_entry":false,'
            '"next_plan":"委派 rce-hunt 打 /query","must_intents":["i_ab"],'
            '"prefer_tactics":["weaponize"],"defer_families":["content_enum"],'
            '"ban_repeats":["/"],"subagents":["rce-hunt"]}'
        )
        self.assertEqual(plan.stall, "chain")
        self.assertEqual(plan.must_intents, ["i_ab"])
        self.assertIn("rce-hunt", plan.next_plan)
        self.assertFalse(plan.rebind_entry)

    def test_fenced_json(self):
        plan = parse_supervisor_plan(
            "ok\n```json\n{\"diagnosis\":\"入口挂了\",\"stall\":\"infra\","
            "\"rebind_entry\":true,\"next_plan\":\"先探活\"}\n```\n"
        )
        self.assertEqual(plan.stall, "infra")
        self.assertTrue(plan.rebind_entry)

    def test_plain_text_fallback(self):
        plan = parse_supervisor_plan("下一轮改打登录面弱口令")
        self.assertIn("弱口令", plan.next_plan)
        self.assertEqual(plan.stall, "none")

    def test_format_steer_mentions_ai(self):
        msg = format_ai_steer(SupervisorPlan(
            diagnosis="有洞未打", next_plan="去武器化", subagents=["rce-hunt"],
        ), pivots=3)
        self.assertIn("AI监督", msg)
        self.assertIn("有洞未打", msg)
        self.assertIn("rce-hunt", msg)

    def test_format_steer_appends_invert_ops_guide(self):
        from atkbrain.engine.supervisor_brief import INVERT_OPS_GUIDE, needs_invert_ops_guidance
        msg = format_ai_steer(
            SupervisorPlan(diagnosis="假收口", next_plan="反演本题表"),
            pivots=1, extra_guide=INVERT_OPS_GUIDE,
        )
        self.assertIn("占位不是答案", msg)
        self.assertIn("反演本题表", msg)
        self.assertIn("本题入口", msg)
        self.assertTrue(needs_invert_ops_guidance(claim_unverified=True))
        self.assertTrue(needs_invert_ops_guidance(graph={
            "nodes": [{"title": "原生跑通全为点号", "detail": "VM execution complete"}],
        }))
        self.assertFalse(needs_invert_ops_guidance(graph={"nodes": [{"title": "登录页"}]}))
        self.assertFalse(needs_invert_ops_guidance(graph={
            "nodes": [{"title": "proxy.php 页面占位符示例", "detail": "url=http://172.16.0.2/"}],
        }))

    def test_postex_pivot_guide_when_ssrf_or_shell(self):
        from atkbrain.engine.supervisor_brief import (
            POSTEX_PIVOT_GUIDE, needs_postex_pivot_guidance,
        )
        self.assertTrue(needs_postex_pivot_guidance(
            graph={"stats": {"has_shell": True}}, correct_flags=2, flag_count=6,
        ))
        self.assertTrue(needs_postex_pivot_guidance(
            graph={"nodes": [{"title": "unauth SSRF open proxy", "detail": "file://"}]},
            correct_flags=2, flag_count=6,
        ))
        self.assertFalse(needs_postex_pivot_guidance(
            graph={"stats": {"has_shell": True}}, correct_flags=6, flag_count=6,
        ))
        self.assertFalse(needs_postex_pivot_guidance(
            graph={"nodes": [{"title": "登录页"}]}, correct_flags=0, flag_count=1,
        ))
        self.assertIn("report_pivot_capability", POSTEX_PIVOT_GUIDE)
        self.assertIn("tactic 正交", POSTEX_PIVOT_GUIDE)
        self.assertIn("每一台", POSTEX_PIVOT_GUIDE)
        self.assertNotIn("SSH/FTP", POSTEX_PIVOT_GUIDE)
        self.assertNotIn("gunicorn", POSTEX_PIVOT_GUIDE)

    def test_sanitize_strips_template_xor_and_poison_intents(self):
        from atkbrain.engine.supervisor_brief import (
            sanitize_invert_ops_plan, strip_template_xor_clauses, _node_line,
        )
        plan = SupervisorPlan(
            diagnosis="ks[0..4] 约束 FLAG{ 拟合 keystream",
            next_plan="对 blob 做 31 轮反演。用 blob[0..4] ^ FLAG{ 得 ks 前缀。立刻 report_flag。",
            must_intents=["info:keystream-partial", "info:blob-full-31", "info:flag-format-uppercase"],
        )
        sanitize_invert_ops_plan(plan, invert_ops=True)
        self.assertNotIn("info:keystream-partial", plan.must_intents)
        self.assertNotIn("info:flag-format-uppercase", plan.must_intents)
        self.assertIn("info:blob-full-31", plan.must_intents)
        self.assertIn("反演", plan.next_plan)
        self.assertNotRegex(plan.next_plan, r"blob\[0\.\.4\]")
        self.assertIn("用 flag 花括号模板拟合密文", plan.ban_repeats)
        self.assertIn("反演本题表", strip_template_xor_clauses("反演本题表。"))
        line = _node_line(
            {"type": "info", "key": "info:ks", "title": "ks[0..4]=71 78 按 FLAG{ 约束"},
            disproved=True,
        )
        self.assertIn("已否证·假收口", line)
        self.assertNotIn("71 78", line)

    def test_runtime_review_continue_false(self):
        got = parse_runtime_review('{"continue": false, "diagnosis": "思路穷尽", "next_plan": ""}')
        self.assertFalse(got["continue"])
        self.assertIn("穷尽", got["diagnosis"])

    def test_runtime_review_parse_fail_defaults_continue(self):
        self.assertTrue(parse_runtime_review("不是 json")["continue"])
        self.assertTrue(parse_runtime_review("")["continue"])

    def test_parse_hold_flag(self):
        got = parse_supervisor_plan('{"diagnosis": "继续", "hold": true, "next_plan": "补耗时通道"}')
        self.assertTrue(got.hold)
        self.assertEqual(got.next_plan, "补耗时通道")
        self.assertFalse(parse_supervisor_plan('{"diagnosis": "更换方案", "next_plan": "x"}').hold)

    def test_refine_lifts_fake_key_hold(self):
        self.assertTrue(plan_is_fake_key_loop("把信息点当开门钥匙 secret_mount"))
        self.assertTrue(plan_is_entry_enum("继续 content_enum 目录枚举"))
        plan = SupervisorPlan(
            diagnosis="尚未否证", hold=True, stall="none",
            next_plan="把爆破失败的密钥当开门钥匙",
        )
        refine_supervisor_plan(plan, no_progress=0, quality="none")
        self.assertFalse(plan.hold)
        self.assertEqual(plan.stall, "method")

    def test_refine_lifts_stalled_hold(self):
        plan = SupervisorPlan(diagnosis="继续 A 面", hold=True, stall="none", next_plan="补观测")
        refine_supervisor_plan(plan, no_progress=2, quality="none")
        self.assertFalse(plan.hold)
        kept = SupervisorPlan(diagnosis="继续 A 面", hold=True, stall="none", next_plan="补观测")
        refine_supervisor_plan(kept, no_progress=1, quality="finding")
        self.assertTrue(kept.hold)

    def test_refine_lifts_login_vs_enum(self):
        plan = SupervisorPlan(
            diagnosis="继续", hold=True, stall="none",
            next_plan="对入口做目录枚举 content_enum",
        )
        graph = {"nodes": [{"type": "credential", "key": "cred:u", "title": "user/pass"}]}
        refine_supervisor_plan(plan, graph=graph, no_progress=0, quality="finding")
        self.assertFalse(plan.hold)

    def test_json_with_raw_newlines_in_next_plan(self):
        raw = (
            '{\n'
            '  "diagnosis": "该转后渗透",\n'
            '  "stall": "postex",\n'
            '  "hold": false,\n'
            '  "rebind_entry": false,\n'
            '  "next_plan": "P18 收口：\n1.【lateral】从 shell 打内网",\n'
            '  "must_intents": ["svc:oa"],\n'
            '  "subagents": ["lateral", "flag-hunt"]\n'
            '}'
        )
        plan = parse_supervisor_plan(raw)
        self.assertEqual(plan.stall, "postex")
        self.assertIn("lateral", plan.next_plan)
        self.assertEqual(plan.diagnosis, "该转后渗透")
        self.assertFalse(plan.hold)
        self.assertIn("flag-hunt", plan.subagents)

    def test_runtime_review_with_raw_newlines(self):
        raw = '{"continue": true, "diagnosis": "还有路\n可走", "next_plan": "继续横向"}'
        got = parse_runtime_review(raw)
        self.assertTrue(got["continue"])
        self.assertIn("还有路", got["diagnosis"])


class PlanHoldPolicyTests(unittest.TestCase):
    def test_no_plan_never_holds(self):
        self.assertFalse(should_hold_active_plan(has_active_plan=False, exec_turns=0, dwell_turns=2))

    def test_holds_until_dwell(self):
        self.assertTrue(should_hold_active_plan(has_active_plan=True, exec_turns=0, dwell_turns=2))
        self.assertTrue(should_hold_active_plan(has_active_plan=True, exec_turns=1, dwell_turns=2))
        self.assertFalse(should_hold_active_plan(has_active_plan=True, exec_turns=2, dwell_turns=2))

    def test_quality_keeps_hold(self):
        self.assertTrue(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, quality="finding",
        ))
        self.assertTrue(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, quality="flag",
        ))
        self.assertTrue(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, quality="capability_edge",
        ))

    def test_infra_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, infra=True,
        ))

    def test_dwell_zero_disables_hold(self):
        self.assertFalse(should_hold_active_plan(has_active_plan=True, exec_turns=0, dwell_turns=0))

    def test_peer_contaminated_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, peer_contaminated=True,
        ))

    def test_claim_unverified_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, claim_unverified=True,
        ))

    def test_enum_vs_surface_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, enum_vs_surface=True,
        ))
        self.assertTrue(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, enum_vs_surface=False,
        ))

    def test_fake_key_loop_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, fake_key_loop=True,
        ))

    def test_graph_stalled_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, graph_stalled=True,
        ))

    def test_login_vs_enum_lifts_hold(self):
        self.assertFalse(should_hold_active_plan(
            has_active_plan=True, exec_turns=0, dwell_turns=2, login_vs_enum=True,
        ))


class ConsultGateTests(unittest.TestCase):
    def test_no_plan_consults(self):
        self.assertTrue(should_consult_supervisor(has_active_plan=False, no_progress=0))

    def test_progress_quality_skips(self):
        self.assertFalse(should_consult_supervisor(
            has_active_plan=True, no_progress=5, quality="flag",
        ))
        self.assertFalse(should_consult_supervisor(
            has_active_plan=True, no_progress=5, quality="finding",
        ))
        self.assertFalse(should_consult_supervisor(
            has_active_plan=True, no_progress=5, quality="weak_graph",
        ))
        self.assertFalse(should_consult_supervisor(
            has_active_plan=True, no_progress=5, quality="info_node",
        ))

    def test_stuck_consults_after_two_dry_turns(self):
        self.assertFalse(should_consult_supervisor(
            has_active_plan=True, no_progress=1, quality="none",
        ))
        self.assertTrue(should_consult_supervisor(
            has_active_plan=True, no_progress=2, quality="none",
        ))

    def test_bad_signals_consult_even_with_progress(self):
        self.assertTrue(should_consult_supervisor(
            has_active_plan=True, no_progress=0, quality="finding", infra=True,
        ))
        self.assertTrue(should_consult_supervisor(
            has_active_plan=True, no_progress=0, quality="finding", graph_stalled=True,
        ))
        self.assertTrue(should_consult_supervisor(
            has_active_plan=True, no_progress=0, quality="weak_graph", fake_key_loop=True,
        ))

    def test_stall_after_zero_restores_always_consult(self):
        self.assertTrue(should_consult_supervisor(
            has_active_plan=True, no_progress=0, stall_after=0, quality="none",
        ))


class ClaimedSecretDisprovedTests(unittest.TestCase):
    def test_two_wrong_flags_without_correct(self):
        self.assertTrue(claimed_secret_disproved(correct_flags=0, wrong_flags=2, plan="继续反编译本题二进制"))
        self.assertFalse(claimed_secret_disproved(correct_flags=0, wrong_flags=1, plan="继续反编译本题二进制"))
        self.assertFalse(claimed_secret_disproved(correct_flags=1, wrong_flags=4, plan="已求得访问码"))

    def test_claim_plus_wrong_or_placeholder(self):
        self.assertTrue(claimed_secret_disproved(
            plan="已求得访问码，解密 blob",
            correct_flags=0, wrong_flags=1,
        ))
        self.assertTrue(claimed_secret_disproved(
            plan="凭据已拿到，继续 keystream",
            graph={"nodes": [{"title": "输出", "detail": "原生跑通全为点号"}]},
            correct_flags=0, wrong_flags=0,
        ))
        self.assertFalse(claimed_secret_disproved(
            plan="已求得访问码",
            correct_flags=0, wrong_flags=0,
        ))

    def test_intent_claims_obtained_secret(self):
        self.assertTrue(intent_claims_obtained_secret({
            "description": "已求得访问码，继续解密 blob",
            "strategy_key": "bin::weaponize",
        }))
        self.assertFalse(intent_claims_obtained_secret({
            "description": "反编译本题入口二进制的校验分支",
            "strategy_key": "bin::recon",
        }))

    def test_template_decrypt_node(self):
        from atkbrain.engine.supervisor_brief import node_is_template_decrypt
        self.assertTrue(node_is_template_decrypt({
            "key": "info:ks", "title": "ks 前缀按 FLAG{ 约束",
        }))
        self.assertFalse(node_is_template_decrypt({
            "key": "info:bin", "title": "本题入口二进制",
        }))


class PlanCitesPeerTests(unittest.TestCase):
    def test_cites_host_port_and_svc_not_current_entry(self):
        peers = ["10.0.182.80:9107", "10.0.182.81:9104"]
        self.assertTrue(plan_cites_peer_entry("继续打 http://10.0.182.80:9107/", peers))
        self.assertTrue(plan_cites_peer_entry("weaponize svc:9107/http", peers))
        self.assertTrue(plan_cites_peer_entry("objdump 9107_validator.bin", peers))
        self.assertTrue(plan_cites_peer_entry("cred:9107-valid-key", peers))
        self.assertFalse(plan_cites_peer_entry("reverse 10.0.182.81:9105 custom VM", peers))
        self.assertFalse(plan_cites_peer_entry("", peers))
        self.assertFalse(plan_cites_peer_entry("continue current binary", None))
        self.assertFalse(plan_cites_peer_entry(
            "不要打邻题 10.0.182.80:9107，去本题入口过内网 hop", peers,
        ))
        self.assertFalse(plan_cites_peer_entry(
            "邻题入口 10.0.182.80:9107 禁止当本题主线，从跳板打容器网", peers,
        ))

    def test_shared_low_port_does_not_void_own_entry(self):
        peers = ["10.0.162.201:80", "10.0.162.202:80"]
        self.assertFalse(plan_cites_peer_entry(
            "入口 10.0.162.200:80 可达，对 http://10.0.162.200:80/ 做指纹", peers,
        ))
        self.assertFalse(plan_cites_peer_entry(
            "禁止引入 10.0.162.201/202，只打本题 10.0.162.200:80", peers,
        ))
        self.assertTrue(plan_cites_peer_entry(
            "转去打邻题 http://10.0.162.201:80/admin", peers,
        ))


class SupervisorConsultIsolationTests(unittest.IsolatedAsyncioTestCase):
    def test_supervisor_query_has_no_tools(self):
        from atkbrain.config import Settings

        opts = supervisor_query_options()
        self.assertEqual(opts.mcp_servers, {})
        self.assertTrue(opts.strict_mcp_config)
        self.assertEqual(opts.max_turns, 1)
        self.assertEqual(opts.permission_mode, "plan")
        self.assertEqual(opts.tools, [])
        self.assertEqual(opts.allowed_tools, [])
        self.assertEqual(opts.setting_sources, [])
        self.assertEqual(opts.skills, [])
        self.assertIn("mcp__atkbrain__run_cmd", opts.disallowed_tools)
        self.assertIn("mcp__atkbrain__http_request", opts.disallowed_tools)
        self.assertIn("Bash", opts.disallowed_tools)
        self.assertIsNone(opts.can_use_tool)
        self.assertEqual(Settings.model_fields["supervisor_consult_max_attempts"].default, 0)

    async def test_query_timeout_abandons_uncancellable(self):
        import time
        from atkbrain.engine.ai_supervisor import _query_text_guarded

        async def hanging_query(*_a, **_k):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(3600)
            if False:
                yield None

        t0 = time.monotonic()
        with patch("claude_agent_sdk.query", hanging_query):
            with self.assertRaises(TimeoutError) as ctx:
                await _query_text_guarded("x", object(), 0.12, abandon_sec=0.2)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertIn("未返回", str(ctx.exception))

    async def test_query_rejects_can_use_tool_without_calling_sdk(self):
        from types import SimpleNamespace
        from atkbrain.engine.ai_supervisor import _query_text_guarded

        called = {"n": 0}

        async def should_not_run(*_a, **_k):
            called["n"] += 1
            if False:
                yield None

        opts = SimpleNamespace(can_use_tool=lambda *_a, **_k: None)
        with patch("claude_agent_sdk.query", should_not_run):
            with self.assertRaises(RuntimeError) as ctx:
                await _query_text_guarded("brief", opts, 5.0)
        self.assertEqual(called["n"], 0)
        self.assertIn("can_use_tool", str(ctx.exception))
        self.assertTrue(is_oneshot_prompt_config_error(ctx.exception))

    async def test_await_plan_does_not_retry_streaming_mode_error(self):
        calls: list[int] = []
        waits: list[tuple] = []

        async def boom(brief, **_kw):
            calls.append(len(brief or ""))
            raise ValueError(
                "can_use_tool callback requires streaming mode. "
                "Please provide prompt as an AsyncIterable instead of a string."
            )

        async def on_wait(attempt, err, delay):
            waits.append((attempt, err, delay))

        with self.assertRaises(RuntimeError) as ctx:
            await await_supervisor_plan(
                "x" * 3800,
                on_wait=on_wait,
                consult=boom,
            )
        self.assertEqual(calls, [3800])
        self.assertEqual(waits, [])
        self.assertIn("一次性提问不能挂 can_use_tool", str(ctx.exception))
        self.assertNotIn("简报", str(ctx.exception))
        self.assertNotIn("已达重试上限", str(ctx.exception))


class SupervisorStallTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        import atkbrain.graph.store as store_mod
        import atkbrain.db as db_mod
        import atkbrain.engine.supervise as sup_mod
        import atkbrain.engine.supervisor_brief as brief_mod
        import atkbrain.events as ev_mod
        import atkbrain.memory.evolve as evo_mod
        from atkbrain.config import settings
        self._old_db = db_mod.db
        db_mod.db = self.db
        store_mod.db = self.db
        sup_mod.db = self.db
        brief_mod.db = self.db
        ev_mod.db = self.db
        evo_mod.db = self.db
        self.evo_mod = evo_mod
        self._old_cd = getattr(settings, "supervisor_cooldown_sec", 8.0)
        self._old_fail_cd = getattr(settings, "supervisor_fail_cooldown_sec", 45.0)
        self._old_dwell = getattr(settings, "supervisor_plan_dwell_turns", 2)
        self._old_stall = getattr(settings, "supervisor_consult_stall_turns", 2)
        self._old_interval = getattr(settings, "advisor_min_turn_interval", 3)
        self._old_hold = getattr(settings, "advisor_hold_turns", 3)
        self._old_soft = getattr(settings, "loop_supervise_soft_turns", 3)
        self._old_hard = getattr(settings, "loop_supervise_hard_turns", 6)
        self._old_max_attempts = getattr(settings, "supervisor_consult_max_attempts", 0)
        self._old_retry_base = getattr(settings, "supervisor_consult_retry_base_sec", 4.0)
        settings.supervisor_cooldown_sec = 0.0
        settings.supervisor_fail_cooldown_sec = 0.0
        settings.supervisor_plan_dwell_turns = 2
        settings.supervisor_consult_stall_turns = 2
        settings.advisor_min_turn_interval = 3
        settings.advisor_hold_turns = 3
        settings.loop_supervise_soft_turns = 3
        settings.loop_supervise_hard_turns = 6
        settings.supervisor_consult_max_attempts = 2
        settings.supervisor_consult_retry_base_sec = 0.0
        self._old_consult = sup_mod.consult_supervisor
        self.sup_mod = sup_mod
        self.settings = settings
        self.pid = "p_stall_test"
        await self.db.execute(
            "INSERT INTO projects(id,name,kind,target,ports,scope,config,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.pid, "t", "single", "10.1.2.3", "[]", "{}", "{}", "idle", now(), now()),
        )

    def _arm_first_consult(self, sup):
        """单测里把主测打到连续两轮无有效进展，顾问才会开口。"""
        sup.no_progress = 2

    async def asyncTearDown(self):
        import atkbrain.graph.store as store_mod
        import atkbrain.db as db_mod
        import atkbrain.engine.supervisor_brief as brief_mod
        import atkbrain.events as ev_mod
        db_mod.db = self._old_db
        store_mod.db = self._old_db
        self.sup_mod.db = self._old_db
        brief_mod.db = self._old_db
        ev_mod.db = self._old_db
        self.evo_mod.db = self._old_db
        self.sup_mod.consult_supervisor = self._old_consult
        self.settings.supervisor_cooldown_sec = self._old_cd
        self.settings.supervisor_fail_cooldown_sec = self._old_fail_cd
        self.settings.supervisor_plan_dwell_turns = self._old_dwell
        self.settings.supervisor_consult_stall_turns = self._old_stall
        self.settings.advisor_min_turn_interval = self._old_interval
        self.settings.advisor_hold_turns = self._old_hold
        self.settings.loop_supervise_soft_turns = self._old_soft
        self.settings.loop_supervise_hard_turns = self._old_hard
        self.settings.supervisor_consult_max_attempts = self._old_max_attempts
        self.settings.supervisor_consult_retry_base_sec = self._old_retry_base
        await self.db.close()
        os.unlink(self.tmp.name)

    def _mock_plan(self, **kwargs):
        base = dict(
            diagnosis="测试判断",
            stall="none",
            rebind_entry=False,
            next_plan="下一步打利用链",
            must_intents=[],
            prefer_tactics=[],
            defer_families=[],
            ban_repeats=[],
            subagents=["web-exploit"],
        )
        base.update(kwargs)
        plan = SupervisorPlan(**base)

        async def fake(brief, **kw):
            fake.last_brief = brief
            return plan

        fake.last_brief = ""
        self.sup_mod.consult_supervisor = fake
        return fake

    async def test_ai_plan_injected_and_intents_assigned(self):
        await gstore.add_intent(self.pid, IntentIn(
            description="weaponize confirmed vuln", rationale="t",
            strategy_key="svc:80::weaponize", est_success=0.9,
        ))
        graph = {
            "nodes": [{
                "type": "vuln", "key": "vuln:x", "title": "/probe SSRF",
                "detail": "POST /probe", "tags": ["verified"], "severity": "high",
            }],
            "edges": [], "findings": [], "stats": {},
        }
        self._mock_plan(
            diagnosis="SQLi 已验证未武器化",
            stall="chain",
            next_plan="本轮只打 /query UNION 读文件，委派 rce-hunt",
            must_intents=["i_nope"],
            prefer_tactics=["weaponize"],
            defer_families=["content_enum"],
            ban_repeats=["/login"],
            subagents=["rce-hunt"],
        )
        sup = LoopSupervisor(project_id=self.pid, run_id="run_ai", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=1, findings=0, flags=0, graph=graph,
                           scope_hosts=["10.1.2.3"], turn=3, last_turn_text="仍在扫目录")
        self.assertEqual(sup.stall_class, "chain")
        self.assertFalse(sup.drain_rebind())
        steer = sup.drain_steer()
        self.assertIsNotNone(steer)
        self.assertIn("AI监督", steer)
        from atkbrain.engine.advisor_bind import CLOSEOUT_OVERRIDE
        self.assertIn(CLOSEOUT_OVERRIDE, steer)
        self.assertNotIn("UNION", steer)
        self.assertIn("`weaponize`", steer)
        self.assertIn("content_enum", sup.banned_strategies)
        self.assertIn("weaponize", sup.drain_prefer_tactics() or set())
        self.assertIsNotNone(sup.binding)
        self.assertIn("content_enum", sup.binding.deny_tactics)
        self.assertIn("/login", sup.banned)

    async def test_ignored_binding_does_not_consult_new_essay(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="新散文", next_plan="再写一份去横向")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{
                "type": "foothold", "key": "foothold:shell", "title": "www-data",
                "tags": ["verified", "getshell"], "is_rce": True,
            }],
            "edges": [], "findings": [], "stats": {"has_shell": True},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_bind", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        sup._apply_plan(
            SupervisorPlan(diagnosis="去横向", next_plan="从壳打邻机", stall="postex"),
            repeats=[],
            bind_flags={
                "has_foothold": True, "remaining_goals": True,
                "has_verified_asset": True, "has_internal_hops": True,
            },
        )
        sup.drain_steer()
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=5, last_tool_uses=10,
            last_turn_text="继续目录枚举 /uploads/cmd.php",
            project={"config": {"flag_count": 4}},
        )
        self.assertEqual(calls, [])
        steer = sup.drain_steer()
        self.assertIn("约束收紧", steer or "")
        self.assertIn("content_enum", sup.frontier_exclude_strategies())
        self.assertGreaterEqual(sup.binding.misses, 1)
        self.assertIn("不是评语", steer or "")

    async def test_stale_explore_bundle_refresh_consults_again(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(
                diagnosis="换路线包", next_plan="并行 oracle 与输入面",
                prefer_tactics=["channel_oracle", "input_abuse"],
            )

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{
                "type": "danger", "key": "danger:http-500", "title": "恒定 500",
                "tags": ["500-surface"],
            }],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_bundle", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        sup._apply_plan(
            SupervisorPlan(
                diagnosis="升级 500", next_plan="info_to_danger", stall="method",
                prefer_tactics=["info_to_danger"],
                defer_families=["content_enum"],
            ),
            repeats=[],
        )
        sup.binding.misses = 2
        sup.binding.deny_tactics = list(set(sup.binding.deny_tactics or []) | {"content_enum"})
        sup.drain_steer()
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=8, last_tool_uses=10,
            last_turn_text="继续目录枚举 /uploads/cmd.php",
            open_intents=[
                {"id": "i_d", "strategy_key": "500::info_to_danger", "status": "open"},
                {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
            ],
        )
        self.assertEqual(calls, [1])
        self.assertIn("channel_oracle", (sup.binding.prefer_tactics if sup.binding else []))

    async def test_restore_ignored_explore_forces_new_bundle(self):
        old = LoopSupervisor(project_id=self.pid, run_id="run_old", objective="flag")
        plan = SupervisorPlan(
            diagnosis="升级 500", stall="method",
            next_plan="对 /login 做 GET 对照取证",
            prefer_tactics=["info_to_danger"],
            ban_repeats=["/login", "/admin"],
        )
        old._apply_plan(plan, repeats=[])
        old.pivots = 1
        await old._emit_supervisor("plan", plan=plan, turn=3)
        await old._emit_continue(4, reason="binding_ignored", detail="未执行")
        sup = LoopSupervisor(project_id=self.pid, run_id="run_new", objective="flag")
        self.assertFalse(await sup.restore_last_plan())
        self.assertTrue(sup.force_bundle_review)
        self.assertIsNone(sup.binding)
        self.assertIsNone(sup.drain_steer())

    async def test_bundle_review_survives_consult_failure(self):
        async def boom(brief, **kw):
            raise RuntimeError("cli down")

        self.sup_mod.consult_supervisor = boom
        sup = LoopSupervisor(project_id=self.pid, run_id="run_fail_bundle", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        sup.force_bundle_review = True
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=8, last_tool_uses=4,
        )
        self.assertTrue(sup.force_bundle_review)
        self.assertIsNone(sup.drain_steer())

    async def test_bundle_review_waits_while_intents_in_flight(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="不该开口", next_plan="换面")

        self.sup_mod.consult_supervisor = fake
        sup = LoopSupervisor(project_id=self.pid, run_id="run_inflight_bundle", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        sup.force_bundle_review = True
        opens = [{"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"}]
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=3, last_tool_uses=4,
            assigned=opens, open_intents=opens,
        )
        self.assertEqual(calls, [])
        self.assertTrue(sup.force_bundle_review)
        self.assertIsNone(sup.drain_steer())

    async def test_bundle_review_proceeds_when_verified_oracle_leftover(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(
                diagnosis="消耗注入", next_plan="换更快证明类", stall="chain",
                prefer_tactics=["finding_sqli_chain"],
                must_intents=["i_sql"],
            )

        self.sup_mod.consult_supervisor = fake
        sup = LoopSupervisor(project_id=self.pid, run_id="run_close_oracle", objective="flag")
        sup.last_sig = (1, 0, 1, 0)
        sup.force_bundle_review = True
        opens = [
            {"id": "i_ch", "strategy_key": "500::channel_oracle", "status": "open"},
            {"id": "i_sql", "strategy_key": "login::finding_sqli_chain", "status": "open"},
        ]
        graph = {
            "nodes": [{
                "type": "vuln", "key": "v", "title": "注入",
                "tags": ["verified", "sqli"],
            }],
            "edges": [],
            "findings": [{
                "category": "sqli", "verification_status": "verified",
                "title": "time channel", "severity": "high",
            }],
            "stats": {},
        }
        await sup.evaluate(
            nodes=1, edges=0, findings=1, flags=0, graph=graph,
            turn=3, last_tool_uses=4,
            assigned=[{"id": "i_ch", "strategy_key": "500::channel_oracle"}],
            open_intents=opens,
        )
        self.assertGreaterEqual(len(calls), 1)

    async def test_infra_signal_in_brief_ai_decides_rebind(self):
        run = "run_infra"
        for _ in range(4):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                (self.pid, run, now(), "tool_result", json.dumps({
                    "tool": "http_request", "url": "http://10.1.2.3/",
                    "status": None, "error": "Connection timed out after 5000 milliseconds",
                }, ensure_ascii=False)),
            )
        fake = self._mock_plan(
            diagnosis="入口传输层失败",
            stall="infra",
            rebind_entry=True,
            next_plan="不要换攻击方法，先确认入口是否还活着",
        )
        graph = {
            "nodes": [{
                "type": "host", "key": "target:10.1.2.3", "title": "10.1.2.3",
            }],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id=run, objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=1, findings=0, flags=0, graph=graph,
                           scope_hosts=["10.1.2.3"], turn=3)
        self.assertEqual(sup.stall_class, "infra")
        self.assertTrue(sup.drain_rebind())
        self.assertEqual(fake.last_brief, "")
        self.assertIsNone(sup.drain_steer())
        self.assertNotIn("fingerprint", sup.banned_strategies)

    async def test_consult_failure_does_not_inject_template(self):
        async def boom(brief, **kw):
            raise RuntimeError("cli down")

        self.sup_mod.consult_supervisor = boom
        sup = LoopSupervisor(project_id=self.pid, run_id="run_fail", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        sup.pivots = 1
        sup.last_steer_turn = 3
        await sup.evaluate(nodes=1, edges=1, findings=0, flags=0,
                           graph={"nodes": [], "edges": [], "findings": [], "stats": {}},
                           turn=6)
        self.assertIsNone(sup.drain_steer())
        self.assertEqual(sup.stall_class, "none")

    async def test_brief_includes_graph_and_unmounted_secret(self):
        graph = {
            "nodes": [{
                "key": "cred:tok", "type": "credential", "title": "admin_token",
                "tags": ["token"], "detail": "admin_token=example",
            }],
            "disproved": [{"description": "未授权绕过 /admin", "failure_fingerprint": "401"}],
            "stats": {"nodes": 1, "edges": 0, "findings": 0},
            "findings": [], "edges": [],
        }
        facts = SupervisorFacts(unmounted_secret=True, chain_live=True)
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=facts, brief="某 CTF web",
            last_turn_text="扫了 /", turn=3, scope_hosts=["10.1.2.3"],
        )
        self.assertIn("admin_token", text)
        self.assertIn("未授权绕过", text)
        self.assertIn("未挂载的机器密钥：是", text)
        self.assertIn("某 CTF web", text)
        self.assertIn("当前入口：10.1.2.3", text)
        self.assertIn("换址", text)
        self.assertIn("客户端契约过时", text)

    async def test_brief_single_channel_negation_without_exploit_asset(self):
        graph = {
            "nodes": [{
                "key": "danger:login", "type": "danger", "title": "统一错误页",
                "detail": "always 500 无 Set-Cookie",
            }],
            "stats": {"nodes": 1, "edges": 0, "findings": 0},
            "findings": [], "edges": [],
        }
        facts = SupervisorFacts(chain_live=False)
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=facts, brief="某 CTF web",
            last_turn_text="打了登录面", turn=3, scope_hosts=["10.1.2.3"],
        )
        self.assertIn("单通道否证", text)
        self.assertIn("禁止 defer channel_oracle", text)
        live = SupervisorFacts(chain_live=True)
        live_text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r2", objective="flag",
            graph=graph, facts=live, brief="某 CTF web",
            last_turn_text="已验证注入", turn=4, scope_hosts=["10.1.2.3"],
        )
        self.assertNotIn("单通道否证", live_text)

    async def test_brief_shows_evo_tactics_and_intent_families(self):
        graph = {
            "nodes": [{"key": "foothold:sh", "type": "foothold", "title": "shell"}],
            "intents": [
                {"id": "i_h", "priority": 0.9, "status": "open",
                 "description": "过门", "strategy_key": "hop::hop_auth"},
                {"id": "i_a", "priority": 0.8, "status": "open",
                 "description": "未授权", "strategy_key": "hop::access_control"},
            ],
            "stats": {"nodes": 1, "edges": 0, "findings": 0},
            "findings": [], "edges": [],
        }
        facts = SupervisorFacts(
            postex=True, chain_live=True,
            evo_do=["access_control"], evo_avoid=["hop_auth"],
        )
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=facts, brief="web",
            turn=6, scope_hosts=["10.1.2.3"],
        )
        self.assertIn("可迁移战术", text)
        self.assertIn("优先：access_control", text)
        self.assertIn("避开：hop_auth", text)
        self.assertIn("战术族", text)
        self.assertIn("hop_auth×1", text)
        self.assertIn("access_control×1", text)
        self.assertNotIn("进化经验", text)

    def test_ctf_highlight_chain_is_not_rce_probability(self):
        from atkbrain.engine.supervisor_brief import highlight_chain_line
        rce = {"path": ["svc:80", "vuln:x"], "likelihood": 0.55}
        ctf = highlight_chain_line(rce, objective="flag")
        self.assertIn("图上高亮链", ctf)
        self.assertIn("不是夺旗概率", ctf)
        self.assertNotIn("0.55", ctf)
        self.assertNotIn("RCE 最优路径", ctf)
        rt = highlight_chain_line(rce, objective="redteam")
        self.assertIn("RCE 最优路径", rt)
        self.assertIn("边权乘积≈0.55", rt)
        self.assertNotIn("概率≈", rt)

    async def test_brief_marks_peer_entries(self):
        facts = SupervisorFacts(
            current_entry="10.0.182.81:9105",
            peer_entries=["10.0.182.80:9107", "10.0.182.81:9104"],
        )
        graph = {
            "nodes": [
                {
                    "key": "svc:9107/http", "type": "service",
                    "title": "http://10.0.182.80:9107/",
                    "tags": ["http", "port:9107", "host:10.0.182.80"],
                },
                {
                    "key": "cred:peer-key", "type": "credential",
                    "title": "邻题密钥模板 xor-key",
                    "tags": ["port:9107", "host:10.0.182.80"],
                },
                {
                    "key": "info:local-bin", "type": "info",
                    "title": "本题可执行文件",
                    "tags": ["port:9105", "host:10.0.182.81"],
                },
            ],
            "stats": {"nodes": 3, "edges": 0, "findings": 0},
            "findings": [], "edges": [],
        }
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=facts, brief="分析可执行文件",
            turn=3, scope_hosts=["10.0.182.81"],
        )
        self.assertIn("邻题入口", text)
        self.assertIn("10.0.182.80:9107", text)
        self.assertIn("邻题污染", text)
        self.assertIn("本题可执行文件", text)
        self.assertIn("rebind", text)
        self.assertNotIn("邻题密钥模板", text)
        self.assertNotIn("http://10.0.182.80:9107/", text)

    async def test_brief_strips_peer_subgraph_keeps_current_binary(self):
        facts = SupervisorFacts(
            current_entry="10.0.182.81:9105",
            peer_entries=["10.0.182.80:9107"],
        )
        graph = {
            "nodes": [
                {"key": "target:10.0.182.80", "type": "target", "title": "邻题主机"},
                {"key": "target:10.0.182.81", "type": "target", "title": "本题入口"},
                {"key": "info:a3-07-fnv1a-mechanism", "type": "info",
                 "title": "校验机制: XOR 混淆 + 哈希循环"},
                {"key": "info:local-bin", "type": "info",
                 "title": "本题可执行文件", "tags": ["port:9105", "host:10.0.182.81"]},
            ],
            "edges": [
                {"from": "target:10.0.182.80", "to": "info:a3-07-fnv1a-mechanism", "relation": "CONTAINS"},
                {"from": "target:10.0.182.80", "to": "info:local-bin", "relation": "CONTAINS"},
                {"from": "target:10.0.182.81", "to": "info:local-bin", "relation": "CONTAINS"},
            ],
            "stats": {"nodes": 4, "edges": 3, "findings": 0},
            "findings": [],
        }
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=facts, brief="分析可执行文件",
            turn=3, scope_hosts=["10.0.182.81"],
        )
        self.assertIn("本题可执行文件", text)
        self.assertNotIn("XOR 混淆", text)
        self.assertIn("邻题污染", text)

    async def test_brief_puts_uniform_error_node_on_graph_not_as_recipe(self):
        graph = {
            "nodes": [{
                "key": "danger:login-500-fault", "type": "danger",
                "title": "/login 视图持续 500(GET/POST)",
            }],
            "stats": {}, "findings": [], "edges": [],
        }
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="r", objective="flag",
            graph=graph, facts=SupervisorFacts(), brief="web",
            turn=4, scope_hosts=["10.0.189.56"],
        )
        self.assertIn("danger:login-500-fault", text)
        self.assertIn("持续 500", text)
        self.assertNotIn("不能关闭输入面", text)
        self.assertNotIn("机械信号", text)

    async def test_brief_is_graph_not_tool_flood(self):
        from atkbrain.engine.supervisor_brief import BRIEF_BUDGET
        self.assertEqual(BRIEF_BUDGET, 256_000)
        run = "run_budget"
        for i in range(40):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                (self.pid, run, now(), "tool_result", json.dumps({
                    "command": "curl " * 80, "preview": "500 " * 40,
                }, ensure_ascii=False)),
            )
        graph = {
            "nodes": [
                {"key": "danger:x", "type": "danger", "title": "/login 持续 500", "risk_score": 80},
                {"key": "svc:80", "type": "service", "title": "http", "risk_score": 10},
            ],
            "edges": [{"from": "svc:80", "to": "danger:x", "relation": "EXPOSES"}],
            "intents": [{
                "id": "i_ch", "priority": 0.8, "status": "open",
                "description": "换观测通道", "strategy_key": "svc:80::channel_oracle",
            }],
            "stats": {"nodes": 2, "edges": 1}, "findings": [],
        }
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id=run, objective="flag",
            graph=graph, facts=SupervisorFacts(), brief="题面 " * 800,
            last_turn_text="上轮流水 " * 1500, turn=16, scope_hosts=["10.1.2.3"],
        )
        self.assertLessEqual(len(text), BRIEF_BUDGET)
        self.assertIn("攻击图", text)
        self.assertIn("danger:x", text)
        self.assertIn("EXPOSES", text)
        self.assertIn("i_ch", text)
        self.assertIn("局面摘要", text)
        self.assertNotIn("curl curl", text)
        self.assertNotIn("上轮流水", text)
        self.assertNotIn("近期时间线", text)
        self.assertNotIn("指挥官上一轮", text)
        self.assertNotIn("进化经验", text)
        self.assertIn("危险点", text)
        self.assertIn("服务", text)
        self.assertIn("已给过的方案", text)
        self.assertIn("对照全部", text)
        self.assertIn("你还没给过方案", text)

    async def test_brief_matches_legend_and_prior_plans(self):
        await self.db.execute(
            "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
            (self.pid, "run_hist", now(), "supervisor", json.dumps({
                "kind": "plan", "turn": 5, "pivot": 1,
                "diagnosis": "登录面只否证了状态码",
                "next_plan": "改打耗时通道，不要再扫目录",
            }, ensure_ascii=False)),
        )
        await self.db.execute(
            "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
            (self.pid, "run_hist", now(), "supervisor", json.dumps({
                "kind": "plan", "turn": 8, "pivot": 2,
                "diagnosis": "耗时通道仍无差异",
                "next_plan": "只测长度与响应头，不要回头扫目录",
            }, ensure_ascii=False)),
        )
        graph = {
            "nodes": [
                {"key": "target:10.1.2.3", "type": "target", "title": "入口"},
                {"key": "svc:80", "type": "service", "title": "http"},
                {"key": "danger:login", "type": "danger", "title": "/login 500"},
                {"key": "vuln:sqli", "type": "vuln", "title": "盲注", "severity": "high", "is_rce": True},
                {"key": "foothold:shell", "type": "foothold", "title": "www-data",
                 "is_rce": True, "tags": ["getshell"]},
                {"key": "target:10.1.2.9", "type": "target", "title": "内网跳板"},
            ],
            "edges": [
                {"from": "target:10.1.2.3", "to": "svc:80", "relation": "CONTAINS"},
                {"from": "svc:80", "to": "danger:login", "relation": "EXPOSES"},
                {"from": "foothold:shell", "to": "target:10.1.2.9", "relation": "PIVOTS_TO"},
            ],
            "rce_path": {"path": ["svc:80", "vuln:sqli", "foothold:shell"], "likelihood": 0.8},
            "stats": {"nodes": 6, "edges": 3, "has_shell": True},
            "findings": [], "intents": [],
        }
        text = await assemble_supervisor_brief(
            project_id=self.pid, run_id="run_hist", objective="flag",
            graph=graph, facts=SupervisorFacts(), brief="web",
            turn=8, scope_hosts=["10.1.2.3"],
        )
        self.assertIn("目标：", text)
        self.assertIn("服务：", text)
        self.assertIn("危险点：", text)
        self.assertIn("漏洞：", text)
        self.assertIn("立足点：", text)
        self.assertIn("★GETSHELL [立足点", text)
        self.assertNotIn("★GETSHELL [漏洞", text)
        self.assertNotIn("候选 RCE", text)
        self.assertNotIn("候选RCE", text)
        self.assertIn("图上高亮链：", text)
        self.assertIn("svc:80 → vuln:sqli → foothold:shell", text)
        self.assertIn("不是夺旗概率", text)
        self.assertNotIn("概率≈", text)
        self.assertNotIn("RCE 最优路径", text)
        self.assertIn("内网横向", text)
        self.assertIn("PIVOTS_TO", text)
        self.assertIn("EXPOSES", text)
        self.assertNotIn("CONTAINS", text)
        self.assertIn("已给过的方案", text)
        self.assertIn("对照全部", text)
        self.assertIn("你自己写过的全部方案", text)
        self.assertIn("改打耗时通道", text)
        self.assertIn("只测长度与响应头", text)
        self.assertIn("第 1 份", text)
        self.assertIn("第 2 份", text)
        self.assertNotIn("你还没给过方案", text)

    async def test_timeout_retries_same_brief_and_injects(self):
        calls: list[int] = []

        async def flaky(brief, **kw):
            calls.append(len(brief or ""))
            if len(calls) == 1:
                raise TimeoutError("slow")
            return SupervisorPlan(diagnosis="换观测通道", stall="method", next_plan="测耗时")

        self.sup_mod.consult_supervisor = flaky
        sup = LoopSupervisor(project_id=self.pid, run_id="run_to", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "持续 500"}],
                   "edges": [], "findings": [], "stats": {}},
            last_turn_text="上轮输出 " * 400, brief="题面 " * 300, turn=15,
        )
        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(calls[1], calls[0])
        steer = sup.drain_steer()
        self.assertIsNotNone(steer)
        self.assertIn("换观测通道", steer)
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='log' ORDER BY id",
            (self.pid,),
        )
        retry_logs = []
        for r in rows:
            p = json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"]
            msg = str((p or {}).get("message") or "")
            if "原简报立刻再问" in msg or "原简报再问" in msg:
                retry_logs.append(p)
        self.assertTrue(retry_logs)
        self.assertEqual(retry_logs[0].get("level"), "info")
        self.assertNotIn("压短", retry_logs[0].get("message") or "")

    async def test_consult_caps_after_retry_without_third_wait(self):
        calls: list[int] = []

        async def dead(brief, **kw):
            calls.append(len(brief or ""))
            raise TimeoutError("超过 120s 未返回")

        self.sup_mod.consult_supervisor = dead
        sup = LoopSupervisor(project_id=self.pid, run_id="run_cap", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "持续 500"}],
                   "edges": [], "findings": [], "stats": {}},
            last_turn_text="上轮输出 " * 400, brief="题面 " * 300, turn=15,
        )
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], calls[0])
        self.assertIsNone(sup.drain_steer())

    async def test_streaming_mode_config_error_fails_once_without_inject(self):
        calls: list[int] = []

        async def boom(brief, **kw):
            calls.append(len(brief or ""))
            raise ValueError(
                "can_use_tool callback requires streaming mode. "
                "Please provide prompt as an AsyncIterable instead of a string."
            )

        self.sup_mod.consult_supervisor = boom
        sup = LoopSupervisor(project_id=self.pid, run_id="run_sdk", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "持续 500"}],
                   "edges": [], "findings": [], "stats": {}},
            last_turn_text="上轮输出 " * 400, brief="题面 " * 300, turn=15,
        )
        self.assertEqual(len(calls), 1)
        self.assertIsNone(sup.drain_steer())
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='log' ORDER BY id",
            (self.pid,),
        )
        msgs = " ".join(
            str((json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"]).get("message") or "")
            for r in rows
        )
        self.assertIn("一次性提问不能挂 can_use_tool", msgs)
        self.assertNotIn("已达重试上限", msgs)
        self.assertNotIn("简报", msgs)

    async def test_consult_fail_does_not_inject_mechanical_plan(self):
        async def dead(brief, **kw):
            raise TimeoutError("slow")

        self.sup_mod.consult_supervisor = dead
        sup = LoopSupervisor(project_id=self.pid, run_id="run_gap", objective="flag")
        sup.last_sig = (1, 1, 0, 0)
        sup.pivots = 1
        sup.last_steer_turn = 3
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{
                "type": "danger", "key": "d",
                "title": "持续 500", "detail": "无 Set-Cookie",
            }], "edges": [], "findings": [], "stats": {}},
            turn=6,
        )
        self.assertFalse(sup.prefer_tactics)
        self.assertFalse(sup.banned_strategies)
        self.assertIsNone(sup.drain_steer())

    def test_supervisor_prompt_is_procedure_not_recipe(self):
        from atkbrain.engine.ai_supervisor import SUPERVISOR_SYSTEM
        self.assertIn("观测通道", SUPERVISOR_SYSTEM)
        self.assertIn("与控制台图例相同", SUPERVISOR_SYSTEM)
        self.assertIn("你没有工具", SUPERVISOR_SYSTEM)
        self.assertIn("禁止调用", SUPERVISOR_SYSTEM)
        self.assertIn("已给过的方案", SUPERVISOR_SYSTEM)
        self.assertIn("对照第 1", SUPERVISOR_SYSTEM)
        self.assertIn("hold", SUPERVISOR_SYSTEM)
        self.assertIn("★GETSHELL", SUPERVISOR_SYSTEM)
        self.assertIn("邻题", SUPERVISOR_SYSTEM)
        self.assertIn("邻题隔离", SUPERVISOR_SYSTEM)
        self.assertIn("hold=false", SUPERVISOR_SYSTEM)
        self.assertIn("假收口", SUPERVISOR_SYSTEM)
        self.assertIn("已有 ★GETSHELL 而当前方案还在打入口", SUPERVISOR_SYSTEM)
        self.assertIn("不要因为「尚未否证」就 hold", SUPERVISOR_SYSTEM)
        self.assertIn("假钥匙", SUPERVISOR_SYSTEM)
        self.assertIn("tactic 必须互异", SUPERVISOR_SYSTEM)
        self.assertIn("看似一份方案，其实是多条路线", SUPERVISOR_SYSTEM)
        self.assertIn("禁止三条同义复述", SUPERVISOR_SYSTEM)
        self.assertIn("仅当其它路线无果", SUPERVISOR_SYSTEM)
        self.assertIn("同一状态码再采样", SUPERVISOR_SYSTEM)
        self.assertNotIn("刀", SUPERVISOR_SYSTEM)
        self.assertIn("题面给出的账号", SUPERVISOR_SYSTEM)
        self.assertIn("交旗优先于把题审完", SUPERVISOR_SYSTEM)
        self.assertIn("禁止 rockyou", SUPERVISOR_SYSTEM)
        self.assertIn("超级大字典撞哈希", SUPERVISOR_SYSTEM)
        self.assertIn("回显/联合/报错", SUPERVISOR_SYSTEM)
        self.assertIn("唯一目标是正确 flag", SUPERVISOR_SYSTEM)
        self.assertIn("红队：最高指令是 GETSHELL", SUPERVISOR_SYSTEM)
        self.assertIn("下一活体面再来一圈", SUPERVISOR_SYSTEM)
        self.assertIn("不要把整个猎收成只打一条走廊", SUPERVISOR_SYSTEM)
        self.assertIn("不是夺旗概率", SUPERVISOR_SYSTEM)
        self.assertNotIn("必须换正交动作", SUPERVISOR_SYSTEM)
        self.assertNotIn("flask-unsign", SUPERVISOR_SYSTEM)
        self.assertNotIn("/login 一直", SUPERVISOR_SYSTEM)
        self.assertNotIn("时间盲注", SUPERVISOR_SYSTEM)
        self.assertNotIn("进化经验", SUPERVISOR_SYSTEM)
        self.assertNotIn("时间线", SUPERVISOR_SYSTEM)
        self.assertNotIn("指挥官上轮输出", SUPERVISOR_SYSTEM)
        self.assertNotIn("keystream", SUPERVISOR_SYSTEM)
        self.assertNotIn("循环位移", SUPERVISOR_SYSTEM)
        self.assertNotIn("FLAG{", SUPERVISOR_SYSTEM)
        self.assertNotIn("SSH/FTP", SUPERVISOR_SYSTEM)
        self.assertNotIn("gunicorn", SUPERVISOR_SYSTEM)
        self.assertNotIn("/api/config", SUPERVISOR_SYSTEM)
        from atkbrain.engine.ai_supervisor import SUPERVISOR_RUNTIME_SYSTEM
        self.assertNotIn("keystream", SUPERVISOR_RUNTIME_SYSTEM)
        self.assertNotIn("FLAG{", SUPERVISOR_RUNTIME_SYSTEM)
        self.assertIn("必须输出 continue", SUPERVISOR_RUNTIME_SYSTEM)
        self.assertIn("不算失败", SUPERVISOR_RUNTIME_SYSTEM)
        from atkbrain.agents.prompts import _GOAL_BLOCKS, SYSTEM_PROMPT_TMPL
        self.assertNotIn("keystream", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("循环位移", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("占位符", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("1337", SYSTEM_PROMPT_TMPL)
        self.assertIn("pwntools", SYSTEM_PROMPT_TMPL)
        self.assertIn("不要用不同状态码、不同路由的耗时互相比较来结案", SYSTEM_PROMPT_TMPL)
        self.assertIn("同一状态码再采样", SYSTEM_PROMPT_TMPL)
        self.assertIn("回显/联合/报错", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("刀", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("413/405", SYSTEM_PROMPT_TMPL)
        self.assertIn("等它结束并读回结果", SYSTEM_PROMPT_TMPL)
        self.assertIn("{ctf_dict_block}", SYSTEM_PROMPT_TMPL)
        from atkbrain.agents.prompts import _flag_fragments
        postex = _flag_fragments("flag")["graph_postex_block"]
        self.assertIn("新身份域", postex)
        self.assertNotIn("登录面", postex)
        self.assertIn("protocol-model", SYSTEM_PROMPT_TMPL)
        self.assertNotIn("keystream", _GOAL_BLOCKS["flag"])
        self.assertNotIn("占位符", _GOAL_BLOCKS["flag"])
        self.assertIn("禁止超级大字典撞库", _GOAL_BLOCKS["flag"])
        self.assertIn("工作循环", _GOAL_BLOCKS["redteam"])
        self.assertIn("高危/严重", _GOAL_BLOCKS["redteam"])
        self.assertIn("GETSHELL", _GOAL_BLOCKS["redteam"])
        self.assertIn("rockyou", _flag_fragments("flag")["ctf_dict_block"])
        self.assertEqual(_flag_fragments("redteam")["ctf_dict_block"], "")
        from atkbrain.agents.prompts import _flag_fragments
        postex = _flag_fragments("flag")["graph_postex_block"]
        self.assertIn("新身份域", postex)
        self.assertNotIn("登录面", postex)

    async def test_first_eval_quality_is_none_not_flag(self):
        from atkbrain.graph.store import quality_progress_delta
        g = {"nodes": [{"type": "info"}], "edges": []}
        self.assertEqual(
            await quality_progress_delta((-1, -1, -1, -1), (5, 3, 0, 0), g),
            "none",
        )
        self.assertEqual(
            await quality_progress_delta((5, 3, 0, 0), (5, 3, 0, 1), g),
            "flag",
        )
        recon = {
            "nodes": [{"type": "service"}, {"type": "danger"}],
            "edges": [],
        }
        self.assertEqual(
            await quality_progress_delta((1, 0, 0, 0), (2, 0, 0, 0), recon),
            "weak_graph",
        )
        asset = {
            "nodes": [{"type": "vuln", "tags": ["verified"]}],
            "edges": [],
        }
        self.assertEqual(
            await quality_progress_delta((1, 0, 0, 0), (2, 0, 0, 0), asset),
            "valuable_node",
        )
        fake = self._mock_plan(diagnosis="未拿旗", next_plan="打登录")
        sup = LoopSupervisor(project_id=self.pid, run_id="run_first", objective="flag")
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=5, edges=2, findings=0, flags=0,
            graph={"nodes": [], "edges": [], "findings": [], "stats": {}},
            project={"id": self.pid, "target": "10.0.189.56"},
            scope_hosts=["10.0.189.56"],
            turn=3,
        )
        self.assertIn("本轮质量进展：none", fake.last_brief)
        self.assertNotIn("本轮质量进展：flag", fake.last_brief)
        self.assertIn("当前入口：10.0.189.56", fake.last_brief)

    def test_prefer_chain_frontier_ranks_hop_auth_above_auth_reuse(self):
        from atkbrain.engine.supervise import LoopSupervisor
        sup = LoopSupervisor(project_id="p_x", run_id="r", objective="flag")
        ranked = sup._prefer_chain_frontier([
            {"id": "a", "strategy_key": "cred:admin::auth_reuse", "description": "喷相关服务"},
            {"id": "b", "strategy_key": "target:172.20.0.4::hop_auth", "description": "过邻机自己的门"},
            {"id": "c", "strategy_key": "svc:80::content_enum", "description": "目录枚举"},
        ])
        self.assertEqual(ranked[0]["id"], "b")
        self.assertEqual(ranked[1]["id"], "a")

    def test_prefer_chain_frontier_keeps_orthogonal_postex(self):
        from atkbrain.engine.supervise import LoopSupervisor
        sup = LoopSupervisor(project_id="p_x", run_id="r", objective="flag")
        ranked = sup._prefer_chain_frontier([
            {"id": "e", "strategy_key": "w::content_enum", "description": "目录"},
            {"id": "a", "strategy_key": "x::access_control", "description": "未授权"},
            {"id": "b", "strategy_key": "y::hop_auth", "description": "过门"},
            {"id": "c", "strategy_key": "z::svc_auth_bruteforce", "description": "SSH"},
        ])
        self.assertEqual({x["id"] for x in ranked}, {"a", "b", "c"})

    def test_successful_claude_plan_is_not_rewritten(self):
        plan = SupervisorPlan(
            diagnosis="继续扫目录", stall="none",
            next_plan="content_enum",
            prefer_tactics=["content_enum"],
            defer_families=[],
        )
        sup = LoopSupervisor(project_id="p_x", run_id="r", objective="flag")
        sup._apply_plan(plan, repeats=[])
        self.assertEqual(sup.prefer_tactics, ["content_enum"])
        self.assertNotIn("channel_oracle", sup.prefer_tactics)
        self.assertNotIn("content_enum", sup.banned_strategies)
        steer = sup.drain_steer()
        self.assertIn("继续扫目录", steer)
        self.assertNotIn("flask-unsign", steer)
        self.assertEqual(sup.active_steer, steer)

    async def test_active_plan_holds_until_dwell(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="先打差分", stall="method", next_plan="只测耗时通道")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_hold", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=3, last_tool_uses=4, scope_hosts=["10.1.2.3"],
        )
        first = sup.drain_steer()
        self.assertIsNotNone(first)
        self.assertEqual(calls, [1])
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=4, last_tool_uses=6, scope_hosts=["10.1.2.3"],
        )
        self.assertEqual(calls, [1])
        self.assertEqual(sup.drain_steer(), first)
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor' ORDER BY id",
            (self.pid,),
        )
        kinds = [json.loads(r["payload"]).get("kind") for r in rows]
        self.assertEqual(kinds, ["plan", "hold"])
        self.assertEqual(json.loads(rows[1]["payload"]).get("reason"), "skip")

    async def test_peer_contaminated_plan_does_not_hold(self):
        calls: list[str] = []

        async def fake(brief, **kw):
            calls.append(brief or "")
            if len(calls) == 1:
                return SupervisorPlan(
                    diagnosis="打邻题入口",
                    next_plan="继续 http://10.0.182.80:9107/ 的模板",
                )
            return SupervisorPlan(
                diagnosis="回到本题产物",
                next_plan="反编译本题入口二进制",
            )

        self.sup_mod.consult_supervisor = fake
        import atkbrain.scope_pivot as sp
        old_peers = sp.peer_challenge_entry_addrs

        async def fake_peers(pid):
            return {"10.0.182.80:9107"}

        sp.peer_challenge_entry_addrs = fake_peers
        try:
            graph = {
                "nodes": [{"type": "danger", "key": "d", "title": "x"}],
                "edges": [], "findings": [], "stats": {},
            }
            sup = LoopSupervisor(project_id=self.pid, run_id="run_peer", objective="flag")
            sup.last_sig = (1, 0, 0, 0)
            self._arm_first_consult(sup)
            await sup.evaluate(
                nodes=1, edges=0, findings=0, flags=0, graph=graph,
                turn=3, last_tool_uses=4, scope_hosts=["10.0.182.81"],
            )
            self.assertEqual(len(calls), 1)
            await sup.evaluate(
                nodes=1, edges=0, findings=0, flags=0, graph=graph,
                turn=4, last_tool_uses=6, scope_hosts=["10.0.182.81"],
            )
            self.assertEqual(len(calls), 2)
            self.assertIn("邻题入口，已作废", calls[1])
            steer = sup.drain_steer() or ""
            self.assertIn("本题入口二进制", steer)
            self.assertNotIn("10.0.182.80:9107", steer)
        finally:
            sp.peer_challenge_entry_addrs = old_peers

    async def test_claimed_secret_wrong_flags_void_plan(self):
        calls: list[str] = []

        async def fake(brief, **kw):
            calls.append(brief or "")
            if len(calls) == 1:
                return SupervisorPlan(
                    diagnosis="已求得访问码",
                    next_plan="用该码解密 blob 并对模板做 keystream",
                )
            return SupervisorPlan(
                diagnosis="候选码已否证",
                hold=True,
                next_plan="从本题入口二进制尚未解释的校验分支求解",
            )

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{
                "type": "info", "key": "bin", "title": "本题入口二进制",
                "detail": "原生跑通输出全为点号 access denied",
            }],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_claim", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=3, last_tool_uses=4, scope_hosts=["10.1.2.3"],
        )
        self.assertEqual(len(calls), 1)
        first = sup.drain_steer() or ""
        self.assertIn("解密", first)
        for val in ("FLAG{aaa}", "FLAG{bbb}"):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                (self.pid, "run_claim", now(), "flag", json.dumps(
                    {"value": val, "correct": False}, ensure_ascii=False,
                )),
            )
        n_ok, n_bad = await flag_submission_stats(self.pid)
        self.assertEqual(n_ok, 0)
        self.assertEqual(n_bad, 2)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=4, last_tool_uses=6, scope_hosts=["10.1.2.3"],
        )
        self.assertEqual(len(calls), 2)
        self.assertIn("假收口", calls[1])
        self.assertIn("不同错误 flag：2", calls[1])
        steer = sup.drain_steer() or ""
        self.assertIn("尚未解释的校验", steer)
        self.assertNotIn("keystream", steer.lower())

    async def test_dwell_met_allows_new_plan(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(diagnosis="第一份方案", next_plan="测 A 面")
            return SupervisorPlan(diagnosis="第二份方案", next_plan="测 B 面")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_dwell", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=3)
        sup.drain_steer()
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=4, last_tool_uses=3)
        sup.drain_steer()
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=6, last_tool_uses=3)
        self.assertEqual(calls, [1, 1])
        steer = sup.drain_steer() or ""
        self.assertIn("第二份方案", steer)

    async def test_model_hold_keeps_same_plan(self):
        self.settings.supervisor_plan_dwell_turns = 1
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(diagnosis="第一份方案", next_plan="测 A 面")
            return SupervisorPlan(diagnosis="还没否证", next_plan="应被忽略", hold=True)

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_mhold", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        first = sup.drain_steer()
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=1, flags=0, graph=graph, turn=6, last_tool_uses=2)
        self.assertEqual(calls, [1])
        self.assertEqual(sup.pivots, 1)
        self.assertEqual(sup.drain_steer(), first)
        self.assertNotIn("应被忽略", first or "")

    async def test_fake_key_plan_does_not_llm_hold(self):
        self.settings.supervisor_plan_dwell_turns = 1
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(
                    diagnosis="挂密钥", next_plan="把爆破失败的 SECRET_KEY 当开门钥匙",
                )
            return SupervisorPlan(
                diagnosis="还没否证", hold=True,
                next_plan="把信息点验证为可用凭证并尝试登录",
            )

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "info", "key": "info:k", "title": "会话密钥爆破失败"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_fk", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=6, last_tool_uses=2)
        self.assertEqual(calls, [1, 1])
        self.assertEqual(sup.pivots, 2)

    async def test_graph_stall_does_not_llm_hold(self):
        self.settings.supervisor_plan_dwell_turns = 1
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(diagnosis="第一份方案", next_plan="测 A 面")
            return SupervisorPlan(diagnosis="换面", hold=True, next_plan="测 B 面")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_stall", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        self.assertEqual(calls, [1])
        # 新方案会清空转计数；再给主测两轮无进展，第二份 hold 才应被图停滞抬掉。
        sup.no_progress = 2
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=6, last_tool_uses=2)
        self.assertEqual(calls, [1, 1])
        self.assertEqual(sup.pivots, 2)
        self.assertIn("测 B 面", sup.drain_steer() or "")

    async def test_login_enum_does_not_llm_hold(self):
        self.settings.supervisor_plan_dwell_turns = 1
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(diagnosis="已登录", next_plan="对入口做目录枚举 content_enum")
            return SupervisorPlan(
                diagnosis="还没否证", hold=True, next_plan="继续目录枚举 content_enum",
            )

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [
                {"type": "credential", "key": "cred:u", "title": "user/pass", "severity": "high"},
                {"type": "service", "key": "svc:80", "title": "http"},
            ],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_enum", objective="flag")
        sup.last_sig = (2, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=2, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        first_pivots = sup.pivots
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=2, edges=0, findings=0, flags=0, graph=graph, turn=6, last_tool_uses=2)
        self.assertEqual(calls, [1, 1])
        self.assertGreater(sup.pivots, first_pivots)

    async def test_flag_progress_does_not_consult(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            if len(calls) == 1:
                return SupervisorPlan(diagnosis="第一份方案", next_plan="测 A 面")
            return SupervisorPlan(diagnosis="收口", stall="chain", next_plan="flag-hunt")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_flag", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        first = sup.drain_steer()
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=1, graph=graph, turn=4, last_tool_uses=2)
        self.assertEqual(calls, [1])
        self.assertEqual(sup.drain_steer(), first)
        self.assertNotIn("收口", first or "")

    async def test_progress_after_dwell_skips_consult(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="第一份方案", next_plan="测 A 面")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_prog", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=3)
        first = sup.drain_steer()
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=4, last_tool_uses=3)
        sup.drain_steer()
        await sup.evaluate(nodes=1, edges=0, findings=1, flags=0, graph=graph, turn=5, last_tool_uses=3)
        self.assertEqual(calls, [1])
        self.assertEqual(sup.drain_steer(), first)
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor' ORDER BY id",
            (self.pid,),
        )
        kinds = [json.loads(r["payload"]).get("kind") for r in rows]
        self.assertEqual(kinds, ["plan", "hold", "hold"])

    async def test_cooldown_emits_skip_not_silent(self):
        import time
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            raise AssertionError("cooldown must not consult")

        self.sup_mod.consult_supervisor = fake
        self.settings.supervisor_cooldown_sec = 8.0
        sup = LoopSupervisor(project_id=self.pid, run_id="run_cd", objective="flag")
        sup.last_pivot_ts = time.monotonic()
        await sup.evaluate(
            nodes=0, edges=0, findings=0, flags=0,
            graph={"nodes": [], "edges": [], "findings": [], "stats": {}},
            turn=3,
        )
        self.assertEqual(calls, [])
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (self.pid,),
        )
        kinds = [json.loads(r["payload"]).get("kind") for r in rows]
        self.assertEqual(kinds, ["skip"])
        self.assertEqual(json.loads(rows[0]["payload"]).get("turn"), 3)
        self.assertIsNone(sup.drain_steer())

    async def test_backfill_fills_missing_turns(self):
        from atkbrain.engine.supervise import load_supervised_turns
        sup = LoopSupervisor(project_id=self.pid, run_id="run_bf", objective="flag")
        await sup._emit_supervisor("plan", turn=2, extra={"next_plan": "x", "diagnosis": "y"})
        n = await sup.backfill_missing_turns(4)
        self.assertEqual(n, 3)
        self.assertEqual(await load_supervised_turns(self.pid), {1, 2, 3, 4})
        self.assertEqual(await sup.backfill_missing_turns(4), 0)

    def test_consult_after_hang_or_planless_empty(self):
        self.assertFalse(should_consult_after_exec_fault(reason="hang", has_active_plan=True))
        self.assertFalse(should_consult_after_exec_fault(reason="hang", has_active_plan=False))
        self.assertTrue(should_consult_after_exec_fault(reason="empty_turn", has_active_plan=False))
        self.assertFalse(should_consult_after_exec_fault(reason="empty_turn", has_active_plan=True))
        self.assertFalse(should_consult_after_exec_fault(reason="exec_fault", has_active_plan=False))

    async def test_hang_skip_is_not_an_injected_plan(self):
        sup = LoopSupervisor(project_id=self.pid, run_id="run_skip", objective="flag")
        await sup.emit_skip(1, reason="hang")
        self.assertFalse(await has_injected_supervisor_plan(self.pid))
        await sup._emit_supervisor("plan", turn=2, extra={"next_plan": "x", "diagnosis": "y"})
        self.assertTrue(await has_injected_supervisor_plan(self.pid))

    async def test_restore_last_plan_keeps_pivot(self):
        old = LoopSupervisor(project_id=self.pid, run_id="run_old", objective="flag")
        old.pivots = 3
        plan = SupervisorPlan(
            diagnosis="去横向", stall="postex",
            next_plan="从 shell 打 OA",
            must_intents=["svc:oa"],
            prefer_tactics=["lateral"],
            ban_repeats=["/home/kali/", "/admin/login.php"],
            subagents=["lateral"],
        )
        await old._emit_supervisor("plan", plan=plan, turn=18)
        await old._emit_supervisor(
            "hold", plan=plan, turn=19,
            extra={"diagnosis": "继续横向", "reason": "plan_hold"},
        )
        await old._emit_supervisor(
            "plan", turn=20,
            extra={
                "diagnosis": "监督输出未结构化，按全文执行",
                "next_plan": "{bad",
                "pivot": 1,
                "stall": "none",
            },
        )
        sup = LoopSupervisor(project_id=self.pid, run_id="run_new", objective="flag")
        self.assertTrue(await sup.restore_last_plan())
        self.assertEqual(sup.pivots, 3)
        self.assertEqual(sup.stall_class, "postex")
        self.assertEqual(sup.last_steer_turn, 19)
        steer = sup.drain_steer() or ""
        self.assertIn("方案 #3", steer)
        self.assertIn("从 shell 打 OA", steer)
        self.assertNotIn("/home/kali/", " ".join(sup.banned))
        self.assertIn("/admin/login.php", sup.banned)

    async def test_restore_skips_disproved_claim(self):
        old = LoopSupervisor(project_id=self.pid, run_id="run_claim_old", objective="flag")
        old.pivots = 2
        plan = SupervisorPlan(
            diagnosis="已求得访问码",
            next_plan="用该码解密 blob 并对模板做 keystream",
        )
        await old._emit_supervisor("plan", plan=plan, turn=8)
        for val in ("FLAG{aaa}", "FLAG{bbb}"):
            await self.db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                (self.pid, "run_claim_old", now(), "flag", json.dumps(
                    {"value": val, "correct": False}, ensure_ascii=False,
                )),
            )
        sup = LoopSupervisor(project_id=self.pid, run_id="run_claim_new", objective="flag")
        self.assertFalse(await sup.restore_last_plan())
        self.assertIsNone(sup.drain_steer())
        self.assertFalse(sup.last_plan_text)

    async def test_off_interval_does_not_consult(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="不该出现", next_plan="换面")

        self.sup_mod.consult_supervisor = fake
        sup = LoopSupervisor(project_id=self.pid, run_id="run_skip1", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=1, last_tool_uses=2,
        )
        self.assertEqual(calls, [])
        self.assertIsNone(sup.drain_steer())
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (self.pid,),
        )
        self.assertEqual(json.loads(rows[0]["payload"]).get("reason"), "skip")

    async def test_in_flight_blocks_interval_consult(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            raise AssertionError("in_flight must not consult")

        self.sup_mod.consult_supervisor = fake
        sup = LoopSupervisor(project_id=self.pid, run_id="run_if", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=3, last_tool_uses=2,
            assigned=[{"id": "i1"}],
            open_intents=[{"id": "i1"}],
        )
        self.assertEqual(calls, [])
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (self.pid,),
        )
        self.assertEqual(json.loads(rows[0]["payload"]).get("reason"), "skip")

    async def test_first_interval_lets_commander_before_hard_stall(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="不该出现", next_plan="换面")

        self.sup_mod.consult_supervisor = fake
        sup = LoopSupervisor(project_id=self.pid, run_id="run_letcmd", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=3, last_tool_uses=2,
        )
        self.assertEqual(calls, [])
        self.assertIsNone(sup.drain_steer())
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (self.pid,),
        )
        self.assertEqual(json.loads(rows[0]["payload"]).get("reason"), "skip")

    async def test_second_brief_includes_own_last_plan(self):
        captured: list[str] = []

        async def fake(brief, **kw):
            captured.append(brief or "")
            if len(captured) == 1:
                return SupervisorPlan(
                    diagnosis="登录面只否证了状态码",
                    stall="method",
                    next_plan="改打耗时通道，不要再扫目录",
                    defer_families=["content_enum"],
                    must_intents=["i_ch"],
                )
            if len(captured) == 2:
                return SupervisorPlan(
                    diagnosis="相对上一步只补耗时观测",
                    stall="method",
                    next_plan="只测耗时通道",
                )
            return SupervisorPlan(
                diagnosis="相对前两份改测响应头",
                stall="method",
                next_plan="只看 Content-Length",
            )

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "/login 500"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_own", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=7, last_tool_uses=2,
        )
        self.assertEqual(len(captured), 1)
        self.assertIn("你还没给过方案", captured[0])
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=10, last_tool_uses=2,
            assigned=[{"id": "i_ch", "strategy_key": "svc:80::channel_oracle"}],
            open_intents=[],
        )
        self.assertEqual(len(captured), 2)
        text_b = captured[1]
        self.assertIn("已给过的方案", text_b)
        self.assertIn("对照全部", text_b)
        self.assertIn("改打耗时通道", text_b)
        self.assertIn("登录面只否证了状态码", text_b)
        self.assertNotIn("你还没给过方案", text_b)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0, graph=graph,
            turn=13, last_tool_uses=2,
            assigned=[{"id": "i_ch", "strategy_key": "svc:80::channel_oracle"}],
            open_intents=[],
        )
        self.assertEqual(len(captured), 3)
        text_c = captured[2]
        self.assertIn("登录面只否证了状态码", text_c)
        self.assertIn("改打耗时通道", text_c)
        self.assertIn("相对上一步只补耗时观测", text_c)
        self.assertIn("只测耗时通道", text_c)
        self.assertIn("第 1 份", text_c)
        self.assertIn("第 2 份", text_c)
        self.assertIn("对照全部", text_c)

    async def test_hard_stall_breaks_hold(self):
        calls: list[int] = []

        async def fake(brief, **kw):
            calls.append(1)
            return SupervisorPlan(diagnosis="硬空转换路", next_plan="换证据链")

        self.sup_mod.consult_supervisor = fake
        graph = {
            "nodes": [{"type": "danger", "key": "d", "title": "x"}],
            "edges": [], "findings": [], "stats": {},
        }
        sup = LoopSupervisor(project_id=self.pid, run_id="run_hard", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=3, last_tool_uses=2)
        self.assertEqual(calls, [1])
        sup.drain_steer()
        sup.no_progress = 5
        await sup.evaluate(nodes=1, edges=0, findings=0, flags=0, graph=graph, turn=4, last_tool_uses=2)
        self.assertEqual(calls, [1, 1])
        self.assertIn("硬空转换路", sup.drain_steer() or "")

    async def test_stall_pivot_consult_fail_does_not_use_fallback(self):
        async def dead(brief, **kw):
            raise TimeoutError("slow")

        self.sup_mod.consult_supervisor = dead
        sup = LoopSupervisor(project_id=self.pid, run_id="run_fb", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        sup.no_progress = 5
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=4, last_tool_uses=2,
        )
        self.assertIsNone(sup.drain_steer())
        rows = await self.db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor' ORDER BY id",
            (self.pid,),
        )
        kinds = [json.loads(r["payload"]).get("kind") for r in rows]
        self.assertIn("error", kinds)
        self.assertNotIn("plan", kinds)

    async def test_consult_retries_until_claude_returns_plan(self):
        calls: list[int] = []

        async def flaky(brief, **kw):
            calls.append(len(brief or ""))
            if len(calls) < 3:
                raise TimeoutError("slow")
            return SupervisorPlan(diagnosis="换观测通道", stall="method", next_plan="测耗时")

        self.settings.supervisor_consult_max_attempts = 0
        self.sup_mod.consult_supervisor = flaky
        sup = LoopSupervisor(project_id=self.pid, run_id="run_retry", objective="flag")
        sup.last_sig = (1, 0, 0, 0)
        self._arm_first_consult(sup)
        await sup.evaluate(
            nodes=1, edges=0, findings=0, flags=0,
            graph={"nodes": [{"type": "danger", "key": "d", "title": "x"}],
                   "edges": [], "findings": [], "stats": {}},
            turn=4, last_tool_uses=2,
        )
        self.assertGreaterEqual(len(calls), 3)
        steer = sup.drain_steer() or ""
        self.assertIn("换观测通道", steer)
        self.assertNotIn("换路兜底", steer)


if __name__ == "__main__":
    unittest.main()
