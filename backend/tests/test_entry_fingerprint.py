"""入口指纹与同题多地址：按活探针分流，不写死端口、不扫题面关键词。"""
from __future__ import annotations

import unittest

from atkbrain.entry_fingerprint import (
    classify_banner,
    kind_from_fingerprints,
    pick_focus_addr,
    project_entry_addrs,
    subtract_own_entries,
    subtract_own_hosts,
)


class ClassifyBannerTests(unittest.TestCase):
    def test_http_status_line(self):
        self.assertEqual(
            classify_banner(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
            "http",
        )

    def test_filter_page(self):
        self.assertEqual(
            classify_banner(b"HTTP/1.1 403 Forbidden\r\n\r\nblocked by filter"),
            "filter",
        )
        self.assertEqual(classify_banner(b"<html>ok</html>", http_status=403), "filter")

    def test_numbered_menu_is_interactive(self):
        self.assertEqual(
            classify_banner(b"Welcome\n1) encrypt\n2) decrypt\n> "),
            "interactive",
        )

    def test_binary_is_interactive(self):
        self.assertEqual(classify_banner(b"\x00\x01\x02\xff" * 20), "interactive")

    def test_empty_is_unknown(self):
        self.assertEqual(classify_banner(b""), "unknown")

    def test_http_surface_tags_from_synthetic_body(self):
        from atkbrain.entry_fingerprint import classify_http_surface
        self.assertIn(
            "graphql",
            classify_http_surface(b"HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"__schema\":{}}}"),
        )
        soap = classify_http_surface(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n"
            b"<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"></soap:Envelope>"
        )
        self.assertIn("soap", soap)
        self.assertIn("xml", soap)
        self.assertIn(
            "jwt",
            classify_http_surface(
                b"HTTP/1.1 200 OK\r\nAuthorization: Bearer "
                b"eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0.signature\r\n\r\n"
            ),
        )
        self.assertIn(
            "multipart",
            classify_http_surface(b"<form enctype=\"multipart/form-data\"><input type=\"file\"></form>"),
        )
        self.assertIn(
            "template_error",
            classify_http_surface(b"Traceback jinja2.exceptions.UndefinedError: x"),
        )
        self.assertIn(
            "json_api",
            classify_http_surface(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"openapi\":\"3.0\"}"),
        )
        self.assertEqual(classify_http_surface(b"Welcome\n1) encrypt\n"), [])

    def test_object_store_beats_xml_parse(self):
        from atkbrain.entry_fingerprint import classify_http_surface, merge_surface_tags
        s3 = classify_http_surface(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\r\n"
            b"<?xml version=\"1.0\"?>"
            b"<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
            b"<Name>demo</Name></ListBucketResult>"
        )
        self.assertIn("object_store", s3)
        self.assertNotIn("xml", s3)
        hdr = classify_http_surface(
            b"HTTP/1.1 404 Not Found\r\n\r\nNoSuchBucket",
            headers={"x-amz-request-id": "abc", "Server": "S3rver"},
        )
        self.assertIn("object_store", hdr)
        self.assertEqual(merge_surface_tags(["xml", "object_store"]), ["object_store"])

    def test_html_php_expr_and_race_surfaces(self):
        from atkbrain.entry_fingerprint import classify_http_surface
        self.assertIn(
            "html_sink",
            classify_http_surface(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                b"<html><body>hello canary123</body></html>",
                url="http://10.0.0.8/?q=canary123",
            ),
        )
        self.assertNotIn(
            "html_sink",
            classify_http_surface(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                b"<html><body>ok</body></html>",
                url="http://10.0.0.8/?q=canary123",
            ),
        )
        self.assertIn(
            "php_serial",
            classify_http_surface(
                b'HTTP/1.1 200 OK\r\n\r\nO:8:"stdClass":1:{s:1:"a";s:1:"b";}',
            ),
        )
        self.assertIn(
            "expr_eval",
            classify_http_surface(
                b"HTTP/1.1 400 Bad Request\r\n\r\nSyntaxError: unexpected token '*'",
            ),
        )
        self.assertIn(
            "race_window",
            classify_http_surface(
                b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
                method="PUT", status=200,
            ),
        )
        self.assertNotIn(
            "race_window",
            classify_http_surface(
                b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}",
                method="PUT", status=200, headers={"ETag": "1"},
            ),
        )

    def test_homepage_script_graphql_missed_by_512(self):
        from atkbrain.entry_fingerprint import classify_http_surface
        html = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            + b"<!DOCTYPE html>" + (b"x" * 1900)
            + b"fetch('/graphql/', {method:'POST'})"
        )
        self.assertNotIn("graphql", classify_http_surface(html[:512]))
        self.assertIn("graphql", classify_http_surface(html[:4096]))

    def test_contract_error_body_still_tags_graphql(self):
        from atkbrain.entry_fingerprint import classify_http_surface
        self.assertIn(
            "graphql",
            classify_http_surface(
                b"HTTP/1.1 400 Bad Request\r\n\r\nNo GraphQL query found in the request"
            ),
        )

    def test_contract_paths_skip_already_tagged(self):
        from atkbrain.entry_fingerprint import contract_paths_for, merge_surface_tags
        all_paths = contract_paths_for([])
        self.assertIn("/graphql", all_paths)
        self.assertIn("/?wsdl", all_paths)
        self.assertNotIn("/graphql", contract_paths_for(["graphql"]))
        self.assertEqual(merge_surface_tags(["graphql"], ["graphql", "soap"]), ["graphql", "soap"])
        self.assertEqual(merge_surface_tags(["nope"], None), [])

    def test_contract_404_echo_is_not_a_surface(self):
        from atkbrain.entry_fingerprint import contract_response_usable, classify_http_surface
        apache_404 = (
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
            b"<p>The requested URL /graphql was not found on this server.</p>"
            b"<p>The requested URL /wsdl was not found on this server.</p>"
            b"<p>The requested URL /openapi.json was not found on this server.</p>"
        )
        self.assertFalse(contract_response_usable(apache_404))
        gql400 = b"HTTP/1.1 400 Bad Request\r\n\r\nNo GraphQL query found in the request"
        self.assertTrue(contract_response_usable(gql400))
        self.assertIn("graphql", classify_http_surface(gql400))


class FocusAndOwnTests(unittest.TestCase):
    def test_pick_interactive_before_http(self):
        addrs = ["10.0.0.8:80", "10.0.0.9:81"]
        fps = {"10.0.0.8:80": "http", "10.0.0.9:81": "interactive"}
        self.assertEqual(pick_focus_addr(addrs, fps), "10.0.0.9:81")
        self.assertEqual(kind_from_fingerprints(fps), "mixed")

    def test_http_only_keeps_first(self):
        addrs = ["10.0.0.8:80", "10.0.0.8:8080"]
        fps = {"10.0.0.8:80": "http", "10.0.0.8:8080": "http"}
        self.assertEqual(pick_focus_addr(addrs, fps), "10.0.0.8:80")
        self.assertEqual(kind_from_fingerprints(fps), "http")

    def test_subtract_own_second_addr(self):
        peer = {"10.0.0.8:80", "10.0.0.9:81", "10.0.0.7:80"}
        own = {"10.0.0.8:80", "10.0.0.9:81"}
        self.assertEqual(subtract_own_entries(peer, own), {"10.0.0.7:80"})
        self.assertEqual(
            subtract_own_hosts({"10.0.0.8", "10.0.0.7"}, {"10.0.0.8", "10.0.0.9"}),
            {"10.0.0.7"},
        )

    def test_project_entry_addrs_include_all_container_addr(self):
        proj = {
            "target": "10.0.0.8",
            "ports": [80, 81],
            "config": {"benchmark": {"container_addr": ["10.0.0.8:80", "10.0.0.9:81"]}},
        }
        addrs = project_entry_addrs(proj)
        self.assertIn("10.0.0.8:80", addrs)
        self.assertIn("10.0.0.9:81", addrs)

    def test_surfaces_from_project_flat_and_per_addr(self):
        from atkbrain.entry_fingerprint import surfaces_from_project
        proj = {
            "config": {
                "benchmark": {
                    "entry_surface": {
                        "10.0.0.8:80": ["graphql", "json_api"],
                        "10.0.0.8:8080": ["graphql"],
                    }
                }
            }
        }
        flat = surfaces_from_project(proj)
        self.assertEqual(flat, ["graphql", "json_api"])
        per = surfaces_from_project(proj, per_addr=True)
        self.assertEqual(per["10.0.0.8:80"], ["graphql", "json_api"])

    def test_no_port_number_literals_in_module(self):
        import inspect
        from atkbrain import entry_fingerprint as m
        src = inspect.getsource(m)
        self.assertNotIn("1337", src)
        self.assertNotIn("9999", src)
        self.assertNotIn("背包", src)
        self.assertNotIn("S盒", src)


class TurnHintTests(unittest.TestCase):
    def test_interactive_turn_does_not_default_web_exploit(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(
            1, "10.0.0.9", "", "",
            objective="flag", entry_kind="interactive",
            entry_addrs=["10.0.0.8:80", "10.0.0.9:81"],
        )
        self.assertIn("protocol-model", text)
        self.assertIn("10.0.0.9:81", text)
        self.assertNotIn("早期：并行 `recon` + `web-exploit`", text)

    def test_http_turn_still_web_exploit(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(1, "10.0.0.8", "", "", objective="flag", entry_kind="http")
        self.assertIn("recon` + `web-exploit", text)
        self.assertNotIn("protocol-model", text)

    def test_filter_turn_skips_dir_enum(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(1, "10.0.0.8", "", "", objective="flag", entry_kind="filter")
        self.assertIn("拦截", text)
        self.assertIn("不要结案去枚举目录", text)

    def test_flag_postex_turn_asks_lateral_not_only_local_flag_hunt(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(
            4, "10.0.0.8", "", "",
            objective="flag", postex_phase="active",
            steering="【AI监督】从壳打邻机",
        )
        self.assertIn("后渗透", text)
        self.assertIn("lateral", text)
        self.assertIn("硬约束", text)
        self.assertIn("不是评语", text)
        self.assertNotIn("纠偏指令（人工覆盖监督", text)

    def test_lock_intents_skips_early_recon(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(
            2, "10.0.0.8", "", "【本轮必须推进】\n  ★ [i_hop] hop",
            objective="flag", lock_intents=True,
            steering="【AI监督】从壳打邻机",
        )
        self.assertIn("强制执行", text)
        self.assertIn("顾问=人工指令", text)
        self.assertNotIn("早期：并行 `recon` + `web-exploit`", text)
        self.assertIn("不要另开与硬约束无关的 Task", text)

    def test_system_prompt_names_solvers_and_protocol_model(self):
        from atkbrain.agents.prompts import build_subagents, build_system_prompt
        from atkbrain.scope import Scope
        prompt = build_system_prompt(Scope(targets=["10.0.0.8"]), "/tmp/ws", objective="flag")
        self.assertIn("z3-solver", prompt)
        self.assertIn("pwntools", prompt)
        self.assertIn("protocol-model", prompt)
        self.assertNotIn("1337", prompt)
        agents = build_subagents("flag")
        self.assertIn("protocol-model", agents)
        self.assertIn("reverse", agents)
        blob = agents["protocol-model"].prompt
        self.assertIn("记下", blob)
        self.assertIn("可执行文件", blob)
        self.assertNotIn("SPN", blob)
        self.assertNotIn("JWT", blob)
        rev = agents["reverse"].prompt
        self.assertIn("objdump", rev)
        self.assertIn("不要目录枚举", rev)
        recon_tools = agents["recon"].tools or []
        self.assertNotIn("WebSearch", recon_tools)
        self.assertNotIn("WebFetch", recon_tools)
        self.assertIn("禁止用 unique_code", prompt)
        from atkbrain.agents.prompts import builtin_allowed_tools, builtin_fs_tools
        self.assertNotIn("WebSearch", builtin_fs_tools("flag"))
        self.assertNotIn("WebSearch", builtin_allowed_tools("flag"))
        self.assertIn("WebSearch", builtin_allowed_tools("getshell"))

    def test_graphql_surface_turn_hint(self):
        from atkbrain.agents.prompts import build_turn_instruction
        text = build_turn_instruction(
            1, "10.0.0.8", "", "", objective="flag", entry_kind="http",
            entry_surface=["graphql"],
        )
        self.assertIn("GraphQL", text)
        self.assertIn("不要目录爆破", text)
        self.assertIn("中型字典", text)
        self.assertIn("web-exploit", text)
        self.assertIn("recon", text)
        self.assertNotIn("writeup", text.lower())

    def test_object_store_and_html_sink_turn_hints(self):
        from atkbrain.agents.prompts import build_subagents, build_turn_instruction
        text = build_turn_instruction(
            1, "10.0.0.8", "", "", objective="flag", entry_kind="http",
            entry_surface=["object_store"],
        )
        self.assertIn("对象存储", text)
        self.assertIn("键级", text)
        self.assertNotIn("XXE", text)
        self.assertNotIn("TRACE", text)
        self.assertIn("web-exploit", text)
        html = build_turn_instruction(
            1, "10.0.0.8", "", "", objective="flag", entry_kind="http",
            entry_surface=["html_sink"],
        )
        self.assertIn("短 canary", html)
        self.assertIn("不要目录爆破", html)
        prompt = build_subagents("flag")["web-exploit"].prompt
        self.assertIn("对象存储", prompt)
        self.assertIn("受限反序列化", prompt)
        self.assertIn("并发窗口", prompt)
        self.assertNotIn("XXE", prompt)
        self.assertNotIn("TRACE", prompt)
        self.assertNotIn("xben", prompt.lower())
        self.assertNotIn("writeup", prompt.lower())

    def test_entry_url_still_does_medium_recon(self):
        from atkbrain.agents.prompts import build_brief, build_turn_instruction
        brief = build_brief({
            "config": {
                "description": "simple idor",
                "entry_url": "http://10.0.0.8/",
                "objective": "flag",
            },
            "scope": {"ips": ["10.0.0.8"]},
            "ports": [80],
        })
        self.assertIn("入口 URL", brief)
        self.assertNotIn("只做一次 nmap", brief)
        text = build_turn_instruction(
            1, "10.0.0.8", "", "", objective="flag", brief=brief, entry_kind="http",
        )
        self.assertIn("web-exploit", text)
        self.assertIn("recon", text)
        self.assertIn("--top-ports 1000", text)
        self.assertIn("中型字典", text)
        self.assertNotIn("不要开局 nmap", text)
        self.assertNotIn("只做一次 nmap", text)
        self.assertIn("不要开局", text)
        self.assertIn("large", text)

    def test_binary_brief_turn_delegates_reverse(self):
        from atkbrain.agents.prompts import build_brief, build_turn_instruction
        brief = build_brief({
            "config": {
                "description": "请分析该可执行文件并取得凭据",
                "objective": "flag",
            },
        })
        text = build_turn_instruction(
            1, "10.0.0.8", "", "", objective="flag", brief=brief, entry_kind="http",
        )
        self.assertIn("`reverse`", text)
        self.assertIn("不要扫目录", text)
        self.assertNotIn("并行 `recon` + `web-exploit`", text)

    def test_machine_note_asks_top_ports_not_full_scan(self):
        from atkbrain.agents.prompts import build_brief
        brief = build_brief({
            "target": "vhost.local",
            "config": {
                "description": "web",
                "entry_url": "http://vhost.local/",
                "objective": "flag",
                "vhosts": ["vhost.local"],
            },
            "scope": {"ips": ["10.0.0.8"]},
            "ports": [80],
        })
        self.assertIn("--top-ports 1000", brief)
        self.assertIn("中型字典", brief)
        self.assertIn("-p-", brief)
        self.assertNotIn("不要把本轮耗在 nmap", brief)
        self.assertNotIn("只做一次 nmap", brief)

    def test_both_tracks_open_with_medium_recon(self):
        from atkbrain.agents.prompts import build_brief, build_subagents, build_turn_instruction
        for obj in ("getshell", "flag"):
            brief = build_brief({
                "target": "vhost.local",
                "config": {
                    "description": "web",
                    "entry_url": "http://vhost.local/",
                    "objective": obj,
                    "vhosts": ["vhost.local"],
                },
                "scope": {"ips": ["10.0.0.8"]},
                "ports": [80],
            })
            self.assertIn("--top-ports 1000", brief, obj)
            self.assertNotIn("不要把本轮耗在 nmap", brief, obj)
            text = build_turn_instruction(
                1, "vhost.local", "", "", objective=obj, brief=brief, entry_kind="http",
            )
            self.assertIn("recon", text, obj)
            self.assertIn("--top-ports 1000", text, obj)
            self.assertIn("中型字典", text, obj)
            self.assertNotIn("不要开局 nmap", text, obj)
            recon = build_subagents(obj)["recon"].prompt
            self.assertIn("--top-ports 1000", recon, obj)
            self.assertIn("中型字典", recon, obj)
            self.assertNotIn("不要把本轮耗在 nmap", recon, obj)

    def test_http_result_surface_tags(self):
        from atkbrain.entry_fingerprint import surfaces_from_http_result
        tags = surfaces_from_http_result({
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"data":{"__schema":{}}}',
        })
        self.assertIn("graphql", tags)


if __name__ == "__main__":
    unittest.main()
