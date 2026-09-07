"""自进化：episode → 剧本 → 取回 → 强化。"""
from __future__ import annotations

import os
import tempfile
import unittest

from atkbrain.db import Database, now
from atkbrain.memory.evolve import (
    distill_content,
    episode_worth_ai_refine,
    evolve_from_episode_id,
    format_lessons_block,
    lesson_key,
    parse_evolve_lessons,
    reinforce_lessons,
    retrieve_lessons,
    tactics_from_lessons,
    avoid_from_lessons,
    upsert_lesson,
)


class DistillTests(unittest.TestCase):
    def test_win_episode_becomes_lesson(self):
        draft = distill_content({
            "approach": "手法 sqli；线索：inject_surface",
            "winning_chain": "entry → service(http) → vuln(sqli)",
            "techniques": ["sqli"],
            "cues": ["inject_surface"],
            "tech": ["php"],
            "failed_techniques": ["content_enum"],
            "achievements": ["getshell"],
        }, "shell", "php")
        self.assertIsNotNone(draft)
        assert draft is not None
        self.assertIn("finding_sqli_chain", draft["do"])
        self.assertIn("content_enum", draft["avoid"])
        self.assertIn("php", draft["when"])
        self.assertEqual(draft["wins"], 1)

    def test_empty_episode_not_worth_ai_refine(self):
        self.assertFalse(episode_worth_ai_refine(None))
        self.assertFalse(episode_worth_ai_refine({"skipped": True, "techniques": ["sqli"]}))
        self.assertFalse(episode_worth_ai_refine({"content": {}, "outcome": "none"}))
        self.assertTrue(episode_worth_ai_refine({
            "content": {"techniques": ["sqli"], "cues": ["inject_surface"]},
            "outcome": "fail",
        }))

    def test_fail_episode_avoid_only(self):
        draft = distill_content({
            "approach": "避免：content_enum",
            "failed_techniques": ["content_enum"],
            "cues": ["auth_surface"],
        }, "fail", "*")
        self.assertIsNotNone(draft)
        assert draft is not None
        self.assertEqual(draft["do"], [])
        self.assertIn("content_enum", draft["avoid"])
        self.assertEqual(draft["fails"], 1)

    def test_specialized_writeup_skipped(self):
        draft = distill_content({
            "approach": "主攻 /control.php 预置凭证 employee/admin",
            "techniques": [],
        }, "partial", "*")
        self.assertIsNone(draft)

    def test_getflag_only_is_not_a_method(self):
        draft = distill_content({
            "approach": "手法 getflag",
            "techniques": ["getflag"],
            "tech": ["host:10.0.182.82:9103", "flag"],
            "cues": [],
            "winning_chain": "",
            "achievements": ["getflag"],
        }, "flag", "single:web")
        self.assertIsNone(draft)

    def test_host_tags_do_not_enter_when(self):
        draft = distill_content({
            "approach": "手法 sqli；线索：inject_surface",
            "winning_chain": "entry → vuln(sqli)",
            "techniques": ["sqli"],
            "cues": ["inject_surface"],
            "tech": ["php", "host:10.0.1.2", "9014"],
            "achievements": ["getshell"],
        }, "shell", "php")
        self.assertIsNotNone(draft)
        assert draft is not None
        self.assertEqual(draft["do"], ["finding_sqli_chain"])
        self.assertIn("php", draft["when"])
        self.assertNotIn("host:10.0.1.2", draft["when"])
        self.assertNotIn("9014", draft["when"])
        self.assertNotIn("10.0.1.2", draft["rule"])

    def test_unauth_alias_maps_to_access_control(self):
        from atkbrain.memory.methodology import graph_methodology_signals, keep_tactic, scrub_lesson
        self.assertEqual(keep_tactic("unauth"), "access_control")
        self.assertEqual(keep_tactic("ssrf"), "ssrf_as_gateway")
        self.assertEqual(keep_tactic("file_read"), "file_read_chain")
        self.assertEqual(keep_tactic("rce"), "weaponize")
        self.assertEqual(keep_tactic("sqli"), "finding_sqli_chain")
        clean = scrub_lesson({"do": ["unauth"], "avoid": ["hop_auth"], "when": ["php"]})
        self.assertIsNotNone(clean)
        assert clean is not None
        self.assertIn("access_control", clean["do"])
        self.assertIn("hop_auth", clean["avoid"])
        sig = graph_methodology_signals({
            "nodes": [],
            "findings": [{"category": "unauth", "title": ""}],
            "intents": [{"strategy_key": "hop:x::access_control"}],
        })
        self.assertIn("access_control", sig)

    def test_parse_evolve_json(self):
        items = parse_evolve_lessons(
            '{"lessons":[{"action":"upsert","rule":"手法 ssti","when":["php"],'
            '"do":["ssti"],"avoid":["content_enum"],"chain":"entry → vuln(ssti)"}]}'
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["do"], ["ssti"])

    def test_parse_drops_host_writeup(self):
        items = parse_evolve_lessons(
            '{"lessons":[{"action":"upsert","when":["host:10.0.1.2"],'
            '"do":["getflag"],"avoid":[],"chain":"info:check-api -> /flag"}]}'
        )
        self.assertEqual(items, [])

    def test_lesson_key_stable(self):
        a = lesson_key(when=["php", "a"], do=["sqli"], avoid=["x"], chain="c")
        b = lesson_key(when=["a", "php"], do=["sqli"], avoid=["x"], chain="c")
        self.assertEqual(a, b)


class PlaybookStoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db = Database(self.tmp.name)
        await self.db.connect()
        import atkbrain.db as db_mod
        import atkbrain.memory.evolve as evo_mod
        from atkbrain.config import settings
        self._old = db_mod.db
        db_mod.db = self.db
        evo_mod.db = self.db
        self._old_ai = getattr(settings, "evolve_ai", True)
        settings.evolve_ai = False
        self.settings = settings
        self.evo_mod = evo_mod

    async def asyncTearDown(self):
        import atkbrain.db as db_mod
        db_mod.db = self._old
        self.evo_mod.db = self._old
        self.settings.evolve_ai = self._old_ai
        await self.db.close()
        os.unlink(self.tmp.name)

    async def test_upsert_merges_same_key(self):
        draft = distill_content({
            "approach": "手法 sqli；线索：inject_surface",
            "winning_chain": "entry → vuln(sqli)",
            "techniques": ["sqli"],
            "cues": ["inject_surface"],
            "tech": ["php"],
            "achievements": ["getshell"],
        }, "shell", "php")
        first = await upsert_lesson(dict(draft), episode_id="m_a")
        second = await upsert_lesson(dict(draft), episode_id="m_b")
        self.assertEqual(first["id"], second["id"])
        self.assertTrue(second["updated"])
        self.assertGreaterEqual(int(second["wins"]), 2)

    async def test_retrieve_prefers_matching_stack(self):
        php = distill_content({
            "approach": "手法 ssti；线索：error_reflects_input",
            "winning_chain": "entry → vuln(ssti)",
            "techniques": ["ssti"],
            "cues": ["error_reflects_input"],
            "tech": ["php"],
            "achievements": ["getshell"],
        }, "shell", "php")
        java = distill_content({
            "approach": "手法 deserialization",
            "winning_chain": "entry → vuln(deserialization)",
            "techniques": ["deserialization"],
            "cues": ["deserialize_surface"],
            "tech": ["java"],
            "achievements": ["getshell"],
        }, "shell", "java")
        await upsert_lesson(php)
        await upsert_lesson(java)
        graph = {
            "nodes": [{"type": "info", "title": "PHP 报错反射", "tags": ["php", "jinja"]}],
            "findings": [{"category": "ssti"}],
        }
        picked = await retrieve_lessons({"kind": "single"}, graph, limit=3, bump_uses=False)
        self.assertTrue(picked)
        dos = tactics_from_lessons(picked)
        self.assertIn("ssti", dos)
        block = format_lessons_block(picked)
        self.assertIn("进化经验", block)
        self.assertNotIn("10.", block)

    async def test_ctf_retrieve_ignores_host_template(self):
        await self.db.execute(
            """INSERT INTO memory(id, project_id, target_fp, version, kind, tags, content, outcome, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("m_bad", None, "single:web", 1, "lesson", '["lesson_key:bad"]',
             '{"rule":"打 host:10.0.182.82:9103 的 /check","when":["host:10.0.182.82:9103","getflag"],'
             '"do":["getflag"],"avoid":[],"chain":"","confidence":0.9}',
             "playbook", now()),
        )
        php = distill_content({
            "approach": "手法 ssti；线索：error_reflects_input",
            "winning_chain": "entry → vuln(ssti)",
            "techniques": ["ssti"],
            "cues": ["error_reflects_input"],
            "tech": ["php"],
            "achievements": ["getshell"],
        }, "shell", "php")
        await upsert_lesson(php)
        graph = {
            "nodes": [{"type": "info", "title": "PHP 报错反射", "tags": ["php", "jinja"]}],
            "findings": [{"category": "ssti"}],
        }
        picked = await retrieve_lessons(
            {"kind": "single", "config": {"objective": "flag"}},
            graph, limit=6, bump_uses=False,
        )
        blob = str(picked)
        self.assertNotIn("10.0.182.82", blob)
        self.assertNotIn("/check", blob)
        self.assertIn("ssti", tactics_from_lessons(picked))

    async def test_ctf_retrieve_skips_unrelated_stack(self):
        java = distill_content({
            "approach": "手法 deserialization",
            "winning_chain": "entry → vuln(deserialization)",
            "techniques": ["deserialization"],
            "cues": ["deserialize_surface"],
            "tech": ["java"],
            "achievements": ["getshell"],
        }, "shell", "java")
        await upsert_lesson(java)
        graph = {
            "nodes": [{"type": "info", "title": "PHP 报错反射", "tags": ["php"]}],
            "findings": [{"category": "ssti"}],
        }
        picked = await retrieve_lessons(
            {"kind": "single", "config": {"objective": "flag"}},
            graph, limit=6, bump_uses=False,
        )
        self.assertNotIn("deserialization", tactics_from_lessons(picked))

    async def test_postex_unauth_lesson_retrieves_on_foothold_graph(self):
        draft = distill_content({
            "approach": "手法 unauth",
            "techniques": ["unauth"],
            "failed_techniques": ["hop_auth"],
            "cues": ["foothold"],
            "tech": ["php"],
            "winning_chain": "foothold → vuln(unauth)",
            "achievements": ["getflag"],
        }, "flag", "php")
        self.assertIsNotNone(draft)
        assert draft is not None
        self.assertIn("access_control", draft["do"])
        self.assertIn("hop_auth", draft["avoid"])
        await upsert_lesson(draft)
        graph = {
            "nodes": [{
                "type": "foothold", "title": "shell", "tags": ["php"], "is_rce": True,
            }],
            "intents": [{"strategy_key": "hop::access_control", "status": "open"}],
            "findings": [],
        }
        picked = await retrieve_lessons(
            {"kind": "single", "config": {"objective": "flag"}},
            graph, limit=6, bump_uses=False,
        )
        self.assertIn("access_control", tactics_from_lessons(picked))
        self.assertIn("hop_auth", avoid_from_lessons(picked))

    async def test_ctf_no_playbook_before_graph_signals(self):
        php = distill_content({
            "approach": "手法 ssti；线索：error_reflects_input",
            "winning_chain": "entry → vuln(ssti)",
            "techniques": ["ssti"],
            "cues": ["error_reflects_input"],
            "tech": ["php"],
            "achievements": ["getshell"],
        }, "shell", "php")
        await upsert_lesson(php)
        picked = await retrieve_lessons(
            {"kind": "single", "config": {"objective": "flag"}},
            {"nodes": [], "findings": []},
            limit=6, bump_uses=False,
        )
        self.assertEqual(picked, [])

    async def test_reinforce_win_raises_confidence(self):
        draft = distill_content({
            "approach": "手法 sqli；线索：inject_surface",
            "techniques": ["sqli"],
            "cues": ["inject_surface"],
            "achievements": ["getshell"],
        }, "shell", "*")
        row = await upsert_lesson(draft)
        before = float(row["confidence"])
        await reinforce_lessons([row["id"]], won=True)
        got = await self.db.fetchone("SELECT content FROM memory WHERE id=?", (row["id"],))
        import json
        c = json.loads(got["content"]) if isinstance(got["content"], str) else got["content"]
        self.assertGreater(float(c["confidence"]), before)

    async def test_evolve_from_episode_row(self):
        await self.db.execute(
            """INSERT INTO memory(id, project_id, target_fp, version, kind, tags, content, outcome, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("m_ep1", "p1", "php", 1, "episode", "[]",
             '{"approach":"手法 sqli；线索：inject_surface","techniques":["sqli"],'
             '"cues":["inject_surface"],"tech":["php"],"winning_chain":"entry → vuln(sqli)",'
             '"achievements":["getshell"],"failed_techniques":[]}',
             "shell", now()),
        )
        lesson = await evolve_from_episode_id("m_ep1")
        self.assertIsNotNone(lesson)
        assert lesson is not None
        self.assertIn("finding_sqli_chain", lesson["do"])


if __name__ == "__main__":
    unittest.main()
