"""引擎回合收口：三赛道共用，工人不得拖住御主。"""
from __future__ import annotations

import inspect
import unittest
from pathlib import Path

from atkbrain_native import role_wrote_turn_done, turn_must_close


class RoleWroteTurnDoneTests(unittest.TestCase):
    def test_src_wrapup(self) -> None:
        self.assertTrue(role_wrote_turn_done("已完成本轮可做的面。收尾结论如下。", role="lead"))

    def test_redteam_wrapup(self) -> None:
        self.assertTrue(role_wrote_turn_done("本轮小结：已验证 SSRF。", role="lead"))

    def test_ctf_wrapup(self) -> None:
        self.assertTrue(role_wrote_turn_done("本轮结束，等待御主。", role="lead"))

    def test_english_wrapup(self) -> None:
        self.assertTrue(role_wrote_turn_done("Round complete. Stopping tools.", role="lead"))

    def test_worker_wrapup(self) -> None:
        for role in (
            "src-hunt", "web-exploit", "recon",
            "flag-hunt", "rce-hunt", "protocol-model",
            "privesc", "lateral", "reverse",
        ):
            self.assertTrue(role_wrote_turn_done("本轮完成。", role=role), role)

    def test_reviewer_never_closes(self) -> None:
        self.assertFalse(role_wrote_turn_done("本轮完成。", role="finding-review"))

    def test_mid_work_not_wrapup(self) -> None:
        self.assertFalse(role_wrote_turn_done("继续测 SSRF 和 hop_auth。", role="lead"))
        self.assertFalse(role_wrote_turn_done("", role="lead"))


class TurnMustCloseTests(unittest.TestCase):
    def test_cap_off(self) -> None:
        self.assertFalse(turn_must_close(9999, 0))

    def test_cap_hit(self) -> None:
        self.assertTrue(turn_must_close(900, 900))
        self.assertTrue(turn_must_close(901, 900))

    def test_cap_not_yet(self) -> None:
        self.assertFalse(turn_must_close(100, 900))


class TrackAgnosticCloseTests(unittest.TestCase):
    def test_close_helpers_have_no_track_params(self) -> None:
        for fn in (role_wrote_turn_done, turn_must_close):
            names = set(inspect.signature(fn).parameters)
            self.assertFalse(names & {"objective", "src", "flag", "redteam", "is_benchmark"})

    def test_session_waits_first_completed_not_gather_hunters(self) -> None:
        src = Path(__file__).resolve().parents[3] / "rust" / "atkbrain-core" / "src" / "engine.rs"
        text = src.read_text(encoding="utf-8")
        body = text.split("pub fn run_turn", 1)[1].split("fn abort_prompts", 1)[0]
        self.assertIn("turn_must_close_sec", body)
        self.assertNotIn("gather", body)

    def test_pi_aborts_on_wrapup_text(self) -> None:
        src = Path(__file__).resolve().parents[3] / "rust" / "atkbrain-core" / "src" / "pi.rs"
        text = src.read_text(encoding="utf-8")
        self.assertIn("role_wrote_turn_done", text)
        self.assertIn("self.abort()", text)
        self.assertIn("turn_closed", text)

    def test_config_cap_shared(self) -> None:
        from ..config import settings
        self.assertEqual(int(settings.turn_must_close_sec), 15 * 60)


if __name__ == "__main__":
    unittest.main()
