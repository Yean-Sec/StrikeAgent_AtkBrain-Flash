"""顾问复盘调度：当前验证未结束不改方向。"""
from __future__ import annotations

import unittest

from atkbrain.engine.advisor_schedule import (
    assigned_still_open,
    hold_note_text,
    should_review_advisor,
    should_yield_turn_to_advisor,
    unfinished_verification,
)


_KW = dict(
    interval=3,
    hold_turns=3,
    hard_turns=6,
    last_steer_turn=None,
    in_flight=False,
    no_progress=0,
    stall_class="none",
)


class AssignedStillOpenTests(unittest.TestCase):
    def test_overlap_is_in_flight(self):
        self.assertTrue(assigned_still_open(
            [{"id": "i1"}, {"id": "i2"}],
            [{"id": "i2"}, {"id": "i9"}],
        ))

    def test_resolved_is_not_in_flight(self):
        self.assertFalse(assigned_still_open(
            [{"id": "i1"}],
            [{"id": "i9"}],
        ))

    def test_empty_assigned(self):
        self.assertFalse(assigned_still_open([], [{"id": "i1"}]))
        self.assertFalse(assigned_still_open(None, None))


class ShouldReviewAdvisorTests(unittest.TestCase):
    def test_one_turn_no_graph_growth_does_not_review(self):
        ok, why = should_review_advisor(turn=1, stall_class="none", no_progress=1, **{
            k: v for k, v in _KW.items() if k not in ("stall_class", "no_progress")
        })
        self.assertFalse(ok)
        self.assertEqual(why, "skip")

    def test_in_flight_does_not_speak_without_two_empty_turns(self):
        ok, why = should_review_advisor(turn=3, in_flight=True, **{
            k: v for k, v in _KW.items() if k != "in_flight"
        })
        self.assertFalse(ok)
        self.assertEqual(why, "skip")

    def test_in_flight_on_off_interval_is_silent_skip(self):
        ok, why = should_review_advisor(turn=1, in_flight=True, **{
            k: v for k, v in _KW.items() if k != "in_flight"
        })
        self.assertFalse(ok)
        self.assertEqual(why, "skip")

    def test_interval_alone_does_not_speak(self):
        ok, why = should_review_advisor(turn=3, **_KW)
        self.assertFalse(ok)
        self.assertEqual(why, "skip")
        ok, why = should_review_advisor(
            turn=6, last_steer_turn=3, pivots=1, stall_class="none",
            no_progress=0, interval=3, hold_turns=3, hard_turns=6, in_flight=False,
        )
        self.assertFalse(ok)
        self.assertEqual(why, "skip")

    def test_two_empty_turns_speaks_every_time(self):
        ok, why = should_review_advisor(
            turn=2, stall_class="none", no_progress=1, last_steer_turn=None,
            interval=3, hold_turns=3, hard_turns=6, in_flight=False, pivots=0,
        )
        self.assertFalse(ok)
        self.assertEqual(why, "skip")
        ok, why = should_review_advisor(
            turn=2, stall_class="none", no_progress=2, last_steer_turn=None,
            interval=3, hold_turns=3, hard_turns=6, in_flight=False, pivots=0,
        )
        self.assertTrue(ok)
        self.assertEqual(why, "stall_pivot")
        ok, why = should_review_advisor(
            turn=8, last_steer_turn=3, pivots=1, stall_class="none",
            no_progress=2, interval=3, hold_turns=3, hard_turns=6, in_flight=False,
        )
        self.assertTrue(ok)
        self.assertEqual(why, "stall_pivot")

    def test_two_empty_turns_overrides_hold_and_in_flight(self):
        ok, why = should_review_advisor(
            turn=4, last_steer_turn=3, stall_class="method", no_progress=2,
            interval=3, hold_turns=3, hard_turns=6, in_flight=True, pivots=1,
        )
        self.assertTrue(ok)
        self.assertEqual(why, "stall_pivot")

    def test_hold_without_two_empty_turns_does_not_speak(self):
        ok, why = should_review_advisor(
            turn=4, last_steer_turn=3, stall_class="method", no_progress=1,
            interval=3, hold_turns=3, hard_turns=6, in_flight=False,
        )
        self.assertFalse(ok)
        self.assertEqual(why, "skip")

    def test_hold_note_demands_noop(self):
        self.assertIn("必须 noop", hold_note_text(in_flight=True, hold_course=False))
        self.assertIn("必须 noop", hold_note_text(in_flight=False, hold_course=True))
        self.assertIn("红队/SRC/CTF", hold_note_text(in_flight=True, hold_course=False))
        self.assertEqual(hold_note_text(in_flight=False, hold_course=False), "（无）")

    def test_gate_is_track_agnostic(self):
        import inspect
        for fn in (
            assigned_still_open, unfinished_verification, should_review_advisor,
            hold_note_text, should_yield_turn_to_advisor,
        ):
            names = set(inspect.signature(fn).parameters)
            self.assertFalse(
                names & {"objective", "src", "flag", "redteam", "is_benchmark"},
                fn.__name__,
            )

    def test_unfinished_blocks_new_steer_before_due(self):
        """运行时审查也用这道门：任务未关时即使没到复盘点，也不能改方向。"""
        why = unfinished_verification(
            turn=1, stall_class="none", no_progress=1, last_steer_turn=None,
            hold_turns=3, in_flight=True, hard_turns=6,
        )
        self.assertEqual(why, "in_flight")
        why = unfinished_verification(
            turn=4, stall_class="method", no_progress=4, last_steer_turn=3,
            hold_turns=3, in_flight=False, hard_turns=6,
        )
        self.assertEqual(why, "hold_course")
        self.assertIsNone(unfinished_verification(
            turn=6, stall_class="method", no_progress=6, last_steer_turn=3,
            hold_turns=3, in_flight=True, hard_turns=6,
        ))


class YieldTurnToAdvisorTests(unittest.TestCase):
    def test_never_interrupts_mid_turn(self):
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"web_inject", "fingerprint", "secret_mount"},
            has_verified_asset=True,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"content_enum"},
            has_verified_asset=False,
        ))
        self.assertFalse(should_yield_turn_to_advisor(assigned_tactics=None))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"fingerprint", "protocol_model"},
            has_advisor_plan=False,
        ))

    def test_closeout_and_foothold_do_not_yield(self):
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"finding_sqli_chain"},
            has_verified_asset=True,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"ssrf_as_gateway"},
            has_verified_asset=True,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"content_enum"},
            has_foothold=True,
        ))

    def test_verified_oracle_leftover_does_not_yield(self):
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"channel_oracle", "input_abuse"},
            has_verified_asset=True,
            verified_categories={"sqli"},
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"channel_oracle", "access_control"},
            has_verified_asset=True,
            verified_categories={"sqli"},
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"channel_oracle"},
            has_verified_asset=False,
            has_advisor_plan=True,
        ))

    def test_unverified_inject_does_not_yield(self):
        mixed = {"web_inject", "fingerprint"}
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics=mixed, has_verified_asset=False,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics=mixed, has_verified_asset=False, has_advisor_plan=True,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"input_abuse", "channel_oracle"},
            has_verified_asset=False, has_advisor_plan=True,
        ))
        self.assertFalse(should_yield_turn_to_advisor(
            assigned_tactics={"fingerprint", "content_enum"},
            has_verified_asset=False, has_advisor_plan=True,
        ))


if __name__ == "__main__":
    unittest.main()
