"""评测调度：按题号顺序覆盖全部题目；不按易/难跳过；不连环切容器。"""
from __future__ import annotations

import unittest

from atkbrain.benchmark import (
    coverage_dwell_sec,
    hunt_idle_sec,
    count_remaining_fresh,
    focus_code_key,
    include_in_autopilot,
    leftover_fill_ids,
    leftover_round_dwell_sec,
    open_autopilot_slots,
    parse_focus_codes,
    pick_dwell_yield,
    pick_yield_for_easies,
    rotate_dwell_sec,
    schedule_fill_ids,
    unique_code_seq,
    is_real_run_duration,
    count_real_attempts_from_runs,
)
from atkbrain.config import settings


class UniqueCodeOrderTests(unittest.TestCase):
    def test_numeric_and_prefix_order(self):
        codes = ["f2-08", "a-10", "a-02", "e3-01", "e1-02", "f1-01", "d-01"]
        ordered = sorted(codes, key=unique_code_seq)
        self.assertEqual(ordered, ["a-02", "a-10", "d-01", "e1-02", "e3-01", "f1-01", "f2-08"])

    def test_other_contest_names_also_natural_sort(self):
        codes = ["web-10", "web-2", "pwn-1", "misc", "rev2", "crypto_03"]
        ordered = sorted(codes, key=unique_code_seq)
        self.assertEqual(ordered, ["crypto_03", "misc", "pwn-1", "rev2", "web-2", "web-10"])


class WaveScheduleTests(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual(int(settings.benchmark_max_concurrency), 10)
        self.assertFalse(bool(settings.benchmark_autopilot_resume))
        self.assertTrue(bool(settings.benchmark_autopilot_second_pass))
        self.assertEqual(int(settings.benchmark_max_attempts), 8)
        self.assertEqual(int(settings.benchmark_first_pass_dwell_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_dwell_floor_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_grow_grace_sec), 8 * 60)
        self.assertEqual(int(settings.benchmark_min_attempt_sec), 120)
        self.assertEqual(int(settings.benchmark_min_hunt_sec), 180)
        self.assertEqual(int(settings.benchmark_hard_no_flag_rotate_sec), 0)
        self.assertEqual(int(settings.benchmark_watchdog_idle_ticks), 3)
        self.assertEqual(str(settings.benchmark_focus_codes or ""), "")

    def test_unopened_never_skipped_for_hard_prefix(self):
        kw = dict(attempts=0, correct_flags=0, resume=False, second_pass=True, any_fresh=True)
        self.assertTrue(include_in_autopilot(**kw, hard=True, easy=False))
        self.assertTrue(include_in_autopilot(**kw, hard=False, easy=True))
        self.assertTrue(include_in_autopilot(**kw, hard=False, easy=False))

    def test_idle_partial_waits_until_coverage_done(self):
        self.assertFalse(include_in_autopilot(
            attempts=1, correct_flags=1, resume=False, second_pass=True, any_fresh=True,
        ))
        self.assertTrue(include_in_autopilot(
            attempts=1, correct_flags=1, resume=False, second_pass=True, any_fresh=False,
        ))

    def test_skipped_zero_flag_waits_for_second_pass(self):
        kw = dict(attempts=1, correct_flags=0, resume=False, easy=False, hard=True)
        self.assertFalse(include_in_autopilot(**kw, second_pass=True, any_fresh=True))
        self.assertTrue(include_in_autopilot(**kw, second_pass=True, any_fresh=False))
        self.assertFalse(include_in_autopilot(**kw, second_pass=False, any_fresh=False))

    def test_resume_does_not_cut_in_line_during_coverage(self):
        self.assertFalse(include_in_autopilot(
            attempts=1, correct_flags=0, resume=True, second_pass=True, any_fresh=True,
        ))


class FillOrderTests(unittest.TestCase):
    def test_coverage_fills_unopened_in_code_order(self):
        pool = [
            {"id": "f1", "unique_code": "f1-01"},
            {"id": "d2", "unique_code": "d-02"},
            {"id": "d1", "unique_code": "d-01"},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"f1": 0, "d2": 0, "d1": 0},
            progress={}, any_fresh=True,
        )
        self.assertEqual(ids, ["d1", "d2", "f1"])

    def test_coverage_does_not_pull_attempted_zero_or_partial(self):
        pool = [
            {"id": "cont", "unique_code": "a-01"},
            {"id": "zero", "unique_code": "a-02"},
            {"id": "fresh", "unique_code": "f1-01"},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"cont": 1, "zero": 1, "fresh": 0},
            progress={"cont": 1, "zero": 0, "fresh": 0},
            any_fresh=True,
        )
        self.assertEqual(ids, ["fresh"])

    def test_after_coverage_continues_before_zero_flag(self):
        pool = [
            {"id": "z", "unique_code": "a-01"},
            {"id": "c", "unique_code": "b-01"},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"z": 1, "c": 1},
            progress={"z": 0, "c": 2},
            any_fresh=False,
        )
        self.assertEqual(ids, ["c", "z"])

    def test_leftover_skips_started_and_running(self):
        ids = leftover_fill_ids(
            [{"id": "a", "unique_code": "a-01"}, {"id": "b", "unique_code": "b-01"},
             {"id": "c", "unique_code": "c-01"}],
            started={"a"},
            running={"b"},
            progress={},
            attempts={"a": 0, "b": 0, "c": 0},
            any_fresh=True,
        )
        self.assertEqual(ids, ["c"])

    def test_released_ids_free_slots_same_tick(self):
        self.assertEqual(open_autopilot_slots(3, ["a", "b", "c"]), 0)
        self.assertEqual(open_autopilot_slots(3, {"a", "b"}), 1)

    def test_short_session_not_a_real_attempt(self):
        self.assertFalse(is_real_run_duration(1000, 1100, now_ts=2000, min_sec=120))
        self.assertTrue(is_real_run_duration(1000, 1300, now_ts=2000, min_sec=120))
        self.assertTrue(is_real_run_duration(1000, None, now_ts=1300, min_sec=120))
        self.assertEqual(
            count_real_attempts_from_runs(
                [
                    {"started_at": 1, "ended_at": 20},
                    {"started_at": 50, "ended_at": 400},
                ],
                min_sec=120, now_ts=1000,
            ),
            1,
        )

    def test_coverage_treats_short_session_as_unopened(self):
        pool = [
            {"id": "ghost", "unique_code": "z-40"},
            {"id": "fresh", "unique_code": "a-01"},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"ghost": 1, "fresh": 0},
            progress={}, any_fresh=True,
            real_attempts={"ghost": 0, "fresh": 0},
        )
        self.assertEqual(ids, ["fresh"])

    def test_after_coverage_never_ran_zero_before_attempted_zero(self):
        pool = [
            {"id": "attempted", "unique_code": "a-01"},
            {"id": "ghost", "unique_code": "z-99", "total_score": 1000},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"attempted": 1, "ghost": 1},
            progress={"attempted": 0, "ghost": 0},
            any_fresh=False,
            real_attempts={"attempted": 1, "ghost": 0},
        )
        self.assertEqual(ids[0], "ghost")

    def test_coverage_never_launched_beats_short_session_ghost(self):
        pool = [
            {"id": "ghost", "unique_code": "a-01"},
            {"id": "never", "unique_code": "z-40"},
        ]
        ids = schedule_fill_ids(
            pool, started=set(), running=set(),
            attempts={"ghost": 1, "never": 0},
            progress={}, any_fresh=True,
            real_attempts={"ghost": 0, "never": 0},
        )
        self.assertEqual(ids, ["never"])

    def test_catalog_missing_codes_keeps_order(self):
        from atkbrain.benchmark import catalog_missing_codes
        missing = catalog_missing_codes(
            ["a-01"],
            [{"unique_code": "a-01"}, {"unique_code": "b-02"}, "c-03"],
        )
        self.assertEqual(missing, ["b-02", "c-03"])


class FocusCodeParseTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(parse_focus_codes(""), [])
        self.assertEqual(parse_focus_codes(None), [])
        self.assertEqual(parse_focus_codes([]), [])

    def test_csv_and_list_dedupe(self):
        self.assertEqual(
            parse_focus_codes("web-2, web-10;web-2\nmisc"),
            ["web-2", "web-10", "misc"],
        )
        self.assertEqual(parse_focus_codes(["web-2", "web-10", "web-2"]), ["web-2", "web-10"])

    def test_casefold_dedupe(self):
        self.assertEqual(parse_focus_codes("Web-2, web-2, WEB-10"), ["Web-2", "WEB-10"])
        self.assertEqual(focus_code_key("XBEN-005-24"), "xben-005-24")


class RemainingFreshTests(unittest.TestCase):
    def test_counts_real_zero_not_config_attempts(self):
        items = [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}]
        n = count_remaining_fresh(
            items,
            completed={"a"},
            busy={"b"},
            real_attempts={"a": 0, "b": 0, "c": 1, "d": 0},
        )
        self.assertEqual(n, 1)

    def test_short_ghost_is_fresh(self):
        items = [{"id": "ghost"}]
        n = count_remaining_fresh(
            items, completed=set(), busy=set(), real_attempts={"ghost": 0},
        )
        self.assertEqual(n, 1)


class DwellYieldTests(unittest.TestCase):
    def test_has_flag_never_yields(self):
        running = [{"id": "a"}, {"id": "b"}]
        self.assertEqual(
            pick_dwell_yield(
                running, progress={"a": 1, "b": 0},
                elapsed_sec={"a": 7200, "b": 7200},
                waiting=4, dwell_sec=1500,
            ),
            ["b"],
        )

    def test_partial_flag_yields_when_coverage_asks(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 2},
                elapsed_sec={"a": 20 * 60}, waiting=10, dwell_sec=20 * 60,
                yield_partial=True, hard_cap_sec=20 * 60,
            ),
            ["a"],
        )

    def test_hard_cap_yields_even_if_graph_growing(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 20 * 60}, waiting=10, dwell_sec=16 * 60,
                idle_sec={"a": 60}, grow_grace_sec=8 * 60,
                hard_cap_sec=20 * 60,
            ),
            ["a"],
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 1},
                elapsed_sec={"a": 20 * 60}, waiting=10, dwell_sec=16 * 60,
                idle_sec={"a": 60}, grow_grace_sec=8 * 60,
                yield_partial=True, hard_cap_sec=20 * 60,
            ),
            ["a"],
        )

    def test_under_dwell_does_not_yield(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 600}, waiting=10, dwell_sec=1500,
            ),
            [],
        )

    def test_yields_only_one_oldest(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}, {"id": "b"}], progress={"a": 0, "b": 0},
                elapsed_sec={"a": 2000, "b": 4000}, waiting=5, dwell_sec=1500,
            ),
            ["b"],
        )

    def test_coverage_dwell_keeps_default_when_queue_fits(self):
        self.assertEqual(
            coverage_dwell_sec(
                waiting_fresh=3, concurrency=3, default_sec=1500, floor_sec=480,
            ),
            1500,
        )
        self.assertEqual(
            coverage_dwell_sec(
                waiting_fresh=0, concurrency=3, default_sec=1500, floor_sec=480,
            ),
            1500,
        )

    def test_coverage_dwell_does_not_compress_when_many_unopened(self):
        long_queue = coverage_dwell_sec(
            waiting_fresh=20, concurrency=3, default_sec=1500, floor_sec=480,
        )
        self.assertEqual(long_queue, 1500)
        mid = coverage_dwell_sec(
            waiting_fresh=5, concurrency=3, default_sec=1500, floor_sec=480,
        )
        self.assertEqual(mid, 1500)

    def test_coverage_dwell_then_yields_after_default(self):
        dwell = coverage_dwell_sec(
            waiting_fresh=20, concurrency=3, default_sec=1500, floor_sec=480,
        )
        self.assertEqual(dwell, 1500)
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 1500}, waiting=20, dwell_sec=dwell,
            ),
            ["a"],
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 500}, waiting=20, dwell_sec=dwell,
            ),
            [],
        )

    def test_no_waiting_means_no_yield(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 4000}, waiting=0, dwell_sec=1500,
            ),
            [],
        )

    def test_growing_graph_does_not_yield(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 20 * 60}, waiting=5, dwell_sec=15 * 60,
                idle_sec={"a": 2 * 60}, grow_grace_sec=8 * 60,
            ),
            [],
        )

    def test_stalled_graph_yields_after_dwell(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}, {"id": "b"}], progress={"a": 0, "b": 0},
                elapsed_sec={"a": 20 * 60, "b": 18 * 60}, waiting=5, dwell_sec=15 * 60,
                idle_sec={"a": 10 * 60, "b": 1 * 60}, grow_grace_sec=8 * 60,
            ),
            ["a"],
        )

    def test_missing_idle_allows_yield(self):
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 15 * 60}, waiting=5, dwell_sec=15 * 60,
                grow_grace_sec=8 * 60,
            ),
            ["a"],
        )
        self.assertGreaterEqual(hunt_idle_sec({}), 1e9)
        self.assertEqual(hunt_idle_sec({"hunt": {"idle_sec": 120}}), 120.0)

    def test_two_phase_coverage_dwell(self):
        """覆盖期固定 60 分钟；排队再长也不压；未到硬顶且图还在长不让。"""
        self.assertEqual(int(settings.benchmark_first_pass_dwell_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_dwell_floor_sec), 60 * 60)
        self.assertEqual(int(settings.benchmark_coverage_grow_grace_sec), 8 * 60)
        self.assertEqual(int(settings.benchmark_no_flag_rotate_sec), 0)
        self.assertEqual(
            coverage_dwell_sec(
                waiting_fresh=3, concurrency=3,
                default_sec=60 * 60, floor_sec=60 * 60,
            ),
            60 * 60,
        )
        self.assertEqual(
            coverage_dwell_sec(
                waiting_fresh=20, concurrency=3,
                default_sec=60 * 60, floor_sec=16 * 60,
            ),
            60 * 60,
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 60 * 60}, waiting=5, dwell_sec=60 * 60,
            ),
            ["a"],
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 1},
                elapsed_sec={"a": 60 * 60}, waiting=5, dwell_sec=60 * 60,
            ),
            [],
        )
        self.assertEqual(
            leftover_round_dwell_sec(leftover_waiting=10, default_sec=60 * 60),
            60 * 60,
        )
        self.assertEqual(
            leftover_round_dwell_sec(leftover_waiting=0, default_sec=60 * 60),
            0,
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "a"}], progress={"a": 0},
                elapsed_sec={"a": 4000}, waiting=5, dwell_sec=0,
            ),
            [],
        )

    def test_hard_second_pass_uses_longer_dwell(self):
        self.assertEqual(rotate_dwell_sec("hard"), 0)
        self.assertEqual(rotate_dwell_sec("medium"), 0)
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "hard"}, {"id": "med"}],
                progress={"hard": 0, "med": 0},
                elapsed_sec={"hard": 4000, "med": 4000},
                waiting=2, dwell_sec=3600,
                dwell_for={"hard": 5400, "med": 3600},
            ),
            ["med"],
        )
        self.assertEqual(
            pick_dwell_yield(
                [{"id": "hard"}],
                progress={"hard": 0},
                elapsed_sec={"hard": 5500},
                waiting=1, dwell_sec=3600,
                dwell_for={"hard": 5400},
            ),
            ["hard"],
        )

    def test_easy_insert_no_longer_preempts(self):
        self.assertEqual(
            pick_yield_for_easies(
                [{"id": "med"}], {"med": 0}, {"easy"}, 2,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
