"""顾问复盘调度：当前验证未结束时不改方向。

这是自循环层的基本门闩，**不看赛道**：红队 / SRC / CTF（含评测）走同一套。
顾问只在回合自然结束的轮次边界注入新方向，不中途打断本轮。
本模块决定「这一轮边界要不要复盘 / 要不要注入新方向」。
"""
from __future__ import annotations

import inspect


def assigned_still_open(
    assigned: list[dict] | None,
    open_intents: list[dict] | None,
) -> bool:
    """本轮认领的 Intent 结束后仍开放 → 当前验证还没结束。赛道无关。"""
    ids = {str(i.get("id") or "") for i in (assigned or []) if i.get("id")}
    if not ids:
        return False
    open_ids = {str(i.get("id") or "") for i in (open_intents or []) if i.get("id")}
    return bool(ids & open_ids)


def should_yield_turn_to_advisor(
    *,
    assigned_tactics=None,
    has_foothold: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_advisor_plan: bool = False,
) -> bool:
    """这一轮该不该套顾问让出墙钟。赛道无关。

    不中途打断：指挥官把本轮做完，顾问只在回合返回后的边界开口。
    """
    _ = (assigned_tactics, has_foothold, has_verified_asset, verified_categories, has_advisor_plan)
    return False


def unfinished_verification(
    *,
    turn: int,
    stall_class: str,
    no_progress: int,
    last_steer_turn: int | None,
    hold_turns: int,
    in_flight: bool,
    hard_turns: int,
) -> str | None:
    """当前验证是否还没结束（应推迟任何新方向，含运行时审查的 directives）。

    返回 hold_course / in_flight；None 表示可以换方向。
    硬空转（method/chain 且 no_progress≥hard_turns）视为验证已结束。
    不接受 objective：红队/SRC/CTF 不得各写一套。
    """
    sc = (stall_class or "none").strip().lower()
    need_pivot = sc in ("method", "chain")
    hold_turns = max(0, int(hold_turns or 0))
    hard_turns = max(1, int(hard_turns or 6))
    turn = max(0, int(turn or 0))
    no_progress = max(0, int(no_progress or 0))
    hard_stuck = need_pivot and no_progress >= hard_turns
    if hard_stuck:
        return None

    if last_steer_turn is not None and hold_turns > 0:
        try:
            elapsed = turn - int(last_steer_turn)
        except (TypeError, ValueError):
            elapsed = hold_turns
        if 0 <= elapsed < hold_turns:
            return "hold_course"

    if in_flight and not need_pivot:
        return "in_flight"
    return None


def should_review_advisor(
    *,
    turn: int,
    interval: int,
    stall_class: str,
    no_progress: int,
    last_steer_turn: int | None,
    hold_turns: int,
    in_flight: bool,
    hard_turns: int,
    pivots: int = 0,
    first_turns: int = 2,
) -> tuple[bool, str]:
    """轮次边界是否让顾问开口。赛道无关（无 objective 参数）。

    每一次开口都是同一道门：连续 first_turns 轮无有效进展。
    不是「第一次才看空转、之后按周期问」。有进展（no_progress 被清零）就不开口。
    interval / hold / 是否开过口不作为开口条件；参数仍留给运行时审查和调用方。
    """
    _ = (turn, interval, stall_class, last_steer_turn, hold_turns, in_flight, hard_turns, pivots)
    empty = max(1, int(first_turns or 2))
    no_progress = max(0, int(no_progress or 0))
    if no_progress < empty:
        return False, "skip"
    return True, "stall_pivot"


def hold_note_text(*, in_flight: bool, hold_course: bool) -> str:
    """喂给顾问战况板：未完成验证时必须 noop，不要换新面。赛道无关。"""
    if hold_course:
        return (
            "刚下过顾问指令，主测还在执行。必须 noop。"
            "禁止另起同义散文或改打目录枚举。路线包内的并行子智能体可以继续。"
            "红队/SRC/CTF 同样生效。"
        )
    if in_flight:
        return (
            "本轮认领的 Intent 仍开放（当前假设尚未证实或否证）。必须 noop。"
            "禁止改打目录枚举；让主测把路线包里的并行验证做完并 resolve_intent。"
            "红队/SRC/CTF 同样生效。"
        )
    return "（无）"


def _assert_track_agnostic() -> None:
    """结构守卫：调度函数不得出现 objective/src/flag 参数。"""
    for fn in (
        assigned_still_open, unfinished_verification, should_review_advisor,
        hold_note_text, should_yield_turn_to_advisor,
    ):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"objective", "src", "flag", "redteam", "is_benchmark"}


_assert_track_agnostic()
