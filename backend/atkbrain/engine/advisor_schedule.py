"""御主下令调度：从者整轮打完再问御主。

这是自循环层的基本门闩，**不看赛道**：红队 / SRC / CTF（含评测）走同一套。
编排器先让从者（含工人）把本轮打完，再按卡住 / 周期决定要不要问御主；
超时后下一轮从者按自己的思路打。本模块决定「这一轮要不要问御主 / 空转是否该暂停」。
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
    """这一轮该不该套短墙钟中途打断从者。赛道无关。

    不中途打断：360s 只卡「等御主令」，不卡从者本轮工具墙钟。
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
    """当前验证是否还没结束。未结束则不应换方向、也不应再问御主。

    返回 hold_course / in_flight；None 表示可以换方向。
    硬空转（method/chain 且 no_progress≥hard_turns）视为验证已结束。
    不接受 objective：红队/SRC/CTF 不得各写一套。
    """
    sc = (stall_class or "none").strip().lower()
    need_pivot = sc in ("method", "chain")
    hold_turns = max(0, int(hold_turns or 0))
    hard_turns = max(1, int(hard_turns or 10))
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
    """从者本轮打完后，卡住或到了周期才问御主。赛道无关。

    尚无方案：问一次。刚下过令 / Intent 仍在飞：hold，不问。
    硬空转（method/chain 且 no_progress≥hard_turns）强制开口。
    first_turns：尚无 last_steer_turn 时，前 N 轮允许开口（通常首轮打完即问）。
    """
    turn = max(0, int(turn or 0))
    interval = max(1, int(interval or 3))
    first = max(0, int(first_turns or 0))
    hold_turns = max(0, int(hold_turns or 0))
    hard_turns = max(1, int(hard_turns or 10))
    no_progress = max(0, int(no_progress or 0))
    pivots_n = max(0, int(pivots or 0))
    sc = (stall_class or "none").strip().lower()
    need_pivot = sc in ("method", "chain")
    hard_stuck = need_pivot and no_progress >= hard_turns

    if last_steer_turn is None and (pivots_n <= 0 or (first > 0 and turn <= first)):
        return True, "turn"

    if hard_stuck:
        return True, "turn"

    blocked = unfinished_verification(
        turn=turn,
        stall_class=stall_class,
        no_progress=no_progress,
        last_steer_turn=last_steer_turn,
        hold_turns=hold_turns,
        in_flight=in_flight,
        hard_turns=hard_turns,
    )
    if blocked:
        return False, blocked

    if last_steer_turn is None:
        return True, "turn"

    try:
        elapsed = turn - int(last_steer_turn)
    except (TypeError, ValueError):
        elapsed = interval

    if elapsed < interval and not need_pivot:
        return False, "let_commander"

    if need_pivot or no_progress >= 1:
        return True, "turn"

    return False, "progress"


def stall_pause_due(no_progress: int, limit: int) -> bool:
    """连续无高质量进展达到上限 → 暂停本猎。有开放 Intent 也算。"""
    try:
        n = int(no_progress or 0)
    except (TypeError, ValueError):
        n = 0
    try:
        cap = int(limit or 0)
    except (TypeError, ValueError):
        cap = 0
    return cap > 0 and n >= cap


def hold_note_text(*, in_flight: bool, hold_course: bool) -> str:
    """喂给御主战况板：未完成验证时倾向 hold，不要换新面。赛道无关。"""
    if hold_course:
        return (
            "刚下过御主指令，从者还在执行。必须 noop。"
            "禁止另起同义散文或改打目录枚举。路线包内的并行子智能体可以继续。"
            "红队/SRC/CTF 同样生效。"
        )
    if in_flight:
        return (
            "本轮认领的 Intent 仍开放（当前假设尚未证实或否证）。必须 noop。"
            "禁止改打目录枚举；让从者把路线包里的并行验证做完并 resolve_intent。"
            "红队/SRC/CTF 同样生效。"
        )
    return "（无）"


def _assert_track_agnostic() -> None:
    """结构守卫：调度函数不得出现 objective/src/flag 参数。"""
    for fn in (
        assigned_still_open, unfinished_verification, should_review_advisor,
        hold_note_text, should_yield_turn_to_advisor, stall_pause_due,
    ):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"objective", "src", "flag", "redteam", "is_benchmark"}


_assert_track_agnostic()
