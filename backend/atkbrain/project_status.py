"""项目收口状态。

CTF（含评测子题）：单题最多 60 分钟 / 40 轮 / 图空转 20 分钟触顶记失败，不进「未完成」。
评测覆盖期另有 60 分钟 0 分让槽（不因排队压缩），第二遍不再提前让槽。
红队：4 小时墙钟硬停；不走轮次 / 图空转。人工暂停、入口不可达、运行时审查叫停仍是 idle。
"""
from __future__ import annotations

HUNT_FAILED_REASONS = frozenset({
    "graph_idle", "runtime_cap", "turn_cap",
})


def uses_ctf_hunt_clocks(objective: str | None = None) -> bool:
    """轮次 / 图空转 / 运行时审查只给 CTF（含评测子题）。墙钟红队与 CTF 各自有上限。"""
    raw = str(objective or "").strip().lower()
    if raw in ("src", "lab_src"):
        return False
    from .objective import FLAG, normalize_objective
    return normalize_objective(objective) == FLAG


def hunt_runtime_hard_stop_sec(objective: str | None = None) -> int:
    """本猎墙钟硬上限（秒）。CTF 60 分钟；红队 4 小时；0 表示不限。"""
    from .config import settings
    if uses_ctf_hunt_clocks(objective):
        try:
            return max(0, int(getattr(settings, "runtime_hard_stop_sec", 60 * 60) or 0))
        except (TypeError, ValueError):
            return 60 * 60
    try:
        return max(0, int(getattr(settings, "redteam_runtime_hard_stop_sec", 4 * 60 * 60) or 0))
    except (TypeError, ValueError):
        return 4 * 60 * 60


def hunt_max_turns(objective: str | None = None, *, is_benchmark: bool = False) -> int:
    """本猎最大编排轮次。CTF（含评测）40；SRC 30；红队不限。"""
    from .config import settings
    del is_benchmark
    raw = str(objective or "").strip().lower()
    if raw in ("src", "lab_src"):
        try:
            return max(0, int(getattr(settings, "loop_max_turns_src", 30) or 30))
        except (TypeError, ValueError):
            return 30
    if not uses_ctf_hunt_clocks(objective):
        return 0
    try:
        n = int(getattr(settings, "loop_max_turns", 40) or 40)
    except (TypeError, ValueError):
        n = 40
    return max(0, n)


def final_project_status(
    *, goal: bool, exhausted: bool = False, pause_reason: str | None = None,
) -> str:
    if goal:
        return "completed"
    if exhausted or (pause_reason in HUNT_FAILED_REASONS):
        return "error"
    return "idle"
