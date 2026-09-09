"""项目收口状态。

CTF（含评测子题）：不限轮次、不做御主运行时审查。
墙钟硬停按遍次：第 1 遍 40 分钟，第 2 遍 120 分钟，第 3 遍 180 分钟，之后每次 +60。
图空转：连续 6 个御主方案仍无新节点、无交旗、也无本地长计算 → 失败。
评测覆盖期按第 1 遍墙钟让槽，全部开过一轮后再回头啃未出/未齐 flag。
红队：4 小时墙钟硬停；不走轮次 / 图空转。人工暂停、入口不可达仍是 idle。
"""
from __future__ import annotations

HUNT_FAILED_REASONS = frozenset({
    "graph_idle", "runtime_cap", "turn_cap",
})


def uses_ctf_hunt_clocks(objective: str | None = None) -> bool:
    """图空转只给 CTF（含评测子题）。墙钟红队与 CTF 各自有上限。CTF 不限轮次、不审查。"""
    from .objective import FLAG, normalize_objective
    return normalize_objective(objective) == FLAG


def ctf_pass_hard_stop_sec(pass_n: int | None = None) -> int:
    """CTF 第 N 遍墙钟硬上限（秒）。1=40min，2=120，3=180，之后每次 +60。"""
    from .config import settings
    try:
        n = max(1, int(pass_n or 1))
    except (TypeError, ValueError):
        n = 1
    try:
        p1 = max(0, int(getattr(settings, "runtime_hard_stop_sec", 40 * 60) or 0))
    except (TypeError, ValueError):
        p1 = 40 * 60
    try:
        p2 = max(0, int(getattr(settings, "runtime_hard_stop_pass2_sec", 120 * 60) or 0))
    except (TypeError, ValueError):
        p2 = 120 * 60
    try:
        p3 = max(0, int(getattr(settings, "runtime_hard_stop_pass3_sec", 180 * 60) or 0))
    except (TypeError, ValueError):
        p3 = 180 * 60
    try:
        step = max(0, int(getattr(settings, "runtime_hard_stop_pass_step_sec", 60 * 60) or 0))
    except (TypeError, ValueError):
        step = 60 * 60
    if n <= 1:
        return p1
    if n == 2:
        return p2
    if n == 3:
        return p3
    return p3 + (n - 3) * step


def ctf_pass_index(*, ended_real_attempts: int = 0) -> int:
    """已结束的真正 attempt 数 + 1 = 本猎遍次。"""
    try:
        n = max(0, int(ended_real_attempts or 0))
    except (TypeError, ValueError):
        n = 0
    return n + 1


def hunt_runtime_hard_stop_sec(objective: str | None = None, *, pass_n: int | None = None) -> int:
    """本猎墙钟硬上限（秒）。CTF 按遍次；SRC 180 分钟；红队 4 小时；0 表示不限。"""
    from .config import settings
    from .objective import objective_is_src
    if uses_ctf_hunt_clocks(objective):
        return ctf_pass_hard_stop_sec(pass_n)
    if objective_is_src(objective):
        try:
            return max(0, int(getattr(settings, "src_runtime_hard_stop_sec", 3 * 60 * 60) or 0))
        except (TypeError, ValueError):
            return 3 * 60 * 60
    try:
        return max(0, int(getattr(settings, "redteam_runtime_hard_stop_sec", 4 * 60 * 60) or 0))
    except (TypeError, ValueError):
        return 4 * 60 * 60


def hunt_max_turns(objective: str | None = None, *, is_benchmark: bool = False) -> int:
    """本猎最大编排轮次。0=不限。CTF（含评测）不限；SRC 30；红队不限。"""
    from .config import settings
    from .objective import objective_is_src
    del is_benchmark
    if objective_is_src(objective):
        try:
            return max(0, int(getattr(settings, "loop_max_turns_src", 30) or 30))
        except (TypeError, ValueError):
            return 30
    if not uses_ctf_hunt_clocks(objective):
        return 0
    try:
        n = int(getattr(settings, "loop_max_turns", 0) or 0)
    except (TypeError, ValueError):
        n = 0
    return max(0, n)


def final_project_status(
    *, goal: bool, exhausted: bool = False, pause_reason: str | None = None,
) -> str:
    if goal:
        return "completed"
    if exhausted or (pause_reason in HUNT_FAILED_REASONS):
        return "error"
    return "idle"
