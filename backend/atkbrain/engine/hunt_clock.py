"""猎程时钟：轮次与墙钟跨 run 续跑，避免后端重启把第 N 轮打回第 1 轮。

新开猎（硬重启、达目标、或配置了上限并触顶）才从零计。
人工暂停 / 进程被杀 / systemd 重启后续跑，接着上次的 turn 和 elapsed。
"""
from __future__ import annotations

from typing import Any

# 这些收口表示「这一猎已经按策略结束」，下次启动是新猎，轮次与时长从零计。
# entry_dead 除外：已有命令执行立足点时入口 HTTP 挂了不该开新猎。
HUNT_RESET_REASONS = frozenset({
    "runtime_cap",
    "turn_cap",
    "graph_idle",
    "goal_reached",
    "entry_dead",
    "env_closed",
    "env_unreachable",
    "runtime_review_stop",
})


def empty_hunt() -> dict[str, Any]:
    return {
        "turn": 0,
        "elapsed_sec": 0.0,
        "reviewed_elapsed_sec": None,
        "idle_sec": 0.0,
        "idle_plans": 0,
    }


def hunt_should_reset(
    *,
    hard_restart: bool,
    completion_reason: str | None,
    has_live_foothold: bool = False,
) -> bool:
    if hard_restart:
        return True
    reason = str(completion_reason or "")
    if reason == "entry_dead" and has_live_foothold:
        return False
    return reason in HUNT_RESET_REASONS


def parse_hunt(cfg: dict | None) -> dict[str, Any]:
    raw = (cfg or {}).get("hunt") if isinstance(cfg, dict) else None
    base = empty_hunt()
    if not isinstance(raw, dict):
        return base
    try:
        base["turn"] = max(0, int(raw.get("turn") or 0))
    except (TypeError, ValueError):
        pass
    try:
        base["elapsed_sec"] = max(0.0, float(raw.get("elapsed_sec") or 0))
    except (TypeError, ValueError):
        pass
    rev = raw.get("reviewed_elapsed_sec")
    if rev is not None:
        try:
            base["reviewed_elapsed_sec"] = max(0.0, float(rev))
        except (TypeError, ValueError):
            base["reviewed_elapsed_sec"] = None
    try:
        base["idle_sec"] = max(0.0, float(raw.get("idle_sec") or 0))
    except (TypeError, ValueError):
        pass
    try:
        base["idle_plans"] = max(0, int(raw.get("idle_plans") or 0))
    except (TypeError, ValueError):
        base["idle_plans"] = 0
    return base


def reconstruct_hunt(
    *,
    last_run: dict | None,
    last_turn: int = 0,
    now_ts: float,
) -> dict[str, Any]:
    """config.hunt 尚未写入时，用最近一次被打断的 run 兜底（只接这一段，不把更早已结束的猎加进来）。"""
    h = empty_hunt()
    run_turns = 0
    try:
        run_turns = int((last_run or {}).get("turns") or 0)
    except (TypeError, ValueError):
        run_turns = 0
    try:
        ev_turns = int(last_turn or 0)
    except (TypeError, ValueError):
        ev_turns = 0
    h["turn"] = max(0, run_turns, ev_turns)
    if not last_run:
        return h
    try:
        started = float(last_run.get("started_at") or 0)
    except (TypeError, ValueError):
        return h
    ended_raw = last_run.get("ended_at")
    try:
        ended = float(ended_raw) if ended_raw else float(now_ts)
    except (TypeError, ValueError):
        ended = float(now_ts)
    if started > 0 and ended >= started:
        h["elapsed_sec"] = ended - started
    return h


def fill_hunt_from_last_run(hunt: dict | None, *, reconstructed: dict | None) -> dict:
    """config.hunt 若把进行中轮次写成 0，用上一 run 的轮次/墙钟补上，不要因为 elapsed>0 就跳过。"""
    out = dict(hunt or empty_hunt())
    recon = dict(reconstructed or empty_hunt())
    try:
        cur_turn = int(out.get("turn") or 0)
    except (TypeError, ValueError):
        cur_turn = 0
    try:
        recon_turn = int(recon.get("turn") or 0)
    except (TypeError, ValueError):
        recon_turn = 0
    try:
        cur_el = float(out.get("elapsed_sec") or 0)
    except (TypeError, ValueError):
        cur_el = 0.0
    try:
        recon_el = float(recon.get("elapsed_sec") or 0)
    except (TypeError, ValueError):
        recon_el = 0.0
    if cur_turn <= 0 and recon_turn > 0:
        out["turn"] = recon_turn
    if cur_turn <= 0:
        out["elapsed_sec"] = max(0.0, cur_el, recon_el)
    return out


def resume_completed_turn(*, persisted_turn: int, supervised_turns: Any) -> int:
    """猎钟里的 turn 若还没有监督记录，视为进行中被打断。

    旧逻辑在回合一开始就把 in-progress 轮次落盘，重启后续跑再 +1，会把第 13 轮直接跳成 14。
    续跑时应重跑这一轮，而不是跳号。
    """
    t = max(0, int(persisted_turn or 0))
    have: set[int] = set()
    for x in supervised_turns or ():
        try:
            n = int(x or 0)
        except (TypeError, ValueError):
            continue
        if n > 0:
            have.add(n)
    if t <= 0:
        return max(have) if have else 0
    if t not in have:
        return t - 1
    return t


def snapshot_hunt(
    *,
    turn: int,
    elapsed_sec: float,
    reviewed_elapsed_sec: float | None,
    idle_sec: float,
    idle_plans: int = 0,
) -> dict[str, Any]:
    return {
        "turn": max(0, int(turn)),
        "elapsed_sec": max(0.0, float(elapsed_sec)),
        "reviewed_elapsed_sec": (
            None if reviewed_elapsed_sec is None else max(0.0, float(reviewed_elapsed_sec))
        ),
        "idle_sec": max(0.0, float(idle_sec)),
        "idle_plans": max(0, int(idle_plans or 0)),
    }


def should_reset_graph_idle(
    *, node_grew: bool, new_flag_event: bool, local_progress: bool = False,
) -> bool:
    """交旗、新节点、或长时间本地计算/新产物，都视为图上仍在推进。"""
    return bool(node_grew or new_flag_event or local_progress)


def hunt_elapsed_meets_min(elapsed_sec: float, min_sec: float) -> bool:
    """猎面墙钟是否已达到最短时长。min_sec<=0 视为不限制。"""
    try:
        need = float(min_sec or 0)
    except (TypeError, ValueError):
        need = 0.0
    if need <= 0:
        return True
    try:
        got = float(elapsed_sec or 0)
    except (TypeError, ValueError):
        got = 0.0
    return got >= need


def looks_like_api_key_missing(text: str, *, tool_uses: int = 0) -> bool:
    """是否像 DeepSeek/API 密钥缺失。禁止用泛「authentication fail」匹配御主规划。"""
    try:
        uses = int(tool_uses or 0)
    except (TypeError, ValueError):
        uses = 0
    if uses > 0:
        return False
    t = (text or "").strip().lower()
    if not t or len(t) >= 400:
        return False
    if "deepseek_api_key" in t:
        return True
    if "api key" in t or "apikey" in t:
        return any(
            x in t for x in ("missing", "not set", "not configured", "invalid", "unauthorized")
        )
    return False


def should_end_hunt_fault(
    *,
    elapsed_sec: float,
    min_hunt_sec: float,
    goal_reached: bool = False,
    env_closed: bool = False,
) -> bool:
    """鉴权误判 / 回合卡死 / 会话故障是否结束本 run。

    评测 0 分且未满最短猎面时继续重建，避免十几秒关容器。
    已夺旗或环境关闭仍立即收口。
    """
    if goal_reached or env_closed:
        return True
    return hunt_elapsed_meets_min(elapsed_sec, min_hunt_sec)


def should_end_empty_streak(
    *,
    empty_streak: int,
    elapsed_sec: float,
    min_hunt_sec: float,
    goal_reached: bool = False,
    env_closed: bool = False,
    streak_limit: int = 5,
) -> bool:
    """连续空回合/会话故障是否结束本 run。

    评测 0 分且未满最短猎面时继续重建会话，避免十几秒就关容器。
    已夺旗或环境关闭仍立即收口。
    """
    try:
        streak = int(empty_streak or 0)
    except (TypeError, ValueError):
        streak = 0
    try:
        limit = int(streak_limit or 5)
    except (TypeError, ValueError):
        limit = 5
    if limit <= 0:
        limit = 5
    if streak < limit:
        return False
    if goal_reached or env_closed:
        return True
    return hunt_elapsed_meets_min(elapsed_sec, min_hunt_sec)


def env_probe_halt_reason(
    *,
    probe: str,
    tcp_ok: bool,
    marked: bool = False,
    closed_hits: int = 0,
    confirm_need: int = 2,
) -> tuple[str | None, int]:
    """平台探活要不要结束本猎。返回 (halt_env 或 None, 累计 closed 次数)。

    靶机 TCP 还通时，单次「closed」不当成比赛结束——14661 在 turn 1
    入口仍活就被连坐关箱。入口已死才认 closed；未标记时要连续确认。
    unreachable 只在父任务已标记且入口已死时让槽，不把整场判死。
    """
    p = str(probe or "").strip().lower()
    try:
        hits = max(0, int(closed_hits or 0))
    except (TypeError, ValueError):
        hits = 0
    try:
        need = int(confirm_need or 2)
    except (TypeError, ValueError):
        need = 2
    if need < 2:
        need = 2
    if p == "ok":
        return None, 0
    if p == "closed":
        hits += 1
        if marked:
            return "env_closed", hits
        if tcp_ok:
            return None, hits
        if hits >= need:
            return "env_closed", hits
        return None, hits
    if p == "unreachable":
        if marked and not tcp_ok:
            return "env_unreachable", hits
        return None, hits
    return None, hits


def should_mark_parent_env_closed(halt_env: str | None) -> bool:
    """只有平台明确到期才标父任务关停并连坐停兄弟题。

    env_unreachable 只让本猎让槽，不能把整场评测判死。
    """
    return str(halt_env or "").strip() == "env_closed"


def autopilot_env_gate_action(*, marked_closed: bool, probe: str) -> str:
    """父任务已标 env_closed 时，本 tick 怎么处理。

    resume = 平台仍活，清标记并继续填槽；drain = 仍关着/探不到，停子题；
    continue = 从未标记，走正常调度。
    """
    if not marked_closed:
        return "continue"
    if str(probe or "").strip() == "ok":
        return "resume"
    return "drain"


def parent_keep_alive_status(
    status: str | None,
    *,
    env_closed: bool,
    has_unfinished: bool,
) -> str | None:
    """环境未关且还有未完成子题时，不要把父项目留在 completed/error。"""
    if env_closed or not has_unfinished:
        return None
    st = str(status or "").strip().lower()
    if st in ("completed", "error"):
        return "idle"
    return None


def note_autopilot_watchdog(
    *,
    running: int,
    started: int,
    remaining_fresh: int,
    prev_ticks: int,
    trip_after: int,
) -> tuple[int, bool]:
    """空槽且仍有从未开过的题：累计 tick。返回 (新计数, 是否触发告警)。"""
    try:
        fresh = int(remaining_fresh or 0)
        run_n = int(running or 0)
        start_n = int(started or 0)
        prev = int(prev_ticks or 0)
        need = int(trip_after or 0)
    except (TypeError, ValueError):
        return 0, False
    if fresh > 0 and run_n <= 0 and start_n <= 0:
        ticks = prev + 1
        return ticks, bool(need > 0 and ticks >= need)
    return 0, False


def session_hang_due(
    *,
    idle_for: float,
    hang_sec: float,
    cmd_inflight: int = 0,
) -> bool:
    """回合内无活动才当卡死。命令仍在跑不算；hang_sec<=0 关闭。"""
    if int(cmd_inflight or 0) > 0:
        return False
    try:
        lim = float(hang_sec or 0)
    except (TypeError, ValueError):
        lim = 0.0
    if lim <= 0:
        return False
    try:
        idle = float(idle_for or 0)
    except (TypeError, ValueError):
        idle = 0.0
    return idle >= lim


def turn_event_idle_sec(
    *,
    now_wall: float,
    turn_started_wall: float,
    last_event_ts: float | None,
) -> float:
    """本回合有意义事件（思考/工具）的静默时长。SDK 心跳不算。"""
    try:
        now = float(now_wall or 0)
        started = float(turn_started_wall or 0)
    except (TypeError, ValueError):
        return 0.0
    try:
        last = float(last_event_ts or 0)
    except (TypeError, ValueError):
        last = 0.0
    if last < started - 1.0:
        return max(0.0, now - started)
    return max(0.0, now - last)


def graph_idle_pause_due(idle_for: float, limit: float) -> bool:
    try:
        lim = float(limit or 0)
    except (TypeError, ValueError):
        lim = 0.0
    if lim <= 0:
        return False
    try:
        idle = float(idle_for or 0)
    except (TypeError, ValueError):
        idle = 0.0
    return idle >= lim


def graph_idle_plans_due(empty_plans: int, limit: int) -> bool:
    """连续这么多御主方案仍无新节点/交旗/本地长计算 → 图空转。limit<=0 关闭。"""
    try:
        cap = int(limit or 0)
    except (TypeError, ValueError):
        cap = 0
    if cap <= 0:
        return False
    try:
        n = int(empty_plans or 0)
    except (TypeError, ValueError):
        n = 0
    return n >= cap


def note_graph_idle_plans(
    *,
    idle_plans: int,
    pivots: int,
    last_counted_pivots: int,
    progressed: bool,
) -> tuple[int, int]:
    """方案空转计数：有进展清零；新方案（pivots 增加）才 +1。hold 不加。"""
    try:
        n = max(0, int(idle_plans or 0))
    except (TypeError, ValueError):
        n = 0
    try:
        p = max(0, int(pivots or 0))
    except (TypeError, ValueError):
        p = 0
    try:
        last = max(0, int(last_counted_pivots or 0))
    except (TypeError, ValueError):
        last = 0
    if progressed:
        return 0, p
    if p > last:
        n += p - last
    return n, p


_WS_SKIP_DIR = frozenset({
    "__pycache__", ".git", ".claude", "agent-transcripts", ".pycache",
})
_WS_SKIP_NAME = frozenset({
    "shells.json",
})


def workspace_has_fresh_artifact(path: str | None, since_wall: float) -> bool:
    """工作区在 since_wall（epoch 秒）之后出现过非噪声文件，视为本地仍在推进。"""
    import os
    root = str(path or "").strip()
    if not root or since_wall <= 0:
        return False
    try:
        cutoff = float(since_wall)
    except (TypeError, ValueError):
        return False
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _WS_SKIP_DIR and not d.startswith(".")]
            for name in filenames:
                if name.startswith(".") or name in _WS_SKIP_NAME:
                    continue
                if name.endswith((".pyc", ".pyo", ".log")):
                    continue
                fp = os.path.join(dirpath, name)
                try:
                    if os.path.getmtime(fp) >= cutoff:
                        return True
                except OSError:
                    continue
    except OSError:
        return False
    return False
