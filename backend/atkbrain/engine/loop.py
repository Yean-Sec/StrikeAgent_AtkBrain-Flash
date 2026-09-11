"""攻击图自循环引擎。

固定授权目标下，反复：注入（人工 steering + 攻击图快照）→ 驱动项目会话推进一轮 →
新发现实时落图 → AI 监督给出下一轮方案 → 收工后蒸馏进跨局剧本（自进化）→ 沉淀经验到记忆库。
"""
from __future__ import annotations

import asyncio
import time
import traceback

from ..config import settings
from ..db import db, new_id, now, _dumps
from ..events import emit
from ..graph import store as gstore
from ..graph.hypothesize import (
    enum_sidetrack_when_weaponizable,
    graph_looks_like_served_binary,
    live_gadget_tactics,
    needs_channel_oracle,
    weaponize_prefer_tactics,
)
from ..graph.model import NodeIn
from ..memory import store as memory
from ..projects import build_scope, get_project, update_config, update_status
from ..project_status import (
    ctf_pass_index,
    final_project_status,
    format_duration_zh,
    hunt_hard_stop_info,
    hunt_max_turns,
    hunt_runtime_hard_stop_sec,
    uses_ctf_hunt_clocks,
)
from .hunt_clock import (
    empty_hunt,
    graph_idle_pause_due,
    graph_idle_plans_due,
    hunt_should_reset,
    note_graph_idle_plans,
    parse_hunt,
    reconstruct_hunt,
    fill_hunt_from_last_run,
    resume_completed_turn,
    looks_like_api_key_missing,
    env_probe_halt_reason,
    should_end_empty_streak,
    should_end_hunt_fault,
    should_mark_parent_env_closed,
    should_reset_graph_idle,
    session_hang_due,
    snapshot_hunt,
    turn_event_idle_sec,
    workspace_has_fresh_artifact,
)
from .hunt_resume import cancel_project_status, forget_resume, remember_resume
from .scheduler import RunManager
from .supervise import (
    LoopSupervisor,
    chain_next_tactics,
    graph_has_getshell,
    has_verified_asset,
    load_supervised_turns,
    should_consult_after_exec_fault,
    verified_finding_categories,
)


def is_transient_resource_error(exc: BaseException) -> bool:
    """FD 耗尽 / SQLite 打不开属于本机资源抖动，不应把子项目钉死成 error。"""
    errno = getattr(exc, "errno", None)
    if errno in (24, 23):  # EMFILE / ENFILE
        return True
    text = f"{type(exc).__name__} {exc}".lower()
    return any(
        n in text
        for n in (
            "too many open files",
            "unable to open database",
            "disk i/o error",
            "database is locked",
            "cantopen",
            "emfile",
            "enfile",
        )
    )


def _graph_summary(graph: dict, peer_entries: list[str] | None = None, current_entry: str = "",
                   objective: str = "", workspace_dir: str = "") -> str:
    from .supervisor_brief import expand_peer_node_keys, highlight_chain_line, plan_cites_peer_entry

    stats = graph.get("stats", {})
    rce = graph.get("rce_path", {})
    frontier = graph.get("frontier") or {}
    lines = [
        f"节点 {stats.get('nodes',0)} · 边 {stats.get('edges',0)} · 发现 {stats.get('findings',0)}"
        f"（严重 {stats.get('critical',0)}）· getshell={stats.get('has_shell', False)}",
        f"推理前沿：开放 {frontier.get('open', stats.get('frontier_open', 0))} · "
        f"策略数 {frontier.get('strategies', stats.get('frontier_strategies', 0))} · "
        f"已否证 {frontier.get('disproved', 0)} · 已验证 {frontier.get('verified', 0)}",
    ]
    nodes = list(graph.get("nodes") or [])
    peer_keys = expand_peer_node_keys(nodes, graph.get("edges") or [], peer_entries, current_entry)
    peer_nodes = [n for n in nodes if str(n.get("key") or "") in peer_keys]
    path = [str(x) for x in (rce.get("path") or []) if x]
    peer_void = bool(path and peer_keys and any(k in peer_keys for k in path))
    lines.append(highlight_chain_line(
        rce, objective=objective, peer_void=peer_void,
        arrow=" -> ", show_frontier_tag=True,
    ))
    own_nodes = [
        n for n in sorted(nodes, key=lambda n: n.get("risk_score", 0), reverse=True)
        if str(n.get("key") or "") not in peer_keys
    ][:12]
    if own_nodes:
        lines.append("高价值节点：")
        for n in own_nodes:
            lines.append(
                f"  · [{n.get('type')}/{n.get('severity')}] {n.get('key')} — {n.get('title')} "
                f"(risk={n.get('risk_score')})"
            )
    if peer_nodes:
        lines.append(
            f"邻题污染：{len(peer_nodes)} 个节点已隔离，其上的算法/密钥/flag 候选禁止当本题手法。"
        )
    findings = [
        f for f in (graph.get("findings") or [])
        if not plan_cites_peer_entry(
            f"{f.get('title') or ''} {f.get('detail') or ''} {f.get('node_key') or ''}",
            peer_entries,
        )
    ][:8]
    if findings:
        lines.append("最近发现：")
        for f in findings:
            flag = "★" if f.get("critical") else " "
            lines.append(f"  {flag}[{f['severity']}] {f['title']} ({f['category']})")
    # 已否证·勿重复：带上具体失败路径与失败原因，让本轮（含会话重置后的全新上下文）
    # 直接知道「这些证据组合已试过且失败」，不再走弯路/重复路。无新证据不要复开。
    disproved = graph.get("disproved") or []
    if disproved:
        lines.append("已否证（勿重复，除非有新证据）：")
        for i in disproved[:10]:
            why = (i.get("failure_fingerprint") or i.get("result_summary") or "").strip().replace("\n", " ")
            desc = (i.get("description") or "").strip()
            line = f"  ✗ {desc}"
            if why:
                line += f" — 因 {why[:80]}"
            lines.append(line)
    try:
        if workspace_dir:
            from .spiral import format_coverage_brief, load_ledger
            cov = format_coverage_brief(load_ledger(workspace_dir), objective=objective)
            if cov:
                lines.append(cov)
    except Exception:
        pass
    return "\n".join(lines)


def _intents_text(intents: list[dict], *, assigned: list[dict] | None = None,
                  peer_entries: list[str] | None = None, lock: bool = False) -> str:
    from .supervisor_brief import _intent_cites_peer

    if peer_entries:
        intents = [i for i in (intents or []) if not _intent_cites_peer(i, peer_entries)]
        assigned = [i for i in (assigned or []) if not _intent_cites_peer(i, peer_entries)]
    lines: list[str] = []
    if assigned:
        lines.append("【本轮前沿（局面优先）】")
        for i in assigned[:3]:
            lines.append(
                f"  ★ [{i.get('id')}] ({round(i.get('priority', i.get('est_success', 0.5)), 2)}) "
                f"{i['description']}  strategy=`{i.get('strategy_key')}`"
                + (f" ← {i.get('from')}" if i.get("from") else "")
            )
    if lock:
        return "\n".join(lines)
    open_rest = [i for i in intents if not assigned or i.get("id") not in {a.get("id") for a in assigned}]
    if open_rest:
        lines.append("开放前沿（候选）：")
        for i in open_rest[:8]:
            lines.append(
                f"  · [{i.get('id')}] ({round(i.get('priority', i.get('est_success', 0.5)), 2)}) "
                f"[{i.get('status','open')}] {i['description']}"
                + (f" ← {i.get('from')}" if i.get("from") else "")
            )
    return "\n".join(lines)


async def _recent_events_text(project_id: str, run_id: str | None, limit: int = 40) -> str:
    """取最近事件，压成可读短行（新→旧）。run_id=None 时取项目全量最近事件。"""
    if run_id:
        rows = await db.fetchall(
            "SELECT type, payload FROM events WHERE project_id=? AND run_id=? ORDER BY id DESC LIMIT ?",
            (project_id, run_id, limit),
        )
    else:
        rows = await db.fetchall(
            "SELECT type, payload FROM events WHERE project_id=? ORDER BY id DESC LIMIT ?",
            (project_id, limit),
        )
    import json as _json
    lines: list[str] = []
    for r in rows:
        try:
            p = _json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
        except Exception:
            p = {}
        snippet = (
            str(p.get("message") or p.get("text") or p.get("command")
                or p.get("content") or p.get("preview") or p.get("title") or "")
        ).replace("\n", " ").strip()
        if not snippet and p.get("tool"):
            snippet = f"tool={p.get('tool')} {str(p.get('input') or '')[:80]}"
        if snippet:
            lines.append(f"  · [{r['type']}] {snippet[:160]}")
    return "\n".join(lines)


def _disproved_text(graph: dict) -> str:
    out: list[str] = []
    for i in (graph.get("disproved") or [])[:10]:
        why = (i.get("failure_fingerprint") or i.get("result_summary") or "").strip().replace("\n", " ")
        desc = (i.get("description") or "").strip()
        line = f"  ✗ {desc}"
        if why:
            line += f" — 因 {why[:80]}"
        out.append(line)
    return "\n".join(out)


def _verified_findings_snapshot(graph: dict) -> tuple[str, int, int]:
    """已验证 finding 摘要 + high/critical 计数（供运行时续跑审查）。"""
    findings = graph.get("findings") or []
    verified = [
        f for f in findings
        if str(f.get("verification_status") or "verified").lower() == "verified"
    ]
    high = sum(1 for f in verified if str(f.get("severity") or "").lower() == "high")
    critical = sum(1 for f in verified if str(f.get("severity") or "").lower() == "critical")
    lines: list[str] = []
    # 严重度优先展示
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ranked = sorted(
        verified,
        key=lambda f: (order.get(str(f.get("severity") or "").lower(), 9), -(f.get("risk_score") or 0)),
    )
    for f in ranked[:16]:
        sev = str(f.get("severity") or "?")
        cat = str(f.get("category") or "")
        title = str(f.get("title") or f.get("node_key") or "")[:100]
        lines.append(f"  · [{sev}/{cat}] {title}")
    return ("\n".join(lines) if lines else "（无已验证发现）", high, critical)


async def _tcp_alive(host: str, port: int = 80, timeout: float = 3.0) -> bool:
    """传输层探活。泛化：任意授权入口，不假设 Web 路径。直连，供 CTF/本机靶网。"""
    if not host:
        return False
    try:
        conn = asyncio.open_connection(host, int(port or 80))
        _reader, writer = await asyncio.wait_for(conn, timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _entry_reachable(project: dict, host: str, timeout: float = 2.0) -> bool:
    """入口是否还能连上：主端口 + 80/443，直连 TCP。"""
    if not host:
        return False
    ordered: list[int] = []
    for p in _entry_ports(project) + [80, 443]:
        if p not in ordered:
            ordered.append(p)
    if not ordered:
        ordered = [80, 443]
    for port in ordered[:4]:
        if await _tcp_alive(host, port, timeout=timeout):
            return True
    return False


def _entry_port(project: dict) -> int:
    ports = _entry_ports(project)
    return ports[0] if ports else 80


def _entry_ports(project: dict) -> list[int]:
    raw = project.get("ports") or []
    if isinstance(raw, str):
        try:
            import json as _j
            raw = _j.loads(raw)
        except Exception:
            raw = [80]
    out: list[int] = []
    for p in raw or []:
        try:
            n = int(p)
        except Exception:
            continue
        if n > 0 and n not in out:
            out.append(n)
    return out


def _project_entry_port(project: dict | None) -> int | None:
    cfg = (project or {}).get("config") or {}
    bm = cfg.get("benchmark") or {}
    focus = str(bm.get("entry_focus") or "").strip()
    if ":" in focus:
        try:
            n = int(focus.rsplit(":", 1)[-1])
            if 1 <= n <= 65535:
                return n
        except (TypeError, ValueError):
            pass
    fps = bm.get("entry_fp") if isinstance(bm.get("entry_fp"), dict) else {}
    if fps:
        try:
            from ..entry_fingerprint import pick_focus_addr, project_entry_addrs
            addr = pick_focus_addr(project_entry_addrs(project), fps)
            if addr and ":" in addr:
                n = int(addr.rsplit(":", 1)[-1])
                if 1 <= n <= 65535:
                    return n
        except Exception:
            pass
    ports = (project or {}).get("ports") or []
    if ports:
        try:
            return int(ports[0])
        except (TypeError, ValueError, IndexError):
            pass
    for a in (bm.get("container_addr") or []):
        raw = str(a or "")
        if ":" in raw:
            try:
                n = int(raw.rsplit(":", 1)[-1])
            except (TypeError, ValueError):
                continue
            if 1 <= n <= 65535:
                return n
    return None


def _apply_bound_project(agent, project: dict, scope, *, peers: set[str] | None = None,
                         peer_addrs: set[str] | None = None,
                         own_addrs: set[str] | None = None) -> None:
    agent.project = project
    agent.scope = scope
    ctx = getattr(agent, "ctx", None)
    port = _project_entry_port(project)
    own = set(own_addrs or [])
    if not own:
        try:
            from ..entry_fingerprint import project_entry_addrs
            own = set(project_entry_addrs(project))
        except Exception:
            own = set()
    kind = "http"
    try:
        from ..entry_fingerprint import fingerprints_from_project, kind_from_fingerprints
        kind = kind_from_fingerprints(fingerprints_from_project(project)) or "http"
    except Exception:
        kind = "http"
    if ctx is not None:
        ctx.project = project
        ctx.scope = scope
        if peers is not None:
            ctx.peer_hosts = set(peers)
        if peer_addrs is not None:
            ctx.peer_addrs = set(peer_addrs)
        ctx.own_addrs = set(own)
        ctx.primary_port = port
        ctx.entry_kind = kind
    guard = getattr(agent, "guard", None)
    if guard is not None:
        guard.scope = scope
        if peers is not None:
            guard.peer_hosts = set(peers)
        if peer_addrs is not None:
            guard.peer_addrs = set(peer_addrs)
        guard.own_addrs = set(own)
        guard.primary_port = port


async def _run_runtime_review(
    *, project_id: str, rid: str, objective: str, graph: dict, project: dict,
    brief: str, turn: int, elapsed_sec: float, target: str, supervisor,
) -> dict | None:
    """CTF：默认关闭。runtime_review_after_sec>0 时才由御主审查是否续跑。"""
    from .ai_supervisor import consult_runtime_review
    from .supervisor_brief import SupervisorFacts, assemble_supervisor_brief

    try:
        facts = SupervisorFacts(
            quality=str(getattr(supervisor, "last_quality", "") or "none"),
            infra=int(getattr(supervisor, "infra_streak", 0) or 0) > 0,
            chain_live=has_verified_asset(graph),
            identity_mismatch=bool(getattr(supervisor, "entry_identity_mismatch", False)),
            no_progress=int(getattr(supervisor, "no_progress", 0) or 0),
            last_diagnosis=str(getattr(supervisor, "last_diagnosis", "") or ""),
            last_plan=str(getattr(supervisor, "last_plan_text", "") or ""),
            current_entry=str(target or (project or {}).get("target") or "").split(":")[0],
        )
        text = await assemble_supervisor_brief(
            project_id=project_id, run_id=rid, objective=objective,
            graph=graph, facts=facts, project=project, brief=brief, turn=turn,
        )
        text = (
            f"御主运行时审查：本猎已约 {int(elapsed_sec // 60)} 分钟、第 {turn} 轮。"
            f"由你判断是否续跑。\n"
        ) + (text or "")
        rr = await consult_runtime_review(text)
        diag = str((rr or {}).get("diagnosis") or "")
        plan = str((rr or {}).get("next_plan") or "")
        cont = bool((rr or {}).get("continue", True))
        await emit(
            project_id, "supervisor",
            {
                "kind": "runtime_review", "continue": cont, "diagnosis": diag,
                "next_plan": plan, "turn": turn,
            },
            run_id=rid,
        )
        await emit(
            project_id, "log",
            {"level": "info",
             "message": (
                 f"御主审查：{'续跑' if cont else '建议暂停'}"
                 + (f" — {diag[:160]}" if diag else "")
             )},
            run_id=rid,
        )
        return rr or {"continue": True}
    except Exception as e:
        await emit(
            project_id, "log",
            {"level": "warn", "message": f"御主审查失败（默认续跑）：{type(e).__name__}: {e}"},
            run_id=rid,
        )
        return {"continue": True}


async def _halt_closed_env(*, project: dict, project_id: str, rid: str, reason: str) -> None:
    """评测到期：记原因、停兄弟姐妹、禁止 autopilot 再开题。"""
    from .. import benchmark as bmk
    tag = "env_closed" if str(reason or "").startswith("env_closed") else (
        "env_unreachable" if "unreachable" in str(reason or "") else "env_closed"
    )
    await emit(
        project_id, "log",
        {"level": "warn",
         "message": "评测环境已关停或平台不可达，停止测试与二次验证，不再打已死靶机。"},
        run_id=rid,
    )
    await emit(
        project_id, "supervisor",
        {"kind": "halt", "diagnosis": "评测环境已到期或平台不可达",
         "error": (reason or tag)[:240], "stall": "infra"},
        run_id=rid,
    )
    try:
        await bmk.mark_environment_closed(project, reason or tag)
        await bmk.stop_sibling_runs(project, except_id=project_id)
    except Exception:
        pass
    try:
        row = await get_project(project_id)
        if row:
            cfg = dict(row.get("config") or {})
            cfg["completion_reason"] = tag
            await update_config(project_id, cfg)
    except Exception:
        pass


async def _abort_run_on_platform_error(
    e, *, project: dict, project_id: str, rid: str,
) -> bool:
    """环境到期 → 停测并标记父项目；额度/网络闪断 → 让出槽位。处理了则 True。"""
    from .. import benchmark as bmk
    if bmk.is_environment_closed_error(e):
        await _halt_closed_env(
            project=project, project_id=project_id, rid=rid, reason=f"env_closed:{e}"[:240],
        )
        await _finish_run(rid, "stopped", False, 0, f"env_closed: {e}")
        await update_status(project_id, "idle")
        await emit(project_id, "status", {"status": "stopped", "reason": "env_closed"}, run_id=rid)
        return True
    if bmk.is_transient_platform_error(e):
        await emit(
            project_id, "log",
            {"level": "info",
             "message": f"平台暂不可用，本 run 让出槽位稍后重试：{e}"},
            run_id=rid,
        )
        await _finish_run(rid, "stopped", False, 0, f"platform transient: {e}")
        await update_status(project_id, "idle")
        await emit(project_id, "status", {"status": "stopped", "reason": "platform_transient"}, run_id=rid)
        return True
    return False


async def _maybe_halt_expired_env(
    *, project: dict, supervisor, target: str, turn: int, just_rebound: bool, is_benchmark: bool,
) -> bool:
    """平台任务到期且入口已死 → 置 halt_env。靶机还通时不因单次探活关箱。"""
    if not is_benchmark:
        return False
    if supervisor.halt_env:
        return True
    from .. import benchmark as bmk
    host = str(target or project.get("target") or "").split(":")[0]
    port = _entry_port(project)
    tcp_ok = bool(host and await _tcp_alive(host, port, timeout=2.0))
    marked = False
    try:
        marked = await bmk.parent_env_closed(project)
    except Exception:
        marked = False
    periodic = just_rebound or turn == 1 or (turn % 6) == 0 or marked or not tcp_ok
    if not periodic and tcp_ok:
        return False
    gate = await bmk.probe_environment(project)
    if gate == "ok":
        supervisor.env_closed_hits = 0
        if marked:
            pid = project.get("parent_id") or project.get("id")
            if pid:
                try:
                    await bmk.clear_environment_closed(str(pid))
                except Exception:
                    pass
        return False
    reason, hits = env_probe_halt_reason(
        probe=gate,
        tcp_ok=tcp_ok,
        marked=marked,
        closed_hits=int(getattr(supervisor, "env_closed_hits", 0) or 0),
    )
    supervisor.env_closed_hits = hits
    if reason:
        supervisor.halt_env = reason
        return True
    return False


async def _refresh_entry_identity(
    *, project: dict, graph: dict, brief: str, supervisor, target: str,
    turn: int, just_rebound: bool, project_id: str,
) -> None:
    """探测首页栈，只更新 supervisor.entry_identity_mismatch，不注入机械话术。"""
    from .entry_identity import (
        classify_entry_identity, probe_entry_http, running_peers_same_entry,
    )

    if (
        not just_rebound
        and turn != 1
        and (turn % 6) != 0
        and not getattr(supervisor, "entry_identity_mismatch", False)
    ):
        return
    host = str(target or project.get("target") or "").split(":")[0]
    port = _entry_port(project)
    obj = None
    try:
        obj = (project.get("config") or {}).get("objective") or (project.get("config") or {}).get("track")
    except Exception:
        obj = None
    peers: list[str] = []
    try:
        peers = await running_peers_same_entry(project_id, host)
    except Exception:
        peers = []
    live: dict = {}
    must_px = False
    try:
        from ..proxy.pool import pool as _proxy_pool
        must_px = _proxy_pool.must_proxy(obj)
    except Exception:
        must_px = False
    tcp_ok = True if must_px else bool(host and await _tcp_alive(host, port, timeout=2.0))
    if tcp_ok:
        try:
            live = await probe_entry_http(host, port, objective=obj) or {}
        except Exception:
            live = {}
    result = classify_entry_identity(brief=brief or "", graph=graph, live=live)
    stack_mismatch = bool(result.get("mismatch"))
    mismatch = stack_mismatch or (bool(peers) and (not live or stack_mismatch))
    if live and not stack_mismatch:
        mismatch = False
    supervisor.entry_identity_mismatch = mismatch


async def _revive_ephemeral_entry(
    *, project: dict, agent, supervisor, project_id: str, rid: str, is_benchmark: bool,
):
    """入口不可达：评测容器可重建；真实目标只告警。到期则 halt_env。"""
    from .. import benchmark as bmk

    host = str(project.get("target") or "").split(":")[0]
    ports = project.get("ports") or [80]
    if isinstance(ports, str):
        try:
            import json as _j
            ports = _j.loads(ports)
        except Exception:
            ports = [80]
    try:
        port = int((ports or [80])[0] or 80)
    except Exception:
        port = 80
    scope = build_scope(project)
    target = project.get("target") or (scope.targets[0] if scope.targets else host)

    if host and await _tcp_alive(host, port):
        supervisor.rebind_same_addr = 0
        return project, scope, target

    if not is_benchmark:
        await emit(
            project_id, "log",
            {"level": "warn",
             "message": f"入口 {host}:{port} 传输层不可达（持久目标，不自动重建）。"
                        f"检查路由后继续已验证链，不要换无关策略族。"},
            run_id=rid,
        )
        return project, scope, target

    try:
        info = await bmk.revive_challenge(project, force_new=True)
    except bmk.BenchmarkError as e:
        if bmk.is_environment_closed_error(e):
            supervisor.halt_env = "env_closed"
        else:
            gate = await bmk.probe_environment(project)
            if gate in ("closed", "unreachable"):
                supervisor.halt_env = "env_closed" if gate == "closed" else "env_unreachable"
        await emit(
            project_id, "log",
            {"level": "warn", "message": f"入口重绑失败：{e}"},
            run_id=rid,
        )
        return project, scope, target
    except Exception as e:
        await emit(
            project_id, "log",
            {"level": "warn", "message": f"入口重绑失败：{e}"},
            run_id=rid,
        )
        if not await _tcp_alive(host, port):
            gate = await bmk.probe_environment(project)
            if gate in ("closed", "unreachable"):
                supervisor.halt_env = "env_closed" if gate == "closed" else "env_unreachable"
        return project, scope, target

    if not info and not await _tcp_alive(host, port):
        gate = await bmk.probe_environment(project)
        if gate in ("closed", "unreachable"):
            supervisor.halt_env = "env_closed" if gate == "closed" else "env_unreachable"
        return project, scope, target

    project = await get_project(project_id) or project
    scope = build_scope(project)
    try:
        from ..scope_pivot import hydrate_scope_from_graph, peer_challenge_entry_addrs, peer_challenge_entry_hosts
        peers = await peer_challenge_entry_hosts(project_id)
        addrs = await peer_challenge_entry_addrs(project_id)
        await hydrate_scope_from_graph(project_id, scope, reject_hosts=peers)
    except Exception:
        peers = set()
        addrs = set()
    target = project.get("target") or (scope.targets[0] if scope.targets else host)
    try:
        from ..entry_fingerprint import project_entry_addrs
        own = set(project_entry_addrs(project))
    except Exception:
        own = set()
    _apply_bound_project(agent, project, scope, peers=peers, peer_addrs=addrs, own_addrs=own)
    new_host = str(target or "").split(":")[0]
    reused = bool((info or {}).get("reused"))
    if reused and new_host == host:
        supervisor.rebind_same_addr += 1
    else:
        supervisor.rebind_same_addr = 0
    supervisor.last_entry_addr = new_host
    await emit(
        project_id, "log",
        {"level": "info",
         "message": (
             f"入口重绑：{'复用容器' if reused else '新容器'} → {(info or {}).get('addrs') or target}"
             + ("（同地址仍不可达，下次将换新容器）" if reused and new_host == host else "")
         )},
        run_id=rid,
    )
    return project, scope, target


def _ultimate_goal_met(graph: dict, agent, objective: str | None) -> bool:
    """已有至少一个赛道终极目标（须已验证）。红队达一即等于可停机。"""
    if getattr(agent.ctx, "goal_reached", False):
        return True
    from ..objective import hard_stop_exempt, normalize_objective, objective_allows_flag
    from ..memory.achievements import detect_achievements

    obj = normalize_objective(objective)
    allows = objective_allows_flag(obj)
    ach = detect_achievements(graph, allows_flag=allows)
    _, high, critical = _verified_findings_snapshot(graph)
    return hard_stop_exempt(
        obj,
        flags_correct=int(getattr(agent.ctx, "flags_correct", 0) or 0),
        achievements=ach,
        verified_high=high,
        verified_critical=critical,
    )


async def _sync_redteam_goal(project_id: str, agent, objective: str | None) -> bool:
    """红队：本 run 新达成 getshell → 置位 goal_reached。历史图上的旧达成不收工。"""
    from ..objective import REDTEAM, normalize_objective, redteam_new_ultimate
    from ..memory.achievements import detect_achievements

    if normalize_objective(objective) != REDTEAM:
        return False
    if getattr(agent.ctx, "goal_reached", False):
        return True
    try:
        graph = await gstore.get_graph(project_id)
    except Exception:
        return False
    ach = detect_achievements(graph, allows_flag=False)
    baseline = getattr(agent.ctx, "achievements_at_start", None)
    if redteam_new_ultimate(ach, baseline):
        agent.ctx.goal_reached = True
        return True
    return False


async def _create_run(project_id: str) -> str:
    rid = new_id("run_")
    await db.execute(
        "INSERT INTO runs(id, project_id, status, started_at) VALUES(?,?,?,?)",
        (rid, project_id, "running", now()),
    )
    return rid


async def _finish_run(rid: str, status: str, goal: bool, turns: int, summary: str) -> None:
    await db.execute(
        "UPDATE runs SET status=?, goal_reached=?, turns=?, summary=?, ended_at=? WHERE id=?",
        (status, int(goal), turns, summary, now(), rid),
    )


async def _previous_run_row(project_id: str, current_rid: str) -> dict | None:
    rows = await db.fetchall(
        "SELECT id, status, turns, started_at, ended_at FROM runs "
        "WHERE project_id=? AND id!=? ORDER BY started_at DESC LIMIT 1",
        (project_id, current_rid),
    )
    return rows[0] if rows else None


async def _last_status_turn(project_id: str, run_id: str | None) -> int:
    if not run_id:
        return 0
    rows = await db.fetchall(
        "SELECT payload FROM events WHERE project_id=? AND run_id=? AND type='status' "
        "ORDER BY ts DESC LIMIT 40",
        (project_id, run_id),
    )
    import json as _json
    best = 0
    for r in rows:
        try:
            p = _json.loads(r["payload"] or "{}") if isinstance(r.get("payload"), str) else (r.get("payload") or {})
        except Exception:
            continue
        t = p.get("turn") or p.get("turns")
        try:
            n = int(t or 0)
        except (TypeError, ValueError):
            n = 0
        if n > best:
            best = n
    return best


async def _latest_flag_event_ts(project_id: str) -> float:
    """最近一次交旗（对错都算）的墙钟时间；没有则 0。"""
    if not project_id:
        return 0.0
    try:
        row = await db.fetchone(
            "SELECT ts FROM events WHERE project_id=? AND type='flag' ORDER BY id DESC LIMIT 1",
            (project_id,),
        )
    except Exception:
        return 0.0
    try:
        return max(0.0, float((row or {}).get("ts") or 0))
    except (TypeError, ValueError):
        return 0.0


async def _evaluate_supervisor(
    *, supervisor, project_id: str, rid: str, turn: int, graph: dict,
    flags: int, project: dict, brief: str, summary: str, result: dict,
    target: str, scope, assigned: list | None = None, open_intents: list | None = None,
    record_progress: bool = True,
) -> None:
    """问御主。失败只记 error 并自检重启，不拖垮从者循环。"""
    stats = (graph or {}).get("stats") or {}
    try:
        nodes = int(stats.get("nodes") or 0)
        edges = int(stats.get("edges") or 0)
        findings = int(stats.get("findings") or 0)
    except (TypeError, ValueError):
        nodes = len((graph or {}).get("nodes") or [])
        edges = len((graph or {}).get("edges") or [])
        findings = len((graph or {}).get("findings") or [])
    try:
        await supervisor.evaluate(
            nodes=nodes, edges=edges, findings=findings, flags=flags, graph=graph,
            scope_hosts=[
                str(target or "").split(":")[0],
                *[str(x).split(":")[0] for x in (getattr(scope, "targets", None) or [])],
            ],
            project=project, brief=brief,
            last_turn_text=summary if isinstance(summary, str) else "",
            last_tool_uses=int((result or {}).get("tool_uses") or 0),
            task_subagents=list((result or {}).get("task_subagents") or []),
            turn=turn,
            assigned=assigned,
            open_intents=open_intents,
            record_progress=record_progress,
        )
    except Exception as se:
        await emit(
            project_id, "log",
            {"level": "warn",
             "message": f"监督器异常已忽略（本轮不注入方案）：{type(se).__name__}: {se}"},
            run_id=rid,
        )
        try:
            await supervisor.emit_skip(
                turn, reason="error",
                detail=f"{type(se).__name__}: {se}",
            )
        except Exception:
            pass


async def _ended_real_attempts(project_id: str) -> int:
    """已结束且够长的 run 数。进行中的本遍不计，用来决定 40/120/180 墙钟。"""
    from ..benchmark import count_real_attempts_from_runs
    try:
        rows = await db.fetchall(
            "SELECT started_at, ended_at FROM runs WHERE project_id=?",
            (project_id,),
        )
    except Exception:
        return 0
    min_s = float(getattr(settings, "benchmark_min_attempt_sec", 120) or 0)
    try:
        return int(count_real_attempts_from_runs(
            list(rows or []), min_sec=min_s, now_ts=now(), include_open=False,
        ) or 0)
    except Exception:
        return 0


async def _persist_hunt_clock(project_id: str, rid: str, hunt: dict) -> None:
    """轮次中途也落盘，避免 SIGKILL 来不及走 _finish_run。"""
    try:
        await db.execute("UPDATE runs SET turns=? WHERE id=?", (int(hunt.get("turn") or 0), rid))
    except Exception:
        pass
    try:
        row = await get_project(project_id)
        cfg = dict((row or {}).get("config") or {})
        cfg["hunt"] = hunt
        await update_config(project_id, cfg)
    except Exception:
        pass


async def _run_turn_guarded(
    agent, instruction: str, timeout: float, *, hang_sec: float = 0,
    project_id: str = "",
):
    """跑一轮；timeout<=0 时不限墙钟。hang_sec>0 时，无思考/工具且无命令才当卡死。

    不能用裸 asyncio.wait_for：Py3.11+ 在子协程不响应 CancelledError 时会一直等取消完成，
    导致“回合卡死保护”失效、整题假死。这里用 wait+cancel，超时后最多再等几秒即放弃僵尸任务。
    人工强制指令会打断本轮，尽快把控制权还给 loop。
    """
    task = asyncio.create_task(agent.run_turn(instruction))
    wait_timeout = None if float(timeout or 0) <= 0 else float(timeout)
    hang = float(hang_sec or 0)
    t0 = time.monotonic()
    t0_wall = time.time()
    poll = 2.0
    pid = str(project_id or getattr(agent, "project_id", "") or "")
    human_cut = False
    while True:
        remaining = None
        if wait_timeout is not None:
            remaining = wait_timeout - (time.monotonic() - t0)
            if remaining <= 0:
                break
        slice_wait = poll if hang > 0 else 2.0
        if remaining is not None:
            slice_wait = min(float(slice_wait or remaining), max(0.05, remaining))
        done, _ = await asyncio.wait({task}, timeout=slice_wait)
        if task in done:
            return task.result()
        from .scheduler import manager as _mgr
        if pid and _mgr.has_pending_human(pid):
            human_cut = True
            break
        if hang > 0:
            ctx = getattr(agent, "ctx", None)
            inflight = int(getattr(ctx, "cmd_inflight", 0) or 0)
            last_ev = None
            try:
                if pid:
                    row = await db.fetchone(
                        "SELECT MAX(ts) AS ts FROM events WHERE project_id=? "
                        "AND type IN ('tool','tool_result','thought','text') AND ts>=?",
                        (pid, t0_wall - 2.0),
                    )
                    last_ev = float((row or {}).get("ts") or 0) or None
            except Exception:
                last_ev = None
            idle = turn_event_idle_sec(
                now_wall=time.time(), turn_started_wall=t0_wall, last_event_ts=last_ev,
            )
            if session_hang_due(idle_for=idle, hang_sec=hang, cmd_inflight=inflight):
                break
        if wait_timeout is None and hang <= 0 and not human_cut:
            # 不限墙钟也不看 hang 时仍要能被人工打断：上面 slice_wait=2s 已轮询。
            continue
    try:
        await agent.interrupt()
    except Exception:
        pass
    task.cancel()
    await asyncio.wait({task}, timeout=5)
    if human_cut:
        return {
            "text": "",
            "tool_uses": 0,
            "task_subagents": list(getattr(getattr(agent, "ctx", None), "task_subagents", None) or []),
            "human_interrupt": True,
        }
    # 若仍未结束：留下后台僵尸任务，但必须把控制权还给 loop 继续下一轮
    raise asyncio.TimeoutError()


async def _record_memory(project: dict, project_id: str, goal: bool, turn: int, summary: str, rid: str,
                         applied_lesson_ids: list[str] | None = None) -> None:
    """把本次 run 沉淀为版本化 episode，并蒸馏进跨局剧本。"""
    try:
        final_graph = await gstore.get_graph(project_id, heal=True)
        ep = await memory.summarize_run(project, final_graph, {"goal_reached": goal, "turns": turn, "summary": summary})
        try:
            from ..memory.evolve import episode_qualifies_for_evolve, evolve_after_run
            qualifies = bool(isinstance(ep, dict) and episode_qualifies_for_evolve(ep))
            if ep.get("skipped"):
                if qualifies:
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": (
                             f"经验已在记忆库（同思路跳过重复写入"
                             f"{' · ' + str(ep.get('reason') or '') if ep.get('reason') else ''}）"
                         )},
                        run_id=rid,
                    )
            elif qualifies:
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": f"经验已沉淀到记忆库 v{ep.get('version')}（{ep.get('outcome')}）"},
                    run_id=rid,
                )
            evo = await evolve_after_run(
                episode=ep if isinstance(ep, dict) else None,
                applied_ids=list(applied_lesson_ids or []),
                won=bool(goal),
                project_id=project_id,
            )
            if qualifies and (evo.get("distilled") or evo.get("ai_revised") or evo.get("reinforced")):
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         "自进化："
                         + ("模型已蒸馏路线/方法/思想 " if evo.get("distilled") else "")
                         + (f"强化 {evo.get('reinforced')} 条 " if evo.get("reinforced") else "")
                         + (f"修订 {evo.get('ai_revised')} 条" if evo.get("ai_revised") else "")
                     ).strip()},
                    run_id=rid,
                )
        except Exception:
            pass
    except Exception:
        pass


async def run_project_loop(manager: RunManager, project_id: str) -> None:
    handle = manager.get(project_id)
    project = await get_project(project_id)
    if not project or not handle:
        return
    scope = build_scope(project)
    target = project.get("target") or (scope.targets[0] if scope.targets else "")
    objective = (project.get("config") or {}).get("objective", settings.default_objective)

    # 延迟导入，避免与 SDK 的循环依赖
    from ..agents.session import ProjectAgent
    from ..projects import assert_safe_project_target
    from .. import benchmark as bmk
    from .scheduler import hunt_slot_kind

    is_benchmark = bmk.is_benchmark_sub(project)

    if is_benchmark:
        refuse = await bmk.gate_start_against_closed_env(project)
        if refuse:
            handle.status = "done"
            manager._drop_handle(project_id, handle)
            await update_status(project_id, "idle")
            await emit(project_id, "log", {"level": "warn", "message": refuse})
            await emit(project_id, "status", {"status": "stopped", "reason": "env_closed"})
            return

    if (target or "").strip() and not is_benchmark:
        try:
            assert_safe_project_target(target)
        except ValueError as e:
            handle.status = "done"
            manager._drop_handle(project_id, handle)
            await update_status(project_id, "error")
            await emit(project_id, "log", {"level": "error", "message": str(e)})
            await emit(project_id, "status", {"status": "error", "reason": "unsafe_target"})
            return

    await emit(project_id, "status", {"status": "queued", "reason": "concurrency"})

    agent: ProjectAgent | None = None
    goal = False
    exhausted = False
    pause_reason: str | None = None
    prev_completion_reason = None
    turn = 0
    completed_turn = 0
    summary = ""
    assigned: list = []
    rid = ""
    applied_lesson_ids: list[str] = []
    try:
        handle.slot_kind = hunt_slot_kind(project, objective)
        await manager.slot_sem(handle.slot_kind).acquire()
        handle.slot_held = True
        if is_benchmark:
            refuse = await bmk.gate_start_against_closed_env(project)
            if refuse:
                handle.status = "done"
                await update_status(project_id, "idle")
                await emit(project_id, "log", {"level": "warn", "message": refuse}, run_id=rid or None)
                await emit(project_id, "status", {"status": "stopped", "reason": "env_closed"})
                return
        rid = await _create_run(project_id)
        handle.run_id = rid
        handle.status = "running"
        await update_status(project_id, "running")
        prev_completion_reason = None
        # 清掉上一轮完成标记；但先读出来判断是否新开猎。
        try:
            proj0 = await get_project(project_id)
            cfg0 = dict((proj0 or {}).get("config") or {})
            prev_completion_reason = cfg0.get("completion_reason")
            if cfg0.pop("completion_reason", None) is not None:
                await update_config(project_id, cfg0)
        except Exception:
            prev_completion_reason = None
        await emit(project_id, "status", {"status": "running", "run_id": rid}, run_id=rid)
        if is_benchmark:
            hard = bool(getattr(handle, "hard_restart", False))
            try:
                if hard:
                    await gstore.clear_graph(project_id)
                    info = await bmk.start_challenge(project)
                    await bmk.bump_attempt(project)
                    await emit(project_id, "log",
                               {"level": "warn", "message": "重新开题：已清空攻击图并起新容器。"}, run_id=rid)
                else:
                    info = await bmk.ensure_challenge(project, hard_restart=False)
                    reused = bool((info or {}).get("reused"))
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": ("续跑：复用已开启的容器，攻击图保留。" if reused
                                     else "续跑：原容器已停，已起新容器但保留攻击图与工作区。")},
                        run_id=rid,
                    )
                    try:
                        row = await get_project(project_id)
                        att = int((((row or {}).get("config") or {}).get("benchmark") or {}).get("attempts") or 0)
                        if att <= 0:
                            await bmk.bump_attempt(row or project)
                    except Exception:
                        pass
            except bmk.BenchmarkError as e:
                await emit(project_id, "log",
                           {"level": "error", "message": f"评测容器启动失败：{e}"}, run_id=rid)
                if await _abort_run_on_platform_error(
                    e, project=project, project_id=project_id, rid=rid,
                ):
                    return
                raise
            project = await get_project(project_id) or project
            scope = build_scope(project)
            target = project.get("target") or (scope.targets[0] if scope.targets else "")

        parent_id = (project or {}).get("parent_id")
        if parent_id:
            try:
                from ..agents.prompts import attach_parent_brief_hint
                parent = await get_project(str(parent_id))
                project = attach_parent_brief_hint(project, parent) or project
            except Exception:
                pass

        agent = ProjectAgent(project, scope)
        handle.agent = agent
        agent.set_run(rid)
        brief = agent.brief  # 题目简报：每轮指令都带上，防题面信息被上下文压缩丢弃
        try:
            from ..scope_pivot import peer_challenge_entry_addrs, peer_challenge_entry_hosts
            from ..entry_fingerprint import project_entry_addrs
            peers = await peer_challenge_entry_hosts(project_id)
            addrs = await peer_challenge_entry_addrs(project_id)
            own = set(project_entry_addrs(project))
            agent.ctx.peer_hosts = set(peers)
            agent.ctx.peer_addrs = set(addrs)
            agent.ctx.own_addrs = own
            agent.ctx.primary_port = _project_entry_port(project)
            try:
                from ..entry_fingerprint import (
                    fingerprints_from_project, kind_from_fingerprints, surfaces_from_project,
                )
                agent.ctx.entry_kind = kind_from_fingerprints(fingerprints_from_project(project)) or "http"
                agent.ctx.entry_surface = surfaces_from_project(project)
            except Exception:
                agent.ctx.entry_kind = "http"
                agent.ctx.entry_surface = []
            agent.guard.peer_hosts = set(peers)
            agent.guard.peer_addrs = set(addrs)
            agent.guard.own_addrs = set(own)
            agent.guard.primary_port = agent.ctx.primary_port
        except Exception:
            pass

        # 种子：入口目标。评测容器换 IP 时并入当前地址，避免画出第二个孤立黑点。
        # 同题多个 container 入口都保留，不要把第二地址并进 primary。
        keep_hosts: set[str] = set()
        try:
            from ..entry_fingerprint import project_entry_hosts, project_entry_addrs, fingerprints_from_project
            keep_hosts = project_entry_hosts(project)
        except Exception:
            keep_hosts = set()
        if target:
            await gstore.adopt_entry_host(
                project_id, str(target).split(":")[0],
                scope_detail=_dumps(scope.to_dict()), run_id=rid,
                keep_hosts=keep_hosts,
            )
        try:
            from ..entry_fingerprint import (
                project_entry_addrs, fingerprints_from_project, surfaces_from_project,
            )
            fps = fingerprints_from_project(project)
            surfaces = surfaces_from_project(project, per_addr=True)
            primary_h = str(target or "").split(":")[0].strip().lower()
            for addr in project_entry_addrs(project):
                h = str(addr).split(":")[0].strip().lower()
                if not h:
                    continue
                kind = str(fps.get(addr) or fps.get(addr.lower()) or "").lower()
                port = None
                if ":" in str(addr):
                    try:
                        port = int(str(addr).rsplit(":", 1)[-1])
                    except (TypeError, ValueError):
                        port = None
                if h != primary_h:
                    await gstore.upsert_node(
                        project_id,
                        NodeIn(
                            key=f"target:{h}", type="target", title=f"本题入口 {h}",
                            detail=f"同题入口 {addr}", severity="info",
                            tags=["entry", f"host:{h}"],
                        ),
                        run_id=rid,
                    )
                if port:
                    surf = []
                    if isinstance(surfaces, dict):
                        surf = list(surfaces.get(addr) or surfaces.get(str(addr).lower()) or [])
                    if kind in ("http", "filter"):
                        svc_key = f"svc:{port}/http@{h}"
                        svc_tags = ["http", "entry", f"host:{h}"] + [str(x) for x in surf if x]
                        title = f"HTTP {h}:{port}"
                    elif kind == "interactive":
                        svc_key = f"svc:{port}/tcp@{h}"
                        svc_tags = ["tcp", "interactive", "entry", f"host:{h}"]
                        title = f"交互服务 {h}:{port}"
                    else:
                        svc_key = f"svc:{port}@{h}"
                        svc_tags = ["entry", f"host:{h}"] + [str(x) for x in surf if x]
                        title = f"端口 {h}:{port}"
                    detail = f"入口 {addr} 指纹={kind or 'unknown'}"
                    if surf:
                        detail = detail + " 表面=" + ",".join(str(x) for x in surf)
                    await gstore.upsert_node(
                        project_id,
                        NodeIn(
                            key=svc_key, type="service", title=title,
                            detail=detail,
                            severity="info", tags=svc_tags,
                        ),
                        run_id=rid,
                    )
        except Exception:
            pass
        for vh in list(scope.targets or []):
            host_vh = str(vh or "").strip().lower().rstrip(".")
            if not host_vh or host_vh == str(target or "").strip().lower().rstrip("."):
                continue
            if host_vh in keep_hosts:
                continue
            await gstore.upsert_node(
                project_id,
                NodeIn(key=f"info:vhost:{host_vh}", type="info", title=f"同机 {host_vh}",
                       detail="同机 vhost", severity="info",
                       tags=["vhost", "same-machine", f"host:{host_vh}"]),
                run_id=rid,
            )
        try:
            refreshed = await gstore.refresh_derived_intents(project_id, run_id=rid)
            if refreshed.get("opened") or refreshed.get("stale_deferred"):
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         f"已按当前规则刷新 Intent：新开放 {refreshed.get('opened', 0)}，"
                         f"搁置过时 {refreshed.get('stale_deferred', 0)}"
                     )},
                    run_id=rid,
                )
        except Exception as e:
            await emit(
                project_id, "log",
                {"level": "warn", "message": f"Intent 刷新失败（不阻断）：{e}"},
                run_id=rid,
            )

        last_sig = (-1, -1, -1)
        stall = 0
        last_flags = 0  # 已确认 flag 数（用于“夺 flag 即重置空转”）
        hang = 0        # 连续“回合墙钟超时(疑似会话卡死)”计数
        empty_streak = 0  # 连续空回合（会话已死但仍秒回）计数；用于熔断，防监督空转打爆
        hang_note = ""
        min_hunt_sec = 0.0
        if is_benchmark:
            try:
                min_hunt_sec = float(getattr(settings, "benchmark_min_hunt_sec", 0) or 0)
            except (TypeError, ValueError):
                min_hunt_sec = 0.0
        result: dict = {}
        # AI 御主：从者整轮打完再下令；本轮先沿用上一份方案开打。
        supervisor = LoopSupervisor(
            project_id=project_id, run_id=rid, objective=objective,
        )
        import time as _time
        t_start = _time.monotonic()
        hard_restart = bool(getattr(handle, "hard_restart", False))
        has_live_foothold = False
        _g_boot = None
        try:
            _g_boot = await gstore.get_graph(project_id)
            has_live_foothold = graph_has_getshell(_g_boot)
        except Exception:
            _g_boot = None
        hunt_reset = hunt_should_reset(
            hard_restart=hard_restart,
            completion_reason=prev_completion_reason,
            has_live_foothold=has_live_foothold,
        )
        hunt_state = empty_hunt()
        completed_turn = 0
        if hunt_reset:
            hunt_state = empty_hunt()
            turn = 0
            completed_turn = 0
            await _persist_hunt_clock(project_id, rid, hunt_state)
        else:
            try:
                cfg_h = dict((await get_project(project_id) or {}).get("config") or {})
            except Exception:
                cfg_h = {}
            hunt_state = parse_hunt(cfg_h)
            if int(hunt_state.get("turn") or 0) <= 0:
                prev_run = await _previous_run_row(project_id, rid)
                last_turn = await _last_status_turn(project_id, (prev_run or {}).get("id"))
                hunt_state = fill_hunt_from_last_run(
                    hunt_state,
                    reconstructed=reconstruct_hunt(
                        last_run=prev_run, last_turn=last_turn, now_ts=now(),
                    ),
                )
            turn = int(hunt_state.get("turn") or 0)
            carry = float(hunt_state.get("elapsed_sec") or 0)
            if carry > 0:
                t_start = _time.monotonic() - carry
            supervised = await load_supervised_turns(project_id)
            turn = resume_completed_turn(
                persisted_turn=turn, supervised_turns=supervised,
            )
            completed_turn = turn
        # 攻击图空转：CTF 看连续御主方案数；墙钟上限默认关闭
        graph_idle_limit = int(getattr(settings, "graph_idle_pause_sec", 0) or 0)
        graph_idle_plans_limit = int(getattr(settings, "graph_idle_empty_plans", 6) or 0)
        try:
            _g0 = _g_boot if _g_boot is not None else await gstore.get_graph(project_id)
            last_node_count = int((_g0.get("stats") or {}).get("nodes") or 0)
        except Exception:
            last_node_count = 0
            _g0 = {"nodes": [], "edges": [], "findings": []}
        try:
            from ..memory.achievements import detect_achievements
            from ..objective import objective_allows_flag, redteam_ultimate_reached
            agent.ctx.achievements_at_start = detect_achievements(
                _g0, allows_flag=objective_allows_flag(objective),
            )
            if redteam_ultimate_reached(agent.ctx.achievements_at_start):
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         "攻击图上已有历史 getshell，本 run 不因此收工；"
                         "需本轮新达成 report_shell 才会完成。"
                     )},
                    run_id=rid,
                )
        except Exception:
            agent.ctx.achievements_at_start = []
        last_node_growth_mono = _time.monotonic()
        last_progress_wall = _time.time()
        last_flag_event_ts = 0.0
        idle_plans = 0 if hunt_reset else max(0, int(hunt_state.get("idle_plans") or 0))
        last_counted_pivots = 0
        try:
            last_flag_event_ts = await _latest_flag_event_ts(project_id)
        except Exception:
            last_flag_event_ts = 0.0
        if not hunt_reset:
            idle_carry = float(hunt_state.get("idle_sec") or 0)
            # 接续时若把整段猎时长误当成空转，会一上来就 graph_idle。只恢复明确记下的空转窗口。
            if graph_idle_limit > 0 and idle_carry >= graph_idle_limit:
                idle_carry = 0.0
            if idle_carry > 0:
                last_node_growth_mono = _time.monotonic() - idle_carry
                last_progress_wall = _time.time() - idle_carry
            if last_flag_event_ts > 0 and graph_idle_limit > 0:
                age = now() - last_flag_event_ts
                if 0 <= age < graph_idle_limit:
                    flag_mono = _time.monotonic() - age
                    if flag_mono > last_node_growth_mono:
                        last_node_growth_mono = flag_mono
        last_runtime_review_mono: float | None = None
        if not hunt_reset and hunt_state.get("reviewed_elapsed_sec") is not None:
            last_runtime_review_mono = t_start + float(hunt_state["reviewed_elapsed_sec"])
        if not hunt_reset and (completed_turn > 0 or int(hunt_state.get("turn") or 0) > 0):
            mins = int(float(hunt_state.get("elapsed_sec") or 0) // 60)
            await emit(
                project_id, "log",
                {"level": "info",
                 "message": (
                     f"续跑接续第 {completed_turn + 1} 轮"
                     f"（本猎已运行约 {mins} 分钟，不因后端重启把轮次打回 1）。"
                 )},
                run_id=rid,
            )
            filled = await supervisor.backfill_missing_turns(completed_turn)
            if filled:
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         f"已补齐 {filled} 条缺失的御主记录"
                         "（中断或空回合当时未写盘）。"
                     )},
                    run_id=rid,
                )
            restored = await supervisor.restore_last_plan()
            if restored:
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         f"续跑恢复监督方案 #{supervisor.pivots}"
                         "（不因入口暂停/进程重启把方案打回 #1）。"
                     )},
                    run_id=rid,
                )
            elif supervisor.force_bundle_review:
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": "续跑不恢复已空转的探索方案，按全局重开多路线审查。"},
                    run_id=rid,
                )
        else:
            if hard_restart:
                await emit(
                    project_id, "log",
                    {"level": "info", "message": "新开猎：轮次与时长从零计。"},
                    run_id=rid,
                )
            failed = str(prev_completion_reason or "") not in ("", "goal_reached")
            if failed:
                why = str(prev_completion_reason or "中断")
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": (
                         f"新开猎（上一猎因 {why} 结束）。"
                         "不沿用已否证的凭据/访问码方案。"
                         "已验证漏洞的下一跳仍从攻击图续打，不要当新题从指纹/契约重开。"
                     )},
                    run_id=rid,
                )
                restored = await supervisor.restore_last_plan()
                if restored:
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": (
                             f"新开猎仍恢复监督方案 #{supervisor.pivots}"
                             "（图上收成走廊继续，不从入口重开）。"
                         )},
                        run_id=rid,
                    )
                elif supervisor.force_bundle_review:
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": "新开猎不恢复已空转的探索方案，按全局重开多路线审查。"},
                        run_id=rid,
                    )
        await supervisor.emit_ready_probe()
        last_counted_pivots = int(getattr(supervisor, "pivots", 0) or 0)
        entry_down_since: float | None = None
        entry_rebind_attempts = 0
        entry_rebind_sec = int(getattr(settings, "benchmark_entry_down_rebind_sec", 90) or 0)
        entry_yield_sec = int(getattr(settings, "benchmark_entry_down_yield_sec", 480) or 0)
        redteam_yield_sec = int(
            getattr(settings, "redteam_entry_down_yield_sec", 0)
            or getattr(settings, "entry_unreachable_yield_sec", 0)
            or 0
        )
        runtime_after = int(getattr(settings, "runtime_review_after_sec", 0) or 0)
        runtime_interval = int(getattr(settings, "runtime_review_interval_sec", 0) or 0)
        ctf_clocks = uses_ctf_hunt_clocks(objective)
        ended_att = 0
        if ctf_clocks:
            try:
                ended_att = await _ended_real_attempts(project_id)
            except Exception:
                ended_att = 0
        pass_n = ctf_pass_index(ended_real_attempts=ended_att)
        runtime_hard = hunt_runtime_hard_stop_sec(objective, pass_n=pass_n)
        cap_txt = format_duration_zh(runtime_hard)
        if ctf_clocks:
            await emit(
                project_id, "log",
                {"level": "info",
                 "message": (
                     f"本猎第 {pass_n} 遍，墙钟硬停 {cap_txt}"
                     f"（图空转看连续 {graph_idle_plans_limit} 个御主方案）。"
                 )},
                run_id=rid,
            )
        else:
            info = hunt_hard_stop_info(objective, pass_n=pass_n)
            await emit(
                project_id, "log",
                {"level": "info", "message": info.get("label") or f"墙钟硬停 {cap_txt}。"},
                run_id=rid,
            )
        _fc = int(((project.get("config") or {}).get("flag_count")) or 1)
        _base = int(settings.benchmark_run_budget_sec or 0)
        _cap = int(settings.benchmark_run_budget_cap or 0)
        if is_benchmark and _base > 0:
            budget = _base * max(1, _fc)
            if _cap > 0:
                budget = min(budget, _cap)
        else:
            budget = 0
        max_turns = hunt_max_turns(objective, is_benchmark=is_benchmark)

        async def _save_hunt(done_turn: int) -> None:
            await _persist_hunt_clock(project_id, rid, snapshot_hunt(
                turn=done_turn,
                elapsed_sec=_time.monotonic() - t_start,
                reviewed_elapsed_sec=(
                    None if last_runtime_review_mono is None
                    else max(0.0, last_runtime_review_mono - t_start)
                ),
                idle_sec=max(0.0, _time.monotonic() - last_node_growth_mono),
                idle_plans=idle_plans,
            ))

        elapsed0 = _time.monotonic() - t_start
        if runtime_hard > 0 and elapsed0 >= runtime_hard:
            summary = (
                f"本猎已运行约 {format_duration_zh(elapsed0)}（≥{cap_txt} 硬上限），强制停止，记失败。"
            )
            pause_reason = "runtime_cap"
            await emit(project_id, "log", {"level": "info", "message": summary}, run_id=rid)
        elif max_turns > 0 and turn >= max_turns:
            pause_reason = "turn_cap"
            summary = (
                f"本猎已达 {turn} 轮（上限 {max_turns} 轮），强制停止，记失败。"
            )
            await emit(project_id, "log", {"level": "info", "message": summary}, run_id=rid)
        while pause_reason is None and (max_turns <= 0 or turn < max_turns):
            await _sync_redteam_goal(project_id, agent, objective)
            if agent.ctx.goal_reached:
                goal = True
                await emit(project_id, "status", {"status": "goal_reached", "turn": turn}, run_id=rid)
                break
            elapsed = _time.monotonic() - t_start
            await _save_hunt(completed_turn)
            # 仅在显式开启预算时生效；默认无预算，直到夺旗
            if budget and elapsed > budget and not agent.ctx.goal_reached:
                await emit(project_id, "log",
                           {"level": "info",
                            "message": f"达到单题时间预算 {budget}s（{completed_turn} 轮未夺旗），让出并发槽，稍后可重试。"},
                           run_id=rid)
                break
            if runtime_hard > 0 and elapsed >= runtime_hard:
                summary = (
                    f"本猎已运行约 {format_duration_zh(elapsed)}（≥{cap_txt} 硬上限），强制停止，记失败。"
                )
                pause_reason = "runtime_cap"
                await emit(
                    project_id, "log",
                    {"level": "info", "message": summary},
                    run_id=rid,
                )
                break
            if ctf_clocks:
                try:
                    _g_idle = await gstore.get_graph(project_id)
                    _nc = int((_g_idle.get("stats") or {}).get("nodes") or 0)
                except Exception:
                    _nc = last_node_count
                flag_ts = 0.0
                try:
                    flag_ts = await _latest_flag_event_ts(project_id)
                except Exception:
                    flag_ts = 0.0
                node_grew = _nc > last_node_count
                new_flag = flag_ts > last_flag_event_ts
                cmd_prog = float(getattr(getattr(agent, "ctx", None), "last_local_progress_mono", 0) or 0)
                ws_prog = False
                try:
                    ws = getattr(getattr(agent, "ctx", None), "workspace_dir", None)
                    ws_prog = workspace_has_fresh_artifact(ws, last_progress_wall)
                except Exception:
                    ws_prog = False
                local_prog = bool(cmd_prog > last_node_growth_mono or ws_prog)
                if should_reset_graph_idle(
                    node_grew=node_grew, new_flag_event=new_flag, local_progress=local_prog,
                ):
                    if node_grew:
                        last_node_count = _nc
                    if new_flag:
                        last_flag_event_ts = flag_ts
                    last_node_growth_mono = _time.monotonic()
                    last_progress_wall = _time.time()
                    idle_plans, last_counted_pivots = note_graph_idle_plans(
                        idle_plans=idle_plans,
                        pivots=int(getattr(supervisor, "pivots", 0) or 0),
                        last_counted_pivots=last_counted_pivots,
                        progressed=True,
                    )
                idle_for = _time.monotonic() - last_node_growth_mono
                if graph_idle_pause_due(idle_for, graph_idle_limit):
                    mins = int(idle_for // 60)
                    lim_m = graph_idle_limit // 60
                    summary = (
                        f"攻击图已连续约 {mins} 分钟无新节点、无交旗、也无本地长计算（≥{lim_m} 分钟），"
                        f"当前节点数 {last_node_count}，判定失败。"
                    )
                    pause_reason = "graph_idle"
                    await emit(
                        project_id, "log",
                        {"level": "info", "message": summary + "（可人工复盘后再次启动）"},
                        run_id=rid,
                    )
                    break
                if graph_idle_plans_due(idle_plans, graph_idle_plans_limit):
                    summary = (
                        f"攻击图已连续 {idle_plans} 个御主方案无新节点、无交旗、也无本地长计算"
                        f"（≥{graph_idle_plans_limit} 个），当前节点数 {last_node_count}，判定失败。"
                    )
                    pause_reason = "graph_idle"
                    await emit(
                        project_id, "log",
                        {"level": "info", "message": summary + "（可人工复盘后再次启动）"},
                        run_id=rid,
                    )
                    break
            steering_msgs = list(manager.drain_steering(project_id))
            human_steers = list(steering_msgs)
            ehost = str(target or project.get("target") or "").split(":")[0]
            if ehost and not await _entry_reachable(project, ehost):
                live_shell = False
                try:
                    live_shell = graph_has_getshell(await gstore.get_graph(project_id))
                except Exception:
                    live_shell = False
                if live_shell:
                    # 已有命令执行立足点：入口 HTTP 挂了继续后渗透，不暂停、不重绑入口。
                    entry_down_since = None
                else:
                    if entry_down_since is None:
                        entry_down_since = _time.monotonic()
                    down_for = _time.monotonic() - entry_down_since
                    if is_benchmark:
                        eport = _entry_port(project)
                        if (
                            entry_yield_sec > 0
                            and down_for >= entry_yield_sec
                            and entry_rebind_attempts >= 1
                        ):
                            mins = max(1, int(down_for // 60))
                            await emit(
                                project_id, "log",
                                {"level": "warn",
                                 "message": (
                                     f"入口 {ehost}:{eport} 已连续 {mins} 分钟不可达，"
                                     f"暂停本题让槽（攻击图保留，稍后可续跑）。"
                                 )},
                                run_id=rid,
                            )
                            pause_reason = "entry_dead"
                            break
                        if (
                            entry_rebind_sec > 0
                            and down_for >= entry_rebind_sec
                            and entry_rebind_attempts < 2
                        ):
                            supervisor.want_rebind = True
                    elif redteam_yield_sec > 0 and down_for >= redteam_yield_sec:
                        mins = max(1, int(down_for // 60))
                        await emit(
                            project_id, "log",
                            {"level": "warn",
                             "message": (
                                 f"入口 {ehost} 已连续约 {mins} 分钟不可达"
                                 f"（已探 80/443/登记端口），暂停本项目让出并发槽。"
                                 f"不换目标；站点恢复后可再启动。"
                             )},
                            run_id=rid,
                        )
                        pause_reason = "entry_dead"
                        break
            else:
                entry_down_since = None
            just_rebound = False
            if supervisor.drain_rebind():
                old_t = target
                project, scope, target = await _revive_ephemeral_entry(
                    project=project, agent=agent, supervisor=supervisor,
                    project_id=project_id, rid=rid, is_benchmark=is_benchmark,
                )
                just_rebound = True
                entry_rebind_attempts += 1
                nh = str(target or "").split(":")[0]
                if nh and await _tcp_alive(nh, _entry_port(project)):
                    entry_down_since = None
                if supervisor.halt_env:
                    pause_reason = supervisor.halt_env
                    if should_mark_parent_env_closed(pause_reason):
                        await _halt_closed_env(
                            project=project, project_id=project_id, rid=rid,
                            reason=supervisor.halt_env,
                        )
                    else:
                        await emit(
                            project_id, "log",
                            {"level": "warn",
                             "message": (
                                 f"平台暂不可达（{pause_reason}），本题让槽，"
                                 "不把整场评测标结束。"
                             )},
                            run_id=rid,
                        )
                    break
                if target and target != old_t:
                    steering_msgs.append(f"入口已重绑到 {target}。")
                    try:
                        from ..entry_fingerprint import project_entry_hosts as _own_hosts
                        _keep = _own_hosts(project)
                        await gstore.adopt_entry_host(
                            project_id, str(target).split(":")[0],
                            scope_detail=_dumps(scope.to_dict()), run_id=rid,
                            keep_hosts=_keep,
                        )
                    except Exception:
                        pass
                elif target and supervisor.stall_class not in ("postex", "chain"):
                    steering_msgs.append(f"入口仍是 {target}。")
            if await _maybe_halt_expired_env(
                project=project, supervisor=supervisor, target=target,
                turn=turn, just_rebound=just_rebound, is_benchmark=is_benchmark,
            ):
                pause_reason = supervisor.halt_env or "env_closed"
                if should_mark_parent_env_closed(pause_reason):
                    await _halt_closed_env(
                        project=project, project_id=project_id, rid=rid,
                        reason=pause_reason,
                    )
                else:
                    await emit(
                        project_id, "log",
                        {"level": "warn",
                         "message": (
                             f"平台暂不可达（{pause_reason}），本题让槽，"
                             "不把整场评测标结束。"
                         )},
                        run_id=rid,
                    )
                break
            turn += 1
            try:
                await _save_hunt(turn)
            except Exception:
                pass
            graph = await gstore.get_graph(project_id)
            try:
                await _refresh_entry_identity(
                    project=project, graph=graph, brief=brief, supervisor=supervisor,
                    target=target, turn=turn, just_rebound=just_rebound,
                    project_id=project_id,
                )
            except Exception:
                pass
            # 人工强制与御主分通道：有真人输入时不把御主方案钉进同一条指令。
            # 同一份方案再钉进下一轮只给从者看，不往协同窗口重复刷一条 🧭。
            pinned_advisor = None
            sup_steer = None
            if human_steers:
                supervisor.human_override = True
                try:
                    hold = max(0, int(getattr(settings, "advisor_hold_turns", 3) or 0))
                except (TypeError, ValueError):
                    hold = 3
                supervisor.last_steer_turn = int(turn or 0)
                supervisor.human_hold_until = int(turn or 0) + hold
                for m in human_steers:
                    await emit(
                        project_id, "steer",
                        {"content": m, "applied": True, "source": "human", "force": True},
                        run_id=rid,
                    )
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": "本轮执行人工强制指令（覆盖御主方案，不守御主禁令）。"},
                    run_id=rid,
                )
            else:
                in_human_hold = int(turn or 0) <= int(getattr(supervisor, "human_hold_until", 0) or 0)
                if in_human_hold:
                    pinned_advisor = None
                else:
                    sup_steer = supervisor.drain_steer()
                    if sup_steer:
                        last_emitted = str(getattr(supervisor, "last_emitted_steer", None) or "")
                        if last_emitted.strip() and last_emitted.strip() == str(sup_steer).strip():
                            pinned_advisor = sup_steer
                            steering_msgs = steering_msgs + [sup_steer]
                        else:
                            steering_msgs = steering_msgs + [sup_steer]
                            supervisor.last_emitted_steer = str(sup_steer)
                    elif getattr(supervisor, "binding", None) and supervisor.active_steer:
                        pinned_advisor = supervisor.active_steer
                        steering_msgs = steering_msgs + [pinned_advisor]
                    for m in steering_msgs:
                        if pinned_advisor is not None and m is pinned_advisor:
                            continue
                        source = "supervisor" if m is sup_steer else "human"
                        await emit(project_id, "steer",
                                   {"content": m, "applied": True, "source": source}, run_id=rid)
            steering = "\n".join(f"- {m}" for m in steering_msgs)
            # 每轮从者都是全新 Pi；换方向只改本轮简报，不续接旧对话。
            if supervisor.drain_reset():
                await emit(project_id, "log",
                           {"level": "info", "message": "御主：换攻击思路（新开会话，局面只走攻击图）。"},
                           run_id=rid)

            lessons: list[dict] = []
            evo_text = ""
            try:
                from ..memory.evolve import (
                    avoid_from_lessons, format_lessons_block, retrieve_lessons, tactics_from_lessons,
                )
                lessons = await retrieve_lessons(project, graph, limit=6, bump_uses=True)
                for it in lessons:
                    if it.get("id") and it["id"] not in applied_lesson_ids:
                        applied_lesson_ids.append(it["id"])
                evo_text = format_lessons_block(lessons)
            except Exception:
                lessons = []
                evo_text = ""

            open_intents = await gstore.list_open_intents(project_id)
            prefer = supervisor.drain_prefer_tactics()
            verified = has_verified_asset(graph) and not supervisor.entry_identity_mismatch
            cats = verified_finding_categories(graph) if verified else frozenset()
            from ..objective import objective_is_src
            src_cycle = objective_is_src(objective)
            if verified:
                if src_cycle:
                    prefer = set(prefer or ()) | {
                        "impact_escalate", "web_inject", "access_control",
                        "html_sink", "upload_bypass", "input_abuse",
                    }
                else:
                    prefer = set(prefer or ()) | set(chain_next_tactics(cats))
            elif needs_channel_oracle(graph):
                prefer = set(prefer or ()) | {"channel_oracle", "input_abuse"}
            gadget = live_gadget_tactics(graph)
            if gadget and not src_cycle:
                prefer = set(prefer or ()) | set(gadget)
            wz = weaponize_prefer_tactics(graph)
            if wz and not src_cycle:
                prefer = set(prefer or ()) | set(wz)
            defer_tacs: set[str] = set()
            sidetrack_enum = enum_sidetrack_when_weaponizable(graph)
            if sidetrack_enum:
                prefer = set(prefer or ()) - set(sidetrack_enum)
                defer_tacs |= set(sidetrack_enum)
            kind = str(getattr(getattr(agent, "ctx", None), "entry_kind", "") or "").lower()
            brief_txt = str(getattr(agent, "brief", "") or "")
            if graph_looks_like_served_binary(graph, brief_txt):
                prefer = set(prefer or ()) | {"reverse_binary", "protocol_model"}
                defer_tacs |= {
                    "content_enum", "web_inject", "auth_surface",
                    "access_control", "fingerprint", "file_read_chain",
                }
                prefer -= defer_tacs
            if kind in ("interactive", "mixed"):
                prefer = set(prefer or ()) | {"protocol_model"}
                if graph_looks_like_served_binary(graph, brief_txt):
                    prefer = set(prefer or ()) | {"reverse_binary"}
            elif kind == "filter" and not verified:
                prefer = set(prefer or ()) | {"filter_bypass", "channel_oracle"}
            if not verified:
                prefer = set(prefer or ()) | {"web_inject"}
                prefer -= defer_tacs
            needs_cycle = False
            try:
                from ..entry_fingerprint import merge_surface_tags
                from ..graph.hypothesize import (
                    live_surface_needs_cycle, surface_defer_tactics,
                    surface_prefer_tactics, surfaces_from_graph_nodes,
                )
                surf = merge_surface_tags(
                    list(getattr(agent.ctx, "entry_surface", None) or []),
                    surfaces_from_graph_nodes(graph),
                )
                surf_tacs = surface_prefer_tactics(surf)
                if surf_tacs:
                    prefer = set(prefer or ()) | surf_tacs
                    needs_cycle = live_surface_needs_cycle(surf)
                verified = has_verified_asset(graph) and not supervisor.entry_identity_mismatch
                defer_tacs |= set(surface_defer_tactics(surf, has_verified=verified) or ())
            except Exception:
                surf_tacs = set()
                needs_cycle = False
            try:
                from ..memory.evolve import tactics_from_lessons, avoid_from_lessons
                lesson_do = tactics_from_lessons(lessons)
                if lesson_do:
                    prefer = set(prefer or ()) | lesson_do
                avoid_tacs = avoid_from_lessons(lessons)
                exclude = supervisor.frontier_exclude_strategies()
            except Exception:
                lesson_do = set()
                avoid_tacs = set()
                exclude = supervisor.frontier_exclude_strategies()
            if verified:
                from .advisor_bind import closeout_sidetrack_tactics
                sidetrack = closeout_sidetrack_tactics(cats)
                prefer = set(prefer or ()) - sidetrack
                defer_tacs = set(defer_tacs or ()) | set(sidetrack)
            if needs_cycle and not verified:
                exclude = set(exclude or ()) | {"content_enum"}
            if defer_tacs:
                exclude = set(exclude or ()) | set(defer_tacs)
            peer_entries = sorted(getattr(getattr(agent, "ctx", None), "peer_addrs", None) or [])
            if peer_entries:
                from .supervisor_brief import _intent_cites_peer
                exclude |= {
                    str(it.get("strategy_key") or "")
                    for it in (open_intents or [])
                    if it.get("strategy_key") and _intent_cites_peer(it, peer_entries)
                }
            claim_unverified = False
            try:
                from .supervisor_brief import (
                    claimed_secret_disproved,
                    flag_submission_stats,
                    intent_claims_obtained_secret,
                )
                c_flags, w_flags = await flag_submission_stats(project_id)
                claim_unverified = claimed_secret_disproved(
                    plan=f"{supervisor.last_plan_text or ''} {supervisor.last_diagnosis or ''}",
                    graph=graph,
                    correct_flags=c_flags,
                    wrong_flags=w_flags,
                )
            except Exception:
                intent_claims_obtained_secret = None  # type: ignore
                c_flags = 0
            try:
                fc = int(((project or {}).get("config") or {}).get("flag_count") or 0)
            except (TypeError, ValueError):
                fc = 0
            try:
                got = int(c_flags or 0)
            except Exception:
                got = 0
            bind_flags = supervisor._binding_graph_flags(
                graph, correct_flags=got, flag_count=fc,
            )
            from .advisor_bind import (
                binding_reserve_tactics, ensure_postex_orthogonal,
                format_binding_block, pick_bound_assigned,
                situation_protected_intent_ids,
            )
            from ..objective import objective_is_src as _obj_is_src
            src_cycle = _obj_is_src(objective)
            reserve = () if src_cycle else binding_reserve_tactics(
                has_foothold=bool(bind_flags.get("has_foothold")),
                remaining_goals=bool(bind_flags.get("remaining_goals")),
                has_verified_asset=bool(bind_flags.get("has_verified_asset")),
                verified_categories=bind_flags.get("verified_categories"),
                has_live_gadget=bool(bind_flags.get("has_live_gadget")),
            )
            try:
                await gstore.reopen_live_hop_auth(project_id, run_id=rid)
                if reserve:
                    await gstore.reopen_advisor_deferred_tactics(
                        project_id, reserve, run_id=rid,
                    )
                if bind_flags.get("needs_channel_oracle"):
                    await gstore.reopen_false_closed_oracle(
                        project_id, needs_oracle=True, run_id=rid,
                    )
                await gstore.defer_local_closeout_for_remaining_flags(project_id, run_id=rid)
                open_intents = await gstore.list_open_intents(project_id)
            except Exception:
                pass
            bind = getattr(supervisor, "binding", None)
            oi = list(open_intents or [])
            if peer_entries:
                from .supervisor_brief import _intent_cites_peer
                oi = [i for i in oi if not _intent_cites_peer(i, peer_entries)]
            if claim_unverified and intent_claims_obtained_secret:
                oi = [i for i in oi if not intent_claims_obtained_secret(i)]
            updated = bind
            if not src_cycle:
                updated = ensure_postex_orthogonal(
                    bind, oi,
                    has_foothold=bool(bind_flags.get("has_foothold")),
                    remaining_goals=bool(bind_flags.get("remaining_goals")),
                    has_verified_asset=bool(bind_flags.get("has_verified_asset")),
                    verified_categories=bind_flags.get("verified_categories"),
                    has_live_gadget=bool(bind_flags.get("has_live_gadget")),
                )
            if updated is not None and updated is not bind:
                old_block = format_binding_block(bind)
                new_block = format_binding_block(updated)
                supervisor.binding = updated
                supervisor.assigned_intent_ids = list(updated.must_intents[:3])
                bind = updated
                if not human_steers:
                    if old_block and new_block and old_block in steering:
                        steering = steering.replace(old_block, new_block)
                    elif new_block:
                        steering = (steering + "\n- " + new_block) if steering else new_block
            if reserve:
                supervisor.banned_strategies = [
                    b for b in (supervisor.banned_strategies or []) if b not in reserve
                ]
                exclude -= set(reserve)
            if human_steers:
                want_ids = []
                try:
                    agent.ctx.bound_must_intents = frozenset()
                except Exception:
                    pass
            else:
                want_ids = supervisor.drain_assigned_intents()
                try:
                    agent.ctx.bound_must_intents = situation_protected_intent_ids(bind, oi)
                except Exception:
                    agent.ctx.bound_must_intents = frozenset()
            bind_prefer = set((bind.prefer_tactics if bind else None) or ()) | set(lesson_do or ())
            bind_deny = set((bind.deny_tactics if bind else None) or ())
            bind_deny -= set(reserve)
            if bind_flags.get("has_foothold"):
                bind_deny |= set(avoid_tacs or ())
                exclude |= set(avoid_tacs or ())
            extra: list[dict] = []
            if human_steers:
                assigned = []
                want_ids = []
            elif not claim_unverified:
                extra = await gstore.list_frontier_intents(
                    project_id, limit=8 if peer_entries else 3,
                    exclude_strategies=exclude,
                    prefer_tactics=bind_prefer or prefer,
                )
                if peer_entries:
                    extra = [i for i in extra if not _intent_cites_peer(i, peer_entries)]
            if not human_steers:
                assigned = pick_bound_assigned(
                    open_intents=oi,
                    want_ids=want_ids,
                    extras=extra,
                    prefer=set(),
                    deny=bind_deny,
                    lock=False,
                    reserve=reserve,
                    exclusive=bool(reserve) and not bind_flags.get("has_foothold")
                    and not bind_flags.get("has_verified_asset"),
                )
            if assigned:
                await gstore.claim_intents(project_id, [i["id"] for i in assigned if i.get("id")], run_id=rid)
                await emit(
                    project_id, "log",
                    {"level": "info",
                     "message": "本轮前沿（局面优先）: " + ", ".join(
                         f"{i.get('id')}({(i.get('strategy_key') or '')[:40]})" for i in assigned
                     )},
                    run_id=rid,
                )
            instruction = _build_instruction(
                turn, target, graph, open_intents, steering, objective,
                assigned=assigned, brief=brief, postex_phase=agent.ctx.postex_phase,
                evolution=evo_text, peer_entries=peer_entries,
                entry_kind=getattr(agent.ctx, "entry_kind", "") or "",
                entry_addrs=sorted(getattr(agent.ctx, "own_addrs", None) or []),
                entry_surface=list(getattr(agent.ctx, "entry_surface", None) or []),
                lock_intents=False, has_human=bool(human_steers),
                workspace_dir=getattr(agent, "workspace_dir", "") or "",
            )
            if hang_note:
                instruction = f"{hang_note}\n\n{instruction}"
                hang_note = ""

            await emit(project_id, "status", {"status": "running", "turn": turn}, run_id=rid)
            yield_to_advisor = False
            turn_yielded = False
            hang_sec = 0.0
            try:
                # 单回合墙钟：0 表示不限；评测预算开启时仍用剩余预算卡住。
                # 不中途打断从者；本轮先打完（含工人），打完再问御主。
                turn_timeout = float(getattr(settings, "turn_max_seconds", 0) or 0)
                from .advisor_bind import intent_tactic
                from .advisor_schedule import should_yield_turn_to_advisor
                yield_sec = float(getattr(settings, "turn_advisor_yield_sec", 0) or 0)
                if yield_sec > 0 and should_yield_turn_to_advisor(
                    assigned_tactics={intent_tactic(i) for i in (assigned or [])},
                    has_foothold=bool(bind_flags.get("has_foothold")),
                    has_verified_asset=bool(verified),
                    verified_categories=cats if verified else None,
                    has_advisor_plan=bool(
                        getattr(supervisor, "binding", None)
                        or getattr(supervisor, "active_steer", None)
                    ),
                ):
                    yield_to_advisor = True
                    turn_timeout = yield_sec if turn_timeout <= 0 else min(turn_timeout, yield_sec)
                if budget:
                    remaining = budget - (_time.monotonic() - t_start)
                    if remaining <= 0:
                        break
                    turn_timeout = remaining if turn_timeout <= 0 else min(remaining, turn_timeout)
                hang_sec = float(getattr(settings, "turn_hang_sec", 0) or 0)
                try:
                    from ..agents.prompts import default_fanout_roles
                    if human_steers:
                        subs = default_fanout_roles(objective)
                    else:
                        subs = [
                            str(x).strip()
                            for x in ((bind.subagents if bind else None) or [])
                            if str(x).strip()
                        ]
                        if not subs:
                            subs = default_fanout_roles(objective)
                    agent.ctx.fanout_roles = subs
                except Exception:
                    pass
                result = await _run_turn_guarded(
                    agent, instruction, turn_timeout, hang_sec=hang_sec,
                    project_id=project_id,
                )
                cut_for_human = bool(result.get("human_interrupt")) or manager.take_human_interrupt(project_id)
                if cut_for_human:
                    empty_streak = 0
                    hang = 0
                    completed_turn = turn
                    await _save_hunt(completed_turn)
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": "已打断本轮从者，下一轮执行人工强制指令。"},
                        run_id=rid,
                    )
                    continue
                summary = result.get("text", "")[:4000] or summary
                hang = 0  # 本回合正常返回，清零卡死计数
                # DeepSeek 未配密钥：秒回短文且无工具调用。禁止把「登录失败」规划文当密钥坏了。
                _txt = (result.get("text") or "").strip()
                _auth_fail = looks_like_api_key_missing(
                    _txt, tool_uses=int(result.get("tool_uses") or 0),
                )
                if _auth_fail:
                    elapsed_now = _time.monotonic() - t_start
                    halt = bool(getattr(supervisor, "halt_env", None))
                    if should_end_hunt_fault(
                        elapsed_sec=elapsed_now,
                        min_hunt_sec=min_hunt_sec,
                        goal_reached=bool(agent.ctx.goal_reached),
                        env_closed=halt,
                    ):
                        await emit(
                            project_id, "log",
                            {"level": "error",
                             "message": "DeepSeek Harness 鉴权失败。请检查 "
                                        "backend/data/atkbrain-dsh.env 是否含 DEEPSEEK_API_KEY。"},
                            run_id=rid,
                        )
                        summary = "DeepSeek API key missing"
                        await supervisor.emit_skip(turn, reason="exec_fault", detail="DeepSeek 鉴权失败，本轮未监督。")
                        completed_turn = turn
                        await _save_hunt(completed_turn)
                        break
                    empty_streak += 1
                    await emit(
                        project_id, "log",
                        {"level": "warn",
                         "message": (
                             f"疑似鉴权失败文案但未满最短猎面 {int(min_hunt_sec)}s，"
                             "重建会话继续，不关容器。"
                         )},
                        run_id=rid,
                    )
                    try:
                        await agent.begin_fresh_session()
                        agent.set_run(rid)
                    except Exception:
                        pass
                    completed_turn = turn
                    await _save_hunt(completed_turn)
                    await asyncio.sleep(2.0)
                    continue
                # 空回合检测：SDK 会话已死后 query 会秒回且无任何工具/文本。
                # 视为会话故障 → 全新会话，不续接旧对话。
                text_len = len((result.get("text") or "").strip())
                if int(result.get("tool_uses") or 0) == 0 and text_len < 20:
                    empty_streak += 1
                    await emit(project_id, "log",
                               {"level": "warn",
                                "message": f"本回合无任何工具/有效输出（连续空回合 {empty_streak}），疑似会话已死，开全新 Pi。"},
                               run_id=rid)
                    try:
                        await agent.begin_fresh_session()
                        agent.set_run(rid)
                        supervisor.note_exec_fault("empty turn / dead session")
                        await emit(project_id, "log",
                                   {"level": "info",
                                    "message": "已开全新从者会话（不续接旧对话）。"},
                                   run_id=rid)
                    except Exception as e:
                        await emit(project_id, "log",
                                   {"level": "warn", "message": f"空回后新开会话失败：{e}"},
                                   run_id=rid)
                    completed_turn = turn
                    await _save_hunt(completed_turn)
                    if empty_streak >= 5:
                        elapsed_now = _time.monotonic() - t_start
                        halt = bool(getattr(supervisor, "halt_env", None))
                        if should_end_empty_streak(
                            empty_streak=empty_streak,
                            elapsed_sec=elapsed_now,
                            min_hunt_sec=min_hunt_sec,
                            goal_reached=bool(agent.ctx.goal_reached),
                            env_closed=halt,
                        ):
                            await supervisor.emit_skip(turn, reason="empty_turn")
                            await emit(project_id, "log",
                                       {"level": "info",
                                        "message": f"连续 {empty_streak} 个空回合，结束本 run，交由自动重试(全新会话)。"},
                                       run_id=rid)
                            break
                        empty_streak = 0
                        await emit(project_id, "log",
                                   {"level": "info",
                                    "message": (
                                        f"连续空回合但未满最短猎面 {int(min_hunt_sec)}s，"
                                        "重建会话继续，不关容器。"
                                    )},
                                   run_id=rid)
                        await asyncio.sleep(2.0)
                        continue
                    if not should_consult_after_exec_fault(
                        reason="empty_turn",
                        has_active_plan=bool(supervisor.active_steer or supervisor.pending_steer),
                    ):
                        await supervisor.emit_skip(turn, reason="empty_turn")
                        continue
                    result = {"text": "", "tool_uses": 0, "task_subagents": []}
                empty_streak = 0
            except asyncio.TimeoutError:
                # report_flag 可能在回合超时边界刚好完成。先读取共享上下文，
                # 避免已被平台接受的最后一枚 flag 被误记成 stopped/idle。
                if agent.ctx.goal_reached:
                    goal = True
                    await emit(project_id, "status", {"status": "goal_reached", "turn": turn}, run_id=rid)
                    break
                if budget and (_time.monotonic() - t_start) >= budget:
                    await emit(project_id, "log",
                               {"level": "info", "message": f"单题时间预算 {budget}s 到，让出并发槽，稍后可重试。"},
                               run_id=rid)
                    break
                if yield_to_advisor:
                    turn_yielded = True
                    await emit(
                        project_id, "log",
                        {"level": "info",
                         "message": (
                             f"本回合已满 {turn_timeout:.0f}s（入口侦察或已验证能力未消耗），"
                             "打断以让御主开口。"
                         )},
                        run_id=rid,
                    )
                    for it in assigned:
                        if it.get("id"):
                            try:
                                await gstore.set_intent_status(
                                    project_id, it["id"], "open",
                                    result_summary="turn yield — advisor review",
                                    run_id=rid,
                                )
                            except Exception:
                                pass
                    result = {
                        "text": (summary or "")[:400],
                        "tool_uses": 1,
                        "task_subagents": list(getattr(agent.ctx, "task_subagents", None) or []),
                    }
                    summary = (
                        (summary or "")
                        + (f"\n本回合满 {turn_timeout:.0f}s，让出给御主。" if summary else
                           f"本回合满 {turn_timeout:.0f}s，让出给御主。")
                    ).strip()
                    hang = 0
                else:
                    hang += 1
                    hang_note = (
                        "【上回合卡死】未产生思考或工具。本轮第一动作必须调用工具"
                        "（http_request / run_cmd），禁止只规划。"
                    )
                    shown = turn_timeout if float(turn_timeout or 0) > 0 else hang_sec
                    await emit(project_id, "log",
                               {"level": "info",
                                "message": f"本回合超过 {shown:.0f}s 无活动(疑似会话卡死)，已打断（连续 {hang} 次）。"},
                               run_id=rid)
                    # 超时是执行故障：把本轮 active intent 退回 open，不记为否证
                    for it in assigned:
                        if it.get("id"):
                            try:
                                await gstore.set_intent_status(
                                    project_id, it["id"], "open",
                                    result_summary="turn timeout / session hang — retry",
                                    run_id=rid,
                                )
                            except Exception:
                                pass
                    if hang >= 2:
                        elapsed_now = _time.monotonic() - t_start
                        halt = bool(getattr(supervisor, "halt_env", None))
                        if should_end_hunt_fault(
                            elapsed_sec=elapsed_now,
                            min_hunt_sec=min_hunt_sec,
                            goal_reached=bool(agent.ctx.goal_reached),
                            env_closed=halt,
                        ):
                            await supervisor.emit_skip(turn, reason="hang")
                            completed_turn = turn
                            await _save_hunt(completed_turn)
                            await emit(project_id, "log",
                                       {"level": "info", "message": "连续多回合卡死，结束本 run，交由自动重试(全新会话)。"},
                                       run_id=rid)
                            break
                        hang = 0
                        await emit(
                            project_id, "log",
                            {"level": "info",
                             "message": (
                                 f"连续卡死但未满最短猎面 {int(min_hunt_sec)}s，"
                                 "重建会话继续，不关容器。"
                             )},
                            run_id=rid,
                        )
                        try:
                            await agent.begin_fresh_session()
                            agent.set_run(rid)
                        except Exception:
                            pass
                        completed_turn = turn
                        await _save_hunt(completed_turn)
                        await asyncio.sleep(2.0)
                        continue
                    result = {
                        "text": (summary or "")[:400],
                        "tool_uses": 0,
                        "task_subagents": [],
                    }
                    summary = (
                        (summary or "")
                        + (f"\n本回合超过 {shown:.0f}s 无活动，已打断。" if summary else
                           f"本回合超过 {shown:.0f}s 无活动，已打断。")
                    ).strip()
                    if not should_consult_after_exec_fault(
                        reason="hang",
                        has_active_plan=bool(supervisor.active_steer or supervisor.pending_steer),
                    ):
                        await supervisor.emit_skip(turn, reason="hang")
                        completed_turn = turn
                        await _save_hunt(completed_turn)
                        continue
            except asyncio.CancelledError:
                if agent.ctx.goal_reached:
                    goal = True
                    await emit(project_id, "status", {"status": "goal_reached", "turn": turn}, run_id=rid)
                    break
                raise
            except Exception as e:  # DSH/会话错误：记录；致命错误立刻开全新会话，避免空转打爆
                if agent.ctx.goal_reached:
                    goal = True
                    await emit(project_id, "status", {"status": "goal_reached", "turn": turn}, run_id=rid)
                    break
                msg = str(e)
                await emit(project_id, "log", {"level": "error", "message": f"本轮出错: {e}"}, run_id=rid)
                fatal = supervisor.note_exec_fault(msg)
                if fatal:
                    for it in assigned:
                        if it.get("id"):
                            try:
                                await gstore.set_intent_status(
                                    project_id, it["id"], "open",
                                    result_summary=f"exec fault retry: {msg[:120]}",
                                    run_id=rid,
                                )
                            except Exception:
                                pass
                    # 运行时已死：不要 resume 残骸；丢弃 session 后重建
                    from ..agents.session import is_dead_cli_error
                    empty_streak += 1
                    try:
                        if is_dead_cli_error(msg):
                            await emit(
                                project_id, "log",
                                {"level": "info",
                                 "message": (
                                     f"DeepSeek Harness 运行时已退出，"
                                     f"正在重建会话（第 {empty_streak} 次）…"
                                 )},
                                run_id=rid,
                            )
                            await agent.recover_dead_cli()
                            agent.set_run(rid)
                            await emit(
                                project_id, "log",
                                {"level": "info",
                                 "message": "DeepSeek Harness 已重建，继续下一轮。"},
                                run_id=rid,
                            )
                            # 退避：避免 1s 内连崩 5 次立刻熔断（与内存无关，给 CLI spawn 喘息）
                            await asyncio.sleep(min(12.0, 2.0 * empty_streak))
                        else:
                            await agent.begin_fresh_session()
                            agent.set_run(rid)
                            await emit(
                                project_id, "log",
                                {"level": "info",
                                 "message": "会话故障后已开全新 Pi（不续接旧对话）。"},
                                run_id=rid,
                            )
                            await asyncio.sleep(1.5)
                    except Exception as re:
                        await emit(project_id, "log",
                                   {"level": "warn", "message": f"会话故障后重建失败：{re}"},
                                   run_id=rid)
                        await asyncio.sleep(min(12.0, 2.0 * empty_streak))
                    if empty_streak >= 5:
                        elapsed_now = _time.monotonic() - t_start
                        halt = bool(getattr(supervisor, "halt_env", None))
                        if should_end_empty_streak(
                            empty_streak=empty_streak,
                            elapsed_sec=elapsed_now,
                            min_hunt_sec=min_hunt_sec,
                            goal_reached=bool(agent.ctx.goal_reached),
                            env_closed=halt,
                        ):
                            await supervisor.emit_skip(turn, reason="exec_fault")
                            completed_turn = turn
                            await _save_hunt(completed_turn)
                            await emit(project_id, "log",
                                       {"level": "info",
                                        "message": f"连续 {empty_streak} 次会话故障，结束本 run，交由自动重试。"},
                                       run_id=rid)
                            break
                        empty_streak = 0
                        await emit(project_id, "log",
                                   {"level": "info",
                                    "message": (
                                        f"会话故障但未满最短猎面 {int(min_hunt_sec)}s，"
                                        "重建会话继续，不关容器。"
                                    )},
                                   run_id=rid)
                        await asyncio.sleep(2.0)
                        continue
                    await supervisor.emit_skip(turn, reason="exec_fault")
                    completed_turn = turn
                    await _save_hunt(completed_turn)
                    continue
                await asyncio.sleep(1.5)

            await _sync_redteam_goal(project_id, agent, objective)
            if agent.ctx.goal_reached:
                goal = True
                await emit(project_id, "status", {"status": "goal_reached", "turn": turn}, run_id=rid)
                break

            # checkpoint：旧 stall 停跑 + AI 监督
            g2 = await gstore.get_graph(project_id)
            sig = (g2["stats"]["nodes"], g2["stats"]["edges"], g2["stats"]["findings"])
            graph_grew = False
            # 节点数增长或交旗 → 重置「无新点」墙钟（仅 nodes，不含边/finding）
            if sig[0] > last_node_count:
                last_node_count = sig[0]
                last_node_growth_mono = _time.monotonic()
                last_progress_wall = _time.time()
                graph_grew = True
            else:
                try:
                    flag_ts = await _latest_flag_event_ts(project_id)
                except Exception:
                    flag_ts = 0.0
                cmd_prog = float(getattr(getattr(agent, "ctx", None), "last_local_progress_mono", 0) or 0)
                ws_prog = False
                try:
                    ws = getattr(getattr(agent, "ctx", None), "workspace_dir", None)
                    ws_prog = workspace_has_fresh_artifact(ws, last_progress_wall)
                except Exception:
                    ws_prog = False
                local_prog = bool(cmd_prog > last_node_growth_mono or ws_prog)
                if should_reset_graph_idle(
                    node_grew=False,
                    new_flag_event=flag_ts > last_flag_event_ts,
                    local_progress=local_prog,
                ):
                    last_flag_event_ts = flag_ts
                    last_node_growth_mono = _time.monotonic()
                    last_progress_wall = _time.time()
                    graph_grew = True
            if ctf_clocks:
                idle_plans, last_counted_pivots = note_graph_idle_plans(
                    idle_plans=idle_plans,
                    pivots=int(getattr(supervisor, "pivots", 0) or 0),
                    last_counted_pivots=last_counted_pivots,
                    progressed=graph_grew,
                )
                if graph_idle_plans_due(idle_plans, graph_idle_plans_limit):
                    summary = (
                        f"攻击图已连续 {idle_plans} 个御主方案无新节点、无交旗、也无本地长计算"
                        f"（≥{graph_idle_plans_limit} 个），当前节点数 {last_node_count}，判定失败。"
                    )
                    pause_reason = "graph_idle"
                    await emit(
                        project_id, "log",
                        {"level": "info", "message": summary + "（可人工复盘后再次启动）"},
                        run_id=rid,
                    )
                    break
            open_now = await gstore.list_open_intents(project_id)
            progressed = False
            if agent.ctx.flags_correct > last_flags:
                last_flags = agent.ctx.flags_correct
                stall = 0
                progressed = True
            elif sig == last_sig and not open_now:
                stall += 1
            else:
                stall = 0
                if sig != last_sig:
                    progressed = True
            last_sig = sig
            await _evaluate_supervisor(
                supervisor=supervisor, project_id=project_id, rid=rid, turn=turn,
                graph=g2, flags=last_flags, project=project, brief=brief,
                summary=summary if isinstance(summary, str) else "",
                result=result or {}, target=target, scope=scope,
                assigned=assigned, open_intents=open_now,
                record_progress=False,
            )
            try:
                await supervisor.record_graph_progress(graph=g2, flags=last_flags)
            except Exception:
                pass
            completed_turn = turn
            await _save_hunt(completed_turn)
            from .advisor_schedule import stall_pause_due
            from ..objective import objective_allows_flag, objective_is_src
            stall_limit = int(getattr(settings, "loop_stall_limit", 10) or 0)
            if uses_ctf_hunt_clocks(objective):
                try:
                    stall_limit = int(getattr(settings, "loop_stall_limit_flag", 0) or 0)
                except (TypeError, ValueError):
                    stall_limit = 0
            elif objective == "flag":
                stall_limit = int(
                    getattr(settings, "loop_stall_limit_flag", stall_limit) or stall_limit
                )
            nprog = int(getattr(supervisor, "no_progress", 0) or 0)
            due = stall_pause_due(nprog, stall_limit)
            if due and not objective_allows_flag(objective) and not objective_is_src(objective):
                from pathlib import Path as _Path
                from .spiral import ledger_allowed_ring, load_ledger, redteam_stall_pause_due
                ws = getattr(getattr(agent, "ctx", None), "workspace_dir", None)
                if not ws:
                    ws = _Path(settings.workspaces_dir) / project_id
                due = redteam_stall_pause_due(
                    nprog, stall_limit, ledger_allowed_ring(load_ledger(ws)),
                )
            if due:
                n = int(getattr(supervisor, "no_progress", 0) or 0)
                summary = (
                    f"连续 {n} 轮无高质量进展，暂停本次 run。"
                )
                pause_reason = "stall"
                await emit(
                    project_id, "log",
                    {"level": "info", "message": summary},
                    run_id=rid,
                )
                break
            if ctf_clocks and runtime_after > 0 and supervisor.stall_class != "infra":
                elapsed_now = _time.monotonic() - t_start
                runtime_due = False
                if last_runtime_review_mono is None:
                    runtime_due = elapsed_now >= runtime_after
                elif runtime_interval > 0:
                    runtime_due = (_time.monotonic() - last_runtime_review_mono) >= runtime_interval
                if runtime_due:
                    from .advisor_schedule import assigned_still_open, unfinished_verification
                    in_flight = assigned_still_open(assigned, open_now)
                    defer_new = unfinished_verification(
                        turn=turn,
                        stall_class=supervisor.stall_class,
                        no_progress=int(getattr(supervisor, "no_progress", 0) or 0),
                        last_steer_turn=getattr(supervisor, "last_steer_turn", None),
                        hold_turns=max(0, int(getattr(settings, "advisor_hold_turns", 3) or 0)),
                        in_flight=in_flight,
                        hard_turns=int(getattr(settings, "loop_supervise_hard_turns", 10) or 10),
                    )
                    rr = await _run_runtime_review(
                        project_id=project_id, rid=rid, objective=objective,
                        graph=g2, project=project, brief=brief, turn=turn,
                        elapsed_sec=elapsed_now, target=target, supervisor=supervisor,
                    )
                    last_runtime_review_mono = _time.monotonic()
                    if rr is not None and rr.get("continue") is False:
                        mins = int(elapsed_now // 60)
                        diag = str(rr.get("diagnosis") or "").strip()
                        summary = (
                            f"御主审查建议暂停（已运行约 {mins} 分钟）"
                            + (f"：{diag[:200]}" if diag else "。")
                        )
                        pause_reason = "runtime_review_stop"
                        await emit(
                            project_id, "log",
                            {"level": "info", "message": summary + "（可人工复盘后再次启动）"},
                            run_id=rid,
                        )
                        break
                    if rr and rr.get("continue") and rr.get("next_plan"):
                        if defer_new:
                            await emit(
                                project_id, "log",
                                {"level": "info",
                                 "message": "验证未结束，御主审查只裁 continue，不改方向。"},
                                run_id=rid,
                            )
                        else:
                            extra = "【御主审查】\n" + str(rr["next_plan"]).strip()
                            if supervisor.pending_steer:
                                supervisor.pending_steer = supervisor.pending_steer + "\n" + extra
                            else:
                                supervisor.pending_steer = extra
                            supervisor.last_steer_turn = turn
        if (
            (not goal) and (not exhausted) and (not pause_reason)
            and max_turns > 0 and turn >= max_turns
        ):
            pause_reason = "turn_cap"
            summary = (
                f"本猎已达 {turn} 轮（上限 {max_turns} 轮），强制停止，记失败。"
            )
            await emit(project_id, "log", {"level": "info", "message": summary}, run_id=rid)

        # goal → completed；图空转/时长硬停 → error；入口不可达等 → idle
        proj_status = final_project_status(
            goal=goal, exhausted=exhausted, pause_reason=pause_reason,
        )
        run_status = "completed" if goal else ("error" if proj_status == "error" else "stopped")
        await _finish_run(rid, run_status, goal, turn, summary)
        await update_status(project_id, proj_status)
        try:
            proj_row = await get_project(project_id)
            if proj_row:
                cfg = dict(proj_row.get("config") or {})
                if goal:
                    cfg["completion_reason"] = "goal_reached"
                elif pause_reason:
                    cfg["completion_reason"] = pause_reason
                else:
                    cfg.pop("completion_reason", None)
                await update_config(project_id, cfg)
        except Exception:
            pass
        await emit(
            project_id, "status",
            {
                "status": run_status,
                "goal_reached": goal,
                "exhausted": exhausted,
                "turns": turn,
                "reason": pause_reason if pause_reason else None,
            },
            run_id=rid,
        )
        await _record_memory(project, project_id, goal, turn, summary, rid, applied_lesson_ids)

    except asyncio.CancelledError:
        if agent is not None and agent.ctx.goal_reached:
            goal = True
            await _finish_run(rid, "completed", True, turn, summary or "本题满分")
            await update_status(project_id, "completed")
            try:
                proj_row = await get_project(project_id)
                if proj_row:
                    cfg = dict(proj_row.get("config") or {})
                    cfg["completion_reason"] = "goal_reached"
                    await update_config(project_id, cfg)
            except Exception:
                pass
            await emit(project_id, "status",
                       {"status": "completed", "goal_reached": True, "turns": turn}, run_id=rid)
            await _record_memory(project, project_id, True, turn, summary, rid, applied_lesson_ids)
        else:
            try:
                await _save_hunt(completed_turn)
            except Exception:
                pass
            nxt = cancel_project_status(
                user_stop=bool(getattr(handle, "user_stop", False)),
                handle_status=str(getattr(handle, "status", "") or ""),
                slot_held=bool(getattr(handle, "slot_held", False)),
            )
            if nxt == "running":
                try:
                    remember_resume(project_id)
                except Exception:
                    pass
                await _finish_run(rid, "stopped", goal, turn, summary or "后端重启，将自动续跑")
                await update_status(project_id, "running")
                await emit(
                    project_id, "status",
                    {"status": "stopped", "turns": turn, "reason": "backend_restart"},
                    run_id=rid,
                )
            elif nxt == "idle":
                try:
                    forget_resume(project_id)
                except Exception:
                    pass
                await _finish_run(rid, "stopped", goal, turn, summary or "已被人工停止")
                await update_status(project_id, "idle")
                await emit(project_id, "status", {"status": "stopped", "turns": turn}, run_id=rid)
            else:
                await _finish_run(rid, "stopped", goal, turn, summary or "已被停止")
                await emit(project_id, "status", {"status": "stopped", "turns": turn}, run_id=rid)
            await _record_memory(project, project_id, goal, turn, summary, rid, applied_lesson_ids)
    except Exception as e:
        if is_benchmark and bmk.is_environment_closed_error(e):
            await _halt_closed_env(
                project=project, project_id=project_id, rid=rid, reason=f"env_closed:{e}"[:240],
            )
            await _finish_run(rid, "stopped", goal, turn, summary or f"env_closed: {e}")
            await update_status(project_id, "idle")
            await emit(project_id, "status", {"status": "stopped", "reason": "env_closed"}, run_id=rid)
        elif is_benchmark and bmk.is_transient_platform_error(e):
            await emit(
                project_id, "log",
                {"level": "info", "message": f"平台暂不可用，降级为 idle 等待重试：{e}"},
                run_id=rid,
            )
            await _finish_run(rid, "stopped", goal, turn, summary or f"platform transient: {e}")
            await update_status(project_id, "idle")
            await emit(project_id, "status", {"status": "stopped", "reason": "platform_transient"}, run_id=rid)
        elif is_transient_resource_error(e):
            await emit(
                project_id, "log",
                {"level": "warn",
                 "message": f"本机资源暂不可用（文件描述符/数据库），降级为 idle 可重试：{e}"},
                run_id=rid,
            )
            await _finish_run(rid, "stopped", goal, turn, summary or f"resource transient: {e}")
            await update_status(project_id, "idle")
            await emit(project_id, "status", {"status": "stopped", "reason": "resource_transient"}, run_id=rid)
        else:
            await emit(project_id, "log", {"level": "error", "message": f"引擎异常: {e}\n{traceback.format_exc()[:1200]}"}, run_id=rid)
            await _finish_run(rid, "error", goal, turn, summary)
            await update_status(project_id, "error")
            await emit(project_id, "status", {"status": "error"}, run_id=rid)
    finally:
        # 评测：先关容器再还槽，下一名排队者不会撞上平台「同时最多 3 道」。
        if is_benchmark:
            try:
                await bmk.close_challenge(project)
            except Exception:
                pass
        try:
            await manager.release_handle_slots(handle)
        except Exception:
            pass
        if agent is not None:
            try:
                await agent.close()
            except Exception:
                pass
        handle.status = "done"
        parent_id = (project or {}).get("parent_id") if is_benchmark else None
        if parent_id:
            asyncio.create_task(bmk.autopilot_tick(parent_id))


def _build_instruction(turn, target, graph, open_intents, steering, objective="getshell", assigned=None, brief="", postex_phase="", evolution="", peer_entries=None, entry_kind="", entry_addrs=None, entry_surface=None, lock_intents=False, has_human=False, workspace_dir="") -> str:
    from ..agents.prompts import build_turn_instruction
    return build_turn_instruction(
        turn=turn, target=target,
        graph_summary=_graph_summary(
            graph, peer_entries=peer_entries, current_entry=target, objective=objective,
            workspace_dir=workspace_dir,
        ),
        intents=_intents_text(
            open_intents, assigned=assigned or [], peer_entries=peer_entries, lock=lock_intents,
        ),
        steering=steering, objective=objective, brief=brief,
        postex_phase=postex_phase, evolution=evolution,
        entry_kind=entry_kind or "", entry_addrs=entry_addrs,
        entry_surface=entry_surface,
        lock_intents=lock_intents, has_human=has_human,
    )
