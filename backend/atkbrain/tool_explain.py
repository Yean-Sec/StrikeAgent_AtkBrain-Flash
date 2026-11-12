"""右下角说明：一条常驻、不带工具的 Pi。不发纠偏，也不停命令。"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from .db import db, _loads

_EXPLAIN_LOCK = asyncio.Lock()
_EXPLAIN_SESSION = None
_EXPLAIN_SYSTEM = (
    "你是控制台右下角的说明助手，这条 Pi 会话一直留着。\n"
    "只用下面给出的统计和记录回答，数字不要自己推测。\n"
    "问数量就先给数字。用中文两三句话，直接回答这一问。\n"
    "不要建议下一步，不要给出新的命令，不要提及其他项目。"
)


def _payload(row: dict) -> dict:
    raw = row.get("payload")
    if isinstance(raw, dict):
        return raw
    return _loads(raw) or {}


def _summary(payload: dict) -> str:
    command = str(payload.get("command") or "").strip()
    if command:
        return command[:500]
    url = str(payload.get("url") or "").strip()
    method = str(payload.get("method") or "").strip()
    if url:
        return f"{method} {url}".strip()[:500]
    return str(payload.get("tool") or "").strip()[:80]


async def open_tool(project_id: str) -> dict | None:
    from atkbrain_native import hunt_manager as manager

    if not manager.is_running(project_id):
        return None
    rows = await db.fetchall(
        "SELECT id, type, ts, payload FROM events "
        "WHERE project_id=? AND type IN ('tool', 'tool_result') "
        "ORDER BY id DESC LIMIT 80",
        (project_id,),
    )
    open_rows: list[dict] = []
    for row in reversed(rows or []):
        kind = str(row.get("type") or "")
        payload = _payload(row)
        if kind == "tool":
            open_rows.append({"ts": row.get("ts"), "payload": payload})
            continue
        if kind != "tool_result":
            continue
        name = str(payload.get("tool") or "")
        idx = -1
        for i in range(len(open_rows) - 1, -1, -1):
            if not name or str(open_rows[i]["payload"].get("tool") or "") == name:
                idx = i
                break
        if idx >= 0:
            open_rows.pop(idx)
    ctx = None
    handle = manager.get(project_id)
    agent = getattr(handle, "agent", None) if handle else None
    if agent is not None:
        ctx = getattr(agent, "ctx", None)
    inflight = int(getattr(ctx, "cmd_inflight", 0) or 0)
    if not open_rows and inflight <= 0:
        return None
    chosen = open_rows[-1]["payload"] if open_rows else {}
    ts = open_rows[-1]["ts"] if open_rows else None
    return {
        "tool": str(chosen.get("tool") or "run_cmd"),
        "command": _summary(chosen),
        "cmd_inflight": inflight if inflight > 0 else int(chosen.get("cmd_inflight") or 1),
        "ts": ts,
    }


_STATE = {
    "idle": "空闲",
    "running": "运行中",
    "done": "已结束",
    "error": "出错",
    "stopping": "正在停止",
    "queued": "排队中",
    "starting": "正在启动",
}


def plain_reply(name: str, state: str, lines: list[str]) -> str:
    """没有未结束命令时，仍用这个项目自己的状态回答，不依赖模型。"""
    title = name.strip() or "这个项目"
    last = lines[-1] if lines else "还没有执行记录"
    if state == "运行中":
        head = f"「{title}」正在运行，当前没有未结束的长时间命令。"
    elif state == "排队中":
        head = f"「{title}」在排队，命令还没开始。"
    else:
        head = f"「{title}」现在没有在跑命令，状态是{state}。"
    return f"{head}最近记录：{last}"


def _clip(value: object, limit: int = 120) -> str:
    return " ".join(str(value or "").split())[:limit]


def _recent_line(kind: str, payload: dict) -> str:
    if kind == "tool":
        return f"开始 {_clip(payload.get('tool') or '工具', 40)}：{_summary(payload)[:120]}"
    if kind == "tool_result":
        err = _clip(payload.get("error"), 80)
        base = f"结束 {_clip(payload.get('tool') or '工具', 40)}"
        return f"{base}，出错：{err}" if err else base
    if kind == "text":
        return f"说明：{_clip(payload.get('text'), 120)}"
    if kind in ("log", "thought"):
        return f"记录：{_clip(payload.get('message'), 120)}"
    if kind == "shell":
        return "记录：会话状态有更新"
    return ""


async def project_glance(project_id: str) -> dict:
    """只读这一个项目的状态和最近记录。"""
    from atkbrain_native import hunt_manager as manager

    row = await db.fetchone(
        "SELECT name, status FROM projects WHERE id=?",
        (project_id,),
    )
    if not row:
        return {"missing": True, "name": "", "state": "", "lines": []}
    if manager.is_running(project_id):
        state = "运行中"
    elif manager.is_queued(project_id):
        state = "排队中"
    else:
        raw = str(row.get("status") or "idle")
        state = _STATE.get(raw, raw)
    rows = await db.fetchall(
        "SELECT type, payload FROM events WHERE project_id=? ORDER BY id DESC LIMIT 12",
        (project_id,),
    )
    lines: list[str] = []
    for item in reversed(rows or []):
        text = _recent_line(str(item.get("type") or ""), _payload(item))
        if text:
            lines.append(text)
    return {
        "missing": False,
        "name": str(row.get("name") or ""),
        "state": state,
        "lines": lines[-8:],
    }


async def _explain_session():
    """控制台只有一个操作员，说明助手共用这一条不带工具的 Pi。"""
    global _EXPLAIN_SESSION
    from atkbrain_native import PiSession
    from .config import settings

    current = _EXPLAIN_SESSION
    if current is not None and current.alive():
        return current
    if current is not None:
        try:
            await asyncio.to_thread(current.close)
        except Exception:
            pass
        _EXPLAIN_SESSION = None
    work = Path(settings.data_dir) / "explain-pi"
    os.makedirs(work, exist_ok=True)
    sess = PiSession(
        cwd=str(work),
        system_prompt=_EXPLAIN_SYSTEM,
        project_id="",
        role="console-explain",
        tools=False,
    )
    await asyncio.to_thread(sess.start)
    _EXPLAIN_SESSION = sess
    return sess


async def _ask_resident(prompt: str) -> str:
    async with _EXPLAIN_LOCK:
        try:
            sess = await _explain_session()
            text = await asyncio.to_thread(sess.prompt, prompt, 180)
        except Exception as first:
            global _EXPLAIN_SESSION
            old = _EXPLAIN_SESSION
            _EXPLAIN_SESSION = None
            if old is not None:
                try:
                    await asyncio.to_thread(old.close)
                except Exception:
                    pass
            try:
                sess = await _explain_session()
                text = await asyncio.to_thread(sess.prompt, prompt, 180)
            except Exception as second:
                raise RuntimeError(str(second or first)[:240] or "说明助手没有启动") from second
        reply = str(text or "").strip()
        if not reply:
            raise RuntimeError("模型没有返回说明。")
        return reply


async def project_facts(project_id: str) -> str:
    """这一页能核对的数量。说明助手只能引用这些数字。"""
    row = await db.fetchone("SELECT name, status FROM projects WHERE id=?", (project_id,))
    if not row:
        return ""
    findings = await db.fetchall(
        "SELECT title, severity, verification_status, secondary_verified FROM findings WHERE project_id=?",
        (project_id,),
    ) or []
    nodes = await db.fetchone("SELECT COUNT(*) AS n FROM nodes WHERE project_id=?", (project_id,))
    node_n = int((nodes or {}).get("n") or 0)
    total = len(findings)
    secondary = sum(1 for item in findings if int(item.get("secondary_verified") or 0))
    pending = sum(1 for item in findings if str(item.get("verification_status") or "") == "pending")
    excluded = sum(1 for item in findings if str(item.get("verification_status") or "") == "excluded")
    by_sev: dict[str, int] = {}
    titles: list[str] = []
    for item in findings:
        sev = str(item.get("severity") or "info")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        title = " ".join(str(item.get("title") or "").split())
        if title:
            titles.append(title[:80])
    sev_text = "、".join(f"{name} {count}" for name, count in sorted(by_sev.items())) or "无"
    title_text = "；".join(titles[:12]) or "无"
    from atkbrain_native import hunt_manager as manager
    if manager.is_running(project_id):
        run_state = "运行中"
    elif manager.is_queued(project_id):
        run_state = "排队中"
    else:
        run_state = str(row.get("status") or "idle")
    return (
        f"项目：{row.get('name') or project_id}\n"
        f"运行：{run_state}\n"
        f"图上节点：{node_n}\n"
        f"漏洞库条目：{total}\n"
        f"其中已二次验证：{secondary}，待验证：{pending}，二次验证失败：{excluded}\n"
        f"严重级别：{sev_text}\n"
        f"漏洞标题：{title_text}"
    )


async def explain(
    project_id: str,
    question: str,
    command: str,
    output: str,
    *,
    page: str = "",
    path: str = "",
) -> str:
    ask = (question or "").strip()
    if not ask:
        raise ValueError("需要一个问题")
    parts = [f"页面：{(page or path or '当前页')[:120]}"]
    if path:
        parts.append(f"路径：{path[:180]}")
    shown_command = (command or "").strip()
    if project_id:
        facts = await project_facts(project_id)
        if not facts:
            return "当前页面上的这个项目不存在。"
        parts.append(facts)
        running = await open_tool(project_id)
        if running is None and shown_command:
            running = {"tool": "run_cmd", "command": shown_command}
        if running is not None:
            shown = shown_command or running.get("command") or running.get("tool")
            parts.append(f"未结束命令：{running.get('tool') or 'run_cmd'} {str(shown)[:500]}")
            snippet = (output or "").strip()[:800]
            if snippet:
                parts.append(f"最近输出：\n{snippet}")
        else:
            parts.append("当前没有未结束的长时间命令。")
    else:
        parts.append("这一页没有项目里的长时间命令。")
    parts.append(f"问题：{ask[:800]}")
    return await _ask_resident("\n\n".join(parts))
