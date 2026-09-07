"""事件总线：自循环引擎/智能体产生的事件的唯一出口。

一处调用 emit() 即完成两件事：
1) 持久化到 events 表（供回放/报告）；
2) 发布到内存 pub/sub（供 WebSocket 实时推送到前端攻击图与对话窗口）。
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any

from .db import db, new_id, now, _dumps


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, project_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs[project_id].add(q)
        return q

    def unsubscribe(self, project_id: str, q: asyncio.Queue) -> None:
        self._subs[project_id].discard(q)

    def publish(self, project_id: str, event: dict) -> None:
        for q in list(self._subs.get(project_id, ())):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # 慢消费者：丢弃最旧一条再放入，保证实时性
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except Exception:
                    pass


bus = EventBus()


async def emit(
    project_id: str,
    type: str,
    payload: dict | None = None,
    run_id: str | None = None,
    persist: bool = True,
) -> dict:
    """记录并广播一个事件。"""
    ev = {
        "id": new_id("ev_"),
        "project_id": project_id,
        "run_id": run_id,
        "ts": now(),
        "type": type,
        "payload": payload or {},
    }
    if persist:
        try:
            await db.execute(
                "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?,?,?,?,?)",
                (project_id, run_id, ev["ts"], type, _dumps(payload or {})),
            )
        except Exception:
            # 事件持久化失败不应阻断主流程
            pass
    bus.publish(project_id, ev)
    return ev
