"""WebSocket：实时推送攻击图/时间线事件，并接收人机协同指令（steer/start/stop）。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..config import settings
from ..engine.scheduler import manager
from ..events import bus, emit
from ..graph import store as gstore

ws_router = APIRouter()


def _ws_token_ok(ws: WebSocket) -> bool:
    """ATKBRAIN_API_TOKEN 非空时校验 query ?token= 或 Sec-WebSocket-Protocol / 头。"""
    expected = (settings.api_token or "").strip()
    if not expected:
        return True
    q = (ws.query_params.get("token") or "").strip()
    if q == expected:
        return True
    hdr = (ws.headers.get("x-api-token") or "").strip()
    if hdr == expected:
        return True
    auth = (ws.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer ") and auth[7:].strip() == expected:
        return True
    return False


@ws_router.websocket("/api/projects/{pid}/ws")
async def project_ws(ws: WebSocket, pid: str):
    if not _ws_token_ok(ws):
        await ws.close(code=4401)
        return
    await ws.accept()
    q = bus.subscribe(pid)
    try:
        graph = await gstore.get_graph(pid)
        await ws.send_json({
            "type": "snapshot",
            "payload": graph,
            "running": manager.is_running(pid),
            "queued": manager.is_queued(pid),
        })
    except Exception:
        pass

    async def sender():
        while True:
            ev = await q.get()
            await ws.send_json(ev)

    async def receiver():
        while True:
            msg = await ws.receive_json()
            mtype = msg.get("type")
            if mtype == "steer":
                content = (msg.get("content") or "").strip()
                if content:
                    ok = manager.steer(pid, content)
                    await emit(pid, "steer", {"content": content, "queued": ok, "from": "chat"})
            elif mtype == "start":
                if not manager.is_running(pid):
                    from ..projects import ensure_project_target_safe
                    from .. import benchmark as bmk
                    try:
                        await ensure_project_target_safe(pid)
                    except ValueError as e:
                        await emit(pid, "log", {"level": "error", "message": str(e)})
                        continue
                    from ..projects import get_project
                    p = await get_project(pid)
                    refuse = await bmk.gate_start_against_closed_env(p)
                    if refuse:
                        await emit(pid, "log", {"level": "warn", "message": refuse})
                        continue
                    manager.start(pid, hard_restart=bool(msg.get("confirm_restart")))
            elif mtype == "stop":
                await manager.stop(pid)
            elif mtype == "ping":
                await ws.send_json({"type": "pong"})

    send_task = asyncio.create_task(sender())
    recv_task = asyncio.create_task(receiver())
    try:
        await asyncio.wait({send_task, recv_task}, return_when=asyncio.FIRST_COMPLETED)
    except WebSocketDisconnect:
        pass
    finally:
        send_task.cancel()
        recv_task.cancel()
        bus.unsubscribe(pid, q)
