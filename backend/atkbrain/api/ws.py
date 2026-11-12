"""WebSocket：实时推送攻击图/时间线事件，并接收人机协同指令（steer/start/stop）。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from atkbrain_native import hunt_manager as manager
from ..events import bus, emit
import atkbrain_native as gstore

ws_router = APIRouter()


async def _ws_token_ok(ws: WebSocket) -> bool:
    from ..auth.gate import auth_ok
    return await auth_ok(ws)


@ws_router.websocket("/api/projects/{pid}/ws")
async def project_ws(ws: WebSocket, pid: str):
    if not await _ws_token_ok(ws):
        await ws.close(code=4401)
        return
    from ..auth.gate import session_from_request, session_must_change
    sess = await session_from_request(ws)
    if session_must_change(sess):
        await ws.close(code=4403)
        return
    await ws.accept()
    q = bus.subscribe(pid)
    try:
        graph = gstore.get_graph(pid)
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
                    from atkbrain_native import ensure_project_target_safe
                    from .. import benchmark as bmk
                    try:
                        ensure_project_target_safe(pid)
                    except ValueError as e:
                        await emit(pid, "log", {"level": "error", "message": str(e)})
                        continue
                    from atkbrain_native import get_project
                    p = get_project(pid)
                    refuse = await bmk.gate_start_against_closed_env(p)
                    if refuse:
                        await emit(pid, "log", {"level": "warn", "message": refuse})
                        continue
                    from atkbrain_native import llm_api_key_configured, llm_key_missing_message
                    if not llm_api_key_configured():
                        await emit(pid, "log", {"level": "error", "message": llm_key_missing_message()})
                        continue
                    manager.start(pid, hard_restart=bool(msg.get("confirm_restart")))
            elif mtype == "stop":
                manager.halt(pid)
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
