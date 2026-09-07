"""按项目暴露图工具：Streamable HTTP MCP + 本地 REST（给 DSH 运行时插件桥接）。"""
from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .context import AgentContext
from .tools import mcp_tool_defs, mcp_tool_map

router = APIRouter()

_CTX: dict[str, AgentContext] = {}
_TOOLS: dict[str, dict[str, Any]] = {}
_DEFS: dict[str, list[dict]] = {}
_SESSIONS: dict[str, str] = {}  # mcp session id -> project id


def register_project_mcp(ctx: AgentContext) -> None:
    pid = ctx.project_id
    fns = mcp_tool_map(ctx)
    _CTX[pid] = ctx
    _TOOLS[pid] = fns
    _DEFS[pid] = mcp_tool_defs(ctx)


def unregister_project_mcp(pid: str) -> None:
    _CTX.pop(pid, None)
    _TOOLS.pop(pid, None)
    _DEFS.pop(pid, None)
    for sid, p in list(_SESSIONS.items()):
        if p == pid:
            _SESSIONS.pop(sid, None)


def _rpc_result(rid: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _rpc_error(rid: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


async def _dispatch(pid: str, body: dict) -> dict | None:
    method = body.get("method")
    rid = body.get("id")
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    if method == "initialize":
        sid = uuid.uuid4().hex
        _SESSIONS[sid] = pid
        proto = params.get("protocolVersion") or "2025-03-26"
        result = {
            "protocolVersion": proto,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "atkbrain", "version": "1.0.0"},
            "_sessionId": sid,
        }
        return _rpc_result(rid, result)
    if method in ("notifications/initialized", "notifications/cancelled", "notifications/progress"):
        return None
    if method == "ping":
        return _rpc_result(rid, {})
    if method == "tools/list":
        return _rpc_result(rid, {"tools": _DEFS.get(pid) or []})
    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        fns = _TOOLS.get(pid) or {}
        fn = fns.get(name)
        if fn is None:
            return _rpc_result(rid, {
                "content": [{"type": "text", "text": f"unknown tool {name}"}],
                "isError": True,
            })
        out = await fn(args)
        content = out.get("content") if isinstance(out, dict) else [{"type": "text", "text": str(out)}]
        return _rpc_result(rid, {
            "content": content,
            "isError": bool(isinstance(out, dict) and out.get("is_error")),
        })
    if rid is not None:
        return _rpc_error(rid, -32601, f"Method not found: {method}")
    return None


def _json_headers(session_id: str | None = None) -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if session_id:
        h["Mcp-Session-Id"] = session_id
    return h


@router.api_route("/projects/{pid}/mcp", methods=["GET", "POST", "DELETE"])
@router.api_route("/projects/{pid}/mcp/{path:path}", methods=["GET", "POST", "DELETE"])
async def mcp_endpoint(pid: str, request: Request, path: str = ""):
    if pid not in _CTX:
        return JSONResponse({"detail": "project MCP not registered"}, status_code=404)
    if request.method == "DELETE":
        sid = request.headers.get("mcp-session-id") or ""
        _SESSIONS.pop(sid, None)
        return Response(status_code=204)
    if request.method == "GET":
        return JSONResponse({"ok": True, "service": "atkbrain-mcp", "project_id": pid})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"detail": "invalid json"}, status_code=400)
    messages = body if isinstance(body, list) else [body]
    replies: list[dict] = []
    session_id = request.headers.get("mcp-session-id")
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        reply = await _dispatch(pid, msg)
        if reply is None:
            continue
        result = reply.get("result") if isinstance(reply.get("result"), dict) else None
        if result and "_sessionId" in result:
            session_id = str(result.pop("_sessionId"))
        replies.append(reply)
    payload: Any = replies[0] if len(replies) == 1 else replies
    if not replies:
        return Response(status_code=202)
    return JSONResponse(payload, headers=_json_headers(session_id))


@router.get("/projects/{pid}/agent-tools")
async def list_agent_tools(pid: str):
    if pid not in _CTX:
        return JSONResponse({"detail": "project tools not registered"}, status_code=404)
    return {"tools": _DEFS[pid]}


@router.post("/projects/{pid}/agent-tools/{name}")
async def call_agent_tool(pid: str, name: str, request: Request):
    if pid not in _CTX:
        return JSONResponse({"detail": "project tools not registered"}, status_code=404)
    fn = (_TOOLS.get(pid) or {}).get(name)
    if fn is None:
        return JSONResponse({"text": f"unknown tool {name}", "is_error": True}, status_code=404)
    try:
        args = await request.json()
    except Exception:
        args = {}
    if not isinstance(args, dict):
        args = {}
    out = await fn(args)
    text = ""
    if isinstance(out, dict):
        content = out.get("content") or []
        if isinstance(content, list):
            text = "\n".join(
                str(c.get("text") or "") for c in content if isinstance(c, dict)
            )
        return {"text": text, "is_error": bool(out.get("is_error"))}
    return {"text": str(out), "is_error": False}
