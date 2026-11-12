"""本机 Pi 扩展调用的工具接口。不是 MCP。"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .context import AgentContext, tool_caller_role
from .tools import mcp_tool_defs, mcp_tool_map

router = APIRouter()

_CTX: dict[str, AgentContext] = {}
_TOOLS: dict[str, dict[str, Any]] = {}
_DEFS: dict[str, list[dict]] = {}
_LOCK = threading.Lock()


def register_project_tools(ctx: AgentContext) -> None:
    pid = ctx.project_id
    with _LOCK:
        _CTX[pid] = ctx
        _TOOLS[pid] = mcp_tool_map(ctx)
        _DEFS[pid] = mcp_tool_defs(ctx)


def unregister_project_tools(pid: str) -> None:
    with _LOCK:
        _CTX.pop(pid, None)
        _TOOLS.pop(pid, None)
        _DEFS.pop(pid, None)


def _open_context(pid: str) -> AgentContext | None:
    import atkbrain_native as gstore
    from atkbrain_native import Guard, Scope, normalize_objective

    from ..config import settings

    project = gstore.get_project(pid)
    if not project:
        return None
    cfg = project.get("config") if isinstance(project.get("config"), dict) else {}
    scope_raw = dict(project.get("scope") or {}) if isinstance(project.get("scope"), dict) else {}
    host = str(project.get("target") or "").strip()
    targets = [str(x) for x in (scope_raw.get("targets") or []) if str(x).strip()]
    if host and host not in targets:
        targets.append(host)
    scope_raw["targets"] = targets
    scope = Scope.from_dict(scope_raw)
    objective = normalize_objective(str(cfg.get("objective") or cfg.get("track") or ""))
    workspace = Path(settings.workspaces_dir) / pid
    loot = workspace / "loot"
    workspace.mkdir(parents=True, exist_ok=True)
    loot.mkdir(parents=True, exist_ok=True)
    guard = Guard(scope, objective=objective)
    guard.workspace_dir = str(workspace)
    primary = None
    ports = project.get("ports")
    if isinstance(ports, list) and ports:
        try:
            primary = int(ports[0])
        except (TypeError, ValueError):
            primary = None
    guard.primary_port = primary
    try:
        flags_needed = int(cfg.get("flag_count") or 1)
    except (TypeError, ValueError):
        flags_needed = 1

    async def abort() -> None:
        try:
            from atkbrain_native import hunt_manager as mgr
            mgr.halt(pid, "goal")
        except Exception:
            pass

    return AgentContext(
        project_id=pid,
        workspace_dir=str(workspace),
        loot_dir=str(loot),
        scope=scope,
        guard=guard,
        objective=objective,
        project=project,
        flags_needed=max(1, flags_needed),
        primary_port=primary,
        abort_run=abort,
    )


def ensure_project_tools(pid: str) -> bool:
    """Pi 扩展在进程起来时就拉工具表。猎面线程未必先登记，这里按项目现补。"""
    with _LOCK:
        if pid in _CTX:
            return True
    ctx = _open_context(pid)
    if ctx is None:
        return False
    register_project_tools(ctx)
    return True


@router.get("/projects/{pid}/agent-tools")
async def list_agent_tools(pid: str):
    if not ensure_project_tools(pid):
        return JSONResponse({"detail": "project tools not registered"}, status_code=404)
    return {"tools": list(_DEFS.get(pid) or [])}


@router.post("/projects/{pid}/agent-tools/{name}")
async def call_agent_tool(pid: str, name: str, request: Request):
    if not ensure_project_tools(pid):
        return JSONResponse({"detail": "project tools not registered"}, status_code=404)
    role = (request.headers.get("x-atkbrain-role") or "").strip().lower()
    # 猎面停了也要让专职复核把没做完的二次验证打完。工人通道仍然关掉。
    reviewing = role == "finding-review" or role.startswith("finding-review:")
    try:
        from atkbrain_native import hunt_manager as _mgr
        if not reviewing and not _mgr.is_running(pid) and not _mgr.is_queued(pid):
            return JSONResponse(
                {"text": "hunt stopped", "is_error": True}, status_code=409,
            )
    except Exception:
        pass
    if role == "lead" and name in ("http_request", "http_fuzzer", "web_crawler"):
        return {
            "text": "从者不要自己打 HTTP，交给工人 src-hunt/web-exploit/recon。你只计划、写图与汇总。",
            "is_error": True,
        }
    fn = (_TOOLS.get(pid) or {}).get(name)
    try:
        args = await request.json()
    except Exception:
        args = {}
    if not isinstance(args, dict):
        args = {}
    if fn is None:
        return JSONResponse({"text": f"unknown tool {name}", "is_error": True}, status_code=404)
    from .context import tool_caller_role
    role_token = tool_caller_role.set(role)
    try:
        out = await fn(args)
    finally:
        tool_caller_role.reset(role_token)
    text = ""
    if isinstance(out, dict):
        content = out.get("content") or []
        if isinstance(content, list):
            text = "\n".join(
                str(c.get("text") or "") for c in content if isinstance(c, dict)
            )
        return {"text": text, "is_error": bool(out.get("is_error"))}
    return {"text": str(out), "is_error": False}
