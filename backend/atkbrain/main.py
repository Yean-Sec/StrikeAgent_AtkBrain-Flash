"""FastAPI 入口：装配数据库、路由、WebSocket、静态前端。"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api.routes import router as api_router
from .api.ws import ws_router
from .config import REPO_ROOT, settings
from .db import db, now


def _raise_nofile_limit() -> None:
    """systemd 默认 soft nofile=1024，20 项目×普通 Claude 会 EMFILE 打挂 SQLite。"""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = 1048576
        if hard not in (-1, resource.RLIM_INFINITY) and hard > 0:
            want = min(want, hard)
        if soft < want:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
            print(f"[startup] RLIMIT_NOFILE {soft} → {want} (hard={hard})")
    except Exception as e:
        print(f"[startup] 提升 RLIMIT_NOFILE 失败：{e}")


def _extract_api_token(request: Request) -> str:
    """从 X-API-Token / Authorization: Bearer / ?token= 取令牌。"""
    h = (request.headers.get("x-api-token") or "").strip()
    if h:
        return h
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.query_params.get("token") or "").strip()


async def _benchmark_autopilot_loop():
    from .db import db as _db
    first = True
    while True:
        try:
            if not first:
                await asyncio.sleep(settings.benchmark_autopilot_interval_sec)
            first = False
            if not settings.benchmark_autopilot:
                continue
            from . import benchmark as bmk
            parents = await _db.fetchall("SELECT id FROM projects WHERE kind='benchmark'")
            for p in parents or []:
                try:
                    await bmk.autopilot_tick(p["id"])
                except Exception as e:
                    print(f"[autopilot] {p.get('id')}: {e}")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            print(f"[autopilot] loop: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    _raise_nofile_limit()
    await db.connect()
    # 崩溃/重启后：runs 表孤儿行无法继续，先收口。项目 status=running 先记下来再续跑，
    # 不要一上来全部改 idle，否则 systemd 重启会把进行中的猎丢掉。
    db_running = [
        str(r["id"])
        for r in await db.fetchall(
            "SELECT id FROM projects WHERE status='running' ORDER BY updated_at DESC"
        )
    ]
    await db.execute("UPDATE runs SET status='stopped', ended_at=? WHERE status='running'", (now(),))
    try:
        from .projects import unstick_transient_resource_errors
        n = await unstick_transient_resource_errors()
        if n:
            print(f"[startup] 已将 {n} 个资源抖动误标 error 的项目改回 idle")
    except Exception as e:
        print(f"[startup] 解开资源误标失败，跳过：{e}")
    try:
        from .projects import reclassify_hunt_failures
        n = await reclassify_hunt_failures()
        if n:
            print(f"[startup] 已将 {n} 个图空转/硬停项目改记失败")
    except Exception as e:
        print(f"[startup] 图空转/硬停改记失败跳过：{e}")
    if (settings.api_token or "").strip():
        print("[startup] API Token 鉴权已启用（ATKBRAIN_API_TOKEN 非空；不打印令牌）")
    try:
        from .hosted import ensure_hosted_benchmark
        await ensure_hosted_benchmark()
    except Exception as e:
        print(f"[startup] hosted 自动建评测项目失败：{e}")
    try:
        from .engine.hunt_resume import start_saved_hunts
        from .engine.scheduler import manager as _run_manager
        resumed = await start_saved_hunts(_run_manager, db_running)
        if resumed:
            print(f"[startup] 续跑重启前在跑的 {len(resumed)} 个项目（红队≤{_run_manager.redteam_sem.limit} / CTF≤{_run_manager.ctf_sem.limit}）")
        elif db_running:
            print("[startup] 重启前有 running 记录但均不可续跑，已改回空闲")
    except Exception as e:
        print(f"[startup] 续跑重启前项目失败，跳过：{e}")
        try:
            await db.execute(
                "UPDATE projects SET status='idle', updated_at=? WHERE status='running'",
                (now(),),
            )
        except Exception:
            pass
    autopilot_task = asyncio.create_task(_benchmark_autopilot_loop())
    yield
    autopilot_task.cancel()
    try:
        from .engine.hunt_resume import save_resume_ids
        from .engine.scheduler import manager as _run_manager
        _run_manager.shutting_down = True
        live = list((_run_manager.snapshot().get("running") or []))
        if live:
            save_resume_ids(live)
            print(f"[shutdown] 记下 {len(live)} 个在跑项目，下次启动续跑")
        await _run_manager.checkpoint_for_shutdown(timeout=8.0)
    except Exception as e:
        print(f"[shutdown] 记录续跑清单失败：{e}")
    await db.close()


app = FastAPI(title="StrikeAgent_AtkBrain-Flash", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_token_middleware(request: Request, call_next):
    """ATKBRAIN_API_TOKEN 非空时强制鉴权；放行 /api/health 与非 /api 静态资源。"""
    expected = (settings.api_token or "").strip()
    if not expected:
        return await call_next(request)
    path = request.url.path or ""
    if path == "/api/health" or not path.startswith("/api"):
        return await call_next(request)
    # WebSocket 升级由 ws 端点自行校验，避免中间件吞掉 upgrade
    if (request.headers.get("upgrade") or "").lower() == "websocket":
        return await call_next(request)
    got = _extract_api_token(request)
    if got != expected:
        return JSONResponse({"detail": "Unauthorized：需要有效 API Token"}, status_code=401)
    return await call_next(request)


app.include_router(api_router)
app.include_router(ws_router)

# 生产：若前端已构建，则托管静态资源
_FRONT_DIST = os.path.join(str(REPO_ROOT), "frontend", "dist")
if os.path.isdir(_FRONT_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(_FRONT_DIST, "assets")), name="assets")

    @app.get("/")
    async def _index():
        # index.html 不缓存：后端/前端更新后浏览器总能拿到最新版（避免缓存旧版导致“列表混乱/点错项目”）。
        return FileResponse(os.path.join(_FRONT_DIST, "index.html"),
                            headers={"Cache-Control": "no-cache, must-revalidate"})

    @app.get("/{full_path:path}")
    async def _spa(full_path: str):
        # SPA 回退（非 /api 路径都回 index.html）
        target = os.path.join(_FRONT_DIST, full_path)
        if os.path.isfile(target):
            return FileResponse(target)  # 带哈希的静态资源可长期缓存
        return FileResponse(os.path.join(_FRONT_DIST, "index.html"),
                            headers={"Cache-Control": "no-cache, must-revalidate"})
else:
    @app.get("/")
    async def _root():
        return {"service": "StrikeAgent_AtkBrain-Flash", "docs": "/docs", "hint": "前端开发模式请运行 frontend (vite)"}


def main() -> None:
    uvicorn.run("atkbrain.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    main()
