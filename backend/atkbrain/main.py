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
from .auth.routes import router as auth_router
from .config import REPO_ROOT, settings
from .db import db, now
from .app_version import local_version
from atkbrain_native import locale_from_request, set_locale


def _raise_nofile_limit() -> None:
    """systemd 默认 soft nofile=1024，多项目并发 Pi 会 EMFILE 打挂 SQLite。"""
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
    try:
        from atkbrain_native import ensure_pi_agent_dir
        ensure_pi_agent_dir()
    except Exception as e:
        print(f"[startup] 写入 Pi 配置失败：{e}")
    try:
        from atkbrain_native import apply_hunt_clocks_to_settings
        apply_hunt_clocks_to_settings()
    except Exception as e:
        print(f"[startup] 猎面撞墙钟读取失败：{e}")
    await db.connect()
    try:
        from .auth.bootstrap import bootstrap_admin
        await bootstrap_admin()
    except Exception as e:
        print(f"[startup] 管理员引导失败：{e}")
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
        from atkbrain_native import unstick_transient_resource_errors
        n = unstick_transient_resource_errors()
        if n:
            print(f"[startup] 已将 {n} 个资源抖动误标 error 的项目改回 idle")
    except Exception as e:
        print(f"[startup] 解开资源误标失败，跳过：{e}")
    try:
        from atkbrain_native import reclassify_hunt_failures
        n = reclassify_hunt_failures()
        if n:
            print(f"[startup] 已将 {n} 个图空转/硬停项目改记失败")
    except Exception as e:
        print(f"[startup] 图空转/硬停改记失败跳过：{e}")
    if (settings.api_token or "").strip():
        print("[startup] API Token 鉴权已启用（ATKBRAIN_API_TOKEN 非空；不打印令牌）")
    try:
        from .auth.entry import load_or_create_entry, public_console_url
        load_or_create_entry()
        print(f"[startup] 控制台 {public_console_url()}")
        print("[startup] 忘入口或首登后口令：python -m atkbrain.panel")
    except Exception as e:
        print(f"[startup] 安全入口打印失败：{e}")
    try:
        from atkbrain_native import CREDS_MODE
        print(f"[startup] creds_mode={CREDS_MODE}（只摘录已出现账密，不合成厂商默认口令）")
    except Exception as e:
        print(f"[startup] creds_mode 打印失败：{e}")
    try:
        from .hosted import ensure_hosted_benchmark
        await ensure_hosted_benchmark()
    except Exception as e:
        print(f"[startup] hosted 自动建评测项目失败：{e}")
    try:
        from atkbrain_native import hunt_manager as _run_manager
        resumed = _run_manager.start_saved_hunts(db_running)
        queued_n = _run_manager.resume_queued()
        if queued_n:
            print(f"[startup] 按提交顺序恢复 {queued_n} 个排队项目")
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
    try:
        from .review.jobs import resume_pending_reviews
        asyncio.create_task(resume_pending_reviews())
    except Exception as e:
        print(f"[startup] 续做未完成复核失败：{e}")
    try:
        from .report.claude_export import resume_interrupted_exports
        n_export = resume_interrupted_exports()
        if n_export:
            print(f"[startup] 续做 {n_export} 个被重启打断的交付报告")
    except Exception as e:
        print(f"[startup] 续做交付报告失败：{e}")
    try:
        from .proxy.pool import pool as _proxy_pool
        _proxy_pool.ensure_loop()
    except Exception as e:
        print(f"[startup] 代理池后台任务失败：{e}")
    yield
    autopilot_task.cancel()
    try:
        from atkbrain_native import hunt_manager as _run_manager
        _run_manager.shutting_down = True
        live = list((_run_manager.snapshot().get("running") or []))
        if live:
            print(f"[shutdown] 记下 {len(live)} 个在跑项目，下次启动续跑")
        _run_manager.checkpoint_for_shutdown(timeout=8.0)
    except Exception as e:
        print(f"[shutdown] 记录续跑清单失败：{e}")
    await db.close()


app = FastAPI(
    title="StrikeAgent_AtkBrain-Flash",
    version=local_version(),
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_cors = [x.strip() for x in str(getattr(settings, "cors_origins", "") or "").split(",") if x.strip()]
_pub = str(getattr(settings, "public_origin", "") or "").strip().rstrip("/")
if _pub and _pub not in _cors:
    _cors.append(_pub)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors or ["http://127.0.0.1:2334", "http://localhost:2334"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def locale_middleware(request: Request, call_next):
    set_locale(locale_from_request(request))
    return await call_next(request)


@app.middleware("http")
async def api_auth_middleware(request: Request, call_next):
    """会话 Cookie 或 API Token。auth 公开接口精确白名单。"""
    set_locale(locale_from_request(request))
    path = request.url.path or ""
    if (request.headers.get("upgrade") or "").lower() == "websocket":
        return await call_next(request)
    from .auth.bootstrap import env_no_auth, login_required
    from .auth.cookies import apply_session_cookie
    from .auth.entry import is_loopback_peer, peer_host
    from .auth.gate import (
        api_token_ok,
        auth_public_path,
        must_change_path_allowed,
        session_from_request,
        session_must_change,
    )
    loopback = is_loopback_peer(peer_host(request))
    if path == "/api/health" and loopback:
        return await call_next(request)
    if loopback and "/agent-tools" in path:
        return await call_next(request)
    if auth_public_path(path) or not path.startswith("/api"):
        return await call_next(request)
    if env_no_auth():
        return await call_next(request)
    sess = await session_from_request(request)
    if sess:
        if session_must_change(sess) and not must_change_path_allowed(path):
            return JSONResponse({"detail": "password-change-required"}, status_code=403)
        response = await call_next(request)
        row = sess.get("session") or {}
        try:
            exp = float(row.get("expires_at") or 0)
        except (TypeError, ValueError):
            exp = 0.0
        apply_session_cookie(
            response,
            str(sess.get("token") or ""),
            request,
            expires_at=exp or None,
        )
        return response
    if await api_token_ok(request):
        return await call_next(request)
    if not await login_required():
        expected = (settings.api_token or "").strip()
        if not expected:
            return await call_next(request)
        return JSONResponse({"detail": "Unauthorized：需要有效 API Token"}, status_code=401)
    return JSONResponse({"detail": "login-required"}, status_code=401)


app.include_router(auth_router)
app.include_router(api_router)
app.include_router(ws_router)

from .auth.entry import SecurityEntryMiddleware, entry_prefix

# 入口伪装页。再外包一层公网 HTTP→HTTPS（最后注册最先跑）。
app.add_middleware(SecurityEntryMiddleware)


@app.middleware("http")
async def force_https_middleware(request: Request, call_next):
    """公网 HTTP 301 到 HTTPS。本机回环与已是 https（含 X-Forwarded-Proto）不跳。"""
    if (request.headers.get("upgrade") or "").lower() == "websocket":
        return await call_next(request)
    from .auth.https_redirect import https_redirect_response
    bounced = https_redirect_response(request)
    if bounced is not None:
        return bounced
    return await call_next(request)

# 生产：若前端已构建，则托管静态资源
_FRONT_DIST = os.path.join(str(REPO_ROOT), "frontend", "dist")


def _inject_index_html() -> str:
    raw = open(os.path.join(_FRONT_DIST, "index.html"), encoding="utf-8").read()
    prefix = entry_prefix()
    base = prefix or ""
    snippet = (
        f'<base href="{base}/">'
        f'<script>window.__ATKBRAIN_BASE__="{base}";</script>'
        if base else
        '<script>window.__ATKBRAIN_BASE__="";</script>'
    )
    if "<head>" in raw:
        return raw.replace("<head>", "<head>" + snippet, 1)
    return snippet + raw


def _spa_index():
    from fastapi.responses import HTMLResponse
    return HTMLResponse(
        _inject_index_html(),
        headers={"Cache-Control": "no-cache, must-revalidate"},
    )


if os.path.isdir(_FRONT_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(_FRONT_DIST, "assets")), name="assets")

    @app.get("/")
    async def _index():
        return _spa_index()

    @app.get("/{full_path:path}")
    async def _spa(full_path: str):
        target = os.path.join(_FRONT_DIST, full_path)
        if os.path.isfile(target):
            return FileResponse(target)
        return _spa_index()
else:
    @app.get("/")
    async def _root():
        from fastapi.responses import HTMLResponse
        return HTMLResponse("", headers={"Cache-Control": "no-store"})


def main() -> None:
    uvicorn.run(
        "atkbrain.main:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
