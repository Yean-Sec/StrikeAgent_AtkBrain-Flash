"""REST 路由：项目、攻击图、运行控制、报告、PoC、设置。"""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from ..i18n.locale import get_locale, normalize_locale
from ..i18n.strings import msg
from ..config import settings
from ..db import db, _loads
from ..engine.scheduler import _task_is_cancelling, manager
from ..graph import store as gstore
from ..project_status import displayed_status, hunt_hard_stop_info
from ..app_version import check_latest, local_payload, local_version, normalize_ver
from ..upgrade import live_hunt_ids, start_upgrade
from ..projects import (
    assert_safe_project_target,
    create_benchmark_project,
    create_cluster_project,
    create_single_project,
    delete_project,
    delete_projects,
    get_project,
    list_child_ids,
    list_projects,
    rename_project,
    update_config,
)
from ..report import generator as report_gen
from ..report import claude_export as report_export
from ..report.finding_report import (
    is_reportable_finding,
    prepare_finding_report,
    render_finding_markdown,
    serialize_finding_full,
)
from ..report.poc import poc_for_finding
from .. import cluster as cluster_mod
from .. import benchmark as bmk
from ..agents.mcp_http import router as mcp_router


def _project_http_target(p: dict | None) -> str:
    target = (p or {}).get("target") or ""
    if target and not str(target).startswith("http"):
        ports = (p or {}).get("ports") or []
        target = "http://" + str(target) + (f":{ports[0]}" if ports else "")
    return str(target)


async def _load_reportable_finding(pid: str, fid: str) -> tuple[dict, dict | None, dict]:
    """加载 finding + 关联节点；rejected / 不存在则 404。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    row = await db.fetchone("SELECT * FROM findings WHERE id=? AND project_id=?", (fid, pid))
    if not row:
        raise HTTPException(404, msg("finding_missing"))
    if not is_reportable_finding(row):
        raise HTTPException(404, msg("finding_rejected"))
    related = None
    related_edges: list[dict] = []
    if row["node_key"]:
        nrow = await db.fetchone(
            "SELECT key, type, title, detail, severity, risk_score, tags FROM nodes "
            "WHERE project_id=? AND key=?",
            (pid, row["node_key"]),
        )
        if nrow:
            related = {
                "key": nrow["key"], "type": nrow["type"], "title": nrow["title"],
                "detail": nrow["detail"] if isinstance(nrow["detail"], str) else None,
                "severity": nrow["severity"], "risk_score": nrow["risk_score"],
                "tags": _loads(nrow["tags"]) or [],
            }
        erows = await db.fetchall(
            "SELECT src, dst, relation, rationale FROM edges "
            "WHERE project_id=? AND (src=? OR dst=?)",
            (pid, row["node_key"], row["node_key"]),
        )
        for e in erows or []:
            related_edges.append({
                "from": e["src"], "to": e["dst"],
                "relation": e["relation"], "rationale": e["rationale"],
            })
    finding = serialize_finding_full(row, related_node=related, related_edges=related_edges)
    return finding, p, related

router = APIRouter(prefix="/api")
router.include_router(mcp_router)


def _require_llm_key() -> None:
    from ..agents.pi_runtime import llm_api_key_configured
    if not llm_api_key_configured():
        raise HTTPException(400, msg("llm_key_missing"))


async def _require_llm_key_for(pid: str) -> None:
    from ..agents.pi_runtime import llm_api_key_configured
    if llm_api_key_configured():
        return
    from ..events import emit
    await emit(pid, "log", {"level": "error", "message": msg("llm_key_missing")})
    raise HTTPException(400, msg("llm_key_missing"))


class CreateProjectReq(BaseModel):
    kind: str = "single"
    name: str = ""
    target: str | None = None
    ports: list[int] | None = None
    allow_subdomains: bool = False
    mode: str = "strict"
    model: str | None = None
    assets: list[str] | None = None
    track: str | None = None             # 赛道：redteam | ctf | src
    objective: str = "getshell"          # 目标类型：redteam(旧值 getshell) | flag | src
    base_url: str | None = None          # benchmark 平台基址
    token: str | None = None             # BENCHMARK_TOKEN
    auth_user: str | None = None         # 授权测试账号（红队/蓝队）；不与评测 token 混用
    auth_password: str | None = None
    auth_token: str | None = None        # Bearer / JWT / API key / Cookie 原文
    output_lang: str | None = None       # zh | en；猎面人可见输出语言


class OutputLangReq(BaseModel):
    output_lang: str = "zh"


class PreviewAssetsReq(BaseModel):
    assets: list[str] | str | None = None
    track: str | None = None
    objective: str | None = None


class SteerReq(BaseModel):
    message: str


class RenameProjectReq(BaseModel):
    name: str


class ConcurrencyReq(BaseModel):
    value: int
    track: str | None = None  # redteam | ctf；缺省按红队，避免旧客户端改到 CTF 槽


class BatchDeleteReq(BaseModel):
    ids: list[str]

class BatchRunReq(BaseModel):
    ids: list[str]
    confirm_restart: bool = False


class ProxyEnableReq(BaseModel):
    enabled: bool


class ProxyPoolReq(BaseModel):
    custom_text: str = ""


class PiModelsReq(BaseModel):
    text: str = ""


class LlmProfileReq(BaseModel):
    format: str = "openai"
    model: str = ""
    base_url: str = ""
    api_key: str = ""


class ReviewFlagsReq(BaseModel):
    secondary_verify: bool | None = None
    redteam_rating: bool | None = None


class HuntClocksReq(BaseModel):
    loop_max_turns: int | None = None
    loop_max_turns_src: int | None = None
    loop_max_turns_redteam: int | None = None
    src_runtime_hard_stop_sec: int | None = None
    redteam_runtime_hard_stop_sec: int | None = None
    runtime_hard_stop_sec: int | None = None
    runtime_hard_stop_pass2_sec: int | None = None
    runtime_hard_stop_pass3_sec: int | None = None
    runtime_hard_stop_pass_step_sec: int | None = None
    graph_idle_empty_plans: int | None = None
    loop_stall_limit_redteam: int | None = None
    loop_stall_limit_src: int | None = None


class FindingReviewReq(BaseModel):
    mode: str


def _proxy_snap() -> dict:
    from ..proxy.pool import pool
    snap = pool.snapshot()
    snap.pop("custom_text", None)
    return snap


async def _stop_project_tree(pid: str) -> list[str]:
    """先停子项目再停自身，返回实际被 stop 的 id 列表。同级子树并行停，避免 400 个子项目串行卡死。"""
    child_ids = await list_child_ids(pid)
    nested: list = []
    if child_ids:
        nested = await asyncio.gather(
            *(_stop_project_tree(cid) for cid in child_ids),
            return_exceptions=True,
        )
    stopped: list[str] = []
    for group in nested:
        if isinstance(group, BaseException):
            continue
        stopped.extend(group)
    await manager.halt(pid)
    stopped.append(pid)
    return stopped


async def _set_benchmark_autopilot(pid: str, enabled: bool) -> None:
    p = await get_project(pid)
    if not p or p.get("kind") != "benchmark":
        return
    cfg = dict(p.get("config") or {})
    if bool(cfg.get("autopilot", True)) == bool(enabled):
        return
    cfg["autopilot"] = bool(enabled)
    await update_config(pid, cfg)


@router.get("/health")
async def health(request: Request):
    import shutil
    import subprocess

    from ..agents.pi_runtime import pi_bin
    from ..auth.entry import is_loopback_peer, peer_host
    from ..auth.gate import auth_ok

    if not await auth_ok(request):
        if is_loopback_peer(peer_host(request)):
            return {"ok": True}
        raise HTTPException(401, "login-required")

    from ..agents.pi_runtime import llm_api_key_configured

    bin_path = shutil.which(pi_bin()) or shutil.which("pi")
    try:
        if not llm_api_key_configured():
            raise RuntimeError("llm_key_missing")
        if not bin_path:
            raise FileNotFoundError("pi not found in PATH")
        ver = subprocess.check_output(
            [bin_path, "--version"], timeout=8, text=True, stderr=subprocess.STDOUT,
        ).strip()
        claude_sdk = {"state": "ready", "label": "Pi 就绪", "version": ver[:80], "bin": bin_path}
    except Exception as exc:
        if str(exc) == "llm_key_missing":
            claude_sdk = {"state": "unavailable", "label": "未配置大模型密钥", "error": "DEEPSEEK_API_KEY missing"}
        else:
            claude_sdk = {"state": "unavailable", "label": "Pi 不可用", "error": str(exc)[:160]}
    from ..agents.brief_creds import CREDS_MODE
    return {
        "ok": True,
        "version": local_version(),
        "creds_mode": CREDS_MODE,
        "claude_sdk": claude_sdk,
        "proxy": _proxy_snap(),
        **manager.snapshot(),
    }


@router.get("/version")
async def get_version(refresh: bool = False):
    try:
        return check_latest(force=bool(refresh))
    except Exception:
        return local_payload()


@router.post("/version/apply")
async def apply_version(request: Request):
    from ..auth.gate import origin_ok

    if not origin_ok(request):
        raise HTTPException(status_code=403, detail="origin")
    payload = check_latest(force=True)
    if payload.get("status") != "update_available":
        return {**payload, "ok": True, "started": False, "already_latest": True}
    live = live_hunt_ids()
    if live:
        return JSONResponse(
            {
                "detail": "hunts-live",
                "code": "hunts_live",
                "running": live,
                "ok": False,
                "started": False,
            },
            status_code=409,
        )
    tag = str(payload.get("latest_tag") or payload.get("latest") or "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="no-release-tag")
    try:
        log_path = start_upgrade(tag)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="upgrade-script-missing")
    except ValueError:
        raise HTTPException(status_code=400, detail="illegal-tag")
    return {
        **payload,
        "ok": True,
        "started": True,
        "already_latest": False,
        "tag": tag,
        "target": normalize_ver(tag),
        "log": str(log_path),
    }


@router.get("/settings")
async def get_settings():
    from ..agents.pi_runtime import console_model, role_model
    return {
        "concurrency": manager.snapshot(),
        "proxy": _proxy_snap(),
        "defaults": {
            "model": console_model(),
            "supervisor_model": role_model(getattr(settings, "supervisor_model", None)),
            "evolve_ai": bool(getattr(settings, "evolve_ai", True)),
            "loop_max_turns": settings.loop_max_turns,
            "hard_stop": {
                "src": hunt_hard_stop_info("src"),
                "redteam": hunt_hard_stop_info("redteam"),
                "flag": hunt_hard_stop_info("flag"),
            },
            "hunt_clocks": _hunt_clocks(),
        },
        "review": _review_flags(),
    }


def _review_flags() -> dict:
    from ..review.flags import get_review_flags
    return get_review_flags()


def _hunt_clocks() -> dict:
    from ..engine.hunt_clock_settings import get_hunt_clocks
    return get_hunt_clocks()


@router.post("/settings/review")
async def set_review_flags(req: ReviewFlagsReq):
    from ..review.flags import set_review_flags as _set
    flags = _set(secondary_verify=req.secondary_verify, redteam_rating=req.redteam_rating)
    return {"review": flags}


@router.post("/settings/hunt-clocks")
async def set_hunt_clocks(req: HuntClocksReq):
    from ..engine.hunt_clock_settings import set_hunt_clocks as _set
    clocks = _set(req.model_dump(exclude_none=True))
    return {
        "hunt_clocks": clocks,
        "hard_stop": {
            "src": hunt_hard_stop_info("src"),
            "redteam": hunt_hard_stop_info("redteam"),
            "flag": hunt_hard_stop_info("flag"),
        },
    }


@router.post("/settings/concurrency")
async def set_concurrency(req: ConcurrencyReq):
    """按赛道设置项目并发；顶栏只闸项目槽。"""
    val = await manager.set_concurrency(req.value, track=req.track or "redteam")
    snap = manager.snapshot()
    return {
        "concurrency_limit": snap["concurrency_limit"],
        "cap": snap["cap"],
        "track": "ctf" if str(req.track or "").strip().lower() in ("ctf", "flag", "benchmark") else "redteam",
        "value": val,
        "redteam": snap["redteam"],
        "ctf": snap["ctf"],
        "claude": snap["claude"],
    }


@router.get("/proxy/status")
async def api_proxy_status():
    return _proxy_snap()


@router.post("/proxy/enabled")
async def api_proxy_enabled(req: ProxyEnableReq):
    from ..proxy.pool import pool
    return await pool.set_enabled(bool(req.enabled))


@router.get("/proxy/pool")
async def api_proxy_pool_get():
    from ..proxy.pool import pool
    return pool.snapshot()


@router.post("/proxy/pool")
async def api_proxy_pool_set(req: ProxyPoolReq):
    from ..proxy.pool import pool
    return await pool.set_custom_text(req.custom_text or "")


@router.post("/proxy/verify")
async def api_proxy_verify():
    from ..proxy.pool import pool
    return await pool.verify()


@router.get("/settings/pi-models")
async def api_pi_models_get():
    from ..agents.pi_runtime import pi_models_text
    return {"text": pi_models_text()}


@router.post("/settings/pi-models")
async def api_pi_models_set(req: PiModelsReq):
    from ..agents.pi_runtime import save_pi_models_text
    try:
        save_pi_models_text(req.text or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "text": req.text or ""}


@router.get("/settings/llm")
async def api_llm_profile():
    from ..agents.pi_runtime import llm_profile
    return llm_profile()


@router.post("/settings/llm")
async def api_llm_profile_set(req: LlmProfileReq):
    from ..agents.pi_runtime import save_llm_profile
    try:
        view = save_llm_profile(
            fmt=req.format,
            model=req.model,
            base_url=req.base_url,
            api_key=req.api_key,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, **view}


@router.post("/settings/llm/test")
async def api_llm_profile_test(req: LlmProfileReq):
    from ..agents.pi_runtime import probe_llm
    return await probe_llm(
        fmt=req.format,
        model=req.model,
        base_url=req.base_url,
        api_key=req.api_key,
    )


def _slim_list_config(cfg: dict | None) -> dict:
    """列表页只需展示用字段；剥掉 assets 等大块。"""
    c = cfg or {}
    out: dict = {
        "objective": c.get("objective"),
        "track": c.get("track"),
        "completion_reason": c.get("completion_reason"),
        "env_closed": bool(c.get("env_closed")) or None,
        "env_closed_reason": c.get("env_closed_reason"),
        "vhosts": c.get("vhosts") if isinstance(c.get("vhosts"), list) else None,
        "output_lang": c.get("output_lang") or None,
    }
    if isinstance(c.get("benchmark"), dict):
        out["benchmark"] = {"base_url": (c.get("benchmark") or {}).get("base_url")}
        if c.get("autopilot") is not None:
            out["autopilot"] = c.get("autopilot")
    return {k: v for k, v in out.items() if v is not None}


def _trim_event_payload(payload: dict | None, limit: int = 400) -> dict:
    """时间线只需预览；截断超长 stdout/text，显著减小长跑项目初次加载体积。"""
    if not isinstance(payload, dict):
        return {}
    out: dict = {}
    for k, v in payload.items():
        if isinstance(v, str) and len(v) > limit:
            out[k] = v[:limit] + "…"
        elif isinstance(v, dict):
            # 浅层截断嵌套字符串
            nested = {}
            for nk, nv in v.items():
                nested[nk] = (nv[:limit] + "…") if isinstance(nv, str) and len(nv) > limit else nv
            out[k] = nested
        else:
            out[k] = v
    return out


@router.get("/projects")
async def api_list_projects():
    projs = await list_projects()
    parent_ids = [p["id"] for p in projs]
    child_rows = []
    if parent_ids:
        marks = ",".join("?" * len(parent_ids))
        child_rows = await db.fetchall(
            f"SELECT id, parent_id FROM projects WHERE parent_id IN ({marks})",
            tuple(parent_ids),
        )
    child_ids_by_parent: dict[str, list[str]] = {pid: [] for pid in parent_ids}
    for row in child_rows:
        child_ids_by_parent.setdefault(row["parent_id"], []).append(row["id"])
    stats_map = await gstore.get_stats_batch(parent_ids + [r["id"] for r in child_rows])

    def rollup(items: list[dict]) -> dict:
        if not items:
            return {}
        total = {
            "nodes": 0, "services": 0, "edges": 0, "findings": 0, "high": 0, "medium": 0, "low": 0, "critical": 0,
            "pivot_edges": 0, "hosts_footed": 0, "frontier_open": 0, "frontier_strategies": 0,
            "has_shell": False, "lateral_active": False, "mass_data_leak": False,
        }
        for item in items:
            for key in ("nodes", "services", "edges", "findings", "high", "medium", "low", "critical", "pivot_edges", "hosts_footed", "frontier_open", "frontier_strategies"):
                total[key] += int(item.get(key) or 0)
            for key in ("has_shell", "lateral_active", "mass_data_leak"):
                total[key] = bool(total[key] or item.get(key))
        return total

    out = []
    for p in projs:
        child_ids = child_ids_by_parent.get(p["id"], [])
        is_parent = p["kind"] in ("cluster", "benchmark")
        child_stats = [stats_map.get(cid) or {} for cid in child_ids]
        stats = rollup(child_stats) if is_parent else (stats_map.get(p["id"]) or {})
        slim = {**p, "config": _slim_list_config(p.get("config")),
                "stats": stats,
                "running": (any(manager.is_running(cid) for cid in child_ids) if is_parent else manager.is_running(p["id"]))}
        slim["queued"] = (
            any(manager.is_queued(cid) for cid in child_ids) if is_parent else manager.is_queued(p["id"])
        )
        slim["status"] = displayed_status(
            p.get("status"), running=bool(slim["running"]), queued=bool(slim["queued"]),
        )
        out.append(slim)
    return out


def _resolve_track_objective(track: str | None, objective: str | None) -> tuple[str, str]:
    """把二级赛道 track（优先）与旧字段 objective 归一为 (track, objective)。
    track ∈ {redteam, ctf, src}；objective ∈ {redteam, flag, src}。
    """
    t = (track or "").strip().lower()
    o = (objective or "").strip().lower()
    if o == "getshell":
        o = "redteam"
    if t not in ("redteam", "ctf", "src"):
        t = {"flag": "ctf", "src": "src"}.get(o, "redteam")
    obj = {"redteam": "redteam", "ctf": "flag", "src": "src"}[t]
    return t, obj


@router.post("/projects")
async def api_create_project(req: CreateProjectReq):
    track, objective = _resolve_track_objective(req.track, req.objective)
    cfg: dict = {
        "track": track,
        "objective": objective,
        "output_lang": normalize_locale(req.output_lang or get_locale()),
    }
    if req.model:
        cfg["model"] = req.model
    if track in ("redteam", "src"):
        from ..agents.brief_creds import normalize_supplied_auth
        supplied = normalize_supplied_auth({
            "user": req.auth_user,
            "password": req.auth_password,
            "token": req.auth_token,
        })
        if supplied:
            cfg["supplied_auth"] = supplied
    try:
        if req.kind == "cluster" and track == "ctf" and req.base_url and req.token:
            cfg["track"] = "ctf"
            cfg["objective"] = "flag"
            proj = await create_benchmark_project(req.name or "benchmark", req.base_url, req.token, cfg)
        elif req.kind == "cluster" and track == "src" and req.base_url and req.token:
            cfg["track"] = "src"
            cfg["objective"] = "src"
            proj = await create_benchmark_project(req.name or "benchmark", req.base_url, req.token, cfg)
        elif req.kind == "benchmark":
            if not req.base_url or not req.token:
                raise HTTPException(400, "评测项目需要提供 base_url 与 token")
            if track == "src":
                cfg["track"] = "src"
                cfg["objective"] = "src"
            else:
                cfg["track"] = "ctf"
                cfg["objective"] = "flag"
            proj = await create_benchmark_project(req.name or "benchmark", req.base_url, req.token, cfg)
        elif req.kind == "cluster":
            if not req.assets:
                raise HTTPException(400, "集群项目需要提供资产列表 assets")
            proj = await create_cluster_project(req.name or "cluster", req.assets, cfg)
            assets = (proj.get("config") or {}).get("assets") or req.assets
            hosts, _ = cluster_mod._hosts_from_assets(assets)
            job = cluster_mod.schedule_cluster_import(
                proj["id"], auto_start=True, total_hint=len(hosts),
            )
            proj = {**proj, "importing": True, "import_progress": job, "auto_started": []}
        elif req.kind == "single":
            if not req.target:
                raise HTTPException(400, "单目标项目需要提供 target（域名或 IP）")
            proj = await create_single_project(
                req.name, req.target, req.ports,
                allow_subdomains=False, mode=req.mode, config=cfg,
            )
        else:
            raise HTTPException(400, "kind 仅支持 single|cluster|benchmark")
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return proj


@router.post("/projects/assets/preview")
async def api_preview_assets(req: PreviewAssetsReq):
    """集群导入前预览分组：SRC=产品域，红队=同机。不做 DNS。"""
    assets = req.assets
    if assets is None:
        raise HTTPException(400, "需要提供资产列表 assets")
    return cluster_mod.preview_asset_groups(assets, track=req.track, objective=req.objective)


@router.get("/projects/{pid}")
async def api_get_project(pid: str):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    # 评测/集群父项目不跑攻击图
    if p["kind"] in ("benchmark", "cluster"):
        cfg = dict(p.get("config") or {})
        cfg.pop("challenges", None)
        if p["kind"] == "benchmark":
            cfg.pop("assets", None)
        return {
            **p, "config": cfg, "graph": None,
            "running": False, "run_id": None,
        }
    g = await gstore.get_graph(pid)
    h = manager.get(pid)
    running = manager.is_running(pid)
    queued = manager.is_queued(pid)
    return {
        **p, "graph": g,
        "status": displayed_status(p.get("status"), running=running, queued=queued),
        "running": running,
        "queued": queued,
        "run_id": (h.run_id if h else None),
    }


@router.post("/projects/batch_delete")
async def api_batch_delete_projects(req: BatchDeleteReq):
    """批量删除顶层（或任意）项目：先停整棵子树，再级联清库。"""
    ids = [str(x).strip() for x in (req.ids or []) if str(x).strip()]
    if not ids:
        raise HTTPException(400, "ids 不能为空")
    stopped: list[str] = []
    for pid in dict.fromkeys(ids):  # 保序去重
        stopped.extend(await _stop_project_tree(pid))
    result = await delete_projects(ids)
    return {"ok": True, **result, "stopped": stopped}


@router.post("/projects/batch_stop")
async def api_batch_stop_projects(req: BatchRunReq):
    """跨项目批量暂停；集群项目递归暂停所有子项目。单条失败不让整批 500。"""
    stopped: list[str] = []
    missing: list[str] = []
    failed: list[dict] = []
    ids = [str(x).strip() for x in (req.ids or []) if str(x).strip()]
    if not ids:
        raise HTTPException(400, "ids 不能为空")
    for pid in dict.fromkeys(ids):
        try:
            if not await get_project(pid):
                missing.append(pid)
                continue
            stopped.extend(await _stop_project_tree(pid))
        except asyncio.CancelledError:
            failed.append({"id": pid, "error": "cancelled"})
            if _task_is_cancelling():
                raise
        except Exception as e:
            failed.append({"id": pid, "error": str(e)[:200] or type(e).__name__})
    return {"ok": True, "stopped": stopped, "missing": missing, "failed": failed}


@router.post("/projects/batch_start")
async def api_batch_start_projects(req: BatchRunReq):
    """跨项目批量启动；父项目展开为直属子项目进入调度器。"""
    _require_llm_key()
    started: list[str] = []
    skipped: list[dict] = []
    missing: list[str] = []
    for pid in dict.fromkeys(str(x).strip() for x in req.ids if str(x).strip()):
        project = await get_project(pid)
        if not project:
            missing.append(pid)
            continue
        target_ids = await list_child_ids(pid) if project["kind"] in ("cluster", "benchmark") else [pid]
        for target_id in target_ids:
            child = await get_project(target_id)
            if not child:
                continue
            if manager.is_running(target_id):
                skipped.append({"id": target_id, "reason": "already_running"})
                continue
            refuse = await bmk.gate_start_against_closed_env(child)
            if refuse:
                skipped.append({"id": target_id, "reason": "env_closed"})
                continue
            manager.start(target_id, hard_restart=bool(req.confirm_restart and bmk.is_benchmark_sub(child)))
            started.append(target_id)
    return {"ok": True, "started": started, "skipped": skipped, "missing": missing}


@router.delete("/projects/{pid}")
async def api_delete_project(pid: str):
    if not await get_project(pid):
        raise HTTPException(404, msg("project_missing"))
    stopped = await _stop_project_tree(pid)
    await delete_project(pid)
    return {"ok": True, "stopped": stopped}


@router.patch("/projects/{pid}/output_lang")
async def api_set_output_lang(pid: str, req: OutputLangReq):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    cfg = dict(p.get("config") or {})
    cfg["output_lang"] = normalize_locale(req.output_lang)
    await update_config(pid, cfg)
    return {"ok": True, "output_lang": cfg["output_lang"]}


@router.post("/projects/{pid}/start")
async def api_start(pid: str, confirm_restart: bool = Query(False)):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] in ("cluster", "benchmark"):
        raise HTTPException(400, "父项目不直接运行；请对其子项目单独或批量启动。")
    await _require_llm_key_for(pid)
    refuse = await bmk.gate_start_against_closed_env(p)
    if refuse:
        raise HTTPException(400, refuse)
    tgt = (p.get("target") or "").strip()
    if tgt and not bmk.is_benchmark_sub(p):
        try:
            assert_safe_project_target(tgt)
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
    if manager.is_running(pid):
        return {"ok": True, "already": True}
    hard = bool(confirm_restart)
    manager.start(pid, hard_restart=hard)
    return {"ok": True, "resume": not hard, "restart": hard}


@router.post("/projects/{pid}/stop")
async def api_stop(pid: str):
    await manager.halt(pid)
    return {"ok": True}


@router.patch("/projects/{pid}")
async def api_rename_project(pid: str, req: RenameProjectReq):
    """修改项目名称（集群会同步子项目「集群名 · host」前缀）。"""
    if not await get_project(pid):
        raise HTTPException(404, msg("project_missing"))
    try:
        return await rename_project(pid, req.name)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/projects/{pid}/steer")
async def api_steer(pid: str, req: SteerReq):
    from ..events import emit
    if not manager.is_running(pid):
        raise HTTPException(400, "项目未在运行，无法注入指令；请先启动。")
    ok = manager.steer(pid, req.message)
    await emit(pid, "steer", {"content": req.message, "queued": ok})
    return {"ok": ok}


@router.get("/projects/{pid}/graph")
async def api_graph(pid: str):
    return await gstore.get_graph(pid)


_PINNED_EVENT_TYPES = ("steer", "drift_alert", "supervisor", "finding_review", "report_export")


async def fetch_project_event_rows(pid: str, after: int = 0):
    """时间线事件：最近窗口 + 对话类保底 + 纠偏/自监督钉住（不被 tool 洪水挤掉）。"""
    if after > 0:
        return await db.fetchall(
            "SELECT * FROM events WHERE project_id=? AND id>? ORDER BY id ASC LIMIT 800",
            (pid, after),
        )
    recent = await db.fetchall(
        """SELECT * FROM (
             SELECT * FROM events WHERE project_id=? ORDER BY id DESC LIMIT 800
           ) t ORDER BY id ASC""",
        (pid,),
    )
    chatty = await db.fetchall(
        """SELECT * FROM (
             SELECT * FROM events
             WHERE project_id=?
               AND type IN ('text','shell','lateral','status','thought','finding','log','finding_review','report_export')
             ORDER BY id DESC LIMIT 500
           ) t ORDER BY id ASC""",
        (pid,),
    )
    pinned_types = ",".join(f"'{t}'" for t in _PINNED_EVENT_TYPES)
    pinned = await db.fetchall(
        f"""SELECT * FROM events
           WHERE project_id=? AND type IN ({pinned_types})
           ORDER BY id ASC LIMIT 2000""",
        (pid,),
    )
    by_id: dict[int, dict] = {}
    for r in list(recent) + list(chatty) + list(pinned):
        by_id[int(r["id"])] = r
    return [by_id[i] for i in sorted(by_id)]


@router.get("/projects/{pid}/events")
async def api_events(pid: str, after: int = Query(0)):
    rows = await fetch_project_event_rows(pid, after)
    return [
        {"id": r["id"], "type": r["type"], "ts": r["ts"], "run_id": r["run_id"],
         "payload": _trim_event_payload(_loads(r["payload"]))}
        for r in rows
    ]


@router.get("/projects/{pid}/runs")
async def api_runs(pid: str):
    return await db.fetchall("SELECT * FROM runs WHERE project_id=? ORDER BY started_at DESC", (pid,))


@router.get("/projects/{pid}/report")
async def api_report(pid: str, format: str = Query("html"), lang: str | None = Query(None)):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    fmt = (format or "html").lower()
    loc = normalize_locale(lang or get_locale())
    if fmt == "md":
        raise HTTPException(status_code=410, detail=msg("md_gone"))
    from ..report.pdf_print import html_to_pdf
    from ..report.slots import assemble_deliverable, cache_stem, facts_digest
    data = await report_gen.build_report_data(pid)
    digest = facts_digest(data)
    cached = settings.reports_dir / f"{cache_stem(pid, digest, loc)}.html"
    if cached.exists() and cached.stat().st_size > 200:
        html = cached.read_text(encoding="utf-8")
    else:
        html = assemble_deliverable(data, lang=loc)
        settings.reports_dir.mkdir(parents=True, exist_ok=True)
        cached.write_text(html, encoding="utf-8")
    if fmt == "html":
        return Response(html, media_type="text/html; charset=utf-8")
    if fmt == "pdf":
        try:
            pdf = html_to_pdf(html)
        except RuntimeError as e:
            raise HTTPException(503, str(e))
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="report-{pid}.pdf"'})
    raise HTTPException(400, msg("format_html_pdf"))


@router.post("/projects/{pid}/report/export")
async def api_report_export_start(
    pid: str, format: str = Query("html"), lang: str | None = Query(None),
):
    """启动母版填槽报告任务，返回进度可轮询的 job。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    fmt = (format or "html").lower()
    loc = normalize_locale(lang or get_locale())
    if fmt == "md":
        raise HTTPException(status_code=410, detail=msg("md_gone"))
    try:
        return await report_export.start_export_job(pid, format, force=True, lang=loc)
    except report_export.ProjectReportMdGone as e:
        raise HTTPException(status_code=410, detail=str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.get("/projects/{pid}/report/export/{jid}")
async def api_report_export_status(pid: str, jid: str):
    job = report_export.get_export_job(pid, jid)
    if not job:
        raise HTTPException(404, msg("export_missing"))
    return job


@router.get("/projects/{pid}/report/export/{jid}/file")
async def api_report_export_file(pid: str, jid: str):
    job = report_export.get_export_job(pid, jid)
    if not job:
        raise HTTPException(404, msg("export_missing"))
    if job["status"] != "done":
        raise HTTPException(409, job.get("message") or msg("export_not_ready"))
    path = report_export.export_file_path(jid, pid)
    if not path or not path.exists():
        raise HTTPException(404, msg("export_file_missing"))
    fmt = job.get("format") or "html"
    media = {
        "html": "text/html; charset=utf-8",
        "md": "text/markdown; charset=utf-8",
        "pdf": "application/pdf",
    }.get(fmt, "application/octet-stream")
    disp = "inline" if fmt == "html" else "attachment"
    name = job.get("filename") or path.name
    return Response(
        path.read_bytes(),
        media_type=media,
        headers={"Content-Disposition": report_export.content_disposition(disp, str(name))},
    )


@router.post("/projects/{pid}/triage")
async def api_triage(pid: str):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "cluster":
        raise HTTPException(400, "仅集群项目支持存活快筛与子项目划分")
    return await cluster_mod.triage_cluster(pid)


@router.post("/projects/{pid}/refold_machines")
async def api_refold_machines(pid: str):
    """按同 FQDN / 同 DNS IP 折叠 idle/error 子项目。不自动开跑。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "cluster":
        raise HTTPException(400, "仅集群项目支持按同机折叠")
    result = await cluster_mod.refold_cluster_by_machine(pid)
    if result.get("error"):
        raise HTTPException(400, result["error"])
    return result


@router.get("/projects/{pid}/subprojects")
async def api_subprojects(pid: str):
    # 只用轻量 stats，禁止对每个子项目 get_graph
    subs = await cluster_mod.list_subprojects(pid)
    stats_map = await gstore.get_stats_batch([s["id"] for s in subs])
    out = []
    for s in subs:
        out.append({
            **s,
            "stats": stats_map.get(s["id"]) or {},
            "running": manager.is_running(s["id"]),
            # starting=已点启动但还在等并发槽；UI 显示「排队中」，勿计入「运行中」
            "queued": manager.is_queued(s["id"]),
            "config": _slim_list_config(s.get("config")),
        })
    return out


class AddClusterAssetsReq(BaseModel):
    assets: list[str]
    auto_start: bool = True


@router.post("/projects/{pid}/assets")
async def api_add_cluster_assets(pid: str, req: AddClusterAssetsReq):
    """集群内新增资产：写入资产列表、按 host 补建子项目，默认立即启动新子项目。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "cluster":
        raise HTTPException(400, "仅集群项目支持追加资产")
    result = await cluster_mod.add_assets_to_cluster(pid, req.assets or [])
    if result.get("error") and not result.get("subprojects") and not result.get("added") and not result.get("importing"):
        raise HTTPException(400, result["error"])
    project = await get_project(pid)
    prog = result.get("import_progress")
    if not isinstance(prog, dict):
        prog = {}
    return {**result, "started": prog.get("started") or [], "project": project}


@router.get("/projects/{pid}/import_progress")
async def api_import_progress(pid: str):
    """集群批量导入进度（创建/追加资产时轮询）。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    return await cluster_mod.import_progress_for(pid)


@router.post("/projects/{pid}/import_pause")
async def api_import_pause(pid: str):
    """暂停集群导入：不再新建子项目，已建的保持原状。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "cluster":
        raise HTTPException(400, "仅集群项目支持暂停导入")
    return await cluster_mod.pause_cluster_import(pid)


@router.post("/projects/{pid}/import_resume")
async def api_import_resume(pid: str):
    """继续导入：补建尚未划分子项目的主机。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "cluster":
        raise HTTPException(400, "仅集群项目支持继续导入")
    return cluster_mod.resume_cluster_import(pid, auto_start=True)


@router.post("/projects/{pid}/start_all")
async def api_start_all(
    pid: str,
    confirm_restart: bool = Query(False),
    unfinished_only: bool = Query(False),
):
    """批量启动子项目。默认续跑（保留攻击图）；confirm_restart=1 才清图重开。

    unfinished_only=1 时跳过已完成子项目。
    """
    parent = await get_project(pid)
    if not parent:
        raise HTTPException(404, msg("project_missing"))
    if parent["kind"] not in ("cluster", "benchmark"):
        raise HTTPException(400, "仅集群/评测项目支持全部启动")
    _require_llm_key()
    refuse = await bmk.gate_start_against_closed_env(parent)
    if refuse:
        raise HTTPException(400, refuse)
    await _set_benchmark_autopilot(pid, True)
    if parent["kind"] == "benchmark" and not confirm_restart:
        tick = await bmk.autopilot_tick(pid)
        picked = list(tick.get("picked") or [])
        return {
            "started": picked,
            "count": int(tick.get("started") or 0),
            "unfinished_only": unfinished_only,
            "scheduled": True,
            "skipped_need_confirm": [],
            "skipped_unsafe": [],
            "skipped_completed": [],
            "skipped_deferred": [],
        }
    subs = await cluster_mod.list_subprojects(pid)
    started = []
    skipped_need_confirm = []
    skipped_unsafe = []
    skipped_completed = []
    skipped_deferred = []
    completed_ids = await bmk._completed_sub_ids(subs) if unfinished_only else set()
    for s in subs:
        if unfinished_only and s["id"] in completed_ids:
            skipped_completed.append({"id": s["id"], "name": s.get("name")})
            continue
        if manager.is_running(s["id"]):
            continue
        if await bmk.gate_start_against_closed_env(s):
            continue
        tgt = (s.get("target") or "").strip()
        if tgt and not bmk.is_benchmark_sub(s):
            try:
                assert_safe_project_target(tgt)
            except ValueError as e:
                skipped_unsafe.append({"id": s["id"], "target": tgt, "reason": str(e)})
                continue
        manager.start(s["id"], hard_restart=bool(confirm_restart))
        started.append(s["id"])
    return {
        "started": started,
        "count": len(started),
        "unfinished_only": unfinished_only,
        "skipped_need_confirm": skipped_need_confirm,
        "skipped_unsafe": skipped_unsafe,
        "skipped_completed": skipped_completed,
        "skipped_deferred": skipped_deferred,
    }


@router.post("/projects/{pid}/stop_all")
async def api_stop_all(pid: str):
    """批量暂停运行中/排队的子项目。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] not in ("cluster", "benchmark"):
        raise HTTPException(400, "仅集群/评测项目支持全部暂停")
    await _set_benchmark_autopilot(pid, False)
    stopped: list[str] = []
    for _ in range(2):
        ids = [s["id"] for s in await cluster_mod.list_subprojects(pid) if manager.is_running(s["id"])]
        if not ids:
            break
        await asyncio.gather(*(manager.halt(sid) for sid in ids), return_exceptions=True)
        stopped.extend(ids)
    uniq = list(dict.fromkeys(stopped))
    return {"stopped": uniq, "count": len(uniq), "autopilot": False if p["kind"] == "benchmark" else None}


# ---- Benchmark（CTF 评测）----------------------------------------------------

@router.post("/projects/{pid}/benchmark/import")
async def api_bm_import(pid: str):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    if p["kind"] != "benchmark":
        raise HTTPException(400, "非 benchmark 项目")
    try:
        return await bmk.import_challenges(pid)
    except bmk.BenchmarkError as e:
        raise HTTPException(502, f"[{e.code}] {e.message}")


@router.get("/projects/{pid}/benchmark/scoreboard")
async def api_bm_scoreboard(pid: str):
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    return await bmk.scoreboard(pid)


@router.get("/projects/{pid}/flags")
async def api_flags(pid: str):
    rows = await db.fetchall(
        "SELECT * FROM flags WHERE project_id=? ORDER BY created_at DESC", (pid,)
    )
    return rows


def _serialize_memory(r: dict) -> dict:
    return {
        "id": r["id"], "project_id": r["project_id"], "target_fp": r["target_fp"],
        "version": r["version"], "kind": r["kind"], "outcome": r["outcome"],
        "tags": _loads(r["tags"]) or [], "content": _loads(r["content"]),
        "created_at": r["created_at"],
    }


@router.get("/projects/{pid}/memory")
async def api_project_memory(pid: str):
    """返回项目 episode 与匹配的跨局剧本。"""
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    episodes = await db.fetchall(
        """SELECT * FROM memory WHERE project_id=? AND kind='episode'
           ORDER BY created_at DESC LIMIT 20""",
        (pid,),
    )
    playbook = []
    try:
        from ..memory.evolve import retrieve_lessons
        graph = await gstore.get_graph(pid)
        playbook = await retrieve_lessons(p, graph, limit=12, bump_uses=False)
    except Exception:
        playbook = []
    return {
        "episodes": [_serialize_memory(r) for r in episodes],
        "playbook": playbook,
    }


@router.get("/memory")
async def api_memory(limit: int = Query(100)):
    rows = await db.fetchall("SELECT * FROM memory ORDER BY created_at DESC LIMIT ?", (limit,))
    return [_serialize_memory(r) for r in rows]


@router.get("/findings")
async def api_library_findings(
    q: str = "",
    project: str = "",
    category: str = "",
    severity: str = "",
    track: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=1, le=100),
):
    return await gstore.list_library_findings(
        q=q, project=project, category=category, severity=severity, track=track,
        page=page, page_size=page_size,
    )


@router.get("/review-jobs/{job_id}")
async def api_review_job(job_id: str):
    from ..review.jobs import snapshot
    job = snapshot(job_id)
    if not job:
        raise HTTPException(404, msg("review_job_missing"))
    return job


@router.post("/projects/{pid}/findings/{fid}/review")
async def api_finding_review(pid: str, fid: str, req: FindingReviewReq):
    from ..graph.verify import is_visible_finding
    from ..review.jobs import ReviewBusy, start_manual

    mode = str(req.mode or "").strip().lower()
    if mode not in ("secondary", "rating"):
        raise HTTPException(400, msg("review_mode"))
    p = await get_project(pid)
    if not p:
        raise HTTPException(404, msg("project_missing"))
    row = await db.fetchone("SELECT * FROM findings WHERE id=? AND project_id=?", (fid, pid))
    if not row or not is_visible_finding(row):
        raise HTTPException(404, msg("finding_missing"))
    finding = gstore._serialize_finding(row)
    finding["project_id"] = pid
    try:
        return start_manual(p, finding, mode)
    except ReviewBusy as e:
        raise HTTPException(409, str(e) or msg("review_busy"))


@router.get("/projects/{pid}/findings/{fid}")
async def api_finding_detail(pid: str, fid: str):
    """单漏洞全量详情（不截断），供漏洞弹层。非 rejected 均可查看。"""
    finding, p, _related = await _load_reportable_finding(pid, fid)
    target = _project_http_target(p)
    poc = poc_for_finding(finding, target)
    finding = prepare_finding_report(finding, poc=poc)
    finding["poc"] = poc
    if finding.get("report_state") == "writing":
        from ..report.pi_finding_page import schedule_pi_page
        schedule_pi_page(pid, fid)
    return finding


@router.get("/projects/{pid}/findings/{fid}/report")
async def api_finding_report(pid: str, fid: str, format: str = Query("md"), lang: str | None = Query(None)):
    """单漏洞报告下载。目前仅支持 Markdown。"""
    if format != "md":
        raise HTTPException(400, msg("format_md"))
    loc = normalize_locale(lang or get_locale())
    finding, p, _related = await _load_reportable_finding(pid, fid)
    target = _project_http_target(p)
    poc = poc_for_finding(finding, target)
    body = render_finding_markdown(p, finding, poc=poc, lang=loc)
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in fid)[:48]
    return Response(
        body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="finding-{safe}.md"'},
    )


@router.get("/projects/{pid}/findings/{fid}/poc")
async def api_poc(pid: str, fid: str):
    p = await get_project(pid)
    row = await db.fetchone("SELECT * FROM findings WHERE id=? AND project_id=?", (fid, pid))
    if not row:
        raise HTTPException(404, msg("finding_missing"))
    finding = {
        "category": row["category"], "title": row["title"], "evidence": row["evidence"],
        "poc_curl": row["poc_curl"], "poc_python": row["poc_python"],
        "severity": row["severity"],
        "proof_canary": row["proof_canary"] if "proof_canary" in row.keys() else None,
        "proof_url": row["proof_url"] if "proof_url" in row.keys() else None,
        "proof_detail": row["proof_detail"] if "proof_detail" in row.keys() else None,
        "verification_status": row["verification_status"] if "verification_status" in row.keys() else None,
    }
    return poc_for_finding(finding, _project_http_target(p))
