"""项目管理：单目标/集群项目的 CRUD、Scope 构建、目标解析。"""
from __future__ import annotations

import asyncio
import re
import socket

from .db import db, new_id, now, _dumps, _loads
from .objective import FLAG, REDTEAM, SRC, normalize_objective
from .scope import Scope, forbidden_project_target_reason, is_loopback, is_private

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _clean_target(raw: str) -> tuple[str, str | None]:
    """从输入里剥离协议/端口，返回 (host, port_or_None)。"""
    t = raw.strip()
    t = re.sub(r"^\w+://", "", t)          # 去协议
    t = t.split("/")[0]                     # 去路径
    port = None
    if t.count(":") == 1:                   # host:port（忽略 IPv6 简化处理）
        host, p = t.split(":")
        if p.isdigit():
            t, port = host, p
    return t.strip().lower(), port


def assert_safe_project_target(target: str) -> str:
    """校验项目主目标，不安全则抛 ValueError；返回规范化 host。"""
    host, _ = _clean_target(target or "")
    reason = forbidden_project_target_reason(host)
    if reason:
        raise ValueError(reason)
    return host


async def ensure_project_target_safe(pid: str) -> dict:
    """启动前校验：项目存在且 target 非本机/回环/Fake-IP。返回项目 dict。"""
    p = await get_project(pid)
    if not p:
        raise ValueError("项目不存在")
    tgt = (p.get("target") or "").strip()
    if tgt:
        assert_safe_project_target(tgt)
    return p


async def _resolve(host: str) -> set[str]:
    if _IP_RE.match(host):
        return {host}
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
        return {i[4][0] for i in infos if _IP_RE.match(i[4][0])}
    except Exception:
        return set()


def _filter_scope_ips(host: str, ips: set[str], objective: str | None) -> tuple[set[str], str | None]:
    """创建期 DNS 去漂移：域名解析结果剔除回环；红队额外剔除私网。显式 IP 目标原样保留。"""
    if _IP_RE.match(host):
        return set(ips), None
    external = normalize_objective(objective) in (REDTEAM, SRC)
    kept: set[str] = set()
    for ip in ips:
        if is_loopback(ip):
            continue
        if external and is_private(ip):
            continue
        kept.add(ip)
    warning = None
    if ips and not kept:
        warning = (f"授权域名 {host} 仅解析到回环/内网（{sorted(ips)}），"
                   f"已不写入 scope.ips。")
    return kept, warning


async def create_single_project(
    name: str,
    target: str,
    ports: list[int] | None = None,
    *,
    allow_subdomains: bool = False,
    mode: str = "strict",
    config: dict | None = None,
    parent_id: str | None = None,
    extra_targets: list[str] | None = None,
    extra_ips: set[str] | None = None,
) -> dict:
    host, inline_port = _clean_target(target)
    assert_safe_project_target(host)
    if inline_port and not ports:
        ports = [int(inline_port)]
    extra: list[str] = []
    seen_t = {host}
    for raw in extra_targets or []:
        h, _p = _clean_target(str(raw or ""))
        if not h or h in seen_t:
            continue
        seen_t.add(h)
        extra.append(h)
    all_targets = [host, *extra]
    cfg = dict(config or {})
    ips_raw = await _resolve(host)
    for h in extra:
        ips_raw |= await _resolve(h)
    if extra_ips:
        ips_raw |= {str(x) for x in extra_ips if x}
    ips, dns_warning = _filter_scope_ips(host, ips_raw, cfg.get("objective"))
    if dns_warning:
        cfg["dns_warning"] = dns_warning
    kept_extra = {str(x) for x in (extra_ips or set()) if x}
    ips = set(ips) | kept_extra
    hit_loop = sorted(ip for ip in ips if is_loopback(ip))
    if hit_loop and not _IP_RE.match(host):
        raise ValueError(f"目标 {host} 解析到回环地址（{hit_loop}），禁止创建项目")
    cfg["vhosts"] = list(all_targets)
    # 边界按主机身份（域名/IP）；ports 只记在 projects.ports 供展示/探测，不写入 Scope 收紧端口
    scope = Scope(
        targets=all_targets, ips=ips, ports=None, allow_subdomains=allow_subdomains, mode=mode,
    )
    pid = new_id("p_")
    ts = now()
    await db.execute(
        """INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, name or host, "single", host, _dumps(ports), _dumps(scope.to_dict()),
         _dumps(cfg), "idle", parent_id, ts, ts),
    )
    return await get_project(pid)


async def create_cluster_project(name: str, assets: list[str], config: dict | None = None) -> dict:
    """集群项目（Phase 2 深化）：先建父项目并登记资产列表，存活快筛与子项目划分后续进行。"""
    from .cluster import compact_assets_by_host, parse_asset_lines, preferred_host, _normalize_asset
    cleaned: list[str] = []
    rejected: list[str] = []
    for raw in parse_asset_lines(assets):
        try:
            assert_safe_project_target(raw)
        except ValueError:
            rejected.append(raw)
            continue
        cleaned.append(raw)
    cleaned, _duped = compact_assets_by_host(cleaned)
    if not cleaned:
        raise ValueError(
            "集群资产均为本机/回环/Fake-IP，已全部拒绝"
            + (f"：{rejected[:5]}" if rejected else "")
        )
    pid = new_id("p_")
    ts = now()
    hosts: list[str] = []
    seen: set[str] = set()
    for a in cleaned:
        info = _normalize_asset(a)
        h = preferred_host(info.get("host") or "")
        if h and h not in seen:
            seen.add(h)
            hosts.append(h)
    scope = Scope(targets=hosts or [a.lower() for a in cleaned], mode="strict")
    cfg = {**(config or {}), "assets": cleaned}
    if rejected:
        cfg["assets_rejected"] = rejected
    await db.execute(
        """INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, name, "cluster", None, None, _dumps(scope.to_dict()),
         _dumps(cfg), "idle", None, ts, ts),
    )
    return await get_project(pid)


async def create_benchmark_project(
    name: str, base_url: str, token: str, config: dict | None = None
) -> dict:
    """评测父项目。incoming 为 src 时只叠胶水：复用拉题/起容器，不夺旗。"""
    pid = new_id("p_")
    ts = now()
    scope = Scope(targets=[], mode="strict")
    incoming = dict(config or {})
    is_src = normalize_objective(incoming.get("objective") or incoming.get("track")) == SRC
    cfg = {
        **incoming,
        "objective": "src" if is_src else "flag",
        "track": "src" if is_src else incoming.get("track") or "ctf",
        "benchmark": {"base_url": (base_url or "").rstrip("/"), "token": token or ""},
        "autopilot": False if is_src else (
            True if incoming.get("autopilot") is None else bool(incoming.get("autopilot"))
        ),
    }
    await db.execute(
        """INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, name or "benchmark", "benchmark", None, None, _dumps(scope.to_dict()),
         _dumps(cfg), "idle", None, ts, ts),
    )
    return await get_project(pid)


def _backfill_track(kind: str, cfg: dict) -> dict:
    """给旧数据回填二级赛道 track（前端徽章用）。不落库，仅序列化时补齐。"""
    t = str(cfg.get("track") or "").lower()
    if t in ("redteam", "ctf", "src"):
        return {**cfg, "track": t}
    obj = normalize_objective(cfg.get("objective"))
    if obj == SRC:
        return {**cfg, "track": "src"}
    if kind == "benchmark" or obj == FLAG:
        return {**cfg, "track": "ctf"}
    return {**cfg, "track": "redteam"}


def _serialize(row: dict) -> dict:
    kind = row["kind"]
    cfg = _loads(row["config"]) or {}
    cfg = _backfill_track(kind, cfg)
    from .project_status import hunt_hard_stop_info
    obj = (cfg or {}).get("objective") or (cfg or {}).get("track")
    return {
        "id": row["id"], "name": row["name"], "kind": kind, "target": row["target"],
        "ports": _loads(row["ports"]), "scope": _loads(row["scope"]) or {},
        "config": cfg, "status": row["status"],
        "parent_id": row["parent_id"], "created_at": row["created_at"], "updated_at": row["updated_at"],
        "hard_stop": hunt_hard_stop_info(obj),
    }


async def get_project(pid: str) -> dict | None:
    row = await db.fetchone("SELECT * FROM projects WHERE id=?", (pid,))
    return _serialize(row) if row else None


async def list_projects() -> list[dict]:
    # 只返回顶层项目：子项目（集群每主机）通过其父项目的面板进入。
    rows = await db.fetchall("SELECT * FROM projects WHERE parent_id IS NULL ORDER BY created_at DESC")
    return [_serialize(r) for r in rows]


async def update_status(pid: str, status: str) -> None:
    await db.execute("UPDATE projects SET status=?, updated_at=? WHERE id=?", (status, now(), pid))


def _row_config(row: dict) -> dict:
    cfg = _loads(row.get("config")) or {}
    return cfg if isinstance(cfg, dict) else {}


async def unstick_transient_resource_errors() -> int:
    """把 FD/SQLite 资源抖动误标成 error 的项目改回 idle，使其可再次调度。"""
    from .project_status import HUNT_FAILED_REASONS

    rows = await db.fetchall(
        """SELECT id, config FROM projects WHERE status='error' AND id IN (
             SELECT DISTINCT project_id FROM events
             WHERE type='log' AND (
               payload LIKE '%unable to open database%'
               OR payload LIKE '%Too many open files%'
               OR payload LIKE '%[Errno 24]%'
             )
           )"""
    )
    ids = [
        r["id"] for r in (rows or [])
        if _row_config(r).get("completion_reason") not in HUNT_FAILED_REASONS
    ]
    if not ids:
        return 0
    q = ",".join("?" * len(ids))
    await db.execute(
        f"UPDATE projects SET status='idle', updated_at=? WHERE status='error' AND id IN ({q})",
        (now(), *ids),
    )
    return len(ids)


async def reclassify_hunt_failures() -> int:
    """图空转 / 时长硬停的存量项目从 idle/completed/stopped 改到 error（失败区）。"""
    from .project_status import HUNT_FAILED_REASONS

    rows = await db.fetchall(
        "SELECT id, config FROM projects WHERE status IN ('idle','completed','stopped')"
    )
    ids = [
        r["id"] for r in (rows or [])
        if _row_config(r).get("completion_reason") in HUNT_FAILED_REASONS
    ]
    if not ids:
        return 0
    q = ",".join("?" * len(ids))
    await db.execute(
        f"UPDATE projects SET status='error', updated_at=? WHERE id IN ({q})",
        (now(), *ids),
    )
    return len(ids)


async def update_config(pid: str, config: dict) -> None:
    await db.execute("UPDATE projects SET config=?, updated_at=? WHERE id=?", (_dumps(config), now(), pid))


async def rename_project(pid: str, name: str) -> dict:
    """修改项目显示名。集群会同步改写「旧名 · host」形式的子项目名前缀。"""
    name = (name or "").strip()
    if not name:
        raise ValueError("名称不能为空")
    if len(name) > 80:
        raise ValueError("名称过长（最多 80 字）")
    row = await db.fetchone("SELECT * FROM projects WHERE id=?", (pid,))
    if not row:
        raise ValueError("项目不存在")
    old = (row["name"] or "").strip()
    ts = now()
    await db.execute("UPDATE projects SET name=?, updated_at=? WHERE id=?", (name, ts, pid))
    renamed_children = 0
    if row["kind"] in ("cluster", "benchmark") and old and old != name:
        prefix = f"{old} · "
        children = await db.fetchall(
            "SELECT id, name FROM projects WHERE parent_id=?", (pid,),
        )
        for c in children:
            cname = c["name"] or ""
            if cname.startswith(prefix):
                new_c = name + " · " + cname[len(prefix):]
                await db.execute(
                    "UPDATE projects SET name=?, updated_at=? WHERE id=?",
                    (new_c, ts, c["id"]),
                )
                renamed_children += 1
            elif cname == old:
                await db.execute(
                    "UPDATE projects SET name=?, updated_at=? WHERE id=?",
                    (name, ts, c["id"]),
                )
                renamed_children += 1
    proj = await get_project(pid)
    assert proj is not None
    return {**proj, "renamed_children": renamed_children}


async def update_scope_and_config(pid: str, scope: dict, config: dict) -> None:
    """同步更新集群父项目的 scope + config（新增资产时用）。"""
    await db.execute(
        "UPDATE projects SET scope=?, config=?, updated_at=? WHERE id=?",
        (_dumps(scope), _dumps(config), now(), pid),
    )


# 随项目一并清掉的关联表。
_PROJECT_DATA_TABLES = (
    "nodes", "edges", "findings", "runs", "events", "steering", "intents", "flags",
)


async def _purge_project_rows(pid: str) -> None:
    for tbl in _PROJECT_DATA_TABLES:
        await db.execute(f"DELETE FROM {tbl} WHERE project_id=?", (pid,))
    await db.execute("DELETE FROM projects WHERE id=?", (pid,))


async def list_child_ids(pid: str) -> list[str]:
    rows = await db.fetchall("SELECT id FROM projects WHERE parent_id=?", (pid,))
    return [r["id"] for r in rows]


async def delete_project(pid: str) -> None:
    """删除项目及其全部子项目（图数据/事件/意图/flags）。

    不负责停跑——由 API 层在删除前对整棵子树调用 manager.stop。
    """
    for child_id in await list_child_ids(pid):
        await delete_project(child_id)
    await _purge_project_rows(pid)


async def delete_projects(ids: list[str]) -> dict:
    """批量删除：去重后逐个级联删除。返回 {deleted, missing}。

    停跑由调用方在删除前完成（API 层对整棵子树 stop）。
    """
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in ids or []:
        pid = str(raw or "").strip()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        ordered.append(pid)

    deleted: list[str] = []
    missing: list[str] = []
    for pid in ordered:
        if not await get_project(pid):
            missing.append(pid)
            continue
        await delete_project(pid)
        deleted.append(pid)
    return {"deleted": deleted, "missing": missing}


def build_scope(project: dict) -> Scope:
    return Scope.from_dict(project.get("scope"))
