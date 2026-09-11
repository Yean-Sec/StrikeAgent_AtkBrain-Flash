"""集群项目：批量资产存活快筛 + 子项目自动划分。

面对大量资产：先归一化 → 并发存活/指纹快筛 → 去重 → 按主机/IP 划分子项目
（每个存活主机 = 一个单目标闭环）。探测强制 IPv4。
"""
from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .db import db, now, _dumps
from .events import emit
from .projects import (
    _filter_scope_ips,
    _resolve,
    assert_safe_project_target,
    create_single_project,
    get_project,
    update_config,
    update_scope_and_config,
    update_status,
)
from .scope import _IP_RE

# 导入表头/列名，不是主机
_ASSET_HEADER_TOKENS = frozenset({
    "host", "hosts", "hostname", "ip", "ips", "url", "urls",
    "domain", "domains", "address", "addresses", "target", "targets",
    "资产", "目标",
})
# 不引入完整 PSL；仅覆盖常见两段后缀
_MULTI_PART_TLDS = frozenset({
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.au", "net.au", "org.au", "co.nz",
    "com.tw", "com.hk", "co.kr",
})

COMMON_WEB_PORTS = [80, 443, 8080, 8000, 8443, 8888, 8787]
PROBE_CONCURRENCY = 8
PROBE_TIMEOUT = 15.0

# 批量导入进度（内存）：供 UI 轮询，避免一次 HTTP 卡到全部子项目建完。
_IMPORT: dict[str, dict] = {}
_IMPORT_TASKS: dict[str, asyncio.Task] = {}
_IMPORT_LOCKS: dict[str, asyncio.Lock] = {}
_IMPORT_RESCAN: set[str] = set()
_IMPORT_STOP: set[str] = set()


def _import_task_running(project_id: str) -> bool:
    task = _IMPORT_TASKS.get(project_id)
    return task is not None and not task.done()


def _import_lock(project_id: str) -> asyncio.Lock:
    lock = _IMPORT_LOCKS.get(project_id)
    if lock is None:
        lock = asyncio.Lock()
        _IMPORT_LOCKS[project_id] = lock
    return lock


def import_snapshot(project_id: str) -> dict:
    cur = _IMPORT.get(project_id)
    if cur:
        return dict(cur)
    return {"phase": "idle", "done": 0, "total": 0, "created": 0, "started": 0, "current": ""}


async def _set_import_progress(project_id: str, *, persist_cfg: bool = False, **fields) -> dict:
    cur = dict(_IMPORT.get(project_id) or {})
    cur.update(fields)
    cur["ts"] = time.time()
    cur.setdefault("phase", "spawn")
    cur.setdefault("done", 0)
    cur.setdefault("total", 0)
    cur.setdefault("created", 0)
    cur.setdefault("started", 0)
    cur.setdefault("current", "")
    _IMPORT[project_id] = cur
    try:
        await emit(project_id, "import_progress", dict(cur), persist=False)
    except Exception:
        pass
    if persist_cfg:
        try:
            project = await get_project(project_id)
            if project:
                cfg = dict(project.get("config") or {})
                phase = str(cur.get("phase") or "")
                if phase in ("done", "idle"):
                    cfg.pop("import_progress", None)
                else:
                    cfg["import_progress"] = {
                        k: cur.get(k) for k in (
                            "phase", "done", "total", "created", "started", "current", "message",
                            "group_count", "hosts", "policy", "groups",
                        )
                        if cur.get(k) is not None
                    }
                await update_config(project_id, cfg)
        except Exception:
            pass
    return dict(cur)


async def import_progress_for(project_id: str) -> dict:
    """内存进度优先；任务已停但还停在 spawn 视为暂停，便于继续导入。"""
    live = _import_task_running(project_id)
    mem = _IMPORT.get(project_id)
    if mem and str(mem.get("phase") or "") not in ("idle", ""):
        phase = str(mem.get("phase") or "")
        if phase in ("merge", "spawn", "start") and not live:
            paused = {
                **mem,
                "phase": "paused",
                "message": mem.get("message") or "导入已暂停",
                "importing": False,
            }
            _IMPORT[project_id] = paused
            return dict(paused)
        return {**mem, "importing": live and phase in ("parse", "merge", "spawn", "start")}
    project = await get_project(project_id)
    cfg = ((project or {}).get("config") or {}).get("import_progress") or {}
    if isinstance(cfg, dict):
        phase = str(cfg.get("phase") or "")
        if phase in ("merge", "spawn", "start", "paused") and not live:
            return {
                **cfg,
                "phase": "paused",
                "message": cfg.get("message") or "导入已暂停",
                "importing": False,
            }
        if phase not in (None, "", "idle", "done", "paused"):
            return {**cfg, "phase": "idle", "stale": True, "done": cfg.get("done") or 0, "total": cfg.get("total") or 0}
    return import_snapshot(project_id)


def _canonical_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def preferred_host(host: str) -> str:
    """子项目身份：去掉 www. 前缀，a.com 与 www.a.com 视为同一主机。"""
    h = _canonical_host(host)
    if h.startswith("www.") and len(h) > 4:
        return h[4:]
    return h


def fold_host_keys(host: str) -> set[str]:
    h = _canonical_host(host)
    if not h:
        return set()
    pref = preferred_host(h)
    keys = {h, pref}
    if not h.startswith("www."):
        keys.add("www." + h)
    return {k for k in keys if k}


def is_asset_header_token(raw: str) -> bool:
    """单词语、无点、非 IP：导入表头（host/ip/url/资产），不当成目标。"""
    s = (raw or "").strip().lower()
    if not s or "://" in s or "/" in s or ":" in s:
        return False
    if "." in s or _IP_RE.match(s):
        return False
    return s in _ASSET_HEADER_TOKENS


def registrable_domain(host: str) -> str:
    """eTLD+1。IP 原样；example.com.cn → example.com.cn。"""
    h = preferred_host(host)
    if not h:
        return ""
    if _IP_RE.match(h):
        return h
    parts = [p for p in h.split(".") if p]
    if len(parts) < 2:
        return h
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def product_zone(host: str) -> str:
    """SRC 产品域：注册域再往左留 1 级。pay 与 ipay 分开；*.bbs.ztgame.com 一组。"""
    h = preferred_host(host)
    if not h:
        return ""
    if _IP_RE.match(h):
        return h
    e = registrable_domain(h)
    if not e or h == e:
        return e or h
    rest = h[: -(len(e) + 1)]
    if not rest:
        return e
    left = rest.rsplit(".", 1)[-1]
    return f"{left}.{e}"


def parse_asset_lines(items: list | str | None) -> list[str]:
    """拆行并丢掉空行/注释/BOM，保留原始 URL 以便 entry_url 仍是用户能打开的那条。"""
    if items is None:
        return []
    if isinstance(items, str):
        text = items.replace("\ufeff", "")
        chunks = text.splitlines()
    else:
        chunks = []
        for it in items:
            s = (it if isinstance(it, str) else str(it)).replace("\ufeff", "")
            chunks.extend(s.splitlines())
    out: list[str] = []
    for line in chunks:
        raw = line.strip()
        if not raw:
            continue
        # 必须先认注释，再剥行尾逗号；否则 `; skip` 会被 strip(",;") 吃掉分号变成资产
        if raw.startswith(("#", ";", "//")):
            continue
        raw = raw.strip(",;，")
        if not raw:
            continue
        # 已是 URL 的整行不再按逗号切开（query 里可能有逗号）
        parts = [raw] if "://" in raw else [p.strip() for p in raw.split(",")]
        for p in parts:
            if not p or p.startswith(("#", ";", "//")):
                continue
            if is_asset_header_token(p):
                continue
            out.append(p)
    return out


def list_skipped_headers(items: list | str | None) -> list[str]:
    """parse 丢掉的表头词，供预览展示。"""
    found: list[str] = []
    if items is None:
        chunks: list[str] = []
    elif isinstance(items, str):
        chunks = items.replace("\ufeff", "").splitlines()
    else:
        chunks = []
        for it in items:
            s = (it if isinstance(it, str) else str(it)).replace("\ufeff", "")
            chunks.extend(s.splitlines())
    for line in chunks:
        raw = line.strip()
        if not raw or raw.startswith(("#", ";", "//")):
            continue
        raw = raw.strip(",;，")
        parts = [raw] if "://" in raw else [p.strip() for p in raw.split(",")]
        for p in parts:
            if p and is_asset_header_token(p):
                found.append(p)
    return found


def compact_assets_by_host(assets: list | None) -> tuple[list[str], list[str]]:
    """按 (FQDN, 端口) 去重：www 等价、同端口不同路径只留一条；同主机不同端口都保留。"""
    kept: list[str] = []
    skipped: list[str] = []
    seen_hp: set[tuple[str, int]] = set()
    for raw in parse_asset_lines(assets):
        info = _normalize_asset(raw)
        if not info:
            skipped.append(raw)
            continue
        host = preferred_host(info["host"])
        port = int(info["port"])
        key = (host, port)
        if key in seen_hp:
            skipped.append(raw)
            continue
        seen_hp.add(key)
        kept.append(info.get("probe_url") or raw)
    return kept, skipped


def _hosts_from_assets(assets: list) -> tuple[dict[str, dict], dict[str, set[int]]]:
    by_host: dict[str, dict] = {}
    ports_by_host: dict[str, set[int]] = {}
    for a in assets or []:
        info = _normalize_asset(a if isinstance(a, str) else str(a))
        if not info:
            continue
        host = preferred_host(info["host"])
        if not host:
            continue
        ports_by_host.setdefault(host, set()).add(int(info["port"]))
        if host not in by_host:
            stored = dict(info)
            stored["host"] = host
            by_host[host] = stored
    return by_host, ports_by_host


@dataclass
class MachineGroup:
    """一台机：同 FQDN 或同 DNS IP 合成的子项目。"""
    primary: str
    vhosts: list[str]
    ips: list[str]
    ports: list[int]
    entry_url: str = ""
    zone: str = ""


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        p = self.parent
        while p[x] != x:
            p[x] = p[p[x]]
            x = p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def groups(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for x in self.parent:
            out.setdefault(self.find(x), []).append(x)
        return out


def _pick_primary(members: list[str], ordered_hosts: list[str]) -> str:
    in_group = set(members)
    ordered = [h for h in ordered_hosts if h in in_group]
    names = [h for h in ordered if not _IP_RE.match(h)]
    return (names or ordered or members)[0]


def _zone_for_members(members: list[str]) -> str:
    names = [h for h in members if not _IP_RE.match(h)]
    if names:
        return product_zone(names[0])
    return members[0] if members else ""


def _machine_groups_from_uf(
    uf: _UnionFind,
    ordered_hosts: list[str],
    by_host: dict[str, dict],
    ports_by_host: dict[str, set[int]],
    origin_ips: dict[str, set[str]],
) -> list[MachineGroup]:
    groups: list[MachineGroup] = []
    for _root, members in uf.groups().items():
        in_group = set(members)
        primary = _pick_primary(members, ordered_hosts)
        vhosts: list[str] = []
        seen: set[str] = set()
        for h in [primary, *(x for x in ordered_hosts if x in in_group)]:
            if h not in seen:
                seen.add(h)
                vhosts.append(h)
        ips: set[str] = set()
        ports: set[int] = set()
        for h in members:
            ips |= set(origin_ips.get(h) or ())
            ports |= set(ports_by_host.get(h) or ())
        info = by_host.get(primary) or by_host.get(members[0]) or {}
        groups.append(MachineGroup(
            primary=primary,
            vhosts=vhosts,
            ips=sorted(ips),
            ports=sorted(int(p) for p in ports),
            entry_url=str(info.get("probe_url") or ""),
            zone=_zone_for_members(members),
        ))
    return groups


def group_hosts_by_origin_ips(
    by_host: dict[str, dict],
    ports_by_host: dict[str, set[int]],
    origin_ips: dict[str, set[str]],
) -> list[MachineGroup]:
    """红队默认：全局同源站 IP 并查集。origin_ips 为空的主机保持独立。"""
    hosts = list(by_host.keys())
    if not hosts:
        return []
    uf = _UnionFind(hosts)
    ip_to_hosts: dict[str, list[str]] = {}
    for host in hosts:
        for ip in origin_ips.get(host) or ():
            if not ip:
                continue
            ip_to_hosts.setdefault(str(ip), []).append(host)
    for _ip, hs in ip_to_hosts.items():
        for other in hs[1:]:
            uf.union(hs[0], other)
    return _machine_groups_from_uf(uf, hosts, by_host, ports_by_host, origin_ips)


def group_hosts_for_objective(
    by_host: dict[str, dict],
    ports_by_host: dict[str, set[int]],
    origin_ips: dict[str, set[str]],
    *,
    objective: str | None = None,
) -> list[MachineGroup]:
    """红队：全局源站 IP 并查集。SRC：先按产品域分桶，只在桶内并 IP。"""
    from .objective import objective_is_src

    hosts = list(by_host.keys())
    if not hosts:
        return []
    mapping = origin_ips or {}
    if not objective_is_src(objective):
        return group_hosts_by_origin_ips(by_host, ports_by_host, mapping)

    uf = _UnionFind(hosts)
    buckets: dict[str, list[str]] = {}
    for h in hosts:
        if _IP_RE.match(h):
            continue
        buckets.setdefault(product_zone(h), []).append(h)
    for members in buckets.values():
        for other in members[1:]:
            uf.union(members[0], other)

    ip_to_domains: dict[str, list[str]] = {}
    for host in hosts:
        if _IP_RE.match(host):
            continue
        for ip in mapping.get(host) or ():
            if ip:
                ip_to_domains.setdefault(str(ip), []).append(host)
    for _ip, hs in ip_to_domains.items():
        by_z: dict[str, list[str]] = {}
        for h in hs:
            by_z.setdefault(product_zone(h), []).append(h)
        for z_members in by_z.values():
            for other in z_members[1:]:
                uf.union(z_members[0], other)

    for iph in (h for h in hosts if _IP_RE.match(h)):
        domains = ip_to_domains.get(iph) or []
        if not domains:
            continue
        by_z: dict[str, list[str]] = {}
        for d in domains:
            by_z.setdefault(product_zone(d), []).append(d)
        best_z = max(by_z, key=lambda z: (len(buckets.get(z) or []), len(by_z[z])))
        uf.union(iph, by_z[best_z][0])
    return _machine_groups_from_uf(uf, hosts, by_host, ports_by_host, mapping)


def machine_group_keys(group: MachineGroup) -> set[str]:
    keys: set[str] = set()
    for h in group.vhosts:
        keys |= fold_host_keys(h)
    for ip in group.ips:
        keys.add(str(ip).lower())
    return {k for k in keys if k}


def subproject_machine_keys(project: dict) -> set[str]:
    keys: set[str] = set()
    cfg = project.get("config") or {}
    scope = project.get("scope") or {}
    names = [project.get("target")]
    names.extend(scope.get("targets") or [])
    names.extend(cfg.get("vhosts") or [])
    for t in names:
        if t:
            keys |= fold_host_keys(str(t))
    for ip in scope.get("ips") or []:
        if ip:
            keys.add(str(ip).lower())
    return {k for k in keys if k}


async def origin_ips_for_host(host: str, objective: str | None = None) -> set[str]:
    """字面量 IP 原样作为合并键；域名用 DNS A 记录。"""
    h = preferred_host(host)
    if not h:
        return set()
    if _IP_RE.match(h):
        return {h}
    ips_raw = await _resolve(h)
    ips, _warn = _filter_scope_ips(h, ips_raw, objective)
    return set(ips)


async def group_hosts_by_machine(
    by_host: dict[str, dict],
    ports_by_host: dict[str, set[int]],
    *,
    objective: str | None = None,
    origin_ips: dict[str, set[str]] | None = None,
) -> list[MachineGroup]:
    hosts = list(by_host.keys())
    mapping = dict(origin_ips or {})
    missing = [h for h in hosts if h not in mapping]
    if missing:
        sem = asyncio.Semaphore(16)

        async def _one(h: str) -> tuple[str, set[str]]:
            async with sem:
                return h, await origin_ips_for_host(h, objective)

        pairs = await asyncio.gather(*[_one(h) for h in missing])
        mapping.update(pairs)
    return group_hosts_for_objective(by_host, ports_by_host, mapping, objective=objective)


def preview_asset_groups(
    assets: list | str | None,
    *,
    track: str | None = None,
    objective: str | None = None,
) -> dict:
    """同步预览：去路径/www/表头后按赛道收组。不做 DNS，导入时才会按源站 IP 再并。"""
    from .objective import normalize_objective, objective_is_src

    t = (track or "").strip().lower()
    o = (objective or "").strip().lower()
    if t in ("src", "ctf", "redteam"):
        obj = {"src": "src", "ctf": "flag", "redteam": "redteam"}[t]
    else:
        obj = normalize_objective(o or t)
        t = "src" if obj == "src" else ("ctf" if obj == "flag" else "redteam")
    src = objective_is_src(obj)
    headers = list_skipped_headers(assets)
    kept, skipped_dup = compact_assets_by_host(assets)
    by_host, ports_by_host = _hosts_from_assets(kept)
    origin = {h: ({h} if _IP_RE.match(h) else set()) for h in by_host}
    groups = group_hosts_for_objective(by_host, ports_by_host, origin, objective=obj)
    return {
        "track": t,
        "objective": obj,
        "policy": "product_zone" if src else "machine",
        "lines_kept": len(kept),
        "skipped_dup": skipped_dup[:80],
        "skipped_dup_count": len(skipped_dup),
        "skipped_header": headers,
        "hosts": len(by_host),
        "groups": [
            {
                "primary": g.primary,
                "zone": g.zone,
                "vhosts": g.vhosts,
                "ports": g.ports,
            }
            for g in groups
        ],
        "group_count": len(groups),
        "note": (
            "导入时还会按源站 IP 再并（SRC 仅同产品域内）。"
            if src else
            "导入时还会把解析到同一源站 IP 的主机并成一台。"
        ),
    }


async def _persist_machine_identity(
    pid: str,
    *,
    ports: list[int] | None = None,
    scope: dict | None = None,
    config: dict | None = None,
    name: str | None = None,
) -> None:
    fields = ["updated_at=?"]
    args: list = [now()]
    if name is not None:
        fields.append("name=?")
        args.append(name)
    if ports is not None:
        fields.append("ports=?")
        args.append(_dumps(ports))
    if scope is not None:
        fields.append("scope=?")
        args.append(_dumps(scope))
    if config is not None:
        fields.append("config=?")
        args.append(_dumps(config))
    args.append(pid)
    await db.execute(f"UPDATE projects SET {', '.join(fields)} WHERE id=?", tuple(args))


async def _absorb_group_into(sub: dict, group: MachineGroup) -> dict:
    """把同机资产并进已有子项目（端口/vhost/源站 IP），不新建。"""
    scope = dict(sub.get("scope") or {})
    cfg = dict(sub.get("config") or {})
    targets: list[str] = []
    seen: set[str] = set()
    for t in [sub.get("target"), *(scope.get("targets") or []), *(cfg.get("vhosts") or []), *group.vhosts]:
        h = preferred_host(str(t or ""))
        if h and h not in seen:
            seen.add(h)
            targets.append(h)
    ips = sorted({str(x) for x in (*(scope.get("ips") or []), *group.ips) if x})
    ports = sorted({int(p) for p in (*(sub.get("ports") or []), *group.ports)})
    scope["targets"] = targets
    scope["ips"] = ips
    cfg["vhosts"] = targets
    if group.entry_url and not cfg.get("entry_url"):
        cfg["entry_url"] = group.entry_url
    await _persist_machine_identity(sub["id"], ports=ports or None, scope=scope, config=cfg)
    return await get_project(sub["id"]) or sub


async def _spawn_machine_group(
    project: dict,
    group: MachineGroup,
    *,
    existing: list[dict],
) -> tuple[dict | None, bool]:
    """创建或并入已有子项目。返回 (project, created)。"""
    gkeys = machine_group_keys(group)
    overlap = [s for s in existing if gkeys & subproject_machine_keys(s)]
    if overlap:
        absorbed = await _absorb_group_into(overlap[0], group)
        return absorbed, False
    cfg = dict(project.get("config") or {})
    cfg.pop("import_progress", None)
    cfg.pop("assets", None)
    cfg.pop("assets_rejected", None)
    if group.entry_url:
        cfg["entry_url"] = group.entry_url
    cfg["vhosts"] = list(group.vhosts)
    if group.zone:
        cfg["product_zone"] = group.zone
    extra = [h for h in group.vhosts if h != group.primary]
    extra_ips = set(group.ips)
    n_alias = len(group.vhosts)
    from .objective import objective_is_src
    obj = (project.get("config") or {}).get("objective")
    if n_alias <= 1:
        label = group.primary
    elif objective_is_src(obj):
        label = f"{group.primary}（产品域 {n_alias}）"
    else:
        label = f"{group.primary}（同机 {n_alias}）"
    sub = await create_single_project(
        name=f"{project['name']} · {label}",
        target=group.primary,
        ports=group.ports or None,
        mode="strict",
        allow_subdomains=False,
        config=cfg,
        parent_id=project["id"],
        extra_targets=extra,
        extra_ips=extra_ips,
    )
    return sub, True


def _normalize_asset(asset: str) -> dict:
    """从导入资产解析 host / port / scheme / 可探测 URL。"""
    raw = (asset or "").strip()
    if not raw:
        return {}
    # 允许裸 host / host:port / 完整 URL
    if "://" not in raw:
        raw_url = f"http://{raw}"
    else:
        raw_url = raw
    u = urlparse(raw_url)
    host = (u.hostname or "").lower()
    if not host:
        return {}
    port = u.port
    scheme = (u.scheme or "http").lower()
    if scheme not in ("http", "https"):
        scheme = "http"
    if port is None:
        port = 443 if scheme == "https" else 80
    # 保留路径的探测 URL（用户导入的就是能访问的）
    path = u.path or "/"
    if u.query:
        path = f"{path}?{u.query}"
    probe_url = f"{scheme}://{host}:{port}{path}"
    # 浏览器式 URL（443/80 省略端口）更贴近真实访问，部分 WAF/Fake-IP 路径更稳
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        browser_url = f"{scheme}://{host}{path}"
    else:
        browser_url = probe_url
    return {
        "raw": asset.strip(),
        "host": host,
        "port": int(port),
        "scheme": scheme,
        "probe_url": browser_url,
    }


async def _resolve_ipv4(host: str, timeout: float = 5.0) -> str | None:
    """只取 A 记录，带硬超时。Fake-IP 环境下必须避开 IPv6（fdfe:…）优先导致挂死。"""
    try:
        infos = await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                host, None, family=socket.AF_INET, type=socket.SOCK_STREAM,
            ),
            timeout=timeout,
        )
        for info in infos:
            ip = info[4][0]
            if ip:
                return ip
    except Exception:
        return None
    return None


async def _http_get(url: str) -> dict | None:
    """存活 HTTP 探测：优先 curl -4（强制 IPv4，与浏览器/本机 curl 行为一致）。

    Fake-IP/Clash：getaddrinfo 常先给 IPv6 Fake-IP，httpx 连上去超时；curl -4 走 198.18
    Fake-IP 则秒回。任一 HTTP 状态码（含 403/5xx）都算存活。
    """
    import os
    import tempfile
    body_path = None
    try:
        fd, body_path = tempfile.mkstemp(prefix="rtprobe_", suffix=".body")
        os.close(fd)
        curl_args = [
            "curl", "-4", "-sS", "-k", "-L",
            "--max-time", str(int(PROBE_TIMEOUT)),
            "--connect-timeout", "8",
            "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "-o", body_path,
            "-D", "-",
            "-w", "\n__RT_STATUS__%{http_code}\n__RT_IP__%{remote_ip}\n",
        ]
        try:
            from .proxy.pool import pool as _proxy_pool
            if _proxy_pool.enabled:
                px = _proxy_pool.pick()
                if px:
                    curl_args[1:1] = ["-x", px]
                else:
                    return await _http_get_httpx_v4(url)
        except Exception:
            try:
                from .proxy.pool import pool as _proxy_pool
                if _proxy_pool.enabled:
                    return await _http_get_httpx_v4(url)
            except Exception:
                return await _http_get_httpx_v4(url)
        curl_args.append(url)
        proc = await asyncio.create_subprocess_exec(
            *curl_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out_b, _err_b = await asyncio.wait_for(proc.communicate(), timeout=PROBE_TIMEOUT + 5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return None
        out = (out_b or b"").decode("utf-8", errors="ignore")
        status = None
        for line in out.splitlines():
            if line.startswith("__RT_STATUS__"):
                try:
                    status = int(line.split("__RT_STATUS__", 1)[1].strip() or "0")
                except ValueError:
                    status = None
        if not status or status == 0:
            return await _http_get_httpx_v4(url)
        server = ""
        for line in out.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break
        title = ""
        try:
            with open(body_path, "rb") as f:
                title = _title(f.read(8000).decode("utf-8", errors="ignore"))
        except Exception:
            pass
        return {"status": status, "server": server, "title": title}
    except FileNotFoundError:
        return await _http_get_httpx_v4(url)
    except Exception:
        return await _http_get_httpx_v4(url)
    finally:
        if body_path:
            try:
                os.unlink(body_path)
            except Exception:
                pass


async def _http_get_httpx_v4(url: str) -> dict | None:
    """httpx 兜底：解析 A 记录后直连 IPv4，Host/SNI 仍用原主机名。"""
    try:
        import httpx
        from urllib.parse import urlunparse
    except Exception:
        return None
    proxy = None
    must = False
    try:
        from .proxy.pool import pool as _proxy_pool
        must = bool(_proxy_pool.enabled)
        if must:
            proxy = _proxy_pool.pick()
            if not proxy:
                return None
    except Exception:
        if must:
            return None
    u = urlparse(url)
    host = u.hostname or ""
    if not host:
        return None
    ip = await _resolve_ipv4(host)
    headers = {"User-Agent": "Mozilla/5.0 (compatible; StrikeAgent-AtkBrain-Flash-triage/1.0)"}
    fetch = url
    if ip:
        port = u.port
        netloc = f"{ip}:{port}" if port else ip
        fetch = urlunparse((u.scheme, netloc, u.path or "/", u.params, u.query, u.fragment))
        headers["Host"] = host if not port or port in (80, 443) else f"{host}:{port}"
    try:
        async with httpx.AsyncClient(
            verify=False, timeout=PROBE_TIMEOUT, follow_redirects=True,
            **({"proxy": proxy} if proxy else {}),
        ) as cli:
            # HTTPS 连 IP 时用 extensions 设 SNI（httpx/httpcore 支持）
            ext = None
            if u.scheme == "https" and ip:
                try:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    # 用 transport 不够直接；改走 curl 已优先，这里尽量简单请求
                except Exception:
                    pass
            r = await cli.get(fetch, headers=headers)
            return {
                "status": r.status_code,
                "server": r.headers.get("server", ""),
                "title": _title(r.text),
            }
    except Exception:
        return None


async def _tcp_alive(host: str, port: int) -> bool:
    """IPv4 TCP 连通兜底（避开坏掉的 Fake-IP IPv6），DNS 带硬超时。"""
    ip = await _resolve_ipv4(host, timeout=4.0)
    if not ip:
        return False
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=4)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _probe_asset(asset: dict, sem: asyncio.Semaphore) -> list[dict]:
    """优先用原始 URL 探测；命中即收工，不再扫一堆常见端口（防 Fake-IP 慢路径拖死）。"""
    host = asset["host"]
    primary_port = asset["port"]
    primary_scheme = asset["scheme"]
    found: dict[int, dict] = {}

    async with sem:
        # 1) 原始导入 URL（用户能打开的那条）——命中即返回
        hit = await _http_get(asset["probe_url"])
        if hit:
            found[primary_port] = {
                "host": host, "port": primary_port, "scheme": primary_scheme, **hit,
            }
            return list(found.values())

        # 2) 同 scheme 根路径再试一次（去掉深路径，防单路径 404/超时误杀）
        if (primary_scheme == "https" and primary_port == 443) or (
            primary_scheme == "http" and primary_port == 80
        ):
            root = f"{primary_scheme}://{host}/"
        else:
            root = f"{primary_scheme}://{host}:{primary_port}/"
        if root != asset["probe_url"]:
            hit = await _http_get(root)
            if hit:
                found[primary_port] = {
                    "host": host, "port": primary_port, "scheme": primary_scheme, **hit,
                }
                return list(found.values())

        # 3) 仅补探主端口对端 scheme + 少量常见 Web 端口（已命中即停）
        ports = []
        for p in [primary_port, 443, 80, 8080, 8443]:
            if p not in ports:
                ports.append(p)
        for port in ports:
            if port in found:
                continue
            schemes = ("https", "http") if port in (443, 8443, 8787) else ("http", "https")
            if port in (80, 8080, 8000, 8888):
                schemes = ("http",)
            ok = None
            for scheme in schemes:
                if scheme == "https" and port in (80, 8080, 8000, 8888):
                    continue
                if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
                    url = f"{scheme}://{host}/"
                else:
                    url = f"{scheme}://{host}:{port}/"
                hit = await _http_get(url)
                if hit:
                    ok = {"host": host, "port": port, "scheme": scheme, **hit}
                    break
            if ok:
                found[port] = ok
                return list(found.values())
            # 4) TCP 兜底：仅对主端口
            if port == primary_port and await _tcp_alive(host, port):
                found[port] = {
                    "host": host, "port": port, "scheme": "tcp",
                    "status": None, "server": "", "title": "",
                }
                return list(found.values())

    return list(found.values())


def _title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html or "", re.I | re.S)
    return (m.group(1).strip()[:60] if m else "")


async def triage_cluster(project_id: str, strategy: str = "host") -> dict:
    """对集群项目做存活快筛并按策略划分子项目。"""
    project = await get_project(project_id)
    if not project or project["kind"] != "cluster":
        return {"error": "非集群项目"}
    assets = (project.get("config") or {}).get("assets") or project.get("scope", {}).get("targets", [])
    await emit(project_id, "status", {"status": "triaging", "assets": len(assets)})

    # 归一化 + 按主机去重（保留每主机首条原始 URL 优先探测）
    by_host_assets: dict[str, dict] = {}
    for a in assets:
        info = _normalize_asset(a if isinstance(a, str) else str(a))
        if not info:
            continue
        # 同主机多条资产：合并端口偏好，探测 URL 用第一条
        prev = by_host_assets.get(info["host"])
        if not prev:
            by_host_assets[info["host"]] = info
        else:
            # 若后续资产带非默认端口，记到 primary 以便补探
            pass

    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    tasks = [_probe_asset(info, sem) for info in by_host_assets.values()]
    grouped = await asyncio.gather(*tasks)
    live: list[dict] = []
    for g in grouped:
        live.extend(g)

    # 按主机聚合存活端口
    by_host: dict[str, list[dict]] = {}
    for r in live:
        by_host.setdefault(r["host"], []).append(r)
        await emit(project_id, "log", {
            "level": "info",
            "message": f"存活 {r['host']}:{r['port']} [{r.get('server','')}] {r.get('title','')}",
        })

    dead_hosts = [h for h in by_host_assets if h not in by_host]
    for h in dead_hosts:
        await emit(project_id, "log", {
            "level": "warn",
            "message": (
                f"未存活 {h}（DNS/链路不通；若浏览器可访问，多为 Fake-IP IPv6 优先或超时——"
                f"已强制 IPv4 探测，可再点一次快筛）"
            ),
        })

    # 划分子项目：存活主机再按同机（FQDN / 源站 IP）合并。
    live_by_host: dict[str, dict] = {}
    live_ports: dict[str, set[int]] = {}
    for host, entries in by_host.items():
        pref = preferred_host(host)
        info = by_host_assets.get(host) or by_host_assets.get(pref) or {}
        stored = dict(info)
        stored["host"] = pref
        if pref not in live_by_host:
            live_by_host[pref] = stored
        live_ports.setdefault(pref, set()).update(int(e["port"]) for e in entries)
    objective = ((project.get("config") or {}).get("objective"))
    machines = await group_hosts_by_machine(live_by_host, live_ports, objective=objective)
    existing_subs = await list_subprojects(project_id)
    created = []
    absorbed = 0
    for group in machines:
        try:
            sub, is_new = await _spawn_machine_group(project, group, existing=existing_subs)
        except ValueError as e:
            await emit(project_id, "log", {
                "level": "warn",
                "message": f"跳过子项目 {group.primary}：{e}",
            })
            continue
        if not sub:
            continue
        if is_new:
            created.append(sub)
            existing_subs.append(sub)
            alias = f"，同机 {len(group.vhosts)} 个域名" if len(group.vhosts) > 1 else ""
            await emit(project_id, "node", {
                "type": "info",
                "message": f"子项目 {group.primary}{alias}（探测见端口 {group.ports}，本机只扫一次）",
            })
        else:
            absorbed += 1

    await update_status(project_id, "idle")
    summary = {
        "assets": len(assets), "hosts": len(by_host_assets),
        "live_hosts": len(by_host), "live_endpoints": len(live),
        "machines": len(machines),
        "dead_hosts": dead_hosts,
        "subprojects_created": len(created),
        "absorbed": absorbed,
        "subprojects": [{"id": s["id"], "target": s["target"], "ports": s["ports"]} for s in created],
    }
    await emit(project_id, "status", {"status": "triaged", **summary})
    return summary


async def spawn_subprojects_from_assets(project_id: str, *, auto_start: bool = False) -> dict:
    """按同 FQDN / 同 DNS IP 划分子项目——**不做存活 HTTP 探测**。

    同主机多端口并集；解析到同一 IP 的不同域名合成一台机。
    auto_start=True 时边建边排队启动（进度 phase=start）。
    """
    project = await get_project(project_id)
    if not project or project["kind"] != "cluster":
        return {"error": "非集群项目", "subprojects_created": 0, "subprojects": []}

    assets = (project.get("config") or {}).get("assets") or project.get("scope", {}).get("targets", [])
    by_host, ports_by_host = _hosts_from_assets(assets)
    objective = ((project.get("config") or {}).get("objective"))
    from .objective import objective_is_src
    src = objective_is_src(objective)
    policy = "product_zone" if src else "machine"
    merge_msg = "正在按产品域合并…" if src else "正在按同机（FQDN/源站 IP）合并…"
    await _set_import_progress(
        project_id, persist_cfg=True,
        phase="merge", done=0, total=len(by_host), created=0, started=0, current="",
        message=merge_msg, hosts=len(by_host), policy=policy, group_count=0, groups=[],
    )
    machines = await group_hosts_by_machine(by_host, ports_by_host, objective=objective)
    group_rows = [
        {"primary": g.primary, "zone": g.zone, "vhosts": g.vhosts, "ports": g.ports}
        for g in machines[:40]
    ]
    existing_subs = await list_subprojects(project_id)
    existing_keys: set[str] = set()
    for s in existing_subs:
        existing_keys |= subproject_machine_keys(s)

    pending = [g for g in machines if not (machine_group_keys(g) & existing_keys)]
    absorb_groups = [g for g in machines if g not in pending]
    created = []
    skipped = [g.primary for g in absorb_groups]
    started: list[str] = []
    absorbed = 0
    total = len(pending) + len(absorb_groups)
    await _set_import_progress(
        project_id, persist_cfg=True,
        phase="spawn" if (pending or absorb_groups) else "done",
        done=0, total=total, created=0, started=0, current="",
        hosts=len(by_host), policy=policy, group_count=len(machines), groups=group_rows,
        message=(
            f"已合并为 {len(machines)} 个子项目，正在创建…"
            if pending else
            ("没有新主机" if not absorb_groups else f"已合并为 {len(machines)} 组，正在并入已有项目")
        ),
    )

    queue = absorb_groups + pending
    for i, group in enumerate(queue, 1):
        if project_id in _IMPORT_STOP:
            remain = total - (i - 1)
            await _set_import_progress(
                project_id, persist_cfg=True,
                phase="paused",
                done=i - 1, total=total, created=len(created), started=len(started),
                current="",
                message=f"导入已暂停，已建 {len(created)} 个，剩余 {remain} 个",
            )
            return {
                "assets": len(assets),
                "hosts": len(by_host),
                "machines": len(machines),
                "subprojects_created": len(created),
                "skipped_existing": skipped,
                "absorbed": absorbed,
                "subprojects": [{"id": s["id"], "target": s["target"], "ports": s["ports"]} for s in created],
                "started": started,
                "skip_probe": True,
                "paused": True,
            }
        try:
            sub, is_new = await _spawn_machine_group(project, group, existing=existing_subs)
        except ValueError as e:
            await emit(project_id, "log", {
                "level": "warn",
                "message": f"跳过子项目 {group.primary}：{e}",
            })
            await _set_import_progress(
                project_id, persist_cfg=(i == 1 or i % 5 == 0 or i == total),
                phase="spawn", done=i, total=total, current=group.primary,
                created=len(created), message=f"跳过 {group.primary}",
            )
            continue
        if not sub:
            continue
        n_alias = len(group.vhosts)
        if n_alias > 1 and objective_is_src(objective):
            alias = f"，产品域 {n_alias} 个域名"
        elif n_alias > 1:
            alias = f"，同机 {n_alias} 个域名"
        else:
            alias = ""
        if is_new:
            created.append(sub)
            existing_subs.append(sub)
            existing_keys |= subproject_machine_keys(sub)
            await emit(project_id, "node", {
                "type": "info",
                "message": f"子项目 {group.primary}{alias}（跳过存活探测；本机端口只扫一次）",
            })
            msg = f"已创建 {group.primary}{alias}"
        else:
            absorbed += 1
            msg = f"已并入 {group.primary}{alias}"
        await _set_import_progress(
            project_id, persist_cfg=(i == 1 or i % 5 == 0 or i == total),
            phase="spawn", done=i, total=total, current=group.primary,
            created=len(created), message=msg,
        )
        if auto_start and is_new:
            sid = sub.get("id")
            if sid:
                try:
                    from .engine.scheduler import manager
                    if not manager.is_running(sid):
                        manager.start(sid)
                        started.append(sid)
                except Exception:
                    pass

    if auto_start and created:
        await _set_import_progress(
            project_id, persist_cfg=True,
            phase="start", done=len(started), total=len(created),
            created=len(created), started=len(started), current="",
            message=f"已排队启动 {len(started)} 个",
        )

    await update_status(project_id, "idle")
    summary = {
        "assets": len(assets),
        "hosts": len(by_host),
        "machines": len(machines),
        "subprojects_created": len(created),
        "skipped_existing": skipped,
        "absorbed": absorbed,
        "subprojects": [{"id": s["id"], "target": s["target"], "ports": s["ports"]} for s in created],
        "started": started,
        "skip_probe": True,
    }
    await emit(project_id, "status", {"status": "spawned", **summary})
    return summary


async def _run_cluster_import(project_id: str, *, auto_start: bool = True) -> dict:
    async with _import_lock(project_id):
        last: dict = {}
        try:
            while True:
                _IMPORT_RESCAN.discard(project_id)
                last = await spawn_subprojects_from_assets(project_id, auto_start=auto_start)
                if last.get("paused") or project_id in _IMPORT_STOP:
                    _IMPORT_STOP.discard(project_id)
                    _IMPORT_RESCAN.discard(project_id)
                    return last
                if project_id in _IMPORT_RESCAN:
                    continue
                await _set_import_progress(
                    project_id, persist_cfg=True,
                    phase="done",
                    done=_IMPORT.get(project_id, {}).get("total") or last.get("subprojects_created") or 0,
                    total=_IMPORT.get(project_id, {}).get("total") or last.get("subprojects_created") or 0,
                    created=last.get("subprojects_created") or 0,
                    started=len(last.get("started") or []),
                    current="",
                    message="导入完成",
                )
                return last
        except asyncio.CancelledError:
            await _set_import_progress(
                project_id, persist_cfg=True,
                phase="paused", message="导入已暂停",
            )
            return {"paused": True, **(last or {})}
        except Exception as e:
            await _set_import_progress(
                project_id, persist_cfg=True,
                phase="error", message=str(e)[:240],
            )
            raise


def schedule_cluster_import(project_id: str, *, auto_start: bool = True, total_hint: int | None = None) -> dict:
    """后台划分子项目并启动；立即返回当前进度快照。"""
    _IMPORT_STOP.discard(project_id)
    task = _IMPORT_TASKS.get(project_id)
    if task is not None and not task.done():
        _IMPORT_RESCAN.add(project_id)
        return {**import_snapshot(project_id), "already_running": True, "importing": True}
    snap = {
        "phase": "merge",
        "done": 0,
        "total": int(total_hint or 0),
        "created": 0,
        "started": 0,
        "current": "",
        "message": "正在合并资产…",
        "ts": time.time(),
    }
    _IMPORT[project_id] = snap
    _IMPORT_TASKS[project_id] = asyncio.create_task(
        _run_cluster_import(project_id, auto_start=auto_start)
    )
    return {**snap, "importing": True}


async def pause_cluster_import(project_id: str) -> dict:
    """停止再新建子项目；已创建/已启动的子项目不受影响。"""
    _IMPORT_STOP.add(project_id)
    _IMPORT_RESCAN.discard(project_id)
    cur = import_snapshot(project_id)
    if not _import_task_running(project_id):
        snap = await _set_import_progress(
            project_id, persist_cfg=True,
            phase="paused",
            done=cur.get("done") or 0,
            total=cur.get("total") or 0,
            created=cur.get("created") or 0,
            started=cur.get("started") or 0,
            current="",
            message=cur.get("message") or "导入已暂停",
        )
        return {**snap, "paused": True, "importing": False}
    snap = await _set_import_progress(
        project_id, persist_cfg=False,
        message="正在暂停导入…",
    )
    return {**snap, "pausing": True, "importing": True}


def resume_cluster_import(project_id: str, *, auto_start: bool = True) -> dict:
    """从资产列表里尚未建子项目的主机继续导入。"""
    _IMPORT_STOP.discard(project_id)
    return schedule_cluster_import(project_id, auto_start=auto_start)


async def list_subprojects(project_id: str) -> list[dict]:
    rows = await db.fetchall("SELECT * FROM projects WHERE parent_id=? ORDER BY created_at", (project_id,))
    from .projects import _serialize
    return [_serialize(r) for r in rows]


async def add_assets_to_cluster(project_id: str, assets: list[str]) -> dict:
    """向已有集群追加资产：按 (FQDN, 端口) 去重，同机多端口并入；再按源站 IP 补建/并入子项目。

    「已导入」只看已有 (主机, 端口)。上次导入若只写入了 assets、子项目创建被打断，
    再次导入同一份列表会补建缺失子项目，而不是整表跳过。
    """
    project = await get_project(project_id)
    if not project or project["kind"] != "cluster":
        return {"error": "非集群项目", "added": [], "subprojects_created": 0, "subprojects": []}

    raw_list = parse_asset_lines(assets)
    if not raw_list:
        return {"error": "未提供资产", "added": [], "subprojects_created": 0, "subprojects": []}

    cfg = dict(project.get("config") or {})
    existing_assets = [str(x).strip() for x in (cfg.get("assets") or []) if str(x).strip()]
    seen_hp: set[tuple[str, int]] = set()
    for a in existing_assets:
        info = _normalize_asset(a)
        if not info:
            continue
        seen_hp.add((preferred_host(info["host"]), int(info["port"])))

    existing_subs = await list_subprojects(project_id)
    orig_sub_keys: set[str] = set()
    for p in existing_subs:
        orig_sub_keys |= subproject_machine_keys(p)

    added: list[str] = []
    rejected: list[dict] = []
    skipped_dup: list[str] = []
    skipped_hosts: set[str] = set()
    pending_host_set: set[str] = set()
    seen_batch: set[tuple[str, int]] = set()
    for raw in raw_list:
        info = _normalize_asset(raw)
        if not info:
            rejected.append({"asset": raw, "reason": "无法解析主机"})
            continue
        try:
            assert_safe_project_target(raw)
        except ValueError as e:
            rejected.append({"asset": raw, "reason": str(e)})
            continue
        pref = preferred_host(info["host"])
        port = int(info["port"])
        hp = (pref, port)
        if hp in seen_hp or hp in seen_batch:
            skipped_dup.append(raw)
            skipped_hosts.add(pref)
            continue
        seen_batch.add(hp)
        pending_host_set.add(pref)
        kept = info.get("probe_url") or raw
        existing_assets.append(kept)
        added.append(kept)
        seen_hp.add(hp)

    if not added and not skipped_dup and not pending_host_set and rejected:
        return {
            "error": "资产均被拒绝",
            "added": [],
            "rejected": rejected,
            "skipped_dup": skipped_dup,
            "skipped_dup_count": 0,
            "subprojects_created": 0,
            "subprojects": [],
        }

    by_host, _ = _hosts_from_assets(existing_assets)
    new_hosts = [h for h in by_host if not (fold_host_keys(h) & orig_sub_keys)]
    spawn_n = len(new_hosts) if added else 0
    pending_hosts = spawn_n
    msg = (
        f"本批 {len(raw_list)} 条 URL：同端口已有 {len(skipped_hosts)} 个主机（{len(skipped_dup)} 条）"
        + (f"，待处理 {len(pending_host_set)} 个主机" if pending_host_set else "")
        + (f"，新写入资产 {len(added)} 条" if added else "")
        + ("，将按同机合并补建/并入子项目" if added else "")
        + (f"，拒绝 {len(rejected)}" if rejected else "")
    )
    await emit(project_id, "log", {"level": "info", "message": msg})

    job = None
    importing = False
    if added or rejected:
        cfg["assets"] = existing_assets
        if rejected:
            prev_rej = list(cfg.get("assets_rejected") or [])
            cfg["assets_rejected"] = (prev_rej + [r["asset"] for r in rejected])[-50:]
        scope = dict(project.get("scope") or {})
        scope_targets_out: list[str] = []
        seen_t: set[str] = set()
        for a in existing_assets:
            info = _normalize_asset(a)
            h = preferred_host((info.get("host") or a) if info else a)
            if h and h not in seen_t:
                seen_t.add(h)
                scope_targets_out.append(h)
        scope["targets"] = scope_targets_out
        scope.setdefault("mode", "strict")
        scope.setdefault("allow_subdomains", False)
        await update_scope_and_config(project_id, scope, cfg)
    if added:
        job = schedule_cluster_import(
            project_id, auto_start=True, total_hint=max(spawn_n, len(pending_host_set)),
        )
        importing = True

    return {
        "added": added,
        "rejected": rejected,
        "skipped_dup": skipped_dup[:80],
        "skipped_dup_count": len(skipped_hosts),
        "skipped_dup_urls": len(skipped_dup),
        "pending_batch_hosts": len(pending_host_set),
        "assets_total": len(existing_assets),
        "pending_hosts": pending_hosts,
        "subprojects_created": 0,
        "subprojects": [],
        "importing": importing,
        "import_progress": job,
        "message": msg,
    }


async def refold_cluster_by_machine(project_id: str) -> dict:
    """把已有 idle/error 子项目按同 FQDN / 同 DNS IP 折成一台机。running 不动，不自动开跑。"""
    project = await get_project(project_id)
    if not project or project["kind"] != "cluster":
        return {"error": "非集群项目"}

    from .engine.scheduler import manager
    from .projects import delete_project

    subs = await list_subprojects(project_id)
    running_ids: set[str] = set()
    foldable: list[dict] = []
    for s in subs:
        sid = str(s.get("id") or "")
        if not sid:
            continue
        if manager.is_running(sid) or manager.is_queued(sid) or s.get("status") in ("running", "queued"):
            running_ids.add(sid)
            continue
        if s.get("status") not in ("idle", "error", "stopped", "completed"):
            continue
        foldable.append(s)

    by_host: dict[str, dict] = {}
    ports_by_host: dict[str, set[int]] = {}
    host_to_subs: dict[str, list[dict]] = {}
    for s in foldable:
        host = preferred_host(str(s.get("target") or ""))
        if not host:
            continue
        by_host.setdefault(host, {"host": host, "probe_url": (s.get("config") or {}).get("entry_url") or ""})
        ports_by_host.setdefault(host, set()).update(int(p) for p in (s.get("ports") or []) if p)
        host_to_subs.setdefault(host, []).append(s)
        for extra in ((s.get("scope") or {}).get("targets") or []) + ((s.get("config") or {}).get("vhosts") or []):
            h = preferred_host(str(extra or ""))
            if h and h not in by_host:
                by_host[h] = {"host": h, "probe_url": ""}
                host_to_subs.setdefault(h, []).append(s)

    objective = ((project.get("config") or {}).get("objective"))
    machines = await group_hosts_by_machine(by_host, ports_by_host, objective=objective)

    merged_groups = 0
    deleted: list[str] = []
    kept: list[str] = []
    skipped_running = 0
    for group in machines:
        members: list[dict] = []
        seen_ids: set[str] = set()
        for h in group.vhosts:
            for s in host_to_subs.get(h) or []:
                sid = str(s.get("id") or "")
                if sid and sid not in seen_ids:
                    seen_ids.add(sid)
                    members.append(s)
        if len(members) < 2:
            continue
        if any(str(s.get("id")) in running_ids for s in members):
            skipped_running += 1
            continue
        members.sort(key=lambda s: (
            -(len((s.get("scope") or {}).get("targets") or [])),
            float(s.get("created_at") or 0),
        ))
        canonical = members[0]
        await _absorb_group_into(canonical, group)
        kept.append(canonical["id"])
        merged_groups += 1
        for extra in members[1:]:
            eid = extra.get("id")
            if not eid or eid == canonical["id"]:
                continue
            try:
                await delete_project(eid)
                deleted.append(eid)
            except Exception as e:
                await emit(project_id, "log", {
                    "level": "warn",
                    "message": f"折叠时删除 {extra.get('target')} 失败：{e}",
                })
        alias = f"（同机 {len(group.vhosts)} 个域名）" if len(group.vhosts) > 1 else ""
        await emit(project_id, "log", {
            "level": "info",
            "message": f"已折叠到 {group.primary}{alias}，并入 {len(members) - 1} 个子项目",
        })

    summary = {
        "machines": len(machines),
        "merged_groups": merged_groups,
        "deleted": len(deleted),
        "kept": kept,
        "skipped_running": skipped_running,
        "foldable": len(foldable),
        "running_left": len(running_ids),
    }
    await emit(project_id, "status", {"status": "refolded", **summary})
    return summary
