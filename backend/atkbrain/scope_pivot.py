"""评测入口重绑时保留横向扩容的内网 IP；已验证 SSRF/shell 可把跳板看见的内网机扩进 Scope。"""
from __future__ import annotations

from typing import Any

from .scope import (
    Scope, _IP_RE, _norm_host, forbidden_project_target_reason, is_attacker_identity,
    is_internal_tld, is_loopback, is_platform_endpoint, is_private, is_single_label,
    local_self_hosts,
)


PIVOT_MECHANISMS = frozenset({
    "shell_reachable",
    "ssrf_direct",
    "ssrf_gopher",
    "ssrf_dns_rebind",
    "port_forward",
    "socks_tunnel",
    "dns_leak",
    "rdp_relay",
    "smb_relay",
})
SSRF_MECHANISMS = frozenset({"ssrf_direct", "ssrf_gopher", "ssrf_dns_rebind"})


def _is_internal_host(host: str) -> bool:
    h = _norm_host(host)
    if not h or is_loopback(h):
        return False
    return bool(is_private(h) or is_internal_tld(h) or is_single_label(h))


def _scope_add_ip(scope: Scope, host: str) -> None:
    h = _norm_host(host)
    if not h:
        return
    ips = scope.ips
    if isinstance(ips, set):
        ips.add(h)
        return
    if h not in ips:
        ips.append(h)


def ssrf_gateway_hosts(graph: dict | None) -> set[str]:
    """经 SSRF 扩容、攻击机网卡通常到不了的主机。与题型/具体路径无关。"""
    hosts: set[str] = set()
    if not graph:
        return hosts
    markers = tuple(SSRF_MECHANISMS)

    def _absorb(raw: str) -> None:
        h = (raw or "").strip().lower().split("/")[0].split(":")[0]
        if h and h not in ("localhost", "127.0.0.1"):
            hosts.add(h)

    for n in graph.get("nodes") or []:
        key = str(n.get("key") or "")
        if not key.startswith("info:scope-expanded:"):
            continue
        detail = str(n.get("detail") or "").lower()
        blob = f"{key} {n.get('title') or ''} {detail}"
        tags = n.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        tagset = {str(t).lower() for t in tags}
        via_ssrf = any(m in blob for m in markers) or "ssrf" in blob or any(
            str(t).startswith("ssrf") for t in tagset
        )
        if not via_ssrf:
            continue
        _absorb(key.split(":", 2)[-1])
        for t in tagset:
            if t.startswith("host:"):
                _absorb(t[5:])
    for e in graph.get("edges") or []:
        rel = str(e.get("relation") or "").upper()
        if rel and rel != "PIVOTS_TO":
            continue
        rat = str(e.get("rationale") or e.get("detail") or "").lower()
        if not any(m in rat for m in markers) and "ssrf" not in rat:
            continue
        dst = str(e.get("to") or e.get("dst") or "")
        if dst.startswith("target:"):
            _absorb(dst[7:])
        elif dst.startswith("info:host:"):
            _absorb(dst.split(":", 2)[-1])
        elif dst.startswith("info:scope-expanded:"):
            _absorb(dst.split(":", 2)[-1])
    return hosts


def merge_scope_keep_pivots(
    old: Scope,
    new: Scope,
    *,
    stale_entry_hosts: set[str] | None = None,
    reject_hosts: set[str] | None = None,
) -> Scope:
    stale = {_norm_host(h) for h in (stale_entry_hosts or ()) if h}
    reject = {_norm_host(h) for h in (reject_hosts or ()) if h}
    new_entry = {_norm_host(t) for t in (new.targets or [])}
    for raw in list(old.ips or []):
        h = _norm_host(str(raw))
        if not h or h in new.ips or h in stale or h in reject or h in new_entry:
            continue
        if not _is_internal_host(h):
            continue
        _scope_add_ip(new, h)
    for t in list(old.targets or []):
        h = _norm_host(str(t))
        if not h or h in new_entry or h in stale or h in reject:
            continue
        if not _IP_RE.match(h) or not _is_internal_host(h):
            continue
        _scope_add_ip(new, h)
    return new


async def peer_challenge_entry_addrs(project_id: str) -> set[str]:
    """同一评测父项目下，其它子题的入口 host:port。同 IP 不同端口也算邻题。

    本题自己的 container_addr 即使被写进邻题缓存，也不算邻题。
    """
    from .db import db as _db, _loads
    from .entry_fingerprint import project_entry_addrs, subtract_own_entries

    if not project_id:
        return set()
    row = await _db.fetchone("SELECT parent_id, target, ports, config FROM projects WHERE id=?", (project_id,))
    if not row or not row["parent_id"]:
        return set()
    own_proj = {
        "target": row["target"],
        "ports": row["ports"],
        "config": row["config"] if not isinstance(row["config"], str) else (_loads(row["config"]) or {}),
    }
    if isinstance(own_proj.get("ports"), str):
        own_proj["ports"] = _loads(own_proj["ports"]) or []
    if isinstance(own_proj.get("config"), str):
        own_proj["config"] = _loads(own_proj["config"]) or {}
    own = set(project_entry_addrs(own_proj))
    sibs = await _db.fetchall(
        "SELECT id, target, ports, config FROM projects WHERE parent_id=?",
        (row["parent_id"],),
    )
    out: set[str] = set()
    for s in sibs or []:
        if str(s["id"]) == str(project_id):
            continue
        host = _norm_host(str(s["target"] or "").split(":")[0])
        ports: list[int] = []
        raw_ports = s.get("ports")
        if isinstance(raw_ports, str):
            raw_ports = _loads(raw_ports) or []
        for p in raw_ports or []:
            try:
                n = int(p)
            except (TypeError, ValueError):
                continue
            if 1 <= n <= 65535:
                ports.append(n)
        cfg = s["config"]
        if isinstance(cfg, str):
            cfg = _loads(cfg) or {}
        if not isinstance(cfg, dict):
            cfg = {}
        for a in ((cfg.get("benchmark") or {}).get("container_addr") or []):
            raw = str(a or "").strip()
            h = _norm_host(raw.split(":")[0])
            if h and _IP_RE.match(h) and ":" in raw:
                try:
                    n = int(raw.rsplit(":", 1)[-1])
                except (TypeError, ValueError):
                    n = 0
                if 1 <= n <= 65535:
                    out.add(f"{h}:{n}")
            elif h and _IP_RE.match(h) and host and h != host:
                # 只有 IP、没有端口时仍记下，由 host 级闸处理
                pass
        if host and _IP_RE.match(host):
            for n in ports:
                out.add(f"{host}:{n}")
    return subtract_own_entries(out, own)


async def peer_challenge_entry_hosts(project_id: str) -> set[str]:
    from .db import db as _db, _loads
    from .entry_fingerprint import project_entry_hosts, subtract_own_hosts

    if not project_id:
        return set()
    row = await _db.fetchone("SELECT parent_id, target, ports, config FROM projects WHERE id=?", (project_id,))
    if not row or not row["parent_id"]:
        return set()
    own_proj = {
        "target": row["target"],
        "ports": row["ports"],
        "config": row["config"] if not isinstance(row["config"], str) else (_loads(row["config"]) or {}),
    }
    if isinstance(own_proj.get("ports"), str):
        own_proj["ports"] = _loads(own_proj["ports"]) or []
    if isinstance(own_proj.get("config"), str):
        own_proj["config"] = _loads(own_proj["config"]) or {}
    own_hosts = project_entry_hosts(own_proj)
    sibs = await _db.fetchall(
        "SELECT id, target, config FROM projects WHERE parent_id=?",
        (row["parent_id"],),
    )
    out: set[str] = set()
    for s in sibs or []:
        if str(s["id"]) == str(project_id):
            continue
        t = _norm_host(str(s["target"] or "").split(":")[0])
        if t and _IP_RE.match(t):
            out.add(t)
        cfg = s["config"]
        if isinstance(cfg, str):
            cfg = _loads(cfg) or {}
        if not isinstance(cfg, dict):
            cfg = {}
        for a in ((cfg.get("benchmark") or {}).get("container_addr") or []):
            h = _norm_host(str(a).split(":")[0])
            if h and _IP_RE.match(h):
                out.add(h)
    addrs = await peer_challenge_entry_addrs(project_id)
    out |= {_norm_host(a.split(":")[0]) for a in addrs}
    return subtract_own_hosts(out, own_hosts)


def _hosts_from_scope_node(key: str, tags: Any) -> list[str]:
    hosts: list[str] = []
    k = str(key or "")
    if k.startswith("info:scope-expanded:"):
        hosts.append(k.split(":", 2)[-1])
    elif k.startswith("info:host:"):
        hosts.append(k.split(":", 2)[-1])
    elif k.startswith("target:"):
        hosts.append(k.split(":", 1)[-1])
    if isinstance(tags, str):
        try:
            import json as _json
            tags = _json.loads(tags)
        except Exception:
            tags = [tags]
    for t in tags or []:
        s = str(t)
        if s.startswith("host:"):
            hosts.append(s[5:])
    return hosts


async def hydrate_scope_from_graph(
    project_id: str,
    scope: Scope,
    *,
    reject_hosts: set[str] | None = None,
) -> bool:
    from .db import db as _db

    if not project_id:
        return False
    rows = await _db.fetchall(
        "SELECT key, tags FROM nodes WHERE project_id=? AND key LIKE 'info:scope-expanded:%'",
        (project_id,),
    )
    reject = {_norm_host(h) for h in (reject_hosts or ()) if h}
    added = False
    for r in rows or []:
        for raw in _hosts_from_scope_node(r["key"], r["tags"] if "tags" in r.keys() else None):
            h = _norm_host(raw)
            if not h or h in reject or scope._explicit_member(h):
                continue
            if not _IP_RE.match(h) or not _is_internal_host(h):
                continue
            _scope_add_ip(scope, h)
            added = True
    return added


async def try_expand_scope(
    project_id: str,
    scope: Scope,
    *,
    from_host: str,
    to_host: str,
    mechanism: str,
    evidence: str = "",
    verified: bool = True,
    run_id: str | None = None,
    gstore: Any | None = None,
) -> dict:
    """已验证跳板把内网主机写入 Scope。邻题入口 / 本机 / 公网一律拒绝。"""
    src = _norm_host(from_host)
    dst = _norm_host(to_host)
    result = {"expanded": False, "reason": ""}
    if not dst:
        result["reason"] = "empty_target"
        return result
    if not src:
        result["reason"] = "missing_pivot_source"
        return result
    if mechanism and mechanism not in PIVOT_MECHANISMS:
        result["reason"] = f"unknown_mechanism:{mechanism}"
        return result
    if not verified:
        result["reason"] = "capability_not_verified"
        return result
    if is_attacker_identity(dst) or is_loopback(dst):
        result["reason"] = "attacker_or_loopback"
        return result
    if dst in {_norm_host(x) for x in local_self_hosts()}:
        result["reason"] = "attacker_or_loopback"
        return result
    forbid = forbidden_project_target_reason(dst)
    if forbid:
        result["reason"] = f"forbidden:{forbid}"
        return result
    if is_platform_endpoint(dst, None, self_hosts=local_self_hosts()):
        result["reason"] = "platform_endpoint"
        return result
    if not _is_internal_host(dst):
        result["reason"] = "not_internal_asset"
        return result
    try:
        peers = await peer_challenge_entry_hosts(project_id)
        if dst in peers:
            result["reason"] = "peer_challenge_entry"
            return result
    except Exception:
        pass
    if scope._explicit_member(dst):
        result["reason"] = "already_in_scope"
        return result
    if _IP_RE.match(dst):
        _scope_add_ip(scope, dst)
    else:
        if dst not in [t.lower() for t in scope.targets]:
            scope.targets.append(dst)
    result["expanded"] = True
    result["reason"] = f"pivot:{mechanism} via {src or '(unknown)'}"
    try:
        from .events import emit
        await emit(
            project_id, "log",
            {"level": "warn",
             "message": (
                 f"scope_expanded：内网资产 {dst} 已加入 Scope（{mechanism}，"
                 f"来自 {src or '未知跳板'}；仅授权当前项目内使用）。"
             )},
            run_id=run_id,
        )
    except Exception:
        pass
    try:
        if gstore is not None:
            from .graph.model import NodeIn
            await gstore.upsert_node(
                project_id,
                NodeIn(
                    key=f"info:scope-expanded:{dst}",
                    type="info",
                    title=f"内网资产 {dst} 加入 Scope",
                    detail=(
                        f"通过 {mechanism} 触发扩容；跳板：{src or '未知'}；"
                        f"证据摘要：{(evidence or '')[:280]}"
                    ),
                    tags=["scope", "pivot", f"host:{dst}", "internal"]
                    + (["ssrf"] if mechanism.startswith("ssrf") else []),
                ),
                run_id=run_id,
            )
    except Exception:
        pass
    return result


async def persist_scope(project_id: str, scope: Scope) -> None:
    try:
        from .db import db as _db
        import json as _json
        await _db.execute(
            "UPDATE projects SET scope=?, updated_at=strftime('%s','now') WHERE id=?",
            (_json.dumps(scope.to_dict(), ensure_ascii=False), project_id),
        )
    except Exception:
        pass
