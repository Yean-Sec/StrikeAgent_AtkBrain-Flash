"""跨项目厂商资产库。

导入只解析归并，不发请求、不派工人。项目只引用库里的行。
根域和同网段地址入库但不自动授权。全局拒绝名单里的目标不入库。
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

from .db import db, new_id, now
from atkbrain_native import _IP_RE, _norm_host, registrable_domain, sensitive_domain_reason

KINDS = ("root_domain", "subdomain", "ip", "service", "endpoint", "app")
_BODY_CAP = 200_000


def _loads(raw) -> dict:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        got = json.loads(raw or "{}")
    except Exception:
        return {}
    return got if isinstance(got, dict) else {}


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False)


def classify_host(host: str) -> tuple[str, str] | None:
    h = _norm_host(host)
    if not h:
        return None
    if _IP_RE.match(h):
        return "ip", h
    apex = registrable_domain(h) or h
    if h == apex:
        return "root_domain", h
    return "subdomain", h


def endpoint_identity(method: str, url: str) -> str | None:
    raw = (url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "http://" + raw
    try:
        u = urlparse(raw)
    except Exception:
        return None
    host = _norm_host(u.hostname or "")
    if not host:
        return None
    path = u.path or "/"
    query = f"?{u.query}" if u.query else ""
    port = f":{u.port}" if u.port else ""
    return f"{(method or 'GET').upper()} {u.scheme}://{host}{port}{path}{query}"


def _slash24(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    parts = str(addr).split(".")
    return ".".join(parts[:3])


async def ensure_vendor(name: str) -> dict:
    label = (name or "").strip() or "未命名厂商"
    row = await db.fetchone("SELECT * FROM vendors WHERE name=?", (label,))
    if row:
        return row
    vid = new_id("v_")
    ts = now()
    await db.execute(
        "INSERT INTO vendors(id, name, created_at, updated_at) VALUES(?,?,?,?)",
        (vid, label, ts, ts),
    )
    return await db.fetchone("SELECT * FROM vendors WHERE id=?", (vid,))


async def deny_reason(kind: str, identity: str) -> str | None:
    ident = (identity or "").strip().lower()
    host = ident
    if kind == "endpoint":
        host = _norm_host(urlparse(ident.split(" ", 1)[-1]).hostname or "")
    elif kind == "service":
        host = _norm_host(ident.split("|", 1)[0])
    if host and kind != "app":
        why = sensitive_domain_reason(host)
        if why:
            return why
    rows = await db.fetchall("SELECT pattern, reason FROM asset_denies")
    for row in rows:
        pat = _norm_host(str(row.get("pattern") or ""))
        if not pat:
            continue
        if ident == pat or ident.endswith("." + pat) or host == pat or host.endswith("." + pat):
            return str(row.get("reason") or "全局拒绝名单")
    return None


def _allow_ok(cfg: dict | None, identity: str) -> bool:
    allow = list((cfg or {}).get("asset_allow") or [])
    if not allow:
        return True
    norms = {_norm_host(str(x)) for x in allow if str(x or "").strip()}
    return _norm_host(identity) in norms


async def _same_subnet_blocked(project_id: str, ip: str, *, own: bool) -> bool:
    if own:
        return False
    block = _slash24(ip)
    if not block:
        return False
    rows = await db.fetchall(
        """SELECT a.identity FROM assets a
           JOIN project_assets pa ON pa.asset_id=a.id
           WHERE pa.project_id=? AND pa.in_scope=1 AND a.kind='ip'""",
        (project_id,),
    )
    for row in rows:
        other = str(row.get("identity") or "")
        if other == ip:
            return False
        if _slash24(other) == block:
            return True
    return False


async def upsert_asset(
    vendor_id: str,
    kind: str,
    identity: str,
    *,
    attrs: dict | None = None,
    project_id: str | None = None,
    in_scope: bool = False,
    basis: str | None = None,
    finding_id: str | None = None,
) -> dict | None:
    if kind not in KINDS:
        return None
    ident = (identity or "").strip()
    if kind in ("root_domain", "subdomain", "ip"):
        ident = _norm_host(ident)
    elif kind == "endpoint":
        ident = ident.strip()
    elif kind == "service":
        ident = ident.strip().lower()
    else:
        ident = ident.strip()
    if not ident:
        return None
    why = await deny_reason(kind, ident)
    if why:
        return None
    ts = now()
    row = await db.fetchone(
        "SELECT * FROM assets WHERE vendor_id=? AND kind=? AND identity=?",
        (vendor_id, kind, ident),
    )
    merged = _loads(row.get("attrs") if row else None)
    if attrs:
        merged.update({k: v for k, v in attrs.items() if v is not None})
    if row:
        await db.execute(
            "UPDATE assets SET attrs=?, updated_at=? WHERE id=?",
            (_dumps(merged), ts, row["id"]),
        )
        asset_id = row["id"]
    else:
        asset_id = new_id("a_")
        await db.execute(
            """INSERT INTO assets(id, vendor_id, kind, identity, attrs, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?)""",
            (asset_id, vendor_id, kind, ident, _dumps(merged), ts, ts),
        )
    if project_id:
        link = await db.fetchone(
            "SELECT in_scope FROM project_assets WHERE project_id=? AND asset_id=?",
            (project_id, asset_id),
        )
        scoped = 1 if in_scope or (link and int(link.get("in_scope") or 0)) else 0
        if in_scope:
            scoped = 1
        if link:
            await db.execute(
                """UPDATE project_assets SET in_scope=?, scope_basis=COALESCE(?, scope_basis),
                       confirmed_at=CASE WHEN ?=1 THEN COALESCE(confirmed_at, ?) ELSE confirmed_at END
                   WHERE project_id=? AND asset_id=?""",
                (scoped, basis, scoped, ts, project_id, asset_id),
            )
        else:
            await db.execute(
                """INSERT INTO project_assets(project_id, asset_id, in_scope, scope_basis, confirmed_at)
                   VALUES(?,?,?,?,?)""",
                (project_id, asset_id, scoped, basis, ts if scoped else None),
            )
    if finding_id:
        await db.execute(
            "INSERT OR IGNORE INTO finding_assets(finding_id, asset_id) VALUES(?,?)",
            (finding_id, asset_id),
        )
    return await db.fetchone("SELECT * FROM assets WHERE id=?", (asset_id,))


async def _project_cfg(project_id: str) -> tuple[dict, dict]:
    from atkbrain_native import get_project

    proj = get_project(project_id)
    if not proj:
        return {}, {}
    cfg = proj.get("config") if isinstance(proj.get("config"), dict) else {}
    return proj, cfg


async def _vendor_id_for(project_id: str, vendor_name: str | None = None) -> str:
    proj, cfg = await _project_cfg(project_id)
    existing = str((proj or {}).get("vendor_id") or "").strip()
    if existing and not vendor_name:
        return existing
    label = (vendor_name or cfg.get("vendor") or (proj or {}).get("target") or (proj or {}).get("name") or "").strip()
    vendor = await ensure_vendor(label)
    await db.execute(
        "UPDATE projects SET vendor_id=?, updated_at=? WHERE id=?",
        (vendor["id"], now(), project_id),
    )
    return vendor["id"]


async def _authorize_host(project_id: str, host: str) -> None:
    """把这一台已经授权的主机写进 Scope，不带上根域或 www。"""
    from atkbrain_native import Scope

    proj, _cfg = await _project_cfg(project_id)
    if not proj:
        return
    scope = Scope.from_dict(proj.get("scope") or {})
    kind = classify_host(host)
    if not kind:
        return
    k, ident = kind
    if k == "ip":
        if ident not in {_norm_host(x) for x in scope.ips}:
            scope.ips.append(ident)
    else:
        if ident not in {_norm_host(x) for x in scope.targets}:
            scope.targets.append(ident)
    await db.execute(
        "UPDATE projects SET scope=?, updated_at=? WHERE id=?",
        (_dumps(scope.to_dict()), now(), project_id),
    )


async def remember_host(
    project_id: str,
    host: str,
    *,
    in_scope: bool,
    vendor_name: str | None = None,
    finding_id: str | None = None,
    own_ip: bool = False,
    basis: str | None = None,
    attrs: dict | None = None,
) -> dict | None:
    kind = classify_host(host)
    if not kind:
        return None
    k, ident = kind
    _proj, cfg = await _project_cfg(project_id)
    vid = await _vendor_id_for(project_id, vendor_name)
    scoped = bool(in_scope) and _allow_ok(cfg, ident)
    if k == "ip" and scoped and await _same_subnet_blocked(project_id, ident, own=own_ip):
        scoped = False
    row = await upsert_asset(
        vid, k, ident, attrs=attrs, project_id=project_id,
        in_scope=scoped, basis=basis, finding_id=finding_id,
    )
    if k == "subdomain":
        apex = registrable_domain(ident)
        if apex and apex != ident:
            await upsert_asset(
                vid, "root_domain", apex, project_id=project_id, in_scope=False,
                finding_id=finding_id,
            )
    if row and scoped:
        await _authorize_host(project_id, ident)
    return row


async def seed_declared(
    project_id: str,
    hosts: list[str],
    ips: list[str] | None = None,
    *,
    vendor_name: str | None = None,
) -> None:
    """建项时只把用户写下的主机，以及这台主机自己的解析地址，标进范围。"""
    for host in hosts:
        await remember_host(project_id, host, in_scope=True, vendor_name=vendor_name, own_ip=True)
    for ip in ips or []:
        await remember_host(
            project_id, ip, in_scope=True, vendor_name=vendor_name, own_ip=True,
        )


def _hosts_in_text(text: str) -> list[str]:
    found: list[str] = []
    for match in re.findall(r"https?://[^\s\"'<>]+", text or "", flags=re.I):
        host = _norm_host(urlparse(match).hostname or "")
        if host and host not in found:
            found.append(host)
    return found


async def attach_finding_assets(
    project_id: str,
    finding_id: str,
    *,
    proof_url: str | None = None,
    evidence: str | None = None,
) -> None:
    """证明 URL 上的那台主机可以进范围；根域和同网段只入库。"""
    hosts = _hosts_in_text(proof_url or "")
    for host in hosts:
        await remember_host(project_id, host, in_scope=True, finding_id=finding_id)
        ident = endpoint_identity("GET", proof_url or "")
        if ident:
            vid = await _vendor_id_for(project_id)
            await upsert_asset(
                vid, "endpoint", ident, project_id=project_id, in_scope=False, finding_id=finding_id,
            )
    for host in _hosts_in_text(evidence or ""):
        if host in hosts:
            continue
        await remember_host(project_id, host, in_scope=False, finding_id=finding_id)
    verified = await db.fetchone(
        "SELECT verification_status FROM findings WHERE id=?",
        (finding_id,),
    )
    if verified and str(verified.get("verification_status") or "") == "verified":
        await db.execute(
            """UPDATE assets SET verified_at=COALESCE(verified_at, ?)
               WHERE id IN (SELECT asset_id FROM finding_assets WHERE finding_id=?)""",
            (now(), finding_id),
        )


async def import_text(
    text: str,
    *,
    vendor_name: str,
    project_id: str | None = None,
) -> dict:
    """纯解析。不发请求，不派工人，重复身份合并到同一行。"""
    vendor = await ensure_vendor(vendor_name)
    if project_id:
        await db.execute(
            "UPDATE projects SET vendor_id=?, updated_at=? WHERE id=?",
            (vendor["id"], now(), project_id),
        )
    raw = (text or "").strip()
    lines: list[str] = []
    if raw.startswith("[") or raw.startswith("{"):
        try:
            loaded = json.loads(raw)
        except Exception:
            loaded = None
        if isinstance(loaded, dict):
            loaded = loaded.get("assets") or loaded.get("hosts") or []
        if isinstance(loaded, list):
            for item in loaded:
                if isinstance(item, str):
                    lines.append(item)
                elif isinstance(item, dict):
                    lines.append(str(item.get("url") or item.get("host") or item.get("ip") or ""))
    if not lines:
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    stored = 0
    denied = 0
    for line in lines:
        piece = line.split(",")[0].strip()
        if not piece:
            continue
        method = "GET"
        url = piece
        if piece.upper().startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ")):
            method, url = piece.split(" ", 1)
        if "://" in url or url.startswith("/"):
            host = _norm_host(urlparse(url if "://" in url else "http://" + url).hostname or "")
            kind = classify_host(host) if host else None
            if kind:
                if await deny_reason(*kind):
                    denied += 1
                    continue
                if project_id:
                    await remember_host(project_id, host, in_scope=False, vendor_name=vendor["name"])
                else:
                    await upsert_asset(vendor["id"], kind[0], kind[1])
                    if kind[0] == "subdomain":
                        apex = registrable_domain(kind[1])
                        if apex and apex != kind[1]:
                            await upsert_asset(vendor["id"], "root_domain", apex, in_scope=False)
            ident = endpoint_identity(method, url if "://" in url else "")
            if ident:
                row = await upsert_asset(vendor["id"], "endpoint", ident, project_id=project_id, in_scope=False)
                if row:
                    stored += 1
            elif host:
                stored += 1
            continue
        if ":" in piece and not _IP_RE.match(piece):
            host_part, _, port = piece.rpartition(":")
            if port.isdigit() and classify_host(host_part):
                k, ident = classify_host(host_part)
                if await deny_reason(k, ident):
                    denied += 1
                    continue
                if project_id:
                    await remember_host(project_id, ident, in_scope=False, vendor_name=vendor["name"])
                else:
                    await upsert_asset(vendor["id"], k, ident)
                svc = f"{ident}|{int(port)}|tcp"
                row = await upsert_asset(vendor["id"], "service", svc, project_id=project_id, in_scope=False)
                if row:
                    stored += 1
                continue
        kind = classify_host(piece)
        if not kind:
            continue
        if await deny_reason(*kind):
            denied += 1
            continue
        if project_id:
            row = await remember_host(project_id, kind[1], in_scope=False, vendor_name=vendor["name"])
        else:
            row = await upsert_asset(vendor["id"], kind[0], kind[1])
            apex = registrable_domain(kind[1]) if kind[0] == "subdomain" else ""
            if apex and apex != kind[1]:
                await upsert_asset(vendor["id"], "root_domain", apex, in_scope=False)
        if row:
            stored += 1
    return {"vendor_id": vendor["id"], "stored": stored, "denied": denied}


async def untested_in_scope(project_id: str, limit: int = 20) -> list[dict]:
    rows = await db.fetchall(
        """SELECT a.kind, a.identity FROM assets a
           JOIN project_assets pa ON pa.asset_id=a.id
           WHERE pa.project_id=? AND pa.in_scope=1
             AND NOT EXISTS (
               SELECT 1 FROM finding_assets fa
               JOIN findings f ON f.id=fa.finding_id
               WHERE fa.asset_id=a.id AND f.verification_status='verified'
             )
           ORDER BY a.kind, a.identity
           LIMIT ?""",
        (project_id, limit),
    )
    return rows


async def untested_in_scope_count(project_id: str) -> int:
    row = await db.fetchone(
        """SELECT COUNT(*) AS n FROM assets a
           JOIN project_assets pa ON pa.asset_id=a.id
           WHERE pa.project_id=? AND pa.in_scope=1
             AND NOT EXISTS (
               SELECT 1 FROM finding_assets fa
               JOIN findings f ON f.id=fa.finding_id
               WHERE fa.asset_id=a.id AND f.verification_status='verified'
             )""",
        (project_id,),
    )
    return int((row or {}).get("n") or 0)


def format_untested_brief(rows: list[dict]) -> str:
    if not rows:
        return ""
    lines = [f"范围内未验证资产 {len(rows)}（派工分母，与扫描覆盖分开）："]
    for row in rows[:12]:
        lines.append(f"  - {row.get('kind')} {row.get('identity')}")
    return "\n".join(lines)


async def confirm_expansion(project_id: str, *, mode: str, basis: str, value: str = "") -> dict:
    """整域、整段、整家厂商必须单独确认，并写下依据。"""
    from atkbrain_native import Scope

    why = (basis or "").strip()
    if not why:
        raise ValueError("确认整域、整段或整家厂商必须写下依据")
    proj, cfg = await _project_cfg(project_id)
    if not proj:
        raise ValueError("项目不存在")
    scope = Scope.from_dict(proj.get("scope") or {})
    mode = (mode or "").strip().lower()
    vid = await _vendor_id_for(project_id)
    marked = 0
    if mode == "domain":
        apex = _norm_host(value)
        if not apex:
            raise ValueError("要确认的域名不能为空")
        scope.allow_subdomains = True
        if apex not in {_norm_host(x) for x in scope.targets}:
            scope.targets.append(apex)
        await upsert_asset(vid, "root_domain", apex, project_id=project_id, in_scope=True, basis=why)
        rows = await db.fetchall(
            """SELECT a.id, a.identity FROM assets a
               JOIN project_assets pa ON pa.asset_id=a.id
               WHERE pa.project_id=? AND a.kind IN ('root_domain','subdomain')""",
            (project_id,),
        )
        for row in rows:
            ident = _norm_host(str(row.get("identity") or ""))
            if ident == apex or ident.endswith("." + apex):
                await db.execute(
                    "UPDATE project_assets SET in_scope=1, scope_basis=?, confirmed_at=? WHERE project_id=? AND asset_id=?",
                    (why, now(), project_id, row["id"]),
                )
                marked += 1
    elif mode == "cidr":
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("网段格式无效") from exc
        cidr = str(net)
        if cidr not in scope.cidrs:
            scope.cidrs.append(cidr)
        rows = await db.fetchall(
            """SELECT a.id, a.identity FROM assets a
               JOIN project_assets pa ON pa.asset_id=a.id
               WHERE pa.project_id=? AND a.kind='ip'""",
            (project_id,),
        )
        for row in rows:
            try:
                addr = ipaddress.ip_address(str(row.get("identity") or ""))
            except ValueError:
                continue
            if addr in net:
                await db.execute(
                    "UPDATE project_assets SET in_scope=1, scope_basis=?, confirmed_at=? WHERE project_id=? AND asset_id=?",
                    (why, now(), project_id, row["id"]),
                )
                marked += 1
    elif mode == "vendor":
        rows = await db.fetchall(
            """SELECT a.id, a.kind, a.identity FROM assets a
               WHERE a.vendor_id=?""",
            (vid,),
        )
        for row in rows:
            await db.execute(
                """INSERT INTO project_assets(project_id, asset_id, in_scope, scope_basis, confirmed_at)
                   VALUES(?,?,1,?,?)
                   ON CONFLICT(project_id, asset_id) DO UPDATE SET
                     in_scope=1, scope_basis=excluded.scope_basis, confirmed_at=excluded.confirmed_at""",
                (project_id, row["id"], why, now()),
            )
            if row["kind"] in ("root_domain", "subdomain") and row["identity"] not in scope.targets:
                scope.targets.append(row["identity"])
            if row["kind"] == "ip" and row["identity"] not in scope.ips:
                scope.ips.append(row["identity"])
            marked += 1
    else:
        raise ValueError("mode 仅支持 domain、cidr、vendor")
    cfg = dict(cfg)
    cfg["scope_basis"] = why
    cfg["scope_expansion"] = {"mode": mode, "value": value, "basis": why}
    await db.execute(
        "UPDATE projects SET scope=?, config=?, updated_at=? WHERE id=?",
        (_dumps(scope.to_dict()), _dumps(cfg), now(), project_id),
    )
    return {"ok": True, "marked": marked, "mode": mode}


async def save_template(project_id: str, name: str) -> dict:
    from atkbrain_native import get_hunt_clocks

    proj, cfg = await _project_cfg(project_id)
    if not proj:
        raise ValueError("项目不存在")
    clocks = dict(get_hunt_clocks())
    extra = cfg.get("template_clocks")
    if isinstance(extra, dict):
        clocks.update(extra)
    chain = list(cfg.get("model_chain") or [])
    if cfg.get("model") and cfg.get("model") not in chain:
        chain = [cfg.get("model"), *chain]
    tid = new_id("tpl_")
    await db.execute(
        """INSERT INTO project_templates(id, name, track, clocks, model_chain, created_at)
           VALUES(?,?,?,?,?,?)""",
        (tid, (name or proj.get("name") or "模板").strip(),
         cfg.get("track") or cfg.get("objective") or "",
         _dumps(clocks), _dumps(chain), now()),
    )
    return {"id": tid, "name": name, "track": cfg.get("track"), "model_chain": chain}


async def template_config(template_id: str) -> dict:
    row = await db.fetchone("SELECT * FROM project_templates WHERE id=?", (template_id,))
    if not row:
        raise ValueError("模板不存在")
    try:
        clocks = json.loads(row.get("clocks") or "{}")
    except Exception:
        clocks = {}
    try:
        chain = json.loads(row.get("model_chain") or "[]")
    except Exception:
        chain = []
    raw_track = str(row.get("track") or "agent").lower()
    track = "ctf" if raw_track in ("ctf", "flag") else "agent"
    cfg = {
        "track": track,
        "objective": "flag" if track == "ctf" else "agent",
        "template_clocks": clocks if isinstance(clocks, dict) else {},
        "model_chain": chain if isinstance(chain, list) else [],
    }
    if cfg["model_chain"]:
        cfg["model"] = cfg["model_chain"][0]
        cfg["model_chain_index"] = 0
    return cfg
