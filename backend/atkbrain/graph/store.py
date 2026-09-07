"""攻击图仓储：节点/边/发现/意图的读写，图序列化，RCE 最优路径高亮。"""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections import defaultdict
from typing import Any

import networkx as nx

from ..db import db, new_id, now, _dumps, _loads
from ..events import emit
from ..objective import DATA_ACCESS_CATEGORIES, KEY_LEAK_CATEGORIES, USER_VISIBLE_SEVERITIES, listed_finding_rows
from .model import (
    CRITICAL_CATEGORIES,
    EdgeIn,
    FindingIn,
    IntentIn,
    NodeIn,
    coerce_goal_node_type,
    compute_risk_score,
    display_finding_severity,
    is_critical,
    normalize_redteam_rating,
    normalize_severity,
    scrub_candidate_rce_label,
)


# ---- 节点 -------------------------------------------------------------------

async def upsert_node(project_id: str, node: NodeIn, run_id: str | None = None) -> dict:
    orig_key = node.key
    node = await _coerce_intranet_target_node(project_id, node)
    coerced = coerce_goal_node_type(node.key, node.type, node.tags)
    if coerced != node.type:
        node = node.model_copy(update={"type": coerced})
    score = compute_risk_score(node.severity, node.type, node.is_rce)
    existing = await db.fetchone(
        "SELECT id FROM nodes WHERE project_id=? AND key=?", (project_id, node.key)
    )
    ts = now()
    detail = _dumps(node.detail)
    tags = _dumps(node.tags)
    created = False
    if existing:
        await db.execute(
            """UPDATE nodes SET type=?, title=?, detail=?, severity=?, is_rce=?,
                   risk_score=?, tags=?, status=?, updated_at=?
               WHERE project_id=? AND key=?""",
            (node.type, node.title, detail, node.severity, int(node.is_rce),
             score, tags, node.status, ts, project_id, node.key),
        )
        nid = existing["id"]
    else:
        created = True
        nid = new_id("n_")
        await db.execute(
            """INSERT INTO nodes(id, project_id, key, type, title, detail, severity,
                   is_rce, risk_score, tags, status, created_at, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (nid, project_id, node.key, node.type, node.title, detail, node.severity,
             int(node.is_rce), score, tags, node.status, ts, ts),
        )
    row = await db.fetchone("SELECT * FROM nodes WHERE id=?", (nid,))
    await emit(project_id, "node", _serialize_node(row), run_id=run_id)
    if orig_key and orig_key != node.key:
        leftover = await db.fetchone(
            "SELECT id FROM nodes WHERE project_id=? AND key=?", (project_id, orig_key)
        )
        if leftover:
            await _rewire_node_key(project_id, orig_key, node.key)
    await _autofinding_from_node(project_id, row, run_id)
    # 新建或更新非蜜罐节点时派生推理前沿（strategy_key 去重，不会无限膨胀）
    if node.type not in ("target", "honeypot"):
        await derive_intents_for_node(project_id, row, run_id=run_id)
    # 新主机上的任意发现落图后即补齐目标区域与横向链路，不必等 get_graph。
    # Redis 等服务常先于该主机的 shell 被发现，不能因此留下游离区域。
    if created and node.type != "target" and _host_of_node(node.key, node.tags):
        await ensure_lateral_pivots(project_id, run_id=run_id)
    # 智能体常 add_node 却忘了 add_edge：新建节点立刻补 CONTAINS，前端才能实时看到连线
    if created and node.type != "target":
        await ensure_target_attachments(project_id, run_id=run_id)
    return row


async def _autofinding_from_node(project_id: str, row: dict, run_id: str | None) -> None:
    """高危 vuln 节点自动沉淀为 finding（去重）。

    foothold/goal（getshell）不在此自动抬升——由 report_shell 落点。
    高危 vuln 节点自动沉淀为 finding，与 report_finding 去重。
    """
    from ..graph.model import SEVERITY_ORDER
    if row["type"] in ("foothold", "goal"):
        return
    if row["type"] != "vuln":
        return
    if not (bool(row["is_rce"]) or SEVERITY_ORDER.get(row["severity"], 0) >= SEVERITY_ORDER["high"]):
        return
    exists = await db.fetchone(
        "SELECT 1 FROM findings WHERE project_id=? AND node_key=?", (project_id, row["key"])
    )
    if exists:
        return
    tags = _loads(row["tags"]) or []
    category = _derive_category(row["type"], tags, bool(row["is_rce"]))
    await add_finding(
        project_id,
        FindingIn(
            node_key=row["key"],
            severity="critical" if bool(row["is_rce"]) else row["severity"],
            category=category,
            title=row["title"],
            description=(row["detail"] if isinstance(row["detail"], str) else None),
            evidence=(row["detail"] if isinstance(row["detail"], str) else None),
        ),
        run_id=run_id,
    )


def _derive_category(node_type: str, tags: list[str], is_rce: bool) -> str:
    tagset = {str(t).lower() for t in tags}
    known = ["rce", "command_injection", "deserialization", "sqli", "file_upload",
             "file_write", "file_read", "lfi", "ssrf", "auth_bypass", "unauth",
             "idor", "admin_access", "privilege_escalation", "xxe", "ssti", "xss"]
    for k in known:
        if k in tagset or any(k in t for t in tagset):
            return k
    if is_rce or node_type in ("foothold", "goal"):
        return "rce"
    return "vuln"


async def ensure_node(project_id: str, key: str, run_id: str | None = None) -> None:
    """边引用了尚不存在的节点时，惰性建占位节点。"""
    exists = await db.fetchone(
        "SELECT 1 FROM nodes WHERE project_id=? AND key=?", (project_id, key)
    )
    if not exists:
        await upsert_node(
            project_id, NodeIn(key=key, type="info", title=key), run_id=run_id
        )


# 游离组件挂回 target 时的根节点优先级（越靠前越适合作入口）
_ATTACH_ROOT_PRIORITY = {
    "service": 0,
    "danger": 1,
    "vuln": 2,
    "credential": 3,
    "foothold": 4,
    "goal": 5,
    "info": 6,
    "honeypot": 7,
}
_attaching_projects: set[str] = set()


# 只把漏洞/危险点改挂到 service/info；立足点/goal 仍走 target CONTAINS，避免交叉网。
_CHAIN_CHILD_TYPES = frozenset({"vuln", "danger"})
_CHAIN_PARENT_TYPES = ("service", "info")


def _node_tags(row) -> list:
    raw = row["tags"] if "tags" in row.keys() else None
    if isinstance(raw, list):
        return raw
    return _loads(raw) or []


def _prefer_chain_parent(
    *,
    root_key: str,
    root_type: str,
    root_tags,
    primary: str,
    reachable: set[str],
    by_key: dict,
) -> tuple[str, str] | None:
    """漏洞/危险点等优先挂到同机 service/info，而不是 target 直连。"""
    if root_type not in _CHAIN_CHILD_TYPES:
        return None
    host = _host_of_node(root_key, root_tags) or _host_from_target_key(primary)
    ranked: list[tuple[int, float, str]] = []
    for k in reachable:
        n = by_key.get(k)
        if not n:
            continue
        ntype = n["type"]
        if ntype not in _CHAIN_PARENT_TYPES:
            continue
        if ntype == root_type and k == root_key:
            continue
        ph = _host_of_node(k, _node_tags(n))
        if host and ph and ph != host:
            continue
        if host and not ph and ntype != "service":
            continue
        try:
            pri = _CHAIN_PARENT_TYPES.index(ntype)
        except ValueError:
            pri = 9
        ranked.append((pri, float(n["created_at"] or 0), k))
    if not ranked:
        return None
    ranked.sort()
    return ranked[0][2], "LEADS_TO"


async def _heal_target_vuln_shortcuts(project_id: str, run_id: str | None = None) -> int:
    """已有 target CONTAINS vuln 且同机已有 service/info → 改挂到父节点。"""
    nodes = await db.fetchall(
        "SELECT key, type, created_at, tags FROM nodes WHERE project_id=?", (project_id,)
    )
    by_key = {n["key"]: n for n in nodes}
    targets = {n["key"] for n in nodes if n["type"] == "target"}
    if not targets:
        return 0
    edges = await db.fetchall(
        "SELECT id, src, dst, relation FROM edges WHERE project_id=?", (project_id,)
    )
    adj: dict[str, set[str]] = {n["key"]: set() for n in nodes}
    for e in edges:
        if e["src"] in adj and e["dst"] in adj:
            adj[e["src"]].add(e["dst"])
            adj[e["dst"]].add(e["src"])
    reachable: set[str] = set()
    stack = list(targets)
    reachable.update(stack)
    i = 0
    while i < len(stack):
        for nb in adj.get(stack[i], ()):
            if nb not in reachable:
                reachable.add(nb)
                stack.append(nb)
        i += 1
    healed = 0
    for e in edges:
        if e["relation"] != "CONTAINS" or e["src"] not in targets:
            continue
        dst = by_key.get(e["dst"])
        if not dst or dst["type"] not in _CHAIN_CHILD_TYPES:
            continue
        parent = _prefer_chain_parent(
            root_key=dst["key"],
            root_type=dst["type"],
            root_tags=_node_tags(dst),
            primary=e["src"],
            reachable=reachable - {dst["key"]},
            by_key=by_key,
        )
        if not parent:
            continue
        pkey, rel = parent
        if pkey == e["dst"]:
            continue
        exists = await db.fetchone(
            "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
            (project_id, pkey, e["dst"], rel),
        )
        if not exists:
            eid = new_id("e_")
            rationale = f"系统改挂：漏洞/危险点经 {pkey} 进入攻击链，不再由 target 直连"
            await db.execute(
                """INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (eid, project_id, pkey, e["dst"], rel, 0.7, rationale, now()),
            )
            row = await db.fetchone("SELECT * FROM edges WHERE id=?", (eid,))
            await emit(project_id, "edge", _serialize_edge(row), run_id=run_id)
        await db.execute("DELETE FROM edges WHERE id=?", (e["id"],))
        await emit(
            project_id, "log",
            {"level": "info",
             "message": f"关系图改挂：去掉 {e['src']} → {e['dst']} 直连，改为经 {pkey}"},
            run_id=run_id,
        )
        healed += 1
        reachable.add(e["dst"])
    return healed


async def _entry_primary_target_key(project_id: str, targets: list) -> str:
    """挂边起点用当前入口主机，不用图上最早出现的 target（邻题 target 常更早）。"""
    row = await db.fetchone("SELECT target FROM projects WHERE id=?", (project_id,))
    host = str((row or {}).get("target") or "").split(":")[0].strip().lower().rstrip(".")
    keys = [t["key"] for t in targets]
    if host:
        want = f"target:{host}"
        if want in keys:
            return want
        for t in targets:
            blob = f"{t['key']} {t.get('title') or ''}".lower()
            if host in blob:
                return t["key"]
    return sorted(targets, key=lambda n: n["created_at"])[0]["key"]


async def _rehang_auto_edges_from_peer_targets(
    project_id: str, primary: str, *, run_id: str | None = None,
) -> int:
    """把误挂在邻题 target 上的本题节点改挂回当前入口。邻题自己的节点不动。"""
    from ..engine.supervisor_brief import plan_cites_peer_entry
    from ..scope_pivot import peer_challenge_entry_addrs, peer_challenge_entry_hosts

    try:
        addrs = list(await peer_challenge_entry_addrs(project_id) or [])
        hosts = set(await peer_challenge_entry_hosts(project_id) or [])
    except Exception:
        addrs, hosts = [], set()
    hosts |= {str(a).split(":")[0].strip().lower() for a in addrs if a}
    primary_host = _host_from_target_key(primary)
    hosts.discard(primary_host)
    try:
        from ..projects import get_project as _gp
        from ..entry_fingerprint import project_entry_hosts
        own = project_entry_hosts(await _gp(project_id))
        hosts -= {str(h).strip().lower() for h in own}
    except Exception:
        pass
    if not hosts:
        return 0
    nodes = await db.fetchall(
        "SELECT key, type, title, tags, detail FROM nodes WHERE project_id=?", (project_id,)
    )
    by_key = {n["key"]: n for n in nodes}
    edges = await db.fetchall(
        "SELECT id, src, dst, relation, rationale FROM edges "
        "WHERE project_id=? AND relation='CONTAINS'",
        (project_id,),
    )
    moved = 0
    for e in edges:
        src_host = _host_from_target_key(e["src"])
        if not src_host or src_host not in hosts:
            continue
        dst = by_key.get(e["dst"])
        if not dst:
            continue
        blob = " ".join([
            str(dst["key"] or ""), str(dst["title"] or ""),
            " ".join(str(t) for t in (_node_tags(dst))),
            str(dst["detail"] or "")[:200],
        ])
        if plan_cites_peer_entry(blob, addrs) or src_host in blob.lower():
            continue
        exists = await db.fetchone(
            "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
            (project_id, primary, e["dst"], "CONTAINS"),
        )
        await db.execute("DELETE FROM edges WHERE id=?", (e["id"],))
        if not exists and primary != e["dst"]:
            eid = new_id("e_")
            await db.execute(
                """INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (eid, project_id, primary, e["dst"], "CONTAINS", 0.55,
                 "系统改挂：游离发现从邻题入口改挂回本题入口", now()),
            )
            row = await db.fetchone("SELECT * FROM edges WHERE id=?", (eid,))
            await emit(project_id, "edge", _serialize_edge(row), run_id=run_id)
        moved += 1
    return moved


async def ensure_target_attachments(project_id: str, run_id: str | None = None) -> int:
    """把无法从 target 到达的节点/子图挂回攻击链。

    智能体常 add_node 却忘了 add_edge。服务挂回当前入口 target（CONTAINS）；
    漏洞/危险点优先挂到同机 service/info（LEADS_TO），避免 target 直连漏洞。
    挂边起点是项目当前入口，不是图上最早出现的 target。
    """
    if project_id in _attaching_projects:
        return 0
    _attaching_projects.add(project_id)
    try:
        nodes = await db.fetchall(
            "SELECT key, type, created_at, tags FROM nodes WHERE project_id=?", (project_id,)
        )
        if len(nodes) < 2:
            return 0
        targets = [n for n in nodes if n["type"] == "target"]
        if not targets:
            return 0
        primary = await _entry_primary_target_key(project_id, targets)
        added = await _rehang_auto_edges_from_peer_targets(
            project_id, primary, run_id=run_id,
        )
        edges = await db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=?", (project_id,)
        )
        adj: dict[str, set[str]] = {n["key"]: set() for n in nodes}
        for e in edges:
            if e["src"] in adj and e["dst"] in adj:
                adj[e["src"]].add(e["dst"])
                adj[e["dst"]].add(e["src"])

        reachable: set[str] = set()
        stack = [t["key"] for t in targets]
        for k in stack:
            reachable.add(k)
        i = 0
        while i < len(stack):
            for nb in adj.get(stack[i], ()):
                if nb not in reachable:
                    reachable.add(nb)
                    stack.append(nb)
            i += 1

        orphan_keys = {n["key"] for n in nodes if n["key"] not in reachable}
        by_key = {n["key"]: n for n in nodes}
        visited: set[str] = set()
        for seed in list(orphan_keys):
            if seed in visited:
                continue
            comp: list[str] = []
            queue = [seed]
            visited.add(seed)
            while queue:
                cur = queue.pop()
                comp.append(cur)
                for nb in adj.get(cur, ()):
                    if nb in orphan_keys and nb not in visited:
                        visited.add(nb)
                        queue.append(nb)
            root = min(
                comp,
                key=lambda k: (
                    _ATTACH_ROOT_PRIORITY.get(by_key[k]["type"], 9),
                    by_key[k]["created_at"],
                    k,
                ),
            )
            if root == primary:
                continue
            root_node = by_key[root]
            if root_node["type"] == "target":
                continue
            preferred = _prefer_chain_parent(
                root_key=root,
                root_type=root_node["type"],
                root_tags=_node_tags(root_node),
                primary=primary,
                reachable=reachable,
                by_key=by_key,
            )
            if preferred:
                src, relation = preferred
                weight, rationale = 0.7, f"系统自动补边：经 {src} 挂入攻击链"
            else:
                src, relation = primary, "CONTAINS"
                weight, rationale = 0.55, "系统自动补边：将游离发现挂回目标起点"
            exists = await db.fetchone(
                "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
                (project_id, src, root, relation),
            )
            if exists:
                reachable.add(root)
                orphan_keys.discard(root)
                continue
            eid = new_id("e_")
            await db.execute(
                """INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (eid, project_id, src, root, relation, weight, rationale, now()),
            )
            row = await db.fetchone("SELECT * FROM edges WHERE id=?", (eid,))
            await emit(project_id, "edge", _serialize_edge(row), run_id=run_id)
            adj.setdefault(src, set()).add(root)
            adj.setdefault(root, set()).add(src)
            reachable.add(root)
            orphan_keys.discard(root)
            added += 1
        healed = await _heal_target_vuln_shortcuts(project_id, run_id=run_id)
        added += healed
        if added:
            await recompute_rce_path(project_id, run_id=run_id)
        added += await ensure_lateral_pivots(project_id, run_id=run_id)
        return added
    finally:
        _attaching_projects.discard(project_id)


_HOST_AT_RE = re.compile(
    r"@((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[\w.-]{0,251}[A-Za-z0-9])?)$"
)
_IPV4_RE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?![\d.])"
)
_pivoting_projects: set[str] = set()


def _host_of_node(key: str, tags) -> str:
    """优先 tags 里的 host:；否则从 key 的 @host 后缀、资产键或 key 内嵌 IPv4 解析。"""
    h = _host_from_tags(tags)
    if h:
        return h
    m = _HOST_AT_RE.search(key or "")
    if m:
        return m.group(1).lower().rstrip(".")
    h = _host_from_asset_key(key)
    if h:
        return h
    m2 = _IPV4_RE.search(key or "")
    if m2:
        return m2.group(0).lower().rstrip(".")
    return ""


def _host_from_target_key(key: str) -> str:
    if not key:
        return ""
    if key.startswith("target:"):
        rest = key.split(":", 1)[1]
        # target:10.0.185.96 或 target:10.0.185.96:80
        host = rest.split(":")[0].strip().lower().rstrip(".")
        return host
    return ""


def _host_from_asset_key(key: str) -> str:
    """入口 target:IP、内网 info:host:IP / info:scope-expanded:IP 上的主机。"""
    k = str(key or "")
    host = _host_from_target_key(k)
    if host:
        return host
    if k.startswith("info:host:") or k.startswith("info:scope-expanded:"):
        rest = k.split(":", 2)[-1]
        return rest.split(":")[0].strip().lower().rstrip(".")
    return ""


_DASH_OCTETS_RE = re.compile(r"(?<![\d-])(\d{1,3}(?:-\d{1,3}){3})(?![\d])")


def _is_rfc1918(host: str) -> bool:
    parts = (host or "").strip().lower().rstrip(".").split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    a, b = nums[0], nums[1]
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def _same_slash24(a: str, b: str) -> bool:
    pa = (a or "").strip().lower().split(".")
    pb = (b or "").strip().lower().split(".")
    return len(pa) == 4 and len(pb) == 4 and pa[:3] == pb[:3]


def _is_intranet_asset_host(host: str, tags: list | None = None) -> bool:
    """本题内网/同机资产：RFC1918 或横向/vhost 标签。入口换址残留与邻题入口另判。"""
    tags_l = {str(t).lower() for t in (tags or [])}
    if "entry" in tags_l:
        return False
    if tags_l & {"lateral", "pivot", "vhost", "same-machine", "internal", "scope-expanded"}:
        return True
    return _is_rfc1918(host)


async def _project_entry_host(project_id: str) -> str:
    row = await db.fetchone("SELECT target FROM projects WHERE id=?", (project_id,))
    return str((row or {}).get("target") or "").split(":")[0].strip().lower().rstrip(".")


async def _is_peer_entry_host(project_id: str, host: str) -> bool:
    host = (host or "").strip().lower().split(":")[0].rstrip(".")
    if not host:
        return False
    try:
        from ..scope_pivot import peer_challenge_entry_hosts
        peers = await peer_challenge_entry_hosts(project_id) or set()
    except Exception:
        peers = set()
    return host in {str(p or "").split(":")[0].strip().lower().rstrip(".") for p in peers}


async def _coerce_intranet_target_node(project_id: str, node: NodeIn) -> NodeIn:
    """内网 IP 不得另开黑色 target：改挂为本题入口下的 info:host 资产。"""
    tags = list(node.tags or [])
    host = _host_from_asset_key(node.key) or _host_of_node(node.key, tags)
    if node.type != "target" and not str(node.key or "").startswith("target:"):
        return node
    if not host:
        return node
    primary = await _project_entry_host(project_id)
    if primary and host == primary:
        return node
    if await _is_peer_entry_host(project_id, host):
        return node
    if not _is_intranet_asset_host(host, tags):
        return node
    for t in ("internal", "pivot", f"host:{host}"):
        if t not in tags:
            tags.append(t)
    return node.model_copy(update={
        "type": "info",
        "key": f"info:host:{host}",
        "tags": tags,
        "title": node.title or f"内网主机 {host}",
    })


_folding_projects: set[str] = set()


async def fold_intranet_targets(project_id: str, run_id: str | None = None) -> int:
    """把误建成 type=target 的内网 IP 并入本题唯一入口目标。"""
    if not project_id or project_id in _folding_projects:
        return 0
    primary = await _project_entry_host(project_id)
    if not primary:
        return 0
    primary_key = f"target:{primary}"
    _folding_projects.add(project_id)
    folded = 0
    try:
        rows = await db.fetchall(
            "SELECT key, type, tags, title FROM nodes WHERE project_id=? AND key LIKE 'target:%'",
            (project_id,),
        )
        for r in rows:
            key = r["key"]
            if key == primary_key:
                continue
            host = _host_from_target_key(key)
            if not host or host == primary:
                continue
            if await _is_peer_entry_host(project_id, host):
                continue
            tags = _loads(r["tags"]) if not isinstance(r["tags"], list) else r["tags"]
            tags = tags or []
            if not _is_intranet_asset_host(host, tags):
                continue
            ikey = f"info:host:{host}"
            if key == ikey:
                if r["type"] == "target":
                    await db.execute(
                        "UPDATE nodes SET type='info', updated_at=? WHERE project_id=? AND key=?",
                        (now(), project_id, key),
                    )
                    folded += 1
                continue
            existing = await db.fetchone(
                "SELECT key FROM nodes WHERE project_id=? AND key=?",
                (project_id, ikey),
            )
            if not existing:
                await upsert_node(
                    project_id,
                    NodeIn(
                        key=ikey,
                        type="info",
                        title=(r["title"] or f"内网主机 {host}"),
                        detail=f"本题内网资产 {host}",
                        severity="info",
                        tags=["internal", "pivot", f"host:{host}"],
                    ),
                    run_id=run_id,
                )
            await _rewire_node_key(project_id, key, ikey)
            if await _insert_edge_once(
                project_id, primary_key, ikey, "CONTAINS",
                weight=0.8,
                rationale=f"内网资产 {host} 属于入口目标 {primary}",
                run_id=run_id,
            ):
                pass
            folded += 1
        return folded
    finally:
        _folding_projects.discard(project_id)


def _canon_host_fragment(host: str) -> str:
    """与 hypothesize._canon_source 一致：octet 按字符串排序，得到 0-10-189-58。"""
    parts = [p for p in (host or "").strip().lower().rstrip(".").split(".") if p]
    return "-".join(sorted(parts)) if len(parts) == 4 else ""


def _mentions_host(text: str, host: str, *, allow_octet_shorthand: bool = False) -> bool:
    """全文是否点名该主机：点分 IP、原始连字符、strategy_key 排序连字符。

    不用共享前缀（10.0.189）匹配，避免把 .56 和 .58 当成同一个。
    allow_octet_shorthand：换址残留 Intent 常写「.58 与 .56 为同一应用」。
    """
    blob = text or ""
    host = (host or "").strip().lower().split(":")[0].rstrip(".")
    if not blob or not host:
        return False
    dotted = re.escape(host)
    dashed = re.escape(host.replace(".", "-"))
    frag = re.escape(_canon_host_fragment(host)) if _canon_host_fragment(host) else ""
    parts = [rf"(?<![\d.]){dotted}(?![\d.])", rf"(?<![\d-]){dashed}(?![\d])"]
    if frag:
        parts.append(rf"(?<![\d-]){frag}(?![\d])")
    last = host.rsplit(".", 1)[-1]
    if allow_octet_shorthand and last.isdigit():
        parts.append(rf"(?<![\d.])\.{last}(?!\d)")
    return bool(re.search("|".join(parts), blob, re.I))


def _private_hosts_in_text(text: str) -> set[str]:
    """从描述/策略键抽出内网 IPv4；连字符四段按 octet 还原不出顺序时只收点分形式。"""
    blob = text or ""
    out: set[str] = set()
    for m in _IPV4_RE.findall(blob):
        h = m.lower().rstrip(".")
        if _is_rfc1918(h):
            out.add(h)
    return out


def _absent_canon_fragments(text: str, live_frags: set[str]) -> bool:
    """strategy_key 形如 0-10-189-58-target，且这段 octet 不是任何仍存活主机。

    必须紧挨 target，避免把 80-443-8080-8443 这类端口串当成旧 IP。
    """
    blob = text or ""
    for m in _DASH_OCTETS_RE.finditer(blob):
        frag = m.group(1)
        nums = frag.split("-")
        try:
            if any(int(n) > 255 for n in nums):
                continue
        except ValueError:
            continue
        if frag in live_frags:
            continue
        after = blob[m.end(): m.end() + 16].lstrip("-:")
        before = blob[max(0, m.start() - 16): m.start()].lower()
        if after.lower().startswith("target") or "target" in before:
            return True
    return False


async def ensure_host_target(
    project_id: str, host: str, *, title: str = "", run_id: str | None = None,
) -> str:
    """确保主机在图上有节点。入口仍是唯一黑色 target；内网 IP 挂成 info 资产。"""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    primary = await _project_entry_host(project_id)
    if primary and host == primary:
        tkey = f"target:{host}"
        existing = await db.fetchone(
            "SELECT id FROM nodes WHERE project_id=? AND key=?", (project_id, tkey)
        )
        if not existing:
            await upsert_node(
                project_id,
                NodeIn(
                    key=tkey,
                    type="target",
                    title=title or f"目标 {host}",
                    detail=f"入口 {host}",
                    severity="info",
                    tags=["entry", f"host:{host}"],
                ),
                run_id=run_id,
            )
        return tkey
    if await _is_peer_entry_host(project_id, host):
        return ""
    ikey = f"info:host:{host}"
    for cand in (f"info:host:{host}", f"info:scope-expanded:{host}"):
        existing = await db.fetchone(
            "SELECT key FROM nodes WHERE project_id=? AND key=?", (project_id, cand)
        )
        if existing:
            ikey = cand
            break
    else:
        await upsert_node(
            project_id,
            NodeIn(
                key=ikey,
                type="info",
                title=title or f"内网主机 {host}",
                detail=f"本题内网资产 {host}",
                severity="info",
                tags=["internal", "pivot", "lateral", f"host:{host}"],
            ),
            run_id=run_id,
        )
    if primary:
        await _insert_edge_once(
            project_id, f"target:{primary}", ikey, "CONTAINS",
            weight=0.8,
            rationale=f"内网资产 {host} 属于入口目标 {primary}",
            run_id=run_id,
        )
    old = f"target:{host}"
    leftover = await db.fetchone(
        "SELECT id FROM nodes WHERE project_id=? AND key=?", (project_id, old)
    )
    if leftover and old != ikey:
        await _rewire_node_key(project_id, old, ikey)
        if primary:
            await _insert_edge_once(
                project_id, f"target:{primary}", ikey, "CONTAINS",
                weight=0.8,
                rationale=f"内网资产 {host} 属于入口目标 {primary}",
                run_id=run_id,
            )
    return ikey


def _is_entry_target_row(row) -> bool:
    tags = _loads(row["tags"]) if not isinstance(row["tags"], list) else row["tags"]
    tags = tags or []
    if any(t in tags for t in ("lateral", "pivot", "vhost", "same-machine")):
        return False
    return "entry" in tags or not tags


async def _rewire_node_key(project_id: str, old_key: str, new_key: str) -> int:
    """把 old_key 上的边改挂到 new_key，并删掉旧节点。"""
    if not old_key or not new_key or old_key == new_key:
        return 0
    edges = await db.fetchall(
        "SELECT id, src, dst, relation FROM edges WHERE project_id=? AND (src=? OR dst=?)",
        (project_id, old_key, old_key),
    )
    moved = 0
    for e in edges:
        nsrc = new_key if e["src"] == old_key else e["src"]
        ndst = new_key if e["dst"] == old_key else e["dst"]
        if nsrc == ndst:
            await db.execute("DELETE FROM edges WHERE id=?", (e["id"],))
            moved += 1
            continue
        dup = await db.fetchone(
            "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
            (project_id, nsrc, ndst, e["relation"]),
        )
        if dup:
            await db.execute("DELETE FROM edges WHERE id=?", (e["id"],))
        else:
            await db.execute("UPDATE edges SET src=?, dst=? WHERE id=?", (nsrc, ndst, e["id"]))
        moved += 1
    await db.execute(
        "UPDATE findings SET node_key=? WHERE project_id=? AND node_key=?",
        (new_key, project_id, old_key),
    )
    await db.execute("DELETE FROM nodes WHERE project_id=? AND key=?", (project_id, old_key))
    return moved


async def adopt_entry_host(
    project_id: str, host: str, *, scope_detail: Any = None, run_id: str | None = None,
    keep_hosts: set[str] | None = None,
) -> dict:
    """评测容器换 IP 后，旧入口不是第二台主机：把 entry target 并到当前地址。

    keep_hosts：本题当前仍活着的入口（全部 container_addr），不要并进 primary。
    """
    host = (host or "").strip().lower().split(":")[0].rstrip(".")
    if not host:
        return {"entry": "", "retired": [], "deferred": 0}
    keep = {
        (h or "").strip().lower().split(":")[0].rstrip(".")
        for h in (keep_hosts or ()) if h
    }
    keep.discard("")
    new_key = f"target:{host}"
    existing = await db.fetchone(
        "SELECT key FROM nodes WHERE project_id=? AND key=?", (project_id, new_key)
    )
    rows = await db.fetchall(
        "SELECT key, tags FROM nodes WHERE project_id=? AND type='target'",
        (project_id,),
    )
    extras = []
    for n in rows:
        if n["key"] == new_key:
            continue
        if not _is_entry_target_row(n):
            continue
        other = _host_from_target_key(n["key"])
        if other and other in keep:
            continue
        extras.append(n)
    retired: list[str] = []
    if not existing:
        await upsert_node(
            project_id,
            NodeIn(
                key=new_key, type="target", title=f"目标 {host}",
                detail=scope_detail if scope_detail is not None else f"入口 {host}",
                severity="info", tags=["entry"],
            ),
            run_id=run_id,
        )
    for n in extras:
        await _rewire_node_key(project_id, n["key"], new_key)
        retired.append(n["key"])
    if retired:
        await emit(
            project_id, "log",
            {"level": "info",
             "message": f"入口换址：{', '.join(retired)} 并入 {new_key}（同一容器，不是新主机）"},
            run_id=run_id,
        )
        await recompute_rce_path(project_id, run_id=run_id)
    old_hosts = [h for h in (_host_from_target_key(k) for k in retired) if h]
    deferred = await defer_intents_for_absent_entry_hosts(
        project_id, host, extra_hosts=old_hosts, run_id=run_id,
    )
    return {"entry": new_key, "retired": retired, "deferred": deferred}


async def _live_graph_hosts(project_id: str) -> set[str]:
    """仍作为独立主机存在的地址：入口 target、内网资产节点、立足点/shell。

    换址后残留的普通 service/info 仍可能带着旧 host 标签，那些不是第二台主机。
    """
    rows = await db.fetchall(
        """SELECT key, type, tags FROM nodes
           WHERE project_id=? AND (
             type IN ('target','foothold','goal')
             OR key LIKE 'info:host:%'
             OR key LIKE 'info:scope-expanded:%'
           )""",
        (project_id,),
    )
    live: set[str] = set()
    for r in rows:
        tags = _loads(r["tags"]) if not isinstance(r["tags"], list) else r["tags"]
        h = _host_of_node(r["key"], tags or []) or _host_from_asset_key(r["key"])
        if h:
            live.add(h)
    return live


async def defer_intents_for_absent_entry_hosts(
    project_id: str,
    current_host: str,
    *,
    extra_hosts: list[str] | None = None,
    run_id: str | None = None,
) -> int:
    """搁置仍指向已换走入口 IP 的 open/active Intent。"""
    current_host = (current_host or "").strip().lower().split(":")[0].rstrip(".")
    if not current_host:
        return 0
    extra = {
        (h or "").strip().lower().split(":")[0].rstrip(".")
        for h in (extra_hosts or [])
        if h
    }
    extra.discard(current_host)
    extra.discard("")
    live = await _live_graph_hosts(project_id)
    live.add(current_host)
    leftover_rows = await db.fetchall(
        "SELECT key, tags FROM nodes WHERE project_id=?", (project_id,)
    )
    for r in leftover_rows:
        tags = _loads(r["tags"]) if not isinstance(r["tags"], list) else r["tags"]
        h = _host_of_node(r["key"], tags or [])
        # 只收「入口同网段残留」，不要把 SSRF 看见的容器网 IP 当成换址旧入口。
        if h and h not in live and _same_slash24(h, current_host):
            extra.add(h)
    live_frags = {_canon_host_fragment(h) for h in live if _canon_host_fragment(h)}
    rows = await db.fetchall(
        """SELECT id, strategy_key, description, rationale, from_keys
           FROM intents WHERE project_id=? AND status IN ('open','active')""",
        (project_id,),
    )
    n = 0
    reason = f"入口换址：旧地址不是新主机，当前入口 {current_host}"
    for r in rows:
        blob = " ".join(
            str(r.get(k) or "")
            for k in ("strategy_key", "description", "rationale", "from_keys")
        )
        hit = any(_mentions_host(blob, h, allow_octet_shorthand=True) for h in extra)
        if not hit:
            for ip in _private_hosts_in_text(blob):
                if ip == current_host or ip in live:
                    continue
                if ip in extra or _same_slash24(ip, current_host):
                    hit = True
                    break
        if not hit and _absent_canon_fragments(blob, live_frags):
            hit = True
        if not hit:
            continue
        await set_intent_status(
            project_id, r["id"], "deferred",
            result_summary=reason, failure_fingerprint=reason, run_id=run_id,
        )
        n += 1
    if n:
        await emit(
            project_id, "log",
            {"level": "info",
             "message": f"入口换址：已搁置 {n} 条仍指向旧地址的 Intent（当前入口 {current_host}）"},
            run_id=run_id,
        )
    return n


_LOCAL_CLOSEOUT_TACS = frozenset({
    "flag_hunt", "finding_rce_close", "read_to_creds",
    "finding_sqli_chain", "flag_or_privesc",
})


async def _intranet_hop_hosts(project_id: str) -> set[str]:
    entry = await _project_entry_host(project_id)
    live = await _live_graph_hosts(project_id)
    hops: set[str] = set()
    for h in live:
        if not h or h == entry or not _is_rfc1918(h):
            continue
        if await _is_peer_entry_host(project_id, h):
            continue
        hops.add(h)
    return hops


async def reopen_live_hop_auth(project_id: str, run_id: str | None = None) -> int:
    """入口换址误把容器网身份面对偶搁置时，主机仍在图上则重新开放。"""
    hops = await _intranet_hop_hosts(project_id)
    if not hops:
        return 0
    rows = await db.fetchall(
        """SELECT id, strategy_key, description, rationale, from_keys FROM intents
           WHERE project_id=? AND status='deferred'
             AND (
               IFNULL(strategy_key,'') LIKE '%hop_auth%'
               OR IFNULL(strategy_key,'') LIKE '%access_control%'
             )""",
        (project_id,),
    )
    n = 0
    reason = "内网主机仍在图上：恢复过门与未授权对偶"
    for r in rows:
        blob = " ".join(
            str(r.get(k) or "")
            for k in ("strategy_key", "description", "rationale", "from_keys")
        )
        if not any(_mentions_host(blob, h) for h in hops):
            continue
        await set_intent_status(
            project_id, r["id"], "open",
            result_summary=reason, run_id=run_id,
        )
        n += 1
    return n


_ADVISOR_DEFER_MARKS: tuple[str, ...] = (
    "ai-supervisor defer family=",
    "advisor-bind deny family=",
)


async def reopen_advisor_deferred_tactics(
    project_id: str,
    tactics: tuple[str, ...] | list[str],
    *,
    run_id: str | None = None,
) -> int:
    """顾问误把利用下一跳整族搁置时，只恢复带顾问 defer 标记的 Intent。

    不碰规则刷新搁置的过时 tactic（例如 SSRF 上的 weaponize）。
    """
    want = {str(t).strip() for t in (tactics or ()) if str(t).strip()}
    if not want:
        return 0
    rows = await db.fetchall(
        """SELECT id, strategy_key, result_summary, failure_fingerprint FROM intents
           WHERE project_id=? AND status='deferred'""",
        (project_id,),
    )
    n = 0
    reason = "已验证资产尚未立足：恢复顾问误搁置的利用下一跳"
    for r in rows:
        sk = str(r.get("strategy_key") or "")
        tac = sk.split("::")[-1] if "::" in sk else sk
        if tac not in want:
            continue
        blob = f"{r.get('result_summary') or ''} {r.get('failure_fingerprint') or ''}"
        if not any(m in blob for m in _ADVISOR_DEFER_MARKS):
            continue
        await set_intent_status(
            project_id, r["id"], "open",
            result_summary=reason, run_id=run_id,
        )
        n += 1
    return n


_ORACLE_REOPEN_TACTICS: frozenset[str] = frozenset({"channel_oracle", "input_abuse"})


async def reopen_false_closed_oracle(
    project_id: str,
    *,
    needs_oracle: bool,
    run_id: str | None = None,
) -> int:
    """图上输入面未关时，状态码/正文矩阵不能把换通道 Intent 写成否证。"""
    if not needs_oracle:
        return 0
    rows = await db.fetchall(
        """SELECT id, strategy_key FROM intents
           WHERE project_id=? AND status='disproved'""",
        (project_id,),
    )
    n = 0
    reason = "单通道否证不能关闭输入面：复开换观测通道"
    for r in rows:
        sk = str(r.get("strategy_key") or "")
        tac = sk.split("::")[-1] if "::" in sk else sk
        if tac not in _ORACLE_REOPEN_TACTICS:
            continue
        await set_intent_status(
            project_id, r["id"], "open",
            result_summary=reason, run_id=run_id,
        )
        n += 1
    return n


async def defer_local_closeout_for_remaining_flags(
    project_id: str, run_id: str | None = None,
) -> int:
    """本机已交过 flag、图上还有其它内网 hop、总数未齐：本机 flag_hunt/再读文件让路。"""
    hops = await _intranet_hop_hosts(project_id)
    if not hops:
        return 0
    row = await db.fetchone(
        "SELECT config FROM projects WHERE id=?", (project_id,)
    )
    cfg = _loads((row or {}).get("config")) or {}
    needed = int(cfg.get("flag_count") or 0)
    if needed <= 1:
        return 0
    got_row = await db.fetchone(
        "SELECT COUNT(*) AS n FROM flags WHERE project_id=? AND correct=1",
        (project_id,),
    )
    got = int((got_row or {}).get("n") or 0)
    if got <= 0 or got >= needed:
        return 0
    entry = await _project_entry_host(project_id)
    rows = await db.fetchall(
        """SELECT id, strategy_key, description, rationale, from_keys, status
           FROM intents WHERE project_id=? AND status IN ('open','active')""",
        (project_id,),
    )
    n = 0
    reason = "本机 flag 已交、剩余在邻机：搁置本机收口，改打邻机身份面（过门与未授权并行）"
    for r in rows:
        sk = str(r.get("strategy_key") or "")
        tac = sk.split("::")[-1] if "::" in sk else sk
        if tac not in _LOCAL_CLOSEOUT_TACS:
            continue
        blob = " ".join(
            str(r.get(k) or "")
            for k in ("strategy_key", "description", "rationale", "from_keys")
        )
        if any(_mentions_host(blob, h) for h in hops):
            continue
        await set_intent_status(
            project_id, r["id"], "deferred",
            result_summary=reason, failure_fingerprint=reason, run_id=run_id,
        )
        n += 1
    if n:
        await emit(
            project_id, "log",
            {"level": "info",
             "message": f"剩余 flag：已搁置 {n} 条本机收口 Intent，优先 hop_auth（入口 {entry}）"},
            run_id=run_id,
        )
    return n


async def _insert_edge_once(
    project_id: str, src: str, dst: str, relation: str, *,
    weight: float = 0.9, rationale: str = "", run_id: str | None = None,
) -> bool:
    if not src or not dst or src == dst:
        return False
    exists = await db.fetchone(
        "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
        (project_id, src, dst, relation),
    )
    if exists:
        return False
    # 端点必须存在
    for k in (src, dst):
        if not await db.fetchone(
            "SELECT 1 FROM nodes WHERE project_id=? AND key=?", (project_id, k)
        ):
            return False
    eid = new_id("e_")
    await db.execute(
        """INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (eid, project_id, src, dst, relation, weight, rationale, now()),
    )
    row = await db.fetchone("SELECT * FROM edges WHERE id=?", (eid,))
    await emit(project_id, "edge", _serialize_edge(row), run_id=run_id)
    return True


async def ensure_lateral_pivots(project_id: str, run_id: str | None = None) -> int:
    """多主机立足点挂在本题唯一入口 target 下，不另开黑色目标。

    拓扑：
      target:入口 ──CONTAINS──►  info:host:内网IP / foothold:shell@内网IP
      foothold:shell@入口  ──PIVOTS_TO──►  foothold:shell@内网IP
    SSRF 可达、端口发现等未验证 shell 的边降级为 LEADS_TO。
    """
    if project_id in _pivoting_projects:
        return 0
    _pivoting_projects.add(project_id)
    try:
        added = await fold_intranet_targets(project_id, run_id=run_id)
        rows = await db.fetchall(
            """SELECT key, type, tags, is_rce, created_at, title FROM nodes
               WHERE project_id=?
                 AND (type='foothold' OR (type='goal' AND key LIKE 'goal:shell%'))
               ORDER BY created_at""",
            (project_id,),
        )
        contain_host: dict[str, str] = {}
        for e in await db.fetchall(
            "SELECT src, dst FROM edges WHERE project_id=? AND relation='CONTAINS'",
            (project_id,),
        ):
            parent = _host_from_asset_key(e["src"])
            if parent and e["dst"]:
                contain_host.setdefault(e["dst"], parent)
        by_host: dict[str, list[dict]] = {}
        control_list: list[dict] = []
        for r in rows:
            rec = dict(r)
            tags = list(_loads(rec["tags"]) or [])
            host = _host_of_node(rec["key"], tags)
            if not host:
                host = contain_host.get(rec["key"], "")
                if host:
                    tag = f"host:{host}"
                    if tag not in tags:
                        tags.append(tag)
                        rec["tags"] = _dumps(tags)
                        await db.execute(
                            "UPDATE nodes SET tags=? WHERE project_id=? AND key=?",
                            (rec["tags"], project_id, rec["key"]),
                        )
            rec["_host"] = host
            control_list.append(rec)
            if host:
                by_host.setdefault(host, []).append(rec)
        targets = await db.fetchall(
            "SELECT key, created_at FROM nodes WHERE project_id=? AND type='target' ORDER BY created_at",
            (project_id,),
        )
        primary_host = await _project_entry_host(project_id)
        primary_target = f"target:{primary_host}" if primary_host else (
            targets[0]["key"] if targets else ""
        )
        if primary_target and not any(t["key"] == primary_target for t in targets):
            primary_target = targets[0]["key"] if targets else primary_target
            primary_host = _host_from_target_key(primary_target) or primary_host
        if not primary_host:
            for t in targets:
                primary_host = _host_from_target_key(t["key"])
                if primary_host:
                    primary_target = t["key"]
                    break
        if not primary_host:
            for host, ns in by_host.items():
                if any("@" not in n["key"] for n in ns):
                    primary_host = host
                    break
        if not primary_host:
            if by_host:
                primary_host = sorted(
                    by_host.keys(),
                    key=lambda h: min(n["created_at"] for n in by_host[h]),
                )[0]
            # by_host 为空时不能 sorted()[0]：会 500，前端 catch 空回调后永远「加载中…」

        # PIVOTS_TO 只表示「已验证 shell/RCE 踏上另一台主机」。
        # SSRF 可达、端口发现、Redis 凭证等都只是发现链路，必须降级为 LEADS_TO。
        all_edges = await db.fetchall(
            "SELECT * FROM edges WHERE project_id=? ORDER BY created_at", (project_id,)
        )
        controls = {n["key"]: n for n in control_list}
        control_hosts = {
            n["key"]: (n.get("_host") or _host_of_node(n["key"], _loads(n["tags"]) or []))
            for n in control_list
        }
        asset_hosts = {t["key"]: _host_from_asset_key(t["key"]) for t in targets}
        for n in await db.fetchall(
            "SELECT key FROM nodes WHERE project_id=? AND "
            "(key LIKE 'info:host:%' OR key LIKE 'info:scope-expanded:%')",
            (project_id,),
        ):
            h = _host_from_asset_key(n["key"])
            if h:
                asset_hosts[n["key"]] = h
        verified_hosts = {
            host for key, host in control_hosts.items()
            if host and bool(controls[key].get("is_rce"))
        }
        for e in all_edges:
            if e["relation"] != "PIVOTS_TO":
                continue
            dst_host = (
                asset_hosts.get(e["dst"], "")
                or control_hosts.get(e["dst"], "")
                or _host_from_asset_key(e["dst"])
            )
            src_host = control_hosts.get(e["src"], "")
            valid = bool(
                dst_host
                and src_host
                and src_host != dst_host
                and bool(controls.get(e["src"], {}).get("is_rce"))
                and dst_host in verified_hosts
            )
            if not valid:
                duplicate = await db.fetchone(
                    """SELECT id FROM edges WHERE project_id=? AND src=? AND dst=?
                       AND relation='LEADS_TO'""",
                    (project_id, e["src"], e["dst"]),
                )
                if duplicate:
                    # 已有相同发现线时，删除错误紫线，避免违反边关系的唯一约束。
                    await db.execute("DELETE FROM edges WHERE id=?", (e["id"],))
                else:
                    await db.execute(
                        """UPDATE edges SET relation='LEADS_TO', rationale=? WHERE id=?""",
                        (
                            f"{e['rationale'] or '发现链路'} [未验证新主机 shell/RCE，非内网横向]",
                            e["id"],
                        ),
                    )
                added += 1

        if len(by_host) < 2:
            if added:
                await recompute_rce_path(project_id, run_id=run_id)
            return added

        def _best_foothold(ns: list[dict]) -> dict:
            return min(
                ns,
                key=lambda n: (
                    0 if n.get("is_rce") else 1,
                    0 if n["type"] == "foothold" else 1,
                    0 if "shell" in n["key"] else 1,
                    n["created_at"],
                    n["key"],
                ),
            )

        # 紫线起点必须是已验证 RCE 立足点。入口 shell 常挂在同机另一地址上，
        # 不能退化成 target 节点——target 没有 is_rce，后面整段都画不出 PIVOTS_TO。
        rce_hosts = [
            h for h, ns in by_host.items()
            if any(bool(n.get("is_rce")) for n in ns)
        ]
        pivot_src = ""
        pivot_src_host = ""
        if primary_host in by_host and any(bool(n.get("is_rce")) for n in by_host[primary_host]):
            pivot_src_host = primary_host
            pivot_src = _best_foothold(by_host[primary_host])["key"]
        elif rce_hosts:
            pivot_src_host = min(
                rce_hosts,
                key=lambda h: (
                    0 if h == primary_host else 1,
                    min(n["created_at"] for n in by_host[h]),
                ),
            )
            pivot_src = _best_foothold(by_host[pivot_src_host])["key"]
        if not pivot_src:
            return added

        existing = await db.fetchall(
            "SELECT id, src, dst FROM edges WHERE project_id=? AND relation='PIVOTS_TO'",
            (project_id,),
        )
        pivoted_hosts: set[str] = set()
        for e in existing:
            h = (
                _host_from_asset_key(e["dst"])
                or control_hosts.get(e["dst"], "")
            )
            if h:
                pivoted_hosts.add(h)

        other_hosts = sorted(
            (h for h in by_host if h != pivot_src_host),
            key=lambda h: min(n["created_at"] for n in by_host[h]),
        )
        prev_shell = pivot_src
        for host in other_hosts:
            shell = _best_foothold(by_host[host])
            shell_key = shell["key"]
            asset_key = await ensure_host_target(
                project_id, host,
                title=f"内网主机 {host}",
                run_id=run_id,
            )

            # 横向线：上一台已验证 shell → 本机已验证 shell（仍属同一入口目标）
            if host not in pivoted_hosts:
                src_rce = bool(controls.get(prev_shell, {}).get("is_rce"))
                if src_rce and host in verified_hosts:
                    if await _insert_edge_once(
                        project_id, prev_shell, shell_key, "PIVOTS_TO",
                        weight=0.95,
                        rationale=f"内网横向：{prev_shell} → {host}",
                        run_id=run_id,
                    ):
                        added += 1
                        pivoted_hosts.add(host)

            if primary_target:
                if await _insert_edge_once(
                    project_id, primary_target, shell_key, "CONTAINS",
                    weight=0.85,
                    rationale=f"内网立足点 {host} 属于入口目标",
                    run_id=run_id,
                ):
                    added += 1
            if asset_key and asset_key not in (primary_target, shell_key):
                if await _insert_edge_once(
                    project_id, asset_key, shell_key, "LEADS_TO",
                    weight=0.8,
                    rationale=f"内网主机 {host} 上的立足点",
                    run_id=run_id,
                ):
                    added += 1

            if bool(shell.get("is_rce")):
                prev_shell = shell_key

        if added:
            await recompute_rce_path(project_id, run_id=run_id)
        return added
    finally:
        _pivoting_projects.discard(project_id)


async def find_pivot_source(project_id: str, primary_host: str = "") -> str:
    """给 report_shell 找 PIVOTS_TO 的起点：主目标上的 shell 立足点，否则 target 节点。"""
    ph = (primary_host or "").strip().lower().rstrip(".")
    rows = await db.fetchall(
        """SELECT key, tags, is_rce, created_at FROM nodes
           WHERE project_id=? AND type IN ('foothold','goal')
           ORDER BY created_at""",
        (project_id,),
    )
    primary_nodes: list[dict] = []
    for r in rows:
        tags = _loads(r["tags"]) or []
        host = _host_of_node(r["key"], tags)
        if ph and host and host != ph:
            continue
        if ph and host == ph:
            primary_nodes.append(dict(r))
        elif not host and "@" not in r["key"]:
            primary_nodes.append(dict(r))
    if primary_nodes:
        best = min(
            primary_nodes,
            key=lambda n: (
                0 if n.get("is_rce") else 1,
                0 if "shell" in n["key"] else 1,
                n["created_at"],
            ),
        )
        return best["key"]
    t = await db.fetchone(
        "SELECT key FROM nodes WHERE project_id=? AND type='target' ORDER BY created_at LIMIT 1",
        (project_id,),
    )
    return t["key"] if t else ""


async def has_verified_internal_vantage(project_id: str) -> bool:
    """是否已有能看见目标内网的立足点：verified RCE/shell 或 verified SSRF。"""
    if not project_id:
        return False
    row = await db.fetchone(
        """SELECT 1 FROM findings WHERE project_id=? AND verification_status='verified'
           AND (
             lower(IFNULL(category,'')) IN
               ('rce','command_injection','deserialization','ssti','ssrf')
             OR IFNULL(node_key,'') LIKE 'goal:shell%'
             OR IFNULL(node_key,'') LIKE 'foothold:shell%'
           ) LIMIT 1""",
        (project_id,),
    )
    return bool(row)


async def is_verified_lateral_pivot(project_id: str, src: str, dst: str) -> bool:
    """只有已控 RCE/shell 踏上另一台且已验证 shell/RCE 的主机，才允许 PIVOTS_TO。"""
    rows = await db.fetchall(
        """SELECT key, type, tags, is_rce FROM nodes
           WHERE project_id=?""",
        (project_id,),
    )
    by_key = {r["key"]: r for r in rows}
    source = by_key.get(src)
    dest = by_key.get(dst)
    if not source or not dest or not bool(source["is_rce"]):
        return False
    src_host = _host_of_node(source["key"], _loads(source["tags"]) or [])
    dst_host = (
        _host_of_node(dest["key"], _loads(dest["tags"]) or [])
        or _host_from_asset_key(dest["key"])
    )
    if not src_host or not dst_host or src_host == dst_host:
        return False
    dest_ok = dest["type"] in ("target", "info", "foothold", "goal")
    if not dest_ok:
        return False
    return any(
        bool(r["is_rce"])
        and r["type"] in ("foothold", "goal")
        and _host_of_node(r["key"], _loads(r["tags"]) or []) == dst_host
        for r in rows
    )


async def find_host_source(project_id: str, host: str) -> str:
    """为 report_flag 找同主机上最可信的来源节点（shell 优先，其次该主机 target）。"""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    rows = await db.fetchall(
        """SELECT key, type, tags, is_rce, created_at FROM nodes
           WHERE project_id=?
             AND (type != 'goal' OR key LIKE 'goal:shell%')
           ORDER BY created_at""",
        (project_id,),
    )
    candidates: list[dict] = []
    for r in rows:
        tags = _loads(r["tags"]) or []
        if _host_of_node(r["key"], tags) == host:
            candidates.append(dict(r))
    if candidates:
        best = min(
            candidates,
            key=lambda n: (
                0 if n["type"] == "foothold" and n.get("is_rce") else 1,
                0 if n["type"] == "foothold" else 1,
                0 if "shell" in n["key"] else 1,
                n["created_at"],
            ),
        )
        return best["key"]
    for cand in (f"info:host:{host}", f"info:scope-expanded:{host}", f"target:{host}"):
        row = await db.fetchone(
            "SELECT key FROM nodes WHERE project_id=? AND key=?",
            (project_id, cand),
        )
        if row:
            return row["key"]
    return ""


# ---- 边权学习（Phase 2）：历史成功率回灌到边权 -----------------------------
# 各手法历史成功率带 TTL 缓存，避免每次建边都扫记忆表。
_priors_cache: dict[str, Any] = {"ts": 0.0, "rates": {}}


async def _learned_priors() -> dict[str, float]:
    now_ts = time.time()
    if now_ts - _priors_cache["ts"] > 20:
        _priors_cache["rates"] = {}
        _priors_cache["ts"] = now_ts
    return _priors_cache["rates"]


async def _learn_edge_weight(project_id: str, base: float, dst_key: str) -> tuple[float, bool]:
    """按目标节点关联手法的历史净先验温和融合修正边权。
    无相关历史时返回原权重。"""
    priors = await _learned_priors()
    if not priors:
        return base, False
    cands: set[str] = set()
    node = await db.fetchone(
        "SELECT type, tags, is_rce FROM nodes WHERE project_id=? AND key=?", (project_id, dst_key)
    )
    if node:
        cands |= {str(t).lower() for t in (_loads(node["tags"]) or [])}
        if node["is_rce"]:
            cands.add("rce")
    fcats = await db.fetchall(
        "SELECT DISTINCT category FROM findings WHERE project_id=? AND node_key=?", (project_id, dst_key)
    )
    cands |= {str(r["category"]).lower() for r in fcats if r["category"]}
    matched = [priors[c] for c in cands if c in priors]
    if not matched:
        return base, False
    # 取候选手法里的最高净先验为主导信号：正向经验拉高、纯失败手法(净先验≈0)会把权重拉向 0.65*base
    rate = max(matched)
    # 融合：以 agent 判断为主(0.65)、历史净先验为辅(0.35)，越用越准
    return round(max(0.01, min(1.0, 0.65 * base + 0.35 * rate)), 3), True


async def add_edge(project_id: str, edge: EdgeIn, run_id: str | None = None) -> dict:
    await ensure_node(project_id, edge.src, run_id)
    await ensure_node(project_id, edge.dst, run_id)
    weight = max(0.01, min(1.0, float(edge.weight)))
    rationale = edge.rationale
    learned_w, learned = await _learn_edge_weight(project_id, weight, edge.dst)
    if learned:
        weight = learned_w
        rationale = (rationale + " " if rationale else "") + "[边权学习:净先验(含失败阻尼)回灌]"
    existing = await db.fetchone(
        "SELECT id FROM edges WHERE project_id=? AND src=? AND dst=? AND relation=?",
        (project_id, edge.src, edge.dst, edge.relation),
    )
    if existing:
        await db.execute(
            "UPDATE edges SET weight=?, rationale=? WHERE id=?",
            (weight, rationale, existing["id"]),
        )
        eid = existing["id"]
    else:
        eid = new_id("e_")
        await db.execute(
            """INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at)
               VALUES(?,?,?,?,?,?,?,?)""",
            (eid, project_id, edge.src, edge.dst, edge.relation, weight, rationale, now()),
        )
    row = await db.fetchone("SELECT * FROM edges WHERE id=?", (eid,))
    await emit(project_id, "edge", _serialize_edge(row), run_id=run_id)
    # 若新建边落在游离子图上，补一条到 target，避免攻击链与黑点起点脱节
    await ensure_target_attachments(project_id, run_id=run_id)
    # 每次拓扑变化后重算 RCE 路径
    await recompute_rce_path(project_id, run_id=run_id)
    return row


async def add_finding(project_id: str, finding: FindingIn, run_id: str | None = None) -> dict:
    from .verify import verify_finding

    sev = normalize_severity(finding.category, finding.severity)
    vr = await verify_finding(finding, project_id=project_id)
    ts = now()
    verified_at = ts if vr.status == "verified" else None
    stored_detail = vr.proof_detail
    rating = normalize_redteam_rating(getattr(finding, "redteam_rating", None))
    rating_why = (getattr(finding, "redteam_rating_rationale", None) or "").strip() or None
    secondary = 1 if getattr(finding, "secondary_verified", False) else 0

    existing = None
    if finding.node_key:
        existing = await db.fetchone(
            """SELECT * FROM findings WHERE project_id=? AND node_key=?
               ORDER BY created_at DESC LIMIT 1""",
            (project_id, finding.node_key),
        )

    if existing:
        # 同节点再次上报：补强证据与 PoC，不重复造 finding；可升为已验证 / 二次验证
        fid = existing["id"]
        prev_sec = int(existing.get("secondary_verified") or 0)
        prev_st = str(existing.get("verification_status") or "")
        prev_vat = existing.get("verified_at")
        if vr.status == "verified":
            new_st = "verified"
            verified_at = ts if prev_st != "verified" else prev_vat
        else:
            new_st = prev_st or vr.status
            verified_at = prev_vat
        await db.execute(
            """UPDATE findings SET evidence=COALESCE(?, evidence),
                   poc_curl=COALESCE(?, poc_curl), poc_python=COALESCE(?, poc_python),
                   proof_type=COALESCE(?, proof_type), proof_canary=COALESCE(?, proof_canary),
                   proof_url=COALESCE(?, proof_url), proof_detail=COALESCE(?, proof_detail),
                   verification_status=?, verified_at=COALESCE(?, verified_at),
                   secondary_verified=?, redteam_rating=COALESCE(?, redteam_rating),
                   redteam_rating_rationale=COALESCE(?, redteam_rating_rationale)
               WHERE id=?""",
            (finding.evidence, finding.poc_curl, finding.poc_python,
             vr.proof_type, vr.proof_canary, vr.proof_url, stored_detail,
             new_st, verified_at, 1 if (secondary or prev_sec) else 0,
             rating, rating_why, fid),
        )
    else:
        fid = new_id("f_")
        await db.execute(
            """INSERT INTO findings(id, project_id, node_key, severity, category, title,
                   description, evidence, poc_curl, poc_python, cvss, created_at,
                   verification_status, verified_at, proof_type, proof_canary, proof_url, proof_detail,
                   secondary_verified, redteam_rating, redteam_rating_rationale)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fid, project_id, finding.node_key, sev, finding.category, finding.title,
             finding.description, finding.evidence, finding.poc_curl, finding.poc_python,
             finding.cvss, ts,
             vr.status, verified_at, vr.proof_type, vr.proof_canary, vr.proof_url, stored_detail,
             secondary, rating, rating_why),
        )

    row = await db.fetchone("SELECT * FROM findings WHERE id=?", (fid,))
    data = _serialize_finding(row)
    data["critical"] = is_critical(sev, finding.category)
    data["verify_reason"] = vr.reason
    await emit(project_id, "finding", data, run_id=run_id)
    if finding.node_key:
        nrow = await db.fetchone(
            "SELECT * FROM nodes WHERE project_id=? AND key=?", (project_id, finding.node_key)
        )
        if nrow:
            await db.execute(
                "UPDATE nodes SET severity=?, risk_score=?, updated_at=? WHERE id=?",
                (sev, compute_risk_score(sev, nrow["type"], bool(nrow["is_rce"]), finding.category),
                 now(), nrow["id"]),
            )
            await derive_intents_for_finding(project_id, finding, nrow, run_id=run_id)
    return data


# ---- 意图 / 推理前沿 --------------------------------------------------------

_OPEN_STATUSES = ("open", "active", "deferred")
_TERMINAL_STATUSES = ("verified", "disproved")


async def add_intent(project_id: str, intent: IntentIn, run_id: str | None = None) -> dict:
    """写入意图；若带 strategy_key 则按策略去重（同证据可复开 disproved）。"""
    ts = now()
    priority = float(intent.priority if intent.priority is not None else intent.est_success)
    status = intent.status or "open"
    sk = (intent.strategy_key or "").strip() or None
    ev = intent.evidence_fingerprint

    if sk:
        existing = await db.fetchone(
            "SELECT * FROM intents WHERE project_id=? AND strategy_key=?",
            (project_id, sk),
        )
        if existing:
            # 同策略且证据未变：不重复插入；若曾否证但证据变了则复开
            same_ev = (existing.get("evidence_fingerprint") or "") == (ev or "")
            if existing["status"] in _TERMINAL_STATUSES and same_ev:
                return _serialize_intent(existing)
            if existing["status"] in _OPEN_STATUSES and same_ev:
                # 刷新优先级描述，保持开放
                await db.execute(
                    """UPDATE intents SET description=?, rationale=?, est_success=?, priority=?,
                           evidence_fingerprint=?, updated_at=? WHERE id=?""",
                    (intent.description, intent.rationale, float(intent.est_success),
                     priority, ev, ts, existing["id"]),
                )
                row = await db.fetchone("SELECT * FROM intents WHERE id=?", (existing["id"],))
                return _serialize_intent(row)
            # 证据变化或曾延期：复开
            await db.execute(
                """UPDATE intents SET description=?, rationale=?, est_success=?, priority=?,
                       evidence_fingerprint=?, status='open', failure_fingerprint=NULL,
                       result_summary=NULL, updated_at=? WHERE id=?""",
                (intent.description, intent.rationale, float(intent.est_success),
                 priority, ev, ts, existing["id"]),
            )
            row = await db.fetchone("SELECT * FROM intents WHERE id=?", (existing["id"],))
            await emit(project_id, "intent", _serialize_intent(row), run_id=run_id)
            return _serialize_intent(row)

    iid = new_id("i_")
    await db.execute(
        """INSERT INTO intents(
               id, project_id, from_keys, description, rationale, est_success, status,
               strategy_key, evidence_fingerprint, priority, attempt_count,
               failure_fingerprint, result_summary, active_run_id, created_at, updated_at
           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (iid, project_id, _dumps(intent.from_keys), intent.description, intent.rationale,
         float(intent.est_success), status, sk, ev, priority, 0, None, None, None, ts, ts),
    )
    row = await db.fetchone("SELECT * FROM intents WHERE id=?", (iid,))
    await emit(project_id, "intent", _serialize_intent(row), run_id=run_id)
    return _serialize_intent(row)


_BRIEF_CACHE: dict[str, str] = {}
_OBJ_META_CACHE: dict[str, tuple[bool, str]] = {}


async def _project_brief_text(project_id: str) -> str:
    if project_id in _BRIEF_CACHE:
        return _BRIEF_CACHE[project_id]
    text = ""
    try:
        row = await db.fetchone("SELECT config FROM projects WHERE id=?", (project_id,))
        cfg = {}
        if row and row.get("config"):
            import json
            cfg = json.loads(row["config"]) or {}
        text = "\n".join(
            x for x in (
                str(cfg.get("description") or "").strip(),
                str(cfg.get("hint") or "").strip(),
                str(cfg.get("tip") or "").strip(),
            ) if x
        )
    except Exception:
        text = ""
    _BRIEF_CACHE[project_id] = text
    return text


async def _project_objective_meta(project_id: str) -> tuple[bool, str]:
    """(allows_flag, normalized objective)。带轻量缓存。"""
    if project_id in _OBJ_META_CACHE:
        return _OBJ_META_CACHE[project_id]
    allows, obj = True, "flag"
    try:
        from ..objective import normalize_objective, objective_allows_flag
        row = await db.fetchone("SELECT config FROM projects WHERE id=?", (project_id,))
        cfg = {}
        if row and row.get("config"):
            import json
            cfg = json.loads(row["config"]) or {}
        obj = normalize_objective(cfg.get("objective"))
        allows = objective_allows_flag(obj)
    except Exception:
        allows, obj = True, "flag"
    _OBJ_META_CACHE[project_id] = (allows, obj)
    return allows, obj


async def _project_allows_flag(project_id: str) -> bool:
    """项目 objective 是否允许 flag 派生（仅 CTF/flag 赛道）。"""
    allows, _ = await _project_objective_meta(project_id)
    return allows


async def derive_intents_for_node(project_id: str, node_row: dict, run_id: str | None = None) -> list[dict]:
    from .hypothesize import hypotheses_for_node
    allows_flag, obj = await _project_objective_meta(project_id)
    brief = await _project_brief_text(project_id)
    created: list[dict] = []
    for hyp in hypotheses_for_node(
        node_row, allows_flag=allows_flag, objective=obj, brief=brief,
    ):
        row = await add_intent(project_id, hyp, run_id=run_id)
        if row:
            created.append(row)
    return created


async def _defer_intent_tactic(
    project_id: str, source_key: str, tactic: str, reason: str, run_id: str | None = None,
) -> bool:
    from .hypothesize import strategy_key
    sk = strategy_key(source_key, tactic)
    row = await db.fetchone(
        "SELECT id, status FROM intents WHERE project_id=? AND strategy_key=?",
        (project_id, sk),
    )
    if not row or row["status"] not in ("open", "active"):
        return False
    await set_intent_status(
        project_id, row["id"], "deferred",
        result_summary=reason, failure_fingerprint=reason, run_id=run_id,
    )
    return True


async def _open_strategy_keys(project_id: str) -> set[str]:
    rows = await db.fetchall(
        "SELECT strategy_key FROM intents WHERE project_id=? AND status IN ('open','active')",
        (project_id,),
    )
    return {r["strategy_key"] for r in rows if r.get("strategy_key")}


async def refresh_derived_intents(project_id: str, run_id: str | None = None) -> dict:
    """按当前 hypothesize 规则补派生，并搁置过时 tactic。

    规则升级后旧图不会自动长出 secret_mount，也不会自行丢掉 SSRF 上的 weaponize。
    每个 run 开头跑一次即可。
    """
    from .hypothesize import stale_tactics_for_node
    from .model import FindingIn

    nodes = await db.fetchall("SELECT * FROM nodes WHERE project_id=?", (project_id,))
    before = await _open_strategy_keys(project_id)
    stale_deferred = 0
    reason = "规则刷新：该 tactic 不再适用于此节点（SSRF≠weaponize；机器令牌≠登录复用）"
    serialized = [_serialize_node(raw) for raw in nodes]
    node_by_key = {n["key"]: n for n in serialized}
    brief = await _project_brief_text(project_id)
    for node in serialized:
        await derive_intents_for_node(project_id, node, run_id=run_id)
        for tac in stale_tactics_for_node(node, brief=brief):
            if await _defer_intent_tactic(project_id, node.get("key") or "", tac, reason, run_id=run_id):
                stale_deferred += 1

    findings = await db.fetchall("SELECT * FROM findings WHERE project_id=?", (project_id,))
    for f in findings:
        key = f.get("node_key") or ""
        nrow = node_by_key.get(key) or {"key": key, "type": "info", "title": f.get("title") or key}
        try:
            finding = FindingIn(
                node_key=key or None,
                severity=f.get("severity") or "medium",
                category=f.get("category") or "info",
                title=f.get("title") or key or "finding",
                description=f.get("description"),
                evidence=f.get("evidence"),
            )
        except Exception:
            continue
        await derive_intents_for_finding(project_id, finding, nrow, run_id=run_id)
    after = await _open_strategy_keys(project_id)
    return {"opened": max(0, len(after - before)), "stale_deferred": stale_deferred}


async def derive_intents_for_finding(
    project_id: str, finding: FindingIn | dict, node_row: dict, run_id: str | None = None
) -> list[dict]:
    from .hypothesize import hypotheses_for_finding
    allows_flag, obj = await _project_objective_meta(project_id)
    created: list[dict] = []
    for hyp in hypotheses_for_finding(finding, node_row, allows_flag=allows_flag, objective=obj):
        row = await add_intent(project_id, hyp, run_id=run_id)
        if row:
            created.append(row)
    return created


async def list_open_intents(project_id: str, limit: int = 20) -> list[dict]:
    rows = await db.fetchall(
        """SELECT * FROM intents
           WHERE project_id=? AND status IN ('open','deferred','active')
           ORDER BY
             CASE status WHEN 'active' THEN 0 WHEN 'open' THEN 1 ELSE 2 END,
             COALESCE(priority, est_success) DESC,
             created_at ASC
           LIMIT ?""",
        (project_id, limit),
    )
    return [_serialize_intent(r) for r in rows]


async def list_disproved_intents(project_id: str, limit: int = 12) -> list[dict]:
    """取已否证意图（带失败指纹），用于每轮回灌「勿重复」清单——
    会话被硬重置后新智能体只看图快照，若不显式带上已失败路径就会重走弯路/重复路。"""
    rows = await db.fetchall(
        """SELECT * FROM intents
           WHERE project_id=? AND status='disproved'
           ORDER BY updated_at DESC
           LIMIT ?""",
        (project_id, limit),
    )
    return [_serialize_intent(r) for r in rows]


_CHAIN_CLOSE_ORDER = (
    "access_control", "file_read_chain", "svc_auth_bruteforce", "ssrf_as_gateway",
    "hop_auth", "finding_rce_close", "flag_hunt", "flag_or_privesc", "weaponize",
    "finding_read_loot", "finding_sqli_chain",
    "read_to_creds", "channel_oracle", "input_abuse",
    "protocol_model", "reverse_binary", "restricted_deserialize", "filter_bypass",
)


async def list_frontier_intents(
    project_id: str, *, limit: int = 3, exclude_strategies: set[str] | None = None,
    prefer_tactics: set[str] | None = None,
) -> list[dict]:
    """取正交高价值前沿：优先不同 strategy 族与不同来源节点。

    prefer_tactics：已有已验证资产时传入 CHAIN_NEXT，避免 captcha/目录枚举压过 weaponize。
    """
    exclude_strategies = exclude_strategies or set()
    candidates = await list_open_intents(project_id, limit=50)
    candidates = [it for it in candidates if it.get("status") != "deferred"]

    def _tac(it: dict) -> str:
        sk = it.get("strategy_key") or ""
        return sk.split("::")[-1] if "::" in sk else sk

    if exclude_strategies:
        candidates = [
            it for it in candidates
            if (it.get("strategy_key") or "") not in exclude_strategies
            and _tac(it) not in exclude_strategies
        ]
    if prefer_tactics:
        head = [it for it in candidates if _tac(it) in prefer_tactics]
        tail = [it for it in candidates if _tac(it) not in prefer_tactics]
        rank = {name: i for i, name in enumerate(_CHAIN_CLOSE_ORDER)}
        if "reverse_binary" in prefer_tactics:
            rank["reverse_binary"] = -3
            rank["protocol_model"] = -2
        head.sort(key=lambda it: rank.get(_tac(it), 50))
        candidates = head + tail
    picked: list[dict] = []
    used_sources: set[str] = set()
    used_tactics: set[str] = set()
    for it in candidates:
        sk = it.get("strategy_key") or ""
        tactic = sk.split("::")[-1] if "::" in sk else sk
        if sk in exclude_strategies or tactic in exclude_strategies:
            continue
        sources = set(it.get("from") or [])
        if sources & used_sources and len(picked) > 0:
            # 允许同来源，但优先换 tactic
            if tactic in used_tactics:
                continue
        if tactic in used_tactics and len(picked) >= 1:
            continue
        picked.append(it)
        used_sources |= sources
        if tactic:
            used_tactics.add(tactic)
        if len(picked) >= limit:
            break
    return picked


async def frontier_stats(project_id: str) -> dict:
    rows = await db.fetchall(
        "SELECT status, strategy_key, attempt_count FROM intents WHERE project_id=?",
        (project_id,),
    )
    by_status: dict[str, int] = {}
    strategies = set()
    for r in rows:
        st = r.get("status") or "open"
        by_status[st] = by_status.get(st, 0) + 1
        if r.get("strategy_key"):
            strategies.add(r["strategy_key"])
    open_n = sum(by_status.get(s, 0) for s in ("open", "active", "deferred"))
    return {
        "open": open_n,
        "by_status": by_status,
        "strategies": len(strategies),
        "disproved": by_status.get("disproved", 0),
        "verified": by_status.get("verified", 0),
    }


async def set_intent_status(
    project_id: str,
    intent_id: str,
    status: str,
    *,
    result_summary: str | None = None,
    failure_fingerprint: str | None = None,
    run_id: str | None = None,
) -> dict | None:
    row = await db.fetchone(
        "SELECT * FROM intents WHERE id=? AND project_id=?", (intent_id, project_id)
    )
    if not row:
        return None
    ts = now()
    attempts = int(row.get("attempt_count") or 0)
    if status == "active":
        attempts += 1
    await db.execute(
        """UPDATE intents SET status=?, result_summary=COALESCE(?, result_summary),
               failure_fingerprint=COALESCE(?, failure_fingerprint),
               attempt_count=?, active_run_id=?, updated_at=?
           WHERE id=? AND project_id=?""",
        (status, result_summary, failure_fingerprint, attempts, run_id, ts, intent_id, project_id),
    )
    out = await db.fetchone("SELECT * FROM intents WHERE id=?", (intent_id,))
    await emit(project_id, "intent", _serialize_intent(out), run_id=run_id)
    return _serialize_intent(out)


async def claim_intents(project_id: str, intent_ids: list[str], run_id: str | None = None) -> list[dict]:
    claimed = []
    for iid in intent_ids:
        row = await set_intent_status(project_id, iid, "active", run_id=run_id)
        if row:
            claimed.append(row)
    return claimed


async def resolve_intent(
    project_id: str,
    intent_id: str,
    *,
    verified: bool,
    summary: str | None = None,
    failure_fingerprint: str | None = None,
    run_id: str | None = None,
) -> dict | None:
    status = "verified" if verified else "disproved"
    return await set_intent_status(
        project_id, intent_id, status,
        result_summary=summary,
        failure_fingerprint=None if verified else (failure_fingerprint or summary),
        run_id=run_id,
    )


async def defer_strategy_family(project_id: str, tactic_substr: str, reason: str, run_id: str | None = None) -> int:
    """硬换路时把某策略族从 open 降为 deferred。"""
    rows = await db.fetchall(
        """SELECT id, strategy_key FROM intents
           WHERE project_id=? AND status IN ('open','active') AND strategy_key LIKE ?""",
        (project_id, f"%::{tactic_substr}%"),
    )
    n = 0
    for r in rows:
        await set_intent_status(
            project_id, r["id"], "deferred",
            result_summary=reason, failure_fingerprint=reason, run_id=run_id,
        )
        n += 1
    return n


async def quality_progress_delta(prev: tuple, curr: tuple, graph: dict) -> str:
    """评估进展：flag/finding/能力边/可消耗资产节点才算高质量。

    service/danger 是入口侦察刷图，不得清零顾问空转。
    prev 未初始化（含负数哨兵）时返回 none，避免 0 个 flag 被当成新增 flag。
    """
    # curr/prev: (nodes, edges, findings, flags)
    if not prev or any(int(x) < 0 for x in prev[:4]):
        return "none"
    if curr[3] > prev[3]:
        return "flag"
    if curr[2] > prev[2]:
        return "finding"
    # 能力边
    edges = graph.get("edges") or []
    if any(e.get("relation") in ("EXPLOITS", "ESCALATES_TO", "PIVOTS_TO") for e in edges):
        if curr[1] > prev[1]:
            return "capability_edge"
    nodes = graph.get("nodes") or []
    # 只有可接着打的资产落图才算 valuable；目录/指纹刷出来的 service/danger 不算。
    valuable = sum(
        1 for n in nodes if n.get("type") in ("vuln", "credential", "foothold", "goal")
    )
    if curr[0] > prev[0] and valuable > 0:
        return "valuable_node"
    # 新增 info 节点也算有效产出（被动情报/画像落图）
    if curr[0] > prev[0]:
        info_n = sum(1 for n in nodes if n.get("type") == "info")
        if info_n > 0:
            return "info_node"
        return "weak_graph"
    if curr[1] > prev[1]:
        return "weak_graph"
    return "none"


# ---- RCE 最优路径 -----------------------------------------------------------

# 记录每个项目上次已推送的 RCE 路径签名，避免只读重算时重复 emit 造成事件洪泛。
_last_rce_sig: dict[str, tuple] = {}


def _path_likelihood(g: "nx.DiGraph", path: list[str]) -> float:
    if len(path) <= 1:
        return 1.0 if path else 0.0
    lik = 1.0
    for a, b in zip(path, path[1:]):
        data = g.get_edge_data(a, b) or {}
        lik *= float(data.get("w", 0.01))
    return lik


_CLOSE_FINDING_CATS = frozenset({
    "rce", "command_injection", "deserialization", "ssti",
    "file_read", "lfi", "file_write", "file_upload", "sqli",
})


def _node_tag_set(n) -> set[str]:
    try:
        raw = n["tags"]
    except Exception:
        raw = n.get("tags") if isinstance(n, dict) else None
    return {str(t).lower() for t in (_loads(raw) or [])}


def _node_flag(n, key: str) -> bool:
    try:
        return bool(n[key])
    except Exception:
        return bool(n.get(key)) if isinstance(n, dict) else False


def _node_text(n, key: str) -> str:
    try:
        v = n[key]
    except Exception:
        v = n.get(key) if isinstance(n, dict) else ""
    return str(v or "")


def _closeable_verified(n, findings_by_key: dict) -> bool:
    key = _node_text(n, "key")
    tags = _node_tag_set(n)
    if "verified" in tags and (tags & _CLOSE_FINDING_CATS):
        return True
    for f in findings_by_key.get(key) or []:
        vs = _node_text(f, "verification_status").lower() or "verified"
        if vs != "verified":
            continue
        cat = _node_text(f, "category").lower()
        sev = _node_text(f, "severity").lower()
        critical = _node_flag(f, "critical")
        if cat in _CLOSE_FINDING_CATS or sev == "critical" or critical:
            return True
    return False


def _rce_sink_ok(n, findings_by_key: dict) -> bool:
    t = _node_text(n, "type")
    key = _node_text(n, "key")
    tags = _node_tag_set(n)
    if t == "info":
        return False
    if t == "goal" and key.startswith("goal:shell"):
        return True
    if t == "foothold" and (_node_flag(n, "is_rce") or "getshell" in tags):
        return True
    if t in ("vuln", "danger") and _closeable_verified(n, findings_by_key):
        return True
    if t == "vuln" and _node_flag(n, "is_rce"):
        return True
    return False


_TRANSPORT_NODE_RE = re.compile(
    r"(timed?\s*out|timeout|connection refused|unreachable|no route to host|"
    r"name or service not known|empty reply)",
    re.I,
)


def _transport_stuck(n) -> bool:
    blob = f"{_node_text(n, 'title')} {_node_text(n, 'detail')} {_node_text(n, 'key')}"
    return bool(_TRANSPORT_NODE_RE.search(blob))


def _pick_attack_chain(g: "nx.DiGraph", sources: list[str], sinks: list[str],
                       node_by_key: dict, findings_by_key: dict | None = None) -> list[str]:
    """选「目标 → … → 本机 RCE/会话」攻击链，而不是 target 直连终点的捷径。

    终点优先级：getshell goal > 已控立足点/已验证可收口漏洞 > 遗留 is_rce 漏洞。
    信息点不当终点。PIVOTS_TO / flag goal 不进入此图。
    """
    findings_by_key = findings_by_key or {}

    def sink_prio(key: str) -> int:
        n = node_by_key.get(key) or {}
        t = n.get("type") if isinstance(n, dict) else (n["type"] if n else None)
        tags = _node_tag_set(n) if n else set()
        if t == "goal" and str(key).startswith("goal:shell"):
            return 4
        if t == "foothold" and (_node_flag(n, "is_rce") or "getshell" in tags):
            return 3
        if t in ("vuln", "danger") and _closeable_verified(n, findings_by_key):
            return 3
        if _node_flag(n, "is_rce") and t == "vuln":
            return 2
        if t == "foothold":
            return 1
        return 0

    # 高优先级终点先搜；有结果就不再落到更弱的终点（避免长弯路停在半途 foothold）
    for prio in (4, 3, 2, 1, 0):
        group = [t for t in sinks if sink_prio(t) == prio]
        if not group:
            continue
        best_path: list[str] = []
        best_key: tuple[int, float] = (-1, -1.0)  # (hops, likelihood)
        cutoff = 16
        for s in sources:
            for t in group:
                if s == t:
                    key = (0, 1.0)
                    if key > best_key:
                        best_key = key
                        best_path = [s]
                    continue
                if s not in g or t not in g:
                    continue
                try:
                    for i, path in enumerate(nx.all_simple_paths(g, s, t, cutoff=cutoff)):
                        if i >= 4000:
                            break
                        hops = len(path) - 1
                        lik = _path_likelihood(g, path)
                        key = (hops, lik)
                        if key > best_key:
                            best_key = key
                            best_path = path
                except (nx.NetworkXNoPath, nx.NodeNotFound, nx.NetworkXError):
                    continue
        if best_path:
            return best_path

    # 枚举失败时退回概率最短路
    best_path = []
    best_cost = float("inf")
    for s in sources:
        for t in sinks:
            if s == t:
                return [s]
            try:
                cost, path = nx.single_source_dijkstra(g, s, target=t, weight="cost")
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if cost < best_cost:
                best_cost = cost
                best_path = path
    return best_path


async def recompute_rce_path(
    project_id: str, run_id: str | None = None, emit_event: bool = True
) -> dict:
    """计算并标记通往 RCE 的最优攻击链。

    连接线按「目标 → 中间点 → … → 本机 RCE/会话」多跳链路高亮。
    PIVOTS_TO 是独立的横向紫线，flag 是攻击成果；两者都不属于橙色 RCE 最优路径。
    终点优先已控 GETSHELL，其次已验证可收口的漏洞/危险点；未落地 foothold 和信息点不当橙线终点。
    若尚无这类终点，则取风险分最高的 danger/vuln 作为前沿高亮。

    emit_event=False 时只计算/标记、不推送事件（供只读的 get_graph 调用，防止刷新回路刷屏）。
    即使 emit_event=True，也仅在路径结果相对上次发生变化时才推送。
    """
    nodes = await db.fetchall("SELECT * FROM nodes WHERE project_id=?", (project_id,))
    edges = await db.fetchall("SELECT * FROM edges WHERE project_id=?", (project_id,))
    if not nodes:
        return {"path": [], "likelihood": 0.0}

    node_by_key = {n["key"]: n for n in nodes}
    g = nx.DiGraph()
    for n in nodes:
        g.add_node(n["key"])
    for e in edges:
        if e["src"] in node_by_key and e["dst"] in node_by_key:
            src_n, dst_n = node_by_key[e["src"]], node_by_key[e["dst"]]
            # 横向边语义上是「已控 shell → 下一台目标」，不能被当成当前主机的 RCE 链。
            if e["relation"] == "PIVOTS_TO":
                continue
            # 忽略目标直连 flag/goal 的捷径边，避免关系图出现「目标→flag」连线
            if src_n["type"] == "target" and (
                dst_n["type"] == "goal"
                or str(e["dst"]).startswith("goal:")
                or str(e["dst"]).startswith("flag:")
            ):
                continue
            w = max(0.01, min(1.0, e["weight"]))
            g.add_edge(e["src"], e["dst"], cost=-math.log(w), w=w, key_id=e["id"])

    sources = [n["key"] for n in nodes if n["type"] == "target"]
    if not sources:
        sources = [k for k in g.nodes if g.in_degree(k) == 0] or [nodes[0]["key"]]

    findings_rows = await db.fetchall(
        "SELECT * FROM findings WHERE project_id=?", (project_id,),
    )
    findings_by_key: dict[str, list] = {}
    for f in findings_rows:
        nk = f["node_key"] if "node_key" in f.keys() else ""
        if nk:
            findings_by_key.setdefault(nk, []).append(f)

    sinks = [n["key"] for n in nodes if _rce_sink_ok(n, findings_by_key)]
    frontier_mode = False
    if not sinks:
        frontier_mode = True
        ranked = sorted(
            [n for n in nodes if n["type"] in ("danger", "vuln") and not _transport_stuck(n)],
            key=lambda n: n["risk_score"], reverse=True,
        )
        if not ranked:
            ranked = sorted(
                [n for n in nodes if n["type"] in ("danger", "vuln")],
                key=lambda n: n["risk_score"], reverse=True,
            )
        sinks = [ranked[0]["key"]] if ranked else []

    # 每个已能到达 RCE 的 target 各自保留最优路径。横向边已从图中排除，
    # 因此每条橙线只代表本机 target → … → RCE，而不会跨主机串成一条线。
    paths: list[list[str]] = []
    seen_paths: set[tuple[str, ...]] = set()
    if sinks:
        for source in sources:
            path = _pick_attack_chain(g, [source], sinks, node_by_key, findings_by_key)
            sig = tuple(path)
            if len(path) >= 2 and sig not in seen_paths:
                paths.append(path)
                seen_paths.add(sig)
    # 无 RCE 时保留一个前沿路径；兼容旧调用方的 path 字段，选择最长的本机链。
    if not paths and sinks:
        fallback = _pick_attack_chain(g, sources, sinks, node_by_key, findings_by_key)
        if fallback:
            paths = [fallback]
    best_path = max(paths, key=lambda p: (len(p), _path_likelihood(g, p)), default=[])
    likelihood = round(_path_likelihood(g, best_path), 4) if best_path else 0.0

    # 标记所有本机最优路径的相邻边，不把路径上任意两点的捷径边一并高亮。
    path_pairs = {
        pair
        for path in paths
        for pair in zip(path, path[1:])
    }
    for e in edges:
        on = 1 if (e["src"], e["dst"]) in path_pairs else 0
        if e["on_rce_path"] != on:
            await db.execute("UPDATE edges SET on_rce_path=? WHERE id=?", (on, e["id"]))

    result = {
        "path": best_path,
        "paths": paths,
        "likelihood": likelihood,
        "frontier_mode": frontier_mode,
    }
    sig = (tuple(tuple(path) for path in paths), likelihood, frontier_mode)
    if emit_event and _last_rce_sig.get(project_id) != sig:
        _last_rce_sig[project_id] = sig
        await emit(project_id, "rce_path", result, run_id=run_id)
    return result


# ---- 序列化 -----------------------------------------------------------------

def _serialize_node(row: dict) -> dict:
    return {
        "id": row["id"], "key": row["key"], "type": row["type"],
        "title": scrub_candidate_rce_label(row["title"]) or row["title"],
        "detail": _loads(row["detail"]), "severity": row["severity"],
        "is_rce": bool(row["is_rce"]), "risk_score": row["risk_score"],
        "tags": _loads(row["tags"]) or [], "status": row["status"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


def _serialize_edge(row: dict) -> dict:
    return {
        "id": row["id"], "from": row["src"], "to": row["dst"], "relation": row["relation"],
        "weight": row["weight"], "rationale": row["rationale"],
        "on_rce_path": bool(row["on_rce_path"]),
    }


def _serialize_finding(row: dict) -> dict:
    # UI 图/发现面板只需预览；截断超长 evidence/poc，避免单页图 JSON 膨胀
    def _clip(s, n=600):
        if not s:
            return s
        s = str(s)
        return s if len(s) <= n else s[:n] + "…"
    def _get(k, default=None):
        try:
            return row[k]
        except (KeyError, IndexError, TypeError):
            return default if not isinstance(row, dict) else row.get(k, default)
    disp = display_finding_severity(row)
    return {
        "id": row["id"], "node_key": row["node_key"], "severity": disp,
        "category": row["category"],
        "title": scrub_candidate_rce_label(_get("title")) or _get("title"),
        "description": _clip(row["description"], 800),
        "evidence": _clip(row["evidence"], 600),
        "poc_curl": _clip(row["poc_curl"], 800),
        "poc_python": _clip(row["poc_python"], 800),
        "cvss": row["cvss"], "created_at": row["created_at"],
        "critical": disp == "critical",
        "verification_status": _get("verification_status") or "verified",
        "verified_at": _get("verified_at"),
        "proof_type": _get("proof_type"),
        "proof_canary": _get("proof_canary"),
        "proof_url": _clip(_get("proof_url"), 400),
        "proof_detail": _clip(_get("proof_detail"), 800),
        "secondary_verified": bool(_get("secondary_verified") or 0),
        "redteam_rating": _get("redteam_rating"),
        "redteam_rating_rationale": _clip(_get("redteam_rating_rationale"), 800),
    }


def _serialize_intent(row: dict) -> dict:
    return {
        "id": row["id"],
        "from": _loads(row["from_keys"]) or [],
        "description": row["description"],
        "rationale": row["rationale"],
        "est_success": row["est_success"],
        "status": row["status"],
        "strategy_key": row.get("strategy_key"),
        "evidence_fingerprint": row.get("evidence_fingerprint"),
        "priority": row.get("priority") if row.get("priority") is not None else row.get("est_success"),
        "attempt_count": int(row.get("attempt_count") or 0),
        "failure_fingerprint": row.get("failure_fingerprint"),
        "result_summary": row.get("result_summary"),
        "active_run_id": row.get("active_run_id"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


async def clear_graph(project_id: str) -> dict:
    """清空某项目的实时攻击图（节点/边/发现/意图）。保留 events(审计)/memory(跨 run 经验)/flags(计分)。"""
    for tbl in ("nodes", "edges", "findings", "intents"):
        await db.execute(f"DELETE FROM {tbl} WHERE project_id=?", (project_id,))
    return {"cleared": ["nodes", "edges", "findings", "intents"]}


def _host_from_tags(tags) -> str:
    """从节点 tags 里取出 host:<h> 标注的主机名（供横向判定用）。"""
    for t in tags or []:
        if isinstance(t, str) and t.startswith("host:"):
            h = t[5:].strip().lower().rstrip(".")
            if h:
                return h
    return ""


def lateral_state(nodes: list, edges: list) -> dict:
    """内网横向判定（唯一真源）：任一 PIVOTS_TO 边落图，或 foothold/goal 覆盖 ≥2 台不同主机。

    nodes/edges 可传 sqlite Row 或已序列化 dict。host 取自 foothold/goal 节点的 `host:<h>` tag。
    """
    def _rel(e) -> str:
        return (e.get("relation") if isinstance(e, dict) else e["relation"]) or ""

    def _type(n) -> str:
        return (n.get("type") if isinstance(n, dict) else n["type"]) or ""

    def _tags(n):
        raw = n.get("tags") if isinstance(n, dict) else n["tags"]
        return raw if isinstance(raw, list) else (_loads(raw) or [])

    pivot = sum(1 for e in edges if _rel(e) == "PIVOTS_TO")
    hosts: set[str] = set()
    for n in nodes:
        key = n.get("key") if isinstance(n, dict) else n["key"]
        if _type(n) == "foothold" or (_type(n) == "goal" and str(key).startswith("goal:shell")):
            h = _host_of_node(str(key), _tags(n))
            if h:
                hosts.add(h)
    return {
        "lateral_active": bool(pivot > 0 or len(hosts) >= 2),
        "pivot_edges": int(pivot),
        "hosts_footed": len(hosts),
    }


async def get_stats(project_id: str) -> dict:
    """轻量统计（用于项目列表卡片）：只做计数，不重算 rce_path/序列化，避免列表页为每个项目算全图而卡顿。"""
    batch = await get_stats_batch([project_id])
    return batch.get(project_id) or {
        "nodes": 0, "services": 0, "edges": 0, "findings": 0, "high": 0, "medium": 0, "low": 0, "critical": 0, "has_shell": False,
        "lateral_active": False, "pivot_edges": 0, "hosts_footed": 0,
        "mass_data_leak": False,
    }


# 红队「大量数据 / 关键泄露」卡片徽章（与 objective 白名单对齐；不含 phpinfo/info_disclosure）
_MASS_LEAK_CATS = set(DATA_ACCESS_CATEGORIES) | set(KEY_LEAK_CATEGORIES)
_MASS_LEAK_TAGS = {
    "data_leak", "backup_leak", "source_leak", "mass_disclosure", "dump", "db_dump",
    "key_leak", "hardcoded_secret", "mass_pii",
}


async def get_stats_batch(project_ids: list[str]) -> dict[str, dict]:
    """一次查出多个项目的卡片统计，避免列表/子项目页 N+1 查询卡顿。"""
    empty = {
        "nodes": 0, "services": 0, "edges": 0, "findings": 0, "high": 0, "medium": 0, "low": 0, "critical": 0, "has_shell": False,
        "lateral_active": False, "pivot_edges": 0, "hosts_footed": 0,
        "mass_data_leak": False,
    }
    ids = [p for p in project_ids if p]
    if not ids:
        return {}
    out: dict[str, dict] = {pid: dict(empty) for pid in ids}
    hosts_by_pid: dict[str, set] = {pid: set() for pid in ids}
    placeholders = ",".join("?" * len(ids))

    nrows = await db.fetchall(
        f"SELECT project_id, key, type, is_rce, tags FROM nodes WHERE project_id IN ({placeholders})",
        tuple(ids),
    )
    for n in nrows:
        s = out[n["project_id"]]
        s["nodes"] += 1
        if n["type"] == "service":
            s["services"] += 1
        # has_shell 由 verified findings / goal 节点判定，vuln 节点 alone 不点亮。
        if n["type"] == "foothold" or (
            n["type"] == "goal" and str(n.get("key") or "").startswith("goal:shell")
        ):
            h = _host_of_node(str(n.get("key") or ""), _loads(n["tags"]) or [])
            if h:
                hosts_by_pid[n["project_id"]].add(h)
        ntags = {str(t).lower() for t in (_loads(n["tags"]) or [])}
        if ntags & _MASS_LEAK_TAGS:
            s["mass_data_leak"] = True

    erows = await db.fetchall(
        f"SELECT project_id, COUNT(*) AS c FROM edges WHERE project_id IN ({placeholders}) GROUP BY project_id",
        tuple(ids),
    )
    for e in erows:
        out[e["project_id"]]["edges"] = int(e["c"] or 0)

    prows = await db.fetchall(
        f"SELECT project_id, COUNT(*) AS c FROM edges "
        f"WHERE project_id IN ({placeholders}) AND relation='PIVOTS_TO' GROUP BY project_id",
        tuple(ids),
    )
    for e in prows:
        out[e["project_id"]]["pivot_edges"] = int(e["c"] or 0)

    frows = await db.fetchall(
        f"SELECT project_id, severity, category, title, verification_status, node_key, redteam_rating FROM findings "
        f"WHERE project_id IN ({placeholders})",
        tuple(ids),
    )
    f_by_pid: dict[str, list] = defaultdict(list)
    for f in frows:
        # rejected 不计入发现数
        try:
            st = f["verification_status"]
        except (KeyError, IndexError):
            st = "verified"
        if st is None:
            st = "verified"
        if st == "rejected":
            continue
        severity = display_finding_severity(f)
        if severity not in USER_VISIBLE_SEVERITIES:
            continue
        f_by_pid[f["project_id"]].append(f)
        s = out[f["project_id"]]
        cat = str(f["category"] or "").lower()
        if cat in _MASS_LEAK_CATS:
            s["mass_data_leak"] = True
        try:
            nkey = str(f["node_key"] or "")
        except (KeyError, IndexError):
            nkey = ""
        if st in ("verified", "flaky") and (
            cat in ("rce", "command_injection", "deserialization")
            or nkey.startswith(("goal:shell", "foothold:shell"))
        ):
            s["has_shell"] = True
    for pid, rows in f_by_pid.items():
        listed = listed_finding_rows(rows)
        s = out[pid]
        s["findings"] = len(listed)
        # 列表统计必须严格按严重度展示：high 不能被“可报告/关键类别”再归入 critical。
        # 风险判定函数 is_critical 仍供报告优先级使用，但不应用于这两个 UI 计数。
        # 同洞重复稿与发现页折叠规则一致，不计入高危/严重。
        s["critical"] = sum(1 for r in listed if display_finding_severity(r) == "critical")
        s["high"] = sum(1 for r in listed if display_finding_severity(r) == "high")

    for pid in ids:
        s = out[pid]
        s["hosts_footed"] = len(hosts_by_pid[pid])
        s["lateral_active"] = bool(s["pivot_edges"] > 0 or s["hosts_footed"] >= 2)
    return out


async def _rce_path_from_marks(project_id: str) -> dict:
    """只读：从已标记的 on_rce_path 边还原路径，不触发 networkx 重算/写库。"""
    edges = await db.fetchall(
        "SELECT src, dst, weight FROM edges WHERE project_id=? AND on_rce_path=1",
        (project_id,),
    )
    if not edges:
        return {"path": [], "paths": [], "likelihood": 0.0, "frontier_mode": False}
    succ: dict[str, list[tuple[str, float]]] = {}
    indeg: dict[str, int] = {}
    for e in edges:
        succ.setdefault(e["src"], []).append((e["dst"], float(e["weight"] or 0.5)))
        indeg[e["dst"]] = indeg.get(e["dst"], 0) + 1
        indeg.setdefault(e["src"], 0)
    starts = [k for k, d in indeg.items() if d == 0] or [edges[0]["src"]]
    # 每个无入边起点是一台主机的一条独立最优 RCE 链；保留全部供关系图逐条绘制。
    paths: list[list[str]] = []
    likelihoods: list[float] = []
    for s in starts:
        path = [s]
        like = 1.0
        cur = s
        seen = {s}
        while succ.get(cur):
            nxt, w = succ[cur][0]
            if nxt in seen:
                break
            path.append(nxt)
            like *= max(0.01, min(1.0, w))
            seen.add(nxt)
            cur = nxt
        if len(path) >= 2:
            paths.append(path)
            likelihoods.append(like)
    best_idx = max(
        range(len(paths)),
        key=lambda i: (len(paths[i]), likelihoods[i]),
        default=None,
    )
    best = paths[best_idx] if best_idx is not None else []
    best_like = likelihoods[best_idx] if best_idx is not None else 0.0
    return {"path": best, "paths": paths,
            "likelihood": round(best_like, 4) if len(best) > 1 else 0.0,
            "frontier_mode": False}


async def get_graph(project_id: str, *, heal: bool = False) -> dict:
    """读取攻击图快照。

    heal=True：写路径/收尾用，会补边并重算 RCE 路径（较慢）。
    heal=False（默认，UI/WS/列表）：只读已落库标记，避免每次打开页面都 networkx 重算把 SQLite 打满。
    写入节点/边时已调用 ensure_target_attachments + recompute_rce_path，日常展示不必再算。
    """
    if heal:
        await ensure_target_attachments(project_id, run_id=None)
        path = await recompute_rce_path(project_id, emit_event=False)
    else:
        # 只读路径也轻量自愈横向边：完成后项目打开时，多主机立足点缺 PIVOTS_TO 会补上紫线
        await ensure_lateral_pivots(project_id, run_id=None)
        try:
            from ..projects import get_project as _gp
            from ..entry_fingerprint import project_entry_hosts
            _p = await _gp(project_id)
            _host = str((_p or {}).get("target") or "").split(":")[0]
            keep = project_entry_hosts(_p) if _p else set()
            if _host:
                await adopt_entry_host(project_id, _host, keep_hosts=keep)
        except Exception:
            pass
        try:
            await reopen_live_hop_auth(project_id)
            await defer_local_closeout_for_remaining_flags(project_id)
        except Exception:
            pass
        path = await _rce_path_from_marks(project_id)
    nodes = await db.fetchall("SELECT * FROM nodes WHERE project_id=? ORDER BY created_at", (project_id,))
    findings_all = await db.fetchall(
        "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,)
    )
    from .verify import is_visible_finding
    findings = [f for f in findings_all if is_visible_finding(f)]
    def _sev(row) -> str:
        try:
            return str(row["severity"] or "").lower()
        except Exception:
            return ""
    listed = listed_finding_rows(findings)
    edges = await db.fetchall("SELECT * FROM edges WHERE project_id=? ORDER BY created_at", (project_id,))
    intents = await list_open_intents(project_id, limit=30)
    disproved = await list_disproved_intents(project_id, limit=12)
    fstats = await frontier_stats(project_id)
    # has_shell：只有已控 shell/GETSHELL；未落地 foothold 和漏洞节点不算
    verified_shell = any(
        (n["type"] in ("foothold", "goal") and (
            bool(n["is_rce"])
            or "getshell" in (_loads(n["tags"]) or [])
            or str(n["key"] or "").startswith("goal:shell")
        ))
        for n in nodes
    )
    out = {
        "nodes": [_serialize_node(n) for n in nodes],
        "edges": [_serialize_edge(e) for e in edges],
        "findings": [_serialize_finding(f) for f in findings],
        "intents": intents,
        "disproved": disproved,
        "frontier": fstats,
        "rce_path": path,
        "stats": {
            "nodes": len(nodes),
            "services": sum(1 for n in nodes if n["type"] == "service"),
            "edges": len(edges),
            "findings": len(findings),
            "high": sum(1 for f in listed if str(f["severity"] or "").lower() == "high"),
            "medium": sum(1 for f in findings if _sev(f) == "medium"),
            "low": sum(1 for f in findings if _sev(f) in ("low", "info")),
            "critical": sum(1 for f in listed if str(f["severity"] or "").lower() == "critical"),
            "has_shell": bool(verified_shell),
            "frontier_open": fstats.get("open", 0),
            "frontier_strategies": fstats.get("strategies", 0),
            **lateral_state(nodes, edges),
        },
    }
    return out
