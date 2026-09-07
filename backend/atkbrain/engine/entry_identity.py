"""入口身份：题面/攻击图预期栈 vs 当前首页栈。

评测容器 IP 会重绑到另一题。图上的 PHP 路径和账号不能套到当前 Flask 页。
与具体题目路径无关。
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

_FAMILY_PATTERNS: dict[str, tuple[str, ...]] = {
    "php": (
        r"\bphp(?:/[\d.]+)?\b",
        r"x-powered-by:\s*php",
        r"\bthinkphp\b",
        r"\blaravel\b",
        r"\bwordpress\b",
        r"\.php(?:\b|\?|$|/)",
    ),
    "python-web": (
        r"\bwerkzeug\b",
        r"\bflask\b",
        r"\bdjango\b",
        r"\bgunicorn\b",
        r"\buvicorn\b",
        r"\bwsgiserver\b",
        r"\bjinja2?\b",
    ),
    "java": (
        r"\btomcat\b",
        r"\bweblogic\b",
        r"\bspring\b",
        r"\bjsessionid\b",
        r"\.jsp(?:\b|\?|$|/)",
        r"\bweaver\b",
        r"\becology\b",
        r"泛微",
    ),
    "aspnet": (
        r"\basp\.net\b",
        r"\baspx\b",
        r"\biis/",
    ),
    "node": (
        r"\bexpress\b",
        r"\bnext\.js\b",
        r"x-powered-by:\s*express",
    ),
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def infer_families(text: str) -> set[str]:
    t = text or ""
    hit: set[str] = set()
    for fam, pats in _FAMILY_PATTERNS.items():
        for p in pats:
            if re.search(p, t, re.I):
                hit.add(fam)
                break
    return hit


def graph_stack_text(graph: dict | None, limit: int = 24000) -> str:
    parts: list[str] = []
    for n in (graph or {}).get("nodes") or []:
        if not isinstance(n, dict):
            continue
        tags = n.get("tags") or []
        if isinstance(tags, (list, tuple)):
            tag_s = " ".join(str(x) for x in tags)
        else:
            tag_s = str(tags)
        parts.append(f"{n.get('key','')} {n.get('title','')} {n.get('type','')} {tag_s}")
        if sum(len(x) for x in parts) >= limit:
            break
    return " ".join(parts)[:limit]


def live_stack_text(live: dict | None) -> str:
    p = live or {}
    headers = p.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    hdr = " ".join(f"{k}: {v}" for k, v in headers.items())
    return " ".join([
        hdr,
        str(p.get("server") or ""),
        str(p.get("title") or ""),
        str(p.get("body") or "")[:4000],
    ])


def classify_entry_identity(
    *,
    brief: str = "",
    graph: dict | None = None,
    live: dict | None = None,
) -> dict[str, Any]:
    """expected ∩ live 为空且两边都有栈信号 → mismatch。

    图被邻题污染时 expected 是并集，当前首页栈仍落在并集里则不误报。
    """
    expected = infer_families(f"{brief or ''} {graph_stack_text(graph)}")
    live_fams = infer_families(live_stack_text(live))
    mismatch = bool(expected and live_fams and live_fams.isdisjoint(expected))
    return {
        "expected": sorted(expected),
        "live": sorted(live_fams),
        "mismatch": mismatch,
        "title": str((live or {}).get("title") or "")[:120],
        "server": str((live or {}).get("server") or "")[:80],
        "status": (live or {}).get("status"),
    }


def parse_http_identity(raw: bytes, headers: dict[str, str], status: int | None) -> dict[str, Any]:
    body = ""
    try:
        body = raw.decode("utf-8", errors="ignore")
    except Exception:
        body = ""
    m = _TITLE_RE.search(body)
    title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    hdr_l = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    return {
        "status": status,
        "headers": hdr_l,
        "server": hdr_l.get("server") or hdr_l.get("x-powered-by") or "",
        "title": title[:200],
        "body": body[:4000],
    }


async def probe_entry_http(host: str, port: int, timeout: float = 4.0) -> dict[str, Any]:
    """只打授权入口首页，用于栈指纹。失败返回空 dict。"""
    if not host:
        return {}
    try:
        port_i = int(port or 80)
    except Exception:
        port_i = 80
    scheme = "https" if port_i == 443 else "http"
    url = f"{scheme}://{host}:{port_i}/"

    def _get() -> dict[str, Any]:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"User-Agent": "StrikeAgent-AtkBrain-Flash-identity/1", "Accept": "text/html,*/*"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(8000)
                hdrs = dict(resp.headers.items()) if resp.headers else {}
                return parse_http_identity(raw, hdrs, int(getattr(resp, "status", 200) or 200))
        except urllib.error.HTTPError as e:
            raw = b""
            try:
                raw = e.read(8000)
            except Exception:
                pass
            hdrs = dict(e.headers.items()) if e.headers else {}
            return parse_http_identity(raw, hdrs, int(e.code or 0))
        except Exception:
            return {}

    try:
        return await asyncio.wait_for(asyncio.to_thread(_get), timeout=timeout + 1.0)
    except Exception:
        return {}


async def running_peers_same_entry(project_id: str, host: str) -> list[str]:
    """其它正在跑的项目是否绑了同一入口 IP（评测重绑撞车）。"""
    from ..db import db
    h = (host or "").strip()
    if not h:
        return []
    rows = await db.fetchall(
        "SELECT id, name, target FROM projects WHERE status='running' AND id != ?",
        (project_id,),
    )
    peers: list[str] = []
    for r in rows:
        other = str(r["target"] or "").split(":")[0]
        if other and other == h:
            peers.append(str(r["name"] or r["id"]))
    return peers
