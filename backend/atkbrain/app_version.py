"""本机版本与 GitHub Release 对照。只提示，不自动升级。"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

_FALLBACK = "0.5.0-beta.1"
_CACHE_TTL = 10 * 60
_cache: dict[str, Any] = {"at": 0.0, "payload": None}

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def local_version() -> str:
    p = REPO_ROOT / "VERSION"
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return _FALLBACK
    line = (text.splitlines() or [""])[0].strip()
    return line or _FALLBACK


def normalize_ver(raw: str | None) -> str:
    s = str(raw or "").strip()
    if s.lower().startswith("v") and len(s) > 1 and s[1].isdigit():
        return s[1:]
    return s


def _parse(raw: str | None):
    from packaging.version import InvalidVersion, Version

    s = normalize_ver(raw)
    if not s:
        return None
    try:
        return Version(s)
    except InvalidVersion:
        return None


def _headers() -> dict[str, str]:
    from .config import settings

    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "StrikeAgent_AtkBrain-Flash",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = str(getattr(settings, "github_token", "") or "").strip()
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _repo_slug() -> str:
    from .config import settings

    raw = str(getattr(settings, "github_repo", "") or "").strip()
    raw = raw.removeprefix("https://github.com/").removeprefix("http://github.com/")
    raw = raw.strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    return raw or "Yean-Sec/StrikeAgent_AtkBrain-Flash"


def _gh_get(path: str) -> tuple[int, Any]:
    import httpx

    url = "https://api.github.com" + path
    try:
        with httpx.Client(timeout=6.0, follow_redirects=True) as client:
            r = client.get(url, headers=_headers())
    except Exception as e:
        return 0, {"message": str(e)[:240]}
    try:
        data = r.json()
    except Exception:
        data = {"message": (r.text or "")[:240]}
    return r.status_code, data


def _from_release(data: dict) -> dict[str, Any]:
    tag = str(data.get("tag_name") or "").strip()
    body = str(data.get("body") or "").strip()
    html = str(data.get("html_url") or "").strip()
    return {
        "latest_tag": tag,
        "latest": normalize_ver(tag),
        "html_url": html,
        "notes": body[:1200],
    }


def _newest_release(items: list) -> dict[str, Any] | None:
    best = None
    best_v = None
    for item in items or []:
        if not isinstance(item, dict) or item.get("draft"):
            continue
        parsed = _parse(item.get("tag_name"))
        if parsed is None:
            continue
        if best_v is None or parsed > best_v:
            best_v = parsed
            best = item
    return _from_release(best) if best else None


def _status_for(local: str, remote: str | None) -> tuple[str, str, bool]:
    """远程没有发行、或本机不低于远程，都算最新。只提示，不升级。"""
    if not remote:
        return "latest", "已是最新", True
    lv = _parse(local)
    rv = _parse(remote)
    if lv is None or rv is None:
        if normalize_ver(local) == normalize_ver(remote):
            return "latest", "已是最新", True
        return "update_available", f"有新版本 v{normalize_ver(remote)}", False
    if rv > lv:
        return "update_available", f"有新版本 v{normalize_ver(remote)}", False
    return "latest", "已是最新", True


def check_latest(*, force: bool = False) -> dict[str, Any]:
    now = time.monotonic()
    if not force and _cache["payload"] and (now - float(_cache["at"] or 0)) < _CACHE_TTL:
        return dict(_cache["payload"])

    local = local_version()
    slug = _repo_slug()
    payload: dict[str, Any] = {
        "local": local,
        "latest": None,
        "latest_tag": None,
        "is_latest": True,
        "status": "latest",
        "html_url": f"https://github.com/{slug}/releases",
        "notes": "",
        "message": "已是最新",
        "repo": slug,
    }

    code, data = _gh_get(f"/repos/{slug}/releases?per_page=30")
    remote: dict[str, Any] | None = None
    if code == 200 and isinstance(data, list):
        remote = _newest_release(data)
    elif code == 200 and isinstance(data, dict) and data.get("tag_name"):
        remote = _from_release(data)

    if remote:
        payload.update({
            "latest": remote.get("latest"),
            "latest_tag": remote.get("latest_tag"),
            "html_url": remote.get("html_url") or payload["html_url"],
            "notes": remote.get("notes") or "",
        })
        st, message, is_latest = _status_for(local, remote.get("latest"))
        payload["status"] = st
        payload["is_latest"] = is_latest
        payload["message"] = message
    else:
        payload["status"] = "latest"
        payload["is_latest"] = True
        payload["message"] = "已是最新"

    _cache["at"] = now
    _cache["payload"] = dict(payload)
    return payload
