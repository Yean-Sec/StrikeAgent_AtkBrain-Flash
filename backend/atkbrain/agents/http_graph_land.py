"""把单次 HTTP 探测结果分类成攻击图节点（纯函数，不写库）。

自动落图只覆盖「一条 curl / http_request 打到的活路径」，不扫 ffuf 词表。
从者仍须对脚本结论、参数面、已验证洞自行 add_node。
"""
from __future__ import annotations

import re

_PATH_INFO_STATUSES = {200, 204, 301, 302, 303, 307, 308}
_PATH_DANGER_STATUSES = {401, 403, 405, 500, 502, 503}

_HTTP_PROBE_BIN = re.compile(
    r"(?:^|[;&|\n]\s*|`\s*|\(\s*)(?:/usr/bin/)?(?:curl|wget)(?:\.exe)?\b",
    re.I,
)
_SCANNER_BIN = re.compile(
    r"\b(?:ffuf|gobuster|feroxbuster|dirb|dirbuster|nmap|nuclei|httpx|nikto|wfuzz|dirsearch)\b",
    re.I,
)
_URL_IN_CMD = re.compile(r"https?://[^\s'\"\\<>]+", re.I)
_HTTP_STATUS = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})\b", re.I)
_WGET_STATUS = re.compile(
    r"(?:HTTP request sent[^\n]*?|awaiting response\.\.\.\s*)(\d{3})\b",
    re.I,
)


def _norm_path(path: str) -> str:
    raw = (path or "/").split("?", 1)[0] or "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    if len(raw) > 1:
        raw = raw.rstrip("/")
    return raw or "/"


def classify_http_path_node(*, path: str, status) -> tuple[str, str, str] | None:
    """路径节点：(type, title, severity)。根路径和 404 不落点（根由 service 覆盖）。"""
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None
    raw = _norm_path(path)
    if raw in ("/", ""):
        return None
    if code == 404:
        return None
    if code in _PATH_DANGER_STATUSES:
        sev = "medium" if code >= 500 else "low"
        return "danger", f"{raw} {code}", sev
    if code in _PATH_INFO_STATUSES:
        return "info", f"{raw} {code}", "info"
    return None


def http_path_node_key(*, host: str, port: int, path: str) -> str:
    p = _norm_path(path)
    return f"http:{host}:{int(port)}{p}"[:160]


def parse_curl_http(*, command: str, stdout: str) -> dict | None:
    """单次 curl/wget 且 stdout 带状态码时抽出 url+status；扫描器命令一律跳过。"""
    cmd = command or ""
    if _SCANNER_BIN.search(cmd):
        return None
    if not _HTTP_PROBE_BIN.search(cmd):
        return None
    murl = _URL_IN_CMD.search(cmd)
    if not murl:
        return None
    url = murl.group(0).rstrip("),;\"'")
    blob = stdout or ""
    ms = _HTTP_STATUS.search(blob) or _WGET_STATUS.search(blob)
    if not ms:
        return None
    return {"url": url, "status": int(ms.group(1))}
