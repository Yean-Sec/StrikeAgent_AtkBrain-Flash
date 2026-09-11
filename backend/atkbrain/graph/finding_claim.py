"""漏洞上报纠偏：未证明的 RCE 不得抬级；同一 CVE/同一利用口不得重复造条。"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .model import SEVERITY_ORDER, normalize_redteam_rating, normalize_severity

_CVE_RE = re.compile(r"cve-\d{4}-\d{4,}", re.I)
_AJAX_ACTION_RE = re.compile(
    r"fusion_form_submit_ajax|fusion_form_update_view|action=fusion_form_[a-z0-9_]+",
    re.I,
)
_EXEC_RE = re.compile(
    r"\bwhoami\b|uid=\d+|www-data|phpinfo\s*\(|\bshell_exec\b|"
    r"command executed|命令执行成功|canary_ok",
    re.I,
)
_NO_EXEC_RE = re.compile(
    r"未打成执行|未证明\s*rce|尚未证明|未获得代码执行|rce\s*未证明|"
    r"upload_failed|未打通|没有解释器|未复现|版本命中|"
    r"不给\s*rce|不标\s*rce|不能评.{0,8}rce|未打成.{0,6}执行",
    re.I,
)
_WRITE_HINT_RE = re.compile(r"upload|file_write|file write|写入|上传|fusion-forms", re.I)

RCE_CLAIM_CATEGORIES = frozenset({
    "rce", "command_injection", "deserialization", "ssti", "code_execution",
})


def _field(row: Any, key: str) -> str:
    if isinstance(row, dict):
        v = row.get(key)
    else:
        try:
            v = row[key]
        except Exception:
            v = getattr(row, key, None)
    return "" if v is None else str(v)


def _blob(*parts: Any) -> str:
    return " ".join(str(p or "") for p in parts)


def execution_impact_proven(*parts: Any) -> bool:
    """证据里是否已有命令执行回显。版本命中 / 未打成执行 不算。"""
    blob = _blob(*parts)
    if _NO_EXEC_RE.search(blob) and not _EXEC_RE.search(blob):
        return False
    return bool(_EXEC_RE.search(blob))


def claims_rce(*parts: Any, category: str = "") -> bool:
    cat = str(category or "").strip().lower()
    if cat in RCE_CLAIM_CATEGORIES:
        return True
    blob = _blob(*parts).lower()
    return "rce" in blob or "命令执行" in blob or "getshell" in blob


def finding_dedup_keys(*parts: Any) -> set[str]:
    """同一 CVE 或同一利用接口视为一条。没有这类锚点则不合并。"""
    blob = _blob(*parts).lower()
    keys: set[str] = set()
    for m in _CVE_RE.findall(blob):
        keys.add("cve:" + m.lower())
    for m in _AJAX_ACTION_RE.findall(blob):
        keys.add("ep:" + re.sub(r"[^a-z0-9_]+", "", m.lower()))
    if "fusion-forms" in blob or "fusion_form" in blob:
        keys.add("ep:fusion_form_upload")
    return keys


def finding_dedup_keys_from_row(row: Any) -> set[str]:
    return finding_dedup_keys(
        _field(row, "title"),
        _field(row, "category"),
        _field(row, "node_key"),
        _field(row, "description"),
        _field(row, "evidence"),
        _field(row, "poc_curl"),
        _field(row, "poc_python"),
    )


def coerce_unproven_rce_claim(
    *,
    category: str | None,
    severity: str | None,
    redteam_rating: str | None,
    title: str = "",
    description: str = "",
    evidence: str = "",
    poc_curl: str = "",
    poc_python: str = "",
) -> tuple[str, str, str | None]:
    """未打成执行时：去掉 rce 类别，严重度和红队评级最高 medium。"""
    cat = str(category or "info").strip().lower() or "info"
    parts = (title, description, evidence, poc_curl, poc_python, cat)
    proven = execution_impact_proven(*parts)
    rce_claim = claims_rce(*parts, category=cat)
    if rce_claim and not proven:
        blob = _blob(*parts)
        cat = "file_write" if _WRITE_HINT_RE.search(blob) else "vuln"
    sev = normalize_severity(cat, severity)
    rating = normalize_redteam_rating(redteam_rating)
    if rce_claim and not proven:
        if SEVERITY_ORDER.get(sev, 0) > SEVERITY_ORDER["medium"]:
            sev = "medium"
        if rating in ("high", "critical"):
            rating = "medium"
    return cat, sev, rating


def pick_canonical_finding(members: list) -> Any:
    def _key(row: Any) -> tuple:
        sec = 1 if str(_field(row, "secondary_verified") or "").strip() not in ("", "0", "false", "False") else 0
        try:
            ts = float(_field(row, "created_at") or 0)
        except (TypeError, ValueError):
            ts = 0.0
        return (-sec, ts, _field(row, "id"))
    return sorted(members, key=_key)[0]


def collapse_duplicate_findings(rows: list) -> list:
    """按 CVE/利用口并集聚类，每簇只留一条（已二次验证优先，其次最早入库）。"""
    if len(rows) <= 1:
        return list(rows)
    n = len(rows)
    keys = [finding_dedup_keys_from_row(r) for r in rows]
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        if not keys[i]:
            continue
        for j in range(i + 1, n):
            if keys[j] and keys[i] & keys[j]:
                union(i, j)
    clusters: dict[int, list] = defaultdict(list)
    for i in range(n):
        clusters[find(i)].append(rows[i])
    return [pick_canonical_finding(members) for members in clusters.values()]
