"""赛道：红队(redteam) 与 CTF(flag)。"""
from __future__ import annotations

import re

from .graph.model import display_finding_severity

REDTEAM = "redteam"
FLAG = "flag"

RT_GETSHELL = "getshell"
RT_DATA_ACCESS = "data_access"
RT_ADMIN_ACCESS = "admin_access"
RT_KEY_LEAK = "key_leak"
RT_ADMIN_AND_KEY = "admin_and_key"
CTF_GETFLAG = "getflag"
MEANS_PRIVESC = "privesc"
MEANS_LATERAL = "lateral"

ULTIMATE_GOALS: dict[str, tuple[str, ...]] = {
    FLAG: (CTF_GETFLAG,),
    REDTEAM: (RT_GETSHELL,),
}
MEANS_GOALS: tuple[str, ...] = (MEANS_PRIVESC, MEANS_LATERAL)
GOAL_ALIASES: dict[str, str] = {
    "db_access": RT_DATA_ACCESS,
    "mass_data_leak": RT_DATA_ACCESS,
}

DATA_ACCESS_CATEGORIES: frozenset[str] = frozenset({
    "db_access", "db_dump", "dump",
    "data_leak", "mass_data_leak", "mass_disclosure",
})
KEY_LEAK_CATEGORIES: frozenset[str] = frozenset({
    "source_leak", "backup_leak", "hardcoded_secret", "cloud_credential",
    "mass_pii", "sensitive_data_exposure", "credential_dump", "secrets_leak",
    "key_leak",
})
TRIVIAL_INFO_CATEGORIES: frozenset[str] = frozenset({
    "info_disclosure", "information_disclosure", "info", "info_leak",
    "tech-stack", "tech_stack", "banner", "version", "phpinfo",
    "path_disclosure", "directory_listing",
})
USER_VISIBLE_SEVERITIES: frozenset[str] = frozenset({"high", "critical"})

_FINDING_FAMILY = {
    "lfi": "file_read",
    "arbitrary_file_read": "file_read",
    "path_traversal": "file_read",
    "command_injection": "rce",
    "file_write": "rce",
    "file_upload": "rce",
}
_API_PATH_RE = re.compile(r"/api/[A-Za-z0-9_./-]+", re.I)


def normalize_objective(obj: str | None) -> str:
    o = (obj or "").strip().lower()
    if o in ("flag", "ctf"):
        return FLAG
    return REDTEAM


def objective_allows_flag(obj: str | None) -> bool:
    return normalize_objective(obj) == FLAG


def cfg_is_lab_src(cfg: dict | None) -> bool:
    """Flash 无 SRC 赛道；评测胶水一律按 CTF flag 处理。"""
    return False


def ultimate_goals(obj: str | None) -> tuple[str, ...]:
    return ULTIMATE_GOALS[normalize_objective(obj)]


def canon_goal(name: str | None) -> str:
    n = (name or "").strip().lower()
    return GOAL_ALIASES.get(n, n)


def ctf_needed_flags(*, flags_needed: int | None = None, flag_count: int | None = None) -> int:
    for v in (flags_needed, flag_count):
        try:
            n = int(v or 0)
        except (TypeError, ValueError):
            n = 0
        if n > 0:
            return n
    return 1


def ctf_full_score(
    *,
    flags_correct: int = 0,
    flags_needed: int | None = None,
    flag_count: int | None = None,
    flags_score: float = 0.0,
    total_score: float | int | None = None,
) -> bool:
    """本题是否收工：正确 flag 数 ≥ 所需。

    平台 total_score 是理论满分（常含时间衰减）。flag 数齐后的分差不是还能再交的 flag，
    不要为此占槽。flags_score / total_score 仅保留给调用方展示。
    """
    needed = ctf_needed_flags(flags_needed=flags_needed, flag_count=flag_count)
    try:
        got = int(flags_correct or 0)
    except (TypeError, ValueError):
        got = 0
    _ = (flags_score, total_score)
    return got >= needed


def ctf_full_score_from_project(
    project: dict | None,
    *,
    flags_correct: int = 0,
    flags_needed: int | None = None,
    flags_score: float = 0.0,
) -> bool:
    cfg = (project or {}).get("config") or {}
    return ctf_full_score(
        flags_correct=flags_correct,
        flags_needed=flags_needed,
        flag_count=cfg.get("flag_count"),
        flags_score=flags_score,
        total_score=cfg.get("total_score"),
    )


def redteam_ultimate_reached(achievements: list[str] | set[str] | None) -> bool:
    ach = {canon_goal(a) for a in (achievements or [])}
    return RT_GETSHELL in ach


def redteam_new_ultimate(
    now: list[str] | set[str] | None,
    baseline: list[str] | set[str] | None = None,
) -> bool:
    if not redteam_ultimate_reached(now):
        return False
    now_s = {canon_goal(a) for a in (now or [])}
    base_s = {canon_goal(a) for a in (baseline or [])}
    return RT_GETSHELL in now_s and RT_GETSHELL not in base_s


def is_run_complete(
    obj: str | None,
    *,
    flags_correct: int = 0,
    flags_needed: int | None = None,
    flag_count: int | None = None,
    flags_score: float = 0.0,
    total_score: float | int | None = None,
    achievements: list[str] | set[str] | None = None,
) -> bool:
    o = normalize_objective(obj)
    if o == FLAG:
        return ctf_full_score(
            flags_correct=flags_correct,
            flags_needed=flags_needed,
            flag_count=flag_count,
            flags_score=flags_score,
            total_score=total_score,
        )
    return redteam_ultimate_reached(achievements)


def hard_stop_exempt(
    obj: str | None,
    *,
    flags_correct: int = 0,
    achievements: list[str] | set[str] | None = None,
    verified_high: int = 0,
    verified_critical: int = 0,
) -> bool:
    o = normalize_objective(obj)
    if o == FLAG:
        return int(flags_correct or 0) > 0
    return redteam_ultimate_reached(achievements)


def user_visible_finding(
    obj: str | None = None,
    *,
    severity: str | None = None,
    verification_status: str | None = "verified",
    category: str | None = None,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
) -> bool:
    vs = (verification_status or "verified").strip().lower()
    if vs not in ("verified", "flaky"):
        return False
    return (severity or "").strip().lower() in USER_VISIBLE_SEVERITIES


def _row_field(row: object, key: str) -> str:
    try:
        v = row.get(key) if isinstance(row, dict) else row[key]  # type: ignore[index]
    except Exception:
        return ""
    return "" if v is None else str(v)


def _finding_path_key(title: str, category: str) -> str:
    m = _API_PATH_RE.search(f"{title} {category}")
    return m.group(0).lower() if m else ""


def _finding_family(category: str) -> str:
    c = (category or "").strip().lower()
    return _FINDING_FAMILY.get(c, c)


def listed_finding_rows(rows: list) -> list:
    verified = [r for r in rows if _row_field(r, "verification_status").strip().lower() in ("", "verified")]
    verified_keys = {
        k for r in verified
        if (k := _finding_path_key(_row_field(r, "title"), _row_field(r, "category")))
    }
    verified_fam = {
        fam for r in verified
        if (fam := _finding_family(_row_field(r, "category")))
    }
    out = []
    for r in rows:
        vs = _row_field(r, "verification_status").strip().lower() or "verified"
        if vs == "rejected":
            continue
        sev = display_finding_severity(r)
        if sev not in USER_VISIBLE_SEVERITIES:
            continue
        title = _row_field(r, "title")
        cat = _row_field(r, "category")
        if vs == "pending":
            k = _finding_path_key(title, cat)
            if k and k in verified_keys:
                continue
            if not k and _finding_family(cat) in verified_fam:
                continue
        out.append(r)
    return out


def awarded_sum(captured: list | None) -> float:
    total = 0.0
    for x in captured or []:
        if not isinstance(x, dict) or not x.get("correct"):
            continue
        try:
            total += float(x.get("awarded") or 0)
        except (TypeError, ValueError):
            pass
    return total
