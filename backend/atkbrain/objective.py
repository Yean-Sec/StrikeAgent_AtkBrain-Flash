"""赛道：红队(redteam)、CTF(flag)、SRC(src)。三赛道目标函数硬隔离。"""
from __future__ import annotations

import re

from .graph.model import SEVERITY_ORDER, display_finding_severity

REDTEAM = "redteam"
FLAG = "flag"
SRC = "src"

# 用户可见角色名（代码标识 advisor/supervisor/commander 不改）
ROLE_EXECUTOR = "从者"  # 攻击主会话
ROLE_MASTER = "御主"  # 顾问会话

RT_GETSHELL = "getshell"
RT_DATA_ACCESS = "data_access"
RT_ADMIN_ACCESS = "admin_access"
RT_KEY_LEAK = "key_leak"
RT_ADMIN_AND_KEY = "admin_and_key"
CTF_GETFLAG = "getflag"
SRC_HIGH = "high_critical_finding"
MEANS_PRIVESC = "privesc"
MEANS_LATERAL = "lateral"

ULTIMATE_GOALS: dict[str, tuple[str, ...]] = {
    FLAG: (CTF_GETFLAG,),
    REDTEAM: (RT_GETSHELL,),
    SRC: (SRC_HIGH,),
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
USER_VISIBLE_SEVERITIES: frozenset[str] = frozenset({
    "info", "low", "medium", "high", "critical",
})
SRC_VISIBLE_SEVERITIES: frozenset[str] = USER_VISIBLE_SEVERITIES
SRC_SKIP_CATEGORIES: frozenset[str] = frozenset({
    "csrf", "open_redirect", "redirect",
    "phpinfo", "tech-stack", "tech_stack", "banner", "version",
    "path_disclosure", "directory_listing", "fingerprint",
})

SRC_POLICY_BRIEF = """\
SRC 厂商关注的是漏洞**类型**（不是只挖这几条具体洞）：同一类型下所有变体/实例都要挖。
11 类是菜单，按入口形态选该测的，不要每轮全开：有 HTML 汇才打 XSS，有 JSON/查询参数才打 SQLi，
有 ping/exec 才打命令执行，有模板/反序列化才打代码执行，有 path/file 才打包含/任意文件，
有身份/对象 ID 才打越权，有金额/订单才打逻辑，有配置/备份/密钥才打高危泄露，
有隐藏管理口才打后门，有产品+版本才查 N-day。没有对应面就暂缓。
低/中/高危/严重都要 `report_finding` 进漏洞页（页面按危害从高到低排）。
只碰到业务报错的口不能评高危，但仍要报进漏洞页。
phpinfo/指纹/Banner 不算漏洞。
1. XSS  2. SQL注入  3. 命令执行  4. 代码执行  5. 文件包含  6. 任意文件操作
7. 权限绕过  8. 逻辑漏洞  9. 信息泄露  10. 存在后门  11. N-day（已知组件版本）。
高危（要重点报）：直接拿服务器权限（命令执行/webshell/代码执行）；大量个人敏感信息泄露；支付/改金额等影响盈利的逻辑；
能直接盗取用户身份且影响严重（可拿大量敏感数据或执行命令的 SQLi）；可重置管理员密码并导致大量敏感信息泄露。
中低危也要报进漏洞页，评级按真实危害：一般 SQLi 只证库名、存储 XSS、普通越权评中低危，不要抬成高危。
未授权只打到「角色不存在 / 参数不完整 / 空 data / ObjectId 报错」不能评高危——打出非空业务数据，或真实领取/兑换/改价，或拖库/命令执行才能评高危/严重。
能打到高危再加码：**读面铺开、写面克制**。只读/未授权/敏感字段按类型覆盖，不能停在第一条；每条危害用最小样本证明，禁止拖全表、禁止真改生产。
真阳性：高危/严重必须二次验证且 evidence 含已证实危害（非同一条业务报错重放）；未过验证仍进漏洞页，标待验证。
本资产最多 **30 轮**；满 30 轮或满 180 分钟硬停，都记失败（不是未完成）。
**隐身（让人感觉没来过）**：低速率、不留持久痕迹。隐身靠少写、不靠少读。
禁止高危破坏：DoS、打满磁盘、删库删站、改生产配置、关服务、持久化 webshell。
禁止无限制写垃圾：批量注册/灌评论/刷订单、INSERT/UPDATE 业务表、短信邮件轰炸。
禁止破坏业务：不准 DROP/TRUNCATE/DELETE FROM；SQLi 只用 SELECT/布尔/报错证明；RCE 只写无害短 txt canary，取回后立刻删掉。
不算漏洞：phpinfo/指纹/Banner/目录列表；错误页回显的内网 IP；CSRF、开放重定向、前台弱口令。
不夺旗、不以 getshell 收工、不打内网横向（其它环境主机交给集群对应子项目）。
"""

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
    """把 config.objective 归一到 redteam|flag|src。getshell 是 redteam 旧值；未知归 redteam。"""
    o = (obj or "").strip().lower()
    if o in ("flag", "ctf"):
        return FLAG
    if o == "src":
        return SRC
    return REDTEAM


def objective_allows_flag(obj: str | None) -> bool:
    return normalize_objective(obj) == FLAG


def objective_is_src(obj: str | None) -> bool:
    return normalize_objective(obj) == SRC


def cfg_is_lab_src(cfg: dict | None) -> bool:
    """评测平台胶水：SRC 目标函数 + benchmark token/容器。真实资产 SRC 不走这里。"""
    if not isinstance(cfg, dict):
        return False
    if normalize_objective(cfg.get("objective") or cfg.get("track")) != SRC:
        return False
    bm = cfg.get("benchmark") if isinstance(cfg.get("benchmark"), dict) else {}
    return bool(bm.get("unique_code") or bm.get("base_url") or bm.get("token"))


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
    if o == SRC:
        return False
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
    if o == SRC:
        return (int(verified_high or 0) + int(verified_critical or 0)) > 0
    return redteam_ultimate_reached(achievements)


_TRIVIAL_ERROR_ECHO_RE = re.compile(
    r"resteasy|jax-?rs|"
    r"echo\s*reflector|"
    r"private\s*ipv4|"
    r"pod\s*ipv4|"
    r"(?:404|错误页).{0,48}(?:内网|私网|pod).{0,16}(?:ip|地址|端口)|"
    r"(?:内网|私网|pod)\s*(?:ip|地址).{0,24}(?:错误页|404|回显)",
    re.I,
)
_REAL_LEAK_RE = re.compile(
    r"password|passwd|secret|api[_-]?key|access[_-]?key|credential|jdbc:|"
    r"mysql://|\.env\b|private[_-]?key|aws_secret|db[_-]?pass|heapdump|"
    r"id_rsa|\.git\b|口令|密码|密钥|连接串",
    re.I,
)
_INFO_CATS = frozenset({
    "info_disclosure", "information_disclosure", "info", "info_leak",
    "path_disclosure", "banner", "version", "fingerprint", "phpinfo",
})


def src_should_skip_category(category: str | None) -> bool:
    return (category or "").strip().lower() in SRC_SKIP_CATEGORIES


def src_is_non_vuln_finding(
    *,
    category: str | None = None,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
) -> bool:
    """SRC 不当漏洞：指纹类类别，或标题就是错误页回显内网 IP。"""
    del description, evidence
    cat = (category or "").strip().lower()
    if cat in SRC_SKIP_CATEGORIES:
        return True
    if cat not in _INFO_CATS:
        return False
    title_s = title or ""
    if _REAL_LEAK_RE.search(title_s):
        return False
    return bool(_TRIVIAL_ERROR_ECHO_RE.search(title_s))


def src_should_skip_finding(
    category: str | None,
    *,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
) -> bool:
    if src_should_skip_category(category):
        return True
    return src_is_non_vuln_finding(
        category=category, title=title, description=description, evidence=evidence,
    )


_SRC_IMPACT_RE = re.compile(
    r"uid=\d+\(|www-data|nt authority|root:[^:\n]*:0:0:"
    r"|领取成功|兑换成功|发放成功|下单成功|支付成功|订单已",
    re.I,
)
_SRC_ERROR_ONLY_RE = re.compile(
    r"角色不存在|参数不完整|活动未配置|没有获奖记录|游戏未配置|"
    r"Error parsing ObjectId|the \$sort key specification",
    re.I,
)
_SRC_EMPTY_DATA_RE = re.compile(r'"data"\s*:\s*(\{\s*\}|\[\s*\])')


def _src_json_data_has_payload(blob: str) -> bool:
    """evidence 里 data 是否含非空业务载荷（空 {} / [] 不算）。"""
    for m in re.finditer(r'"data"\s*:\s*(\{.*?\}|\[.*?\])', blob, re.S):
        raw = re.sub(r"\s+", "", m.group(1))
        if raw in ("{}", "[]", "null"):
            continue
        if len(raw) >= 8:
            return True
    return False


def src_impact_proven(row: object | None = None, **kwargs) -> bool:
    """SRC 发现页门槛：证据必须含已证实危害，不能只靠业务报错和猎人自评。"""
    data: object = row if row is not None else kwargs
    evidence = _row_field(data, "evidence")
    proof_detail = _row_field(data, "proof_detail")
    proof_canary = _row_field(data, "proof_canary")
    proof_url = _row_field(data, "proof_url")
    proof_type = _row_field(data, "proof_type").strip().lower()
    blob = "\n".join(x for x in (evidence, proof_detail, proof_canary, proof_url) if x).strip()
    if not blob and not (proof_type in ("impact_extract", "write_txt") and (proof_canary or proof_url or proof_detail)):
        return False
    if _SRC_IMPACT_RE.search(blob):
        return True
    if _SRC_ERROR_ONLY_RE.search(blob):
        return False
    if proof_type in ("impact_extract", "write_txt") and (proof_canary or proof_url or proof_detail):
        return True
    if not blob:
        return False
    if _src_json_data_has_payload(blob) and not _SRC_EMPTY_DATA_RE.search(blob):
        return True
    return False


def user_visible_finding(
    obj: str | None = None,
    *,
    severity: str | None = None,
    verification_status: str | None = "verified",
    category: str | None = None,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
    proof_type: str | None = None,
    proof_canary: str | None = None,
    proof_url: str | None = None,
    proof_detail: str | None = None,
) -> bool:
    """漏洞页：非 rejected 的低/中/高危/严重都展示。obj 保留兼容，不再按赛道隐藏。"""
    del obj, severity, category, title, description, evidence
    del proof_type, proof_canary, proof_url, proof_detail
    vs = (verification_status or "verified").strip().lower()
    return vs != "rejected"


def finding_row_visible(obj: str | None, row: object) -> bool:
    """图/列表/报告共用：非 rejected 即进漏洞页。"""
    return user_visible_finding(
        obj,
        severity=display_finding_severity(row),
        verification_status=_row_field(row, "verification_status") or "verified",
        category=_row_field(row, "category"),
        title=_row_field(row, "title"),
        description=_row_field(row, "description"),
        evidence=_row_field(row, "evidence"),
        proof_type=_row_field(row, "proof_type"),
        proof_canary=_row_field(row, "proof_canary"),
        proof_url=_row_field(row, "proof_url"),
        proof_detail=_row_field(row, "proof_detail"),
    )


def sort_findings_by_severity(rows: list) -> list:
    """危害从高到低：critical > high > medium > low > info；同级新的在前。"""
    def _key(row: object) -> tuple[int, float]:
        sev = display_finding_severity(row)
        rank = SEVERITY_ORDER.get(sev, 0)
        try:
            ts = float(_row_field(row, "created_at") or 0)
        except (TypeError, ValueError):
            ts = 0.0
        return (-rank, -ts)
    return sorted(rows, key=_key)


def _row_field(row: object, key: str) -> str:
    v = None
    if isinstance(row, dict):
        v = row.get(key)
    else:
        getter = getattr(row, "get", None)
        if callable(getter):
            try:
                v = getter(key)
            except Exception:
                v = None
        if v is None:
            v = getattr(row, key, None)
        if v is None:
            try:
                v = row[key]  # type: ignore[index]
            except Exception:
                v = None
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
        title = _row_field(r, "title")
        cat = _row_field(r, "category")
        if vs == "pending":
            k = _finding_path_key(title, cat)
            if k and k in verified_keys:
                continue
            if not k and _finding_family(cat) in verified_fam:
                continue
        out.append(r)
    return sort_findings_by_severity(out)


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
