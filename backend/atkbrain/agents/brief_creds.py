"""题面个位数凭据候选。赛道无关、不写某题口令、不扩字典。"""
from __future__ import annotations

import re

_YEAR_RE = re.compile(r"\b(20[1-3]\d)\b")
_PAREN_LATIN_RE = re.compile(r"\(([A-Z][A-Za-z0-9]{2,24})\)")
_CAP_TOKEN_RE = re.compile(r"\b([A-Z][A-Za-z]{2,20})\b")
_CN_VENDOR_RE = re.compile(
    r"(?<![\u4e00-\u9fff])([\u4e00-\u9fff]{2,4})(?:OA|CMS|ERP)(?:系统)?",
)
_CN_FILLER_RE = re.compile(
    r"资产|管理|业务|系统|设备|嵌入|团队|报告|安全|评估|核心|内部|"
    r"授权|保护|机制|流程|凭据|访问|校验|输出|分析|部署|一套|"
    r"厂商|软件|产品|平台|公司|员工|漏洞|测试|渗透|攻击|企业|"
    r"获取|目标|机密|数据|后台|服务|开放|大型|开展|逐步|突破|"
    r"防线|最终|需要|找到|有效|登录|官网|报销|报表|部门|帮助|"
    r"最近|收到|该|某|了|的|一"
)
_EXPLICIT_PAIR_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9._-]{1,20})\s*(?:[:/=])\s*"
    r"([A-Za-z0-9@._!#$%^*+-]{3,32})\b"
)
_STOP = frozenset({
    "http", "https", "html", "flag", "ctf", "linux", "windows", "ubuntu",
    "apache", "nginx", "mysql", "redis", "python", "java", "php", "node",
    "admin", "root", "user", "test", "guest", "login", "password", "token",
    "get", "post", "put", "head", "options", "api", "url", "json", "xml",
    "sql", "ssh", "ftp", "tcp", "udp", "icmp", "dns", "smtp", "imap",
    "the", "and", "for", "with", "from", "this", "that", "system", "server",
    "please", "help", "team", "security", "internal", "core", "web",
    "application", "service", "device", "code", "access", "check", "please",
    "task", "challenge", "target", "host", "port", "file", "path",
    "getshell", "report", "flag",
})
_USER_STOP = frozenset({
    "http", "https", "www", "ftp", "ssh", "tcp", "udp", "api", "url",
})
_PASS_STOP = frozenset({
    "http", "https", "html", "com", "org", "net", "php", "asp", "jsp",
})


def _vendors_of(text: str) -> list[str]:
    raw = text or ""
    out: list[str] = []
    seen: set[str] = set()

    def add(tok: str) -> None:
        t = (tok or "").strip()
        if not t or t.lower() in _STOP:
            return
        if not re.search(r"[A-Za-z]", t):
            if len(t) > 4 or _CN_FILLER_RE.search(t):
                return
        key = t.lower()
        if key in seen:
            return
        seen.add(key)
        out.append(t)

    for m in _PAREN_LATIN_RE.finditer(raw):
        add(m.group(1))
    for m in _CN_VENDOR_RE.finditer(raw):
        add(m.group(1))
    for m in _CAP_TOKEN_RE.finditer(raw):
        add(m.group(1))
    return out[:6]


def _explicit_pairs(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _EXPLICIT_PAIR_RE.finditer(text or ""):
        user, pw = m.group(1), m.group(2)
        if user.lower() in _USER_STOP or pw.lower() in _PASS_STOP:
            continue
        if "//" in f"{user}/{pw}" or user.lower() in {"http", "https"}:
            continue
        key = f"{user}/{pw}".lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{user}/{pw}")
    return out[:6]


def credential_candidates_from_brief(text: str, max_pairs: int = 10) -> list[str]:
    """从题面抽取个位数候选（user/pass 或单口令）。禁止扩字典。"""
    blob = (text or "").strip()
    if not blob:
        return []
    limit = max(1, min(int(max_pairs or 10), 10))
    out: list[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        s = (item or "").strip()
        if not s or s.lower() in seen:
            return
        seen.add(s.lower())
        out.append(s)

    for p in _explicit_pairs(blob):
        add(p)
    vendors = _vendors_of(blob)
    years = [m.group(1) for m in _YEAR_RE.finditer(blob)]
    years = list(dict.fromkeys(years))[:3]
    if vendors or years:
        add("admin/admin")
    for v in vendors:
        add(f"{v}@123")
        add(f"admin/{v}")
        add(f"admin/{v}@123")
        for y in years:
            add(f"{v}@{y}")
            add(f"admin/{v}@{y}")
    if years and not vendors:
        for y in years:
            add(f"admin@{y}")
            add(f"admin/admin@{y}")
    return out[:limit]


def format_cred_hint(cands: list[str] | None) -> str:
    items = [str(x).strip() for x in (cands or []) if str(x).strip()]
    if not items:
        return ""
    return "；题面凭据候选（个位数尝试，禁止扩字典）：" + "、".join(items[:8])
