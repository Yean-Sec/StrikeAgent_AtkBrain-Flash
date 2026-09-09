"""SRC 厂商类型：按入口形态选该测的洞，不是每轮 11 路全开。"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

SRC_VENDOR_TYPES: tuple[tuple[str, str], ...] = (
    ("xss", "XSS"),
    ("sqli", "SQLi"),
    ("cmd", "命令执行"),
    ("code", "代码执行"),
    ("lfi", "文件包含"),
    ("file", "任意文件"),
    ("authz", "越权"),
    ("logic", "逻辑"),
    ("leak", "高危信息泄露"),
    ("backdoor", "后门"),
    ("nday", "N-day"),
)

SRC_TYPE_TACTIC: dict[str, str] = {
    "xss": "html_sink",
    "sqli": "web_inject",
    "cmd": "web_inject",
    "code": "restricted_deserialize",
    "lfi": "file_read_chain",
    "file": "file_read_chain",
    "authz": "access_control",
    "logic": "business_logic",
    "leak": "info_to_danger",
    "backdoor": "auth_surface",
    "nday": "nday",
}


@dataclass(frozen=True)
class SrcTypePick:
    key: str
    label: str
    tactic: str
    why: str


@dataclass
class SrcTypeAdvice:
    suggested: list[SrcTypePick] = field(default_factory=list)
    skipped: list[SrcTypePick] = field(default_factory=list)

    @property
    def suggested_keys(self) -> frozenset[str]:
        return frozenset(p.key for p in self.suggested)


def graph_haystack(graph: dict | None) -> str:
    parts: list[str] = []
    for n in (graph or {}).get("nodes") or []:
        if not isinstance(n, dict):
            continue
        tags = n.get("tags") or []
        if not isinstance(tags, (list, tuple, set)):
            tags = []
        parts.append(str(n.get("key") or ""))
        parts.append(str(n.get("type") or ""))
        parts.append(str(n.get("title") or ""))
        parts.append(str(n.get("detail") or ""))
        parts.extend(str(t) for t in tags)
    return " ".join(parts).lower()


_OSS_RE = re.compile(
    r"aliyunoss|oss-cn-|accessdenied|nosuchbucket|私有桶|object.?store|x-oss-",
    re.I,
)
_APP_RE = re.compile(
    r"\bjson\b|/api|payment|openid|kong|integral|/user|/gift|/order|"
    r"application/json|game-char|x-token|支付|积分",
    re.I,
)
_PARAM_RE = re.compile(
    r"json_api|/api|query|param|search|openid|zoneid|game_id|charid|"
    r"application/json|表单|查询参数|接口",
    re.I,
)
_AUTHZ_RE = re.compile(
    r"/user|/gift|/order|openid|charid|\bidor\b|越权|未授权|x-token|"
    r"game-char|role.?id|uid=|object.?id",
    re.I,
)
_LOGIC_RE = re.compile(
    r"pay|amount|price|coupon|count|integral|score|product|改价|"
    r"订单|优惠|gift|营销|支付|金额|商品",
    re.I,
)
_HTML_RE = re.compile(
    r"text/html|<form|innerhtml|document\.write|html_sink|</html>|vue|react",
    re.I,
)
_CMD_RE = re.compile(
    r"\bping\b|\bexec\b|\bcmd\b|nslookup|traceroute|diag(?:nostic)?|"
    r"shell.?cmd|system\(|popen",
    re.I,
)
_CODE_RE = re.compile(
    r"ssti|template_error|freemarker|velocity|thymeleaf|deserialize|"
    r"unserialize|pickle|ysoserial|spel\b|ognl|groovy|expr_eval",
    re.I,
)
_LFI_RE = re.compile(
    r"\binclude\b|\blfi\b|page=|file=|path=|template=|lang=|view=|php://",
    re.I,
)
_FILE_RE = re.compile(
    r"download|readfile|export|backup|upload|multipart|attachment|"
    r"path.?traversal|任意文件|\.git\b|zip.?slip",
    re.I,
)
_LEAK_RE = re.compile(
    r"swagger|\.git\b|backup|heapdump|\.env\b|accesskey|act-center-config|"
    r"user-info|scorelog|site-config|awards?-info",
    re.I,
)
_BACKDOOR_RE = re.compile(
    r"/admin|/debug|/console|phpmyadmin|manager/html|/status|"
    r"webshell|预留口令|隐藏.?管理|kong.?admin",
    re.I,
)
_NDAY_RE = re.compile(
    r"kong\s*0\.\d+|nginx/\d+|apache/\d+|tomcat/?\d+|spring[ -]?boot|"
    r"shiro|struts|weblogic|openssl/\d+|php/\d+\.\d+|thinkphp|"
    r"\bversion\b.{0,12}\d+\.\d+",
    re.I,
)
_HTTP_RE = re.compile(r"\bhttps?\b|nginx|kong|/tcp http", re.I)


def _pick(key: str, why: str) -> SrcTypePick:
    label = next(lbl for k, lbl in SRC_VENDOR_TYPES if k == key)
    return SrcTypePick(key=key, label=label, tactic=SRC_TYPE_TACTIC[key], why=why)


def suggest_src_types(graph: dict | None) -> SrcTypeAdvice:
    """有对应面才建议测；没有证据就暂缓。空图不预开 11 路。"""
    hay = graph_haystack(graph)
    if not hay.strip() or not _HTTP_RE.search(hay):
        skip = [
            _pick(k, "入口未建账或非 HTTP：先铺开，不要预开 11 路")
            for k, _ in SRC_VENDOR_TYPES
        ]
        return SrcTypeAdvice(skipped=skip)

    oss = bool(_OSS_RE.search(hay))
    app = bool(_APP_RE.search(hay))
    html = bool(_HTML_RE.search(hay))
    params = bool(_PARAM_RE.search(hay))
    hits: dict[str, str] = {}

    def want(key: str, why: str) -> None:
        hits[key] = why

    if html:
        want("xss", "有 HTML/前端汇，测反射/DOM")
    if params or app:
        want("sqli", "有 JSON/查询参数，测注入")
    if _CMD_RE.search(hay):
        want("cmd", "有 ping/exec 类参数")
    if _CODE_RE.search(hay):
        want("code", "有模板/反序列化/表达式面")
    if _LFI_RE.search(hay):
        want("lfi", "有 include/path/file 类参数")
    if _FILE_RE.search(hay):
        want("file", "有下载/上传/备份/任意文件面")
    if _AUTHZ_RE.search(hay) or (app and params):
        want("authz", "有身份/对象 ID 或未授权 200 接口")
    elif oss and not app:
        want("authz", "对象存储面先测桶/对象 ACL 与未授权读")
    if _LOGIC_RE.search(hay):
        want("logic", "有支付/金额/积分/商品参数，测改价与逻辑")
    if _LEAK_RE.search(hay) or (oss and not app):
        why = "有配置/备份/敏感接口或密钥线索"
        if oss and not app:
            why = "OSS 子资源/ACL/策略是否外泄"
        want("leak", why)
    if _BACKDOOR_RE.search(hay):
        want("backdoor", "有管理/调试/隐藏入口迹象")
    if _NDAY_RE.search(hay):
        want("nday", "已识别产品或版本，WebSearch 查已知 CVE/N-day")

    # 活体 HTTP 但还没分型：只开便宜且常见的注入+越权，不把 11 类全开。
    if not hits and not oss:
        want("sqli", "HTTP 活体尚无分型，先打参数注入")
        want("authz", "HTTP 活体尚无分型，先测未授权")

    suggested = [_pick(k, hits[k]) for k, _ in SRC_VENDOR_TYPES if k in hits]
    skipped = [
        _pick(k, "当前图上没有这类入口形态，暂缓")
        for k, _ in SRC_VENDOR_TYPES
        if k not in hits
    ]
    return SrcTypeAdvice(suggested=suggested, skipped=skipped)


def format_src_surface_brief(graph: dict | None) -> str:
    advice = suggest_src_types(graph)
    lines = [
        "本轮按入口形态选类型（厂商 11 类是菜单，不是每轮全开）：",
    ]
    if advice.suggested:
        bits = [f"{p.label}（{p.why}）" for p in advice.suggested]
        lines.append("建议测：" + "；".join(bits))
    else:
        lines.append("建议测：先铺开入口，再按面选；不要预开 11 路。")
    if advice.skipped:
        bits = [p.label for p in advice.skipped]
        lines.append("暂缓：" + "、".join(bits) + "（没有对应面就不要硬派 Task）。")
    lines.append("有版本指纹才 WebSearch 查 N-day；纯私有 OSS 不要假装有 SQLi/XSS。")
    return "\n".join(lines)
