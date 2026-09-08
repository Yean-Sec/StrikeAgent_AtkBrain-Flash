"""攻击图驱动的假设派生：节点/发现 → 有限、可去重的推理前沿 Intent。

目标：发现服务/危险点/漏洞/凭证等后，自动泛化出正交后续事件，避免智能体
只记点不串链，也避免无边界重复死磕。
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .model import SEVERITY_ORDER, IntentIn


_PORT_RE = re.compile(r"(?:^|[:/])(\d{2,5})(?:/|$)")
_PATH_RE = re.compile(r"(/(?:[A-Za-z0-9_\-./%]{1,80}))")
# 机器密钥/令牌（不是登录口令）。字段名不等于查询参数名。
_SECRET_RE = re.compile(
    r"\b(admin[_-]?token|api[_-]?key|access[_-]?token|secret[_-]?key|"
    r"bearer|auth[_-]?token|internal[_-]?token)\b"
    r"|[\"']?(?:token|secret|api_key|apikey)[\"']?\s*[:=]",
    re.I,
)
_LOGIN_CRED_RE = re.compile(
    r"(?:\b(?:password|passwd|username|default-cred|default.creds)\b|口令|账密|用户名)",
    re.I,
)
# 把「没扫到」写成结案的信息点：不能再派生登录/危险面 Intent。
_NEGATIVE_CONCLUSION_RE = re.compile(
    r"(无挂载|无\s*HTTP\s*挂载|挂载点.{0,6}无|无任何挂载|"
    r"差分.{0,12}闭环|全闭环|面.{0,8}穷尽|穷尽.{0,8}(?:路由|HTTP|功能)|终审|"
    r"no[-_ ]?(?:http[-_ ]?)?mount|exhausted|"
    r"仅有?\s*\d+\s*条?(?:路由|路径)|其余.{0,8}404|全部.?404|"
    r"分析方法.{0,12}穷尽|全部.{0,16}穷尽|无法通过现有方法|"
    r"纯诱饵|判定为诱饵|确为诱饵|(?<![不])是诱饵|\bdecoy\b|\btheater\b|"
    r"全负|口令空间.{0,12}(?:穷尽|全负)|登录门.{0,16}全部失败|"
    r"突破尝试全部失败|"
    r"爆破失败|brute[-_ ]?fail|强随机|不可爆破)",
    re.I,
)
# 过程笔记 / 表单字段清单：不是可登录资产，不能派生换凭证或挂密钥。
_NON_ASSET_INFO_RE = re.compile(
    r"(枚举进行中|进行中[,，。]|\binflight\b|"
    r"无业务逻辑|零业务|模板\s*UI|"
    r"表单结构|字段.{0,40}username\s*/\s*password|"
    r"csrf.?token.?头|非POST未带)",
    re.I,
)
# 真像泄露的账密，而不是「表单里有 password 字段」。
_INFO_CRED_LEAK_RE = re.compile(
    r"(?:泄露|泄漏|注释).{0,16}(?:password|passwd|token|口令|账号|credential)|"
    r"(?:password|passwd|口令)\s*[=:]\s*\S|"
    r"\b(?:default[-_ ]creds?|test:test|有效账号|默认口令)\b",
    re.I,
)
# 一类观测（状态码/Cookie/跳转）无差异：不关闭输入面，换通道。
_UNIFORM_OBS_RE = re.compile(
    r"(恒定\s*\d{3}|恒\s*\d{3}|无条件\s*\d{3}|持续\s*\d{3}|统一(?:错误|模板|状态)|无差异|"
    r"无\s*set-cookie|没有\s*set-cookie|无\s*cookie|"
    r"uniform\s+(?:error|status)|\balways\s+\d{3}\b|no\s+set-cookie)",
    re.I,
)
# 真正做完通道：出现差分，而不是「记过耗时 / 已闭合 / 与输入无关的恒定延迟」。
_CHANNEL_DIFF_RE = re.compile(
    r"(时间差|长度差|布尔差|耗时差|延时差|"
    r"timing\s+diff|length\s+diff|boolean\s+diff|"
    r"差分.{0,12}(?:耗时|长度|rtt|delay))",
    re.I,
)
# info 笔记把参数面写成关闭：仍要换通道。不要把 4xx 跳板否证算进来。
_UNIFORM_ERROR_PAGE_RE = re.compile(
    r"(恒定\s*5\d\d|恒\s*5\d\d|无条件\s*5\d\d|持续\s*5\d\d|"
    r"always\s+5\d\d|统一(?:错误|模板).{0,12}5\d\d)",
    re.I,
)
_INPUT_SURFACE_FALSE_CLOSE_RE = re.compile(
    r"(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|"
    r"(?:该|此)面(?:已死|关闭)|面已关|"
    r"通道级否证|确定性\s*500|死面|输入无关|无条件崩溃",
    re.I,
)
_SURFACE_PATH_RE = re.compile(r"(?:https?://[^\s/]+)?(/[A-Za-z][A-Za-z0-9._-]{0,63})")
_SURFACE_WORD_RE = re.compile(
    r"[a-z]{3,}|"
    r"登录|口令|认证|表单|资产|报销|后台",
    re.I,
)
_SURFACE_STOP = frozenset({
    "danger", "info", "vuln", "http", "https", "www", "html",
    "always", "error", "page", "uniform", "status", "cookie",
    "crash", "closed", "none", "null", "diff", "query", "param",
    "post", "get", "svc", "service", "target", "goal", "host",
    "tcp", "udp", "port", "flask", "gunicorn", "werkzeug",
    "the", "and", "for", "from", "with", "ams",
})
_SURFACE_PATH_STOP = frozenset({"/http", "/https", "/tcp", "/udp"})
_AUTHZ_HIT_RE = re.compile(r"\b(401|403)\b|unauthorized|www-authenticate", re.I)
# 「通道否证 / 同体 4xx」是一种观测，不是把跳板整族写成死。
_CHANNEL_NEGATION_RE = re.compile(
    r"通道否证|否证.{0,12}(?:SSRF|通道|网关|跳板)|判定为存根|"
    r"同体.{0,12}400|硬\s*400|存根级|"
    r"恒定\s*4\d\d|统一\s*4\d\d",
    re.I,
)
_GADGET_TAGS = frozenset({
    "ssrf", "ssrf_internal", "ssrf_as_gateway", "proxy", "import", "upload",
    "open_proxy", "ssrf-echo", "ssrf_echo",
})
_GADGET_BLOB_RE = re.compile(
    r"\bssrf\b|open\s*proxy|gopher://|file://|跳板|导入面|upload",
    re.I,
)
_TRANSPORT_DEAD_RE = re.compile(
    r"connection refused|no route to host|code=000|http_code=000|"
    r"network is unreachable|name or service not known",
    re.I,
)
# 过程笔记 / 同形态再试：不是新资产，不能再派生同一战术。
_PROCESS_NOTE_RE = re.compile(
    r"(变体|包装|绕过族).{0,12}(?:失败|否证)|"
    r"探测失败|"
    r"仍被(?:拦|阻止|拒绝)|"
    r"过程笔记",
    re.I,
)
# 本地程序的开门钥匙（argv/访问码），不是 Web token。
_LOCAL_GATE_RE = re.compile(
    r"访问码|access[_\s-]?code|argv\s*\[|license[_\s-]?key",
    re.I,
)
_LOCAL_BIN_RE = re.compile(
    r"\bELF\b|stripped|validator|bytecode|自定义\s*VM|自研\s*(?:VM|执行)|"
    r"\./[A-Za-z0-9_.-]+",
    re.I,
)
# info→凭证：要像口令/令牌，禁止用裸 "key"（VM_KEY07 / key4 / .data key 都会误触发）。
_INFO_CRED_RE = re.compile(
    r"\b(password|passwd|token|secret|credential|账号|口令)\b",
    re.I,
)
# info→危险面：要像接口路径，禁止用裸 "admin"（测试输入 flag{test}/admin 会误触发）。
_INFO_DANGER_RE = re.compile(
    r"(?:(?:^|[\s\"'=])\/admin\b|\bswagger\b|\bendpoint\b|\bapi/[A-Za-z]|"
    r"\bdebug\s*(?:port|panel|interface|endpoint))",
    re.I,
)
_SECRET_MOUNT_HINT = (
    "浅层路径 404 不能否证带叶子的深层路径。无密钥基线先找 401/403（路存在），"
    "再把同一密钥值用短名与字段名回挂。没见过 401/403 就不能写无挂载点。"
)

# 已验证洞停在「证明存在」不够：提危害常打出另一条独立高危。
_IMPACT_LADDER = {
    "info_disclosure": "文档/接口清单 → 读全 swagger，GET 类按 tag 覆盖未授权与敏感字段，不能停在第一条；写接口不落库",
    "information_disclosure": "文档/配置 → 按类型覆盖只读未授权面，禁止灌数据",
    "info_leak": "泄露片段 → 覆盖相关只读接口与样本，禁止拖全量",
    "config_leak": "配置泄露 → 本机只读鉴权差分，禁止改配",
    "key_leak": "密钥泄露 → 本机只读鉴权差分证明未授权数据",
    "ssrf": "能打内网 → 本机云元数据/敏感口一次证明；禁止当跳板扩网",
    "ssrf_internal": "能打内网 → 本机元数据一次证明；禁止扩网",
    "sqli": "证库名/用户 → 只读 SELECT 一条敏感样本；禁止 DROP/DELETE/INSERT/UPDATE/拖全表",
    "db_access": "有库面 → 只读一条敏感样本，禁止拖全表",
    "idor": "单条越权 → 按对象类型覆盖敏感读，不要脚本扫穿全部 ID，禁止写",
    "unauth": "单接口未授权 → 同文档内只读/未授权面按 tag 覆盖，写接口不落库",
    "auth_bypass": "绕过登录 → 只读证明后台/敏感数据覆盖，禁止改配改价",
    "authz": "权限缺口 → 按对象类型覆盖敏感读，禁止写生产",
    "admin_access": "进后台 → 只读证明敏感面，禁止改配/重置/落持久化",
    "lfi": "证路径 → 读配置/密钥/源码样本",
    "file_read": "任意读 → 凭证或少量敏感文件样本",
    "arbitrary_file_read": "任意读 → 凭证或少量敏感文件样本",
    "xss": "反射/存储 → 可盗号且影响面大才独立报高危；禁止对真实用户灌存储 XSS",
    "file_upload": "能传文件 → 无害短 canary，取回即删",
    "rce": "已能执行 → 短 txt canary 取回即删，切下一类，不横向",
    "command_injection": "已能执行 → 固化后换类，不横向",
}
_IMPACT_LADDER_DEFAULT_RT = (
    "把已确认漏洞推进到命令执行（getshell），不要停在存在性 PoC；尚未 GETSHELL 则对其它活体面继续测→证"
)


def _impact_escalate_intent(
    key: str, title: str, cat: str, *, sev: str, node: dict, obj: str | None,
) -> IntentIn | None:
    from ..objective import FLAG, normalize_objective
    o = normalize_objective(obj)
    if o == FLAG:
        return None
    c = (cat or "").strip().lower()
    ladder = _IMPACT_LADDER.get(c, _IMPACT_LADDER_DEFAULT_RT)
    extra = "提权/横向只在已有立足点之后，不要为换路丢掉这条已验证洞。"
    return _mk(
        key, "impact_escalate",
        f"提升已验证洞「{title}」的危害：{ladder}。"
        f"影响实质性变大就独立 report_finding，不要只改标题重报同一事实。"
        f"厂商清单/攻击面穷尽时优先走这一步。{extra}",
        rationale="已证明的洞停在存在性不够；危害上调常打出新的独立高危",
        est=0.77, severity=sev or "high", boost=0.14, evidence_extra=c or "impact", node=node,
    )


def is_negative_conclusion(blob: str, title: str = "") -> bool:
    """穷尽/无挂载/闭环一类结案，不是可利用资产。恒定 4xx 不是穷尽。"""
    text = f"{title or ''} {blob or ''}"
    if is_channel_negation_note(blob, title):
        return False
    return bool(_NEGATIVE_CONCLUSION_RE.search(text))


def is_channel_negation_note(blob: str, title: str = "") -> bool:
    """把一种 4xx/同体错误写成「通道否证」：不是整族关闭。"""
    return bool(_CHANNEL_NEGATION_RE.search(f"{title or ''} {blob or ''}"))


def _node_looks_like_gadget(blob: str, tags: set[str], title: str = "") -> bool:
    hay = f"{title or ''} {blob or ''} {' '.join(sorted(tags))}"
    if tags & _GADGET_TAGS:
        return True
    return bool(_GADGET_BLOB_RE.search(hay))


def live_gadget_tactics(graph: dict | None) -> frozenset[str]:
    """图上仍活着的跳板族。finding 未标 verified 也要留在跳板上。赛道无关。"""
    if not graph:
        return frozenset()
    out: set[str] = set()
    for n in graph.get("nodes") or []:
        ntype = str(n.get("type") or "")
        if ntype not in ("service", "danger", "vuln"):
            continue
        tags = _tags(n)
        blob = _blob(n)
        title = str(n.get("title") or "")
        if not _node_looks_like_gadget(blob, tags, title):
            continue
        if _TRANSPORT_DEAD_RE.search(f"{title} {blob}") and "ssrf" not in f"{title} {blob}".lower():
            continue
        out.add("ssrf_as_gateway")
        if "upload" in tags or "upload" in f"{title} {blob}".lower():
            out.add("upload_bypass")
    for f in graph.get("findings") or []:
        vs = str(f.get("verification_status") or "").lower()
        if vs in ("disproved", "false", "rejected"):
            continue
        cat = str(f.get("category") or "").lower()
        fblob = f"{f.get('title') or ''} {f.get('description') or ''} {cat}"
        if cat in ("ssrf", "ssrf_internal") or _GADGET_BLOB_RE.search(fblob):
            out.add("ssrf_as_gateway")
        if "upload" in fblob.lower():
            out.add("upload_bypass")
    return frozenset(out)


_WEAPONIZE_CAT_TACTICS: dict[str, tuple[str, ...]] = {
    "ssrf": ("ssrf_as_gateway", "ssrf_local_svc"),
    "ssrf_internal": ("ssrf_as_gateway", "ssrf_local_svc"),
    "lfi": ("file_read_chain", "read_to_creds", "finding_read_loot"),
    "file_read": ("file_read_chain", "read_to_creds", "finding_read_loot"),
    "arbitrary_file_read": ("file_read_chain", "read_to_creds", "finding_read_loot"),
    "sqli": ("finding_sqli_chain", "weaponize"),
    "sql-injection": ("finding_sqli_chain", "weaponize"),
    "db_access": ("finding_sqli_chain", "weaponize"),
    "rce": ("finding_rce_close", "weaponize"),
    "command_injection": ("finding_rce_close", "weaponize"),
}


def weaponize_prefer_tactics(graph: dict | None) -> frozenset[str]:
    """已验证高危能力：优先消耗，不要回头扫目录。赛道无关。"""
    if not graph:
        return frozenset()
    out: set[str] = set(live_gadget_tactics(graph))
    for f in graph.get("findings") or []:
        vs = str(f.get("verification_status") or "").lower()
        if vs and vs not in ("verified", "accepted"):
            continue
        cat = str(f.get("category") or "").lower()
        sev = str(f.get("severity") or "").lower()
        if vs != "verified" and sev not in ("high", "critical"):
            continue
        out.update(_WEAPONIZE_CAT_TACTICS.get(cat, ()))
    for n in graph.get("nodes") or []:
        if str(n.get("type") or "") != "vuln":
            continue
        tags = _tags(n)
        if "verified" not in tags and str(n.get("severity") or "") not in ("high", "critical"):
            continue
        hay = f"{n.get('title') or ''} {_blob(n)} {' '.join(tags)}".lower()
        for cat, tacs in _WEAPONIZE_CAT_TACTICS.items():
            if cat in hay or cat in tags:
                out.update(tacs)
    return frozenset(out)


def enum_sidetrack_when_weaponizable(graph: dict | None) -> frozenset[str]:
    """有可消耗的已验证能力时，推迟入口枚举。"""
    if weaponize_prefer_tactics(graph):
        return frozenset({"content_enum", "fingerprint"})
    return frozenset()


_BINARY_RE_RE = re.compile(
    r"逆向|可执行文件|固件|字节码|bytecode|\bELF\b|octet-stream|"
    r"自定义\s*(?:VM|执行)|自研\s*(?:VM|执行)|"
    r"stripped\s+binary|"
    r"analy[sz]e.{0,24}(?:executable|binary)|"
    r"(?:executable|binary).{0,16}analy",
    re.I,
)


def looks_like_served_binary(blob: str, title: str = "", brief: str = "") -> bool:
    """题面/节点要求分析下发的可执行文件，不是网站目录枚举。"""
    return bool(_BINARY_RE_RE.search(f"{title or ''} {blob or ''} {brief or ''}"))


def graph_looks_like_served_binary(graph: dict | None, brief: str = "") -> bool:
    if looks_like_served_binary("", "", brief):
        return True
    for n in (graph or {}).get("nodes") or []:
        if not isinstance(n, dict):
            continue
        if looks_like_served_binary(_blob(n), str(n.get("title") or ""), brief):
            return True
    return False


def _brief_cred_suffix(brief: str) -> str:
    try:
        from ..agents.brief_creds import credential_candidates_from_brief, format_cred_hint
        return format_cred_hint(credential_candidates_from_brief(brief))
    except Exception:
        return ""


def is_non_asset_info(blob: str, title: str = "") -> bool:
    """枚举进行中、表单字段清单、前端无逻辑：不是钥匙，也不当登录凭证。"""
    return bool(_NON_ASSET_INFO_RE.search(f"{title or ''} {blob or ''}"))


def is_process_note(blob: str, title: str = "", key: str = "") -> bool:
    """同形态再试 / 执行过程笔记：不是新资产，也不要把已有战术再派生一遍。"""
    kid = str(key or "")
    if ":exec:" in kid or ":knife:" in kid:
        return True
    return bool(_PROCESS_NOTE_RE.search(f"{title or ''} {blob or ''}"))


def looks_like_leaked_login(blob: str, title: str = "") -> bool:
    """信息点里是否像泄露的账密，而不是表单结构里写了 password 字段。"""
    text = f"{title or ''} {blob or ''}"
    if is_negative_conclusion(blob, title) or is_non_asset_info(blob, title) or is_process_note(blob, title):
        return False
    if is_channel_negation_note(blob, title):
        return False
    if _INFO_CRED_LEAK_RE.search(text):
        return True
    if _INFO_CRED_RE.search(text) and not re.search(
        r"表单|字段|username\s*/\s*password|POST\s+/login", text, re.I,
    ):
        return True
    return False


def looks_like_secret(blob: str, tags: set[str] | None = None) -> bool:
    """配置/节点里是否像 API token，而不是账号口令。与题型无关。"""
    t = {str(x).lower() for x in (tags or set())}
    if t & {"token", "api-key", "api_key", "secret", "config-leak", "config_leak"}:
        return True
    return bool(_SECRET_RE.search(blob or ""))


def looks_like_login_cred(blob: str, title: str = "") -> bool:
    """登录型凭证：走 auth_reuse，不走密钥挂载。"""
    if looks_like_local_gate(blob, title):
        return False
    if _LOGIN_CRED_RE.search(blob or "") or _LOGIN_CRED_RE.search(title or ""):
        return True
    if re.match(r"^[\w.@+-]+/.+", (title or "").strip()):
        return True
    return False


def looks_like_local_gate(blob: str, title: str = "") -> bool:
    """本地二进制的开门钥匙（访问码/argv），不是可往 HTTP 面挂的 token。"""
    s = f"{title or ''} {blob or ''}"
    return bool(_LOCAL_GATE_RE.search(s) and _LOCAL_BIN_RE.search(s))


def graph_has_unmounted_secret(graph: dict | None) -> bool:
    """图上有机器密钥，却没有任何 401/403 命中——挂载枚举未完成。"""
    if not graph:
        return False
    has_secret = False
    saw_authz = False
    for n in graph.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        title = str(n.get("title") or "")
        blob = _blob(n)
        if (n.get("type") or "").lower() == "credential" and looks_like_secret(blob, _tags(n)):
            if looks_like_local_gate(blob, title):
                continue
            has_secret = True
        if is_negative_conclusion(blob, title):
            continue
        if _AUTHZ_HIT_RE.search(title) or _AUTHZ_HIT_RE.search(blob):
            saw_authz = True
    return has_secret and not saw_authz


def _tags(node: dict) -> set[str]:
    raw = node.get("tags") or []
    if isinstance(raw, str):
        try:
            import json
            raw = json.loads(raw) or []
        except Exception:
            raw = [raw]
    return {str(t).lower() for t in raw}


_CRASH_VULN_RE = re.compile(
    r"availability|error_handling|misconfig|\bdos\b|\bcrash\b|"
    r"崩溃|可用性|渲染层|视图层|模板异常|确定性\s*500",
    re.I,
)
_EXPLOIT_VULN_RE = re.compile(
    r"sqli|sql.?inject|sql注入|db_access|\brce\b|command.inject|"
    r"\bssrf\b|\blfi\b|file_read|file_write|file_upload|ssti|"
    r"deserial|unauth|auth_bypass|\bidor\b|xxe",
    re.I,
)
_EXPLOIT_VULN_TAGS = frozenset({
    "sqli", "sql-injection", "sql注入", "db_access", "rce", "command_injection",
    "ssrf", "ssrf_internal", "lfi", "file_read", "file_write", "file_upload",
    "ssti", "deserialization", "unauth", "auth_bypass", "idor", "xxe",
})
_CRASH_VULN_TAGS = frozenset({
    "availability", "crash", "dos", "error_handling", "misconfig", "template",
})


def node_is_non_exploit_crash(node: dict | None) -> bool:
    """崩溃/可用性节点：没有注入/执行/读文件等利用标签。"""
    if not node:
        return False
    tags = _tags(node)
    blob = _blob(node)
    if tags & _EXPLOIT_VULN_TAGS or _EXPLOIT_VULN_RE.search(blob):
        return False
    return bool(tags & _CRASH_VULN_TAGS) or bool(_CRASH_VULN_RE.search(blob))


def _info_needs_channel_oracle(blob: str, title: str = "") -> bool:
    """info 笔记把 5xx / 参数面写成关闭：仍要换通道。4xx 跳板否证不算。"""
    text = f"{title or ''} {blob or ''}"
    if _CHANNEL_DIFF_RE.search(text):
        return False
    if is_channel_negation_note(blob, title):
        return False
    return bool(
        _UNIFORM_ERROR_PAGE_RE.search(text) or _INPUT_SURFACE_FALSE_CLOSE_RE.search(text)
    )


def _channel_oracle_intents(
    key, title, node, sev, *, crash: bool = False, include_input: bool = True,
) -> list:
    desc = (
        f"对 {title} 换观测通道：状态码/正文/Cookie/跳转无差异时，"
        "对同一输入的两次提交比对耗时差/长度差/响应头差/其它路由副作用；"
        "同一状态码再采样不算换通道，不要关闭输入面"
    )
    if crash:
        desc += "；不要把恒定错误页写成已验证利用"
    out = [
        _mk(
            key, "channel_oracle", desc,
            rationale="一类 oracle 失败不等于后端没处理参数",
            est=0.78, severity=sev, boost=0.14, node=node,
        ),
    ]
    if include_input:
        out.append(_mk(
            key, "input_abuse",
            f"验证 {title} 的可控输入是否仍被后端处理，不要关闭输入面",
            rationale="恒定错误页只否证了这一类观测",
            est=0.7, severity=sev, boost=0.08, node=node,
        ))
    return out


def _surface_tokens(node: dict | None) -> frozenset[str]:
    """同一输入面的弱标识：URL 路径，或 key/标题里的登录、login 一类词。"""
    if not isinstance(node, dict):
        return frozenset()
    key = str(node.get("key") or "")
    title = str(node.get("title") or "")
    text = f"{key} {title}"
    paths = []
    for raw in _SURFACE_PATH_RE.findall(text):
        p = str(raw or "").lower().rstrip("/")
        if p and p not in _SURFACE_PATH_STOP:
            paths.append(p)
    if paths:
        return frozenset(paths)
    rest = key.split(":", 1)[-1] if ":" in key else key
    out: set[str] = set()
    for w in _SURFACE_WORD_RE.findall(f"{rest} {title}"):
        s = str(w or "").lower()
        if s and s not in _SURFACE_STOP:
            out.add(s)
    return frozenset(out)


def _node_has_channel_diff(node: dict | None) -> bool:
    if not isinstance(node, dict):
        return False
    blob = _blob(node)
    title = str(node.get("title") or "")
    return bool(_CHANNEL_DIFF_RE.search(blob) or _CHANNEL_DIFF_RE.search(title))


def _node_uniform_or_false_close(node: dict | None) -> bool:
    """该节点仍是单通道/假关闭：本面还要换观测通道。"""
    if not isinstance(node, dict):
        return False
    ntype = str(node.get("type") or "").lower()
    blob = _blob(node)
    title = str(node.get("title") or "")
    if ntype in ("danger", "vuln"):
        if _node_has_channel_diff(node):
            return False
        text = f"{title} {blob}"
        return bool(
            _UNIFORM_OBS_RE.search(blob) or _UNIFORM_OBS_RE.search(title)
            or _INPUT_SURFACE_FALSE_CLOSE_RE.search(text)
        )
    if ntype == "info":
        return _info_needs_channel_oracle(blob, title)
    return False


def needs_channel_oracle(graph: dict | None) -> bool:
    """参数面只有状态码/正文一类观测：输入面未关，还要换通道。

    按节点/输入面判断：某一面出现耗时/长度/布尔差分，只结算那一面。
    其它面上的恒定错误页/假关闭仍钉住换通道。
    御主把假关闭写成 info 时同样钉住，避免只打指纹。
    """
    if not graph:
        return False
    nodes = [n for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    settled: set[str] = set()
    for n in nodes:
        ntype = str(n.get("type") or "").lower()
        if ntype not in ("danger", "vuln", "info"):
            continue
        if _node_has_channel_diff(n):
            settled |= set(_surface_tokens(n))
    for n in nodes:
        if not _node_uniform_or_false_close(n):
            continue
        toks = _surface_tokens(n)
        if toks and settled and (toks & settled):
            continue
        return True
    return False


def _blob(node: dict) -> str:
    detail = node.get("detail")
    if isinstance(detail, dict):
        detail_s = " ".join(str(v) for v in detail.values())
    else:
        detail_s = str(detail or "")
    return f"{node.get('key','')} {node.get('title','')} {detail_s} {' '.join(_tags(node))}".lower()


def evidence_fingerprint(node: dict, extra: str = "") -> str:
    raw = f"{node.get('key')}|{node.get('type')}|{node.get('title')}|{node.get('severity')}|{extra}"
    return hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:16]


_TYPE_PREFIXES = ("vuln:", "danger:", "svc:", "service:", "cred:", "credential:",
                  "info:", "foothold:", "goal:", "file:", "dir:", "web:", "host:")


def _canon_source(source_key: str) -> str:
    """把来源节点 key 归一化，让同义不同写法折叠为一个策略：
    - 去掉类型前缀（vuln:/cred:… 只是分类，不改变“打的是同一个点”）；
    - 按分隔符切词后排序再拼回，使 `download-lfi` 与 `lfi-download` 等价；
    这样避免智能体为同一目标建了两个 key 就派生出重复 intent 反复死磕。
    """
    s = (source_key or "").strip().lower()
    for p in _TYPE_PREFIXES:
        if s.startswith(p):
            s = s[len(p):]
            break
    toks = [t for t in re.split(r"[^a-z0-9]+", s) if t]
    return "-".join(sorted(toks)) if toks else s


def strategy_key(source_key: str, tactic: str) -> str:
    sk = f"{_canon_source(source_key)}::{tactic}".strip().lower()
    return hashlib.sha1(sk.encode()).hexdigest()[:20] if len(sk) > 120 else sk


def _priority(base: float, severity: str, boost: float = 0.0) -> float:
    sev = SEVERITY_ORDER.get(severity or "info", 0)
    return round(min(0.99, max(0.05, base + sev * 0.04 + boost)), 3)


def _mk(
    source_key: str,
    tactic: str,
    description: str,
    *,
    rationale: str,
    est: float,
    severity: str = "info",
    boost: float = 0.0,
    evidence_extra: str = "",
    node: dict | None = None,
) -> IntentIn:
    node = node or {"key": source_key, "type": "info", "title": "", "severity": severity}
    return IntentIn(
        **{"from": [source_key]},
        description=description,
        rationale=rationale,
        est_success=est,
        strategy_key=strategy_key(source_key, tactic),
        evidence_fingerprint=evidence_fingerprint(node, evidence_extra or tactic),
        priority=_priority(est, severity, boost),
        status="open",
    )


def _node_is_ssrf(blob: str, tags: set[str]) -> bool:
    return any(x in blob or x in tags for x in ("ssrf",))


def _gadget_skips_entry_filter(blob: str, tags: set[str], title: str = "", *, is_ssrf: bool = False) -> bool:
    """跳板/传输层已成立：入口 WAF 绕过不是下一跳，剩下的是消耗 gadget。"""
    return is_ssrf or _node_looks_like_gadget(blob, tags, title)


_TOKEN_CLASS_RE = re.compile(
    r"\bjwt\b|\bjws\b|\bjwe\b|\bhs256\b|\brs256\b|\bes256\b|"
    r"json\s*web\s*token|signed\s+(?:token|cookie)|hmac-sha",
    re.I,
)


def _node_is_token(blob: str, tags: set[str], title: str = "") -> bool:
    if tags & {"jwt", "jws", "jwe", "hs256", "signed_token"}:
        return True
    return bool(_TOKEN_CLASS_RE.search(blob) or _TOKEN_CLASS_RE.search(title or ""))


_CHAIN_RPC_MARKERS = (
    "json-rpc", "jsonrpc", "ethereum", "geth", "anvil", "hardhat",
    "nethermind", "besu", "ganache", "erigon",
)


def _node_is_chain_rpc(blob: str, tags: set[str]) -> bool:
    """JSON-RPC 节点：走 chain_rpc，不要当 PHP 站 web_inject。"""
    if tags & {"json-rpc", "jsonrpc", "ethereum", "geth"}:
        return True
    return any(x in blob for x in _CHAIN_RPC_MARKERS)


def _node_is_rce(node: dict, blob: str, tags: set[str]) -> bool:
    return bool(node.get("is_rce")) or any(
        x in blob or x in tags for x in ("rce", "command", "shell", "desp")
    )


_AUTH_SVC_TOKENS = frozenset({
    "ssh", "sshd", "rdp", "smb", "ftp", "redis", "mysql", "mariadb",
    "postgres", "postgresql", "mongo", "mongodb", "telnet", "vnc",
})
_AUTH_SVC_RE = re.compile(
    r"(?i)\b(?:sshd?|rdp|smb|ftp|redis|mysql|mariadb|postgres(?:ql)?|"
    r"mongo(?:db)?|telnet|vnc)\b",
)


def _looks_like_auth_service(blob: str, tags: set[str]) -> bool:
    if tags & _AUTH_SVC_TOKENS:
        return True
    return bool(_AUTH_SVC_RE.search(f"{blob} {' '.join(sorted(tags))}"))


_HTTP_SVC_MARKERS = (
    "http", "https", "apache", "nginx", "php", "tomcat", "weblogic", "spring", "iis",
    "gunicorn", "uwsgi", "flask", "django", "fastapi", "web 应用", "web应用",
)
_DSN_RE = re.compile(
    r"jdbc:|redis://|mysql://|mongodb://|postgres(?:ql)?://"
    r"|\.rds\.|\.internal(?:[.:/\s]|$)|(?<![a-z])db_host\s*[:=]",
    re.I,
)


def _service_is_http(blob: str, tags: set[str]) -> bool:
    hay = f"{blob} {' '.join(tags)}".lower()
    return any(x.lower() in hay for x in _HTTP_SVC_MARKERS)


def _looks_like_data_plane_dsn(blob: str) -> bool:
    """JS/配置里的库/缓存 DSN，不是可扫的新主机。"""
    return bool(_DSN_RE.search(blob or ""))


def _data_plane_via_app_intent(key: str, title: str, node: dict, obj: str, sev: str) -> IntentIn:
    desc = (
        f"把 {title} 里的库/缓存 DSN 当成「经应用碰数据面」："
        f"经已验证 SSRF/gopher 碰 db_host，禁止 Kali 直连内网库，不要把 RDS IP 建成新子项目。"
    )
    return _mk(
        key, "data_plane_via_app", desc,
        rationale="红队数据面经应用/跳板，不是 Kali 直连",
        est=0.74, severity=sev or "high", boost=0.14, node=node,
    )


def stale_tactics_for_node(node: dict, brief: str = "") -> list[str]:
    """当前规则不派生的 tactic。刷新 Intent 时搁置。"""
    ntype = (node.get("type") or "info").lower()
    title = node.get("title") or node.get("key") or ""
    tags = _tags(node)
    blob = _blob(node)
    stale: list[str] = ["split_tier"]
    if ntype == "vuln" and _node_is_ssrf(blob, tags) and not _node_is_rce(node, blob, tags):
        stale.append("weaponize")
    if ntype == "credential" and looks_like_secret(blob, tags) and not looks_like_login_cred(blob, title):
        stale.extend(["auth_reuse", "priv_enum"])
    if ntype == "credential" and looks_like_local_gate(blob, title):
        stale.extend(["auth_reuse", "priv_enum", "secret_mount"])
    if ntype == "info" and (
        is_negative_conclusion(blob, title) or is_non_asset_info(blob, title)
        or is_process_note(blob, title, str(node.get("key") or ""))
    ):
        stale.extend(["info_to_cred", "info_to_danger", "secret_mount"])
    if ntype == "service" and (
        not _service_is_http(blob, tags) or looks_like_served_binary(blob, title, brief)
    ):
        stale.extend(["content_enum", "web_inject", "auth_surface"])
    return stale


_LIVE_SURFACE_INTENTS: tuple[tuple[str, str, str, str], ...] = (
    (
        "graphql", "graphql_contract",
        "对 {title} 先读 GraphQL 契约，再按字段做授权差分",
        "GraphQL 入口的下一步是契约与授权差分",
    ),
    (
        "soap", "soap_contract",
        "对 {title} 先拉 WSDL/SOAP 契约再调操作",
        "SOAP 入口的下一步是契约操作",
    ),
    (
        "jwt", "token_inspect",
        "对 {title} 的会话令牌本地解码 header/claims，按通用缺陷族验证",
        "令牌面先看结构再验证",
    ),
    (
        "multipart", "upload_bypass",
        "对 {title} 把内容类型与扩展名当服务端校验假设，只传无害短 canary",
        "上传面用短 canary 验证解析链",
    ),
    (
        "object_store", "object_write",
        "对 {title} 先列桶/键，再在可写或已登录面做对象级读写与键级授权差分",
        "对象存储面的下一步是键级读写差分",
    ),
    (
        "xml", "xml_parse",
        "对 {title} 先确认 XML 解析器如何处理外部实体与扩展，短 canary",
        "XML 面先确认解析行为再验证",
    ),
    (
        "template_error", "ssti",
        "对 {title} 的模板报错回显先做无害 canary 确认注入面",
        "模板报错说明渲染面还活着，先 canary",
    ),
    (
        "json_api", "api_contract",
        "对 {title} 先读 JSON API 契约/字段，再做未授权与对象级授权差分。"
        "前端/JS 键不是后端必填名：4xx 正文若点名其它字段，立刻换那个名，不要对已否证键做编码变体。",
        "JSON API 的下一步是契约与授权差分；客户端字段名过时则按错误正文换键",
    ),
    (
        "html_sink", "html_sink",
        "对 {title} 用短 canary 确认查询/表单参数是否原样进 HTML/DOM",
        "反射 HTML 汇的下一步是短 canary",
    ),
    (
        "php_serial", "restricted_deserialize",
        "对 {title} 按受限反序列化族短验证入口里的序列化形态",
        "序列化字节本身就是入口标签",
    ),
    (
        "expr_eval", "expr_eval",
        "对 {title} 用无害 canary 确认表达式/编码求值面",
        "求值报错回显输入说明求值面还活着，先 canary",
    ),
    (
        "race_window", "race_window",
        "对 {title} 在无条件锁的写接口上做短并发窗口验证",
        "无锁写成功是并发窗口的证据",
    ),
)


SURFACE_TACTICS: dict[str, str] = {
    name: tactic for name, tactic, _d, _r in _LIVE_SURFACE_INTENTS
}
LIVE_SURFACE_TACTICS: frozenset[str] = frozenset(SURFACE_TACTICS.values())
_ENUM_PLAN_RE = re.compile(r"content_enum|目录爆破|目录枚举", re.I)
_OBJECT_STORE_SIDETRACK_RE = re.compile(
    r"方法矩阵|method[\s_-]*matrix|方法枚举|verb\s*enum",
    re.I,
)


def live_surfaces_from_node(blob: str, tags: set[str]) -> list[str]:
    """节点标签/正文里的活体表面。只认通用标签名。"""
    hay = f"{blob} {' '.join(sorted(tags))}"
    out: list[str] = []
    for name, _tac, _d, _r in _LIVE_SURFACE_INTENTS:
        if name in tags or name in hay:
            if name not in out:
                out.append(name)
    try:
        from ..entry_fingerprint import classify_http_surface, merge_surface_tags
        extra = classify_http_surface((blob or "").encode("utf-8", "ignore")[:4096])
        out = merge_surface_tags(out, extra)
    except Exception:
        if "object_store" in out:
            out = [x for x in out if x != "xml"]
    return out


def surface_prefer_tactics(surfaces) -> set[str]:
    """入口/节点活体表面 → 应优先的契约/canary tactic。"""
    out: set[str] = set()
    for x in surfaces or []:
        tac = SURFACE_TACTICS.get(str(x or "").strip().lower())
        if tac:
            out.add(tac)
    return out


def surface_defer_tactics(surfaces, *, has_verified: bool = False) -> set[str]:
    """活体表面下应搁置的枚举/方法矩阵族。"""
    names = {str(x).strip().lower() for x in (surfaces or []) if x}
    out: set[str] = set()
    if surface_prefer_tactics(names):
        out.add("content_enum")
    if "object_store" in names and has_verified:
        out.update({"content_enum", "filter_bypass", "channel_oracle"})
    return out


def surfaces_from_graph_nodes(graph: dict | None) -> list[str]:
    """从图节点 tags 收集活体表面，不看题名。"""
    out: list[str] = []
    seen: set[str] = set()
    for n in (graph or {}).get("nodes") or []:
        tags = n.get("tags") if isinstance(n, dict) else None
        blob = ""
        if isinstance(n, dict):
            blob = str(n.get("detail") or "") + " " + str(n.get("title") or "")
        for name in live_surfaces_from_node(blob, {str(t).lower() for t in (tags or [])}):
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


def live_surface_needs_cycle(
    surfaces,
    *,
    resolved_tactics: set[str] | None = None,
) -> bool:
    """还有活体表面未走完一轮契约/canary 时，应 defer content_enum。"""
    want = surface_prefer_tactics(surfaces)
    if not want:
        return False
    done = {str(x).strip().lower() for x in (resolved_tactics or ()) if x}
    return not bool(want & done)


def plan_blocks_live_surface(plan_text: str, *, surfaces=None) -> bool:
    """当前方案还在目录枚举/方法矩阵，但图上已有活体表面 → 监督不应 hold。"""
    names = [str(x).strip().lower() for x in (surfaces or []) if x]
    blob = plan_text or ""
    if surface_prefer_tactics(names) and _ENUM_PLAN_RE.search(blob):
        return True
    if "object_store" in names and _OBJECT_STORE_SIDETRACK_RE.search(blob):
        return True
    return False


def _surface_intents(key: str, title: str, node: dict, sev: str, surfaces: list[str]) -> list[IntentIn]:
    want = set(surfaces or [])
    out: list[IntentIn] = []
    for name, tactic, desc, why in _LIVE_SURFACE_INTENTS:
        if name not in want:
            continue
        out.append(_mk(
            key, tactic, desc.format(title=title),
            rationale=why, est=0.68, severity=sev, boost=0.1, node=node,
        ))
    return out


def hypotheses_for_node(
    node: dict, allows_flag: bool = True, objective: str | None = None,
    brief: str = "",
) -> list[IntentIn]:
    """按节点类型/标签生成有限候选假设（不去重，由 store 负责）。

    allows_flag=False（红队）时，派生话术不出现 flag/夺旗。
    """
    from ..objective import REDTEAM, normalize_objective
    obj = normalize_objective(objective) if objective is not None else (
        "flag" if allows_flag else "redteam"
    )
    ntype = (node.get("type") or "info").lower()
    key = node.get("key") or ""
    title = node.get("title") or key
    sev = node.get("severity") or "info"
    tags = _tags(node)
    blob = _blob(node)
    cred_sfx = _brief_cred_suffix(brief)
    binary = looks_like_served_binary(blob, title, brief)
    out: list[IntentIn] = []

    if ntype == "service":
        is_http = _service_is_http(blob, tags)
        out.append(_mk(key, "fingerprint", f"确认 {title} 的产品/版本指纹与已知漏洞面",
                       rationale="服务发现后先定性技术栈，才能选对利用族", est=0.7, severity=sev, node=node))
        if binary:
            out.append(_mk(
                key, "reverse_binary",
                f"下载 {title} 下发的可执行文件/固件/字节码，file/strings/objdump/radare2 静态分析，"
                "再用已装的 z3/pwntools 符号求解；不要扫目录、不要当网站打",
                rationale="题面要求分析可执行文件时，下一事件是本地逆向而不是 Web 枚举",
                est=0.8, severity=sev, boost=0.16, node=node,
            ))
            out.append(_mk(
                key, "protocol_model",
                f"对 {title} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录",
                rationale="可执行文件入口常伴随自定义协议，会话建模与静态分析并行",
                est=0.72, severity=sev, boost=0.12, node=node,
            ))
        elif is_http:
            out.extend([
                _mk(key, "auth_surface",
                    f"枚举 {title} 的登录/鉴权/管理入口并测默认口令与弱鉴权{cred_sfx}",
                    rationale="多数 Web 服务的高价值面在认证边界", est=0.62, severity=sev, node=node),
                _mk(key, "content_enum", f"对 {title} 做目录与脚本文件枚举（先看入口已知路径与源码；禁止超 10 万行词表）",
                    rationale="未链接脚本常无目录命中；无扩展名扫描不能当内容枚举完成", est=0.58, severity=sev, node=node),
            ])
            if _node_looks_like_gadget(blob, tags, title):
                out.append(_mk(
                    key, "ssrf_as_gateway",
                    f"把 {title} 当跳板：内网/回环走该 gadget，不要从攻击机直连那些地址",
                    rationale="跳板类服务的下一事件是当传输层，不是直连内网",
                    est=0.8, severity=sev, boost=0.16, node=node,
                ))
            if _node_is_chain_rpc(blob, tags):
                out.append(_mk(key, "chain_rpc",
                               f"对 {title} 做 JSON-RPC 指纹与未授权方法探测，不要当网站做目录枚举",
                               rationale="JSON-RPC 的入口是方法表，不是目录与 SQLi",
                               est=0.72, severity=sev, boost=0.1, node=node))
            else:
                out.append(_mk(key, "web_inject", f"围绕 {title} 探测注入类漏洞（SQLi/SSTI/命令注入/反序列化）",
                               rationale="Web 服务常见通往 RCE/读文件的入口族", est=0.55, severity=sev, boost=0.05, node=node))
            if any(x in blob or x in tags for x in ("403", "waf", "拦截", "blocked", "forbidden", "filter")):
                if not _gadget_skips_entry_filter(
                    blob, tags, title, is_ssrf=_node_is_ssrf(blob, tags),
                ):
                    out.append(_mk(
                        key, "filter_bypass",
                        f"对 {title} 的拦截/过滤页换方法与通道探测，不要结案去枚举目录",
                        rationale="过滤器页说明请求已达应用边界，目录枚举不是下一事件",
                        est=0.66, severity=sev, boost=0.08, node=node,
                    ))
            out.extend(_surface_intents(key, title, node, sev, live_surfaces_from_node(blob, tags)))
        else:
            out.append(_mk(
                key, "protocol_model",
                f"对 {title} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录",
                rationale="非 HTTP 交互口的下一步是会话建模，不是 Web 枚举",
                est=0.72, severity=sev, boost=0.12, node=node,
            ))
            if _looks_like_auth_service(blob, tags):
                out.append(_mk(
                    key, "svc_auth_bruteforce",
                    f"对 {title} 做有节制的默认/弱口令与未授权探测（个位数，禁止全量词表）{cred_sfx}",
                    rationale="非 HTTP 服务常因默认配置失守", est=0.5, severity=sev, node=node,
                ))

    elif ntype == "danger":
        out.extend([
            _mk(key, "input_abuse", f"验证危险点 {title} 的可控输入与参数污染",
                rationale="危险点需确认输入面后才能升级为 vuln", est=0.66, severity=sev, boost=0.05, node=node),
            _mk(key, "access_control", f"测试 {title} 的鉴权/越权/未授权访问",
                rationale="访问控制缺陷常比复杂 exploit 更快出成果", est=0.6, severity=sev, node=node),
        ])
        if _node_looks_like_gadget(blob, tags, title):
            out.append(_mk(
                key, "ssrf_as_gateway",
                f"把危险点 {title} 当跳板继续打，一种 4xx 不关闭整族，禁止攻击机直连内网",
                rationale="跳板类危险点的下一事件是当传输层",
                est=0.78, severity=sev, boost=0.14, node=node,
            ))
        if _UNIFORM_OBS_RE.search(blob) or _UNIFORM_OBS_RE.search(title):
            out.extend(_channel_oracle_intents(key, title, node, sev, include_input=False))
        if any(x in blob or x in tags for x in ("upload", "multipart", "附件", "file-upload", "file_upload")):
            out.append(_mk(key, "upload_bypass", f"对 {title} 做上传/解析链绕过并尝试 webshell/文件写",
                           rationale="上传面是经典 getshell 路径", est=0.64, severity=sev, boost=0.08, node=node))
        if any(x in blob or x in tags for x in ("403", "waf", "拦截", "blocked", "forbidden", "filter")):
            if not _gadget_skips_entry_filter(
                blob, tags, title, is_ssrf=_node_is_ssrf(blob, tags),
            ):
                out.append(_mk(
                    key, "filter_bypass",
                    f"对 {title} 换通道绕过拦截/过滤，不要结案去枚举目录",
                    rationale="拦截页是否定了这一通道，不是攻击面关闭",
                    est=0.7, severity=sev, boost=0.1, node=node,
                ))
        out.extend(_surface_intents(key, title, node, sev, live_surfaces_from_node(blob, tags)))
        if any(x in blob or x in tags for x in (
            "deserial", "pickle", "unserialize", "ysoserial", "gadget", "marshal",
        )):
            out.append(_mk(
                key, "restricted_deserialize",
                f"对 {title} 做受限反序列化：在允许的构造器/类型里搜 gadget，不要把白名单当成攻击面已关闭",
                rationale="白名单反序列化的下一事件是 gadget 搜索，不是停手",
                est=0.7, severity=sev, boost=0.1, node=node,
            ))
        if any(x in blob or x in tags for x in ("download", "read", "include", "path", "lfi", "穿越")):
            _loot = "配置/源码/flag" if allows_flag else "配置/源码/凭证/敏感数据"
            _loot_r = "文件读可直接转凭证或 flag" if allows_flag else "文件读可直接转凭证或大量数据泄露"
            out.append(_mk(key, "file_read_chain", f"利用 {title} 尝试任意文件读并定位{_loot}",
                           rationale=_loot_r, est=0.68, severity=sev, boost=0.1, node=node))

    elif ntype == "vuln":
        is_ssrf = _node_is_ssrf(blob, tags)
        is_rce = _node_is_rce(node, blob, tags)
        is_sqli = any(x in blob or x in tags for x in ("sqli", "sql-injection", "sql注入"))
        is_token = _node_is_token(blob, tags, title)
        crash_only = node_is_non_exploit_crash(node)
        if crash_only:
            out.extend(_channel_oracle_intents(key, title, node, sev, crash=True))
        # SSRF 的下一跳是当传输层/挂密钥，不是「执行/提权」weaponize。
        elif not (is_ssrf and not is_rce):
            if is_token:
                out.append(_mk(key, "weaponize",
                               f"把 {title} 的签名令牌当服务端校验对象继续打："
                               "少数算法或弱密钥变体失败不关闭整类；"
                               "不要只改前端角色字段，也不要把令牌面写成已关闭",
                               rationale="持有令牌后下一事件是打校验类，不是关闭伪造面或只改 UI 角色",
                               est=0.76, severity=sev, boost=0.12, node=node))
            elif is_sqli:
                out.append(_mk(key, "weaponize",
                               f"把 {title} 先打成应用控制流/回显（状态码/Cookie/跳转），再 dump 库/密钥；"
                               "确认注入后不要再校准耗时，也不要在同一面上改打无关的身份伪造",
                               rationale="登录/鉴权查询上错误页只说明失败分支崩了，查询可能已执行完",
                               est=0.76, severity=sev, boost=0.12, node=node))
            else:
                out.append(_mk(key, "weaponize", f"把已确认漏洞 {title} 推进到稳定利用（读文件/执行/提权）",
                               rationale="vuln 节点的下一事件是能力升级而非重复探测",
                               est=0.72, severity=sev, boost=0.1, node=node))
        if not crash_only:
            out.append(_mk(key, "evidence_poc", f"为 {title} 固化最小 PoC 并串联到目标攻击链",
                           rationale=("可复现证据便于后续 flag/shell 收口" if allows_flag
                                      else "可复现证据便于后续 shell/数据收口"), est=0.65, severity=sev, node=node))
            esc = _impact_escalate_intent(key, title, (
                "ssrf" if is_ssrf else ("sqli" if is_sqli else ("rce" if is_rce else "vuln"))
            ), sev=sev, node=node, obj=obj)
            if esc:
                out.append(esc)
        if is_rce:
            _rce_desc = (f"基于 {title} 的执行能力搜 flag / 提权 / 横向" if allows_flag
                         else f"基于 {title} 的执行能力做提权 / 横向 / 收数据库与大量数据")
            out.append(_mk(key, "flag_or_privesc", _rce_desc,
                           rationale="已有 RCE 时应优先收口而不是继续盲扫", est=0.8, severity="critical", boost=0.15, node=node))
        if any(x in blob or x in tags for x in ("file_read", "lfi", "path", "read", "穿越", "include")):
            out.append(_mk(key, "read_to_creds", f"用 {title} 读取配置/密钥/会话并尝试登录复用",
                           rationale="文件读→凭证→更高权限是高胜率链路", est=0.75, severity=sev, boost=0.12, node=node))
        if any(x in blob or x in tags for x in (
            "deserial", "pickle", "unserialize", "ysoserial", "gadget", "marshal",
        )):
            out.append(_mk(
                key, "restricted_deserialize",
                f"把 {title} 的已验证反序列化/写入推进到投递执行（触发链落地可执行面），"
                "不要停在 gadget/白名单理论分析",
                rationale="已验证写/反序列化的下一事件是投递执行，不是继续搜 gadget",
                est=0.74, severity=sev, boost=0.12, node=node,
            ))
        if any(x in blob or x in tags for x in ("403", "waf", "拦截", "blocked", "forbidden", "filter")):
            if not _gadget_skips_entry_filter(blob, tags, title, is_ssrf=is_ssrf):
                out.append(_mk(
                    key, "filter_bypass",
                    f"对 {title} 换通道绕过拦截/过滤，不要结案去枚举目录",
                    rationale="过滤器页不是攻击面关闭",
                    est=0.7, severity=sev, boost=0.1, node=node,
                ))
        if is_ssrf:
            out.append(_mk(key, "ssrf_as_gateway",
                           f"把 {title} 当传输层：对回环/容器网的 HTTP 经该 SSRF 转发，禁止从攻击机直连那些 IP",
                           rationale="SSRF 入 Scope 不给攻击机路由；直连超时不是入口挂了",
                           est=0.8, severity=sev, boost=0.16, node=node))
            out.append(_mk(key, "ssrf_local_svc",
                           f"用 {title} 打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从 Kali 连",
                           rationale="unix socket / bind 127.0.0.1 的库只能从目标侧发起",
                           est=0.74, severity=sev, boost=0.12, node=node))
            out.append(_mk(key, "secret_mount",
                           f"若 {title} 已读到配置/token：在被访问的那台服务上做有/无密钥路由差分"
                           f"（查询参数；401/403=路存在）。JSON 字段名不等于参数名，短名 token/key/auth 都要试。"
                           f"{_SECRET_MOUNT_HINT}",
                           rationale="泄露密钥是开门钥匙；GET-only SSRF 仍可用查询参数携带",
                           est=0.83, severity=sev, boost=0.18, node=node))

    elif ntype == "credential":
        if looks_like_local_gate(blob, title):
            return out
        secret_only = looks_like_secret(blob, tags) and not looks_like_login_cred(blob, title)
        if secret_only:
            out.append(_mk(key, "secret_mount",
                           f"把 {title} 当开门钥匙：在同一服务上做有/无该密钥的路由差分，盯 401/403 而不是只看 200。"
                           f"字段名不等于查询参数/头名；GET-only 通道用查询参数。{_SECRET_MOUNT_HINT}",
                           rationale="机器令牌的第一事件是鉴权差分挂载，不是当战利品结束",
                           est=0.84, severity=sev, boost=0.18, node=node))
        else:
            out.extend([
                _mk(key, "auth_reuse",
                    f"用凭证 {title} 登录签发它的那一跳/同一应用，不要当其它 hop 的万能钥匙",
                    rationale="凭证复用的范围是签发该凭证的应用，不是内网任意协议",
                    est=0.78, severity=sev, boost=0.12, node=node),
                _mk(key, "priv_enum", f"登录后枚举 {title} 可达的管理功能/敏感数据/上传与命令入口",
                    rationale=("认证后的功能面常直接通向 flag 或 RCE" if allows_flag
                               else "认证后的功能面常直接通向 RCE 或敏感数据/后台"),
                    est=0.7, severity=sev, boost=0.08, node=node),
            ])
            if "object_store" in tags or "object_store" in blob:
                out.append(_mk(
                    key, "object_write",
                    f"用凭证 {title} 在对象存储面上做对象级读写与键级授权差分",
                    rationale="登录后对象存储的下一事件是键级授权",
                    est=0.76, severity=sev, boost=0.12, node=node,
                ))
        if obj == REDTEAM and _looks_like_data_plane_dsn(blob):
            out.append(_data_plane_via_app_intent(key, title, node, obj, sev))

    elif (
        (ntype == "target" and (tags & {"lateral", "pivot", "scope-expanded"}))
        or (
            ntype == "info"
            and str(key).startswith(("info:host:", "info:scope-expanded:"))
        )
    ):
        same_box = bool(tags & {"same-machine", "vhost"}) or "同一容器" in str(title or "")
        if not same_box:
            # 新 hop = 新身份域。要身份 / 不要身份是逻辑对偶，不按栈、端口、路径分流。
            # 具体监听（SSH/HTTP/其它）由 service 节点自己派生，这里不猜协议。
            out.append(_mk(
                key, "access_control",
                f"对 {title} 已暴露的面做未授权可达差分，与过门并行；"
                "不要把身份验证写成使用这些面的前置条件。",
                rationale="要身份与不要身份是并行假设",
                est=0.74, severity="high", boost=0.13, node=node,
            ))
            out.append(_mk(
                key, "hop_auth",
                f"过 {title} 自己的身份边界；上一跳泄露只是候选。"
                "同一身份面没有新秘密、只重复失败，这一跳的过门假设做完。",
                rationale="新 hop 是新身份域；过门只是假设之一",
                est=0.74, severity="high", boost=0.13, node=node,
            ))

    elif ntype == "foothold":
        out.extend([
            _mk(key, "stabilize", f"巩固立足点 {title}：持久化通道、环境枚举、敏感文件",
                rationale="立足后先稳住再扩权", est=0.7, severity=sev, boost=0.1, node=node),
            _mk(key, "privesc_lateral", f"从 {title} 做本地提权与授权范围内横向/跳板",
                rationale="foothold 的下一事件是提权或横向", est=0.68, severity=sev, boost=0.1, node=node),
        ])
        if allows_flag:
            out.append(_mk(key, "flag_hunt", f"在 {title} 权限下定位并 report_flag",
                           rationale="flag 赛道下立足点应立即转夺旗；未满分继续，满分由平台收工",
                           est=0.74, severity=sev, boost=0.12, node=node))
        else:
            out.append(_mk(key, "flag_hunt", f"在 {title} 权限下确认 getshell（report_shell）并收工",
                           rationale="红队立足后 report_shell 即收工，不夺旗", est=0.74, severity=sev, boost=0.12, node=node))

    elif ntype == "info":
        # 假穷尽/过程笔记/表单字段清单不是资产：再派生换凭证或挂密钥会把图带歪。
        if is_process_note(blob, title, key):
            return out
        if is_channel_negation_note(blob, title):
            if _node_looks_like_gadget(blob, tags, title):
                out.append(_mk(
                    key, "ssrf_as_gateway",
                    f"把 {title} 当还活着的跳板：恒定 4xx / 一种观测失败不关闭整族；"
                    "按错误正文换键，禁止攻击机直连内网面。"
                    "过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。",
                    rationale="同体 4xx 或否证笔记否定的是一种契约，不是跳板已死",
                    est=0.78, severity="high", boost=0.14, node=node,
                ))
            return out
        if _info_needs_channel_oracle(blob, title):
            out.extend(_channel_oracle_intents(key, title, node, sev))
            return out
        if is_negative_conclusion(blob, title) or is_non_asset_info(blob, title):
            return out
        if looks_like_secret(blob, tags):
            out.append(_mk(key, "secret_mount",
                           f"把信息点 {title} 里的密钥当开门钥匙：同一服务有/无密钥路由差分，401/403=路存在。"
                           f"{_SECRET_MOUNT_HINT}",
                           rationale="配置泄露的 token 不是终点", est=0.8, severity="high", boost=0.16, node=node))
        elif looks_like_leaked_login(blob, title):
            out.append(_mk(key, "info_to_cred", f"把信息点 {title} 验证为可用凭证并尝试登录",
                           rationale="明文口令/密钥应立刻升级为 credential 利用", est=0.7, severity="medium", boost=0.08, node=node))
        if _INFO_DANGER_RE.search(blob) or _INFO_DANGER_RE.search(title):
            out.append(_mk(key, "info_to_danger", f"把 {title} 对应接口升级为危险点并做未授权/注入探测",
                           rationale="接口信息需落到可验证攻击面", est=0.55, severity=sev, node=node))
        if obj == REDTEAM and _looks_like_data_plane_dsn(blob):
            out.append(_data_plane_via_app_intent(key, title, node, obj, sev))

    return out


def hypotheses_for_finding(finding: Any, node: dict, allows_flag: bool = True,
                           objective: str | None = None) -> list[IntentIn]:
    """Finding 触发的后续事件：按 category 收口。allows_flag=False 时不出现 flag/夺旗话术。"""
    from ..objective import normalize_objective
    obj = normalize_objective(objective) if objective is not None else (
        "flag" if allows_flag else "redteam"
    )
    key = node.get("key") or (getattr(finding, "node_key", None) or "finding")
    cat = str(getattr(finding, "category", None) or (finding.get("category") if isinstance(finding, dict) else "") or "info").lower()
    title = getattr(finding, "title", None) or (finding.get("title") if isinstance(finding, dict) else key)
    sev = getattr(finding, "severity", None) or (finding.get("severity") if isinstance(finding, dict) else node.get("severity") or "medium")
    desc = getattr(finding, "description", None) or (finding.get("description") if isinstance(finding, dict) else "") or ""
    evid = getattr(finding, "evidence", None) or (finding.get("evidence") if isinstance(finding, dict) else "") or ""
    fblob = f"{title} {desc} {evid} {cat} {_blob(node)}".lower()
    out: list[IntentIn] = []

    if cat in ("file_read", "lfi", "arbitrary_file_read"):
        _loot = "配置/源码/flag" if allows_flag else "配置/源码/凭证/大量敏感数据"
        out.append(_mk(key, "finding_read_loot", f"利用文件读发现「{title}」提取{_loot}",
                       rationale="文件读 finding 应直接转战利品收集", est=0.8, severity=sev, boost=0.15,
                       evidence_extra=cat, node=node))
    elif cat in ("sqli", "db_access"):
        _sql = (
            f"把 SQLi「{title}」先打成应用控制流/回显（状态码/Cookie/跳转/页面差分），"
            f"再按需 dump 库表/应用密钥/用户。"
            f"时间/布尔差已证明查询在跑：先换回显/联合/报错等更快证明类，不要再校准 oracle，"
            f"也不要把同一耗时通道按位问到底。"
            f"不要只用单一错误页否证。库侧文件读原语常被配置挡住，只有更快类和 dump 都走不通才试。"
        )
        _sql_why = "时间差只证明查询在跑；回显/联合/报错往往比按位抽取更快收口。统一错误页不能否证结果集已变"
        out.append(_mk(key, "finding_sqli_chain", _sql,
                       rationale=_sql_why, est=0.78, severity=sev, boost=0.14,
                       evidence_extra=cat, node=node))
    elif cat in ("rce", "command_injection", "deserialization", "ssti", "file_upload", "file_write"):
        if allows_flag:
            _rce = "落地 shell/webshell 并夺旗或提权"
            _why = "执行类 finding 优先收口"
        else:
            _rce = "落地 shell/webshell 并提权/横向/收数据"
            _why = "执行类 finding 优先收口"
        out.append(_mk(key, "finding_rce_close", f"基于「{title}」{_rce}",
                       rationale=_why, est=0.82, severity="critical", boost=0.18,
                       evidence_extra=cat, node=node))
    elif cat in ("ssrf", "ssrf_internal"):
        out.append(_mk(key, "ssrf_as_gateway",
                       f"把 SSRF「{title}」当跳板：内网/回环 HTTP 走 gadget，不要从攻击机直连那些 IP",
                       rationale="SSRF 扩容只授权打目标，不授予攻击机路由", est=0.82, severity=sev, boost=0.16,
                       evidence_extra=cat, node=node))
        out.append(_mk(key, "ssrf_local_svc",
                       f"用「{title}」打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从 Kali 连",
                       rationale="本机只监听服务必须从 SSRF 所在进程发起", est=0.76, severity=sev, boost=0.12,
                       evidence_extra=cat, node=node))
        out.append(_mk(key, "secret_mount",
                       f"若 SSRF「{title}」已读到 token/配置：在被访问服务上做有/无密钥路由差分"
                       f"（查询参数；401/403=路存在）。{_SECRET_MOUNT_HINT}",
                       rationale="泄露密钥是钥匙；GET-only 通道仍可用查询参数",
                       est=0.84, severity=sev, boost=0.18, evidence_extra=cat, node=node))
    elif cat in ("jwt", "token", "signed_token", "jws"):
        out.append(_mk(key, "weaponize",
                       f"把令牌发现「{title}」当服务端校验对象：少数算法或弱密钥变体失败不关闭整类，不要只改前端角色字段",
                       rationale="签名令牌的下一跳是校验类，不是关闭伪造面",
                       est=0.76, severity=sev, boost=0.12,
                       evidence_extra=cat, node=node))
        out.append(_mk(key, "finding_authz_expand", f"用令牌「{title}」扩大可读可写面并找敏感操作",
                       rationale="令牌面要扩到数据或管理操作，但不要停在 UI 角色",
                       est=0.68, severity=sev, boost=0.08,
                       evidence_extra=cat, node=node))
    elif cat in ("auth_bypass", "unauth", "idor", "admin_access", "authz"):
        if _node_is_token(fblob, set(), title):
            out.append(_mk(key, "weaponize",
                           f"把越权/令牌发现「{title}」当服务端校验对象：少数算法变体失败不关闭整类，不要只改前端角色字段",
                           rationale="鉴权 finding 若带签名令牌，下一跳是校验类而不是 UI 角色切换",
                           est=0.74, severity=sev, boost=0.12,
                           evidence_extra=cat, node=node))
        out.append(_mk(key, "finding_authz_expand", f"用越权/未授权「{title}」扩大可读可写面并找敏感操作",
                       rationale="鉴权类问题要扩权到数据或管理操作", est=0.7, severity=sev, boost=0.1,
                       evidence_extra=cat, node=node))
    elif cat in ("availability", "dos", "crash", "error_handling", "misconfig"):
        out.append(_mk(
            key, "channel_oracle",
            f"对发现「{title}」换观测通道：状态码/正文无差异时测耗时、长度、响应头；不要写成已验证利用",
            rationale="可用性/崩溃不是可利用证明",
            est=0.72, severity=sev, boost=0.1, evidence_extra=cat, node=node,
        ))
        out.append(_mk(
            key, "input_abuse",
            f"验证「{title}」对应输入面是否仍被后端处理",
            rationale="恒定错误页只否证了这一类观测",
            est=0.66, severity=sev, boost=0.06, evidence_extra=cat, node=node,
        ))
    elif cat in ("info_disclosure", "information_disclosure", "info_leak", "config_leak", "key_leak"):
        if looks_like_secret(fblob):
            out.append(_mk(key, "secret_mount",
                           f"把「{title}」泄露的密钥当开门钥匙：同一服务有/无密钥路由差分，盯 401/403。"
                           f"{_SECRET_MOUNT_HINT}",
                           rationale="配置/token 泄露的下一跳是鉴权挂载，不是当战利品结束",
                           est=0.84, severity=sev, boost=0.18, evidence_extra=cat, node=node))
        else:
            out.append(_mk(key, "finding_followup", f"围绕发现「{title}」设计下一条可验证利用链",
                           rationale="通用 finding 至少派生一次跟进事件", est=0.5, severity=sev,
                           evidence_extra=cat, node=node))
    else:
        out.append(_mk(key, "finding_followup", f"围绕发现「{title}」设计下一条可验证利用链",
                       rationale="通用 finding 至少派生一次跟进事件", est=0.5, severity=sev,
                       evidence_extra=cat, node=node))
    from .verify import is_non_exploit_finding_category
    esc = _impact_escalate_intent(key, str(title), cat, sev=str(sev), node=node, obj=obj)
    if esc and not is_non_exploit_finding_category(cat):
        out.append(esc)
    return out
