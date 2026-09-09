"""跨目标经验只留可迁移手法，不进题面路径 / 主机 / 题号。

CTF 与红队共用同一套白名单；CTF 取回时还必须和当前图上的线索或技术栈对得上，
避免把「做过的题」当成固定模板套到下一题。
"""
from __future__ import annotations

import re

from .generalize import TACTIC_NAMES, generalize_chain_str, generalize_node_key

STACK_TOKENS: frozenset[str] = frozenset({
    "php", "java", "python", "node", "nodejs", "nginx", "apache", "tomcat", "iis",
    "wordpress", "spring", "thinkphp", "django", "flask", "struts", "weblogic",
    "redis", "mysql", "mssql", "mongodb", "docker", "k8s", "go", "golang",
    "rails", "laravel", "express", "dotnet", "aspnet", "ruby",
})
CUE_TOKENS: frozenset[str] = frozenset({
    "error_reflects_input", "debug_endpoint", "auth_surface",
    "file_read_surface", "inject_surface", "upload_surface", "deserialize_surface",
    "foothold",
})
PROCESS_TACTICS: frozenset[str] = frozenset({
    "weaponize", "channel_oracle", "content_enum", "fingerprint",
    "file_read_chain", "input_abuse", "hop_auth", "secret_mount",
    "web_inject", "upload_bypass", "priv_enum", "privesc_lateral",
    "auth_reuse", "info_to_cred", "ssrf_as_gateway", "ssrf_local_svc",
    "finding_rce_close", "finding_read_loot", "finding_sqli_chain",
    "finding_authz_expand", "read_to_creds",
    "protocol_model", "reverse_binary", "filter_bypass", "restricted_deserialize",
    "graphql_contract", "soap_contract", "token_inspect", "api_contract",
    "xml_parse", "ssti", "access_control", "svc_auth_bruteforce",
})
TACTIC_TOKENS: frozenset[str] = TACTIC_NAMES | PROCESS_TACTICS
WHEN_TOKENS: frozenset[str] = STACK_TOKENS | CUE_TOKENS
# 目标本身不是手法，不能当 do
_NOT_METHOD = frozenset({
    "getflag", "flag", "goal", "vuln", "info", "entry", "lateral", "pivot",
    "reversing", "firmware", "ctf", "web", "auto", "adjacent", "authorized",
    "banner", "tcp", "udp", "heartbeat", "custom-protocol", "line-protocol",
    "buffer", "buffer-overflow", "guard-bypass", "oob-write", "oob-read",
})

_HOSTISH_RE = re.compile(
    r"host:|target:|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|"
    r":\d{2,5}\b|"
    r"^[\w.-]+:\d{2,5}$|"
    r"^[a-z]{1,4}-\d{1,3}$|"
    r"/|flag\{|<path>|<ip>|<url>|<redacted>",
    re.I,
)
_PORT_ONLY_RE = re.compile(r"^\d{2,5}$")
_CHAIN_OK_RE = re.compile(
    r"^(entry|service|surface|info|vuln|cred|foothold|honeypot|goal)"
    r"(?:\([a-z0-9_]+\))?$",
    re.I,
)
# 思想/方法若在预告尚未出现的 hop，则不是在消耗当前面上的能力。
_AHEAD_RE = re.compile(
    r"尚未出现|尚未发现|图上没有|下一台主机|其它主机|其它容器|"
    r"还差\s*\d|其余面|未出现的",
)
# 图上已有的面允许推进到的下一手法；不在此表里的手法必须自己先出现在图上。
_CONSUME: dict[str, frozenset[str]] = {
    "file_read_chain": frozenset({"weaponize", "finding_read_loot", "read_to_creds", "filter_bypass"}),
    "upload_bypass": frozenset({"weaponize"}),
    "finding_sqli_chain": frozenset({"weaponize", "finding_read_loot", "file_read_chain"}),
    "ssrf_as_gateway": frozenset({"file_read_chain", "finding_read_loot"}),
    "weaponize": frozenset({"finding_read_loot", "privesc_lateral"}),
    "ssti": frozenset({"weaponize"}),
    "access_control": frozenset({"weaponize", "finding_read_loot"}),
    "xml_parse": frozenset({"finding_read_loot", "weaponize"}),
    "restricted_deserialize": frozenset({"weaponize"}),
    "web_inject": frozenset({"weaponize"}),
    "error_reflects_input": frozenset({"ssti", "weaponize"}),
    "file_read_surface": frozenset({"file_read_chain", "weaponize"}),
    "inject_surface": frozenset({"finding_sqli_chain", "ssti", "web_inject"}),
    "upload_surface": frozenset({"upload_bypass", "weaponize"}),
    "deserialize_surface": frozenset({"restricted_deserialize", "weaponize"}),
    "auth_surface": frozenset({"access_control", "info_to_cred"}),
    "debug_endpoint": frozenset({"weaponize"}),
    "foothold": frozenset({"finding_read_loot", "privesc_lateral", "access_control"}),
}


def stack_tokens_of(tags: list[str] | None) -> list[str]:
    out: list[str] = []
    for t in tags or []:
        s = str(t or "").strip().lower()
        if s in STACK_TOKENS and s not in out:
            out.append(s)
    return out


def is_specific_token(s: str) -> bool:
    t = (s or "").strip()
    if not t:
        return True
    if _HOSTISH_RE.search(t) or _PORT_ONLY_RE.match(t):
        return True
    if t in _NOT_METHOD:
        return True
    return False


def _keep_when(s: str) -> str | None:
    t = (s or "").strip().lower()
    if not t or is_specific_token(t) or t not in WHEN_TOKENS:
        return None
    return t


_TACTIC_ALIASES: dict[str, str] = {
    "unauth": "access_control",
    "unauthenticated": "access_control",
    "auth_bypass": "access_control",
    "authz": "access_control",
    "idor": "access_control",
    "ssrf": "ssrf_as_gateway",
    "lfi": "file_read_chain",
    "rfi": "file_read_chain",
    "file_read": "file_read_chain",
    "path_traversal": "file_read_chain",
    "fileread": "file_read_chain",
    "rce": "weaponize",
    "command_injection": "weaponize",
    "file_upload": "upload_bypass",
    "sqli": "finding_sqli_chain",
    "xxe": "xml_parse",
    "deserialization": "restricted_deserialize",
    "privilege_escalation": "privesc_lateral",
    "privesc": "privesc_lateral",
    "info_disclosure": "finding_read_loot",
}


def keep_tactic(s: str) -> str | None:
    t = (s or "").strip().lower()
    t = _TACTIC_ALIASES.get(t, t)
    if not t or t in _NOT_METHOD or is_specific_token(t):
        return None
    if t in TACTIC_TOKENS:
        return t
    return None


def _keep_tactic(s: str) -> str | None:
    return keep_tactic(s)


def scrub_chain(chain: str) -> str:
    raw = (chain or "").strip()
    if not raw:
        return ""
    if "->" in raw and "→" not in raw:
        raw = generalize_chain_str(raw)
    parts: list[str] = []
    for p in re.split(r"\s*→\s*|\s*->\s*", raw):
        tok = (p or "").strip()
        if not tok:
            continue
        if not _CHAIN_OK_RE.match(tok):
            g = generalize_node_key(tok)
            if not g or not _CHAIN_OK_RE.match(g):
                continue
            tok = g
        if parts and parts[-1] == tok:
            continue
        parts.append(tok)
    if not parts:
        return ""
    if set(parts) <= {"entry", "service", "surface", "info", "goal"}:
        return ""
    if not any("(" in p for p in parts):
        return ""
    return " → ".join(parts)


def keep_thought(s: str, *, stacks: list[str] | None = None) -> str:
    """路线/方法/思想：可迁移中文原则，丢掉 IP/路径/题面。"""
    t = re.sub(r"\s+", " ", str(s or "").strip())
    if len(t) < 8 or len(t) > 240:
        return ""
    if _HOSTISH_RE.search(t) or _AHEAD_RE.search(t):
        return ""
    allowed = {str(x).lower() for x in (stacks or []) if x}
    if allowed:
        low = t.lower()
        for tok in STACK_TOKENS:
            if tok in allowed:
                continue
            if re.search(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", low):
                return ""
    return t


def lesson_consumes_evidence(do: list[str] | None, signals: set[str]) -> bool:
    """手法必须能接到当前图已有的栈/线索/战术上，不能凭空多出一跳。"""
    need = {str(x).lower() for x in (do or []) if x}
    if not need:
        return True
    allowed = {str(x).lower() for x in signals}
    for s in list(allowed):
        allowed |= _CONSUME.get(s, frozenset())
    return need <= allowed


def format_methodology(
    *, when: list[str], do: list[str], avoid: list[str], chain: str,
    route: str = "", method: str = "", idea: str = "",
) -> str:
    bits: list[str] = []
    if idea:
        bits.append("思想：" + idea)
    if method:
        bits.append("方法：" + method)
    if route or chain:
        bits.append("路线：" + (route or chain))
    if do:
        bits.append("手法 " + "、".join(do[:4]))
    if when:
        bits.append("线索：" + "、".join(when[:4]))
    if avoid:
        bits.append("避免：" + "、".join(avoid[:4]))
    return "；".join(bits)


def scrub_lesson(content: dict | None) -> dict | None:
    """把一条剧本收成思想/方法/路线 + 手法/线索。题面残留则丢掉。"""
    c = dict(content or {})
    when = []
    for x in list(c.get("when") or []) + list(c.get("tech") or []) + list(c.get("cues") or []):
        k = _keep_when(str(x))
        if k and k not in when:
            when.append(k)
        if len(when) >= 8:
            break
    do = []
    for x in c.get("do") or c.get("techniques") or []:
        k = _keep_tactic(str(x))
        if k and k not in do:
            do.append(k)
        if len(do) >= 6:
            break
    avoid = []
    for x in c.get("avoid") or c.get("failed_techniques") or []:
        k = _keep_tactic(str(x))
        if k and k not in avoid:
            avoid.append(k)
        if len(avoid) >= 6:
            break
    chain = scrub_chain(str(c.get("chain") or c.get("winning_chain") or c.get("route") or ""))
    idea = keep_thought(str(c.get("idea") or ""), stacks=when)
    method = keep_thought(str(c.get("method") or ""), stacks=when)
    route = keep_thought(str(c.get("route") or ""), stacks=when) or chain
    if not do and not avoid and not chain and not (method and idea):
        return None
    rule = format_methodology(
        when=when, do=do, avoid=avoid, chain=chain,
        route=route, method=method, idea=idea,
    )
    if not rule or _HOSTISH_RE.search(rule):
        return None
    out = dict(c)
    out.update({
        "when": when,
        "do": do,
        "avoid": avoid,
        "chain": chain,
        "route": route,
        "method": method,
        "idea": idea,
        "rule": rule[:360],
        "target_fp": "|".join(x for x in when if x in STACK_TOKENS) or "*",
    })
    return out


def graph_methodology_signals(graph: dict | None) -> set[str]:
    """当前图上可用来匹配剧本的信号：技术栈、线索名、已出现的战术类型。"""
    g = graph or {}
    nodes = g.get("nodes") or []
    findings = g.get("findings") or []
    sig: set[str] = set()
    tags: list[str] = []
    titles: list[str] = []
    for n in nodes:
        titles.append(str(n.get("title") or ""))
        for t in (n.get("tags") or []):
            tags.append(str(t))
        key = str(n.get("key") or "")
        gnk = generalize_node_key(key)
        m = re.search(r"\(([a-z0-9_]+)\)", gnk)
        if m and m.group(1) in TACTIC_TOKENS:
            sig.add(m.group(1))
        cat = str(n.get("category") or "").strip().lower()
        k = keep_tactic(cat)
        if k:
            sig.add(k)
    for f in findings:
        cat = str(f.get("category") or "").strip().lower()
        k = keep_tactic(cat)
        if k:
            sig.add(k)
        titles.append(str(f.get("title") or ""))
    for it in g.get("intents") or []:
        sk = str(it.get("strategy_key") or "")
        tac = sk.split("::")[-1] if "::" in sk else sk
        k = keep_tactic(tac)
        if k:
            sig.add(k)
    if any(str(n.get("type") or "") == "foothold" for n in nodes):
        sig.add("foothold")
    sig.update(stack_tokens_of(tags))
    from .store import cues_from_text
    sig.update(cues_from_text(" ".join(titles), " ".join(tags)))
    return sig


def score_methodology(lesson: dict, signals: set[str], *, strict: bool) -> float:
    """strict（CTF）：必须和当前图线索/栈/战术有交集，不给泛 web 保底分。"""
    when = {str(x).lower() for x in (lesson.get("when") or [])}
    do = {str(x).lower() for x in (lesson.get("do") or [])}
    avoid = {str(x).lower() for x in (lesson.get("avoid") or [])}
    when_hit = len(when & signals)
    do_hit = len(do & signals)
    stack_hit = len((when & STACK_TOKENS) & signals)
    if strict and when_hit == 0 and do_hit == 0 and stack_hit == 0:
        return 0.0
    if strict and do and not lesson_consumes_evidence(list(do), signals):
        return 0.0
    conf = float(lesson.get("confidence") or 0.4)
    score = conf * 0.45 + 0.28 * when_hit + 0.22 * do_hit + 0.12 * stack_hit
    if avoid and (avoid & signals):
        score += 0.08
    if not strict:
        score += 0.08
    return score
