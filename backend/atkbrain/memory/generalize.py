"""制胜路径去特化。

把攻击图里带「题面特化」的制胜路径——具体 IP、端口、题面 node key（如
`vuln:path-traversal`、`foothold:app-rce`）——归一为**可迁移的战术类型链**：
只保留「节点类型 + 战术类别」的骨架（如 `entry → service(http) → vuln(lfi) →
vuln(rce) → foothold(rce) → goal`）。这样沉淀出的经验是「思路/手法的顺序」而非
「某道题的固定答案」，换靶场或真实环境同样适用。

单一职责：不读库、不写库，纯字符串归一，供 distill 与 retrieve 复用。
"""
from __future__ import annotations

import re

# node key 的类型前缀（含常见简写）→ 归一后的类型标签。
_TYPE_MAP: dict[str, str] = {
    "target": "entry", "host": "entry",
    "svc": "service", "service": "service", "port": "service",
    "info": "info",
    "danger": "surface", "attack-surface": "surface", "surface": "surface",
    "vuln": "vuln", "weakness": "vuln",
    "cred": "cred", "credential": "cred", "creds": "cred",
    "foothold": "foothold", "shell": "foothold",
    "honeypot": "honeypot",
    "goal": "goal", "flag": "goal",
}

# service 节点里可保留的协议 token（其余产品名/题面 slug 一律丢弃）。
_PROTOCOLS = {
    "http", "https", "ftp", "ssh", "smb", "redis", "mysql", "mssql", "mongodb",
    "mongo", "postgres", "postgresql", "ldap", "smtp", "pop3", "imap", "rdp",
    "telnet", "dns", "snmp", "rpc", "ws", "wss", "grpc", "api", "graphql",
    "memcached", "kafka", "rabbitmq", "elasticsearch", "vnc", "sip",
}

# 战术词表：把题面标识里的关键字归一为通用战术类别。顺序=优先级（更具体的在前，
# 命中即返回）。value 为归一后的战术名，与 finding 类别 / CRITICAL_CATEGORIES 对齐。
_TACTIC_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("command-injection", "command_injection"), ("cmdinject", "command_injection"),
    ("cmd-inject", "command_injection"), ("os-command", "command_injection"),
    ("cmdi", "command_injection"),
    ("deserial", "deserialization"), ("unserialize", "deserialization"),
    ("pickle", "deserialization"), ("ysoserial", "deserialization"),
    ("gadget", "deserialization"),
    # rce 关键字要早于 debug/session 等：`rce-debug-endpoint` 的战术是 rce 而非 debug。
    ("remote-code", "rce"), ("code-exec", "rce"), ("code-execution", "rce"),
    ("rce", "rce"),
    ("ssti", "ssti"), ("template-injection", "ssti"), ("jinja", "ssti"),
    ("nosql", "nosqli"),
    ("sql-injection", "sqli"), ("sqlinjection", "sqli"), ("sqli", "sqli"),
    ("union-select", "sqli"),
    ("path-traversal", "lfi"), ("directory-traversal", "lfi"), ("traversal", "lfi"),
    ("absolute-path", "lfi"), ("arbitrary-file-read", "lfi"), ("file-read", "lfi"),
    ("file-include", "lfi"), ("local-file", "lfi"), ("lfi", "lfi"),
    ("remote-file", "rfi"), ("rfi", "rfi"),
    ("file-write", "file_upload"), ("arbitrary-upload", "file_upload"),
    ("upload", "file_upload"),
    ("server-side-request", "ssrf"), ("ssrf", "ssrf"),
    ("xml-external", "xxe"), ("xml-entity", "xxe"), ("xxe", "xxe"),
    ("cross-site-script", "xss"), ("xss", "xss"),
    ("csrf", "csrf"),
    ("insecure-direct", "idor"), ("idor", "idor"),
    ("prototype", "prototype_pollution"), ("proto-pollution", "prototype_pollution"),
    ("jwt", "jwt"), ("jsonwebtoken", "jwt"),
    ("secret-key", "secret_key"), ("secret_key", "secret_key"),
    ("session-forge", "secret_key"), ("flask-session", "secret_key"),
    ("privilege-escalation", "privilege_escalation"), ("privesc", "privilege_escalation"),
    ("escalat", "privilege_escalation"), ("suid", "privilege_escalation"),
    ("open-redirect", "redirect"), ("redirect", "redirect"),
    ("auth-bypass", "auth_bypass"), ("authbypass", "auth_bypass"),
    ("bypass-auth", "auth_bypass"), ("login-bypass", "auth_bypass"),
    ("unauthenticated", "unauth"), ("no-auth", "unauth"), ("unauth", "unauth"),
    ("info-disclosure", "info_disclosure"), ("disclosure", "info_disclosure"),
    ("info-leak", "info_disclosure"), ("infoleak", "info_disclosure"),
    ("tech-stack", "info_disclosure"), ("exposure", "info_disclosure"),
    ("credential", "credential"), ("password", "credential"), ("weak-pass", "credential"),
    ("default-pass", "credential"), ("cred", "credential"),
    ("debug-endpoint", "debug"), ("werkzeug", "debug"), ("console", "debug"),
    ("debug", "debug"),
    # 泛化关键字放最后，避免抢占更具体的匹配（如 auth-bypass 先于 auth/login）。
    ("auth", "auth_bypass"), ("login", "auth_bypass"), ("bypass", "auth_bypass"),
    ("exec", "rce"),
)

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

TACTIC_NAMES: frozenset[str] = frozenset(t for _, t in _TACTIC_KEYWORDS)


def _strip_ip(text: str) -> str:
    return _IPV4.sub("", text or "")


def _match_tactic(ident: str) -> str | None:
    """从题面标识里归一出通用战术类别；识别不出返回 None。"""
    s = ident.lower()
    for kw, tactic in _TACTIC_KEYWORDS:
        if kw in s:
            return tactic
    return None


def _service_protocol(ident: str) -> str | None:
    """从 service 节点标识里只保留已知协议 token，丢弃端口与产品名/题面 slug。"""
    for tok in re.split(r"[^a-z0-9]+", ident.lower()):
        if tok in _PROTOCOLS:
            return tok
    return None


def generalize_node_key(key: str) -> str:
    """把单个 node key 归一为「类型(战术)」骨架，剥离 IP/端口/题面 slug。

    例：`vuln:path-traversal` → `vuln(lfi)`；`svc:80/http` → `service(http)`；
    `target:10.0.189.113` → `entry`；无法识别战术时退化为纯类型（如 `info`）。
    """
    raw = _strip_ip((key or "").strip().lower())
    if not raw:
        return ""
    if ":" in raw:
        typ, ident = raw.split(":", 1)
    else:
        typ, ident = "", raw
    ctype = _TYPE_MAP.get(typ.strip(), (typ.strip() or "node"))
    if ctype == "entry":
        return "entry"          # 入口只保留“入口”，丢弃具体主机/IP
    if ctype == "goal":
        return "goal"           # 终点统一为 goal，丢弃 flag 序号等
    if ctype == "service":
        proto = _service_protocol(ident)
        return f"service({proto})" if proto else "service"
    tactic = _match_tactic(ident)
    return f"{ctype}({tactic})" if tactic else ctype


def generalize_chain(path: str) -> list[str]:
    """把 ` -> ` 连接的原始制胜路径归一为去特化的战术类型链（连续去重）。

    输入既可能是 store.summarize_run 存的 `winning_path`，也可能是任意 node key 串。
    输出如 ["entry", "service(http)", "vuln(lfi)", "vuln(rce)", "foothold(rce)", "goal"]。
    """
    if not path:
        return []
    parts = re.split(r"\s*->\s*", str(path))
    chain: list[str] = []
    for p in parts:
        g = generalize_node_key(p)
        if not g:
            continue
        if chain and chain[-1] == g:
            continue            # 折叠连续重复（如两跳都是 vuln(rce)）
        chain.append(g)
    return chain


def generalize_chain_str(path: str) -> str:
    """渲染成可读的一行战术链。"""
    return " → ".join(generalize_chain(path))
