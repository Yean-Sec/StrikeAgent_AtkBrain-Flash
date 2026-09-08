"""监督输入：只给攻击图上的事实（节点/边/发现/Intent/否证/flag）和局面摘要。

不喂工具流水、上轮长摘录、进化经验全文。顾问走 Claude Code（约 1M 上下文），
简报预算是安全轨，不是因为装不下才裁图。超时是 CLI 墙钟，不要靠压短简报抢救。
可喂跨局蒸馏的战术族名（do/avoid），禁止当本题步骤或 payload。
不把换通道/禁枚举写成现成方案；通道怎么打由 Claude Code 根据图判断。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..db import db

# Claude Code 约 1M token；简报按 256k 字给足图，不是小上下文配额。
BRIEF_BUDGET = 256_000
COMPACT_BUDGET = 256_000

# 与控制台关系图图例一致（AttackGraph LEGEND_TYPES + 橙线/紫线/★）
_LEGEND_LABEL = {
    "target": "目标",
    "service": "服务",
    "danger": "危险点",
    "vuln": "漏洞",
    "credential": "凭证",
    "foothold": "立足点",
    "goal": "立足点",
    "info": "信息",
    "honeypot": "蜜罐",
}
_TYPE_ORDER = (
    "target", "service", "danger", "vuln", "credential", "foothold", "goal", "info", "honeypot",
)
_SKIP_REL = frozenset({"CONTAINS"})  # 从属边图上已由节点归属表达，不必再倒一遍
_LATERAL_REL = frozenset({"PIVOTS_TO"})


@dataclass
class SupervisorFacts:
    quality: str = "none"
    infra: bool = False
    chain_live: bool = False
    postex: bool = False
    identity_mismatch: bool = False
    unmounted_secret: bool = False
    repeats: list[str] = field(default_factory=list)
    no_progress: int = 0
    last_diagnosis: str = ""
    last_plan: str = ""
    last_plan_outcome: str = ""
    last_must_intents: list[str] = field(default_factory=list)
    last_deny_tactics: list[str] = field(default_factory=list)
    prior_plans: list[dict] = field(default_factory=list)
    current_entry: str = ""
    peer_entries: list[str] = field(default_factory=list)
    last_tool_uses: int = 0
    plan_exec_turns: int = 0
    plan_dwell_turns: int = 2
    active_plan_live: bool = False
    claim_unverified: bool = False
    invert_ops: bool = False
    postex_pivot: bool = False
    chain_close: bool = False
    channel_oracle_open: bool = False
    wrong_flags: int = 0
    correct_flags: int = 0
    flag_count: int = 0
    evo_do: list[str] = field(default_factory=list)
    evo_avoid: list[str] = field(default_factory=list)


_CLAIM_RE = re.compile(
    r"已求得|已拿到|已破译|已锁定|访问码已|凭据已|正确访问码",
    re.I,
)
_PLACEHOLDER_RE = re.compile(
    r"全为点|恒为\.|"
    r"未输出\s*flag|输出[^\n]{0,24}(点|\.|denied)|"
    r"complete[^\n]{0,24}(点|\.)|"
    r"原生.{0,16}占位",
    re.I,
)


INVERT_OPS_GUIDE = (
    "收口手法（仅在简报标明假收口或占位输出时适用）："
    "校验通过但只打印固定占位时，占位不是答案；只用本题入口已经出现过的运算与数据反演，立刻 report_flag。"
    "不要用 flag 格式字符串去拟合未知量，不要把改过的 dump 当答案，不要另找图上没出现过的算法。"
)

POSTEX_PIVOT_GUIDE = (
    "横向收口（可迁移，不是某题 payload）：已验证 SSRF/开放代理或 GETSHELL 之后，"
    "剩余 flag 通常不在本容器。从跳板看见的容器网/内网主机（arp、hosts、init 拓扑）"
    "用 report_pivot_capability 扩进 Scope。"
    "经 SSRF 扩容的主机，攻击机网卡通常到不了：把目标 URL 放进已验证 SSRF 参数，或从 webshell 访问；"
    "禁止 Kali 直连，禁止把这些地址当邻题入口。"
    "邻机是新身份域：must_intents 按 tactic 正交，同一 tactic 只占一格。"
    "身份验证与未授权可达并行；上一跳账密只是候选。同一身份面无新秘密则结束该跳 hop_auth。"
    "跳板扫描到的每一台都要单独 report_pivot_capability，不要只扩一台。"
    "本机已交过的旗不要再挖；再读本机下一项打不开 → 去邻机。"
    "邻题入口（同评测其它 unique_code 的入口 IP/端口）仍然越界。"
)

CHAIN_CLOSE_GUIDE = (
    "收口（可迁移，不是某题 payload）：图上已有已验证可利用发现时，下一步是抽取/执行，不是再证明同一面。"
    "时间差/布尔差已经验证注入 → 先换成回显/联合/报错/状态差分，打成控制流或会话；"
    "同一耗时通道按位 dump 只是退路。不要再校准耗时，也不要把库侧文件读原语当默认收口（常被配置挡住），更不要把抽出的哈希拿去超级大字典硬撞。"
    "前端/JS 字段反复 4xx、或错误正文点名了你没发的键 → 客户端契约过时，按错误正文与同接口其它泄露名换键，禁止对已否证键做编码变体；恒定 4xx 点名缺字段说明通道活着，不要把整条网关写成存根。"
    "已验证跳板（SSRF/导入/代理）不要改成攻击机直连错误正文里的内网地址。"
    "过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类。"
    "写/反序列化/上传已验证 → 投递执行，不是继续分析 gadget/封装理论。"
    "已持有签名令牌：少数算法或弱密钥变体失败不关闭整类；把令牌当服务端校验对象继续打，不要只改前端角色字段。"
    "一种证明通道被挡，换抽取面，不要把整点钟花在同一通道。"
)

SINGLE_CHANNEL_GUIDE = (
    "单通道否证：状态码/正文无差异，输入面未关；禁止把恒定错误页写成已验证利用，也禁止 defer channel_oracle。"
)

_TEMPLATE_DECRYPT_RE = re.compile(
    r"FLAG\s*\{|keystream|套.{0,12}密文|模板\s*flag|"
    r"(?:flag|密文).{0,16}(?:拟合|约束)|(?:拟合|约束).{0,16}(?:flag|密文)",
    re.I,
)
_TEMPLATE_XOR_CLAUSE_RE = re.compile(
    r"(?:blob.{0,48}\^\s*.{0,36}FLAG|FLAG\s*\{.{0,48}\^|"
    r"FLAG.{0,24}(约束|拟合).{0,24}(ks|keystream|密文)|"
    r"(ks|keystream).{0,24}(约束|拟合).{0,24}FLAG)",
    re.I,
)
_POISON_INTENT_ID_RE = re.compile(r"keystream|flag.?format", re.I)


def needs_invert_ops_guidance(*, graph: dict | None = None, claim_unverified: bool = False) -> bool:
    if claim_unverified:
        return True
    blob = _graph_text(graph)
    if _PLACEHOLDER_RE.search(blob):
        return True
    return bool(re.search(
        r"execution complete|自定义.{0,12}(执行|解释|字节码)|内嵌.{0,8}解释",
        blob, re.I,
    ))


def needs_postex_pivot_guidance(
    *,
    graph: dict | None = None,
    correct_flags: int = 0,
    flag_count: int = 0,
) -> bool:
    """已有跳板且 flag 未齐：引导从跳板扩内网，而不是把容器网当邻题。"""
    if int(flag_count or 0) > 0 and int(correct_flags or 0) >= int(flag_count):
        return False
    g = graph or {}
    stats = g.get("stats") or {}
    if stats.get("has_shell"):
        return True
    nodes = g.get("nodes") or []
    if any(
        n.get("type") in ("foothold", "goal") and (n.get("is_rce") or "getshell" in {str(t).lower() for t in (n.get("tags") or [])})
        for n in nodes
    ):
        return True
    blob = _graph_text(g)
    return bool(re.search(r"\bssrf\b|开放代理|file://|webshell|GETSHELL", blob, re.I))


def _graph_text(graph: dict | None) -> str:
    parts: list[str] = []
    for n in (graph or {}).get("nodes") or []:
        parts.append(str(n.get("title") or ""))
        parts.append(str(n.get("key") or ""))
        parts.append(str(n.get("detail") or "")[:240])
    for f in (graph or {}).get("findings") or []:
        parts.append(str(f.get("title") or ""))
    return "\n".join(parts)


def claimed_secret_disproved(
    *,
    plan: str = "",
    graph: dict | None = None,
    correct_flags: int = 0,
    wrong_flags: int = 0,
) -> bool:
    """方案或图声称已拿到访问码/凭据，但正确 flag 仍为 0，且有错旗或占位输出。"""
    if int(correct_flags or 0) > 0:
        return False
    blob = f"{plan or ''}\n{_graph_text(graph)}"
    claimed = bool(_CLAIM_RE.search(blob))
    if int(wrong_flags or 0) >= 2:
        return True
    if claimed and int(wrong_flags or 0) >= 1:
        return True
    if claimed and _PLACEHOLDER_RE.search(blob):
        return True
    return False


def plan_claims_obtained_secret(text: str) -> bool:
    """方案/诊断是否声称已拿到访问码、凭据或已可解密。"""
    return bool(_CLAIM_RE.search(text or ""))


def _clip(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _goal_line(objective: str) -> str:
    if (objective or "").strip().lower() in ("flag", "ctf"):
        return "CTF：唯一目标是夺齐正确 flag 后收工（平台扣分不是漏旗）。本题必有解，禁止超级大字典撞库/撞哈希。"
    return "红队：report_shell 确认服务器命令执行后收工"


def highlight_chain_line(
    rce: dict | None,
    *,
    objective: str = "",
    peer_void: bool = False,
    arrow: str = " → ",
    show_frontier_tag: bool = False,
) -> str:
    """CTF 不把橙线边权乘积写成「RCE 概率」；那不是夺旗进度。"""
    from ..objective import FLAG, normalize_objective

    ctf = normalize_objective(objective) == FLAG
    rce = rce or {}
    path = [str(x) for x in (rce.get("path") or []) if x]
    if peer_void:
        return (
            "图上高亮链：（邻题节点已隔离，路径作废）"
            if ctf else
            "RCE 最优路径：（邻题节点已隔离，路径作废）"
        )
    if not path:
        return "图上高亮链：（未形成）" if ctf else "RCE 最优路径：（未形成）"
    chain = arrow.join(path)
    if ctf:
        note = "（前沿高亮，不是夺旗进度）" if rce.get("frontier_mode") else "（高亮链，不是夺旗概率）"
        return f"图上高亮链：{chain}  {note}"
    extra = "  [frontier_mode]" if show_frontier_tag and rce.get("frontier_mode") else ""
    return f"RCE 最优路径：{chain}  边权乘积≈{rce.get('likelihood', 0)}{extra}"


def _node_tags(n: dict) -> list[str]:
    tags = n.get("tags") or []
    if isinstance(tags, str):
        return [tags]
    return [str(t) for t in tags if t]


def _is_getshell(n: dict) -> bool:
    """与控制台 ★ 一致：只有已拿到命令执行的立足点/goal。漏洞不算。"""
    t = str(n.get("type") or "")
    key = str(n.get("key") or "")
    tags = {x.lower() for x in _node_tags(n)}
    if t == "goal" and (n.get("is_rce") or "getshell" in tags or key.startswith("goal:shell")):
        return True
    if t == "foothold" and (n.get("is_rce") or "getshell" in tags):
        return True
    return False


def plan_cites_peer_entry(text: str, peer_entries: list[str] | None) -> bool:
    """当前方案是否还在引用邻题 host:port / svc:端口。

    不按 IP 单独命中。高位端口（>=1024）才用 svc:9107 / :9107/ 这类端口标记，
    避免多题都是 :80 时把「本题 10.0.x.x:80」误判成邻题污染、每轮作废方案再问顾问。
    只出现在「不要打/邻题禁区」语境里的点名不算污染。
    """
    blob = (text or "").lower()
    if not blob:
        return False
    for a in peer_entries or []:
        s = str(a or "").strip().lower()
        if not s:
            continue
        if s in blob and not _all_mentions_forbidden(blob, s):
            return True
        if ":" not in s:
            continue
        _host, _, port = s.rpartition(":")
        if not port.isdigit():
            continue
        try:
            pn = int(port)
        except ValueError:
            continue
        # 80/443/22 等常见口多题共享；端口标记只给赛题高位口。
        if pn < 1024:
            continue
        for tok in (
            f"svc:{port}", f"port:{port}", f"{port}-http", f"{port}/http",
            f":{port}/", f":{port} ", f"{port}-",
        ):
            if tok in blob and not _all_mentions_forbidden(blob, tok.strip()):
                return True
        if f"{port}_" in blob and not _all_mentions_forbidden(blob, f"{port}_"):
            return True
    return False


_FORBID_PEER_CTX_RE = re.compile(
    r"(不要打|不要碰|别去打|禁止打|勿打|禁打|不要去|禁止当本题|不是本题|禁区|越界)",
)


def _all_mentions_forbidden(blob: str, needle: str) -> bool:
    if not needle or needle not in blob:
        return False
    idx = 0
    found = False
    while True:
        i = blob.find(needle, idx)
        if i < 0:
            return found
        found = True
        window = blob[max(0, i - 24): i + len(needle) + 16]
        if not _FORBID_PEER_CTX_RE.search(window):
            return False
        idx = i + max(1, len(needle))


def intent_claims_obtained_secret(intent: dict | None) -> bool:
    """开放 Intent 是否还在声称已拿到访问码/凭据或已可解密。"""
    if not intent:
        return False
    froms = intent.get("from") or intent.get("from_keys") or []
    if isinstance(froms, str):
        froms = [froms]
    return plan_claims_obtained_secret(" ".join([
        str(intent.get("description") or ""),
        str(intent.get("strategy_key") or ""),
        str(intent.get("rationale") or ""),
        " ".join(str(x) for x in froms),
    ]))


def _intent_cites_peer(intent: dict, peer_entries: list[str] | None) -> bool:
    froms = intent.get("from") or intent.get("from_keys") or []
    if isinstance(froms, str):
        froms = [froms]
    return plan_cites_peer_entry(
        " ".join([
            str(intent.get("description") or ""),
            str(intent.get("strategy_key") or ""),
            str(intent.get("rationale") or ""),
            " ".join(str(x) for x in froms),
        ]),
        peer_entries,
    )


def _node_is_peer(n: dict, peer_entries: list[str] | None) -> bool:
    if not peer_entries:
        return False
    blob = " ".join([
        str(n.get("key") or ""), str(n.get("title") or ""),
        " ".join(str(t) for t in (n.get("tags") or [])),
        str(n.get("detail") or "")[:200],
    ]).lower()
    if plan_cites_peer_entry(blob, peer_entries):
        return True
    for a in peer_entries:
        s = str(a or "").lower()
        if not s:
            continue
        if s in blob:
            return True
        host = s.split(":")[0]
        port = s.split(":")[-1] if ":" in s else ""
        if host and host in blob and port and (f"port:{port}" in blob or f"svc:{port}" in blob or f":{port}" in blob):
            return True
    return False


def _target_is_peer(n: dict, peer_entries: list[str] | None, current_entry: str = "") -> bool:
    if str(n.get("type") or "") != "target":
        return False
    current_host = str(current_entry or "").split(":")[0].strip().lower()
    blob = f"{n.get('key') or ''} {n.get('title') or ''}".lower()
    if current_host and current_host in blob:
        return False
    for a in peer_entries or []:
        host = str(a or "").split(":")[0].strip().lower()
        if host and host in blob:
            return True
    return False


def expand_peer_node_keys(
    nodes: list[dict],
    edges: list[dict] | None,
    peer_entries: list[str] | None,
    current_entry: str = "",
) -> set[str]:
    """邻题入口节点及其只连在邻题上的子图。本题入口 host/port 上的节点不收入。"""
    if not peer_entries:
        return set()
    seeds = {
        str(n.get("key") or "")
        for n in nodes
        if n.get("key") and (
            _node_is_peer(n, peer_entries) or _target_is_peer(n, peer_entries, current_entry)
        )
    }
    current_host = str(current_entry or "").split(":")[0].strip().lower()
    current_port = ""
    if current_entry and ":" in str(current_entry):
        current_port = str(current_entry).rsplit(":", 1)[-1]
    current_keys: set[str] = set()
    by_key = {str(n.get("key") or ""): n for n in nodes if n.get("key")}
    for n in nodes:
        k = str(n.get("key") or "")
        if not k:
            continue
        blob = " ".join([
            k, str(n.get("title") or ""),
            " ".join(str(t) for t in (n.get("tags") or [])),
        ]).lower()
        if current_host and current_host in blob and k not in seeds:
            current_keys.add(k)
        elif current_port and current_port.isdigit() and k not in seeds and any(
            tok in blob for tok in (f"svc:{current_port}", f"port:{current_port}", f"{current_port}-http", f"{current_port}-")
        ):
            current_keys.add(k)
    adj: dict[str, set[str]] = {}
    for e in edges or []:
        src, _, dst = _edge_ends(e)
        if src and dst:
            adj.setdefault(src, set()).add(dst)
            adj.setdefault(dst, set()).add(src)
    out = set(seeds)
    stack = list(seeds)
    while stack:
        cur = stack.pop()
        for nb in adj.get(cur, ()):
            if nb in out or nb in current_keys:
                continue
            out.add(nb)
            stack.append(nb)
    del by_key
    return {k for k in out if k}


def node_is_template_decrypt(n: dict | None) -> bool:
    """图节点是否在用 FLAG 花括号模板 / keystream 去套同一密文。"""
    if not n:
        return False
    blob = f"{n.get('key') or ''} {n.get('title') or ''} {str(n.get('detail') or '')[:240]}"
    if _CLAIM_RE.search(blob):
        return True
    return bool(_TEMPLATE_DECRYPT_RE.search(blob))


def intent_is_template_decrypt(intent: dict | None) -> bool:
    """开放 Intent 是否还在把花括号模板 / keystream 当前缀约束。"""
    if not intent:
        return False
    blob = " ".join([
        str(intent.get("id") or ""),
        str(intent.get("description") or ""),
        str(intent.get("strategy_key") or ""),
        str(intent.get("rationale") or ""),
    ])
    return bool(_TEMPLATE_DECRYPT_RE.search(blob) or _CLAIM_RE.search(blob))


def strip_template_xor_clauses(text: str) -> str:
    """去掉「用花括号模板 XOR/约束 keystream」的句子，保留其余步骤。"""
    raw = text or ""
    if not raw.strip():
        return raw
    parts = re.split(r"(?<=[。；;\n])", raw)
    kept = [p for p in parts if p and not _TEMPLATE_XOR_CLAUSE_RE.search(p)]
    return "".join(kept).strip()


def sanitize_invert_ops_plan(plan, *, invert_ops: bool = False):
    """假收口/占位输出时：丢掉模板拟合 Intent，并剥掉花括号 XOR 句子。"""
    if not invert_ops or plan is None:
        return plan
    try:
        plan.must_intents = [
            i for i in list(plan.must_intents or [])
            if not _POISON_INTENT_ID_RE.search(str(i or ""))
        ][:3]
        plan.diagnosis = strip_template_xor_clauses(str(plan.diagnosis or ""))
        cleaned = strip_template_xor_clauses(str(plan.next_plan or ""))
        plan.next_plan = cleaned or INVERT_OPS_GUIDE
        bans = list(plan.ban_repeats or [])
        tag = "用 flag 花括号模板拟合密文"
        if tag not in bans:
            bans.append(tag)
        plan.ban_repeats = bans[:12]
    except Exception:
        return plan
    return plan


def _node_line(n: dict, *, peer: bool = False, disproved: bool = False) -> str:
    label = _LEGEND_LABEL.get(str(n.get("type") or ""), str(n.get("type") or "?"))
    star = "★GETSHELL " if _is_getshell(n) else ""
    peer_bit = "邻题 " if peer else ""
    dead_bit = "已否证·假收口 " if disproved else ""
    sev = str(n.get("severity") or "").strip()
    sev_bit = f"/{sev}" if sev and sev.lower() not in ("", "info") else ""
    title = _clip(str(n.get("title") or ""), 70)
    if disproved:
        title = "模板拟合约束已否证，禁止写入 next_plan"
    return (
        f"  · {star}{dead_bit}{peer_bit}[{label}{sev_bit}] {n.get('key')} — "
        f"{title}"
    )


def _edge_ends(e: dict) -> tuple[str, str, str]:
    return (
        str(e.get("from") or e.get("src") or ""),
        str(e.get("relation") or ""),
        str(e.get("to") or e.get("dst") or ""),
    )


def _graph_block(
    graph: dict | None,
    *,
    compact: bool = False,
    peer_entries: list[str] | None = None,
    current_entry: str = "",
    claim_unverified: bool = False,
    invert_ops: bool = False,
    objective: str = "",
) -> str:
    """按控制台图例写图：节点类型、★GETSHELL、RCE 橙线、横向紫线。不倒 CONTAINS。"""
    g = graph or {}
    stats = g.get("stats") or {}
    rce = g.get("rce_path") or {}
    frontier = g.get("frontier") or {}
    lines = [
        f"节点 {stats.get('nodes', 0)} · 边 {stats.get('edges', 0)} · 发现 {stats.get('findings', 0)}"
        f"（严重 {stats.get('critical', 0)}）· GETSHELL={'是' if stats.get('has_shell') else '否'}",
        f"前沿：开放 {frontier.get('open', stats.get('frontier_open', 0))} · "
        f"策略数 {frontier.get('strategies', stats.get('frontier_strategies', 0))} · "
        f"已否证 {frontier.get('disproved', 0)} · 已验证 {frontier.get('verified', 0)}",
    ]
    nodes = list(g.get("nodes") or [])
    edges = list(g.get("edges") or [])
    peer_keys = expand_peer_node_keys(nodes, edges, peer_entries, current_entry)
    peer_nodes = [n for n in nodes if str(n.get("key") or "") in peer_keys]
    path = [str(x) for x in (rce.get("path") or []) if x]
    peer_void = bool(path and peer_keys and any(k in peer_keys for k in path))
    lines.append(highlight_chain_line(rce, objective=objective, peer_void=peer_void))
    by_type: dict[str, list[dict]] = {t: [] for t in _TYPE_ORDER}
    other: list[dict] = []
    for n in nodes:
        if str(n.get("key") or "") in peer_keys:
            continue
        t = str(n.get("type") or "")
        if t in by_type:
            by_type[t].append(n)
        else:
            other.append(n)
    listed = 0
    cap = 36 if compact else 80
    for t in _TYPE_ORDER:
        group = by_type[t]
        if not group:
            continue
        group.sort(key=lambda n: -int(n.get("risk_score") or 0))
        label = _LEGEND_LABEL.get(t, t)
        lines.append(f"{label}：")
        for n in group:
            if listed >= cap:
                break
            lines.append(_node_line(
                n,
                disproved=bool(
                    (claim_unverified or invert_ops) and node_is_template_decrypt(n)
                ),
            ))
            listed += 1
        if listed >= cap:
            break
    extra = len(nodes) - listed - len(peer_nodes)
    if extra > 0:
        lines.append(f"  · …另 {extra} 个节点未列出")
    if peer_nodes:
        lines.append(
            f"邻题污染：{len(peer_nodes)} 个节点已隔离。"
            "其上的算法、密钥、flag 候选禁止当本题手法模板。"
        )

    edges = list(g.get("edges") or [])
    laterals = [
        e for e in edges
        if _edge_ends(e)[1] in _LATERAL_REL
        and _edge_ends(e)[0] not in peer_keys
        and _edge_ends(e)[2] not in peer_keys
    ]
    if laterals:
        lines.append("内网横向（shell→新目标）：")
        for e in laterals[: 12 if compact else 24]:
            src, rel, dst = _edge_ends(e)
            lines.append(f"  · {src} -{rel}-> {dst}")
    rels = [
        e for e in edges
        if _edge_ends(e)[1] not in _SKIP_REL
        and _edge_ends(e)[1] not in _LATERAL_REL
        and _edge_ends(e)[0] not in peer_keys
        and _edge_ends(e)[2] not in peer_keys
    ]
    rel_cap = 16 if compact else 40
    if rels:
        lines.append("关系：")
        for e in rels[:rel_cap]:
            src, rel, dst = _edge_ends(e)
            mark = " [RCE路径]" if e.get("on_rce_path") else ""
            lines.append(f"  · {src} -{rel}->{dst}{mark}")
        extra_e = len(rels) - rel_cap
        if extra_e > 0:
            lines.append(f"  · …另 {extra_e} 条关系未列出")

    findings = [
        f for f in (g.get("findings") or [])
        if not plan_cites_peer_entry(
            f"{f.get('title') or ''} {f.get('detail') or ''} {f.get('node_key') or ''}",
            peer_entries,
        )
    ]
    if findings:
        lines.append("发现：")
        for f in findings[: 12 if compact else 24]:
            vs = f.get("verification_status") or ""
            flag = "★" if f.get("critical") else " "
            lines.append(
                f"  {flag}[{f.get('severity')}/{f.get('category')}/{vs}] "
                f"{_clip(str(f.get('title') or ''), 80)}"
            )
    disproved = g.get("disproved") or []
    if disproved:
        lines.append("已否证（勿重复，除非有新证据）：")
        for i in disproved[: 8 if compact else 24]:
            why = _clip(str(i.get("failure_fingerprint") or i.get("result_summary") or ""), 60)
            desc = _clip(str(i.get("description") or ""), 80)
            line = f"  ✗ {desc}"
            if why:
                line += f" — 因 {why}"
            lines.append(line)
    return "\n".join(lines)


def _intent_tactic(intent: dict | None) -> str:
    sk = str((intent or {}).get("strategy_key") or "")
    return sk.split("::")[-1] if "::" in sk else sk


def _intents_family_line(intents: list[dict]) -> str:
    counts: dict[str, int] = {}
    for i in intents or []:
        tac = _intent_tactic(i)
        if not tac:
            continue
        counts[tac] = counts.get(tac, 0) + 1
    if not counts:
        return ""
    bits = [f"{k}×{counts[k]}" for k in sorted(counts, key=lambda x: (-counts[x], x))[:12]]
    return "战术族（must_intents 三条必须不同族；身份验证与未授权要同时占格）：" + "、".join(bits)


def _evo_tactics_block(do: list[str], avoid: list[str]) -> str:
    if not do and not avoid:
        return ""
    lines = ["## 可迁移战术（跨局蒸馏族名，不是本题步骤，禁止当 payload）"]
    if do:
        lines.append("优先：" + "、".join(do[:8]))
    if avoid:
        lines.append("避开：" + "、".join(avoid[:8]))
    return "\n".join(lines)


def _intents_block(intents: list[dict], *, limit: int = 12) -> str:
    if not intents:
        return "（无开放 Intent）"
    lines: list[str] = []
    fam = _intents_family_line(intents)
    if fam:
        lines.append(fam)
    for i in intents[:limit]:
        lines.append(
            f"  · [{i.get('id')}] ({round(i.get('priority', i.get('est_success', 0.5)), 2)}) "
            f"[{i.get('status', 'open')}] {_clip(str(i.get('description') or ''), 90)}  "
            f"strategy=`{_clip(str(i.get('strategy_key') or ''), 48)}`"
        )
    return "\n".join(lines)


async def flag_submission_stats(project_id: str) -> tuple[int, int]:
    """正确 flag 数、不同错误 flag 数。错旗常只在 events，不落 flags 表。"""
    correct_vals: set[str] = set()
    wrong_vals: set[str] = set()
    if not project_id:
        return 0, 0

    def _take(val: str, ok: bool) -> None:
        v = (val or "").strip()
        if not v:
            return
        if ok:
            correct_vals.add(v)
            wrong_vals.discard(v)
        elif v not in correct_vals:
            wrong_vals.add(v)

    try:
        rows = await db.fetchall(
            "SELECT value, correct FROM flags WHERE project_id=?",
            (project_id,),
        )
        for r in rows or []:
            _take(str(r.get("value") or ""), bool(r.get("correct")))
    except Exception:
        pass
    try:
        evs = await db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='flag' "
            "ORDER BY id DESC LIMIT 80",
            (project_id,),
        )
        for r in evs or []:
            try:
                p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
            except Exception:
                continue
            _take(str(p.get("value") or ""), bool(p.get("correct")))
    except Exception:
        pass
    return len(correct_vals), len(wrong_vals)


async def _flags_block(project_id: str) -> str:
    seen: set[str] = set()
    lines: list[str] = []

    def _add(val: str, ok: bool, extra: str = "") -> None:
        v = (val or "").strip()
        if not v or v in seen:
            return
        seen.add(v)
        mark = "✓" if ok else "✗"
        lines.append(f"  {mark} {_clip(v, 80)}{extra}")

    try:
        rows = await db.fetchall(
            "SELECT value, awarded, correct FROM flags WHERE project_id=? ORDER BY created_at DESC LIMIT 12",
            (project_id,),
        )
        for r in rows or []:
            awarded = r.get("awarded")
            extra = f" +{awarded}" if awarded else ""
            _add(str(r.get("value") or ""), bool(r.get("correct")), extra)
    except Exception:
        pass
    try:
        evs = await db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='flag' "
            "ORDER BY id DESC LIMIT 24",
            (project_id,),
        )
        for r in evs or []:
            try:
                p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
            except Exception:
                continue
            _add(str(p.get("value") or ""), bool(p.get("correct")))
    except Exception:
        pass
    if not lines:
        return "（尚未夺旗）"
    return "\n".join(lines[:12])


def _facts_block(facts: SupervisorFacts) -> str:
    lines = [
        f"- 本轮质量进展：{facts.quality}；连续无高质量进展轮数：{facts.no_progress}",
        f"- 当前入口：{facts.current_entry or '（未填）'}"
        + (
            "；邻题入口（禁止当本题主线）：" + "、".join(facts.peer_entries[:16])
            if facts.peer_entries else
            "（无横向边/立足点的其它 IP 视为换址残留，不是新主机）"
        ),
        f"- 入口传输层连续失败（超时/拒绝/DNS）：{'是' if facts.infra else '否'}",
        f"- 已有可接着打的资产（已验证漏洞/凭证/立足点）：{'是' if facts.chain_live else '否'}",
        f"- 已有立足点但无提权/横向能力边：{'是' if facts.postex else '否'}",
        f"- 入口栈/身份与 BRIEF 不一致：{'是' if facts.identity_mismatch else '否'}",
        f"- 图上有未挂载的机器密钥：{'是' if facts.unmounted_secret else '否'}",
        f"- 正确 flag：{int(facts.correct_flags or 0)}；不同错误 flag：{int(facts.wrong_flags or 0)}",
    ]
    if facts.claim_unverified:
        lines.append(
            "- 假收口：是。方案或图声称已经解密出凭据/flag，但正确 flag 仍为 0。"
            "否证的是该解密式和已提交的值，不是整条链已死。hold=false。"
        )
    if facts.invert_ops or facts.claim_unverified:
        lines.append("- " + INVERT_OPS_GUIDE)
    if facts.postex_pivot:
        lines.append("- " + POSTEX_PIVOT_GUIDE)
    if facts.chain_close:
        lines.append("- " + CHAIN_CLOSE_GUIDE)
    if facts.channel_oracle_open and not facts.chain_close:
        lines.append("- " + SINGLE_CHANNEL_GUIDE)
    if facts.active_plan_live:
        dwell = max(1, int(facts.plan_dwell_turns or 2))
        lines.append(
            f"- 当前方案已执行 {int(facts.plan_exec_turns or 0)}/{dwell} 轮有工具回合"
            "（未满或未否证则继续执行，不要改成另一套）"
        )
        lines.append(f"- 本轮工具调用：{int(facts.last_tool_uses or 0)} 次")
    if facts.repeats:
        lines.append("- 近期重复路径/命令：" + "、".join(f"`{x}`" for x in facts.repeats[:8]))
    return "\n".join(lines)


def _norm_plan_rec(raw: dict | None, *, diag_n: int = 240, plan_n: int = 400) -> dict:
    p = raw or {}
    diagnosis = _clip(str(p.get("diagnosis") or ""), diag_n)
    plan = _clip(str(p.get("next_plan") or ""), plan_n)
    rec = {
        "turn": p.get("turn") or 0,
        "pivot": p.get("pivot") or 0,
        "diagnosis": diagnosis,
        "next_plan": plan,
        "must_intents": list(p.get("must_intents") or [])[:3],
        "deny_tactics": list(p.get("deny_tactics") or p.get("defer_families") or [])[:8],
        "outcome": str(p.get("outcome") or ""),
    }
    return rec


def _plan_sig(p: dict | None) -> str:
    p = p or {}
    return f"{_clip(str(p.get('diagnosis') or ''), 120)}|{_clip(str(p.get('next_plan') or ''), 180)}"


def _merge_own_plans(*groups: list[dict] | None, limit: int = 8) -> list[dict]:
    """按时间合并顾问自己的方案；后出现的同签名覆盖（带执行结果）。"""
    out: list[dict] = []
    idx: dict[str, int] = {}
    for group in groups:
        for raw in group or []:
            rec = _norm_plan_rec(raw)
            if not (rec.get("diagnosis") or rec.get("next_plan")):
                continue
            sig = _plan_sig(rec)
            if sig in idx:
                old = out[idx[sig]]
                if rec.get("outcome") or not old.get("outcome"):
                    rec["outcome"] = rec.get("outcome") or old.get("outcome") or ""
                    rec["turn"] = rec.get("turn") or old.get("turn") or 0
                    rec["pivot"] = rec.get("pivot") or old.get("pivot") or 0
                    if not rec.get("must_intents"):
                        rec["must_intents"] = list(old.get("must_intents") or [])
                    if not rec.get("deny_tactics"):
                        rec["deny_tactics"] = list(old.get("deny_tactics") or [])
                    out[idx[sig]] = rec
                continue
            idx[sig] = len(out)
            out.append(rec)
    return out[-max(1, int(limit or 8)):]


async def load_prior_supervisor_plans(project_id: str, *, limit: int = 8) -> list[dict]:
    """本项目已注入的监督方案（不限 run，重启后续跑也看得到）。"""
    if not project_id:
        return []
    try:
        rows = await db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor' "
            "ORDER BY id DESC LIMIT 40",
            (project_id,),
        )
    except Exception:
        return []
    snapshot: list[dict] | None = None
    individuals: list[dict] = []
    seen: set[str] = set()
    for r in rows:
        try:
            p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
        except Exception:
            continue
        if str(p.get("kind") or "") != "plan":
            continue
        if snapshot is None and isinstance(p.get("plan_history"), list) and p.get("plan_history"):
            snapshot = [x for x in p["plan_history"] if isinstance(x, dict)]
        rec = _norm_plan_rec(p)
        if not (rec.get("diagnosis") or rec.get("next_plan")):
            continue
        sig = _plan_sig(rec)
        if sig in seen:
            continue
        seen.add(sig)
        individuals.append(rec)
        if len(individuals) >= max(limit, 8):
            break
    if snapshot:
        return _merge_own_plans(snapshot, limit=limit)
    individuals.reverse()
    return individuals[-max(1, int(limit or 8)):]


_OUTCOME_CN = {
    "oracle": "御主有高质量进展（flag/发现/能力边）",
    "executed": "御主碰过绑定，但图上还没有新的收口",
    "ignored": "御主未执行该绑定（仍在打被禁战术/入口回流）",
    "empty": "御主本轮几乎没有工具调用",
}


def _own_plans_block(plans: list[dict], *, compact: bool = False) -> str:
    """顾问自己写过的全部方案。写第 N 份必须对照第 1…N-1 份。"""
    if not plans:
        return "（你还没给过方案。这是第一次开口：连续两轮无有效进展才问你。）"
    n = len(plans)
    diag_n, plan_n = (80, 140) if compact else (240, 400)
    lines = [
        f"这是你自己写过的全部方案（共 {n} 份），不是御主笔记。写下一份必须对照这里每一份，不只看最近一份。",
        "已执行无收口 → 说明相对前面哪一步改了；未执行 → 收紧同一绑定，禁止同义改写成另一套；已否证的不要复开。",
    ]
    for i, p in enumerate(plans, 1):
        tag = "（最近一份）" if i == n else ""
        pivot = p.get("pivot") or ""
        turn = p.get("turn") or ""
        head = f"  · 第 {i} 份{tag}"
        extra_h = []
        if pivot:
            extra_h.append(f"方案#{pivot}")
        if turn:
            extra_h.append(f"第 {turn} 轮")
        if extra_h:
            head += " " + " ".join(extra_h)
        lines.append(head + "：" + _clip(str(p.get("diagnosis") or ""), diag_n))
        if p.get("next_plan"):
            lines.append("    方案：" + _clip(str(p.get("next_plan") or ""), plan_n))
        outcome = _OUTCOME_CN.get(str(p.get("outcome") or ""), "当时未记执行结果")
        lines.append("    执行结果：" + outcome)
        bits = []
        if p.get("must_intents"):
            bits.append("must=" + ",".join(str(x) for x in p["must_intents"][:3]))
        if p.get("deny_tactics"):
            bits.append("deny=" + ",".join(str(x) for x in p["deny_tactics"][:6]))
        if bits:
            lines.append("    " + "；".join(bits))
    return "\n".join(lines)


async def assemble_supervisor_brief(
    *,
    project_id: str,
    run_id: str,
    objective: str,
    graph: dict | None,
    facts: SupervisorFacts,
    project: dict | None = None,
    brief: str = "",
    last_turn_text: str = "",
    last_tool_uses: int = 0,
    turn: int = 0,
    scope_hosts: list[str] | None = None,
    open_intents: list[dict] | None = None,
    compact: bool = False,
) -> str:
    """只拼图：节点/边/发现/Intent/否证/flag + 局面摘要。忽略流水参数。"""
    from ..graph import store as gstore

    # 不上御主长摘要：那是简报膨胀主因。当前方案是否跑完用工具次数和已执行轮次表达。
    del last_turn_text
    try:
        facts.last_tool_uses = int(last_tool_uses or facts.last_tool_uses or 0)
    except (TypeError, ValueError):
        facts.last_tool_uses = 0
    budget = COMPACT_BUDGET if compact else BRIEF_BUDGET
    intent_limit = 16 if compact else 40
    prior_limit = 8 if compact else 16
    brief_clip = 220 if compact else 800
    proj = project or {}
    target = str(proj.get("target") or "")
    hosts = "、".join(h for h in (scope_hosts or []) if h) or target or "（未填）"
    entry = str(facts.current_entry or target or "").split(":")[0].strip()
    if not entry and scope_hosts:
        entry = str(scope_hosts[0] or "").split(":")[0].strip()
    if entry and not facts.current_entry:
        facts.current_entry = entry
    ports = (proj.get("ports") or []) if isinstance(proj.get("ports"), list) else []
    try:
        eport = int(ports[0]) if ports else 0
    except (TypeError, ValueError, IndexError):
        eport = 0
    if eport and facts.current_entry and ":" not in str(facts.current_entry):
        facts.current_entry = f"{facts.current_entry}:{eport}"
    if not facts.peer_entries:
        try:
            from ..scope_pivot import peer_challenge_entry_addrs
            facts.peer_entries = sorted(await peer_challenge_entry_addrs(project_id))[:20]
        except Exception:
            facts.peer_entries = []
    if open_intents is None:
        open_intents = list((graph or {}).get("intents") or [])
        if not open_intents:
            try:
                open_intents = await gstore.list_open_intents(project_id, limit=intent_limit * 2)
            except Exception:
                open_intents = []
    if facts.peer_entries:
        open_intents = [
            i for i in (open_intents or [])
            if not _intent_cites_peer(i, facts.peer_entries)
        ]
    try:
        c_flags, w_flags = await flag_submission_stats(project_id)
    except Exception:
        c_flags, w_flags = 0, 0
    if not facts.correct_flags:
        facts.correct_flags = int(c_flags or 0)
    if not facts.wrong_flags:
        facts.wrong_flags = int(w_flags or 0)
    if not facts.claim_unverified:
        facts.claim_unverified = claimed_secret_disproved(
            plan=f"{facts.last_plan or ''} {facts.last_diagnosis or ''}",
            graph=graph,
            correct_flags=facts.correct_flags,
            wrong_flags=facts.wrong_flags,
        )
    facts.invert_ops = needs_invert_ops_guidance(
        graph=graph, claim_unverified=facts.claim_unverified,
    )
    if not facts.flag_count:
        cfg = proj.get("config") or {}
        if isinstance(cfg, str):
            try:
                cfg = json.loads(cfg)
            except Exception:
                cfg = {}
        try:
            facts.flag_count = int((cfg or {}).get("flag_count") or 0)
        except (TypeError, ValueError):
            facts.flag_count = 0
    facts.postex_pivot = needs_postex_pivot_guidance(
        graph=graph,
        correct_flags=facts.correct_flags,
        flag_count=facts.flag_count,
    )
    facts.chain_close = bool(facts.chain_live) and not bool(facts.postex_pivot)
    if not facts.channel_oracle_open:
        try:
            from ..graph.hypothesize import needs_channel_oracle
            facts.channel_oracle_open = bool(
                needs_channel_oracle(graph) and not facts.chain_live and not facts.chain_close
            )
        except Exception:
            facts.channel_oracle_open = False
    if (facts.claim_unverified or facts.invert_ops) and open_intents:
        open_intents = [
            i for i in open_intents
            if not intent_claims_obtained_secret(i)
            and not intent_is_template_decrypt(i)
        ]
    loaded = await load_prior_supervisor_plans(project_id, limit=prior_limit)
    facts.prior_plans = _merge_own_plans(loaded, facts.prior_plans, limit=prior_limit)
    if facts.peer_entries and facts.prior_plans:
        facts.prior_plans = [
            p for p in facts.prior_plans
            if not plan_cites_peer_entry(
                f"{p.get('diagnosis') or ''} {p.get('next_plan') or ''}",
                facts.peer_entries,
            )
        ]
    if (facts.claim_unverified or facts.invert_ops) and facts.prior_plans:
        facts.prior_plans = [
            p for p in facts.prior_plans
            if not _CLAIM_RE.search(f"{p.get('diagnosis') or ''} {p.get('next_plan') or ''}")
            and not _TEMPLATE_XOR_CLAUSE_RE.search(
                f"{p.get('diagnosis') or ''} {p.get('next_plan') or ''}"
            )
        ]
    if facts.last_diagnosis or facts.last_plan:
        facts.prior_plans = _merge_own_plans(
            facts.prior_plans,
            [{
                "turn": max(0, turn - 1),
                "diagnosis": facts.last_diagnosis,
                "next_plan": facts.last_plan,
                "must_intents": list(facts.last_must_intents or [])[:3],
                "deny_tactics": list(facts.last_deny_tactics or [])[:8],
                "outcome": facts.last_plan_outcome,
            }],
            limit=prior_limit,
        )
    elif facts.prior_plans:
        latest = facts.prior_plans[-1]
        facts.last_diagnosis = str(latest.get("diagnosis") or "")
        facts.last_plan = str(latest.get("next_plan") or "")
        if not facts.last_must_intents:
            facts.last_must_intents = list(latest.get("must_intents") or [])
        if not facts.last_deny_tactics:
            facts.last_deny_tactics = list(latest.get("deny_tactics") or [])
        if not facts.last_plan_outcome:
            facts.last_plan_outcome = str(latest.get("outcome") or "")
    if facts.prior_plans and facts.last_plan_outcome:
        facts.prior_plans[-1]["outcome"] = facts.last_plan_outcome

    evo_block = ""
    if not facts.evo_do and not facts.evo_avoid:
        try:
            from ..memory.evolve import (
                avoid_from_lessons, format_lessons_block, retrieve_lessons, tactics_from_lessons,
            )
            lessons = await retrieve_lessons(proj, graph, limit=6, bump_uses=False)
            facts.evo_do = sorted(tactics_from_lessons(lessons))[:8]
            facts.evo_avoid = sorted(avoid_from_lessons(lessons))[:8]
            evo_block = format_lessons_block(lessons) or ""
        except Exception:
            pass
    hist_title = (
        "## 已给过的方案（写下一份必须对照全部，不只看最近一份；假收口方案已剔除）"
        if facts.claim_unverified else
        "## 已给过的方案（写下一份必须对照全部，不只看最近一份）"
    )
    if not evo_block:
        evo_block = _evo_tactics_block(facts.evo_do, facts.evo_avoid)
    parts = [
        f"# 监督简报 · 第 {turn} 轮之后",
        f"目标：{_goal_line(objective)}",
        f"作业对象：{hosts}",
        f"当前入口：{facts.current_entry or entry or '（未填）'}。邻题入口见局面摘要，禁止当本题主线；本题入口端口不通则 rebind，不要改打邻题端口。",
        "",
        "## 题目要点",
        _clip((brief or "").strip(), brief_clip) or "（无）",
        "",
        "## 局面摘要",
        _facts_block(facts),
        "",
    ]
    try:
        from ..config import settings as _st
        from .spiral import format_coverage_brief, load_ledger, scan_ban_repeats
        ws = Path(_st.workspaces_dir) / project_id
        ledger = load_ledger(ws)
        cov = format_coverage_brief(ledger, objective=objective)
        parts.extend(["## 已覆盖（螺旋账本）", cov, ""])
        from ..objective import objective_allows_flag
        if objective_allows_flag(objective):
            for b in scan_ban_repeats(ledger, objective=objective):
                if b and b not in facts.repeats:
                    facts.repeats.append(b)
    except Exception:
        pass
    if evo_block:
        parts.extend([evo_block, ""])
    parts.extend([
        hist_title,
        _own_plans_block(facts.prior_plans, compact=compact),
        "",
        "## 攻击图（与控制台图例相同）",
        _graph_block(
            graph, compact=compact, peer_entries=facts.peer_entries,
            current_entry=str(facts.current_entry or ""),
            claim_unverified=bool(facts.claim_unverified),
            invert_ops=bool(facts.invert_ops),
            objective=objective,
        ),
        "",
        "## 开放 Intent",
        _intents_block(open_intents or [], limit=intent_limit),
        "",
        "## 已夺 flag",
        await _flags_block(project_id),
    ])
    text = "\n".join(parts)
    if len(text) > budget:
        text = text[: budget - 1] + "…"
    return text
