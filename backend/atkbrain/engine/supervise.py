"""Loop 监督：把攻击图交给 Claude Code，方案只来自御主模型。

每轮从者开打前先问御主（与红队/SRC 同一套门闩）。
入口传输层失败整段跳过，不当方法失败去换路。需要开口时在总墙钟内问 Claude Code，
直到给出方案或超时；不注入机械换路模板。
"""
from __future__ import annotations

import asyncio
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..config import settings
from ..db import db
from ..events import emit
from ..graph import store as gstore
from ..graph.hypothesize import (
    LIVE_SURFACE_TACTICS,
    graph_has_unmounted_secret,
    live_gadget_tactics,
    needs_channel_oracle,
    node_is_non_exploit_crash,
    plan_blocks_live_surface,
    surfaces_from_graph_nodes,
)
from ..graph.verify import is_non_exploit_finding_category
from .advisor_bind import (
    AdvisorBinding,
    CLOSEOUT_OVERRIDE,
    GADGET_KEEP,
    binding_compliance,
    closeout_sidetrack_tactics,
    compile_binding,
    format_binding_block,
    in_flight_blocks_new_direction,
    intent_tactic,
    oracle_blocks_closeout,
    protected_tactics,
    should_force_chain_close_review,
    should_force_oracle_review,
    should_refresh_stale_binding,
    starves_chain_close,
    tighten_binding,
)
from .advisor_schedule import should_review_advisor
from .ai_supervisor import (
    SupervisorPlan,
    await_supervisor_plan,
    consult_supervisor,
    format_ai_steer,
    graph_has_login_or_surface,
    supervisor_system_prompt,
    plan_is_entry_enum,
    plan_is_fake_key_loop,
    plan_is_usable,
    refine_supervisor_plan,
)
from .supervisor_brief import (
    SupervisorFacts,
    assemble_supervisor_brief,
    claimed_secret_disproved,
    flag_submission_stats,
    plan_cites_peer_entry,
    plan_claims_obtained_secret,
)

_SKIP_TEXT = {
    "empty_turn": "本回合无工具/有效输出，疑似会话已死，未问御主（避免空转连发）。",
    "hang": "本回合超时已打断，未问御主。",
    "exec_fault": "本轮会话故障，未问御主。",
    "interrupted": "本轮从者未跑完或御主未落盘（后端重启/取消），未注入新方案。",
    "cooldown": "距上一份方案过近，本轮沿用，未再问御主。",
    "fail_cooldown": "御主刚失败，本轮暂不问。",
    "error": "御主异常，本轮未注入方案。",
    "plan_hold": "当前方案尚未验证完，本轮继续执行，不更换方案。",
    "progress": "从者仍在推进当前方案，本轮未问御主。",
    "skip": "本轮御主未改方向。",
    "in_flight": "本轮认领的 Intent 仍开放，验证尚未结束，御主强制 noop。",
    "hold_course": "刚注入过指令，再给几轮把当前验证做完，御主强制 noop。",
    "infra": "入口传输层失败，御主整段跳过，不当方法失败去换路。",
    "let_commander": "从者尚未连着空转满暂停阈值，先让从者打。",
    "binding_ignored": "上一步未执行御主绑定，收紧约束后重注，不开新方案。",
    "binding_empty": "本轮无工具，御主绑定沿用，不开新方案。",
}

_KEEP_PLAN_QUALITY = frozenset({"flag", "finding", "capability_edge", "valuable_node"})
_MOVING_QUALITY = _KEEP_PLAN_QUALITY | frozenset({"weak_graph", "info_node"})


def should_hold_active_plan(
    *,
    has_active_plan: bool,
    exec_turns: int,
    dwell_turns: int = 2,
    quality: str = "none",
    infra: bool = False,
    peer_contaminated: bool = False,
    claim_unverified: bool = False,
    enum_vs_surface: bool = False,
    fake_key_loop: bool = False,
    graph_stalled: bool = False,
    login_vs_enum: bool = False,
) -> bool:
    """当前方案还没经过足够的有工具回合、且没有纠偏信号时，继续执行该方案。

    泛化：不看题型。入口已死、方案引用了邻题入口、凭据假设已被否证、
    假钥匙意图、图停滞、已登录还在入口枚举、或活体表面仍在而方案还在目录枚举
    才允许提前更换。验证发现 / flag 不算更换信号——方案仍在推进。
    dwell_turns<=0 关闭这项等待。
    """
    if not has_active_plan:
        return False
    if infra or peer_contaminated or claim_unverified or enum_vs_surface:
        return False
    if fake_key_loop or graph_stalled or login_vs_enum:
        return False
    try:
        dwell = int(dwell_turns or 0)
    except (TypeError, ValueError):
        dwell = 2
    if dwell <= 0:
        return False
    try:
        ran = int(exec_turns or 0)
    except (TypeError, ValueError):
        ran = 0
    return ran < dwell


def should_consult_supervisor(
    *,
    has_active_plan: bool,
    no_progress: int = 0,
    stall_after: int = 2,
    quality: str = "none",
    infra: bool = False,
    peer_contaminated: bool = False,
    claim_unverified: bool = False,
    enum_vs_surface: bool = False,
    fake_key_loop: bool = False,
    graph_stalled: bool = False,
    login_vs_enum: bool = False,
) -> bool:
    """卡住或纠偏才问顾问。有方案且仍在推进时沿用，不问。

    stall_after<=0：关掉卡住门槛，满 dwell 后每轮都问（旧行为）。
    """
    if infra or peer_contaminated or claim_unverified or enum_vs_surface:
        return True
    if fake_key_loop or graph_stalled or login_vs_enum:
        return True
    if not has_active_plan:
        return True
    try:
        need = int(stall_after if stall_after is not None else 2)
    except (TypeError, ValueError):
        need = 2
    if need <= 0:
        return True
    if (quality or "none") in _MOVING_QUALITY:
        return False
    try:
        n = int(no_progress or 0)
    except (TypeError, ValueError):
        n = 0
    return n >= need


async def has_injected_supervisor_plan(project_id: str) -> bool:
    """是否已经有过真正的监督方案（skip/error 不算启动）。"""
    if not project_id:
        return False
    try:
        rows = await db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (project_id,),
        )
    except Exception:
        return False
    for r in rows:
        try:
            p = json.loads(r["payload"] or "{}") if isinstance(r.get("payload"), str) else (r.get("payload") or {})
        except Exception:
            continue
        if str(p.get("kind") or "plan") in ("plan", "hold"):
            return True
    return False


def should_consult_after_exec_fault(*, reason: str, has_active_plan: bool) -> bool:
    """御主本轮没正常收口时，是否仍要问监督。

    超时打断：图上往往已有本轮写入，必须问。
    空回合：还没有任何方案时要问，避免挂死后续跑永远 skip；已有方案则跳过。
    """
    r = str(reason or "")
    if r == "hang":
        # 无活动卡死：下一轮立刻重开会话，不要再占一路顾问打满 API。
        return False
    if r == "empty_turn":
        return not bool(has_active_plan)
    return False


async def load_supervised_turns(project_id: str) -> set[int]:
    """本项目已有监督记录的轮次（plan/error/empty/skip 都算写过）。"""
    if not project_id:
        return set()
    try:
        rows = await db.fetchall(
            "SELECT payload FROM events WHERE project_id=? AND type='supervisor'",
            (project_id,),
        )
    except Exception:
        return set()
    out: set[int] = set()
    for r in rows:
        try:
            p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
            t = int(p.get("turn") or 0)
        except Exception:
            continue
        if t > 0:
            out.add(t)
    return out

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_PATH_RE = re.compile(r"(?:^|[\s'\"])(/[A-Za-z0-9_\-./%]{2,80})")
_EXEC_FAULT_RE = re.compile(
    r"(exit code:\s*143|terminated process|Command failed with exit code 143|"
    r"tool use was rejected|Async agent|session.*dead|Cannot write to terminated|"
    r"exceeded maximum buffer size|Failed to decode JSON|CLIJSONDecodeError|"
    r"JSON message exceeded|Control request timeout)",
    re.I,
)

# 策略族轮转顺序（硬换路时推进）
_STRATEGY_FAMILIES = [
    "fingerprint", "auth_surface", "content_enum", "web_inject",
    "input_abuse", "access_control", "upload_bypass", "file_read_chain",
    "weaponize", "auth_reuse", "priv_enum", "flag_hunt", "privesc_lateral",
    "protocol_model", "reverse_binary",
]

# 两次换路之间的最小间隔（秒）。空回合/会话故障时防止每轮连发把时间线打爆。
_PIVOT_COOLDOWN_SEC = 30.0
# 监督失败后的冷却：超时后同轮再试一次（拥堵）；两次都失败才冷却。
_FAIL_COOLDOWN_SEC = 45.0
# 入口不可达：重绑/提示冷却。比方法换路略长，避免每轮 ensure 打满平台槽。
_INFRA_COOLDOWN_SEC = 45.0
_INFRA_WINDOW = 10
_INFRA_MIN_FAILS = 3

# 已验证漏洞/凭证之后的下一跳——硬换路不得把这些族当「死磕入口」封掉。
_CHAIN_CONTINUE = frozenset({
    "weaponize", "auth_reuse", "hop_auth", "access_control", "svc_auth_bruteforce",
    "priv_enum", "flag_hunt",
    "file_read_chain", "privesc_lateral", "info_to_cred", "info_to_danger",
    "input_abuse", "ssrf_as_gateway", "ssrf_local_svc", "secret_mount",
    "read_to_creds", "finding_read_loot", "finding_rce_close",
    "impact_escalate", "finding_authz_expand", "channel_oracle",
    "protocol_model", "reverse_binary", "filter_bypass", "restricted_deserialize",
}) | LIVE_SURFACE_TACTICS

# 已有已验证资产时，每轮前沿应优先这些（不要再把 captcha/目录枚举排到前面）。
CHAIN_NEXT = frozenset({
    "weaponize", "auth_reuse", "hop_auth", "access_control", "svc_auth_bruteforce",
    "priv_enum", "flag_hunt",
    "privesc_lateral", "read_to_creds", "finding_read_loot",
    "finding_sqli_chain", "finding_rce_close", "finding_authz_expand",
    "ssrf_as_gateway", "ssrf_local_svc", "secret_mount",
    "impact_escalate", "channel_oracle", "file_read_chain",
    "protocol_model", "reverse_binary", "filter_bypass", "restricted_deserialize",
}) | LIVE_SURFACE_TACTICS

_TAG_TO_FINDING_CAT = {
    "sqli": "sqli", "sql-injection": "sqli", "sql注入": "sqli",
    "db_access": "db_access",
    "ssrf": "ssrf", "ssrf_internal": "ssrf",
    "deserial": "deserialization", "deserialization": "deserialization",
    "unserialize": "deserialization", "pickle": "deserialization",
    "file_write": "file_write", "file-write": "file_write",
    "file_read": "file_read", "lfi": "file_read",
    "rce": "rce", "command_injection": "rce",
    "ssti": "ssti", "file_upload": "file_upload",
    "jwt": "token", "jws": "token", "jwe": "token",
    "hs256": "token", "rs256": "token", "es256": "token",
    "auth_bypass": "auth_bypass", "authz": "authz",
}


def verified_finding_categories(graph: dict | None) -> frozenset[str]:
    """已验证 finding / vuln 的类别，供收口偏置。不含登录面噪声。"""
    out: set[str] = set()
    if not graph:
        return frozenset()
    for f in graph.get("findings") or []:
        vs = str(f.get("verification_status") or "").lower()
        if vs not in ("verified", "flaky"):
            continue
        cat = str(f.get("category") or "").strip().lower()
        if not cat or cat in _SURFACE_FINDING_CATS or is_non_exploit_finding_category(cat):
            continue
        mapped = _TAG_TO_FINDING_CAT.get(cat, cat)
        if is_non_exploit_finding_category(mapped):
            continue
        out.add(mapped)
    for n in graph.get("nodes") or []:
        if n.get("type") != "vuln":
            continue
        tags = _node_tagset(n)
        vs = str(n.get("verification_status") or "").lower()
        if "verified" not in tags and vs not in ("verified", "flaky"):
            continue
        if node_is_non_exploit_crash(n):
            continue
        for t in tags:
            mapped = _TAG_TO_FINDING_CAT.get(str(t).lower())
            if mapped:
                out.add(mapped)
        title = (
            f"{n.get('title') or ''} {n.get('key') or ''} "
            f"{str(n.get('detail') or '')[:200]}"
        ).lower()
        for tok, cat in _TAG_TO_FINDING_CAT.items():
            if tok in title:
                out.add(cat)
    return frozenset(out)


def chain_next_tactics(verified_cats=None) -> frozenset[str]:
    """已验证资产时的前沿优先族：去掉校准/契约空转。"""
    return frozenset(CHAIN_NEXT - closeout_sidetrack_tactics(verified_cats))

_TRANSPORT_FAIL_RE = re.compile(
    r"(timed?\s*out|timeout|connection refused|connection reset|"
    r"name or service not known|could not resolve|no route to host|"
    r"network is unreachable|network unreachable|code=000|http_code=000|"
    r"curl:\s*\(6\)|curl:\s*\(7\)|curl:\s*\(28\)|"
    r"failed to connect|empty reply from server|operation timed out|"
    r"\b(?:still\s+)?down\b|仍\s*down)",
    re.I,
)
_APP_LAYER_RE = re.compile(
    r"(HTTP/\d\.\d\s+[1-5]\d\d|status['\":\s]+[1-5]\d\d|"
    r"探测成功|访问被阻止|禁止访问|"
    r"Set-Cookie|<!DOCTYPE|<html)",
    re.I,
)
_NOISE_REPEAT_RE = re.compile(
    r"(^cmd:cd\s|/workspaces/|^/tmp/.*\.(log|sh|txt|json)$|^/dev/null$|"
    r"^cmd:for\s|^cmd:timeout\s)",
    re.I,
)


def _payload_blob(payload: dict | None) -> str:
    p = payload or {}
    parts = [
        str(p.get("tool") or ""),
        str(p.get("url") or ""),
        str(p.get("error") or ""),
        str(p.get("command") or ""),
        str(p.get("preview") or "")[:500],
        str(p.get("input") or "")[:300],
        str(p.get("message") or ""),
        str(p.get("status") if p.get("status") is not None else ""),
    ]
    return " ".join(parts)


def infra_from_probes(
    probes: list[str] | None,
    *,
    has_verified_asset: bool = False,
    entry_tcp_alive: bool | None = None,
) -> bool:
    """传输层窗口是否表示入口挂了。已验证能力、窗口内出现过业务层、或入口 TCP 仍通 → 不是 infra。"""
    if has_verified_asset:
        return False
    if entry_tcp_alive:
        return False
    kinds = [str(k) for k in (probes or []) if k]
    if len(kinds) < _INFRA_MIN_FAILS:
        return False
    if "app" in kinds:
        return False
    fails = sum(1 for k in kinds if k == "transport")
    return fails >= _INFRA_MIN_FAILS


async def _scope_tcp_alive(hosts: set[str] | None, *, timeout: float = 0.6) -> bool:
    """入口主机 TCP 仍通：短超时窗口不是传输层死亡。"""
    targets: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for raw in list(hosts or ())[:3]:
        host = str(raw or "").strip().lower().split("/")[0]
        port = 80
        if ":" in host:
            h, _, p = host.rpartition(":")
            if h and p.isdigit():
                host, port = h, int(p)
        if not host or (host, port) in seen:
            continue
        seen.add((host, port))
        targets.append((host, port))

    async def _one(host: str, port: int) -> bool:
        try:
            conn = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

    if not targets:
        return False
    hits = await asyncio.gather(*[_one(h, p) for h, p in targets], return_exceptions=True)
    return any(x is True for x in hits)


def classify_probe_payload(payload: dict | None) -> str:
    """把一次工具结果分成 transport / app / ignore。

    泛化：不看题型。目标返回了 HTTP 业务层（含 403/被拦）算入口还活着；
    超时/拒绝/DNS/code=000 才算入口不可达。
    """
    p = payload or {}
    tool = str(p.get("tool") or "")
    status = p.get("status")
    err = str(p.get("error") or "")
    blob = _payload_blob(p) + " " + err
    if re.search(r"攻击机不可路由|须经已验证 SSRF|ssrf_gateway|不要 http_request 直连", blob, re.I):
        return "ignore"
    if isinstance(status, int) and status > 0:
        return "app"
    if status in (0, "0", "000"):
        return "transport"
    if tool == "http_request":
        if err or status in (None, 0, "0"):
            return "transport"
        return "ignore"
    if re.search(r"HTTP/\d\.\d\s+[1-5]\d\d|status['\":\s]+[1-5]\d\d|探测成功", blob, re.I):
        return "app"
    # 「探测失败」只有带着 HTTP 正文/拦截页才算入口还活着（WAF）；光失败走 transport
    if re.search(r"探测失败", blob, re.I) and re.search(
        r"HTTP/\d|status['\":\s]+[1-5]\d\d|访问被阻止", blob, re.I,
    ):
        return "app"
    if _APP_LAYER_RE.search(blob) and not _TRANSPORT_FAIL_RE.search(blob):
        return "app"
    if _TRANSPORT_FAIL_RE.search(blob):
        if re.search(r"\btimeout\s+\d+", blob) and not re.search(
            r"curl:\s*\(|connection refused|timed out after|code=000|"
            r"\b(?:still\s+)?down\b|仍\s*down", blob, re.I
        ):
            return "ignore"
        return "transport"
    return "ignore"


def extract_scope_hosts(graph: dict | None, extra: list[str] | None = None) -> set[str]:
    hosts: set[str] = set()
    for h in extra or []:
        h = (h or "").strip().lower().split("/")[0].split(":")[0]
        if h:
            hosts.add(h)
    for n in (graph or {}).get("nodes") or []:
        if n.get("type") not in ("target", "service"):
            continue
        key = str(n.get("key") or "")
        title = str(n.get("title") or "")
        for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", key + " " + title):
            hosts.add(m)
        if key.startswith("target:") and "/" not in key[7:]:
            hosts.add(key[7:].split(":")[0].lower())
    return {h for h in hosts if h and h not in ("localhost", "127.0.0.1")}


def event_touches_scope(blob: str, hosts: set[str]) -> bool:
    if not hosts:
        return True
    low = (blob or "").lower()
    return any(h.lower() in low for h in hosts)


# 只说明「发现了面」，不能当已打穿：误把它们当 chain 会禁止过登录门。
_SURFACE_FINDING_CATS = frozenset({
    "admin_access", "info", "fingerprint", "recon", "open_redirect",
})


def _node_tagset(n: dict) -> set[str]:
    tags = n.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    return {str(t).lower() for t in tags}


def _confirmed_control(n: dict) -> bool:
    """已拿到命令执行的立足点/goal。未落地的 foothold（进行中、无 is_rce）不算资产。"""
    ntype = n.get("type")
    key = str(n.get("key") or "")
    tags = _node_tagset(n)
    if ntype == "goal" and (n.get("is_rce") or key.startswith("goal:shell") or "getshell" in tags):
        return True
    if ntype == "foothold":
        return bool(n.get("is_rce") or "getshell" in tags)
    return False


def has_verified_asset(graph: dict | None) -> bool:
    """是否已有「能接着打」的资产：已验证漏洞、凭证、已控立足点。

    未验证的高危假设、仅发现登录面、未落地的 foothold，不算。
    """
    if not graph:
        return False
    for n in graph.get("nodes") or []:
        ntype = n.get("type")
        tags = _node_tagset(n)
        verified = "verified" in tags
        if _confirmed_control(n):
            return True
        if ntype == "credential" and (
            verified or n.get("severity") in ("high", "critical")
        ):
            return True
        if ntype == "vuln" and verified:
            if node_is_non_exploit_crash(n):
                continue
            return True
    for f in graph.get("findings") or []:
        vs = str(f.get("verification_status") or "").lower()
        if vs != "verified":
            continue
        cat = str(f.get("category") or "").lower()
        if cat in _SURFACE_FINDING_CATS or is_non_exploit_finding_category(cat):
            continue
        if f.get("severity") in ("high", "critical", "medium") or f.get("critical"):
            return True
    return False


def verified_chain_paths(graph: dict | None) -> set[str]:
    """已验证节点里出现过的 URL path，换路时不得当「重复」封禁。"""
    paths: set[str] = set()
    if not graph:
        return paths
    blobs: list[str] = []
    for n in graph.get("nodes") or []:
        if n.get("type") not in ("vuln", "credential", "foothold", "service", "info"):
            continue
        tags = n.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        if n.get("type") in ("info", "service") and "verified" not in {str(t).lower() for t in tags}:
            if n.get("severity") not in ("high", "critical"):
                continue
        detail = n.get("detail")
        if isinstance(detail, dict):
            detail = " ".join(str(v) for v in detail.values())
        blobs.append(f"{n.get('key','')} {n.get('title','')} {detail or ''}")
    for f in graph.get("findings") or []:
        blobs.append(f"{f.get('title','')} {f.get('description','')} {f.get('evidence','')}")
    for blob in blobs:
        for m in _PATH_RE.findall(" " + blob):
            if 2 <= len(m) <= 80 and not m.startswith("//"):
                paths.add(m.rstrip(".,;"))
    return paths


def graph_has_getshell(graph: dict | None) -> bool:
    """图上是否已有 ★GETSHELL（已拿到命令执行的立足点/goal）。"""
    if not graph:
        return False
    return any(_confirmed_control(n) for n in (graph.get("nodes") or []))


def is_noise_repeat(token: str) -> bool:
    t = (token or "").strip()
    if not t:
        return True
    if _NOISE_REPEAT_RE.search(t):
        return True
    if t.startswith("/home/") and "workspaces" in t:
        return True
    if t.startswith("/home/kali"):
        return True
    if "atkbrain.db" in t.lower():
        return True
    return False


def intent_tactic(intent: dict | None) -> str:
    sk = str((intent or {}).get("strategy_key") or "")
    return sk.split("::")[-1] if "::" in sk else sk


def _internal_graph_hosts(graph: dict | None) -> set[str]:
    """图上已出现的内网/容器网主机（target: 与 scope-expanded），不含入口同 /24。"""
    if not graph:
        return set()
    import ipaddress
    from ..scope import _IP_RE, _norm_host, is_loopback, is_private

    tagged: set[str] = set()
    for n in graph.get("nodes") or []:
        key = str(n.get("key") or "")
        h = ""
        if key.startswith("info:scope-expanded:"):
            h = key.split(":", 2)[-1]
        elif key.startswith("info:host:"):
            h = key.split(":", 2)[-1]
        elif key.startswith("target:"):
            h = key.split(":", 1)[-1]
        h = _norm_host(h)
        if h and _IP_RE.match(h) and is_private(h) and not is_loopback(h):
            tagged.add(h)
    if not tagged:
        return set()
    entry_nets: list = []
    for h in tagged:
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        if ip.version != 4:
            continue
        # 入口候选：非 docker 172.16/12 的私网 IP（常见 10.x）
        if ip in ipaddress.ip_network("172.16.0.0/12"):
            continue
        entry_nets.append(ipaddress.ip_network(f"{ip}/24", strict=False))
        break
    out: set[str] = set()
    for h in tagged:
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            continue
        if any(ip in net for net in entry_nets):
            continue
        out.add(h)
    return out


def _postex_stalled(graph: dict | None) -> bool:
    """已拿到立足点/shell，却还没有横向能力边——或图上已有内网主机却没 PIVOTS_TO。"""
    if not graph:
        return False
    nodes = graph.get("nodes") or []
    stats = graph.get("stats") or {}
    has_foot = bool(stats.get("has_shell")) or any(
        (n.get("type") == "foothold") or (n.get("type") == "goal" and n.get("is_rce"))
        for n in nodes
    )
    if not has_foot:
        return False
    edges = graph.get("edges") or []
    has_pivot = any(e.get("relation") == "PIVOTS_TO" for e in edges)
    has_esc = any(e.get("relation") == "ESCALATES_TO" for e in edges)
    if _internal_graph_hosts(graph) and not has_pivot:
        return True
    return not (has_esc or has_pivot)


@dataclass
class LoopSupervisor:
    project_id: str
    run_id: str
    objective: str = "flag"
    no_progress: int = 0
    pivots: int = 0
    last_sig: tuple = (-1, -1, -1, -1)  # nodes, edges, findings, flags
    banned: list[str] = field(default_factory=list)
    banned_strategies: list[str] = field(default_factory=list)
    pending_steer: str | None = None
    force_reset: bool = False
    family_index: int = 0
    exec_faults: int = 0
    last_quality: str = "none"
    assigned_intent_ids: list[str] = field(default_factory=list)
    last_pivot_ts: float = 0.0
    soft_fired: bool = False  # 本轮空转窗口内软转向是否已发过（边沿触发）
    stall_class: str = "none"  # none | infra | method | chain
    want_rebind: bool = False  # 入口不可达：循环侧尝试重绑可重建目标
    infra_streak: int = 0
    rebind_same_addr: int = 0
    last_entry_addr: str = ""
    entry_identity_mismatch: bool = False
    last_identity_sig: str = ""
    halt_env: str | None = None
    env_closed_hits: int = 0
    prefer_tactics: list[str] = field(default_factory=list)
    last_diagnosis: str = ""
    last_plan_text: str = ""
    last_plan_outcome: str = ""
    plan_history: list[dict] = field(default_factory=list)
    last_fail_ts: float = 0.0
    active_steer: str | None = None
    plan_exec_turns: int = 0
    last_steer_turn: int | None = None
    claimed_ids: list[str] = field(default_factory=list)
    binding: AdvisorBinding | None = None
    force_bundle_review: bool = False


    def note_progress(self, *, nodes: int, edges: int, findings: int, flags: int, quality: str = "none") -> bool:
        """有高质量进展则清零空转；弱图扩张只减缓计数。首轮无高质量进展也计入空转。"""
        sig = (nodes, edges, findings, flags)
        self.last_quality = quality
        first = self.last_sig == (-1, -1, -1, -1)
        if quality in ("flag", "finding", "capability_edge"):
            self.last_sig = sig
            self.no_progress = 0
            self.exec_faults = 0
            self.soft_fired = False
            return True
        if first:
            self.last_sig = sig
            if quality == "valuable_node":
                return False
            self.no_progress += 1
            return False
        if quality == "valuable_node":
            self.last_sig = sig
            self.no_progress = max(0, self.no_progress - 1)
            return False
        if quality == "weak_graph" or nodes > self.last_sig[0] or edges > self.last_sig[1]:
            # 低价值 info 刷图不算真进展
            self.last_sig = sig
            self.no_progress += 1
            return False
        self.no_progress += 1
        return False

    def note_exec_fault(self, message: str) -> bool:
        """会话/SDK/工具拒绝类故障：不计为漏洞分支失败。"""
        if not message or not _EXEC_FAULT_RE.search(message):
            return False
        self.exec_faults += 1
        return True

    async def _recent_repeats(self, limit: int = 80, *, protected: set[str] | None = None) -> list[str]:
        rows = await db.fetchall(
            "SELECT type, payload FROM events WHERE project_id=? AND run_id=? ORDER BY id DESC LIMIT ?",
            (self.project_id, self.run_id, limit),
        )
        bag: Counter[str] = Counter()
        protected = protected or set()
        for r in rows:
            try:
                p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
            except Exception:
                continue
            texts = [
                str(p.get("command") or ""),
                str(p.get("url") or ""),
                str(p.get("preview") or "")[:200],
                str(p.get("input") or "")[:200],
            ]
            blob = " ".join(texts)
            for u in _URL_RE.findall(blob):
                # 命令源码里常出现伪 URL（如 http://([^:]+):(\\d+)），urlsplit 会抛 Invalid IPv6 URL
                try:
                    path = urlsplit(u).path or "/"
                except ValueError:
                    continue
                if len(path) > 1:
                    bag[path] += 1
            for m in _PATH_RE.findall(blob):
                if not m.startswith("//"):
                    bag[m] += 1
            cmd = str(p.get("command") or "")
            if cmd:
                head = " ".join(cmd.strip().split()[:3])[:80]
                if head:
                    bag[f"cmd:{head}"] += 1
        out: list[str] = []
        for k, v in bag.most_common(16):
            if v < 3:
                continue
            if is_noise_repeat(k):
                continue
            if k in protected or any(k.startswith(p) or p.startswith(k) for p in protected if len(p) > 2):
                continue
            out.append(k)
            if len(out) >= 12:
                break
        return out

    async def _detect_infra(self, graph: dict | None, scope_hosts: list[str] | None) -> bool:
        if has_verified_asset(graph):
            return False
        hosts = extract_scope_hosts(graph, scope_hosts)
        rows = await db.fetchall(
            "SELECT type, payload FROM events WHERE project_id=? AND run_id=? "
            "AND type IN ('tool_result','log') ORDER BY id DESC LIMIT ?",
            (self.project_id, self.run_id, 40),
        )
        probes: list[str] = []
        ignored = 0
        for r in rows:
            try:
                p = json.loads(r["payload"] or "{}") if isinstance(r["payload"], str) else (r["payload"] or {})
            except Exception:
                continue
            blob = _payload_blob(p)
            if r["type"] == "log" and not event_touches_scope(blob, hosts):
                continue
            if r["type"] == "tool_result" and hosts and not event_touches_scope(blob, hosts):
                continue
            kind = classify_probe_payload(p)
            if kind == "ignore":
                ignored += 1
                continue
            probes.append(kind)
            if len(probes) >= _INFRA_WINDOW:
                break
        if not infra_from_probes(probes):
            return False
        tcp_ok = False
        try:
            tcp_ok = await _scope_tcp_alive(hosts)
        except Exception:
            tcp_ok = False
        return infra_from_probes(probes, entry_tcp_alive=tcp_ok)

    def _prefer_chain_frontier(self, frontier: list[dict]) -> list[dict]:
        chain = [it for it in frontier if intent_tactic(it) in _CHAIN_CONTINUE]
        pool = chain or list(frontier)

        def _rank(it: dict) -> int:
            t = intent_tactic(it)
            if t in ("secret_mount", "hop_auth", "access_control", "svc_auth_bruteforce"):
                return 0
            if t in _CHAIN_CONTINUE:
                return 1
            return 2

        return sorted(pool, key=_rank)

    def _refresh_stall_class(self, *, chain_live: bool, graph: dict | None, quality: str = "none") -> None:
        """本地空转分类：软阈值打成 method/chain，供调度门闩使用。"""
        if self.stall_class == "infra":
            return
        if (quality or "none") in ("flag", "finding", "capability_edge"):
            self.stall_class = "none"
            return
        soft = max(1, int(getattr(settings, "loop_supervise_soft_turns", 3) or 3))
        if int(self.no_progress or 0) < soft:
            return
        if chain_live or _postex_stalled(graph):
            self.stall_class = "chain"
        else:
            self.stall_class = "method"

    def _binding_graph_flags(
        self, graph: dict | None, *, correct_flags: int = 0, flag_count: int = 0,
    ) -> dict:
        from ..objective import objective_allows_flag
        has_foot = graph_has_getshell(graph)
        hops = bool(_internal_graph_hosts(graph))
        remaining = False
        if objective_allows_flag(self.objective):
            if int(flag_count or 0) > 0:
                remaining = int(correct_flags or 0) < int(flag_count)
            else:
                remaining = bool(has_foot and hops)
        cats = verified_finding_categories(graph)
        return {
            "has_foothold": has_foot,
            "remaining_goals": remaining,
            "has_verified_asset": has_verified_asset(graph) and not self.entry_identity_mismatch,
            "has_internal_hops": hops,
            "verified_categories": sorted(cats),
            "has_live_gadget": bool(live_gadget_tactics(graph)),
            "needs_channel_oracle": bool(needs_channel_oracle(graph)),
        }

    def _protected_now(self, graph: dict | None, *, remaining_goals: bool | None = None) -> frozenset[str]:
        has_foot = graph_has_getshell(graph)
        remaining = True if remaining_goals is None and has_foot else bool(remaining_goals)
        return protected_tactics(
            has_foothold=has_foot,
            remaining_goals=remaining,
            has_verified_asset=has_verified_asset(graph) and not self.entry_identity_mismatch,
            verified_categories=verified_finding_categories(graph),
            has_live_gadget=bool(live_gadget_tactics(graph)),
        )

    def _install_binding(
        self, binding: AdvisorBinding, *, plan: SupervisorPlan, extra: str = "",
        record_history: bool = True,
    ) -> None:
        self.binding = binding
        self.assigned_intent_ids = list(binding.must_intents[:3])
        self.prefer_tactics = list(binding.prefer_tactics[:8])
        for fam in list(binding.deny_tactics):
            if fam and fam not in self.banned_strategies:
                self.banned_strategies.append(fam)
        self.banned_strategies = self.banned_strategies[-20:]
        self.last_diagnosis = binding.diagnosis or plan.diagnosis
        self.last_plan_text = binding.next_plan or plan.next_plan
        # 御主看到的 prefer/deny 必须是编译后的绑定，不能漏出 LLM 原文里的 oracle。
        plan.diagnosis = binding.diagnosis or plan.diagnosis
        plan.next_plan = binding.next_plan or plan.next_plan
        plan.must_intents = list(binding.must_intents)
        plan.prefer_tactics = list(binding.prefer_tactics)
        plan.defer_families = list(binding.deny_tactics)
        plan.ban_repeats = list(binding.ban_repeats)
        plan.subagents = list(binding.subagents)
        if binding.stall in ("none", "infra", "method", "chain", "postex"):
            plan.stall = binding.stall
        steer = format_ai_steer(plan, pivots=self.pivots, extra_guide=extra)
        block = format_binding_block(binding)
        if block and block not in steer:
            steer = steer + "\n" + block
        self.active_steer = steer
        self.pending_steer = steer
        if binding.stall in ("none", "infra", "method", "chain", "postex"):
            self.stall_class = binding.stall
        if record_history:
            rec = {
                "pivot": self.pivots,
                "diagnosis": binding.diagnosis,
                "next_plan": binding.next_plan,
                "must_intents": list(binding.must_intents),
                "prefer_tactics": list(binding.prefer_tactics),
                "deny_tactics": list(binding.deny_tactics),
                "outcome": "",
            }
            prev = self.plan_history[-1] if self.plan_history else None
            if not prev or (prev.get("next_plan") or "") != (rec.get("next_plan") or ""):
                self.plan_history.append(rec)
                self.plan_history = self.plan_history[-8:]
        self.last_plan_outcome = ""

    def _stamp_history_outcome(self, *, turn: int = 0) -> None:
        if not self.plan_history or not self.last_plan_outcome:
            return
        rec = dict(self.plan_history[-1])
        rec["outcome"] = self.last_plan_outcome
        if turn:
            rec["turn"] = int(turn or 0)
        self.plan_history[-1] = rec

    def _reapply_binding(self, *, turn: int) -> None:
        if not self.binding:
            return
        plan = SupervisorPlan(
            diagnosis=self.binding.diagnosis,
            stall=self.binding.stall,
            next_plan=self.binding.next_plan,
            must_intents=list(self.binding.must_intents),
            prefer_tactics=list(self.binding.prefer_tactics),
            defer_families=list(self.binding.deny_tactics),
            ban_repeats=list(self.binding.ban_repeats),
            subagents=list(self.binding.subagents),
        )
        self._install_binding(self.binding, plan=plan, record_history=False)
        self.last_steer_turn = int(turn or 0)
        self.plan_exec_turns = 0
        if self.plan_history:
            rec = dict(self.plan_history[-1])
            rec["next_plan"] = self.binding.next_plan
            rec["deny_tactics"] = list(self.binding.deny_tactics)
            rec["must_intents"] = list(self.binding.must_intents)
            if self.last_plan_outcome:
                rec["outcome"] = self.last_plan_outcome
            self.plan_history[-1] = rec

    def _apply_plan(self, plan: SupervisorPlan, *, repeats: list[str], invert_ops: bool = False, postex_pivot: bool = False, open_intents: list | None = None, bind_flags: dict | None = None) -> None:
        extra_parts: list[str] = []
        if invert_ops:
            from .supervisor_brief import INVERT_OPS_GUIDE, sanitize_invert_ops_plan
            sanitize_invert_ops_plan(plan, invert_ops=True)
            extra_parts.append(INVERT_OPS_GUIDE)
        if postex_pivot:
            from .supervisor_brief import POSTEX_PIVOT_GUIDE
            extra_parts.append(POSTEX_PIVOT_GUIDE)
        flags = bind_flags or {}
        cats = flags.get("verified_categories")
        oracle_open = bool(flags.get("needs_channel_oracle"))
        skip_close_guide = oracle_blocks_closeout(
            needs_channel_oracle=oracle_open,
            has_verified_asset=bool(flags.get("has_verified_asset")),
            verified_categories=cats,
        )
        if (
            bool(flags.get("has_verified_asset"))
            and not bool(flags.get("has_foothold"))
            and not skip_close_guide
        ):
            from .supervisor_brief import CHAIN_CLOSE_GUIDE
            extra_parts.append(CHAIN_CLOSE_GUIDE)
        extra = "\n".join(extra_parts)
        self.stall_class = plan.stall if plan.stall in ("none", "infra", "method", "chain", "postex") else "none"
        self.want_rebind = bool(plan.rebind_entry)
        self.force_reset = False
        raw_blob = f"{getattr(plan, 'diagnosis', '') or ''} {getattr(plan, 'next_plan', '') or ''}"
        binding = compile_binding(
            plan,
            open_intents=open_intents,
            repeats=repeats,
            has_foothold=bool(flags.get("has_foothold")),
            remaining_goals=bool(flags.get("remaining_goals")),
            has_verified_asset=bool(flags.get("has_verified_asset")),
            has_internal_hops=bool(flags.get("has_internal_hops")),
            verified_categories=cats,
            has_live_gadget=bool(flags.get("has_live_gadget")),
            needs_channel_oracle=oracle_open,
        )
        protect = protected_tactics(
            has_foothold=bool(flags.get("has_foothold")),
            remaining_goals=bool(flags.get("remaining_goals")),
            has_verified_asset=bool(flags.get("has_verified_asset")),
            verified_categories=cats,
            has_live_gadget=bool(flags.get("has_live_gadget")),
        )
        if protect:
            self.banned_strategies = [b for b in self.banned_strategies if b not in protect]
        for r in list(binding.ban_repeats):
            if r and r not in self.banned and not is_noise_repeat(r):
                self.banned.append(r)
        self.banned = self.banned[-20:]
        self._install_binding(binding, plan=plan, extra=extra)
        self.plan_exec_turns = 0
        if skip_close_guide:
            try:
                from .advisor_bind import surface_false_close
                if surface_false_close(raw_blob):
                    self.force_bundle_review = True
            except Exception:
                pass
        if self.stall_class != "none":
            self.no_progress = 0
            self.soft_fired = False

    async def _emit_supervisor(
        self,
        kind: str,
        *,
        plan: SupervisorPlan | None = None,
        quality: str = "",
        turn: int = 0,
        extra: dict | None = None,
    ) -> None:
        """给前端监督窗口写一条结构化记录。"""
        payload: dict = {
            "kind": kind,
            "pivot": self.pivots,
            "stall": self.stall_class,
            "quality": quality or self.last_quality,
            "turn": turn,
        }
        if plan is not None:
            bind = self.binding
            stall = plan.stall if plan.stall in ("none", "infra", "method", "chain", "postex") else self.stall_class
            payload.update({
                "diagnosis": (bind.diagnosis if bind else None) or plan.diagnosis,
                "next_plan": (bind.next_plan if bind else None) or plan.next_plan,
                "must_intents": list((bind.must_intents if bind else None) or plan.must_intents),
                "prefer_tactics": list((bind.prefer_tactics if bind else None) or plan.prefer_tactics),
                "defer_families": list((bind.deny_tactics if bind else None) or plan.defer_families),
                "ban_repeats": list((bind.ban_repeats if bind else None) or plan.ban_repeats),
                "subagents": list((bind.subagents if bind else None) or plan.subagents),
                "rebind_entry": bool(plan.rebind_entry),
                "deny_tactics": list(bind.deny_tactics) if bind else list(plan.defer_families),
                "binding_misses": int(bind.misses) if bind else 0,
                "stall": stall,
                "plan_history": list(self.plan_history)[-8:],
            })
        if extra:
            payload.update(extra)
        await emit(self.project_id, "supervisor", payload, run_id=self.run_id)

    async def emit_ready_probe(self) -> None:
        """御主探活：猎开始或超时自检重启后各发一次。"""
        wait = int(getattr(settings, "supervisor_timeout_sec", 360) or 360)
        await emit(
            self.project_id, "supervisor",
            {"kind": "probe", "probe": True, "ready": True,
             "diagnosis": "御主就绪（冒烟）", "directives": []},
            run_id=self.run_id,
        )
        await emit(
            self.project_id, "log",
            {"level": "info",
             "message": (
                 f"御主就绪：每轮先下令，从者等待；"
                 f"超时 {wait}s 后从者自走。"
             )},
            run_id=self.run_id,
        )

    async def restart_after_consult_fail(self, turn: int, *, error: str) -> None:
        """360s 未拿到令：清冷却、释放后探活，便于下一轮再拉起。不拆旧绑定。"""
        _ = turn
        _ = error
        self.last_fail_ts = 0.0
        await self.emit_ready_probe()

    async def record_graph_progress(
        self, *, graph: dict | None, flags: int,
    ) -> str:
        """从者本轮打完后记空转。不咨询御主。"""
        stats = (graph or {}).get("stats") or {}
        try:
            nodes = int(stats.get("nodes") or 0)
            edges = int(stats.get("edges") or 0)
            findings = int(stats.get("findings") or 0)
        except (TypeError, ValueError):
            nodes = len((graph or {}).get("nodes") or [])
            edges = len((graph or {}).get("edges") or [])
            findings = len((graph or {}).get("findings") or [])
        try:
            nflags = int(flags or 0)
        except (TypeError, ValueError):
            nflags = 0
        quality = "none"
        if graph is not None and self.last_sig[0] >= 0:
            quality = await gstore.quality_progress_delta(
                self.last_sig, (nodes, edges, findings, nflags), graph,
            )
        self.note_progress(
            nodes=nodes, edges=edges, findings=findings, flags=nflags, quality=quality,
        )
        await self._note_redteam_empty_plan(quality)
        return quality

    async def _note_redteam_empty_plan(self, quality: str) -> None:
        """红队：从者打完一轮后记御主方案空转；满 6 升圈。CTF 不走。"""
        from ..objective import objective_allows_flag
        if objective_allows_flag(self.objective):
            return
        from pathlib import Path
        from .spiral import RING_LABELS, note_empty_plan
        ws = Path(settings.workspaces_dir) / self.project_id
        grew = quality in ("flag", "finding", "capability_edge")
        infra = self.stall_class == "infra"
        try:
            led = note_empty_plan(ws, grew=grew, infra=infra)
        except Exception:
            return
        if not led.get("promoted"):
            return
        try:
            ring = int(led.get("allowed_ring") or 1)
        except (TypeError, ValueError):
            ring = 1
        label = RING_LABELS.get(ring, str(ring))
        await emit(
            self.project_id, "log",
            {"level": "info", "message": (
                f"螺旋进入第 {ring} 圈（{label}）：按该圈完整清单做，不要因小圈做过而省略。"
            )},
            run_id=self.run_id,
        )

    async def emit_skip(self, turn: int, *, reason: str, detail: str = "") -> None:
        """本轮不调用 Claude，但仍留下一条可见的御主记录，避免轮次空洞。"""
        text = (detail or "").strip() or _SKIP_TEXT.get(reason) or reason
        await self._emit_supervisor(
            "skip",
            turn=int(turn or 0),
            extra={"reason": reason, "diagnosis": text, "next_plan": text},
        )

    async def _emit_continue(self, turn: int, *, reason: str, quality: str = "", detail: str = "") -> None:
        """已有方案、本轮不换方向：写入 hold，自监督栏能看见，不只在对话框里重复钉指令。"""
        bind = self.binding
        diag = (detail or self.last_diagnosis or "继续当前方案").strip()[:400]
        extra: dict = {
            "reason": reason,
            "diagnosis": diag,
            "next_plan": (self.last_plan_text or (bind.next_plan if bind else "") or diag)[:4000],
        }
        if bind:
            extra.update({
                "must_intents": list(bind.must_intents),
                "prefer_tactics": list(bind.prefer_tactics),
                "defer_families": list(bind.deny_tactics),
                "ban_repeats": list(bind.ban_repeats),
                "subagents": list(bind.subagents),
            })
        await self._emit_supervisor(
            "hold", quality=quality or self.last_quality, turn=int(turn or 0), extra=extra,
        )

    async def backfill_missing_turns(self, upto_turn: int) -> int:
        """续跑时把历史上没写盘的轮次补成 skip，让「第 N 轮」和自监督条数对齐。"""
        have = await load_supervised_turns(self.project_id)
        n = 0
        for t in range(1, max(0, int(upto_turn or 0)) + 1):
            if t in have:
                continue
            await self.emit_skip(t, reason="interrupted")
            n += 1
        return n

    async def restore_last_plan(self) -> bool:
        """续跑时从最近一条有效监督方案恢复内存状态。

        探索阶段若最近一条已是 binding_ignored hold，不把空转方案再注回去，
        让循环按全局重开多路线；收成/横向走廊仍恢复原文。
        """
        if not self.project_id:
            return False
        try:
            rows = await db.fetchall(
                "SELECT payload FROM events WHERE project_id=? AND type='supervisor' "
                "ORDER BY id DESC LIMIT 80",
                (self.project_id,),
            )
        except Exception:
            return False
        latest: dict | None = None
        full_by_pivot: dict[int, dict] = {}
        for r in rows:
            try:
                p = json.loads(r["payload"] or "{}") if isinstance(r.get("payload"), str) else (r.get("payload") or {})
            except Exception:
                continue
            if not isinstance(p, dict):
                continue
            kind = str(p.get("kind") or "plan")
            if kind not in ("plan", "hold"):
                continue
            diag = str(p.get("diagnosis") or "")
            if diag.startswith("监督输出未结构化"):
                continue
            try:
                pivot = int(p.get("pivot") or 0)
            except (TypeError, ValueError):
                pivot = 0
            if kind == "plan" and pivot and p.get("next_plan") and pivot not in full_by_pivot:
                full_by_pivot[pivot] = p
            if latest is None and (p.get("next_plan") or diag):
                latest = p
        if not latest:
            return False
        try:
            pivot = int(latest.get("pivot") or 0)
        except (TypeError, ValueError):
            pivot = 0
        src = full_by_pivot.get(pivot) or latest
        plan = SupervisorPlan(
            diagnosis=str(src.get("diagnosis") or latest.get("diagnosis") or "").strip(),
            stall=str(src.get("stall") or latest.get("stall") or "none").strip().lower() or "none",
            next_plan=str(src.get("next_plan") or latest.get("next_plan") or "").strip(),
            must_intents=list(src.get("must_intents") or latest.get("must_intents") or [])[:3],
            prefer_tactics=list(src.get("prefer_tactics") or latest.get("prefer_tactics") or [])[:8],
            defer_families=list(src.get("defer_families") or latest.get("defer_families") or [])[:6],
            ban_repeats=list(src.get("ban_repeats") or latest.get("ban_repeats") or [])[:12],
            subagents=list(src.get("subagents") or latest.get("subagents") or [])[:4],
            rebind_entry=bool(src.get("rebind_entry") or latest.get("rebind_entry")),
        )
        if not (plan.next_plan or plan.diagnosis):
            return False
        latest_kind = str(latest.get("kind") or "")
        latest_reason = str(latest.get("reason") or "")
        explore_stale = (
            str(plan.stall or "").strip().lower() in ("none", "method")
            and latest_kind == "hold"
            and latest_reason == "binding_ignored"
        )
        if explore_stale:
            self.pivots = max(0, pivot)
            self.force_bundle_review = True
            self.last_steer_turn = None
            self.binding = None
            self.active_steer = None
            self.pending_steer = None
            self.plan_exec_turns = 0
            return False
        try:
            c_flags, w_flags = await flag_submission_stats(self.project_id)
        except Exception:
            c_flags, w_flags = 0, 0
        if claimed_secret_disproved(
            plan=f"{plan.diagnosis} {plan.next_plan}",
            correct_flags=c_flags,
            wrong_flags=w_flags,
        ):
            return False
        invert_ops = False
        postex_pivot = False
        opens: list = []
        try:
            from ..graph import store as gstore
            from .supervisor_brief import needs_invert_ops_guidance, needs_postex_pivot_guidance
            graph = await gstore.get_graph(self.project_id)
            invert_ops = needs_invert_ops_guidance(graph=graph, claim_unverified=False)
            row = await db.fetchone("SELECT config FROM projects WHERE id=?", (self.project_id,))
            cfg = {}
            if row and row["config"]:
                raw = row["config"]
                cfg = json.loads(raw) if isinstance(raw, str) else (raw or {})
            try:
                flag_count = int(cfg.get("flag_count") or 0)
            except (TypeError, ValueError):
                flag_count = 0
            postex_pivot = needs_postex_pivot_guidance(
                graph=graph, correct_flags=c_flags, flag_count=flag_count,
            )
            try:
                opens = [
                    it for it in await gstore.list_open_intents(self.project_id, limit=50)
                    if str(it.get("status") or "") != "deferred"
                ]
            except Exception:
                opens = []
        except Exception:
            invert_ops = False
            postex_pivot = False
            graph = None
            flag_count = 0
            opens = []
        self.pivots = max(0, pivot)
        hist = src.get("plan_history")
        if isinstance(hist, list) and hist:
            self.plan_history = [x for x in hist if isinstance(x, dict)][-8:]
        bind_flags = self._binding_graph_flags(
            graph, correct_flags=c_flags, flag_count=flag_count,
        )
        self._apply_plan(
            plan, repeats=[], invert_ops=invert_ops, postex_pivot=postex_pivot,
            open_intents=opens or None, bind_flags=bind_flags,
        )
        try:
            restored_turn = int(latest.get("turn") or src.get("turn") or 0)
        except (TypeError, ValueError):
            restored_turn = 0
        if restored_turn > 0:
            self.last_steer_turn = restored_turn
        try:
            dwell = int(getattr(settings, "advisor_hold_turns", 3) or 3)
        except (TypeError, ValueError):
            dwell = 3
        self.plan_exec_turns = max(dwell, 0)
        return True

    async def evaluate(
        self, *, nodes: int, edges: int, findings: int, flags: int,
        graph: dict | None = None, scope_hosts: list[str] | None = None,
        project: dict | None = None, brief: str = "",
        last_turn_text: str = "", last_tool_uses: int = 0, turn: int = 0,
        assigned: list | None = None,
        open_intents: list | None = None,
        record_progress: bool = True,
    ) -> None:
        protected = verified_chain_paths(graph)
        chain_live = has_verified_asset(graph) and not self.entry_identity_mismatch
        try:
            infra = await self._detect_infra(graph, scope_hosts)
        except Exception:
            infra = False
        if infra:
            self.infra_streak += 1
            self.stall_class = "infra"
            self.want_rebind = True
        else:
            self.infra_streak = 0
            if self.stall_class == "infra":
                self.stall_class = "none"

        quality = "none"
        if graph is not None and self.last_sig[0] >= 0:
            quality = await gstore.quality_progress_delta(
                self.last_sig, (nodes, edges, findings, flags), graph,
            )
        if record_progress:
            self.note_progress(nodes=nodes, edges=edges, findings=findings, flags=flags, quality=quality)

        had_plan = bool(self.active_steer)
        if had_plan and int(last_tool_uses or 0) > 0:
            self.plan_exec_turns += 1

        def _requeue_active() -> None:
            if self.active_steer:
                self.pending_steer = self.active_steer

        if assigned is not None:
            self.claimed_ids = [str(i.get("id") or "") for i in assigned if i.get("id")]

        if (not infra) and self.binding is not None:
            status = binding_compliance(
                self.binding,
                assigned=assigned,
                open_intents=open_intents,
                last_turn_text=last_turn_text,
                last_tool_uses=last_tool_uses,
                quality=quality,
            )
            if status == "oracle":
                self.binding.misses = 0
                self.last_plan_outcome = "oracle"
            elif status == "empty":
                _requeue_active()
                self.last_plan_outcome = "empty"
            elif status == "ignored":
                self.last_plan_outcome = "ignored"
                self._stamp_history_outcome(turn=turn)
                self.binding = tighten_binding(self.binding)
                try:
                    miss_limit = int(getattr(settings, "advisor_bind_refresh_misses", 3) or 3)
                except (TypeError, ValueError):
                    miss_limit = 3
                if should_refresh_stale_binding(self.binding, misses_limit=miss_limit):
                    await emit(
                        self.project_id, "log",
                        {"level": "info",
                         "message": (
                             f"御主路线包空转 {self.binding.misses} 次，作废旧绑定，"
                             "按全局重开多路线审查。"
                         )},
                        run_id=self.run_id,
                    )
                    try:
                        from .advisor_bind import EXPLORE_REFRESH_TACTICS
                        await gstore.reopen_advisor_deferred_tactics(
                            self.project_id, EXPLORE_REFRESH_TACTICS,
                            run_id=self.run_id,
                        )
                    except Exception:
                        pass
                    self.binding = None
                    self.active_steer = None
                    self.pending_steer = None
                    self.last_steer_turn = None
                    self.plan_exec_turns = 0
                    self.force_bundle_review = True
                    self.last_pivot_ts = 0.0
                    self.last_fail_ts = 0.0
                else:
                    self._reapply_binding(turn=turn)
                    await emit(
                        self.project_id, "log",
                        {"level": "info",
                         "message": (
                             f"御主绑定未执行，收紧约束后重注（miss={self.binding.misses}），"
                             "不开新方案。"
                         )},
                        run_id=self.run_id,
                    )
                    await self._emit_continue(
                        turn, reason="binding_ignored", quality=quality,
                        detail=format_binding_block(self.binding),
                    )
                    protect = self._protected_now(graph)
                    for fam in list(self.binding.deny_tactics):
                        if fam in protect:
                            continue
                        try:
                            await gstore.defer_strategy_family(
                                self.project_id, fam,
                                reason=f"advisor-bind deny family={fam}",
                                run_id=self.run_id,
                            )
                        except Exception:
                            pass
                    return
            else:
                self.last_plan_outcome = "executed"

        self._stamp_history_outcome(turn=turn)

        if infra:
            _requeue_active()
            await emit(
                self.project_id, "log",
                {"level": "info",
                 "message": "入口传输层失败，御主本轮跳过，不当方法失败去换弱口令/扫网段。"},
                run_id=self.run_id,
            )
            await self.emit_skip(turn, reason="infra")
            return

        self._refresh_stall_class(chain_live=chain_live, graph=graph, quality=quality)

        now = time.monotonic()
        skip_cd = bool(self.force_bundle_review)
        fail_cd = float(getattr(settings, "supervisor_fail_cooldown_sec", _FAIL_COOLDOWN_SEC) or 0)
        if (not skip_cd) and fail_cd > 0 and self.last_fail_ts and (now - self.last_fail_ts) < fail_cd:
            _requeue_active()
            await self.emit_skip(turn, reason="fail_cooldown")
            return

        try:
            dwell = int(getattr(settings, "advisor_hold_turns", 3) or 3)
        except (TypeError, ValueError):
            dwell = 3
        peer_entries: list[str] = []
        try:
            from ..scope_pivot import peer_challenge_entry_addrs
            peer_entries = sorted(await peer_challenge_entry_addrs(self.project_id))[:20]
        except Exception:
            peer_entries = []
        plan_blob = f"{self.last_plan_text or ''} {self.active_steer or ''} {self.last_diagnosis or ''}"
        peer_contaminated = plan_cites_peer_entry(plan_blob, peer_entries)
        try:
            correct_flags, wrong_flags = await flag_submission_stats(self.project_id)
        except Exception:
            correct_flags, wrong_flags = 0, 0
        claim_unverified = claimed_secret_disproved(
            plan=plan_blob,
            graph=graph,
            correct_flags=correct_flags,
            wrong_flags=wrong_flags,
        )
        claim_in_plan = plan_claims_obtained_secret(plan_blob)
        enum_vs_surface = False
        try:
            enum_vs_surface = plan_blocks_live_surface(
                plan_blob, surfaces=surfaces_from_graph_nodes(graph),
            )
        except Exception:
            enum_vs_surface = False
        fake_key_loop = plan_is_fake_key_loop(plan_blob)
        login_vs_enum = plan_is_entry_enum(plan_blob) and graph_has_login_or_surface(graph)

        claimed = assigned
        if claimed is None:
            claimed = [{"id": i} for i in (self.claimed_ids or self.assigned_intent_ids or []) if i]
        bind_now = self._binding_graph_flags(graph, correct_flags=flags)
        in_flight = in_flight_blocks_new_direction(
            claimed, open_intents,
            has_verified_asset=bool(bind_now.get("has_verified_asset")),
            verified_categories=bind_now.get("verified_categories"),
        )
        try:
            interval = max(1, int(getattr(settings, "advisor_min_turn_interval", 3) or 3))
        except (TypeError, ValueError):
            interval = 3
        try:
            hold_turns = max(0, int(getattr(settings, "advisor_hold_turns", 3) or 0))
        except (TypeError, ValueError):
            hold_turns = 3
        try:
            hard_turns = max(1, int(getattr(settings, "loop_supervise_hard_turns", 6) or 6))
        except (TypeError, ValueError):
            hard_turns = 6
        try:
            first_turns = max(1, int(getattr(settings, "advisor_first_turns", 2) or 2))
        except (TypeError, ValueError):
            first_turns = 2
        review, review_why = should_review_advisor(
            turn=turn,
            interval=interval,
            stall_class=self.stall_class,
            no_progress=self.no_progress,
            last_steer_turn=self.last_steer_turn,
            hold_turns=hold_turns,
            in_flight=in_flight,
            hard_turns=hard_turns,
            pivots=self.pivots,
            first_turns=first_turns,
        )
        asked_bundle = bool(self.force_bundle_review)
        if self.force_bundle_review:
            review, review_why = True, "turn"
            self.force_bundle_review = False
        void_plan = bool(peer_contaminated or (claim_unverified and claim_in_plan))
        if void_plan and not review:
            self.last_steer_turn = None
            review, review_why = True, "turn"
        if not review and should_force_chain_close_review(
            chain_live=chain_live,
            has_plan=had_plan,
            assigned_tactics={intent_tactic(i) for i in (claimed or [])},
            verified_categories=verified_finding_categories(graph) if chain_live else None,
        ):
            review, review_why = True, "turn"
            await emit(
                self.project_id, "log",
                {"level": "info",
                 "message": "御主开口：图上已有已验证能力却未消耗，禁止再证明或跳过。"},
                run_id=self.run_id,
            )
        if not review and should_force_oracle_review(
            needs_oracle=bool(bind_now.get("needs_channel_oracle")),
            has_plan=had_plan,
            assigned_tactics={intent_tactic(i) for i in (claimed or [])},
        ):
            review, review_why = True, "turn"
            await emit(
                self.project_id, "log",
                {"level": "info",
                 "message": "御主开口：图上仍是单通道观测，输入面未关，禁止只打指纹或目录。"},
                run_id=self.run_id,
            )

        if not review:
            _requeue_active()
            if had_plan:
                await self._emit_continue(
                    turn, reason=review_why or "hold_course", quality=quality,
                    detail=self.last_diagnosis or "继续当前方案",
                )
            else:
                await self.emit_skip(turn, reason=review_why)
            if review_why in ("hold_course", "in_flight", "let_commander"):
                why_cn = {
                    "hold_course": "刚下过指令，等当前验证做完",
                    "in_flight": "本轮任务仍在验证，尚未证实或否证",
                    "let_commander": "先让从者打",
                }.get(review_why, review_why)
                await emit(
                    self.project_id, "log",
                    {"level": "info", "message": f"御主本轮不改方向：{why_cn}。"},
                    run_id=self.run_id,
                )
            return

        void_msgs: list[str] = []
        if peer_contaminated:
            void_msgs.append("上一份方案引用了邻题入口，已作废，回到本题入口产物。")
        if claim_unverified and claim_in_plan:
            void_msgs.append(
                "上一份方案把「已解密出 flag」当成收口，但正确 flag 仍为 0，该解密式已作废。"
            )
        if void_msgs:
            await emit(
                self.project_id, "log",
                {"level": "info", "message": "御主：" + " ".join(void_msgs)},
                run_id=self.run_id,
            )
            self.last_plan_text = ""
            self.active_steer = None
            self.pending_steer = None
            self.binding = None
            self.plan_exec_turns = 0
            self.last_steer_turn = None

        last_diag = self.last_diagnosis
        last_plan = self.last_plan_text
        if peer_contaminated:
            last_diag = "上一份方案引用了邻题入口，已作废，必须回到本题入口产物。"
            last_plan = ""
        if claim_unverified and claim_in_plan:
            last_diag = (
                "已解密出 flag 的假设已被错旗否证。按简报收口手法从本题入口产物继续，不要停猎。"
            )
            last_plan = ""

        repeats = await self._recent_repeats(protected=protected)
        facts = SupervisorFacts(
            quality=quality,
            infra=infra,
            chain_live=chain_live,
            postex=_postex_stalled(graph),
            identity_mismatch=bool(self.entry_identity_mismatch),
            unmounted_secret=bool(graph_has_unmounted_secret(graph)),
            repeats=repeats,
            no_progress=self.no_progress,
            last_diagnosis=last_diag,
            last_plan=last_plan,
            last_plan_outcome=self.last_plan_outcome,
            last_must_intents=list(self.binding.must_intents) if self.binding else [],
            last_deny_tactics=list(self.binding.deny_tactics) if self.binding else [],
            prior_plans=list(self.plan_history),
            current_entry=str((project or {}).get("target") or "").split(":")[0].strip(),
            last_tool_uses=int(last_tool_uses or 0),
            plan_exec_turns=self.plan_exec_turns,
            plan_dwell_turns=dwell,
            active_plan_live=had_plan and not peer_contaminated and not (claim_unverified and claim_in_plan),
            peer_entries=peer_entries,
            claim_unverified=claim_unverified,
            correct_flags=correct_flags,
            wrong_flags=wrong_flags,
        )
        brief_kw = dict(
            project_id=self.project_id, run_id=self.run_id, objective=self.objective,
            graph=graph, facts=facts, project=project, brief=brief,
            last_turn_text=last_turn_text, last_tool_uses=last_tool_uses,
            turn=turn, scope_hosts=scope_hosts,
        )
        brief_text = await assemble_supervisor_brief(**brief_kw)
        wait = float(getattr(settings, "supervisor_timeout_sec", 360) or 360)

        async def _on_wait(attempt: int, err: str, delay: float) -> None:
            # 超时是 Claude Code CLI 墙钟，不是上下文不够。控制台不要当成报错。
            if delay > 0:
                msg = (
                    f"御主 Claude Code 首问超时（{err}），"
                    f"{delay:.0f}s 后用原简报再问（第 {attempt} 次）。"
                )
            else:
                msg = f"御主 Claude Code 首问超时（{err}），原简报立刻再问（第 {attempt} 次）。"
            await emit(
                self.project_id, "log",
                {"level": "info", "message": msg},
                run_id=self.run_id,
            )

        plan = None
        consult_error = ""
        obj = self.objective

        async def _consult(brief: str, timeout: float | None = None, **_kw):
            return await consult_supervisor(
                brief, timeout=timeout, system_prompt=supervisor_system_prompt(obj),
            )

        try:
            plan = await await_supervisor_plan(
                brief_text, timeout=wait,
                on_wait=_on_wait,
                consult=_consult,
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            consult_error = (str(e) or type(e).__name__).strip()
        if not plan_is_usable(plan):
            self.last_fail_ts = now
            if asked_bundle:
                self.force_bundle_review = True
            if not consult_error:
                consult_error = "监督返回空方案"
            wait_s = int(getattr(settings, "supervisor_timeout_sec", 360) or 360)
            await emit(
                self.project_id, "log",
                {"level": "warn",
                 "message": (
                     f"御主 {wait_s}s 未下达任务，从者按本轮自己的思路继续"
                     f"（{consult_error}）"
                 )},
                run_id=self.run_id,
            )
            await self._emit_supervisor(
                "error",
                quality=quality,
                turn=turn,
                extra={"error": consult_error},
            )
            _requeue_active()
            try:
                await self.restart_after_consult_fail(turn, error=consult_error)
            except Exception:
                pass
            return

        try:
            from pathlib import Path
            from ..objective import objective_allows_flag
            if plan is not None and objective_allows_flag(self.objective):
                from .spiral import load_ledger, scan_ban_repeats
                ws = Path(settings.workspaces_dir) / self.project_id
                extra = scan_ban_repeats(load_ledger(ws), objective=self.objective)
                plan.ban_repeats = list(dict.fromkeys(list(plan.ban_repeats or []) + extra))[:12]
        except Exception:
            pass

        refine_supervisor_plan(
            plan,
            graph=graph,
            no_progress=self.no_progress,
            quality=quality,
            extra_plan_text=plan_blob,
        )
        llm_stalled = (
            int(self.no_progress or 0) >= 2
            and (quality or "none") in ("none", "weak_graph", "info_node")
        )
        llm_hold_ok = (
            plan.hold
            and self.active_steer
            and not claim_unverified
            and not peer_contaminated
            and not enum_vs_surface
            and not fake_key_loop
            and not llm_stalled
            and not login_vs_enum
            and not plan_is_fake_key_loop(
                f"{plan.next_plan or ''} {plan.diagnosis or ''}"
            )
            and not (
                plan_is_entry_enum(f"{plan.next_plan or ''} {plan.diagnosis or ''}")
                and graph_has_login_or_surface(graph)
            )
            and not starves_chain_close(
                self.binding, open_intents,
                has_foothold=graph_has_getshell(graph),
                has_verified_asset=chain_live,
                verified_categories=verified_finding_categories(graph),
            )
        )
        if llm_hold_ok:
            try:
                from .supervisor_brief import POSTEX_PIVOT_GUIDE, needs_postex_pivot_guidance
                cfg = (project or {}).get("config") or {}
                try:
                    flag_count = int(cfg.get("flag_count") or 0)
                except (TypeError, ValueError):
                    flag_count = 0
                if needs_postex_pivot_guidance(
                    graph=graph, correct_flags=correct_flags, flag_count=flag_count,
                ) and POSTEX_PIVOT_GUIDE not in (self.active_steer or ""):
                    self.active_steer = self.active_steer + "\n" + POSTEX_PIVOT_GUIDE
            except Exception:
                pass
            _requeue_active()
            diag = (plan.diagnosis or "当前方案尚未否证，继续执行。")[:200]
            await emit(
                self.project_id, "log",
                {"level": "info",
                 "message": f"御主：继续当前方案 stall={plan.stall or self.stall_class} · {diag[:80]}"},
                run_id=self.run_id,
            )
            await self._emit_supervisor(
                "hold", plan=plan, quality=quality, turn=turn,
                extra={"reason": "plan_hold", "diagnosis": diag},
            )
            return

        self.pivots += 1
        self.last_pivot_ts = now
        self.last_fail_ts = 0.0
        invert_ops = bool(claim_unverified)
        postex_pivot = False
        flag_count = 0
        try:
            from .supervisor_brief import needs_invert_ops_guidance, needs_postex_pivot_guidance
            invert_ops = needs_invert_ops_guidance(graph=graph, claim_unverified=claim_unverified)
            cfg = (project or {}).get("config") or {}
            try:
                flag_count = int(cfg.get("flag_count") or 0)
            except (TypeError, ValueError):
                flag_count = 0
            postex_pivot = needs_postex_pivot_guidance(
                graph=graph, correct_flags=correct_flags, flag_count=flag_count,
            )
        except Exception:
            flag_count = 0
        bind_flags = self._binding_graph_flags(
            graph, correct_flags=correct_flags, flag_count=flag_count,
        )
        self._apply_plan(
            plan, repeats=repeats, invert_ops=invert_ops, postex_pivot=postex_pivot,
            open_intents=open_intents, bind_flags=bind_flags,
        )
        self.last_steer_turn = int(turn or 0)
        protect = protected_tactics(
            has_foothold=bool(bind_flags.get("has_foothold")),
            remaining_goals=bool(bind_flags.get("remaining_goals")),
            has_verified_asset=bool(bind_flags.get("has_verified_asset")),
            verified_categories=bind_flags.get("verified_categories"),
            has_live_gadget=bool(bind_flags.get("has_live_gadget")),
        )
        fams = [f for f in list(plan.defer_families) if f not in protect]
        if self.binding:
            fams.extend(t for t in self.binding.deny_tactics if t not in protect)
        seen_fam: set[str] = set()
        for fam in fams:
            if not fam or fam in seen_fam:
                continue
            seen_fam.add(fam)
            try:
                await gstore.defer_strategy_family(
                    self.project_id, fam,
                    reason=f"ai-supervisor defer family={fam}",
                    run_id=self.run_id,
                )
            except Exception:
                pass
        await emit(
            self.project_id, "log",
            {"level": "info",
             "message": (
                 f"御主：方案#{self.pivots} stall={self.stall_class}"
                 f" quality={self.last_quality}"
                 + (f" · {plan.diagnosis[:80]}" if plan.diagnosis else "")
             )},
            run_id=self.run_id,
        )
        await self._emit_supervisor("plan", plan=plan, quality=quality, turn=turn)

    def drain_steer(self) -> str | None:
        s = self.pending_steer
        self.pending_steer = None
        return s

    def drain_reset(self) -> bool:
        r = self.force_reset
        self.force_reset = False
        return r

    def drain_rebind(self) -> bool:
        w = self.want_rebind
        self.want_rebind = False
        return w

    def frontier_exclude_strategies(self) -> set[str]:
        """本轮取前沿时要排除的策略族。绑定 deny 优先于链上续打。"""
        exclude = set(self.banned_strategies)
        if self.binding:
            exclude |= set(self.binding.deny_tactics)
        if self.stall_class in ("infra", "chain"):
            exclude -= _CHAIN_CONTINUE
        if self.binding:
            exclude |= set(self.binding.deny_tactics)
        if self.binding:
            plan_txt = self.binding.next_plan or ""
            exclude -= protected_tactics(
                has_foothold=self.stall_class == "postex",
                remaining_goals=self.stall_class == "postex",
                has_verified_asset=(
                    self.stall_class in ("chain", "postex")
                    or CLOSEOUT_OVERRIDE in plan_txt
                ),
                has_live_gadget=GADGET_KEEP in plan_txt,
            )
        return exclude

    def drain_assigned_intents(self) -> list[str]:
        if self.binding and self.binding.must_intents:
            return list(self.binding.must_intents[:3])
        return list(self.assigned_intent_ids)

    def drain_prefer_tactics(self) -> set[str] | None:
        tacs = list(
            (self.binding.prefer_tactics if self.binding else None) or self.prefer_tactics
        )
        tacs = [t for t in tacs if t]
        return set(tacs) if tacs else None
