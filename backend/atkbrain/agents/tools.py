"""StrikeAgent_AtkBrain-Flash 自定义 MCP 工具集（in-process）。

这是智能体与外界交互的唯一受控通道：
- run_cmd / http_request：命令与 HTTP 均经作业对象校验。
- add_node / add_edge / report_finding / report_shell / propose_intents：实时构建攻击图与发现。
- note / mark_honeypot：思考流与蜜罐标记。
每个工具闭包绑定一个 AgentContext。
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from urllib.parse import urlparse

from claude_agent_sdk import create_sdk_mcp_server, tool

from ..db import db, new_id, now
from ..events import emit
from ..graph import store as gstore
from ..graph.model import EdgeIn, FindingIn, IntentIn, NodeIn, display_finding_severity
from ..objective import (
    DATA_ACCESS_CATEGORIES,
    KEY_LEAK_CATEGORIES,
    REDTEAM,
    awarded_sum,
    ctf_full_score,
    normalize_objective,
    objective_allows_flag,
)
from .. import benchmark as bm
from ..scope import unauthorized_peer_endpoint, unauthorized_private_host
from .context import AgentContext

SERVER_NAME = "atkbrain"


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v or "").strip().lower() in ("1", "true", "yes", "y", "on")


def _schedule_milestone(ctx: AgentContext, milestone: str, **extra) -> None:
    """未停机的里程碑：异步沉淀，不阻塞本回合。"""
    try:
        asyncio.get_running_loop().create_task(persist_milestone(ctx, milestone, **extra))
    except Exception:
        pass


async def persist_milestone(ctx: AgentContext, milestone: str, **extra) -> dict | None:
    """立刻把路径+去特化思路写入记忆库（满分收工前必须 await，避免被 interrupt 冲掉）。"""
    project = ctx.project
    pid = ctx.project_id
    if not project or not pid or not milestone:
        return None
    try:
        from ..memory.store import summarize_milestone
        graph = await gstore.get_graph(pid, heal=True)
        row = await summarize_milestone(project, milestone, graph=graph, **extra)
        skipped = bool(row and row.get("skipped"))
        if skipped:
            msg = (
                f"同思路已在记忆库，跳过重复沉淀"
                f"（{row.get('reason') or 'approach_key'}）"
            )
        else:
            msg = f"已沉淀里程碑路径（{milestone}）到记忆库"
            try:
                from ..memory.evolve import evolve_from_episode_id
                if row and row.get("id"):
                    evo = await evolve_from_episode_id(str(row["id"]))
                    if evo:
                        msg += "，并写入跨局剧本"
            except Exception:
                pass
        await emit(ctx.project_id, "log", {"level": "info", "message": msg}, run_id=ctx.run_id)
        return row
    except Exception:
        return None


def _text(s: str, is_error: bool = False) -> dict:
    out: dict = {"content": [{"type": "text", "text": s}]}
    if is_error:
        out["is_error"] = True
    return out


FULL_SCORE_HALT = "本题已满分，立即收工换题。不要再调用任何工具。"
GOAL_REACHED_HALT = "本项目已达成终极目标，立即收工。不要再调用任何工具。"
MUST_DISPROVE_REFUSE = "绑定未完成，不能否证顾问 must Intent。"


def refuse_disprove_bound_must(ctx, intent_id, verified) -> str | None:
    """顾问 must Intent 仍在绑定时，指挥官不得写成否证。"""
    if verified:
        return None
    bound = getattr(ctx, "bound_must_intents", None) or ()
    iid = str(intent_id or "").strip()
    if iid and iid in set(bound):
        return MUST_DISPROVE_REFUSE
    return None


def halt_if_full_score(ctx: AgentContext) -> dict | None:
    """终极目标达成后拒绝继续打点，把槽位让给下一目标。"""
    if not ctx.goal_reached:
        return None
    if normalize_objective(getattr(ctx, "objective", None)) == "flag":
        return _text(FULL_SCORE_HALT)
    return _text(GOAL_REACHED_HALT)


async def request_full_score_stop(ctx: AgentContext) -> None:
    """终极目标置位后打断会话；稍等让本条工具结果先回到模型。"""
    await asyncio.sleep(0.05)
    fn = getattr(ctx, "abort_run", None)
    if callable(fn):
        try:
            await fn()
        except Exception:
            pass


async def _finish_redteam_if_ready(ctx: AgentContext) -> str:
    """红队拿到 getshell → 置位收工。"""
    if normalize_objective(ctx.objective) != REDTEAM:
        return ""
    from ..memory.achievements import detect_achievements
    from ..objective import redteam_new_ultimate
    graph = await gstore.get_graph(ctx.project_id, heal=True)
    ach = detect_achievements(graph, allows_flag=False)
    if redteam_new_ultimate(ach, getattr(ctx, "achievements_at_start", None)):
        ctx.goal_reached = True
        return "**本项目完成**（已 getshell）。立即收工，不要再调用任何工具。"
    return "红队最高指令是 GETSHELL（report_shell 即收工）。继续测→证→报高危/严重，推向命令执行。"


def _norm_host(h: str) -> str:
    return (h or "").strip().lower().rstrip(".")


def _primary_host(ctx: AgentContext) -> str:
    """项目主目标主机名（第一台立足点默认归属它；用于区分是否踏上新主机）。"""
    p = ctx.project or {}
    t = _norm_host(p.get("target") or "")
    if t:
        return t
    return ""


def _host_already_authorized(ctx: AgentContext, host: str) -> bool:
    """是否已是授权身份（主目标或 Scope 显式成员），不是新冒出来的内网机。"""
    h = _norm_host(host)
    if not h:
        return True
    if h == _primary_host(ctx):
        return True
    try:
        if ctx.scope._explicit_member(h):
            return True
    except Exception:
        pass
    return False


def _attacker_identity_reason(host: str) -> str | None:
    """本机网卡 / 物机网关：禁止当目标、立足点或内网资产。"""
    h = _norm_host(host)
    if not h:
        return None
    try:
        from ..config import settings
        from ..scope import is_attacker_identity
        if is_attacker_identity(h):
            return f"host={h} 不能作为立足点。"
    except Exception:
        pass
    return None


_LIVE_ID_RE = re.compile(
    r"(?m)^uid=(\d+)\(([^)]+)\)[ \t]+gid=(\d+)\(([^)]*)\)"
)


def _local_unix_identity() -> tuple[str, str]:
    uid = str(os.getuid())
    name = ""
    try:
        import pwd
        name = (pwd.getpwuid(os.getuid()).pw_name or "").lower()
    except Exception:
        name = (os.environ.get("USER") or os.environ.get("LOGNAME") or "").lower()
    return uid, name


def live_exec_user(blob: str) -> str | None:
    """工具输出里的远程 POSIX `id` 回显。必须行首 uid= 且带 gid=，排除本机身份。"""
    if not blob:
        return None
    local_uid, local_name = _local_unix_identity()
    for m in _LIVE_ID_RE.finditer(blob):
        uid, name = m.group(1), m.group(2)
        if uid == local_uid and name.lower() == local_name:
            continue
        return name
    return None


async def project_has_landed_shell(project_id: str) -> bool:
    if not project_id:
        return False
    row = await db.fetchone(
        """SELECT 1 FROM nodes WHERE project_id=? AND type IN ('foothold','goal')
              AND (
                IFNULL(is_rce,0)=1
                OR IFNULL(key,'') LIKE 'goal:shell%'
                OR IFNULL(key,'') LIKE 'foothold:shell%'
              ) LIMIT 1""",
        (project_id,),
    )
    return bool(row)


async def _land_shell(
    ctx: AgentContext,
    *,
    access: str,
    evidence: str,
    host: str = "",
    node_key: str = "",
    channel: str = "",
    reconnect: str = "",
    proof_canary: str = "",
    proof_url: str = "",
    proof_detail: str = "",
) -> dict:
    """report_shell 与工具输出自动落图共用。"""
    ctx.shell_evidence = evidence or ""
    ctx.shell_access = access or ""
    is_goal = ctx.objective in ("getshell", "redteam")
    primary = _primary_host(ctx)
    host = _norm_host(host or "") or primary
    from ..config import settings
    from ..scope import is_platform_endpoint, local_self_hosts
    blocked = _attacker_identity_reason(host)
    if blocked:
        return _text(f"拒绝：{blocked}", is_error=True)
    if host and is_platform_endpoint(
        host, int(settings.port),
        self_hosts=local_self_hosts(),
        self_ports={int(settings.port), int(settings.frontend_port)},
    ):
        return _text(f"拒绝：host={host} 为本机控制台，不能作为立足点。", is_error=True)
    ctx.active_host = host
    is_new_host = bool(host) and not _host_already_authorized(ctx, host)
    base_key = "goal:shell" if is_goal else "foothold:shell"
    gkey = f"{base_key}@{host}" if is_new_host else base_key

    tags = (["getshell", "rce"] if is_goal else ["foothold", "rce"])
    if host:
        tags.append(f"host:{host}")
    if is_new_host:
        tags += ["lateral", "pivot"]

    title_host = f" @ {host}" if is_new_host else ""
    await gstore.upsert_node(
        ctx.project_id,
        NodeIn(key=gkey,
               type="goal" if is_goal else "foothold",
               title=(f"GETSHELL ({ctx.shell_access or 'access'}){title_host}" if is_goal
                      else f"立足点 shell ({ctx.shell_access or 'access'}){title_host}"),
               detail=ctx.shell_evidence, severity="critical", is_rce=True,
               tags=tags),
        run_id=ctx.run_id,
    )
    if (not is_new_host) and node_key:
        await gstore.add_edge(
            ctx.project_id,
            EdgeIn(**{"from": node_key, "to": gkey}, relation="ESCALATES_TO",
                   weight=1.0, rationale="getshell"),
            run_id=ctx.run_id,
        )

    await gstore.add_finding(
        ctx.project_id,
        FindingIn(
            node_key=gkey,
            severity="critical",
            category="rce",
            title=(f"GETSHELL ({ctx.shell_access or 'access'}){title_host}" if is_goal
                   else f"立足点 shell ({ctx.shell_access or 'access'}){title_host}"),
            description="命令执行立足点",
            evidence=ctx.shell_evidence,
            proof_type="write_txt",
            proof_canary=proof_canary or None,
            proof_url=proof_url or None,
            proof_detail=proof_detail or ctx.shell_evidence,
        ),
        run_id=ctx.run_id,
    )

    _append_shell_asset(ctx, host=host or "target", access=ctx.shell_access,
                        evidence=ctx.shell_evidence, channel=channel,
                        reconnect=reconnect)
    ctx.postex_phase = "active"
    await emit(ctx.project_id, "shell",
               {"access": ctx.shell_access, "evidence": ctx.shell_evidence[:2000],
                "node_key": gkey, "host": host,
                "proof_canary": proof_canary, "proof_url": proof_url},
               run_id=ctx.run_id)
    await _maybe_emit_lateral(ctx)
    _schedule_milestone(ctx, "getshell", title=f"GETSHELL {ctx.shell_access or ''}".strip(),
                        category="rce", node_key=gkey,
                        evidence=(ctx.shell_evidence or "")[:400])

    if is_goal:
        extra = await _finish_redteam_if_ready(ctx)
        if ctx.goal_reached:
            await persist_milestone(
                ctx, "getshell",
                title=f"GETSHELL {ctx.shell_access or ''}".strip(),
                category="rce", node_key=gkey,
                evidence=(ctx.shell_evidence or "")[:400],
            )
            try:
                asyncio.get_running_loop().create_task(request_full_score_stop(ctx))
            except Exception:
                pass
            return _text(f"✅ GETSHELL 已达成。{extra}")
    tail = ("5) flag 赛道：用当前权限继续定位并 report_flag；未齐正确 flag 必须继续，齐了立即收工。\n"
            if objective_allows_flag(ctx.objective)
            else "5) 红队：report_shell 成功即收工。\n")
    return _text(
        "✅ 已记录立足点(shell)。下一步请：\n"
        "1) 委派 privesc 做本机提权（提权成边 ESCALATES_TO）；\n"
        "2) 从跳板看见的内网主机用 report_pivot_capability 扩进 Scope，再委派 lateral；"
        "踏上新主机时 report_shell 必填 host；\n"
        "3) 出现域控/LDAP/Kerberos/Windows 凭证线索则继续横向；\n"
        + tail +
        "凭证/会话已落盘 workspace/shells.json 与 post-exploit/creds_*.json，委派时让子代理先读它们。"
    )


async def maybe_autoland_shell(ctx: AgentContext, blob: str) -> str | None:
    """run_cmd / http_request 输出已是远程 id 回显时落图，不等口头确认。"""
    if not ctx or not getattr(ctx, "project_id", None):
        return None
    if getattr(ctx, "shell_evidence", None):
        return None
    user = live_exec_user(blob)
    if not user:
        return None
    try:
        if await project_has_landed_shell(ctx.project_id):
            return None
    except Exception:
        return None
    evidence = (blob or "").strip()
    if len(evidence) > 1500:
        evidence = evidence[:1500]
    try:
        await _land_shell(
            ctx, access=user, evidence=evidence,
            host=_primary_host(ctx) or "", channel="detected-id",
        )
    except Exception:
        return None
    return user


def _append_shell_asset(ctx: AgentContext, *, host: str, access: str, evidence: str,
                        channel: str = "", reconnect: str = "") -> None:
    """把会话落进 workspace/shells.json（可复连资产；子代理委派时读它拿上下文）。"""
    path = os.path.join(ctx.workspace_dir, "shells.json")
    try:
        data = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f) or []
        if not isinstance(data, list):
            data = []
        entry = {
            "host": host, "access": access, "channel": channel,
            "reconnect": reconnect, "evidence": (evidence or "")[:800], "ts": time.time(),
        }
        for i, e in enumerate(data):
            if e.get("host") == host and e.get("access") == access:
                data[i] = entry
                break
        else:
            data.append(entry)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _write_creds_asset(ctx: AgentContext, *, host: str, title: str, detail: str) -> None:
    """凭证落盘 workspace/post-exploit/creds_<host>.json，供提权/横向复用。"""
    try:
        d = os.path.join(ctx.workspace_dir, "post-exploit")
        os.makedirs(d, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9._-]", "_", host or "unknown") or "unknown"
        path = os.path.join(d, f"creds_{safe}.json")
        data = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f) or []
        if not isinstance(data, list):
            data = []
        data.append({"title": title, "detail": (detail or "")[:1000], "ts": time.time()})
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _primary_port(ctx: AgentContext) -> int | None:
    p = getattr(ctx, "primary_port", None)
    if p:
        try:
            return int(p)
        except (TypeError, ValueError):
            pass
    ports = (ctx.project or {}).get("ports") or []
    if ports:
        try:
            return int(ports[0])
        except (TypeError, ValueError, IndexError):
            return None
    return None


def _out_of_scope_hosts(ctx: AgentContext, *texts: str) -> list[str]:
    """当前入口以外的私网 IP（含评测邻题）视为越界。公网域名不拦。

    网段标识（末段为 0）不当主机。节点检查应只传 key/host 标签，避免 init.sql 诱饵 IP 拦掉已扩容资产。
    """
    blob = " ".join(str(t or "") for t in texts)
    primary = _primary_host(ctx)
    peers = set(getattr(ctx, "peer_hosts", None) or [])
    out: list[str] = []
    for h in _IPV4_RE.findall(blob):
        if h.endswith(".0"):
            continue
        why = unauthorized_private_host(h, ctx.scope, primary=primary, peers=peers,
                                       own_hosts={
                                           str(a).split(":")[0]
                                           for a in (getattr(ctx, "own_addrs", None) or set()) if a
                                       })
        if why and h not in out:
            out.append(h)
    return out


_HOSTPORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b")
_SVC_PORT_RE = re.compile(r"(?:svc:|port:)(\d{2,5})", re.I)
_HOST_TAG_RE = re.compile(r"host:(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def _out_of_scope_endpoints(ctx: AgentContext, *texts: str) -> list[str]:
    """邻题 host:port，含同 IP 上其它 unique_code 的端口。"""
    blob = " ".join(str(t or "") for t in texts)
    primary = _primary_host(ctx)
    primary_port = _primary_port(ctx)
    peers = set(getattr(ctx, "peer_hosts", None) or [])
    addrs = set(getattr(ctx, "peer_addrs", None) or [])
    hits: list[str] = []
    seen: set[str] = set()
    pairs: list[tuple[str, int | None]] = []
    for m in _HOSTPORT_RE.finditer(blob):
        pairs.append((m.group(1), int(m.group(2))))
    hosts = _HOST_TAG_RE.findall(blob) or ([primary] if primary else [])
    ports = [int(x) for x in _SVC_PORT_RE.findall(blob)]
    if ports and hosts:
        for h in hosts:
            for p in ports:
                pairs.append((h, p))
    for h, p in pairs:
        why = unauthorized_peer_endpoint(
            h, p, primary=primary, primary_port=primary_port,
            peer_addrs=addrs, peers=peers,
            own_addrs=set(getattr(ctx, "own_addrs", None) or []),
        )
        if why and why not in seen:
            seen.add(why)
            hits.append(why)
    if addrs:
        from ..engine.supervisor_brief import plan_cites_peer_entry
        for a in addrs:
            key = str(a).strip().lower()
            if not key or key in seen:
                continue
            if plan_cites_peer_entry(blob, [key]):
                seen.add(key)
                hits.append(f"{key} 是其它题目入口")
    return hits


async def _touch_http_service(ctx: AgentContext, url: str, res: dict | None) -> None:
    """首次探测到可达 HTTP 时落 service 节点；后续响应刷新活体表面标签。"""
    if not ctx.project_id or not url or not isinstance(res, dict):
        return
    if res.get("blocked") or (res.get("error") and res.get("status") is None
                              and not res.get("desktop") and not res.get("mobile")):
        return
    try:
        parsed = urlparse(url)
        host = _norm_host(parsed.hostname or "")
        if not host:
            return
        if _out_of_scope_hosts(ctx, host) or _out_of_scope_endpoints(ctx, url) or _platform_graph_pollution(host, url):
            return
        from ..db import _loads
        from ..entry_fingerprint import merge_surface_tags, surfaces_from_http_result
        payload = dict(res)
        payload.setdefault("url", url)
        surf = surfaces_from_http_result(payload)
        if surf:
            ctx.entry_surface = merge_surface_tags(list(ctx.entry_surface or []), surf)
        scheme = (parsed.scheme or "http").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        primary = _primary_host(ctx)
        key = f"svc:{port}/http" if (not primary or host == primary) else f"svc:{port}/http@{host}"
        row = await db.fetchone(
            "SELECT * FROM nodes WHERE project_id=? AND key=?", (ctx.project_id, key),
        )
        headers = res.get("headers") or (res.get("desktop") or {}).get("headers") or {}
        server = ""
        if isinstance(headers, dict):
            server = str(headers.get("server") or headers.get("Server") or "")[:80]
        status = res.get("status")
        if status is None:
            status = (res.get("desktop") or {}).get("status")
        title = server or f"HTTP {port}"
        tags = ["http", f"port:{port}", f"host:{host}", "auto"]
        try:
            from ..objective import REDTEAM, normalize_objective
            if normalize_objective(ctx.objective) == REDTEAM:
                tags.append("tier:app")
        except Exception:
            pass
        old_tags: list = []
        if row:
            loaded = _loads(row["tags"]) if row["tags"] else []
            if isinstance(loaded, list):
                old_tags = [str(t) for t in loaded if t]
        merged: list[str] = []
        seen: set[str] = set()
        for t in list(old_tags) + tags + list(surf or []):
            name = str(t or "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            merged.append(name)
        if row and set(merged) <= set(old_tags):
            return
        detail = f"auto from http_request {url} status={status}"
        ntype = "service"
        sev = "info"
        if row:
            title = str(row["title"] or title)
            ntype = str(row["type"] or "service")
            sev = str(row["severity"] or "info")
            raw_detail = row["detail"]
            if raw_detail:
                loaded_d = _loads(raw_detail) if isinstance(raw_detail, str) else raw_detail
                detail = loaded_d if loaded_d not in (None, "") else detail
            if surf:
                extra = "表面=" + ",".join(surf)
                if isinstance(detail, str) and extra not in detail:
                    detail = detail + " " + extra
        await gstore.upsert_node(
            ctx.project_id,
            NodeIn(
                key=key, type=ntype, title=title,
                detail=detail, severity=sev, tags=merged,
            ),
            run_id=ctx.run_id,
        )
    except Exception:
        pass


def _schedule_touch_http(ctx: AgentContext, url: str, res: dict | None) -> None:
    try:
        asyncio.get_running_loop().create_task(_touch_http_service(ctx, url, res))
    except Exception:
        pass


def _platform_graph_pollution(*texts: str) -> str | None:
    blob = " ".join(str(t or "") for t in texts)
    if not blob.strip():
        return None
    try:
        from ..config import settings
        from ..scope import is_platform_endpoint, local_self_hosts
        ports = {int(settings.port), int(settings.frontend_port)}
        hosts = local_self_hosts()
        for ip in _IPV4_RE.findall(blob):
            if is_platform_endpoint(ip, None, self_hosts=hosts, self_ports=ports):
                return f"不要把本机控制台 {ip} 写入攻击图"
            if is_platform_endpoint(ip, int(settings.port), self_hosts=hosts, self_ports=ports):
                return f"不要把本机控制台 {ip} 写入攻击图"
    except Exception:
        pass
    return None


async def _maybe_emit_lateral(ctx: AgentContext) -> None:
    """检测到内网横向（PIVOTS_TO 边 / 第二台主机 foothold）时，播一次 lateral 事件点亮 UI。"""
    try:
        st = await gstore.get_stats(ctx.project_id)
    except Exception:
        return
    if st.get("lateral_active") and not ctx.lateral_emitted:
        ctx.lateral_emitted = True
        await emit(
            ctx.project_id, "lateral",
            {"hosts_footed": st.get("hosts_footed", 0),
             "pivot_edges": st.get("pivot_edges", 0),
             "message": "内网横向已开始"},
            run_id=ctx.run_id,
        )


def _clip(s: str, budget: int) -> str:
    """把返回给模型的输出限制在 token 预算内（否则整条工具结果会超限被丢弃、白费一轮）。
    超长时保留 head+tail 并提示：需要完整内容请用 grep/head/tail/sed 精确过滤后重跑。"""
    s = s or ""
    if len(s) <= budget:
        return s
    head = s[: int(budget * 0.7)]
    tail = s[-int(budget * 0.25):]
    return (f"{head}\n...[输出过长已截断：共 {len(s)} 字符，仅显示首尾。"
            f"如需完整内容，请用 grep/head/tail/sed 精确过滤后重跑，勿直接 dump 大文件]...\n{tail}")


def build_atkbrain_tools(ctx: AgentContext) -> list:
    @tool(
        "run_cmd",
        "在主机侧执行一条 shell 命令。这是唯一的命令执行通道（内置 Bash 已禁用）。",
        {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的 shell 命令"},
                "rationale": {"type": "string", "description": "为什么执行此命令（简述攻击意图）"},
                "timeout": {"type": "integer", "description": "超时秒数（可选；不传或 0 表示不限时）"},
            },
            "required": ["command"],
        },
    )
    async def run_cmd(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        command = args.get("command", "")
        rationale = args.get("rationale", "")
        timeout = args.get("timeout")
        await emit(ctx.project_id, "tool", {
            "tool": "run_cmd", "command": command, "rationale": rationale,
        }, run_id=ctx.run_id)
        res = await ctx.run_command(command, timeout=timeout)
        payload = {
            "tool": "run_cmd", "command": command,
            "exit_code": res.exit_code, "blocked": res.blocked,
            "reason": res.reason, "category": res.category,
            "stdout_preview": res.stdout[:1500], "stderr_preview": res.stderr[:800],
            "duration": getattr(res, "duration", None),
        }
        await emit(ctx.project_id, "tool_result", payload, run_id=ctx.run_id)
        try:
            from ..config import settings as _st
            dur = float(getattr(res, "duration", 0) or 0)
            limit = float(getattr(_st, "graph_idle_cmd_progress_sec", 60) or 60)
            if not res.blocked and int(res.exit_code or 1) == 0 and dur >= limit:
                ctx.last_local_progress_mono = time.monotonic()
        except Exception:
            pass
        if res.blocked:
            return _text(f"[已拦截 · {res.category}] {res.reason}", is_error=True)
        body = (
            f"exit_code={res.exit_code}  {res.duration}s\n"
            f"----- STDOUT -----\n{_clip(res.stdout, 22000)}\n"
            f"----- STDERR -----\n{_clip(res.stderr, 4000)}"
        )
        landed = await maybe_autoland_shell(ctx, body)
        if landed:
            body = body + f"\n[系统已根据远程 id 回显落定立足点 `{landed}`，关系图已更新。]"
        return _text(body)

    @tool(
        "http_request",
        "发起一次 HTTP 请求，用于探测与漏洞验证。内置 WebFetch 已禁用，请用本工具访问目标 Web。",
        {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "description": "GET/POST/PUT... 默认 GET"},
                "headers": {"type": "string", "description": "JSON 字符串形式的请求头（可选）"},
                "data": {"type": "string", "description": "请求体（可选）"},
            },
            "required": ["url"],
        },
    )
    async def http_request(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        url = args.get("url", "")
        method = args.get("method", "GET")
        headers = None
        if args.get("headers"):
            try:
                headers = json.loads(args["headers"])
            except Exception:
                headers = None
        data = args.get("data")
        await emit(ctx.project_id, "tool", {
            "tool": "http_request", "url": url, "method": method,
        }, run_id=ctx.run_id)
        res = await ctx.http(url, method=method, headers=headers, data=data)
        await emit(ctx.project_id, "tool_result", {
            "tool": "http_request", "url": url, "status": res.get("status"),
            "error": res.get("error"),
        }, run_id=ctx.run_id)
        if res.get("blocked"):
            return _text(res["error"], is_error=True)
        if res.get("error"):
            return _text(res["error"], is_error=True)
        touch = dict(res) if isinstance(res, dict) else {}
        touch.setdefault("url", url)
        touch.setdefault("method", method)
        if isinstance(data, str) and data:
            touch.setdefault("data", data)
        _schedule_touch_http(ctx, url, touch)
        hdr_str = "\n".join(f"{k}: {v}" for k, v in list(res.get("headers", {}).items())[:30])
        body = (
            f"HTTP {res.get('status')} ({res.get('engine')})\n"
            f"----- HEADERS -----\n{hdr_str}\n"
            f"----- BODY -----\n{res.get('body','')}"
        )
        landed = await maybe_autoland_shell(ctx, body)
        if landed:
            body = body + f"\n[系统已根据远程 id 回显落定立足点 `{landed}`，关系图已更新。]"
        return _text(body)

    @tool(
        "add_node",
        "向攻击图新增/更新一个节点（信息点/服务/危险点/漏洞/凭证/立足点）。用 key 做稳定标识可重复调用更新。"
        "本题只有一个黑色目标（授权入口）。内网 IP 用 type=info 或 service，不要 type=target。"
        "形成 target→service→info/danger→vuln 链：漏洞/危险点务必再 add_edge 从对应 service 或 info 连过来（LEADS_TO），不要只留 target 直连。",
        {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "项目内稳定唯一键，如 'svc:80/http' 或 'vuln:sqli-login'"},
                "type": {"type": "string", "enum": ["target", "info", "service", "danger", "vuln", "credential", "foothold", "honeypot", "goal"]},
                "title": {"type": "string", "description": "短标题。不要写「候选 RCE」；未拿到命令执行的就是漏洞"},
                "detail": {"type": "string", "description": "详细信息（证据/说明）"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "is_rce": {"type": "boolean", "description": "仅已拿到命令执行的 foothold/goal 为 true。漏洞、危险点不要设这个字段"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["key", "type", "title"],
        },
    )
    async def add_node(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        ntype = args.get("type", "info")
        tags = args.get("tags", []) or []
        from ..graph.model import agent_goal_reserved_error, coerce_goal_node_type
        reserved = agent_goal_reserved_error(args["key"], ntype, tags)
        if reserved:
            return _text(f"⛔ {reserved}", is_error=True)
        ntype = coerce_goal_node_type(args["key"], ntype, tags)
        text_parts = (args["key"], args.get("title"), args.get("detail"),
                      " ".join(str(t) for t in tags))
        # 平台控制面/旁路地址禁止写进攻击图。
        plat = _platform_graph_pollution(*text_parts)
        if plat:
            await emit(ctx.project_id, "log",
                       {"level": "warn", "message": f"平台自保护拦截 add_node：{plat}"},
                       run_id=ctx.run_id)
            return _text(f"⛔ {plat}。请只记录授权业务目标上的资产/漏洞。", is_error=True)
        # 横向 Scope 硬闸：只看节点身份（key / host: 标签），正文里的诱饵网段不拦已扩容主机。
        identity = (args["key"], " ".join(
            str(t) for t in tags if str(t).startswith("host:")
        ))
        oos = _out_of_scope_hosts(ctx, *identity)
        oos_ep = _out_of_scope_endpoints(ctx, *identity)
        if (oos or oos_ep) and getattr(ctx.scope, "mode", "strict") == "strict":
            hit = oos or oos_ep
            await emit(ctx.project_id, "log",
                       {"level": "warn",
                        "message": f"越界拦截：节点 {args['key']} 触碰非授权主机 {hit}，未写入攻击图。"},
                       run_id=ctx.run_id)
            return _text(
                f"⛔ 越界主机 {hit}：不在授权域名/IP 身份内，节点未记录。"
                f"（本题入口端口可以换路径；邻题端口即使同 IP 也越界。）",
                is_error=True,
            )
        confirmed_shell = (
            ntype in ("foothold", "goal")
            or str(args.get("key") or "").startswith(("goal:shell", "foothold:shell"))
            or "getshell" in {str(t).lower() for t in tags}
        )
        node = NodeIn(
            key=args["key"], type=ntype, title=args["title"],
            detail=args.get("detail"), severity=args.get("severity", "info"),
            is_rce=bool(args.get("is_rce", False)) and confirmed_shell, tags=tags,
        )
        row = await gstore.upsert_node(ctx.project_id, node, run_id=ctx.run_id)
        if ntype == "credential":
            _write_creds_asset(ctx, host=_primary_host(ctx) or "unknown",
                               title=args["title"], detail=args.get("detail") or "")
        return _text(f"节点已记录: {row['key']} ({row['type']}, {row['severity']}, risk={row['risk_score']})")

    @tool(
        "add_edge",
        "在攻击图两个节点间新增一条有向边，表达攻击链与该步成功概率(weight 0..1)。"
        "典型：target CONTAINS service；service/info LEADS_TO vuln；vuln EXPLOITS foothold。"
        "漏洞的 from 应为 service 或 info，不要用 target 直连 vuln。",
        {
            "type": "object",
            "properties": {
                "from": {"type": "string", "description": "源节点 key（漏洞请用 service/info，勿用 target）"},
                "to": {"type": "string", "description": "目标节点 key"},
                "relation": {"type": "string", "enum": ["LEADS_TO", "EXPLOITS", "ESCALATES_TO", "PIVOTS_TO", "CONTAINS"]},
                "weight": {"type": "number", "description": "该步成功概率 0..1，越高越可能通往 RCE"},
                "rationale": {"type": "string"},
            },
            "required": ["from", "to"],
        },
    )
    async def add_edge(args: dict) -> dict:
        relation = args.get("relation", "LEADS_TO")
        # 横向硬闸：PIVOTS_TO（踏上新主机）前校验授权边界
        if relation == "PIVOTS_TO":
            oos = _out_of_scope_hosts(ctx, args["from"], args["to"])
            if oos and getattr(ctx.scope, "mode", "strict") == "strict":
                await emit(ctx.project_id, "log",
                           {"level": "warn",
                            "message": f"越界拦截：PIVOTS_TO 触碰非授权主机 {oos}，未写入边。"},
                           run_id=ctx.run_id)
                return _text(
                    f"⛔ 越界：横向目标 {oos} 不在授权 Scope 内，边未记录。",
                    is_error=True,
                )
            if not await gstore.is_verified_lateral_pivot(ctx.project_id, args["from"], args["to"]):
                return _text(
                    "⛔ 未记录为内网横向：PIVOTS_TO 仅在已控 RCE/shell 踏上另一台"
                    "且目标主机已验证 shell/RCE 时成立。仅发现服务、SSRF 可达或拿到凭证请用 LEADS_TO。",
                    is_error=True,
                )
        edge = EdgeIn(
            **{"from": args["from"], "to": args["to"]},
            relation=relation,
            weight=float(args.get("weight", 0.5)),
            rationale=args.get("rationale"),
        )
        await gstore.add_edge(ctx.project_id, edge, run_id=ctx.run_id)
        if relation == "PIVOTS_TO":
            await _maybe_emit_lateral(ctx)
        return _text(f"边已记录: {args['from']} --{edge.relation}--> {args['to']} (w={edge.weight})")

    @tool(
        "report_finding",
        "上报一个漏洞。必须先验证真实性：evidence 或可复现 PoC 缺一不可，否则记为未验证。"
        "二次验证：独立再打一遍（换通道/重放 PoC/对照预期回显）后把 secondary_verified 设为 true。"
        "红队评级站在进攻侧：可打性、前置条件、稳定性、能否通向 GETSHELL/敏感数据；"
        "禁止因类别名高估，也禁止因「只读」低估任意文件读。须写 redteam_rating_rationale。"
        "红队完成条件是 getshell（report_shell）。finding 不单独收工。",
        {
            "type": "object",
            "properties": {
                "node_key": {"type": "string", "description": "关联的攻击图节点 key（可选）"},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "category": {"type": "string", "description": "如 rce/sqli/file_read/file_write/db_access/auth_bypass/unauth/admin_access/ssrf/xss/idor/info_disclosure..."},
                "title": {"type": "string", "description": "短标题。不要写「候选 RCE」"},
                "description": {"type": "string", "description": "漏洞说明：入口、可控参数、成因、危害，写给安全人员复现用"},
                "evidence": {"type": "string", "description": "真实性证据（完整请求/响应片段、命令输出，勿截断关键回显）"},
                "poc_curl": {"type": "string", "description": "可手工复现的 curl（真实请求，禁止占位）"},
                "poc_python": {"type": "string", "description": "可手工复现的 python"},
                "cvss": {"type": "number"},
                "secondary_verified": {
                    "type": "boolean",
                    "description": "是否已二次验证（独立再打一遍并对照预期）。仅一次观测则为 false",
                },
                "redteam_rating": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                    "description": "红队侧可利用评级，可与 severity/CVSS 不同",
                },
                "redteam_rating_rationale": {
                    "type": "string",
                    "description": "红队评级理由：为何是这个级别，避免高估或低估",
                },
                "proof_type": {
                    "type": "string",
                    "enum": ["write_txt", "poc_replay", "impact_extract"],
                    "description": "证明类型（可选）",
                },
                "proof_canary": {"type": "string", "description": "可选 canary"},
                "proof_url": {"type": "string", "description": "可选证明 URL"},
                "proof_detail": {"type": "string", "description": "可选证明详情"},
            },
            "required": ["severity", "category", "title"],
        },
    )
    async def report_finding(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        plat = _platform_graph_pollution(
            args.get("node_key"), args.get("title"), args.get("description"),
            args.get("evidence"), args.get("poc_curl"), args.get("poc_python"),
            args.get("proof_url"), args.get("proof_detail"),
        )
        if plat:
            await emit(ctx.project_id, "log",
                       {"level": "warn", "message": f"平台自保护拦截 report_finding：{plat}"},
                       run_id=ctx.run_id)
            return _text(f"⛔ {plat}。平台故障不是目标漏洞，请回到授权业务资产。",
                         is_error=True)
        f = FindingIn(
            node_key=args.get("node_key"), severity=args.get("severity", "medium"),
            category=args.get("category", "info"), title=args["title"],
            description=args.get("description"), evidence=args.get("evidence"),
            poc_curl=args.get("poc_curl"), poc_python=args.get("poc_python"),
            cvss=args.get("cvss"),
            proof_type=args.get("proof_type"), proof_canary=args.get("proof_canary"),
            proof_url=args.get("proof_url"), proof_detail=args.get("proof_detail"),
            secondary_verified=_truthy(args.get("secondary_verified")),
            redteam_rating=args.get("redteam_rating"),
            redteam_rating_rationale=args.get("redteam_rating_rationale"),
        )
        row = await gstore.add_finding(ctx.project_id, f, run_id=ctx.run_id)
        cat = (f.category or "").lower()
        if "cred" in cat or cat in ("password", "secret", "token", "key_leak"):
            _write_creds_asset(ctx, host=_primary_host(ctx) or "unknown",
                               title=f.title, detail=(f.evidence or f.description or ""))
        vs = ""
        sec = False
        rt = ""
        if isinstance(row, dict):
            row_sev = display_finding_severity(row)
            vs = str(row.get("verification_status") or "")
            sec = bool(row.get("secondary_verified"))
            rt = str(row.get("redteam_rating") or "")
        else:
            row_sev = display_finding_severity(f)
        extra = []
        if vs == "pending":
            extra.append("未验证（缺证据/PoC，请补真实性材料）")
        elif vs == "verified":
            extra.append("已验证")
        extra.append("已二次验证" if sec else "未二次验证")
        if rt:
            extra.append(f"红队评级 {rt}")
        tail = "；".join(extra)
        rt_note = " 红队请继续推进直至 report_shell。" if normalize_objective(ctx.objective) == REDTEAM else ""
        return _text(
            f"✅ 已入库发现: [{row_sev or f.severity}] {f.title} ({f.category})。"
            f"{' ' + tail + '。' if tail else ''}{rt_note}".rstrip()
        )

    @tool(
        "report_shell",
        "确认拿到目标命令执行权限时调用。附 evidence（如 id/whoami 输出）。"
        "红队赛道：report_shell 成功即完成本项目。横向新主机务必填 host。",
        {
            "type": "object",
            "properties": {
                "node_key": {"type": "string", "description": "达成 RCE 的立足点节点 key（可选）"},
                "access": {"type": "string", "description": "权限级别，如 www-data / root / admin"},
                "host": {"type": "string", "description": "该 shell 所在主机（IP/主机名）。横向到新主机时必填"},
                "channel": {"type": "string", "description": "通道类型，如 webshell/reverse-shell/ssh（可选）"},
                "reconnect": {"type": "string", "description": "复连方式（可选）"},
                "evidence": {"type": "string", "description": "证据：id/whoami 或命令输出"},
                "proof_canary": {"type": "string", "description": "可选"},
                "proof_url": {"type": "string", "description": "可选"},
                "proof_detail": {"type": "string", "description": "可选"},
            },
            "required": ["evidence"],
        },
    )
    async def report_shell(args: dict) -> dict:
        return await _land_shell(
            ctx,
            access=str(args.get("access") or ""),
            evidence=str(args.get("evidence") or ""),
            host=str(args.get("host") or ""),
            node_key=str(args.get("node_key") or ""),
            channel=str(args.get("channel") or ""),
            reconnect=str(args.get("reconnect") or ""),
            proof_canary=str(args.get("proof_canary") or ""),
            proof_url=str(args.get("proof_url") or ""),
            proof_detail=str(args.get("proof_detail") or ""),
        )

    @tool(
        "report_pivot_capability",
        "声明已核实的跳板能力：从 from_host 经 SSRF / 端口转发 / socks / DNS 等非 shell 通道，"
        "或经已有 shell 可达 to_host_or_ip。用于把内网资产加入 Scope。"
        "ssrf_*：后续 HTTP 必须把目标 URL 放进已验证 SSRF 参数，禁止 http_request 直连。"
        "必须提供可复现证据。mechanism 取 ssrf_direct / ssrf_gopher / ssrf_dns_rebind / "
        "port_forward / socks_tunnel / dns_leak / rdp_relay / smb_relay / shell_reachable。",
        {
            "type": "object",
            "properties": {
                "from_host": {"type": "string", "description": "已在 Scope 的跳板主机"},
                "to_host_or_ip": {"type": "string", "description": "跳板可触达的内网主机"},
                "mechanism": {"type": "string", "description": "通道类型"},
                "evidence": {"type": "string", "description": "复现证据（请求/响应/命令输出片段）"},
                "port": {"type": "integer", "description": "可选，记账用端口"},
            },
            "required": ["from_host", "to_host_or_ip", "mechanism", "evidence"],
        },
    )
    async def report_pivot_capability(args: dict) -> dict:
        from_host = _norm_host(args.get("from_host") or "")
        to_host = _norm_host(args.get("to_host_or_ip") or "")
        mechanism = (args.get("mechanism") or "").strip().lower()
        evidence = args.get("evidence") or ""
        if not from_host or not to_host or not mechanism or not evidence:
            return _text("参数不足：from_host / to_host_or_ip / mechanism / evidence 均必填。", is_error=True)
        blocked = _attacker_identity_reason(to_host)
        if blocked:
            return _text(f"拒绝：{blocked}", is_error=True)
        if not ctx.scope.host_in_scope(from_host):
            return _text(
                f"⛔ from_host={from_host} 不在授权 Scope 内，不能当跳板。"
                "内网资产必须从已授权目标上的立足点（shell/SSRF）看见。",
                is_error=True,
            )
        try:
            from ..scope_pivot import persist_scope, try_expand_scope
            res = await try_expand_scope(
                ctx.project_id, ctx.scope,
                from_host=from_host, to_host=to_host,
                mechanism=mechanism, evidence=evidence,
                verified=True,
                run_id=ctx.run_id, gstore=gstore,
            )
        except Exception as e:
            return _text(f"扩容失败：{e}", is_error=True)
        if not (res.get("expanded") or res.get("reason") == "already_in_scope"):
            hint = (
                " 这是同一场评测里其它题目的入口 IP，不是本题内网。"
                if res.get("reason") == "peer_challenge_entry" else
                " 公网/回环/本机无法加入；须从授权目标经 shell 或 SSRF 跳板核实。"
            )
            return _text(
                f"⛔ 未登记内网主机、未扩容 Scope（原因：{res.get('reason')}）。" + hint,
                is_error=True,
            )
        if res.get("expanded"):
            await persist_scope(ctx.project_id, ctx.scope)
        asset_key = ""
        try:
            asset_key = await gstore.ensure_host_target(
                ctx.project_id, to_host,
                title=f"内网主机 {to_host}",
                run_id=ctx.run_id,
            )
        except Exception:
            asset_key = ""
        primary = _primary_host(ctx)
        try:
            src = await gstore.find_pivot_source(ctx.project_id, from_host or primary)
        except Exception:
            src = ""
        if src and asset_key and src != asset_key:
            try:
                await gstore.add_edge(
                    ctx.project_id,
                    EdgeIn(**{"from": src, "to": asset_key}, relation="LEADS_TO",
                           weight=0.9,
                           rationale=f"pivot_capability {mechanism}: {evidence[:120]}"),
                    run_id=ctx.run_id,
                )
            except Exception:
                pass
        via_ssrf = mechanism.startswith("ssrf")
        return _text(
            f"✅ 已核实跳板能力（{mechanism}），内网主机 {to_host} 已加入 Scope（授权打它）。"
            + (
                f" mechanism={mechanism} 属于 SSRF 跳板：攻击机网卡通常到不了该网段，"
                f"后续请把 HTTP(S) URL 放进已验证 SSRF 入口的参数，禁止 http_request 直连 {to_host}。"
                if via_ssrf else
                f" 后续可通过已建隧道或 shell 访问 {to_host}。"
            )
        )

    @tool(
        "report_flag",
        "当你拿到目标 flag（形如 flag{...} 或题目要求的答案）时调用。多 flag 题请逐个上报。",
        {
            "type": "object",
            "properties": {
                "flag": {"type": "string", "description": "flag 值（原样，勿加引号/多余空白）"},
                "flag_index": {"type": "integer", "description": "多 flag 题的序号（可选）"},
                "node_key": {"type": "string", "description": "拿到 flag 的直接来源节点（漏洞/服务/shell），应尽量填写"},
                "host": {"type": "string", "description": "flag 所在主机"},
                "evidence": {"type": "string", "description": "从哪/如何拿到"},
            },
            "required": ["flag"],
        },
    )
    async def report_flag(args: dict) -> dict:
        if not objective_allows_flag(ctx.objective):
            return _text(
                "本项目为红队赛道，不夺旗。请用 report_shell / report_finding 上报。",
                is_error=True,
            )
        flag = (args.get("flag") or "").strip()
        if not flag:
            return _text("flag 为空。", is_error=True)
        if any(str(x.get("value") or "").strip() == flag for x in (ctx.flags_captured or [])):
            return _text(f"该 flag 已记录。当前进度 {ctx.flags_correct}/{ctx.flags_needed}。")
        idx = args.get("flag_index")
        submitted = correct = False
        awarded = 0.0
        duplicate = False
        has_bm = bool(ctx.benchmark and ctx.benchmark.get("unique_code") and ctx.project)
        if has_bm:
            res = await bm.submit_flag(ctx.project, flag)
            submitted = True
            if res.get("error"):
                if res.get("duplicate"):
                    duplicate = True
                else:
                    await emit(ctx.project_id, "flag",
                               {"value": flag[:80], "correct": False, "error": res.get("error"),
                                "message": res.get("message")}, run_id=ctx.run_id)
                    return _text(f"提交失败[{res.get('error')}]: {res.get('message')}", is_error=True)
            else:
                correct = bool(res.get("correct"))
                awarded = float(res.get("awarded") or 0)
                if res.get("matched_flag_index") is not None:
                    idx = res.get("matched_flag_index")
                if res.get("correct_flag_count") is not None:
                    ctx.flags_correct = int(res["correct_flag_count"])
                if res.get("total_flag_count"):
                    ctx.flags_needed = int(res["total_flag_count"])
        else:
            correct = True
        if not has_bm and correct:
            ctx.flags_correct += 1
        if duplicate:
            await emit(ctx.project_id, "flag",
                       {"value": flag[:120], "correct": True, "previously_accepted": True,
                        "duplicate": True, "awarded": 0, "flag_index": idx,
                        "progress": f"{ctx.flags_correct}/{ctx.flags_needed}"},
                       run_id=ctx.run_id)
            return _text(
                f"该 flag 此前已被平台接受；本次为重复（+0），未新增本地进度。"
                f"当前 {ctx.flags_correct}/{ctx.flags_needed}。"
            )
        if not correct:
            await emit(ctx.project_id, "flag",
                       {"value": flag[:120], "correct": False, "awarded": 0, "flag_index": idx},
                       run_id=ctx.run_id)
            return _text("平台判定该 flag 不正确。", is_error=True)
        ctx.flags_captured.append({"value": flag, "correct": True, "awarded": awarded, "flag_index": idx})
        try:
            await db.execute(
                """INSERT INTO flags(id, project_id, unique_code, flag_index, value,
                       submitted, correct, awarded, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    new_id("fl_"), ctx.project_id,
                    (ctx.benchmark or {}).get("unique_code") or (str(idx) if idx is not None else None),
                    idx, flag, 1 if submitted else 1, 1, awarded, now(),
                ),
            )
        except Exception:
            pass
        gkey = f"goal:flag:{idx if idx is not None else len(ctx.flags_captured)}"
        host = _norm_host(args.get("host") or "") or ctx.active_host or _primary_host(ctx)
        source_key = (args.get("node_key") or "").strip()
        if not source_key and host:
            source_key = await gstore.find_host_source(ctx.project_id, host)
        await gstore.upsert_node(
            ctx.project_id,
            NodeIn(key=gkey, type="goal", title=f"FLAG {flag[:48]}",
                   detail=args.get("evidence") or flag, severity="critical",
                   tags=["flag", "getflag", *([f"host:{host}"] if host else [])]),
            run_id=ctx.run_id,
        )
        if source_key:
            await gstore.add_edge(
                ctx.project_id,
                EdgeIn(**{"from": source_key, "to": gkey}, relation="LEADS_TO",
                       weight=1.0, rationale="getflag"),
                run_id=ctx.run_id,
            )
        elif host:
            target_key = await gstore.ensure_host_target(
                ctx.project_id, host, title=f"主机 {host}", run_id=ctx.run_id,
            )
            if target_key:
                await gstore.add_edge(
                    ctx.project_id,
                    EdgeIn(**{"from": target_key, "to": gkey}, relation="LEADS_TO",
                           weight=0.9, rationale="getflag"),
                    run_id=ctx.run_id,
                )
        await emit(ctx.project_id, "flag",
                   {"value": flag[:120], "correct": True, "awarded": awarded, "flag_index": idx,
                    "host": host, "node_key": (args.get("node_key") or "").strip(),
                    "progress": f"{ctx.flags_correct}/{ctx.flags_needed}"}, run_id=ctx.run_id)
        cfg = (ctx.project or {}).get("config") or {}
        full = ctf_full_score(
            flags_correct=ctx.flags_correct,
            flags_needed=ctx.flags_needed,
            flag_count=cfg.get("flag_count"),
            flags_score=awarded_sum(ctx.flags_captured),
            total_score=cfg.get("total_score"),
        )
        extra_ms = dict(
            title=f"FLAG {flag[:48]}",
            category="getflag",
            node_key=args.get("node_key") or "",
            evidence=(args.get("evidence") or "")[:400],
        )
        if full:
            ctx.goal_reached = True
            await persist_milestone(ctx, "getflag", **extra_ms)
            try:
                asyncio.get_running_loop().create_task(request_full_score_stop(ctx))
            except Exception:
                pass
            return _text(f"本题 flag 已齐 {ctx.flags_correct}/{ctx.flags_needed}，立即收工换题。")
        _schedule_milestone(ctx, "getflag", **extra_ms)
        return _text(
            f"flag 已记录且得分。未齐，继续夺取剩余 flag（{ctx.flags_correct}/{ctx.flags_needed}）。"
        )

    @tool(
        "propose_intents",
        "登记接下来要尝试的攻击方向（开放意图）。当前路径受阻或需要并行探索多条路径时使用；"
        "每条尽量正交、可独立推进。",
        {
            "type": "object",
            "properties": {
                "intents": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from": {"type": "array", "items": {"type": "string"}},
                            "description": {"type": "string"},
                            "rationale": {"type": "string"},
                            "est_success": {"type": "number"},
                        },
                        "required": ["description"],
                    },
                }
            },
            "required": ["intents"],
        },
    )
    async def propose_intents(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        intents = args.get("intents", []) or []
        n = 0
        for it in intents:
            desc = it.get("description", "") or ""
            # 人工意图也尽量带上可去重 strategy_key
            sk = it.get("strategy_key")
            if not sk and desc:
                from ..graph.hypothesize import strategy_key
                src = (it.get("from") or ["manual"])[0]
                sk = strategy_key(str(src), f"manual:{desc[:48]}")
            await gstore.add_intent(
                ctx.project_id,
                IntentIn(
                    **{"from": it.get("from", [])},
                    description=desc,
                    rationale=it.get("rationale"),
                    est_success=float(it.get("est_success", 0.5)),
                    strategy_key=sk,
                    priority=float(it.get("priority") or it.get("est_success", 0.5)),
                ),
                run_id=ctx.run_id,
            )
            n += 1
        return _text(f"已登记 {n} 条开放意图（与系统前沿合并去重）。")

    @tool(
        "resolve_intent",
        "关闭一条推理前沿 Intent：短验证成功则 verified，失败/无效则 disproved。"
        "同一证据组合失败后不要重复死磕；有新证据时可再 propose 或等系统复开。",
        {
            "type": "object",
            "properties": {
                "intent_id": {"type": "string", "description": "Intent ID（如 i_xxxx）"},
                "verified": {"type": "boolean", "description": "true=验证成功；false=否证/无效"},
                "summary": {"type": "string", "description": "简短结果摘要/失败原因"},
                "failure_fingerprint": {
                    "type": "string",
                    "description": "可选：失败指纹（路径+手法+关键参数），用于阻止同证据重复",
                },
            },
            "required": ["intent_id", "verified"],
        },
    )
    async def resolve_intent(args: dict) -> dict:
        halted = halt_if_full_score(ctx)
        if halted:
            return halted
        refused = refuse_disprove_bound_must(
            ctx, args.get("intent_id"), bool(args.get("verified")),
        )
        if refused:
            return _text(refused, is_error=True)
        row = await gstore.resolve_intent(
            ctx.project_id,
            args["intent_id"],
            verified=bool(args.get("verified")),
            summary=args.get("summary"),
            failure_fingerprint=args.get("failure_fingerprint") or args.get("summary"),
            run_id=ctx.run_id,
        )
        if not row:
            return _text(f"未找到 Intent: {args['intent_id']}")
        return _text(f"Intent {row['id']} → {row['status']} ({row.get('result_summary') or ''})")

    @tool(
        "mark_honeypot",
        "标记一个疑似蜜罐/反制点。命中后该分支会被降权，且其中的文件禁止执行（仅静态分析）。",
        {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "title": {"type": "string"},
                "evidence": {"type": "string"},
            },
            "required": ["key", "title"],
        },
    )
    async def mark_honeypot(args: dict) -> dict:
        await gstore.upsert_node(
            ctx.project_id,
            NodeIn(key=args["key"], type="honeypot", title=args["title"],
                   detail=args.get("evidence"), severity="info", tags=["honeypot", "anti-reprisal"],
                   status="quarantined"),
            run_id=ctx.run_id,
        )
        await emit(ctx.project_id, "log", {"level": "warn", "message": f"⚠️ 疑似蜜罐: {args['title']}（该分支已降权、禁执行其文件）"}, run_id=ctx.run_id)
        return _text("已标记蜜罐并降权该分支。切勿运行其中任何文件。")

    @tool(
        "note",
        "记录一条思考/进展说明，展示在时间线（不落库为漏洞）。",
        {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
                "level": {"type": "string", "enum": ["info", "warn", "debug"]},
            },
            "required": ["message"],
        },
    )
    async def note(args: dict) -> dict:
        await emit(ctx.project_id, "thought", {"message": args["message"], "level": args.get("level", "info")}, run_id=ctx.run_id)
        return _text("ok")

    tools = [
        run_cmd, http_request, add_node, add_edge, report_finding,
        report_shell, report_pivot_capability, propose_intents, resolve_intent, mark_honeypot, note,
    ]
    if objective_allows_flag(ctx.objective):
        tools.insert(6, report_flag)
    return tools


def build_server(ctx: AgentContext):
    return create_sdk_mcp_server(SERVER_NAME, "1.0.0", tools=build_atkbrain_tools(ctx))


def tool_names(objective: str | None = None) -> list[str]:
    names = ["run_cmd", "http_request", "add_node", "add_edge", "report_finding",
             "report_shell", "report_pivot_capability", "propose_intents",
             "resolve_intent", "mark_honeypot", "note"]
    # 仅 flag 赛道声明 report_flag。
    if objective is None or objective_allows_flag(objective):
        names.insert(6, "report_flag")
    return [f"mcp__{SERVER_NAME}__{n}" for n in names]
