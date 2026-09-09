"""顾问方案 → 局面绑定 + 参考假说。赛道无关：不看 objective，只看调用方传入的图状态。

局面（situation）由图编译，从者必须守：未消费凭证、未关输入面、已验证洞、跳板/邻题禁令。
御主 next_plan / must_intents 是参考假说：排到前沿最前，不独占认领，也不因未点名 Intent 判违约。
违背局面（入口枚举、离开已验证洞/跳板）才收紧禁令。
"""
from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field, replace


# 入口枚举/定性。web_inject 是打洞，不进这里，否则收紧绑定会把测→证禁掉。
ENTRY_ENUM_TACTICS: frozenset[str] = frozenset({
    "fingerprint", "auth_surface", "content_enum",
})
WEAPONIZE_TACTICS: tuple[str, ...] = (
    "weaponize", "impact_escalate", "finding_rce_close", "finding_sqli_chain",
)
# 已验证资产、尚未立足：must 至少留一格「收成执行」，避免三格都是读面加深。
# channel_oracle 是证明通道，不是收口；不要占这一格。
_CHAIN_CLOSE_RESERVE: tuple[str, ...] = (
    "weaponize", "impact_escalate", "finding_rce_close", "ssrf_as_gateway",
    "finding_sqli_chain",
)
_LOOT_DEEPEN_TACTICS: frozenset[str] = frozenset({
    "file_read_chain", "finding_read_loot", "filter_bypass",
})
# 已验证之后再打这些 = 重新证明 / 回头扫入口，不是抽取，也不是对其它活体面的新验证。
_CLOSE_SIDETRACK: frozenset[str] = frozenset({
    "channel_oracle", "fingerprint", "api_contract", "graphql_contract",
    "content_enum", "protocol_model",
})
# 已有可消耗洞时，其余格仍可并行验证这些活体面（不是目录枚举）。
_CYCLE_VERIFY_TACTICS: frozenset[str] = frozenset({
    "web_inject", "auth_surface", "access_control", "upload_bypass",
    "restricted_deserialize", "input_abuse", "business_logic", "nday",
})
# 未验证：路线包自动补齐的正交 tactic（不是目录爆破，也不是三条同义复述）。
_EXPLORE_FILL: tuple[str, ...] = (
    "channel_oracle", "input_abuse", "web_inject", "access_control",
    "file_read_chain", "info_to_danger",
)
# 图上已开放时，must 至少留一格：测→证，不是再写 info。
# file_read_chain 也是打洞：有凭证+文件/下载面时不要被 html_sink / 登录注入挤掉。
_HUNT_LIVE_TACTICS: tuple[str, ...] = (
    "web_inject", "input_abuse", "access_control", "upload_bypass",
    "file_read_chain", "html_sink", "restricted_deserialize", "info_to_danger",
    "business_logic", "nday",
)
# 已有可用凭证、尚未立足：优先消费会话，而不是回头打登录表单反射/注入。
_CONSUME_SESSION_FRONT: tuple[str, ...] = (
    "secret_mount", "file_read_chain", "auth_reuse", "access_control", "priv_enum",
)
EXPLORE_REFRESH_TACTICS: tuple[str, ...] = _EXPLORE_FILL + (
    "fingerprint", "filter_bypass", "web_inject",
)
_EXPLORE_SUBAGENTS: tuple[str, ...] = ("web-exploit", "recon")
_HUNT_TASK_SUBAGENTS: frozenset[str] = frozenset({"web-exploit", "src-hunt"})
# 这些战术可以并行，但不能占满 must 三格（HTTP 活体至少留一格打洞）。
_ENUM_FILL_TACTICS: frozenset[str] = frozenset({
    "fingerprint", "protocol_model", "content_enum", "auth_surface",
})
HUNT_TASK_NOTE = (
    "局面：HTTP 活体本轮必须 Agent(subagent_type=web-exploit, run_in_background=true) "
    "或 Task(subagent_type=web-exploit) 并行测→证；禁止省略 subagent_type 的通用 Agent，"
    "禁止主会话 curl/http_request 代替。不限定必须是御主点名的那一条注入。"
    "静态 SPA、同源 API=0、只有 JS 外域名单，都不是无攻击面：打同入口参数/路由/Cookie/鉴权。"
    "info 节点不是战果。"
)
SITUATION_CONSUME = (
    "【局面·已有凭证】必须消费该会话打后认证功能面。"
    "图上若有下载/附件/文件路径类信息点，优先文件读或越权；"
    "禁止回头只打登录表单注入或 HTML 反射。"
)
SITUATION_SECRET = (
    "【局面·未挂载密钥】图上已有机器密钥且尚未出现 401/403 挂载点。"
    "必须在已验证跳板到达的同一服务上做有/无密钥差分（查询参数、请求头、Cookie、body）。"
    "浅层路径 404 只否证这一条路径，不关闭密钥、也不等于无挂载点。"
    "禁止因为猜测路径 404 就转去旁路网段或其它容器端口。"
)
SITUATION_PLACEHOLDER = (
    "【局面·占位输出】校验通过但 stdout 固定占位（点号/denied/complete）不是答案，"
    "也不等于 VM/算法是诱饵。按本题入口已出现的运算与数据取循环末态或真实出口，立刻 report_flag。"
    "禁止把占位仿真写成诱饵/链已死，禁止用 flag 格式串拟合。"
)
SITUATION_EXEC = (
    "【局面·已验证执行面】握手、版本探测、可 attach、可注入不等于已经拿到命令执行。"
    "必须把该能力消耗到一次命令执行（report_shell 或可回读的执行证据）。"
    "一种客户端形态或一次调用失败不关闭整面；换正交调用方式，不要回头做协议转储或入口指纹。"
)
_SITUATION_PROTECT_TACTICS: frozenset[str] = frozenset({
    "channel_oracle", "weaponize", "impact_escalate", "finding_rce_close",
    "finding_sqli_chain", "ssrf_as_gateway", "secret_mount", "reverse_binary",
})
CYCLE_HUNT_NOTE = (
    "挖洞循环：已验证洞不收工。至少一格继续测其它类型并独立 report_finding；"
    "禁止 GETSHELL / 横向 / 提权收工。不要把整猎收成一条利用链。"
)
_CYCLE_HUNT_DENY: tuple[str, ...] = (
    "hop_auth", "privesc_lateral", "ssrf_as_gateway", "flag_hunt",
)
_CLOSEOUT_STALLS: frozenset[str] = frozenset({"chain", "postex"})
# 单轮墙钟让出门闩放过这些：正在做长验证/收成，不要用短墙钟打断本轮。
# 与 closeout sidetrack 不同：channel_oracle 对顾问是再证明，但对御主可能是长 SLEEP。
_KEEP_TURN_TACTICS: frozenset[str] = frozenset({
    "weaponize", "impact_escalate", "finding_rce_close", "finding_sqli_chain",
    "ssrf_as_gateway", "upload_bypass", "file_read_chain", "hop_auth",
    "finding_authz_expand", "finding_read_loot", "flag_or_privesc",
    "auth_reuse", "priv_enum", "privesc_lateral", "svc_auth_bruteforce",
    "ssrf_local_svc", "read_to_creds", "info_to_cred",
    "graphql_contract", "api_contract", "protocol_model", "reverse_binary", "channel_oracle",
    "filter_bypass", "restricted_deserialize",
    # 未验证参数面：耗时/长度差分往往超过让出门闩；有方案后不要掐死。
    "web_inject", "input_abuse",
    "business_logic", "nday",
})
_SQLI_CATS = frozenset({"sqli", "db_access", "sql_injection", "sql-injection"})
_SSRF_CATS = frozenset({"ssrf", "ssrf_internal"})
_EXEC_CATS = frozenset({
    "rce", "command_injection", "deserialization", "ssti",
    "file_upload", "file_write",
})
_READ_CATS = frozenset({"file_read", "lfi", "arbitrary_file_read"})
_TOKEN_CATS = frozenset({"token", "jwt", "signed_token", "jws", "jwe"})
_AUTH_CATS = frozenset({"auth_bypass", "authz", "unauth", "idor"})
# 顾问散文若还在「再证明 / 假关闭 / 离开跳板」，覆盖进绑定，不写某题 payload。
CLOSEOUT_OVERRIDE = (
    "【收口覆盖·消耗已验证能力】禁止再证明同一面。"
    "一种键名或算法失败不等于整面关闭。"
    "过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类，不要用同族变体占下一步。"
    "一种观测类已证明可利用：先换成回显/联合/报错/状态差分等更快证明类，打成控制流或会话；"
    "同一耗时通道按位抽取只是退路，不要把它问到底。"
    "下一步抽取、过门或投递执行。"
    "客户端字段名不是后端契约；错误正文点名缺字段说明通道还活着。"
    "已验证跳板不要改成从本机打内网。"
    "少数令牌变体失败不关闭密码学或鉴权类。"
    "浅层路径 404 不关闭未挂载密钥；换查询参数/请求头/Cookie/body，不要转去旁路网段。"
    "握手/版本/可 attach 不是命令执行：已验证调试或注入能力必须消耗到一次执行证据。"
    "一种客户端形态失败不关闭整面，不要改回协议转储。"
)
GADGET_KEEP = (
    "【跳板仍活】一种 4xx 或否证笔记不等于跳板已死。"
    "禁止从本机打内网面。按错误正文换键。"
    "过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。"
)
ORACLE_KEEP = (
    "【硬约束·输入面未关】状态码/正文无差异只否证这一类观测，不关闭输入面。"
    "换通道 = 同一 URL、同一参数，换观测（耗时/长度/响应头/副作用）。"
    "另一个路由因为允许 POST/JSON，不是换通道，禁止写成主线或「唯一可写面」。"
    "路线包必须并行：同一输入面换耗时/长度/响应头/副作用通道，加上该面的可控输入；"
    "至多再留一条其它正交面，且不能挤掉未关闭的输入面。"
    "禁止把该面写成已闭合/dos，禁止仅当其它路线无果才回来打。"
    "同一状态码再采样、换 Host/方法但仍以状态码判死，都不算换通道；"
    "必须对同一输入的两次提交比对耗时差/长度差/头差/副作用。"
)
ORACLE_DIAG = (
    "一种观测失败不等于输入面关闭。"
    "恒定状态码/正文只否证这一类通道；输入面仍开放。"
    "必须在同一 URL、同一参数上换耗时/长度/响应头/副作用通道。"
    "禁止把另一个允许 POST 的路由当成换通道或唯一可写面。"
    "禁止把该面写成已闭合/dos，禁止把其它面当主线。"
)
_ORACLE_FALSE_CLOSE_RE = re.compile(
    r"已收口|已闭合|输入无关(?:崩溃|延迟|耗时)?|无条件崩溃|"
    r"通道级否证|确定性\s*500|死面|"
    r"离开.{0,16}(?:登录|/login)|"
    r"零翻面.{0,12}收口|视图未处理|该面(?:已死|关闭)|面已关|"
    r"(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|"
    r"仅当.{0,24}无果|主线无果|失败后才(?:回来|再打)|"
    r"唯一可写|唯一允许\s*POST|"
    r"优先打.{0,40}唯一|"
    r"另一(?:个|条).{0,16}(?:可写|POST)|"
    r"优先打.{0,32}(?:其它|其他|另一).{0,20}(?:路由|路径|接口|功能面)",
    re.I,
)
_PREMATURE_TIMING_BAN_RE = re.compile(r"耗时|校准", re.I)
_REPROVE_RE = re.compile(
    r"channel_oracle|校准耗时|再校准|重新验证(?:注入|时间差|盲注)|"
    r"LOAD_FILE\s*\(|INTO\s+(?:OUTFILE|DUMPFILE)|secure_file_priv|"
    r"再打一次oracle|用oracle再",
    re.I,
)
_FALSE_CLOSE_RE = re.compile(
    r"(?:攻击面|伪造面|注入面|通道|入口|网关|接口|令牌面).{0,16}"
    r"(?:关闭|已死|否证|穷尽|存根)|"
    r"判定为存根|当(?:成|作)存根|\bstub\b|"
    r"(?:JWT|令牌|签名|alg).{0,20}(?:关闭|已否证|失败即结束)",
    re.I,
)
_LEAVE_BRIDGE_RE = re.compile(
    r"(?:直连|从攻击机|从\s*Kali).{0,32}"
    r"(?:内网|127\.0\.0\.1|localhost|回环)|"
    r"改打(?:内网|直连)|离开跳板|不用跳板|绕过跳板|改打不可达",
    re.I,
)
_LEAVE_VERIFIED_RE = re.compile(
    r"去扫目录|静态收口|扫静态|静态目录|raft\s*大表|"
    r"再枚举入口|目录枚举|content_enum",
    re.I,
)
_WRAP_SAME_FORM_RE = re.compile(
    r"给同一形态加包装|同族变体|同形态再试|编码变体",
    re.I,
)
_ABANDON_SECRET_RE = re.compile(
    r"停止在.{0,48}(?:token|令牌).{0,16}载体|"
    r"停止.{0,24}(?:token|令牌).{0,12}矩阵|"
    r"改用图上.{0,24}未消费|"
    r"(?:改去|改为|改用).{0,32}(?:端口测绘|旁路网段|其它容器|其他容器)",
    re.I,
)
_DECOY_FALSE_CLOSE_RE = re.compile(
    r"\bdecoy\b|纯诱饵|当(?:成|作)诱饵|"
    r"(?:VM|解释器|字节码).{0,24}(?:诱饵|无用|无关)|"
    r"只输出.{0,12}(?:点号|点|\.|denied).{0,12}(?:诱饵|无关|无用)",
    re.I,
)
# 立足后：未授权/读链/其它协议先于 hop_auth，避免三格都被「过门」占满。
POSTEX_TACTICS: tuple[str, ...] = (
    "access_control", "file_read_chain", "svc_auth_bruteforce",
    "ssrf_as_gateway", "privesc_lateral", "weaponize", "auth_reuse",
    "hop_auth", "protocol_model", "reverse_binary",
)
# 图上若已有这些 Intent，must 至少留一格（与 hop_auth 并行，不是备选叙事）。
_POSTEX_RESERVE: tuple[str, ...] = (
    "access_control", "file_read_chain", "ssrf_as_gateway", "svc_auth_bruteforce",
)
_ORACLE_QUALITY = frozenset({"flag", "finding", "capability_edge"})
_DENY_ALIASES: dict[str, tuple[str, ...]] = {
    "content_enum": ("content_enum", "目录枚举", "目录爆破", "dirb", "dirbuster"),
    "fingerprint": ("fingerprint",),
    "web_inject": ("web_inject",),
    "auth_surface": ("auth_surface", "登录爆破"),
    "flag_hunt": ("flag_hunt", "flag-hunt"),
    "filter_bypass": ("filter_bypass", "同族变体", "编码变体", "加包装"),
}
_ENTRY_REFLUX_RE = re.compile(
    r"目录枚举|目录爆破|content_enum|扫(?:一遍)?目录|回头打入口|再打入口",
    re.I,
)


def intent_tactic(intent: dict | None) -> str:
    sk = str((intent or {}).get("strategy_key") or "")
    return sk.split("::")[-1] if "::" in sk else sk


def situation_protected_intent_ids(
    binding: AdvisorBinding | None,
    open_intents: list[dict] | None,
) -> frozenset[str]:
    """仅局面战术（换通道/收口）在无证据时不可否证；参考假说可以否证。"""
    if binding is None:
        return frozenset()
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id")
    }
    out: list[str] = []
    for iid in binding.must_intents or []:
        tac = intent_tactic(by_id.get(str(iid) or "") or {})
        if tac in _SITUATION_PROTECT_TACTICS:
            out.append(str(iid))
    return frozenset(out)


def _hypo_is_canned_keep(text: str) -> bool:
    t = (text or "").strip()
    if not t:
        return False
    for c in (ORACLE_KEEP, CLOSEOUT_OVERRIDE, GADGET_KEEP, SITUATION_PLACEHOLDER, SITUATION_EXEC):
        if t == c or t.startswith(c):
            return True
    return False


def _closeout_hypo_fallback(
    hypo: str,
    *,
    invert_ops: bool = False,
    chain_close: bool = False,
    live_gadget: bool = False,
) -> str:
    """违规散文可以丢掉，但不能把收口方案留空。"""
    if (hypo or "").strip():
        return hypo
    if invert_ops:
        return SITUATION_PLACEHOLDER
    if chain_close:
        return CLOSEOUT_OVERRIDE
    if live_gadget:
        return GADGET_KEEP
    return hypo


def _deny_http_protocol_model(
    *,
    invert_ops: bool,
    has_http_service: bool,
    open_tacs: set[str],
    cats: frozenset[str],
    chain_close: bool,
) -> bool:
    """HTTP JSON 面、占位反演、已验证执行面：协议转储不是主线。不写某题客户端。"""
    if invert_ops:
        return True
    if chain_close and (cats & _EXEC_CATS):
        return True
    if has_http_service and "reverse_binary" not in open_tacs:
        return True
    return False


@dataclass
class AdvisorBinding:
    """一轮（可跨 hold 窗口）的局面硬约束 + 参考假说。"""
    diagnosis: str = ""
    next_plan: str = ""
    situation: str = ""
    must_intents: list[str] = field(default_factory=list)
    prefer_tactics: list[str] = field(default_factory=list)
    deny_tactics: list[str] = field(default_factory=list)
    ban_repeats: list[str] = field(default_factory=list)
    subagents: list[str] = field(default_factory=list)
    stall: str = "none"
    misses: int = 0
    tightened: bool = False
    cycle_hunt: bool = False

    @property
    def fingerprint(self) -> str:
        return "|".join((
            self.stall or "",
            ",".join(sorted(self.must_intents)[:3]),
            ",".join(sorted(self.prefer_tactics)[:6]),
            ",".join(sorted(self.deny_tactics)[:8]),
        ))


def _uniq(seq: list[str] | None, *, limit: int) -> list[str]:
    out: list[str] = []
    for x in seq or []:
        s = str(x or "").strip()
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _pick_must(
    open_intents: list[dict] | None,
    *,
    prefer: list[str],
    deny: list[str],
    already: list[str],
    limit: int = 3,
    allow: set[str] | frozenset[str] | None = None,
) -> list[str]:
    deny_set = set(deny)
    prefer_set = set(prefer)
    allow_set = set(allow) if allow else None
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id") and str(it.get("status") or "open") not in ("deferred", "disproved")
    }
    picked: list[str] = []
    seen_tac: set[str] = set()

    def _try(iid: str) -> None:
        if not iid or iid in picked or iid not in by_id:
            return
        tac = intent_tactic(by_id[iid])
        if tac in deny_set or (tac and tac in seen_tac):
            return
        if allow_set is not None and tac and tac not in allow_set:
            return
        picked.append(iid)
        if tac:
            seen_tac.add(tac)

    for iid in already:
        _try(iid)
        if len(picked) >= limit:
            return picked
    ordered = list(by_id.values())
    if prefer:
        rank = {t: i for i, t in enumerate(prefer)}
        ordered.sort(key=lambda it: rank.get(intent_tactic(it), 10_000))
    for it in ordered:
        if intent_tactic(it) in deny_set:
            continue
        if prefer_set and intent_tactic(it) not in prefer_set:
            continue
        _try(str(it.get("id") or ""))
        if len(picked) >= limit:
            break
    if len(picked) < limit and allow_set is None:
        for it in ordered:
            _try(str(it.get("id") or ""))
            if len(picked) >= limit:
                break
    return picked[:limit]


def _reserve_open_tactics(
    picked: list[str],
    open_intents: list[dict] | None,
    *,
    reserve: tuple[str, ...],
    deny: list[str],
    limit: int = 3,
    exclusive: bool = False,
) -> list[str]:
    """must 已满时仍给正交面留一格。

    未验证阶段由 _fill_explore_bundle 凑齐路线包；exclusive 只用于活跳板、尚未验证可利用时。
    """
    deny_set = set(deny)
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id") and str(it.get("status") or "open") not in ("deferred", "disproved")
    }
    have = {intent_tactic(by_id[i]) for i in picked if i in by_id}
    extra = ""
    if not (have & set(reserve)):
        for want in reserve:
            if want in deny_set or want in have:
                continue
            for iid, it in by_id.items():
                if intent_tactic(it) == want:
                    extra = iid
                    break
            if extra:
                break
    reserved = [
        i for i in picked
        if i in by_id and intent_tactic(by_id[i]) in set(reserve)
    ]
    lead = ([extra] if extra else []) + reserved
    rest = [i for i in picked if i not in lead]
    if exclusive:
        rest = [
            i for i in rest
            if i in by_id and intent_tactic(by_id[i]) in set(reserve)
        ]
    out: list[str] = []
    seen_tac: set[str] = set()
    for iid in lead + rest:
        if iid not in by_id or iid in out:
            continue
        tac = intent_tactic(by_id[iid])
        if tac in deny_set or (tac and tac in seen_tac):
            continue
        out.append(iid)
        if tac:
            seen_tac.add(tac)
        if len(out) >= limit:
            break
    return out[:limit]


def graph_has_http_service(graph: dict | None) -> bool:
    """图上是否已有 HTTP 服务节点（不看赛道）。"""
    for n in (graph or {}).get("nodes") or []:
        if str(n.get("type") or "") != "service":
            continue
        key = str(n.get("key") or "").lower()
        tags = n.get("tags") or []
        if not isinstance(tags, (list, tuple, set)):
            tags = []
        tagset = {str(t).lower() for t in tags}
        blob = f"{key} {n.get('title') or ''} {n.get('detail') or ''}".lower()
        if "http" in key or "http" in tagset or "https" in blob or "/http" in key:
            return True
    return False


def _http_service_anchor(open_intents: list[dict] | None) -> str:
    for it in open_intents or []:
        sk = str(it.get("strategy_key") or "")
        prefix = sk.rsplit("::", 1)[0] if "::" in sk else sk
        low = prefix.lower()
        if prefix.startswith(("svc:", "service:", "http:")) or "http" in low:
            return prefix
    return "svc:http"


def _ensure_http_hunt_intent(
    open_intents: list[dict] | None, *, has_http: bool,
) -> list[dict]:
    """HTTP 活体但没有打洞 Intent 时，往本轮编译副本插入一条 web_inject。"""
    intents = list(open_intents or [])
    if not has_http:
        return intents
    live = [
        it for it in intents
        if str(it.get("status") or "open") not in ("deferred", "disproved")
    ]
    if {intent_tactic(it) for it in live} & set(_HUNT_LIVE_TACTICS):
        return intents
    anchor = _http_service_anchor(live)
    iid = f"i_bind_hunt:{anchor}"
    if any(str(it.get("id") or "") == iid for it in intents):
        return intents
    intents.append({
        "id": iid,
        "strategy_key": f"{anchor}::web_inject",
        "status": "open",
        "description": f"围绕 {anchor} 探测注入/越权（绑定注入，禁止只验指纹）",
    })
    return intents


def _must_keeps_hunt(
    must: list[str],
    open_intents: list[dict] | None,
    *,
    deny: list[str],
    limit: int,
) -> list[str]:
    """must 不能三格都是指纹/协议/目录。"""
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id")
    }
    tacs = {intent_tactic(by_id[i]) for i in must if i in by_id}
    if tacs & set(_HUNT_LIVE_TACTICS):
        return must
    if not tacs or not (tacs <= _ENUM_FILL_TACTICS):
        return must
    return _ensure_tactics_front(
        must, open_intents, want=_HUNT_LIVE_TACTICS, deny=deny, limit=limit,
    )


def _open_tactic_set(open_intents: list[dict] | None) -> set[str]:
    out: set[str] = set()
    for it in open_intents or []:
        if str(it.get("status") or "open") in ("deferred", "disproved"):
            continue
        tac = intent_tactic(it)
        if tac:
            out.add(tac)
    return out


def _session_unconsumed(open_intents: list[dict] | None) -> bool:
    """图上已有可用凭证 Intent，尚未把会话打到后认证功能面。"""
    tacs = _open_tactic_set(open_intents)
    return bool(tacs & {"auth_reuse", "priv_enum", "secret_mount"})


def _fill_explore_bundle(
    picked: list[str],
    open_intents: list[dict] | None,
    *,
    prefer: list[str],
    deny: list[str],
    oracle: bool = False,
    limit: int = 3,
    http_live: bool = False,
) -> list[str]:
    """未验证：把 must 补成最多 3 条互异 tactic 的并行路线。

    通道未完成时先钉竞争假说（换观测通道 + 输入面），再垫其它 tactic。
    已有凭证时先消费会话打文件/下载/越权，不要让 html_sink / 登录注入占满。
    图上已有打洞 Intent 时，must 至少一格是测→证；顾问点名协议/指纹也不能把打洞挤掉。
    """
    intents = list(open_intents or [])
    if http_live:
        intents = _ensure_http_hunt_intent(intents, has_http=True)
    consume = (not oracle) and _session_unconsumed(intents)
    rank: list[str] = []
    if oracle:
        rank.extend(("channel_oracle", "input_abuse"))
    if consume:
        rank.extend(_CONSUME_SESSION_FRONT)
    rank.extend(_HUNT_LIVE_TACTICS)
    rank.extend(prefer)
    rank.extend(_EXPLORE_FILL)
    already = list(picked or [])
    if oracle:
        already = _ensure_tactics_front(
            already, intents,
            want=("channel_oracle", "input_abuse"),
            deny=deny, limit=limit,
        )
        already = _ensure_tactics_front(
            already, intents,
            want=_HUNT_LIVE_TACTICS,
            deny=deny, limit=limit,
        )
    elif consume:
        hunt_after = tuple(
            t for t in _HUNT_LIVE_TACTICS if t != "html_sink"
        )
        already = _ensure_tactics_front(
            already, intents,
            want=_CONSUME_SESSION_FRONT + hunt_after,
            deny=deny, limit=limit,
        )
    else:
        already = _ensure_tactics_front(
            already, intents,
            want=_HUNT_LIVE_TACTICS,
            deny=deny, limit=limit,
        )
    out = _pick_must(
        intents, prefer=rank, deny=deny, already=already, limit=limit,
        allow=set(rank),
    )
    if http_live:
        out = _must_keeps_hunt(out, intents, deny=deny, limit=limit)
    return out


def _ensure_tactics_front(
    picked: list[str],
    open_intents: list[dict] | None,
    *,
    want: tuple[str, ...],
    deny: list[str],
    limit: int,
) -> list[str]:
    """把指定 tactic 插到 must 最前，挤掉末尾其它格。"""
    deny_set = set(deny)
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id") and str(it.get("status") or "open") not in ("deferred", "disproved")
    }
    have = {intent_tactic(by_id[i]) for i in picked if i in by_id}
    extra: list[str] = []
    for tac in want:
        if tac in deny_set or tac in have:
            continue
        for iid, it in by_id.items():
            if intent_tactic(it) == tac and iid not in extra and iid not in picked:
                extra.append(iid)
                have.add(tac)
                break
    front = list(extra)
    for iid in picked:
        if iid in front or iid not in by_id:
            continue
        if intent_tactic(by_id[iid]) in want:
            front.append(iid)
    rest = [iid for iid in picked if iid not in front]
    merged: list[str] = []
    seen: set[str] = set()
    for iid in front + rest:
        if not iid or iid in seen or iid not in by_id:
            continue
        tac = intent_tactic(by_id[iid])
        if tac in deny_set:
            continue
        seen.add(iid)
        merged.append(iid)
        if len(merged) >= limit:
            break
    return merged


def surface_false_close(text: str) -> bool:
    """散文把单通道无差异写成攻击面关闭。赛道无关。"""
    return bool(_ORACLE_FALSE_CLOSE_RE.search(text or ""))


def strip_premature_timing_bans(bans: list | None) -> list[str]:
    """未验证注入时，禁止把耗时/校准写进 ban_repeats（那是收口规则）。"""
    out: list[str] = []
    for b in bans or []:
        s = str(b or "").strip()
        if not s:
            continue
        if _PREMATURE_TIMING_BAN_RE.search(s):
            continue
        out.append(s)
    return out


def should_refresh_stale_binding(
    binding: AdvisorBinding | None, *, misses_limit: int = 3,
) -> bool:
    """未验证路线包空转满阈值：作废旧绑定，让顾问按全局重开多路线。收成走廊不走这条。"""
    if binding is None:
        return False
    try:
        limit = max(1, int(misses_limit or 3))
    except (TypeError, ValueError):
        limit = 3
    if str(binding.stall or "").strip().lower() in _CLOSEOUT_STALLS:
        return False
    return int(binding.misses or 0) >= limit


def _norm_cats(verified_categories) -> frozenset[str]:
    return frozenset(
        str(c).strip().lower() for c in (verified_categories or ()) if str(c).strip()
    )


_GADGET_SIDETRACK: frozenset[str] = frozenset({
    "file_read_chain", "access_control", "api_contract", "graphql_contract",
    "fingerprint", "content_enum", "protocol_model", "reverse_binary", "channel_oracle",
    "auth_surface",
})


def closeout_sidetrack_tactics(verified_categories=None) -> frozenset[str]:
    """已验证资产后不应再当「收口」去打的族。赛道无关，不写某题 payload。"""
    cats = _norm_cats(verified_categories)
    out = set(_CLOSE_SIDETRACK)
    if (cats & _SQLI_CATS) and not (cats & _READ_CATS):
        out.add("file_read_chain")
        out.add("flag_or_privesc")
        out.add("input_abuse")
        out.add("access_control")
    if (cats & _SSRF_CATS) and not (cats & _READ_CATS):
        out.add("file_read_chain")
        out.add("access_control")
        out.add("filter_bypass")
    if (cats & (_TOKEN_CATS | _AUTH_CATS)) and not (cats & _READ_CATS):
        out.add("file_read_chain")
        out.add("html_sink")
        out.add("flag_hunt")
    if cats & _EXEC_CATS:
        out.add("protocol_model")
        out.add("fingerprint")
    return frozenset(out)


def _closeout_hits(blob: str) -> bool:
    text = blob or ""
    return bool(
        _REPROVE_RE.search(text)
        or _FALSE_CLOSE_RE.search(text)
        or _LEAVE_BRIDGE_RE.search(text)
        or _LEAVE_VERIFIED_RE.search(text)
    )


def _strip_closeout_sentences(text: str) -> str:
    raw = text or ""
    if not raw.strip():
        return raw
    parts = re.split(r"(?<=[。；;\n])", raw)
    kept = [p for p in parts if p and not _closeout_hits(p)]
    return "".join(kept).strip()


def sanitize_closeout_plan(
    plan,
    *,
    has_verified_asset: bool = False,
    has_foothold: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
):
    """已验证或活跳板：方案正文只留覆盖段，不保留顾问后半句。"""
    if plan is None or has_foothold:
        return plan
    if not has_verified_asset and not has_live_gadget:
        return plan
    if has_verified_asset:
        deny = closeout_sidetrack_tactics(verified_categories)
        stall = str(getattr(plan, "stall", None) or "none").strip().lower()
        if stall in ("none", "method"):
            plan.stall = "chain"
        prefix = CLOSEOUT_OVERRIDE
    else:
        deny = _GADGET_SIDETRACK
        prefix = GADGET_KEEP
    prefer = [t for t in list(getattr(plan, "prefer_tactics", None) or []) if t not in deny]
    plan.prefer_tactics = prefer[:8]
    defer = list(getattr(plan, "defer_families", None) or [])
    for t in deny:
        if t not in defer:
            defer.append(t)
    plan.defer_families = defer[:12]
    plan.hold = False
    plan.next_plan = prefix
    diag = str(getattr(plan, "diagnosis", None) or "")
    if _FALSE_CLOSE_RE.search(diag) and "不等于" not in diag:
        plan.diagnosis = "一种键名/算法/观测失败不等于攻击面关闭。" + diag
    return plan


def assigned_is_entry_sidetrack(assigned_tactics=None, verified_categories=None) -> bool:
    """本轮认领是否全是入口/再证明，没有收成战术。空认领也算。赛道无关。"""
    tacs = {str(t).strip() for t in (assigned_tactics or ()) if str(t).strip()}
    if not tacs:
        return True
    side = set(closeout_sidetrack_tactics(verified_categories)) | set(ENTRY_ENUM_TACTICS)
    cats = _norm_cats(verified_categories)
    if not (cats & _TOKEN_CATS):
        side.add("secret_mount")
    return tacs <= side


def assigned_keeps_hunt_turn(assigned_tactics=None) -> bool:
    """认领了正在跑的长验证/收成，单轮不要被顾问让出门闩打断。"""
    tacs = {str(t).strip() for t in (assigned_tactics or ()) if str(t).strip()}
    return bool(tacs & _KEEP_TURN_TACTICS)


_ORACLE_LEFTOVER = frozenset({
    "channel_oracle", "input_abuse", "access_control",
}) | ENTRY_ENUM_TACTICS


def in_flight_blocks_new_direction(
    assigned: list[dict] | None,
    open_intents: list[dict] | None,
    *,
    has_verified_asset: bool = False,
    verified_categories=None,
) -> bool:
    """认领仍开放时是否挡住顾问换方向。

    未验证：挡住。已验证可利用后，若剩下的只是换通道/入口/身份域，放行收口复盘。
    """
    from .advisor_schedule import assigned_still_open
    if not assigned_still_open(assigned, open_intents):
        return False
    if not has_verified_asset:
        return True
    open_ids = {str(i.get("id") or "") for i in (open_intents or []) if i.get("id")}
    still = [it for it in (assigned or []) if str(it.get("id") or "") in open_ids]
    tacs = {intent_tactic(it) for it in still if intent_tactic(it)}
    if assigned_is_entry_sidetrack(tacs, verified_categories):
        return False
    if tacs <= _ORACLE_LEFTOVER:
        return False
    return True


def should_force_chain_close_review(
    *,
    chain_live: bool,
    has_plan: bool,
    assigned_tactics=None,
    verified_categories=None,
) -> bool:
    """已验证能力闲置：从未开口，或本轮认领全是再证明/入口族。赛道无关。"""
    if not chain_live:
        return False
    if not has_plan:
        return True
    return assigned_is_entry_sidetrack(assigned_tactics, verified_categories)


_ORACLE_PROBE_TACTICS: frozenset[str] = frozenset({
    "channel_oracle",
})


def should_force_oracle_review(
    *,
    needs_oracle: bool,
    has_plan: bool,
    assigned_tactics=None,
) -> bool:
    """单通道假关闭：尚未开口，或认领里还没有 channel_oracle。默认口令/web_inject 不算已换通道。"""
    if not needs_oracle:
        return False
    if not has_plan:
        return True
    tacs = {str(t).strip() for t in (assigned_tactics or ()) if str(t).strip()}
    if tacs & _ORACLE_PROBE_TACTICS:
        return False
    return True


def binding_reserve_tactics(
    *,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
    invert_ops: bool = False,
) -> tuple[str, ...]:
    """当前图阶段 must 必须留一格的战术族。不等顾问再开口。"""
    cats = _norm_cats(verified_categories)
    if invert_ops and not (cats & _EXEC_CATS):
        return ("reverse_binary",)
    if has_foothold and remaining_goals:
        return _POSTEX_RESERVE
    if has_verified_asset and not has_foothold:
        if cats & _TOKEN_CATS:
            return ("weaponize", "finding_authz_expand", "secret_mount")
        if cats & _SQLI_CATS:
            return ("finding_sqli_chain", "weaponize")
        if cats & _EXEC_CATS:
            return (
                "finding_rce_close", "weaponize", "impact_escalate",
            )
        if cats & _SSRF_CATS:
            return ("ssrf_as_gateway", "secret_mount", "weaponize")
        if cats & _AUTH_CATS:
            return ("weaponize", "finding_authz_expand")
        return _CHAIN_CLOSE_RESERVE
    if has_live_gadget and not has_foothold:
        return ("ssrf_as_gateway", "upload_bypass")
    return ()


def postex_reserve_tactics(
    *,
    has_foothold: bool,
    remaining_goals: bool,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
) -> tuple[str, ...]:
    """binding_reserve_tactics 的旧名。"""
    return binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
    )


def protected_tactics(
    *,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
) -> frozenset[str]:
    """顾问 defer / deny 不得关掉的下一跳。"""
    return frozenset(binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
    ))


def starves_chain_close(
    binding: AdvisorBinding | None,
    open_intents: list[dict] | None,
    *,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
) -> bool:
    """已验证未立足时，must 全是读面加深、或 deny 掉了利用下一跳。"""
    reserve = binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
    )
    if binding is None or not reserve:
        return False
    by_id = {
        str(it.get("id") or ""): it
        for it in (open_intents or [])
        if it.get("id") and str(it.get("status") or "open") not in ("deferred", "disproved")
    }
    open_tacs = {intent_tactic(it) for it in by_id.values()}
    if not (open_tacs & set(reserve)):
        return False
    if set(binding.deny_tactics or []) & set(reserve):
        return True
    must_tacs = {
        intent_tactic(by_id[i])
        for i in (binding.must_intents or [])
        if i in by_id
    }
    if must_tacs & set(reserve):
        return False
    if must_tacs and must_tacs <= _LOOT_DEEPEN_TACTICS:
        return True
    return bool(binding.must_intents)


def ensure_postex_orthogonal(
    binding: AdvisorBinding | None,
    open_intents: list[dict] | None,
    *,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
) -> AdvisorBinding | None:
    """已钉住的绑定也按本局图补一格下一跳，不等顾问再开口、不抄历史图。"""
    reserve = binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
    )
    if binding is None or not reserve:
        return binding
    deny = [t for t in list(binding.deny_tactics or []) if t not in set(reserve)]
    exclusive = bool(reserve) and not has_foothold and not has_verified_asset
    if has_verified_asset and not has_foothold:
        for t in closeout_sidetrack_tactics(verified_categories):
            if t not in deny and t not in set(reserve):
                deny.append(t)
        for t in _LOOT_DEEPEN_TACTICS:
            if t not in deny and t not in set(reserve):
                deny.append(t)
    elif has_live_gadget and not has_foothold:
        for t in _GADGET_SIDETRACK:
            if t not in deny and t not in set(reserve):
                deny.append(t)
    must = _reserve_open_tactics(
        list(binding.must_intents or []),
        open_intents,
        reserve=reserve,
        deny=deny,
        limit=3,
        exclusive=exclusive,
    )
    open_tacs = {
        intent_tactic(it) for it in (open_intents or [])
        if str(it.get("status") or "open") not in ("deferred", "disproved")
    }
    head = [t for t in reserve if t in open_tacs and t not in deny]
    prefer_src = list(binding.prefer_tactics or [])
    if exclusive:
        prefer_src = [t for t in prefer_src if t in set(reserve)]
    prefer = _uniq(head + prefer_src, limit=8)
    prefer = [t for t in prefer if t not in set(deny)][:8]
    if (
        must == list(binding.must_intents or [])
        and prefer == list(binding.prefer_tactics or [])
        and deny == list(binding.deny_tactics or [])
    ):
        return binding
    return replace(binding, must_intents=must, prefer_tactics=prefer, deny_tactics=deny[:12])


def _exploit_verified_cats(verified_categories) -> set[str]:
    from ..graph.verify import NON_EXPLOIT_FINDING_CATS
    cats = {str(c).strip().lower() for c in (verified_categories or []) if str(c).strip()}
    return {c for c in cats if c not in NON_EXPLOIT_FINDING_CATS}


def oracle_blocks_closeout(
    *,
    needs_channel_oracle: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
) -> bool:
    """恒定错误页还要换观测通道：不要当已验证利用去收口。"""
    if not needs_channel_oracle:
        return False
    if _exploit_verified_cats(verified_categories):
        return False
    listed = [str(c).strip() for c in (verified_categories or []) if str(c).strip()]
    if has_verified_asset and not listed:
        return False
    return True


def compile_binding(
    plan,
    *,
    open_intents: list[dict] | None = None,
    repeats: list[str] | None = None,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    has_internal_hops: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
    needs_channel_oracle: bool = False,
    cycle_hunt: bool = False,
    extra_subagents: list[str] | tuple[str, ...] | None = None,
    has_http_service: bool = False,
    invert_ops: bool = False,
) -> AdvisorBinding:
    """把监督 JSON + 图状态编成绑定。LLM 空字段由规则补全；图约束覆盖散文。"""
    block_oracle_close = oracle_blocks_closeout(
        needs_channel_oracle=needs_channel_oracle,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
    )
    chain_close = bool(has_verified_asset and not has_foothold) and not block_oracle_close
    live_gadget = bool(has_live_gadget and not has_foothold)
    if cycle_hunt:
        chain_close = False
        live_gadget = False
    if invert_ops and not (_norm_cats(verified_categories) & _EXEC_CATS):
        chain_close = False
    orig_hypo = str(getattr(plan, "next_plan", None) or "").strip()
    orig_diag = str(getattr(plan, "diagnosis", None) or "").strip()
    if chain_close or live_gadget:
        sanitize_closeout_plan(
            plan,
            has_verified_asset=chain_close,
            has_foothold=False,
            verified_categories=verified_categories,
            has_live_gadget=live_gadget,
        )
    prefer = _uniq(list(getattr(plan, "prefer_tactics", None) or []), limit=8)
    deny = _uniq(list(getattr(plan, "defer_families", None) or []), limit=12)
    diag = orig_diag
    nxt_src = orig_hypo
    allow_paths = f"{nxt_src} {diag}"
    bans = _uniq(list(getattr(plan, "ban_repeats", None) or []) + list(repeats or []), limit=12)
    bans = [b for b in bans if str(b or "").strip() and str(b).strip() not in allow_paths]
    must = _uniq(list(getattr(plan, "must_intents", None) or []), limit=3)
    subs = _uniq(list(getattr(plan, "subagents", None) or []), limit=4)
    stall = str(getattr(plan, "stall", None) or "none").strip().lower() or "none"
    if block_oracle_close:
        bans = strip_premature_timing_bans(bans)
        deny = [t for t in deny if t != "channel_oracle"]
        try:
            plan.defer_families = [t for t in (getattr(plan, "defer_families", None) or []) if t != "channel_oracle"]
        except Exception:
            pass

    postex = bool(has_foothold and remaining_goals)
    chain_close = bool(has_verified_asset and not has_foothold) and not block_oracle_close
    if cycle_hunt:
        postex = False
        chain_close = False
        live_gadget = False
    if invert_ops and not (_norm_cats(verified_categories) & _EXEC_CATS):
        chain_close = False
    reserve = binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
        invert_ops=invert_ops,
    )
    if postex:
        for t in ENTRY_ENUM_TACTICS:
            if t not in deny:
                deny.append(t)
        deny = [t for t in deny if t not in set(_POSTEX_RESERVE)]
        for t in POSTEX_TACTICS:
            if t not in prefer and t not in deny:
                prefer.append(t)
        open_tacs = {intent_tactic(it) for it in (open_intents or [])}
        head = [t for t in _POSTEX_RESERVE if t in open_tacs and t not in deny]
        prefer = _uniq(head + prefer, limit=8)
        if "lateral" not in subs:
            subs.append("lateral")
        if "privesc" not in subs:
            subs.append("privesc")
        if stall == "none":
            stall = "postex"
    elif chain_close:
        if "content_enum" not in deny:
            deny.append("content_enum")
        for t in closeout_sidetrack_tactics(verified_categories):
            if t not in deny:
                deny.append(t)
        for t in _LOOT_DEEPEN_TACTICS:
            if t not in deny and t not in set(reserve):
                deny.append(t)
        deny = [t for t in deny if t not in set(reserve)]
        open_tacs = {intent_tactic(it) for it in (open_intents or [])}
        head = [t for t in reserve if t in open_tacs and t not in deny]
        extra = [t for t in prefer if t not in deny]
        cycle = [t for t in _CYCLE_VERIFY_TACTICS if t not in deny and t in open_tacs]
        prefer = _uniq(head + extra + cycle, limit=8)
        if stall in ("none", "method"):
            stall = "chain"
    elif live_gadget:
        for t in _GADGET_SIDETRACK:
            if t not in deny and t not in set(reserve):
                deny.append(t)
        deny = [t for t in deny if t not in set(reserve)]
        open_tacs = {intent_tactic(it) for it in (open_intents or [])}
        head = [t for t in reserve if t in open_tacs and t not in deny]
        prefer = _uniq(head + [t for t in prefer if t in set(reserve)], limit=8)
        if stall in ("none", "method"):
            stall = "chain"

    if has_internal_hops and postex:
        for name in ("privesc", "lateral"):
            if name not in subs:
                subs.append(name)

    if cycle_hunt:
        reserve = ()
        for t in _CYCLE_HUNT_DENY:
            if t not in deny:
                deny.append(t)
        keep = set(_HUNT_LIVE_TACTICS) | {"impact_escalate"}
        deny = [t for t in deny if t not in keep]
        head = ["impact_escalate"] if has_verified_asset else []
        prefer = _uniq(head + list(_HUNT_LIVE_TACTICS) + prefer, limit=8)
        prefer = [t for t in prefer if t not in set(deny)][:8]
        if has_verified_asset and "content_enum" not in deny:
            deny.append("content_enum")

    if has_http_service:
        open_intents = _ensure_http_hunt_intent(open_intents, has_http=True)

    prefer = [t for t in prefer if t not in set(deny)][:8]
    open_tacs_now = _open_tactic_set(open_intents)
    cats_now = _norm_cats(verified_categories)
    if invert_ops or (
        "reverse_binary" in open_tacs_now and not (cats_now & _READ_CATS)
    ):
        if "file_read_chain" not in deny and "file_read_chain" not in set(reserve or ()):
            deny.append("file_read_chain")
        if "reverse_binary" in open_tacs_now and "reverse_binary" not in deny:
            prefer = _uniq(["reverse_binary"] + prefer, limit=8)
        if invert_ops and not (cats_now & _EXEC_CATS):
            for t in ("weaponize", "finding_rce_close", "impact_escalate"):
                if t not in deny and t not in set(reserve or ()):
                    deny.append(t)
        prefer = [t for t in prefer if t not in set(deny)][:8]
    if _deny_http_protocol_model(
        invert_ops=invert_ops, has_http_service=has_http_service,
        open_tacs=open_tacs_now, cats=cats_now, chain_close=chain_close,
    ):
        if "protocol_model" not in deny and "protocol_model" not in set(reserve or ()):
            deny.append("protocol_model")
        prefer = [t for t in prefer if t not in set(deny)][:8]
    if (
        not block_oracle_close and not chain_close and not postex and not live_gadget
        and _session_unconsumed(open_intents)
    ):
        head = [t for t in _CONSUME_SESSION_FRONT if t not in set(deny)]
        prefer = _uniq(head + prefer, limit=8)
    if block_oracle_close:
        deny = [t for t in deny if t != "channel_oracle"]
        if "content_enum" not in deny:
            deny.append("content_enum")
        for t in ("channel_oracle", "input_abuse"):
            if t not in prefer and t not in deny:
                prefer.insert(0, t)
        prefer = [
            t for t in prefer
            if t not in set(deny) and t not in _LOOT_DEEPEN_TACTICS
        ][:8]
    lock_must = bool((chain_close or live_gadget) and reserve)
    must_allow: set[str] | None = None
    if chain_close and reserve:
        must_allow = set(reserve) | _CYCLE_VERIFY_TACTICS
    elif lock_must:
        must_allow = set(reserve)
    must = _pick_must(
        open_intents, prefer=prefer, deny=deny, already=must, limit=3,
        allow=must_allow,
    )
    if reserve:
        must = _reserve_open_tactics(
            must, open_intents, reserve=reserve, deny=deny, limit=3,
            exclusive=bool(live_gadget and not chain_close),
        )
    if not lock_must and not postex:
        hunt_open = {
            intent_tactic(it) for it in (open_intents or [])
            if intent_tactic(it) in set(_HUNT_LIVE_TACTICS)
            and str(it.get("status") or "open") not in ("deferred", "disproved")
        }
        if hunt_open:
            deny = [t for t in deny if t not in hunt_open]
        if invert_ops or (
            "reverse_binary" in _open_tactic_set(open_intents)
            and not (_norm_cats(verified_categories) & _READ_CATS)
        ):
            if "file_read_chain" not in deny:
                deny.append("file_read_chain")
        if _deny_http_protocol_model(
            invert_ops=invert_ops, has_http_service=has_http_service,
            open_tacs=_open_tactic_set(open_intents),
            cats=_norm_cats(verified_categories), chain_close=chain_close,
        ):
            if "protocol_model" not in deny:
                deny.append("protocol_model")
        must = _fill_explore_bundle(
            must, open_intents, prefer=prefer, deny=deny,
            oracle=block_oracle_close, limit=3, http_live=has_http_service,
        )
        if has_http_service:
            must = _must_keeps_hunt(must, open_intents, deny=deny, limit=3)
        by_id = {
            str(it.get("id") or ""): it
            for it in (open_intents or [])
            if it.get("id")
        }
        bundle_tacs = {intent_tactic(by_id[i]) for i in must if i in by_id}
        prefer = _uniq(list(prefer) + [t for t in bundle_tacs if t], limit=8)
        prefer = [t for t in prefer if t not in set(deny)][:8]
        for name in _EXPLORE_SUBAGENTS:
            if name not in subs:
                subs.append(name)
    for name in extra_subagents or ():
        s = str(name or "").strip()
        if s and s not in subs:
            subs.append(s)
    hypo = nxt_src
    situation_bits: list[str] = []
    secret_open = "secret_mount" in _open_tactic_set(open_intents)
    if cycle_hunt:
        situation_bits.append(CYCLE_HUNT_NOTE)
    if (
        not block_oracle_close and not chain_close and not postex and not live_gadget
        and _session_unconsumed(open_intents)
    ):
        situation_bits.append(SITUATION_CONSUME)
    if invert_ops:
        situation_bits.append(SITUATION_PLACEHOLDER)
        if _DECOY_FALSE_CLOSE_RE.search(hypo) or _hypo_is_canned_keep(hypo):
            hypo = ""
    if chain_close and (_norm_cats(verified_categories) & _EXEC_CATS):
        situation_bits.append(SITUATION_EXEC)
    if chain_close and secret_open:
        situation_bits.append(SITUATION_SECRET)
        if _ABANDON_SECRET_RE.search(hypo):
            hypo = ""
    if chain_close or live_gadget:
        head = GADGET_KEEP if live_gadget and not chain_close else CLOSEOUT_OVERRIDE
        situation_bits.append(head)
        if (
            _REPROVE_RE.search(hypo)
            or "LOAD_FILE" in hypo
            or _LEAVE_VERIFIED_RE.search(hypo)
            or _LEAVE_BRIDGE_RE.search(hypo)
            or _WRAP_SAME_FORM_RE.search(hypo)
            or _FALSE_CLOSE_RE.search(hypo)
            or _ABANDON_SECRET_RE.search(hypo)
            or _DECOY_FALSE_CLOSE_RE.search(hypo)
            or _hypo_is_canned_keep(hypo)
        ):
            hypo = ""
    elif block_oracle_close:
        situation_bits.append(ORACLE_KEEP)
        false_close = surface_false_close(f"{diag} {hypo}")
        if false_close or _hypo_is_canned_keep(hypo):
            hypo = ""
            try:
                if false_close:
                    plan.diagnosis = ORACLE_DIAG
            except Exception:
                pass
    hypo = _closeout_hypo_fallback(
        hypo, invert_ops=invert_ops, chain_close=chain_close, live_gadget=live_gadget,
    )
    try:
        plan.next_plan = hypo
    except Exception:
        pass
    nxt = hypo
    return AdvisorBinding(
        diagnosis=str(getattr(plan, "diagnosis", None) or "").strip(),
        next_plan=nxt,
        situation="\n".join(x for x in situation_bits if x),
        must_intents=must,
        prefer_tactics=prefer,
        deny_tactics=deny[:12],
        ban_repeats=bans,
        subagents=subs[:4],
        stall=stall,
        cycle_hunt=bool(cycle_hunt),
    )


def _blob_hits_deny(blob: str, deny: list[str]) -> bool:
    text = blob or ""
    low = text.lower()
    for tac in deny:
        for tok in _DENY_ALIASES.get(tac, (tac,)):
            if tok.lower() in low:
                return True
    return bool(deny and _ENTRY_REFLUX_RE.search(text))


def _blob_hits_ban(blob: str, bans: list[str], *, allow: str = "") -> bool:
    """禁令命中：方案自己点名要打的路径不算违约。"""
    text = blob or ""
    allow_text = allow or ""
    for b in bans:
        s = str(b or "").strip()
        if len(s) < 6:
            continue
        if s in allow_text:
            continue
        if s in text:
            return True
    return False


_YIELD_TURN_RE = re.compile(r"让出给顾问|turn yield", re.I)


def binding_requires_hunt_task(binding: AdvisorBinding | None) -> bool:
    """路线包要求本轮派出 Task(web-exploit/src-hunt)，不能用 Agent/落 info 交差。"""
    if binding is None:
        return False
    if binding.cycle_hunt:
        return True
    subs = {str(s).strip() for s in (binding.subagents or [])}
    if subs & _HUNT_TASK_SUBAGENTS:
        return True
    return bool(set(binding.prefer_tactics or ()) & set(_HUNT_LIVE_TACTICS))


def _task_did_hunt(task_subagents) -> bool:
    for s in task_subagents or []:
        if str(s).strip().lower() in _HUNT_TASK_SUBAGENTS:
            return True
    return False


def binding_compliance(
    binding: AdvisorBinding | None,
    *,
    assigned: list[dict] | None = None,
    open_intents: list[dict] | None = None,
    last_turn_text: str = "",
    last_tool_uses: int = 0,
    quality: str = "none",
    task_subagents: list[str] | tuple[str, ...] | None = None,
) -> str:
    """上一步相对绑定的结果：oracle / executed / ignored / empty。"""
    if binding is None:
        return "executed"
    if (quality or "none") in _ORACLE_QUALITY:
        return "oracle"
    if _YIELD_TURN_RE.search(last_turn_text or ""):
        return "executed"
    try:
        tools = int(last_tool_uses or 0)
    except (TypeError, ValueError):
        tools = 0
    if tools <= 0:
        return "empty"
    if binding_requires_hunt_task(binding) and not _task_did_hunt(task_subagents):
        return "ignored"

    assigned_tacs = {intent_tactic(i) for i in (assigned or []) if intent_tactic(i)}
    deny_set = set(binding.deny_tactics or [])
    assigned_all_denied = bool(assigned_tacs and deny_set and assigned_tacs <= deny_set)
    blob = last_turn_text or ""
    sit = f"{binding.situation or ''} {binding.next_plan or ''} {binding.diagnosis or ''}"
    hit_deny = _blob_hits_deny(blob, list(binding.deny_tactics or []))
    hit_ban = _blob_hits_ban(
        blob, list(binding.ban_repeats or []),
        allow=sit,
    )
    reflux = bool(deny_set & ENTRY_ENUM_TACTICS) and bool(_ENTRY_REFLUX_RE.search(blob))

    stall = str(binding.stall or "").strip().lower()
    closeout_locked = (
        stall == "chain"
        or CLOSEOUT_OVERRIDE in sit
        or GADGET_KEEP in sit
    )
    left_closeout = bool(
        _REPROVE_RE.search(blob)
        or _LEAVE_BRIDGE_RE.search(blob)
        or _LEAVE_VERIFIED_RE.search(blob)
        or _WRAP_SAME_FORM_RE.search(blob)
        or (SITUATION_SECRET in sit and _ABANDON_SECRET_RE.search(blob))
        or (SITUATION_PLACEHOLDER in sit and _DECOY_FALSE_CLOSE_RE.search(blob))
        or (SITUATION_EXEC in sit and _LEAVE_VERIFIED_RE.search(blob))
    )
    if closeout_locked and left_closeout:
        return "ignored"
    if assigned_all_denied or hit_ban or hit_deny or reflux:
        return "ignored"
    return "executed"


def tighten_binding(binding: AdvisorBinding) -> AdvisorBinding:
    """同一份绑定收紧：加入口禁令，不换叙事。路线包里的 tactic 不进 deny。"""
    deny = list(binding.deny_tactics)
    keep = set(binding.prefer_tactics or ())
    for t in ENTRY_ENUM_TACTICS:
        if t not in deny and t not in keep:
            deny.append(t)
    prefer = [t for t in list(binding.prefer_tactics) if t not in set(deny)]
    if binding.stall == "postex" or ("hop_auth" in prefer and binding.stall != "chain"):
        head = [t for t in _POSTEX_RESERVE if t not in set(deny)]
        prefer = _uniq(head + prefer, limit=8)
        for t in POSTEX_TACTICS:
            if t not in prefer and t not in set(deny):
                prefer.append(t)
    if binding.stall == "chain":
        deny = [t for t in deny if t not in set(prefer)]
    elif set(prefer) & set(_CHAIN_CLOSE_RESERVE):
        deny = [t for t in deny if t not in set(_CHAIN_CLOSE_RESERVE)]
        head = [t for t in _CHAIN_CLOSE_RESERVE if t not in set(deny)]
        prefer = _uniq(head + prefer, limit=8)
    note = "【局面收紧·上一步违背局面】禁止入口枚举与本机回流。参考假说仍可另选，但不能再违局面。"
    sit = (binding.situation or "").strip()
    if "局面收紧" not in sit:
        sit = note + (("\n" + sit) if sit else "")
    return replace(
        binding,
        deny_tactics=_uniq(deny, limit=12),
        prefer_tactics=_uniq(prefer, limit=8),
        situation=sit,
        misses=int(binding.misses or 0) + 1,
        tightened=True,
    )


def binding_is_locked(binding: AdvisorBinding | None) -> bool:
    """有 must / prefer / deny 即视为有局面绑定。"""
    if binding is None:
        return False
    return bool(binding.must_intents or binding.prefer_tactics or binding.deny_tactics)


def pick_bound_assigned(
    *,
    open_intents: list[dict] | None,
    want_ids: list[str] | None,
    extras: list[dict] | None,
    prefer: set[str] | None = None,
    deny: set[str] | None = None,
    lock: bool = False,
    reserve: tuple[str, ...] | None = None,
    exclusive: bool = False,
    limit: int = 3,
) -> list[dict]:
    """want_ids（建议 Intent）排在最前；lock=False 时用前沿 extras 补满。

    reserve：从图上补一格下一跳（立足前=利用收成，立足后=未授权/其它协议），不是另开一套方案。
    """
    by_id = {i.get("id"): i for i in (open_intents or []) if i.get("id")}
    assigned: list[dict] = []
    seen_tac: set[str] = set()
    seen_id: set[str] = set()
    deny_set = set(deny or ())
    prefer_set = set(prefer or ())
    if reserve:
        deny_set -= set(reserve)

    def _add(it: dict | None) -> bool:
        if not it:
            return False
        iid = it.get("id")
        if not iid or iid in seen_id:
            return False
        if str(it.get("status") or "") == "deferred":
            return False
        tac = intent_tactic(it)
        if tac and tac in deny_set:
            return False
        if tac and tac in seen_tac:
            return False
        assigned.append(it)
        seen_id.add(iid)
        if tac:
            seen_tac.add(tac)
        return True

    for iid in want_ids or []:
        _add(by_id.get(iid))
        if len(assigned) >= limit:
            break

    if reserve:
        ids = _reserve_open_tactics(
            [str(it.get("id") or "") for it in assigned],
            list(open_intents or []),
            reserve=tuple(reserve),
            deny=list(deny_set),
            limit=limit,
            exclusive=exclusive,
        )
        assigned = []
        seen_tac = set()
        seen_id = set()
        for iid in ids:
            _add(by_id.get(iid))

    if lock and assigned:
        return assigned

    for it in extras or []:
        if lock and prefer_set:
            tac = intent_tactic(it)
            if tac not in prefer_set:
                continue
        _add(it)
        if len(assigned) >= limit:
            break
    return assigned


def format_binding_block(binding: AdvisorBinding | None) -> str:
    """写入从者提示：局面必须守；御主假说可打可丢。"""
    if binding is None:
        return ""
    lines = [
        "【局面·必须守住】",
        "循环按攻击图编译本段。必须消费已有凭证、不得离开未关输入面、不得回流目录枚举/邻题/本机内网。",
        "同一身份域：过门与未授权可达并行，不是互为前置。",
    ]
    if (binding.situation or "").strip():
        lines.append(binding.situation.strip())
    if binding.cycle_hunt:
        if CYCLE_HUNT_NOTE not in (binding.situation or ""):
            lines.append(CYCLE_HUNT_NOTE)
    else:
        lines.append(
            "已有可消耗资产时必须消耗（抽取或投递），禁止再证明同一通道。"
            "其余格可测其它活体面并验证高危/严重；禁止改打目录枚举。"
        )
    if binding.stall == "postex":
        lines.append("已有立足点：提权/横向/夺旗，禁止回头刷入口目录。")
    if binding.deny_tactics:
        lines.append("禁止战术：" + "、".join(f"`{x}`" for x in binding.deny_tactics))
    if binding.ban_repeats:
        lines.append("禁止路径：" + "、".join(f"`{x}`" for x in binding.ban_repeats[:8]))
    if set(binding.prefer_tactics or ()) & set(_HUNT_LIVE_TACTICS) or "web-exploit" in set(binding.subagents or ()):
        lines.append(HUNT_TASK_NOTE)
    lines.append("【参考假说·可打可丢】")
    lines.append("排到前沿最前，不是只许打这些；可另选正交假说，但不能违背局面。")
    if binding.must_intents:
        lines.append("建议 Intent：" + "、".join(f"`{x}`" for x in binding.must_intents))
    if binding.prefer_tactics:
        lines.append("建议战术：" + "、".join(f"`{x}`" for x in binding.prefer_tactics))
    if binding.subagents:
        lines.append("建议委派：" + "、".join(f"`{x}`" for x in binding.subagents))
    if binding.tightened:
        lines.append(f"上一步违背局面，已收紧禁令（miss={binding.misses}）。")
    return "\n".join(lines)


def _assert_track_agnostic() -> None:
    for fn in (
        compile_binding, binding_compliance, tighten_binding, format_binding_block,
        binding_is_locked, pick_bound_assigned, ensure_postex_orthogonal,
        postex_reserve_tactics, binding_reserve_tactics, protected_tactics,
        starves_chain_close, closeout_sidetrack_tactics,
        sanitize_closeout_plan, should_force_chain_close_review,
        should_force_oracle_review, should_refresh_stale_binding, surface_false_close,
        in_flight_blocks_new_direction, situation_protected_intent_ids,
    ):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"objective", "src", "flag", "redteam", "is_benchmark"}


_assert_track_agnostic()
