"""顾问方案 → 可执行绑定。赛道无关：不看 objective，只看调用方传入的图状态。

顾问 = 操作员。未验证阶段钉的是一份「路线包」（2～3 条正交 tactic，并行验证），
不是三份同义散文，也不是入口枚举散弹。未执行则收紧同一包；空转满阈值才作废重审。
已验证可利用后至少一格消耗该洞推向立足/GETSHELL；其余格可继续测其它活体面验证高危/严重。
禁止三格都回头做目录枚举/指纹。
"""
from __future__ import annotations

import inspect
import re
from dataclasses import dataclass, field, replace


ENTRY_ENUM_TACTICS: frozenset[str] = frozenset({
    "fingerprint", "auth_surface", "content_enum", "web_inject",
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
    "content_enum",
})
# 已有可消耗洞时，其余格仍可并行验证这些活体面（不是目录枚举）。
_CYCLE_VERIFY_TACTICS: frozenset[str] = frozenset({
    "web_inject", "auth_surface", "access_control", "upload_bypass",
    "restricted_deserialize", "input_abuse",
})
# 未验证：路线包自动补齐的正交 tactic（不是目录爆破，也不是三条同义复述）。
_EXPLORE_FILL: tuple[str, ...] = (
    "channel_oracle", "input_abuse", "web_inject", "access_control", "info_to_danger",
)
EXPLORE_REFRESH_TACTICS: tuple[str, ...] = _EXPLORE_FILL + (
    "fingerprint", "filter_bypass", "web_inject",
)
_EXPLORE_SUBAGENTS: tuple[str, ...] = ("web-exploit", "recon")
_CLOSEOUT_STALLS: frozenset[str] = frozenset({"chain", "postex"})
# 单轮墙钟让出门闩放过这些：正在做长验证/收成，不要用短墙钟打断本轮。
# 与 closeout sidetrack 不同：channel_oracle 对顾问是再证明，但对指挥官可能是长 SLEEP。
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
)
GADGET_KEEP = (
    "【跳板仍活】一种 4xx 或否证笔记不等于跳板已死。"
    "禁止从本机打内网面。按错误正文换键。"
    "过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。"
)
ORACLE_KEEP = (
    "【硬约束·输入面未关】状态码/正文无差异只否证这一类观测，不关闭输入面。"
    "路线包必须并行：同一输入面换耗时/长度/响应头/副作用通道，加上该面的可控输入；"
    "至多再留一条其它正交面。禁止把该面写成已闭合/dos，禁止仅当其它路线无果才回来打。"
    "同一状态码再采样、换 Host/方法但仍以状态码判死，都不算换通道；"
    "必须对同一输入的两次提交比对耗时差/长度差/头差/副作用。"
)
ORACLE_DIAG = (
    "一种观测失败不等于输入面关闭。"
    "恒定状态码/正文只否证这一类通道；输入面仍开放。"
    "必须在同一输入面上换耗时/长度/响应头/副作用通道，并保持可控输入。"
    "禁止把该面写成已闭合/dos，禁止把其它面当主线。"
)
_ORACLE_FALSE_CLOSE_RE = re.compile(
    r"已收口|已闭合|输入无关(?:崩溃|延迟|耗时)|无条件崩溃|"
    r"零翻面.{0,12}收口|视图未处理|该面(?:已死|关闭)|面已关|"
    r"(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|"
    r"仅当.{0,24}无果|主线无果|失败后才(?:回来|再打)",
    re.I,
)
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


@dataclass
class AdvisorBinding:
    """一轮（可跨 hold 窗口）对指挥官生效的硬约束。"""
    diagnosis: str = ""
    next_plan: str = ""
    must_intents: list[str] = field(default_factory=list)
    prefer_tactics: list[str] = field(default_factory=list)
    deny_tactics: list[str] = field(default_factory=list)
    ban_repeats: list[str] = field(default_factory=list)
    subagents: list[str] = field(default_factory=list)
    stall: str = "none"
    misses: int = 0
    tightened: bool = False

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


def _fill_explore_bundle(
    picked: list[str],
    open_intents: list[dict] | None,
    *,
    prefer: list[str],
    deny: list[str],
    oracle: bool = False,
    limit: int = 3,
) -> list[str]:
    """未验证：把 must 补成最多 3 条互异 tactic 的并行路线。

    通道未完成时先钉竞争假说（换观测通道 + 输入面），再垫其它 tactic。
    顾问已填满三格也不能把这两条挤掉。
    """
    rank: list[str] = []
    if oracle:
        rank.extend(("channel_oracle", "input_abuse"))
    rank.extend(prefer)
    rank.extend(_EXPLORE_FILL)
    already = list(picked or [])
    if oracle:
        already = _ensure_tactics_front(
            already, open_intents,
            want=("channel_oracle", "input_abuse"),
            deny=deny, limit=limit,
        )
    return _pick_must(
        open_intents, prefer=rank, deny=deny, already=already, limit=limit,
        allow=set(rank),
    )


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
    "channel_oracle", "input_abuse", "web_inject",
})
_ORACLE_ENUM_ONLY: frozenset[str] = frozenset({
    "fingerprint", "content_enum", "auth_surface", "secret_mount",
})


def should_force_oracle_review(
    *,
    needs_oracle: bool,
    has_plan: bool,
    assigned_tactics=None,
) -> bool:
    """单通道假关闭：尚未开口，或认领仍停在指纹/目录。赛道无关，不写某题 payload。"""
    if not needs_oracle:
        return False
    if not has_plan:
        return True
    tacs = {str(t).strip() for t in (assigned_tactics or ()) if str(t).strip()}
    if tacs & _ORACLE_PROBE_TACTICS:
        return False
    if not tacs:
        return True
    return tacs <= _ORACLE_ENUM_ONLY


def binding_reserve_tactics(
    *,
    has_foothold: bool = False,
    remaining_goals: bool = False,
    has_verified_asset: bool = False,
    verified_categories=None,
    has_live_gadget: bool = False,
) -> tuple[str, ...]:
    """当前图阶段 must 必须留一格的战术族。不等顾问再开口。"""
    if has_foothold and remaining_goals:
        return _POSTEX_RESERVE
    if has_verified_asset and not has_foothold:
        cats = _norm_cats(verified_categories)
        if cats & _TOKEN_CATS:
            return ("weaponize", "finding_authz_expand", "secret_mount")
        if cats & _SQLI_CATS:
            return ("finding_sqli_chain", "weaponize")
        if cats & _EXEC_CATS:
            return (
                "finding_rce_close", "weaponize", "impact_escalate",
            )
        if cats & _SSRF_CATS:
            return ("ssrf_as_gateway", "weaponize", "impact_escalate")
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
) -> AdvisorBinding:
    """把监督 JSON + 图状态编成绑定。LLM 空字段由规则补全；图约束覆盖散文。"""
    block_oracle_close = oracle_blocks_closeout(
        needs_channel_oracle=needs_channel_oracle,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
    )
    chain_close = bool(has_verified_asset and not has_foothold) and not block_oracle_close
    live_gadget = bool(has_live_gadget and not has_foothold)
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
    diag = str(getattr(plan, "diagnosis", None) or "").strip()
    nxt_src = str(getattr(plan, "next_plan", None) or "").strip()
    allow_paths = f"{nxt_src} {diag}"
    bans = _uniq(list(getattr(plan, "ban_repeats", None) or []) + list(repeats or []), limit=12)
    bans = [b for b in bans if str(b or "").strip() and str(b).strip() not in allow_paths]
    must = _uniq(list(getattr(plan, "must_intents", None) or []), limit=3)
    subs = _uniq(list(getattr(plan, "subagents", None) or []), limit=4)
    stall = str(getattr(plan, "stall", None) or "none").strip().lower() or "none"
    if block_oracle_close:
        deny = [t for t in deny if t != "channel_oracle"]
        try:
            plan.defer_families = [t for t in (getattr(plan, "defer_families", None) or []) if t != "channel_oracle"]
        except Exception:
            pass

    postex = bool(has_foothold and remaining_goals)
    chain_close = bool(has_verified_asset and not has_foothold) and not block_oracle_close
    reserve = binding_reserve_tactics(
        has_foothold=has_foothold,
        remaining_goals=remaining_goals,
        has_verified_asset=has_verified_asset,
        verified_categories=verified_categories,
        has_live_gadget=has_live_gadget,
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

    prefer = [t for t in prefer if t not in set(deny)][:8]
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
        must = _fill_explore_bundle(
            must, open_intents, prefer=prefer, deny=deny,
            oracle=block_oracle_close, limit=3,
        )
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
    nxt = str(getattr(plan, "next_plan", None) or "").strip()
    if chain_close or live_gadget:
        by_id = {
            str(it.get("id") or ""): it
            for it in (open_intents or [])
            if it.get("id")
        }
        tacs = []
        for iid in must:
            tac = intent_tactic(by_id.get(iid) or {})
            if tac and tac not in tacs:
                tacs.append(tac)
        head = GADGET_KEEP if live_gadget and not chain_close else CLOSEOUT_OVERRIDE
        nxt = head + (("\n只推进：" + "、".join(f"`{t}`" for t in tacs)) if tacs else "")
        try:
            plan.next_plan = nxt
        except Exception:
            pass
    elif block_oracle_close:
        by_id = {
            str(it.get("id") or ""): it
            for it in (open_intents or [])
            if it.get("id")
        }
        tacs = []
        for iid in must:
            tac = intent_tactic(by_id.get(iid) or {})
            if tac and tac not in tacs:
                tacs.append(tac)
        tail = (("\n只推进：" + "、".join(f"`{t}`" for t in tacs)) if tacs else "")
        if surface_false_close(f"{diag} {nxt}"):
            nxt = ORACLE_KEEP + tail
            try:
                plan.next_plan = nxt
                plan.diagnosis = ORACLE_DIAG
            except Exception:
                pass
        elif ORACLE_KEEP not in nxt:
            nxt = ORACLE_KEEP + (("\n" + nxt) if nxt else "")
            try:
                plan.next_plan = nxt
            except Exception:
                pass
    return AdvisorBinding(
        diagnosis=str(getattr(plan, "diagnosis", None) or "").strip(),
        next_plan=nxt,
        must_intents=must,
        prefer_tactics=prefer,
        deny_tactics=deny[:12],
        ban_repeats=bans,
        subagents=subs[:4],
        stall=stall,
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


def binding_compliance(
    binding: AdvisorBinding | None,
    *,
    assigned: list[dict] | None = None,
    open_intents: list[dict] | None = None,
    last_turn_text: str = "",
    last_tool_uses: int = 0,
    quality: str = "none",
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

    open_ids = {
        str(i.get("id") or "")
        for i in (open_intents or [])
        if i.get("id") and str(i.get("status") or "open") not in ("deferred", "disproved")
    }
    must = [i for i in (binding.must_intents or []) if i]
    must_still_open = bool(must) and all(i in open_ids for i in must)
    assigned_tacs = {intent_tactic(i) for i in (assigned or []) if intent_tactic(i)}
    deny_set = set(binding.deny_tactics or [])
    assigned_all_denied = bool(assigned_tacs and deny_set and assigned_tacs <= deny_set)
    blob = last_turn_text or ""
    hit_deny = _blob_hits_deny(blob, list(binding.deny_tactics or []))
    hit_ban = _blob_hits_ban(
        blob, list(binding.ban_repeats or []),
        allow=f"{binding.next_plan or ''} {binding.diagnosis or ''}",
    )
    reflux = bool(deny_set & ENTRY_ENUM_TACTICS) and bool(_ENTRY_REFLUX_RE.search(blob))

    stall = str(binding.stall or "").strip().lower()
    nxt = binding.next_plan or ""
    closeout_locked = (
        stall == "chain"
        or CLOSEOUT_OVERRIDE in nxt
        or GADGET_KEEP in nxt
    )
    left_closeout = bool(
        _REPROVE_RE.search(blob)
        or _LEAVE_BRIDGE_RE.search(blob)
        or _LEAVE_VERIFIED_RE.search(blob)
        or _WRAP_SAME_FORM_RE.search(blob)
    )
    if closeout_locked and left_closeout:
        return "ignored"
    if assigned_all_denied or hit_ban or (must_still_open and (hit_deny or reflux)):
        return "ignored"
    if hit_deny and must_still_open:
        return "ignored"
    if (not must) and (hit_deny or reflux or hit_ban) and deny_set:
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
    note = "【约束收紧·上一步未执行】禁止入口枚举与本机回流。只推进 must_intents / prefer_tactics。"
    body = (binding.next_plan or "").strip()
    if "约束收紧" in body:
        plan = body
    else:
        plan = note + (("\n" + body) if body else "")
    return replace(
        binding,
        deny_tactics=_uniq(deny, limit=12),
        prefer_tactics=_uniq(prefer, limit=8),
        next_plan=plan,
        misses=int(binding.misses or 0) + 1,
        tightened=True,
    )


def binding_is_locked(binding: AdvisorBinding | None) -> bool:
    """有 must / prefer / deny 即视为钉住的人工指令。"""
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
    """锁定时只认领顾问点名的 Intent，不用入口枚举把本轮冲淡。

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
    """写入指挥官提示：硬约束段。无绑定则空。"""
    if binding is None:
        return ""
    lines = [
        "【硬约束·强制执行，不是评语】",
        "顾问指令等同操作员在对话框输入。循环已按本段认领 Intent；本轮只能推进这些 Intent、只能委派允许的子智能体。",
        "禁止改打开放前沿，禁止另开 recon/目录枚举/未点名 Task。与本段冲突的动作一律不做。",
        "同一身份域：过门与未授权可达并行，不是互为前置。",
        "已验证资产尚未立足：至少一格推进绑定点名的抽取或投递（推向 GETSHELL）；"
        "禁止再校准已通通道，禁止把利用族整族搁置。"
        "其余格继续测试其它活体面并验证高危/严重；禁止改打目录枚举。",
    ]
    if binding.must_intents:
        lines.append("必须推进 Intent：" + "、".join(f"`{x}`" for x in binding.must_intents))
        if len(binding.must_intents) >= 2:
            lines.append(
                "路线包：以上 Intent 是正交并行验证，不是三选一。"
                "本轮 Task 各派子智能体试可行性，汇总后再收口；不要只打第一条。"
                "若其中含换观测通道/输入面，必须与其它面并行，禁止写成其它路线失败后才打。"
            )
    if binding.prefer_tactics:
        lines.append("只允许战术：" + "、".join(f"`{x}`" for x in binding.prefer_tactics))
    if binding.deny_tactics:
        lines.append("禁止战术：" + "、".join(f"`{x}`" for x in binding.deny_tactics))
    if binding.ban_repeats:
        lines.append("禁止路径：" + "、".join(f"`{x}`" for x in binding.ban_repeats[:8]))
    if binding.subagents:
        lines.append("只委派：" + "、".join(f"`{x}`" for x in binding.subagents))
    if binding.tightened:
        lines.append(f"上一步未执行，已收紧（miss={binding.misses}）。")
    return "\n".join(lines)


def _assert_track_agnostic() -> None:
    for fn in (
        compile_binding, binding_compliance, tighten_binding, format_binding_block,
        binding_is_locked, pick_bound_assigned, ensure_postex_orthogonal,
        postex_reserve_tactics, binding_reserve_tactics, protected_tactics,
        starves_chain_close, closeout_sidetrack_tactics,
        sanitize_closeout_plan, should_force_chain_close_review,
        should_force_oracle_review, should_refresh_stale_binding, surface_false_close,
        in_flight_blocks_new_direction,
    ):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"objective", "src", "flag", "redteam", "is_benchmark"}


_assert_track_agnostic()
