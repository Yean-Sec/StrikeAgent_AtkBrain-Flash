"""攻击图的领域常量、Pydantic 模型与评分逻辑。"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

# 漏洞就是漏洞；没有「候选 RCE」这种叫法。
_CANDIDATE_RCE_RE = re.compile(r"[（(]\s*候选\s*RCE\s*[)）]|候选\s*RCE", re.I)


def scrub_candidate_rce_label(text: str | None) -> str:
    s = str(text or "")
    if "候选" not in s:
        return s
    s = _CANDIDATE_RCE_RE.sub("", s)
    s = re.sub(r"\s{2,}", " ", s).strip(" \t-—·/|")
    return s

# ---- 领域常量 ---------------------------------------------------------------

NodeType = Literal[
    "target",      # 项目入口/目标本身；内网 IP 不是新 target，挂 info/service
    "info",        # 信息点（技术栈、路径、参数…）
    "service",     # 开放服务/端口
    "danger",      # 危险点（可疑功能、攻击面）
    "vuln",        # 已确认漏洞
    "credential",  # 凭证/令牌
    "foothold",    # 立足点（webshell/rce/会话）
    "honeypot",    # 蜜罐/反制点（降权、禁触碰）
    "goal",        # 已达成的终点：goal:shell* / goal:flag*，不是策略意图
]

Relation = Literal["LEADS_TO", "EXPLOITS", "ESCALATES_TO", "PIVOTS_TO", "CONTAINS"]

Severity = Literal["info", "low", "medium", "high", "critical"]
IntentStatus = Literal["open", "active", "verified", "disproved", "deferred"]
VerificationStatus = Literal["pending", "verified", "rejected"]
ProofType = Literal["write_txt", "poc_replay", "impact_extract"]

SEVERITY_ORDER: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}
SEVERITY_BASE_SCORE: dict[str, float] = {
    "info": 5, "low": 20, "medium": 45, "high": 72, "critical": 92,
}

# 需要特别高亮的严重类别：文件读写、数据库、越权/未授权、进后台、RCE
CRITICAL_CATEGORIES: set[str] = {
    "rce", "command_injection", "deserialization", "file_write", "file_upload",
    "arbitrary_file_read", "file_read", "lfi", "sqli", "db_access",
    "auth_bypass", "authz", "unauth", "idor", "admin_access", "privilege_escalation",
    "ssrf_internal",
}

# 类别 → 默认最低严重度（用于纠偏 agent 的低估）
CATEGORY_MIN_SEVERITY: dict[str, str] = {
    "rce": "critical", "command_injection": "critical", "deserialization": "critical",
    "file_write": "high", "file_upload": "high", "arbitrary_file_read": "high",
    "file_read": "high", "lfi": "high", "sqli": "high", "db_access": "high",
    "auth_bypass": "high", "admin_access": "high", "privilege_escalation": "high",
    "unauth": "high", "authz": "high", "idor": "medium", "ssrf": "medium",
    "xss": "medium", "info": "info",
    "business_logic": "high", "account_takeover": "high",
    "source_leak": "high", "backup_leak": "high", "hardcoded_secret": "high",
    "key_leak": "high", "mass_pii": "high", "cloud_credential": "high",
    "sensitive_data_exposure": "high", "credential_dump": "high", "secrets_leak": "high",
}

RCE_NODE_TYPES = {"foothold", "goal"}

_GOAL_SHELL_TAGS = {"getshell"}
_GOAL_FLAG_TAGS = {"flag", "getflag"}


def is_achieved_shell_goal(key: str, tags: list | None = None) -> bool:
    key = str(key or "")
    tags_l = {str(t).lower() for t in (tags or [])}
    return key.startswith("goal:shell") or bool(tags_l & _GOAL_SHELL_TAGS)


def is_achieved_flag_goal(key: str, tags: list | None = None) -> bool:
    key = str(key or "")
    tags_l = {str(t).lower() for t in (tags or [])}
    return key.startswith("goal:flag") or bool(tags_l & _GOAL_FLAG_TAGS)


def coerce_goal_node_type(key: str, ntype: str, tags: list | None = None) -> str:
    """未达成的策略/指令不得占用 goal（图上会被标成 GETSHELL）。"""
    if ntype != "goal":
        return ntype
    if is_achieved_shell_goal(key, tags) or is_achieved_flag_goal(key, tags):
        return "goal"
    return "danger"


# key 前缀 → 节点类型。只用于把 info 空壳升到前缀类型，不把已声明的更强类型降回去。
_KEY_TYPE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("target:", "target"),
    ("svc:", "service"),
    ("service:", "service"),
    ("danger:", "danger"),
    ("vuln:", "vuln"),
    ("cred:", "credential"),
    ("credential:", "credential"),
    ("foothold:", "foothold"),
    ("honeypot:", "honeypot"),
    ("goal:", "goal"),
)
_TYPE_RANK: dict[str, int] = {
    "info": 0,
    "service": 1,
    "danger": 2,
    "honeypot": 2,
    "credential": 3,
    "vuln": 4,
    "foothold": 5,
    "target": 6,
    "goal": 7,
}


def infer_node_type_from_key(key: str) -> str | None:
    k = str(key or "").strip().lower()
    if not k:
        return None
    for prefix, ntype in _KEY_TYPE_PREFIXES:
        if k.startswith(prefix):
            return ntype
    return None


def humanize_node_key(key: str) -> str:
    raw = str(key or "").strip()
    if not raw:
        return raw
    inferred = infer_node_type_from_key(raw)
    if not inferred:
        return raw
    rest = raw.split(":", 1)[-1].strip()
    return rest or raw


def coerce_declared_node_type(key: str, ntype: str, tags: list | None = None) -> str:
    """key 前缀是 vuln:/foothold: 等时，禁止用 type=info 占位。已声明的更强类型保留。

    带 placeholder 标签的 vuln: 空壳按危险点处理，不算已确认漏洞；
    report_finding / fill_source_node 会先去掉 placeholder 再升回 vuln。
    """
    declared = coerce_goal_node_type(key, ntype or "info", tags)
    inferred = infer_node_type_from_key(key)
    if not inferred:
        return declared or "info"
    if inferred == "goal":
        return coerce_goal_node_type(key, "goal", tags)
    tagset = {str(t).lower() for t in (tags or [])}
    if inferred == "vuln" and "placeholder" in tagset:
        if _TYPE_RANK.get(declared or "info", 0) <= _TYPE_RANK["vuln"]:
            return "danger"
        return declared or "danger"
    if _TYPE_RANK.get(declared or "info", 0) < _TYPE_RANK.get(inferred, 0):
        return inferred
    return declared or inferred


def placeholder_node_spec(key: str) -> tuple[str, str, str, list[str]]:
    """边/旗引用了还不存在的节点时的占位：(type, title, severity, tags)。"""
    inferred = infer_node_type_from_key(key) or "info"
    title = humanize_node_key(key)
    # vuln: 空壳不是已确认漏洞，按危险点占位，等填证据后再升 vuln。
    if inferred == "vuln":
        return "danger", title, "medium", ["placeholder"]
    ntype = coerce_declared_node_type(key, inferred)
    if ntype in ("foothold", "goal"):
        sev = "critical"
    elif ntype == "danger":
        sev = "medium"
    else:
        sev = "info"
    return ntype, title, sev, ["placeholder"]


def is_placeholder_node(key: str, title: str | None, detail, tags: list | None) -> bool:
    tagset = {str(t).lower() for t in (tags or [])}
    if "placeholder" in tagset:
        return True
    empty_detail = detail in (None, "", {}, [])
    if isinstance(detail, str) and not detail.strip():
        empty_detail = True
    if str(title or "") in (str(key or ""), humanize_node_key(key)) and empty_detail:
        return True
    return False


def agent_goal_reserved_error(key: str, ntype: str, tags: list | None = None) -> str | None:
    """add_node 不得直接落已达成的 shell/flag，须走 report_shell / report_flag。"""
    if ntype != "goal":
        return None
    if is_achieved_shell_goal(key, tags):
        return "命令执行达成请用 report_shell，不要 add_node(type=goal)"
    if is_achieved_flag_goal(key, tags):
        return "夺旗请用 report_flag，不要 add_node(type=goal)"
    return None


# ---- Pydantic 模型 ----------------------------------------------------------

class NodeIn(BaseModel):
    key: str
    type: NodeType = "info"
    title: str
    detail: str | dict | None = None
    severity: Severity = "info"
    is_rce: bool = False
    tags: list[str] = Field(default_factory=list)
    status: str = "open"

    @field_validator("title")
    @classmethod
    def _scrub_title(cls, v: str) -> str:
        return scrub_candidate_rce_label(v) or v


class EdgeIn(BaseModel):
    src: str = Field(alias="from")
    dst: str = Field(alias="to")
    relation: Relation = "LEADS_TO"
    weight: float = 0.5
    rationale: str | None = None

    model_config = {"populate_by_name": True}


class FindingIn(BaseModel):
    node_key: str | None = None
    severity: Severity = "medium"
    category: str = "info"
    title: str
    description: str | None = None
    evidence: str | None = None
    poc_curl: str | None = None
    poc_python: str | None = None
    cvss: float | None = None
    proof_type: ProofType | str | None = None
    proof_canary: str | None = None
    proof_url: str | None = None
    proof_detail: str | None = None
    verification_status: VerificationStatus | str | None = None
    secondary_verified: bool = False
    redteam_rating: str | None = None
    redteam_rating_rationale: str | None = None

    @field_validator("title")
    @classmethod
    def _scrub_title(cls, v: str) -> str:
        return scrub_candidate_rce_label(v) or v


class IntentIn(BaseModel):
    from_keys: list[str] = Field(default_factory=list, alias="from")
    description: str
    rationale: str | None = None
    est_success: float = 0.5
    strategy_key: str | None = None
    evidence_fingerprint: str | None = None
    priority: float | None = None
    status: IntentStatus = "open"

    model_config = {"populate_by_name": True}


# ---- 评分 -------------------------------------------------------------------

def normalize_severity(category: str | None, severity: str | None) -> str:
    """结合类别下限，纠偏 agent 可能的低估。"""
    sev = severity if severity in SEVERITY_ORDER else "info"
    if category:
        floor = CATEGORY_MIN_SEVERITY.get(category.lower())
        if floor and SEVERITY_ORDER[floor] > SEVERITY_ORDER[sev]:
            sev = floor
    return sev


REDTEAM_RATINGS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_REDTEAM_RATING_ALIASES: dict[str, str] = {
    "严重": "critical", "高危": "high", "中危": "medium", "低危": "low", "信息": "info",
    "crit": "critical", "c": "critical", "h": "high", "m": "medium", "l": "low",
}


def normalize_redteam_rating(raw: str | None) -> str | None:
    """红队侧可利用评级。可与 CVSS/严重度不同；空则未评级。"""
    s = str(raw or "").strip()
    if not s:
        return None
    mapped = _REDTEAM_RATING_ALIASES.get(s) or _REDTEAM_RATING_ALIASES.get(s.lower())
    s = (mapped or s).lower()
    return s if s in REDTEAM_RATINGS else None


def display_finding_severity(row: Any) -> str:
    """展示用评级：有红队二次验证评级则用之，否则用入库 severity。"""
    def _get(key: str) -> str:
        try:
            if isinstance(row, dict):
                v = row.get(key)
            else:
                v = getattr(row, key, None)
                if v is None:
                    v = row[key]  # sqlite Row
        except Exception:
            return ""
        return "" if v is None else str(v)

    rt = normalize_redteam_rating(_get("redteam_rating"))
    if rt:
        return rt
    sev = (_get("severity") or "info").strip().lower()
    return sev if sev in SEVERITY_ORDER else "info"


_RT_RATING_ZH = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}


def redteam_rating_label(raw: str | None) -> str:
    rt = normalize_redteam_rating(raw)
    if not rt:
        return "未评级"
    return _RT_RATING_ZH.get(rt, rt)


def secondary_review_error(
    secondary_verified: bool,
    rating: str | None,
    rationale: str | None,
) -> str | None:
    """二次验证与红队评级必须同一轮完成；缺一则拒绝。首次上报两者都不填则放行。"""
    has_rating = bool(normalize_redteam_rating(rating))
    why = (rationale or "").strip()
    if not secondary_verified and not has_rating and not why:
        return None
    if not secondary_verified:
        return (
            "二次验证与红队评级必须一起做：请 secondary_verified=true，"
            "并同时给 redteam_rating 与 redteam_rating_rationale"
            "（须写清二次怎么打：换通道/重放/对照，以及为何是这个级）。"
        )
    if not has_rating:
        return "二次验证已标完成，但缺少 redteam_rating。"
    if len(why) < 40:
        return (
            "redteam_rating_rationale 须同时阐述二次验证过程（换通道/重放 PoC/对照预期）"
            "和进攻侧评级理由，不要只写「高危」。"
        )
    return None


def secondary_review_narrative(row: Any) -> str:
    """报告里「二次验证与红队评级」一节，两者一起阐述。"""
    def _get(key: str):
        try:
            if isinstance(row, dict):
                return row.get(key)
            v = getattr(row, key, None)
            if v is None:
                v = row[key]
            return v
        except Exception:
            return None

    done = bool(_get("secondary_verified"))
    rating = normalize_redteam_rating(_get("redteam_rating") if _get("redteam_rating") is not None else None)
    why = str(_get("redteam_rating_rationale") or "").strip()
    lines: list[str] = []
    if not done and not rating and not why:
        lines.append("【二次验证】未做。本条仍是首次观测入库，尚未换通道或重放 PoC 做二次验证。")
        lines.append("【红队评级】未评级。展示严重度暂用入库 severity。二次验证与红队评级须同一轮完成，并在本节写清过程与理由。")
        return "\n".join(lines)
    if done:
        lines.append("【二次验证】已做。须与红队评级同一轮：独立再打一遍（换观测通道 / 重放 PoC / 对照预期回显），不能只把首次观测再贴一遍。")
    else:
        lines.append("【二次验证】未做。已出现评级或理由但未完成二次验证，报告视为不完整。")
    if rating:
        lines.append(f"【红队评级】**{redteam_rating_label(rating)}**（`{rating}`）。展示严重度以该评级为准。")
    else:
        lines.append("【红队评级】未给出。二次验证完成后必须同时评级。")
    if why:
        lines.append("【阐述】\n" + why)
    else:
        lines.append("【阐述】未写。二次验证过程（怎么打、看到什么）和评级理由必须写在 redteam_rating_rationale。")
    return "\n".join(lines)


def redteam_rating_block(row: Any) -> str:
    """报告里「红队评级」一节：只写级别和为什么是这个级。"""
    def _get(key: str):
        try:
            if isinstance(row, dict):
                return row.get(key)
            v = getattr(row, key, None)
            if v is None:
                v = row[key]
            return v
        except Exception:
            return None

    rating = normalize_redteam_rating(_get("redteam_rating") if _get("redteam_rating") is not None else None)
    why = str(_get("redteam_rating_rationale") or "").strip()
    if rating:
        head = f"级别：**{redteam_rating_label(rating)}**（`{rating}`）"
    else:
        head = "级别：未评级"
    if why:
        return f"{head}\n为什么是这个级：{why}"
    return f"{head}\n为什么是这个级：未写理由。"


def compute_risk_score(
    severity: str,
    node_type: str = "info",
    is_rce: bool = False,
    category: str | None = None,
) -> float:
    """节点风险评分 0..100。综合严重度 + 是否 RCE + 节点类型 + 类别。"""
    sev = normalize_severity(category, severity)
    score = SEVERITY_BASE_SCORE.get(sev, 5.0)
    if is_rce or node_type in RCE_NODE_TYPES:
        score = max(score, 90.0) + 6.0
    if node_type in ("vuln", "danger"):
        score += 4.0
    if category and category.lower() in CRITICAL_CATEGORIES:
        score += 4.0
    if node_type == "honeypot":
        score = min(score, 15.0)  # 蜜罐降权，避免误导路径规划
    return round(min(score, 100.0), 1)


def is_critical(severity: str, category: str | None = None) -> bool:
    sev = normalize_severity(category, severity)
    if SEVERITY_ORDER[sev] >= SEVERITY_ORDER["high"]:
        return True
    return bool(category and category.lower() in CRITICAL_CATEGORIES)
