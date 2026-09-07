"""里程碑：红队 getshell、CTF getflag，以及提权/横向手段。"""
from __future__ import annotations

from ..objective import (
    DATA_ACCESS_CATEGORIES,
    KEY_LEAK_CATEGORIES,
    RT_ADMIN_ACCESS,
    RT_ADMIN_AND_KEY,
    RT_KEY_LEAK,
    TRIVIAL_INFO_CATEGORIES,
    canon_goal,
)

# 一等最终目标（含手段；手段仍可检测但不作停机/豁免）
FIRST_CLASS: tuple[str, ...] = (
    "getflag", "getshell", "data_access", "admin_access", "key_leak",
    RT_ADMIN_AND_KEY, "privesc", "lateral",
)

ULTIMATE_ACHIEVEMENTS: frozenset[str] = frozenset({
    "getflag", "getshell",
})
MEANS_ACHIEVEMENTS: frozenset[str] = frozenset({"privesc", "lateral"})

_RCE_CATS = {"rce", "command_injection", "deserialization"}
_ADMIN_CATS = {"admin_access", "auth_bypass"}
_PRIVESC_CATS = {"privilege_escalation"}
_LATERAL_CATS = {"lateral"}

# 里程碑 -> 触发信号。category 命中须来自已验证 finding。
MILESTONES: dict[str, dict] = {
    "getflag": {
        "categories": set(),
        "node_types": set(),
        "node_tags": {"flag", "getflag"},
        "edge_relations": set(),
        "outcomes": {"flag"},
    },
    "getshell": {
        "categories": set(_RCE_CATS),
        "node_types": {"foothold", "goal"},
        "node_tags": {"rce", "shell", "webshell", "getshell"},
        "edge_relations": set(),
        "outcomes": {"shell"},
        "node_is_rce": True,
    },
    "data_access": {
        "categories": set(DATA_ACCESS_CATEGORIES),
        "node_types": set(),
        "node_tags": {"db_access", "dump", "db_dump", "data_leak", "mass_data_leak"},
        "edge_relations": set(),
        "outcomes": set(),
    },
    "admin_access": {
        "categories": set(_ADMIN_CATS),
        "node_types": set(),
        "node_tags": {"admin_access", "auth_bypass", "admin"},
        "edge_relations": set(),
        "outcomes": set(),
    },
    "key_leak": {
        "categories": set(KEY_LEAK_CATEGORIES),
        "node_types": set(),
        "node_tags": {"source_leak", "backup_leak", "hardcoded_secret", "key_leak", "mass_pii"},
        "edge_relations": set(),
        "outcomes": set(),
    },
    "privesc": {
        "categories": set(_PRIVESC_CATS),
        "node_types": set(),
        "node_tags": {"privesc", "privilege_escalation"},
        "edge_relations": {"ESCALATES_TO"},
        "outcomes": set(),
    },
    "lateral": {
        "categories": set(_LATERAL_CATS),
        "node_types": {"foothold"},
        "node_tags": {"lateral", "pivot"},
        "edge_relations": {"PIVOTS_TO"},
        "outcomes": set(),
    },
}

# 历史别名仍可被 achievements_of_episode 识别
MILESTONES["db_access"] = dict(MILESTONES["data_access"])
MILESTONES["mass_data_leak"] = dict(MILESTONES["data_access"])


def _lower_set(values) -> set[str]:
    return {str(v).lower() for v in (values or []) if v is not None}


def _finding_verified(f: dict) -> bool:
    vs = str(f.get("verification_status") or "verified").strip().lower()
    return vs not in ("pending", "rejected")


def _verified_cats(findings: list) -> set[str]:
    cats: set[str] = set()
    for f in findings or []:
        if not _finding_verified(f):
            continue
        cat = str(f.get("category") or "").lower().strip()
        if cat and cat not in TRIVIAL_INFO_CATEGORIES:
            cats.add(cat)
    return cats


def detect_achievements(graph: dict, allows_flag: bool = True) -> list[str]:
    """从实时攻击图推断已达成的里程碑集合(可多个并存)。

    allows_flag=False（红队赛道）时，剔除 getflag。
    类别类终极目标只认已验证的 finding。
    """
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    findings = graph.get("findings") or []

    cats = _verified_cats(findings)
    relations = _lower_set(e.get("relation") for e in edges)
    node_types = _lower_set(n.get("type") for n in nodes)
    node_tags: set[str] = set()
    has_rce_node = False
    for n in nodes:
        node_tags |= _lower_set(n.get("tags"))
        if n.get("is_rce"):
            has_rce_node = True

    rce_findings = [
        f for f in findings
        if str(f.get("category") or "").lower() in _RCE_CATS
        or str(f.get("node_key") or "").startswith(("goal:shell", "foothold:shell"))
    ]
    verified_rce = [f for f in rce_findings if _finding_verified(f)]
    pending_only_rce = bool(rce_findings) and not verified_rce

    achieved: list[str] = []
    for name in FIRST_CLASS:
        if name == RT_ADMIN_AND_KEY:
            continue
        if name == "getflag" and not allows_flag:
            continue
        spec = MILESTONES[name]
        hit = bool(spec.get("categories", set()) & cats)
        if name in MEANS_ACHIEVEMENTS:
            hit = hit or bool(spec.get("node_types", set()) & node_types)
            hit = hit or bool(spec.get("node_tags", set()) & node_tags)
            hit = hit or bool(
                {r.upper() for r in spec.get("edge_relations", set())}
                & {r.upper() for r in relations}
            )
        elif name == "getflag":
            hit = hit or bool(spec.get("node_tags", set()) & node_tags)
            hit = hit or any(
                str(n.get("type") or "") == "goal"
                and "flag" in str(n.get("key") or "").lower()
                for n in nodes
            )
        elif name == "getshell":
            hit = any(
                str(n.get("type") or "") == "goal"
                and (
                    str(n.get("key") or "").startswith("goal:shell")
                    or "getshell" in {str(t).lower() for t in (n.get("tags") or [])}
                )
                for n in nodes
            )
        if hit and name not in achieved:
            achieved.append(name)
    if RT_ADMIN_ACCESS in achieved and RT_KEY_LEAK in achieved and RT_ADMIN_AND_KEY not in achieved:
        achieved.append(RT_ADMIN_AND_KEY)
    return achieved


def _known_name(name: str) -> bool:
    n = canon_goal(name)
    return n in MILESTONES or n in FIRST_CLASS


def achievements_of_episode(content: dict, outcome: str | None = None) -> list[str]:
    """从已落库 episode 回退推断里程碑。优先用 content.achievements(新数据),
    否则从 content.findings 类别 + techniques + winning_path + outcome 尽力推断(历史数据)。"""
    content = content or {}
    stored = content.get("achievements")
    if isinstance(stored, list) and stored:
        out: list[str] = []
        for a in stored:
            n = canon_goal(str(a))
            if _known_name(n) and n not in out:
                out.append(n)
        return out

    cats = _lower_set(f.get("category") for f in (content.get("findings") or []))
    cats |= _lower_set(content.get("techniques"))
    cats -= set(TRIVIAL_INFO_CATEGORIES)
    oc = (outcome or "").lower()
    winning_path = str(content.get("winning_path") or "").lower()
    milestone = canon_goal(content.get("milestone"))

    achieved: list[str] = []
    if milestone and _known_name(milestone) and milestone not in achieved:
        achieved.append(milestone)
    for name in FIRST_CLASS:
        if name == RT_ADMIN_AND_KEY:
            continue
        spec = MILESTONES[name]
        hit = (
            bool(spec.get("categories", set()) & cats)
            or (oc in spec.get("outcomes", set()))
        )
        if not hit and spec.get("node_is_rce") and (
            "foothold:" in winning_path or "goal:" in winning_path
        ):
            hit = True
        if not hit and name == "lateral" and (
            "foothold:" in winning_path or "pivot" in winning_path
        ):
            hit = True
        if hit and name not in achieved:
            achieved.append(name)
    if RT_ADMIN_ACCESS in achieved and RT_KEY_LEAK in achieved and RT_ADMIN_AND_KEY not in achieved:
        achieved.append(RT_ADMIN_AND_KEY)
    return achieved


def is_win_episode(content: dict | None, outcome: str | None = None) -> bool:
    """赢法 episode：flag/shell 结局，或含一等终极里程碑（不含纯手段）。"""
    oc = (outcome or "").lower()
    if oc in ("flag", "shell"):
        return True
    ach = set(achievements_of_episode(content or {}, outcome))
    return bool(ach & ULTIMATE_ACHIEVEMENTS)
