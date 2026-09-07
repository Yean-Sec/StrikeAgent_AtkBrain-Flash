"""实战 episode 落库（追加式、版本化）。本局推进以攻击图为准。"""
from __future__ import annotations

import hashlib
import re

from ..db import db, new_id, now, _dumps, _loads
from ..objective import REDTEAM, ULTIMATE_GOALS, canon_goal, normalize_objective, objective_allows_flag
from .achievements import ULTIMATE_ACHIEVEMENTS, detect_achievements
from .generalize import generalize_chain_str, generalize_node_key

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s]+", re.I)
_CREDS_RE = re.compile(
    r"(?i)(?:password|passwd|token|secret|api[_-]?key|flag\{)[^\s]{0,60}"
)
_PATHISH_RE = re.compile(
    r"(?:/[\w.\-]{1,40}){2,}"
    r"|/[\w.\-]{1,40}\.(?:php\d*|jspx?|asp|aspx|action|do|cgi|py|js|html?)\b"
    r"|\b[\w.\-]{1,40}\.(?:php\d*|jspx?|asp|aspx|action)\b",
    re.I,
)
_INTENT_ID_RE = re.compile(r"\bi_[a-f0-9]{8,}\b", re.I)
_VERSION_BANNER_RE = re.compile(
    r"\b(?:nginx|apache|php|werkzeug|tomcat|openssl|openresty)/[\d.]+",
    re.I,
)
_PORT_BANNER_RE = re.compile(r"\b\d{2,5}/tcp\b", re.I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w.-]+\.\w+\b")
# 单题 writeup：禁止进跨目标 episode
_SPECIALIZED_RE = re.compile(
    r"Task#|\bi_[a-f0-9]{8,}\b|"
    r"主攻|近况|可直接解|冒烟通过|"
    r"官网|预置凭证|题面核心|题面唯一|"
    r"employee/\w+|admin@example|"
    r"forge_identity|/proxy\.|/control\.php|"
    r"nginx/\d|PHP/\d|Werkzeug/|"
    r"curl exit|审批接口|SAS |se=\d{4}",
    re.I,
)
_TRANSFERABLE_PREFIX = re.compile(r"^(手法 |线索：|避免：|entry )")

_CUE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("error_reflects_input", ("traceback", "jinja", "undefined", "ssti", "templateerror")),
    ("debug_endpoint", ("debug", "werkzeug", "console", "phpinfo")),
    ("auth_surface", ("login", "admin", "jwt", "session", "oauth")),
    ("file_read_surface", ("lfi", "include", "path traversal", "file_read")),
    ("inject_surface", ("sqli", "union select", "ssti", "ognl", "spel")),
    ("upload_surface", ("upload", "multipart")),
    ("deserialize_surface", ("deserialize", "pickle", "ysoserial")),
)
# 夺旗位置模板不进跨目标记忆，不学 grep flag{
_FLAG_HUNT_NOISE = re.compile(
    r"grep\s+.{0,12}flag\{|flag-hunt|report_flag|搜\s*flag|定位并\s*report_flag",
    re.I,
)


def _failed_techniques_of(graph: dict) -> list[str]:
    """从攻击图的已否证意图里抽取失败手法(tactic),作为失败学习原料。
    strategy_key 形如 `source::tactic`;取 tactic 段,回退用 description 关键字。"""
    from .methodology import keep_tactic
    fails: set[str] = set()
    for it in (graph.get("disproved") or []):
        sk = str(it.get("strategy_key") or "")
        if "::" in sk:
            k = keep_tactic(sk.split("::")[-1])
            if k:
                fails.add(k)
    return sorted(fails)


def _tags_of(content: dict) -> list[str]:
    tags: set[str] = set()
    for f in content.get("findings", []) or []:
        if f.get("category"):
            tags.add(str(f["category"]).lower())
    for t in content.get("tech", []) or []:
        tags.add(str(t).lower())
    for t in content.get("techniques", []) or []:
        tags.add(str(t).lower())
    if content.get("approach_key"):
        tags.add(f"approach:{content['approach_key']}")
    if content.get("src_fingerprint"):
        tags.add(f"srcfp:{content['src_fingerprint']}")
    if content.get("milestone"):
        tags.add(f"ms:{canon_goal(content['milestone'])}")
    return sorted(tags)


def sanitize_approach(text: str) -> str:
    """去 URL/IP/路径/凭据/版本横幅，只留可迁移思路。"""
    t = _URL_RE.sub("<url>", text or "")
    t = _IP_RE.sub("<ip>", t)
    t = _CREDS_RE.sub("<redacted>", t)
    t = _EMAIL_RE.sub("<redacted>", t)
    t = _INTENT_ID_RE.sub("<intent>", t)
    t = _VERSION_BANNER_RE.sub("<banner>", t)
    t = _PORT_BANNER_RE.sub("<port>", t)
    t = _PATHISH_RE.sub("<path>", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[:240]


def is_transferable_approach(text: str) -> bool:
    """是否足以写入跨目标经验。当场流水账 / 单题路径一律否。"""
    raw = (text or "").strip()
    if not raw or _is_flag_hunt_noise(raw) or _SPECIALIZED_RE.search(raw):
        return False
    if len(raw) > 120 and not _TRANSFERABLE_PREFIX.match(raw):
        return False
    cleaned = sanitize_approach(raw)
    if not cleaned or _SPECIALIZED_RE.search(cleaned):
        return False
    if cleaned.count("<") >= 3:
        return False
    return True


def cues_from_text(*parts) -> list[str]:
    blob = " ".join(str(p or "") for p in parts).lower()
    return [name for name, kws in _CUE_RULES if any(k in blob for k in kws)][:8]


def _is_flag_hunt_noise(text: str) -> bool:
    return bool(_FLAG_HUNT_NOISE.search(text or ""))


def _node_blob(n: dict) -> str:
    detail = n.get("detail")
    if isinstance(detail, dict):
        detail_s = " ".join(str(v) for v in detail.values())
    else:
        detail_s = str(detail or "")
    tags = n.get("tags") or []
    if isinstance(tags, str):
        tags_s = tags
    else:
        tags_s = " ".join(str(t) for t in tags)
    return f"{n.get('key','')} {n.get('title','')} {detail_s} {tags_s}"


def _tactics_from_intents(intents: list | None) -> list[str]:
    from .methodology import keep_tactic
    out: list[str] = []
    for it in intents or []:
        sk = str(it.get("strategy_key") or "")
        tac = sk.split("::")[-1] if "::" in sk else sk
        k = keep_tactic(tac)
        if k and k not in out:
            out.append(k)
    return out


async def _verified_intents(project_id: str, limit: int = 8) -> list[dict]:
    if not project_id:
        return []
    try:
        return await db.fetchall(
            """SELECT strategy_key, description, rationale FROM intents
               WHERE project_id=? AND status='verified'
               ORDER BY updated_at DESC LIMIT ?""",
            (project_id, limit),
        ) or []
    except Exception:
        return []


def make_approach_key(chain: str, tactic: str, milestone: str) -> str:
    raw = f"{(chain or '').strip()}|{(tactic or '').strip().lower()}|{canon_goal(milestone)}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def src_finding_fingerprint(category: str, node_key: str, title: str) -> str:
    raw = f"{(category or '').lower()}|{generalize_node_key(node_key or '')}|{(title or '')[:40].lower()}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


async def _episode_exists_tag(project_id: str, needle: str) -> dict | None:
    if not project_id or not needle:
        return None
    return await db.fetchone(
        "SELECT id FROM memory WHERE project_id=? AND kind='episode' AND tags LIKE ? LIMIT 1",
        (project_id, f"%{needle}%"),
    )


async def record_episode(
    project_id: str | None,
    target_fp: str,
    outcome: str,
    content: dict,
    tags: list[str] | None = None,
) -> dict:
    """写入一条 episode（追加式、版本化，绝不覆盖）。"""
    prev = await db.fetchone(
        "SELECT MAX(version) AS v FROM memory WHERE target_fp=?", (target_fp,)
    )
    version = int((prev or {}).get("v") or 0) + 1
    mid = new_id("m_")
    tags = tags or _tags_of(content)
    await db.execute(
        """INSERT INTO memory(id, project_id, target_fp, version, kind, tags, content, outcome, created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (mid, project_id, target_fp, version, "episode", _dumps(tags), _dumps(content), outcome, now()),
    )
    return {"id": mid, "version": version, "target_fp": target_fp, "outcome": outcome}


def _build_milestone_payload(
    project: dict, graph: dict, milestone: str, extra: dict | None = None,
    *,
    verified_intents: list | None = None,
) -> dict:
    extra = extra or {}
    findings = graph.get("findings") or []
    nodes = graph.get("nodes") or []
    from .methodology import keep_tactic, scrub_chain, stack_tokens_of
    tech = stack_tokens_of(sorted({t for n in nodes for t in (n.get("tags") or [])}))
    techniques: list[str] = []
    for f in findings:
        k = keep_tactic(str(f.get("category") or extra.get("category") or ""))
        if k and k not in techniques:
            techniques.append(k)
    extra_tac = keep_tactic(str(extra.get("category") or ""))
    if extra_tac and extra_tac not in techniques:
        techniques.insert(0, extra_tac)
    for k in _tactics_from_intents(verified_intents):
        if k not in techniques:
            techniques.append(k)
    rce_path = (graph.get("rce_path") or {}).get("path", [])
    winning_path = " -> ".join(rce_path) if rce_path else ""
    if not winning_path:
        nk = str(extra.get("node_key") or "").strip()
        if nk:
            winning_path = f"{nk} -> goal:{canon_goal(milestone)}"
    chain = scrub_chain(generalize_chain_str(winning_path))
    tactic = keep_tactic(str(extra.get("category") or "")) or (techniques[0] if techniques else "")
    failed = _failed_techniques_of(graph)
    node_text = " ".join(_node_blob(n) for n in nodes[:24])
    intent_text = " ".join(
        f"{it.get('strategy_key','')} {it.get('description','')} {it.get('rationale','')}"
        for it in (verified_intents or [])[:8]
    )
    cues = cues_from_text(
        extra.get("title"), extra.get("category"), extra.get("evidence"),
        extra.get("node_key"), " ".join(techniques), node_text, intent_text,
    )
    graph_verified = [
        it for it in (graph.get("intents") or [])
        if str(it.get("status") or "") == "verified"
    ]
    intents = list(verified_intents or []) or graph_verified
    if intents:
        sk = str(intents[0].get("strategy_key") or "")
        if "::" in sk:
            tactic = keep_tactic(sk.split("::")[-1]) or tactic
    # 只沉淀手法/线索/失败族/战术链。Intent 描述是当场流水账，不进跨目标 episode。
    approach_bits: list[str] = []
    if tactic:
        approach_bits.append(f"手法 {tactic}")
    if cues:
        approach_bits.append("线索：" + "、".join(cues[:4]))
    if failed:
        approach_bits.append("避免：" + ", ".join(failed[:4]))
    if chain:
        approach_bits.append(chain)
    raw_approach = "；".join(approach_bits) or f"达成 {milestone}"
    if _is_flag_hunt_noise(raw_approach):
        raw_approach = "；".join(x for x in (
            ("线索：" + "、".join(cues[:4])) if cues else "",
            ("避免：" + ", ".join(failed[:4])) if failed else "",
            chain,
        ) if x) or f"达成 {milestone}"
    approach = sanitize_approach(raw_approach)
    if not is_transferable_approach(approach):
        approach = sanitize_approach("；".join(x for x in (
            f"手法 {tactic}" if tactic else "",
            ("线索：" + "、".join(cues[:4])) if cues else "",
            ("避免：" + ", ".join(failed[:4])) if failed else "",
            chain,
        ) if x) or f"达成 {milestone}")
    akey = make_approach_key(chain, tactic, milestone)
    src_fp = ""
    if canon_goal(milestone) == "high_critical_finding":
        src_fp = extra.get("src_fingerprint") or src_finding_fingerprint(
            extra.get("category") or "", extra.get("node_key") or "", extra.get("title") or "",
        )
    summary = sanitize_approach(str(extra.get("title") or extra.get("evidence") or ""))
    flag_hunt = objective_allows_flag((project.get("config") or {}).get("objective"))
    store_path = "" if flag_hunt else winning_path
    return {
        "summary": summary,
        "winning_path": store_path,
        "winning_chain": chain,
        "approach": approach,
        "approach_key": akey,
        "cues": cues,
        "milestone": canon_goal(milestone),
        "src_fingerprint": src_fp,
        "techniques": [t for t in techniques if t],
        "tech": tech,
        "findings": [
            {"category": f.get("category"), "severity": f.get("severity")}
            for f in findings
        ] if flag_hunt else [
            {"category": f.get("category"), "severity": f.get("severity"), "title": f.get("title")}
            for f in findings
        ],
        "achievements": [canon_goal(milestone)],
        "failed_techniques": failed,
    }


async def summarize_milestone(
    project: dict,
    milestone: str,
    *,
    graph: dict | None = None,
    title: str = "",
    category: str = "",
    node_key: str = "",
    evidence: str = "",
) -> dict | None:
    """一等里程碑首次 verified 时立刻写 episode（路径+去特化思路）。同 approach_key 不重复。"""
    if not project or not milestone:
        return None
    graph = graph or {}
    extra = {"title": title, "category": category, "node_key": node_key, "evidence": evidence}
    pid = project.get("id") or ""
    verified = await _verified_intents(pid)
    content = _build_milestone_payload(
        project, graph, milestone, extra,
        verified_intents=verified,
    )
    pid = project.get("id")
    akey = content.get("approach_key") or ""
    if pid and akey:
        if await _episode_exists_tag(pid, f"approach:{akey}"):
            return {"skipped": True, "reason": "approach_key", "approach_key": akey}
    src_fp = content.get("src_fingerprint") or ""
    if pid and src_fp:
        if await _episode_exists_tag(pid, f"srcfp:{src_fp}"):
            return {"skipped": True, "reason": "src_fingerprint", "src_fingerprint": src_fp}
    tech = content.get("tech") or []
    target_fp = build_fingerprint(project, tech)
    ms = canon_goal(milestone)
    if ms == "getflag":
        outcome = "flag"
    elif ms == "high_critical_finding":
        outcome = "partial"
    elif ms in ULTIMATE_ACHIEVEMENTS:
        outcome = "shell"
    else:
        outcome = "partial"
    return await record_episode(pid, target_fp, outcome, content, tags=_tags_of(content))


async def summarize_run(project: dict, graph: dict, run: dict) -> dict:
    """把一次 run 沉淀为 episode：赢法路径、有效手法、技术栈指纹。"""
    findings = graph.get("findings", [])
    nodes = graph.get("nodes", [])
    tech_raw = sorted({t for n in nodes for t in (n.get("tags") or [])})
    from .methodology import keep_tactic, scrub_chain, stack_tokens_of
    tech = stack_tokens_of(tech_raw)
    techniques: list[str] = []
    for f in findings:
        k = keep_tactic(str(f.get("category") or ""))
        if k and k not in techniques:
            techniques.append(k)
    pid = project.get("id")
    verified = await _verified_intents(pid) if pid else []
    for k in _tactics_from_intents(verified):
        if k not in techniques:
            techniques.append(k)
    rce_path = (graph.get("rce_path") or {}).get("path", [])
    objective = (project.get("config") or {}).get("objective", "getshell")
    obj = normalize_objective(objective)
    _allows_flag = objective_allows_flag(objective)
    achievements = detect_achievements(graph, allows_flag=_allows_flag)
    if run.get("goal_reached"):
        outcome = "flag" if _allows_flag else "shell"
    elif obj == REDTEAM and (set(ULTIMATE_GOALS[REDTEAM]) & set(achievements)):
        outcome = "shell"
    else:
        outcome = "partial" if findings else "fail"
    target_fp = build_fingerprint(project, tech)
    winning_path = " -> ".join(rce_path) if rce_path else ""
    chain = scrub_chain(generalize_chain_str(winning_path))
    tactic = techniques[0] if techniques else ""
    primary_ms = next((a for a in achievements if a in ULTIMATE_ACHIEVEMENTS), "")
    akey = make_approach_key(chain, tactic, primary_ms) if primary_ms else ""
    pid = project.get("id")
    if pid and akey and await _episode_exists_tag(pid, f"approach:{akey}"):
        return {"skipped": True, "reason": "approach_key", "approach_key": akey}
    failed = _failed_techniques_of(graph)
    cues = cues_from_text(" ".join(techniques), chain)
    content = {
        "summary": sanitize_approach(str(run.get("summary") or ""))[:240],
        "winning_path": "" if _allows_flag else winning_path,
        "winning_chain": chain,
        "approach": sanitize_approach(
            "；".join([x for x in (
                f"手法 {tactic}" if tactic else "",
                ("线索：" + "、".join(cues[:4])) if cues else "",
                ("避免：" + ", ".join(failed[:4])) if failed else "",
                chain,
            ) if x])
        ),
        "approach_key": akey,
        "cues": cues,
        "milestone": primary_ms,
        "techniques": [t for t in techniques if t],
        "tech": tech,
        "findings": [
            {"category": f.get("category"), "severity": f.get("severity")}
            for f in findings
        ] if _allows_flag else [
            {"category": f.get("category"), "severity": f.get("severity"), "title": f.get("title")}
            for f in findings
        ],
        "achievements": achievements,
        "failed_techniques": failed,
        "turns": run.get("turns"),
    }
    return await record_episode(pid, target_fp, outcome, content, tags=_tags_of(content))


def build_fingerprint(project: dict, tech: list[str] | None = None) -> str:
    """目标指纹：技术栈标签优先，否则回退到端口/类型，避免用具体 IP（利于跨目标复用经验）。"""
    tech = tech or []
    keys = [t for t in tech if any(
        k in t.lower() for k in
        ["php", "java", "python", "node", "nginx", "apache", "tomcat", "iis",
         "wordpress", "spring", "thinkphp", "django", "flask", "struts", "weblogic",
         "redis", "mysql", "mssql", "mongodb", "docker", "k8s"]
    )]
    if keys:
        return "|".join(sorted(set(keys))[:5])
    return (project.get("kind") or "single") + ":web"
