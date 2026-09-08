"""自进化：高危/严重洞或 flag 才用 Claude Code 蒸馏成跨局剧本。

CTF 与红队共用同一份 lesson（project_id 为空）。不写机械路线，不蒸失败局。
"""
from __future__ import annotations

import hashlib
import json
from ..config import settings
from ..db import db, new_id, now, _dumps, _loads
from .achievements import is_win_episode
from .store import (
    build_fingerprint,
    is_transferable_approach,
    sanitize_approach,
)
from .methodology import (
    graph_methodology_signals,
    score_methodology,
    scrub_chain,
    scrub_lesson,
    stack_tokens_of,
)

_MIN_CONF = 0.18
_MAX_CONF = 0.95
EVOLVE_MILESTONES = frozenset({"getflag", "high_critical_finding"})
_HIGH = frozenset({"high", "critical"})


def lesson_key(*, when: list[str], do: list[str], avoid: list[str], chain: str) -> str:
    raw = "|".join((
        ",".join(sorted({x.strip().lower() for x in when if x})),
        ",".join(sorted({x.strip().lower() for x in do if x})),
        ",".join(sorted({x.strip().lower() for x in avoid if x})),
        (chain or "").strip(),
    ))
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _norm_list(v, *, limit: int = 8) -> list[str]:
    if isinstance(v, str) and v.strip():
        v = [v]
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        s = str(x or "").strip().lower()
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def _confidence(wins: int, fails: int, uses: int) -> float:
    base = 0.4 + 0.12 * max(0, int(wins)) - 0.14 * max(0, int(fails))
    if uses >= 4 and wins == 0:
        base -= 0.1
    return max(_MIN_CONF, min(_MAX_CONF, base))


def finding_qualifies_for_evolve(row: dict | None) -> bool:
    """高危/严重才蒸：有二次评级用评级；没有则须二次验证成功，再看入库严重度。"""
    if not isinstance(row, dict):
        return False
    vs = str(row.get("verification_status") or "verified").strip().lower()
    if vs not in ("verified", "flaky", ""):
        return False
    from ..graph.model import normalize_redteam_rating
    rt = normalize_redteam_rating(row.get("redteam_rating"))
    if rt:
        return rt in _HIGH
    try:
        sec = bool(int(row.get("secondary_verified") or 0))
    except (TypeError, ValueError):
        sec = bool(row.get("secondary_verified"))
    if not sec:
        return False
    sev = str(row.get("severity") or "").strip().lower()
    return sev in _HIGH


def episode_qualifies_for_evolve(episode: dict | None) -> bool:
    """只蒸 flag 或高危/严重洞对应的 episode。失败/空猎/纯 getshell 不蒸。"""
    if not episode or episode.get("skipped"):
        return False
    oc = str(episode.get("outcome") or "").strip().lower()
    if oc == "flag":
        return True
    c = episode.get("content") if isinstance(episode.get("content"), dict) else episode
    if not isinstance(c, dict):
        return False
    ms = str(c.get("milestone") or episode.get("milestone") or "").strip().lower()
    if ms in EVOLVE_MILESTONES:
        return True
    ach = c.get("achievements") or []
    if any(str(a).strip().lower() in ("getflag", "flag") for a in ach):
        return True
    for f in c.get("findings") or []:
        if isinstance(f, dict) and finding_qualifies_for_evolve(f):
            return True
    return False


def episode_worth_ai_refine(episode: dict | None) -> bool:
    return episode_qualifies_for_evolve(episode)


def distill_content(content: dict | None, outcome: str, target_fp: str = "*") -> dict | None:
    """从一条 episode 抽出剧本草稿。只留手法/线索/失败族/类型链。"""
    c = content or {}
    approach = sanitize_approach(str(c.get("approach") or ""))
    chain = scrub_chain(str(c.get("winning_chain") or c.get("winning_path") or ""))
    won = is_win_episode(c, outcome) or (outcome or "") in ("shell", "flag")
    draft = {
        "when": list(c.get("cues") or []) + stack_tokens_of(list(c.get("tech") or []) + str(target_fp or "").split("|")),
        "do": list(c.get("techniques") or []),
        "avoid": list(c.get("failed_techniques") or []),
        "chain": chain,
        "winning_chain": chain,
        "tech": list(c.get("tech") or []),
        "cues": list(c.get("cues") or []),
        "techniques": list(c.get("techniques") or []),
        "failed_techniques": list(c.get("failed_techniques") or []),
        "approach": approach,
        "confidence": _confidence(1 if won else 0, 0 if won else 1, 0),
        "wins": 1 if won else 0,
        "fails": 0 if won else 1,
        "uses": 0,
        "source_episode_ids": [],
    }
    if approach.startswith("手法 "):
        tactic = approach.split("手法 ", 1)[1].split("；", 1)[0].strip()
        if tactic:
            draft["do"] = [tactic] + list(draft["do"])
    if won and not (is_transferable_approach(approach) or chain or draft["do"]):
        return None
    if (not won) and not draft["avoid"] and not is_transferable_approach(approach):
        return None
    got = scrub_lesson(draft)
    if not got:
        return None
    got["wins"] = 1 if won else 0
    got["fails"] = 0 if won else 1
    got["uses"] = 0
    got["confidence"] = _confidence(got["wins"], got["fails"], 0)
    got["source_episode_ids"] = []
    got["lesson_key"] = lesson_key(
        when=got.get("when") or [], do=got.get("do") or [],
        avoid=got.get("avoid") or [], chain=got.get("chain") or "",
    )
    return got


def _merge_lesson(old: dict, incoming: dict) -> dict:
    when = _norm_list(list(old.get("when") or []) + list(incoming.get("when") or []))
    do = _norm_list(list(old.get("do") or []) + list(incoming.get("do") or []))
    avoid = _norm_list(list(old.get("avoid") or []) + list(incoming.get("avoid") or []))
    chain = str(incoming.get("chain") or old.get("chain") or "")
    wins = int(old.get("wins") or 0) + int(incoming.get("wins") or 0)
    fails = int(old.get("fails") or 0) + int(incoming.get("fails") or 0)
    uses = int(old.get("uses") or 0)
    src = list(old.get("source_episode_ids") or [])
    for i in incoming.get("source_episode_ids") or []:
        if i and i not in src:
            src.append(i)
    rule = str(incoming.get("rule") or old.get("rule") or "")
    if len(str(old.get("rule") or "")) > len(rule):
        rule = str(old.get("rule") or rule)
    idea = str(incoming.get("idea") or old.get("idea") or "")
    method = str(incoming.get("method") or old.get("method") or "")
    route = str(incoming.get("route") or old.get("route") or chain)
    merged = {
        "lesson_key": old.get("lesson_key") or incoming.get("lesson_key"),
        "rule": rule[:360],
        "when": when,
        "do": do,
        "avoid": avoid,
        "chain": chain,
        "route": route,
        "method": method,
        "idea": idea,
        "wins": wins,
        "fails": fails,
        "uses": uses,
        "confidence": _confidence(wins, fails, uses),
        "target_fp": incoming.get("target_fp") or old.get("target_fp") or "*",
        "source_episode_ids": src[-12:],
    }
    cleaned = scrub_lesson(merged)
    if not cleaned:
        return merged
    cleaned["wins"] = wins
    cleaned["fails"] = fails
    cleaned["uses"] = uses
    cleaned["confidence"] = _confidence(wins, fails, uses)
    cleaned["source_episode_ids"] = src[-12:]
    cleaned["lesson_key"] = merged.get("lesson_key") or lesson_key(
        when=cleaned.get("when") or [], do=cleaned.get("do") or [],
        avoid=cleaned.get("avoid") or [], chain=cleaned.get("chain") or "",
    )
    return cleaned


async def upsert_lesson(draft: dict, *, episode_id: str | None = None) -> dict | None:
    draft = scrub_lesson(draft)
    if not draft:
        return None
    if not (
        draft.get("do") or draft.get("avoid") or draft.get("chain")
        or (draft.get("method") and draft.get("idea"))
    ):
        return None
    draft["lesson_key"] = draft.get("lesson_key") or lesson_key(
        when=draft.get("when") or [], do=draft.get("do") or [],
        avoid=draft.get("avoid") or [], chain=draft.get("chain") or "",
    )
    if not draft.get("lesson_key"):
        return None
    if episode_id:
        ids = list(draft.get("source_episode_ids") or [])
        if episode_id not in ids:
            ids.append(episode_id)
        draft["source_episode_ids"] = ids[-12:]
    key = draft["lesson_key"]
    row = await db.fetchone(
        "SELECT * FROM memory WHERE kind='lesson' AND tags LIKE ? LIMIT 1",
        (f"%lesson_key:{key}%",),
    )
    tags = [f"lesson_key:{key}"] + [f"when:{w}" for w in (draft.get("when") or [])[:6]]
    if row:
        old = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
        if not isinstance(old, dict):
            old = {}
        merged = _merge_lesson(old, draft)
        await db.execute(
            "UPDATE memory SET content=?, tags=?, target_fp=?, outcome='playbook', version=version+1 WHERE id=?",
            (_dumps(merged), _dumps(tags), merged.get("target_fp") or "*", row["id"]),
        )
        return {"id": row["id"], "updated": True, **merged}
    mid = new_id("m_")
    await db.execute(
        """INSERT INTO memory(id, project_id, target_fp, version, kind, tags, content, outcome, created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (mid, None, draft.get("target_fp") or "*", 1, "lesson", _dumps(tags),
         _dumps(draft), "playbook", now()),
    )
    return {"id": mid, "updated": False, **draft}


async def evolve_from_episode_id(episode_id: str) -> dict | None:
    """用 Claude Code 蒸馏这一条合格 episode。不用机械映射。"""
    if not episode_id:
        return None
    row = await db.fetchone("SELECT * FROM memory WHERE id=?", (episode_id,))
    if not row or (row.get("kind") or "episode") == "lesson":
        return None
    content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
    if not isinstance(content, dict):
        content = {}
    episode = {
        "id": row.get("id"),
        "outcome": row.get("outcome"),
        "target_fp": row.get("target_fp") or "*",
        "content": content,
        "milestone": content.get("milestone"),
        "achievements": content.get("achievements") or [],
        "findings": content.get("findings") or [],
    }
    if not episode_qualifies_for_evolve(episode):
        return None
    if not bool(getattr(settings, "evolve_ai", True)):
        return None
    try:
        applied = await ai_refine_playbook(
            recent_episodes=[episode],
            playbook=await list_playbook(limit=12),
        )
    except Exception:
        return None
    kept = [x for x in (applied or []) if x.get("action") != "retire"]
    return (kept[-1] if kept else None)


def _graph_signals(project: dict | None, graph: dict | None) -> tuple[set[str], str]:
    sig = graph_methodology_signals(graph)
    tech = []
    for n in (graph or {}).get("nodes") or []:
        tech.extend(str(t) for t in (n.get("tags") or []))
    fp = build_fingerprint(project or {}, stack_tokens_of(tech))
    for part in stack_tokens_of((fp or "").split("|")):
        sig.add(part)
    return sig, fp


def _score_lesson(content: dict, signals: set[str], fp: str, *, strict: bool = False) -> float:
    del fp
    return score_methodology(content, signals, strict=strict)


def serialize_lesson_row(row: dict) -> dict:
    content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
    if not isinstance(content, dict):
        content = {}
    return {
        "id": row.get("id"),
        "target_fp": row.get("target_fp") or content.get("target_fp"),
        "version": row.get("version"),
        "kind": "lesson",
        "outcome": "playbook",
        "content": content,
        "created_at": row.get("created_at"),
        "rule": content.get("rule"),
        "when": content.get("when") or [],
        "do": content.get("do") or [],
        "avoid": content.get("avoid") or [],
        "chain": content.get("chain") or "",
        "route": content.get("route") or "",
        "method": content.get("method") or "",
        "idea": content.get("idea") or "",
        "confidence": content.get("confidence"),
        "wins": content.get("wins"),
        "fails": content.get("fails"),
        "uses": content.get("uses"),
    }


async def list_playbook(*, limit: int = 40) -> list[dict]:
    rows = await db.fetchall(
        "SELECT * FROM memory WHERE kind='lesson' ORDER BY created_at DESC LIMIT ?",
        (max(1, int(limit)),),
    )
    out: list[dict] = []
    for r in rows:
        item = serialize_lesson_row(r)
        clean = scrub_lesson(item.get("content") or item)
        if not clean:
            continue
        item["content"] = clean
        item["rule"] = clean.get("rule")
        item["when"] = clean.get("when") or []
        item["do"] = clean.get("do") or []
        item["avoid"] = clean.get("avoid") or []
        item["chain"] = clean.get("chain") or ""
        item["target_fp"] = clean.get("target_fp") or item.get("target_fp")
        out.append(item)
    out.sort(key=lambda x: float((x.get("content") or {}).get("confidence") or 0), reverse=True)
    return out


async def retrieve_lessons(
    project: dict | None, graph: dict | None, *, limit: int = 6, bump_uses: bool = False,
) -> list[dict]:
    """按当前图上的技术栈/线索/战术取可迁移剧本。CTF 与红队共用，不匹配具体主机或题号。"""
    rows = await db.fetchall(
        "SELECT * FROM memory WHERE kind='lesson' ORDER BY created_at DESC LIMIT 80",
    )
    if not rows:
        return []
    signals, fp = _graph_signals(project, graph)
    ranked: list[tuple[float, dict]] = []
    for r in rows:
        item = serialize_lesson_row(r)
        clean = scrub_lesson(item.get("content") or item)
        if not clean:
            continue
        item["content"] = clean
        item["rule"] = clean.get("rule")
        item["when"] = clean.get("when") or []
        item["do"] = clean.get("do") or []
        item["avoid"] = clean.get("avoid") or []
        item["chain"] = clean.get("chain") or ""
        item["route"] = clean.get("route") or ""
        item["method"] = clean.get("method") or ""
        item["idea"] = clean.get("idea") or ""
        # CTF 与红队同一把尺子：图上要有栈/线索/战术交集才回灌。
        score = _score_lesson(clean, signals, fp, strict=True)
        if score <= 0:
            continue
        ranked.append((score, item))
    ranked.sort(key=lambda x: x[0], reverse=True)
    picked = [it for _, it in ranked[: max(1, int(limit))]]
    if bump_uses and picked:
        await _bump_uses([p["id"] for p in picked if p.get("id")])
    return picked


async def _bump_uses(ids: list[str]) -> None:
    for mid in ids:
        row = await db.fetchone("SELECT content FROM memory WHERE id=? AND kind='lesson'", (mid,))
        if not row:
            continue
        content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
        if not isinstance(content, dict):
            continue
        content["uses"] = int(content.get("uses") or 0) + 1
        content["confidence"] = _confidence(
            int(content.get("wins") or 0), int(content.get("fails") or 0), int(content["uses"]),
        )
        await db.execute("UPDATE memory SET content=? WHERE id=?", (_dumps(content), mid))


async def reinforce_lessons(ids: list[str], *, won: bool) -> None:
    """本局结束：用过的剧本赢则加分，否则衰减。"""
    for mid in ids:
        if not mid:
            continue
        row = await db.fetchone("SELECT content FROM memory WHERE id=? AND kind='lesson'", (mid,))
        if not row:
            continue
        content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
        if not isinstance(content, dict):
            continue
        if won:
            content["wins"] = int(content.get("wins") or 0) + 1
        else:
            content["fails"] = int(content.get("fails") or 0) + 1
        content["confidence"] = _confidence(
            int(content.get("wins") or 0), int(content.get("fails") or 0), int(content.get("uses") or 0),
        )
        await db.execute("UPDATE memory SET content=? WHERE id=?", (_dumps(content), mid))


def format_lessons_block(lessons: list[dict]) -> str:
    if not lessons:
        return ""
    from .methodology import format_methodology
    lines = [
        "## 进化经验（CTF 与红队共用。只作思路启发：按当前图上的栈/线索选用并当场验证；"
        "禁止当作本题步骤清单，禁止套用 IP/路径/题号/payload）"
    ]
    for it in lessons[:6]:
        c = scrub_lesson(it.get("content") or it) or {}
        text = format_methodology(
            when=list(c.get("when") or []),
            do=list(c.get("do") or []),
            avoid=list(c.get("avoid") or []),
            chain=str(c.get("chain") or ""),
            route=str(c.get("route") or ""),
            method=str(c.get("method") or ""),
            idea=str(c.get("idea") or ""),
        )
        if text:
            lines.append("- " + text[:360])
    if len(lines) <= 1:
        return ""
    return "\n".join(lines)


def tactics_from_lessons(lessons: list[dict]) -> set[str]:
    from .methodology import keep_tactic
    out: set[str] = set()
    for it in lessons or []:
        c = it.get("content") or it
        for t in c.get("do") or []:
            k = keep_tactic(str(t))
            if k:
                out.add(k)
    return out


def avoid_from_lessons(lessons: list[dict]) -> set[str]:
    from .methodology import keep_tactic
    out: set[str] = set()
    for it in lessons or []:
        c = it.get("content") or it
        for t in c.get("avoid") or []:
            k = keep_tactic(str(t))
            if k:
                out.add(k)
    return out


EVOLVE_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的进化编辑。只把已经确认的高危/严重漏洞或 flag 收口，蒸馏成 CTF 与红队都能用的经验。

每条必须同时给出三种可迁移内容：
- idea：思想（为什么这条路值得走）
- method：方式方法（怎么推进，不写具体 payload）
- route：路线（类型链，如 entry → vuln(sqli) → foothold）
when 只能是技术栈或线索名（php/java/auth_surface/inject_surface 等）。
do/avoid 只能是战术名（sqli/ssti/ssrf/file_read_chain/weaponize/content_enum 等）。
禁止：IP、主机、端口、题号、URL、题面路径、flag 原文、getflag 当手法、Intent id、具体 payload、机械罗列工具名。
已有剧本可修订或退休，不要重复同一条。最多 3 条。
只输出 JSON：
{"lessons":[{"action":"upsert|retire","idea":"...","method":"...","route":"entry → vuln(sqli)","when":["php"],"do":["sqli"],"avoid":["content_enum"],"chain":"entry → vuln(sqli)"}]}
action=retire 时 rule 或 lesson_key 指出要降权的旧条。
"""


def parse_evolve_lessons(text: str) -> list[dict]:
    raw = (text or "").strip()
    blob = ""
    if "```" in raw:
        import re
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.S)
        if m:
            blob = m.group(1)
    if not blob:
        import re
        m = re.search(r"\{[\s\S]*\}", raw)
        if m:
            blob = m.group(0)
    if not blob:
        return []
    try:
        data = json.loads(blob)
    except Exception:
        return []
    items = data.get("lessons") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for it in items[:3]:
        if not isinstance(it, dict):
            continue
        action = str(it.get("action") or "upsert").lower()
        when = _norm_list(it.get("when"))
        do = _norm_list(it.get("do"))
        avoid = _norm_list(it.get("avoid"))
        chain = str(it.get("chain") or it.get("route") or "")
        rule = sanitize_approach(str(it.get("rule") or ""))
        if action == "retire":
            out.append({"action": "retire", "rule": rule, "lesson_key": it.get("lesson_key")})
            continue
        got = scrub_lesson({
            "when": when, "do": do, "avoid": avoid, "chain": chain,
            "cues": when, "techniques": do, "failed_techniques": avoid,
            "rule": rule,
            "idea": it.get("idea") or "",
            "method": it.get("method") or "",
            "route": it.get("route") or chain,
        })
        if not got:
            continue
        key = str(it.get("lesson_key") or "") or lesson_key(
            when=got.get("when") or [], do=got.get("do") or [],
            avoid=got.get("avoid") or [], chain=got.get("chain") or "",
        )
        got.update({
            "action": "upsert",
            "lesson_key": key,
            "wins": 0, "fails": 0, "uses": 0,
            "confidence": 0.45,
            "source_episode_ids": [],
        })
        out.append(got)
    return out


async def _retire_lesson(spec: dict) -> None:
    key = str(spec.get("lesson_key") or "")
    row = None
    if key:
        row = await db.fetchone(
            "SELECT * FROM memory WHERE kind='lesson' AND tags LIKE ? LIMIT 1",
            (f"%lesson_key:{key}%",),
        )
    if not row and spec.get("rule"):
        row = await db.fetchone(
            "SELECT * FROM memory WHERE kind='lesson' AND content LIKE ? LIMIT 1",
            (f"%{str(spec['rule'])[:40]}%",),
        )
    if not row:
        return
    content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
    if not isinstance(content, dict):
        return
    content["fails"] = int(content.get("fails") or 0) + 2
    content["confidence"] = _confidence(
        int(content.get("wins") or 0), int(content["fails"]), int(content.get("uses") or 0),
    )
    await db.execute("UPDATE memory SET content=? WHERE id=?", (_dumps(content), row["id"]))


async def ai_refine_playbook(*, recent_episodes: list[dict], playbook: list[dict]) -> list[dict]:
    """用 Claude Code 蒸馏合格 episode。失败返回空，不回退机械映射。"""
    if not bool(getattr(settings, "evolve_ai", True)):
        return []
    import asyncio

    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    from ..agents.session import _get_spawn_sem

    ep_lines = []
    for e in recent_episodes[:4]:
        if not episode_qualifies_for_evolve(e):
            continue
        c = e.get("content") if isinstance(e.get("content"), dict) else (e.get("content") or e or {})
        if not isinstance(c, dict):
            c = {}
        findings = []
        for f in c.get("findings") or []:
            if isinstance(f, dict):
                findings.append(
                    f"{f.get('category')}/{f.get('severity')}"
                    f"{'/rt='+str(f.get('redteam_rating')) if f.get('redteam_rating') else ''}"
                    f"{'/2nd' if f.get('secondary_verified') else ''}"
                )
        ep_lines.append(
            " - ".join(x for x in (
                f"outcome={e.get('outcome') or c.get('outcome')}",
                f"milestone={c.get('milestone') or ''}",
                f"stack={c.get('tech') or e.get('target_fp') or ''}",
                f"chain={sanitize_approach(str(c.get('winning_chain') or ''))}",
                f"techniques={c.get('techniques') or []}",
                f"avoid={c.get('failed_techniques') or []}",
                f"cues={c.get('cues') or []}",
                f"findings={findings}",
                f"approach={sanitize_approach(str(c.get('approach') or ''))}",
            ) if x)
        )
    if not ep_lines:
        return []
    pb_lines = []
    for p in playbook[:12]:
        c = scrub_lesson(p.get("content") or p)
        if not c:
            continue
        pb_lines.append(
            f"- key={c.get('lesson_key')} idea={c.get('idea')} method={c.get('method')} "
            f"route={c.get('route') or c.get('chain')} when={c.get('when')} do={c.get('do')}"
        )
    prompt = (
        "# 本局已确认的高危/严重洞或 flag 收口（禁止照抄题面路径）\n"
        + "\n".join(ep_lines)
        + "\n\n# 当前共用剧本（CTF/红队同一份，不要重复）\n"
        + ("\n".join(pb_lines) or "（空）")
        + "\n\n请蒸馏最多 3 条：思想、方式方法、路线。"
    )
    model = (getattr(settings, "evolve_model", None) or "").strip() or (
        (getattr(settings, "supervisor_model", None) or "").strip() or settings.claude_model
    )
    wait = float(getattr(settings, "evolve_timeout_sec", 90) or 90)
    opts = ClaudeAgentOptions(
        tools=[],
        allowed_tools=[],
        disallowed_tools=["Bash", "WebFetch", "Read", "Write", "Edit", "Grep", "Glob", "WebSearch", "TodoWrite", "Task"],
        system_prompt=EVOLVE_SYSTEM,
        model=model,
        fallback_model=settings.claude_fallback_model,
        max_turns=1,
        permission_mode="dontAsk",
        setting_sources=[],
        skills=[],
        plugins=[],
        cwd=str(settings.data_dir),
        max_buffer_size=8 * 1024 * 1024,
    )
    texts: list[str] = []

    async def _run() -> None:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for b in getattr(msg, "content", []) or []:
                    if isinstance(b, TextBlock) and (b.text or "").strip():
                        texts.append(b.text)

    applied: list[dict] = []
    sem = _get_spawn_sem()
    async with sem:
        await asyncio.wait_for(_run(), timeout=max(15.0, wait))
    for spec in parse_evolve_lessons("\n".join(texts)):
        if spec.get("action") == "retire":
            await _retire_lesson(spec)
            applied.append(spec)
        else:
            row = await upsert_lesson(
                spec,
                episode_id=str((recent_episodes[0] or {}).get("id") or "") or None,
            )
            if row:
                applied.append(row)
    return applied


async def evolve_after_run(
    *, episode: dict | None, applied_ids: list[str], won: bool, project_id: str | None = None,
) -> dict:
    """跑完一局：仅 flag / 高危严重洞才蒸馏或强化。失败局、中危洞、空猎不改剧本。"""
    del project_id, won
    full = episode if isinstance(episode, dict) else None
    if full and full.get("id") and not isinstance(full.get("content"), dict):
        row = await db.fetchone("SELECT * FROM memory WHERE id=?", (full["id"],))
        if row:
            content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
            if not isinstance(content, dict):
                content = {}
            full = {
                **full,
                "outcome": row.get("outcome") or full.get("outcome"),
                "content": content,
                "milestone": content.get("milestone"),
                "achievements": content.get("achievements") or [],
                "findings": content.get("findings") or [],
            }
    ok = episode_qualifies_for_evolve(full)
    distilled = None
    if ok and full and not full.get("skipped") and full.get("id"):
        distilled = await evolve_from_episode_id(str(full["id"]))
    if ok:
        await reinforce_lessons(applied_ids, won=True)
    return {
        "distilled": bool(distilled),
        "reinforced": len(applied_ids or []) if ok else 0,
        "ai_revised": 1 if distilled else 0,
    }
