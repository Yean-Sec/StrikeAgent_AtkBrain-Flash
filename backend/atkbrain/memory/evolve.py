"""自进化：把 episode 蒸馏成可迁移剧本，按指纹取回并回灌下一局。

写（episode）→ 蒸（lesson / playbook）→ 取（retrieve）→ 用（指挥官/监督）→ 强化（赢加分、输衰减）。
剧本不含 IP/URL/题面路径；只留手法、线索、失败族、战术链。
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


def episode_worth_ai_refine(episode: dict | None) -> bool:
    """空猎/无手法的 episode 不要再开一轮 evolve LLM（浪费配额、污染会话标题）。"""
    if not episode or episode.get("skipped"):
        return False
    c = episode.get("content") if isinstance(episode.get("content"), dict) else episode
    if not isinstance(c, dict):
        return False
    for key in ("techniques", "failed_techniques", "winning_chain", "winning_path", "cues", "findings"):
        val = c.get(key)
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, (list, tuple, set)) and any(str(x).strip() for x in val):
            return True
    return bool(distill_content(c, str(episode.get("outcome") or ""), str(c.get("target_fp") or "*")))


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
    merged = {
        "lesson_key": old.get("lesson_key") or incoming.get("lesson_key"),
        "rule": rule[:240],
        "when": when,
        "do": do,
        "avoid": avoid,
        "chain": chain,
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
    if not draft or not (draft.get("do") or draft.get("avoid") or draft.get("chain")):
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
    if not episode_id:
        return None
    row = await db.fetchone("SELECT * FROM memory WHERE id=?", (episode_id,))
    if not row or (row.get("kind") or "episode") == "lesson":
        return None
    content = _loads(row["content"]) if isinstance(row.get("content"), str) else (row.get("content") or {})
    if not isinstance(content, dict):
        content = {}
    draft = distill_content(content, str(row.get("outcome") or ""), str(row.get("target_fp") or "*"))
    if not draft:
        return None
    return await upsert_lesson(draft, episode_id=episode_id)


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
    """按当前图上的技术栈/线索/战术取可迁移剧本。CTF 不匹配具体主机或题号。"""
    rows = await db.fetchall(
        "SELECT * FROM memory WHERE kind='lesson' ORDER BY created_at DESC LIMIT 80",
    )
    if not rows:
        return []
    from ..objective import objective_allows_flag
    cfg = (project or {}).get("config") or {}
    strict = objective_allows_flag(cfg.get("objective") or cfg.get("track"))
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
        score = _score_lesson(clean, signals, fp, strict=strict)
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
        "## 进化经验（可迁移手法。只作思路启发：按当前图上的栈/线索选用并当场验证；"
        "禁止当作本题步骤清单，禁止套用 IP/路径/题号/payload）"
    ]
    for it in lessons[:6]:
        c = scrub_lesson(it.get("content") or it) or {}
        text = format_methodology(
            when=list(c.get("when") or []),
            do=list(c.get("do") or []),
            avoid=list(c.get("avoid") or []),
            chain=str(c.get("chain") or ""),
        )
        if text:
            lines.append("- " + text[:220])
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


EVOLVE_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的进化编辑。任务：把实战 episode 收成可迁移手法。
只保留：技术栈名、线索名（如 inject_surface）、战术名（如 sqli/ssti/ssrf）、失败策略族、类型链（entry → vuln(sqli)）。
禁止：IP、主机、端口、题号、URL、题面路径、flag 原文、getflag 当手法、Intent id、具体 payload。
when 只能是技术栈或线索名；do/avoid 只能是战术名。
已有剧本可修订或退休，不要重复同一条。
只输出 JSON：
{"lessons":[{"action":"upsert|retire","rule":"...","when":["php"],"do":["sqli"],"avoid":["content_enum"],"chain":"entry → service(http) → vuln(sqli)"}]}
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
    for it in items[:12]:
        if not isinstance(it, dict):
            continue
        action = str(it.get("action") or "upsert").lower()
        when = _norm_list(it.get("when"))
        do = _norm_list(it.get("do"))
        avoid = _norm_list(it.get("avoid"))
        chain = str(it.get("chain") or "")
        rule = sanitize_approach(str(it.get("rule") or ""))
        if action == "retire":
            out.append({"action": "retire", "rule": rule, "lesson_key": it.get("lesson_key")})
            continue
        got = scrub_lesson({
            "when": when, "do": do, "avoid": avoid, "chain": chain,
            "cues": when, "techniques": do, "failed_techniques": avoid,
            "rule": rule,
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
    """Hunt 结束后可选的 AI 修订。失败则返回空，不影响机械蒸馏。"""
    if not bool(getattr(settings, "evolve_ai", True)):
        return []
    import asyncio

    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    from ..agents.session import _get_spawn_sem

    ep_lines = []
    for e in recent_episodes[:8]:
        c = e.get("content") or e
        d = distill_content(c, str(e.get("outcome") or ""), str(e.get("target_fp") or "*"))
        if not d:
            continue
        ep_lines.append(
            f"- outcome={e.get('outcome')} when={d.get('when')} do={d.get('do')} "
            f"avoid={d.get('avoid')} chain={d.get('chain')}"
        )
    pb_lines = []
    for p in playbook[:12]:
        c = scrub_lesson(p.get("content") or p)
        if not c:
            continue
        pb_lines.append(
            f"- key={c.get('lesson_key')} conf={c.get('confidence')} "
            f"when={c.get('when')} do={c.get('do')} avoid={c.get('avoid')} chain={c.get('chain')}"
        )
    prompt = (
        "# 最近 episode\n" + ("\n".join(ep_lines) or "（无）")
        + "\n\n# 当前剧本\n" + ("\n".join(pb_lines) or "（空）")
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
            row = await upsert_lesson(spec)
            if row:
                applied.append(row)
    return applied


async def evolve_after_run(
    *, episode: dict | None, applied_ids: list[str], won: bool, project_id: str | None = None,
) -> dict:
    """跑完一局：蒸馏新 episode、强化用过的剧本、可选 AI 修订。"""
    distilled = None
    if episode and not episode.get("skipped") and episode.get("id"):
        distilled = await evolve_from_episode_id(str(episode["id"]))
    await reinforce_lessons(applied_ids, won=won)
    ai_n = 0
    if bool(getattr(settings, "evolve_ai", True)) and episode_worth_ai_refine(episode):
        try:
            recent = await db.fetchall(
                """SELECT id, outcome, target_fp, content FROM memory
                   WHERE kind='episode' ORDER BY created_at DESC LIMIT 8""",
            )
            eps = []
            for r in recent or []:
                c = _loads(r["content"]) if isinstance(r.get("content"), str) else (r.get("content") or {})
                eps.append({"outcome": r.get("outcome"), "target_fp": r.get("target_fp"), "content": c or {}})
            pb = await list_playbook(limit=12)
            applied = await ai_refine_playbook(recent_episodes=eps, playbook=pb)
            ai_n = len(applied)
        except Exception:
            ai_n = 0
    return {"distilled": bool(distilled), "reinforced": len(applied_ids), "ai_revised": ai_n}
