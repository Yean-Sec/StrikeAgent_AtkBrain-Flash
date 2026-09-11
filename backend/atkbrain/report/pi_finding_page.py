"""单漏洞页：专职复核 Pi 二次验证+红队评级后撰写五个板块，禁止模板套话。"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from ..config import settings
from ..db import db

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}")
_LOCKS: dict[str, asyncio.Lock] = {}

PAGE_KEYS = ("report_summary", "report_impact", "report_rating", "report_repro", "report_fix")

PENDING_COPY = "专职复核 Pi 完成二次验证与红队评级后撰写本段，不使用模板套话。"

PI_PAGE_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的漏洞页撰稿人，只服务已经二次验证过的这一条洞。

你不是猎洞工人，也不套类别模板。五个板块都必须根据事实包里「这一次打到了什么」来写，写给安全工程师看。

硬约束
- 不得编造事实包没有的 Host、URL、路径、参数、账号、flag、命令输出或状态码。
- 「危害」只写对本项目/本资产已经被证据证明的影响；没打到的后续标「尚未证明」，不要写成已打穿。
- 「手动复现」写复核员实际走过的步骤（跳板、工具、命令、成功判定），不要写 Burp Repeater 十二步套话，不要 CIA 模型。
- 「修复方式」针对本条根因（例如弱口令、未授权接口、拼接 SQL），不要泛泛的「使用参数化查询」。
- 禁止把邻题 IP、本机 Kali 网段、平台控制台写进正文。

只输出 JSON：
{
  "summary": "漏洞简介（120～280 字：什么入口、怎么触发、验证看到了什么）",
  "impact": "对本项目的危害（120～280 字：影响到哪台主机/哪种数据/是否已证明命令执行或数据接管）",
  "rating": "红队评级（先写级别中文名和 critical|high|medium|low|info，再写为何是这个级、二次验证怎么打的）",
  "repro": "手动复现（分条，至少 4 步，含成功判定；可附真实 curl/命令，不新增 payload）",
  "fix": "修复方式（针对本条：立即缓解 + 根治，具体到账号/接口/配置）"
}
"""


def _lock_for(fid: str) -> asyncio.Lock:
    lock = _LOCKS.get(fid)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[fid] = lock
    return lock


def _clean(text: Any, *, limit: int = 8000) -> str:
    s = str(text or "").strip()
    if not s:
        return ""
    return s if len(s) <= limit else s[:limit].rstrip() + "…"


def pi_report_from(src: Any) -> dict[str, str]:
    def g(*names: str) -> str:
        for name in names:
            if isinstance(src, dict):
                val = src.get(name)
            else:
                val = getattr(src, name, None)
            s = _clean(val)
            if s:
                return s
        return ""
    return {
        "report_summary": g("report_summary", "summary"),
        "report_impact": g("report_impact", "impact"),
        "report_rating": g("report_rating", "rating"),
        "report_repro": g("report_repro", "repro"),
        "report_fix": g("report_fix", "fix"),
    }


def has_pi_page(finding: dict | None) -> bool:
    if not isinstance(finding, dict):
        return False
    need = ("report_summary", "report_impact", "report_repro", "report_fix")
    if not all(_clean(finding.get(k)) for k in need):
        return False
    rating = _clean(finding.get("report_rating")) or _clean(finding.get("redteam_rating_rationale"))
    return bool(rating)


def parse_pi_page(text: str) -> dict[str, str]:
    raw = (text or "").strip()
    if not raw:
        return {}
    blob = ""
    m = _JSON_FENCE_RE.search(raw)
    if m:
        blob = m.group(1)
    else:
        m2 = _JSON_OBJ_RE.search(raw)
        if m2:
            blob = m2.group(0)
    if not blob:
        return {}
    try:
        data = json.loads(blob)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return pi_report_from(data)


async def save_pi_page(fid: str, spec: dict[str, str]) -> None:
    if not fid or not spec:
        return
    vals = [(_clean(spec.get(k)) or None) for k in PAGE_KEYS]
    if not any(vals):
        return
    await db.execute(
        """UPDATE findings SET
               report_summary=COALESCE(?, report_summary),
               report_impact=COALESCE(?, report_impact),
               report_rating=COALESCE(?, report_rating),
               report_repro=COALESCE(?, report_repro),
               report_fix=COALESCE(?, report_fix)
           WHERE id=?""",
        (*vals, fid),
    )


def _facts_blob(finding: dict, project: dict | None) -> dict:
    p = project or {}
    cfg = p.get("config") or {}
    return {
        "project_name": p.get("name") or "",
        "target": p.get("target") or "",
        "objective": cfg.get("objective") or cfg.get("track") or "",
        "id": finding.get("id"),
        "title": finding.get("title"),
        "category": finding.get("category"),
        "severity": finding.get("severity"),
        "node_key": finding.get("node_key"),
        "description": _clean(finding.get("description"), limit=2000),
        "evidence": _clean(finding.get("evidence"), limit=6000),
        "poc_curl": _clean(finding.get("poc_curl"), limit=4000),
        "poc_python": _clean(finding.get("poc_python"), limit=4000),
        "proof_detail": _clean(finding.get("proof_detail"), limit=3000),
        "proof_url": finding.get("proof_url") or "",
        "redteam_rating": finding.get("redteam_rating") or "",
        "redteam_rating_rationale": _clean(finding.get("redteam_rating_rationale"), limit=4000),
        "related_node": finding.get("related_node"),
    }


async def compose_pi_page(finding: dict, *, project: dict | None = None) -> dict[str, str]:
    """二次验证完成后，用无工具一次性 Pi 撰写五个板块。"""
    if not bool(getattr(settings, "report_ai", True)):
        return {}
    from ..agents.pi_runtime import query_text

    facts = _facts_blob(finding, project)
    prompt = (
        "下面是本项目里已经二次验证过的一条漏洞事实包。"
        "请按系统要求撰写漏洞页五个板块，只使用这些事实。\n\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)[:80000]
    )
    model = (getattr(settings, "report_model", None) or "").strip() or (
        (getattr(settings, "supervisor_model", None) or "").strip() or settings.claude_model
    )
    wait = float(getattr(settings, "report_timeout_sec", 90) or 90)
    blob = await query_text(
        system_prompt=PI_PAGE_SYSTEM,
        user_prompt=prompt,
        cwd=str(settings.data_dir),
        timeout=max(20.0, wait),
        tools=False,
        model=model,
        role="finding-page",
        project_id=str(finding.get("project_id") or ""),
    )
    return parse_pi_page(blob)


async def ensure_pi_page(
    project_id: str,
    finding: dict,
    *,
    project: dict | None = None,
) -> dict:
    """已二次验证则保证有 Pi 撰写的五板块；未验证不编模板。"""
    out = dict(finding or {})
    fid = str(out.get("id") or "")
    if has_pi_page(out):
        return out
    if not out.get("secondary_verified"):
        return out
    if not fid:
        return out
    async with _lock_for(fid):
        row = await db.fetchone("SELECT * FROM findings WHERE id=? AND project_id=?", (fid, project_id))
        if not row:
            return out
        merged = {**out, **{k: (row.get(k) or out.get(k)) for k in PAGE_KEYS}}
        if has_pi_page(merged):
            for k in PAGE_KEYS:
                out[k] = merged.get(k) or ""
            return out
        merged["project_id"] = project_id
        try:
            spec = await compose_pi_page(merged, project=project)
        except Exception:
            spec = {}
        if spec:
            await save_pi_page(fid, spec)
            out.update(spec)
    return out


async def fill_missing_pi_pages(project_id: str, *, project: dict | None = None) -> int:
    """收口复核会话：给已评级但还没写页的洞补撰写。"""
    rows = await db.fetchall(
        """SELECT * FROM findings WHERE project_id=? AND secondary_verified=1
           AND (report_summary IS NULL OR TRIM(report_summary)='')""",
        (project_id,),
    )
    n = 0
    for row in rows or []:
        data = dict(row)
        if has_pi_page(data):
            continue
        got = await ensure_pi_page(project_id, data, project=project)
        if has_pi_page(got):
            n += 1
    return n
