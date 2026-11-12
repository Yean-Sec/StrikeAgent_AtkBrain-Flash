"""单漏洞页：专职复核 Pi 二次验证+红队评级后撰写五个板块，禁止模板套话。"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from ..config import settings
from ..db import db

_LOCKS: dict[str, asyncio.Lock] = {}
_PAGE_TASKS: set[asyncio.Task] = set()
_SCHEDULED: set[str] = set()
_FAILED: set[str] = set()
log = logging.getLogger(__name__)

PAGE_KEYS = ("report_summary", "report_impact", "report_rating", "report_repro", "report_fix")
_JSON_KEYS = ("summary", "impact", "rating", "repro", "fix", *PAGE_KEYS)

PENDING_COPY = "专职复核 Pi 完成二次验证与红队评级后撰写本段，不使用模板套话。"
WRITING_COPY = "专职 Pi 正在撰写漏洞页…"
FAILED_COPY = "漏洞页这次没有写完。可重新撰写；未写完前不套用模板。"


def _page_system(project: dict | None) -> str:
    from atkbrain_native import config_output_lang, with_output_lang
    cfg = (project or {}).get("config") if isinstance(project, dict) else {}
    return with_output_lang(PI_PAGE_SYSTEM, config_output_lang(cfg))


PI_PAGE_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的漏洞页撰稿人，只服务已经二次验证过的这一条洞。

你不是猎洞工人，也不套类别模板。五个板块都必须根据事实包里「这一次打到了什么」来写，写给安全工程师看。

硬约束
- 不得编造事实包没有的 Host、URL、路径、参数、账号、flag、命令输出或状态码。
- 「危害」只写对本项目/本资产已经被证据证明的影响；没打到的后续标「尚未证明」，不要写成已打穿。
- 事实包若标明二次验证失败：五个板块仍按首次证据写完整，不要写成二次已经复现，也不要写成这类漏洞不存在。失败原因由复核理由单独展示，不要拿占位句代替正文。
- 「手动复现」写复核员实际走过的步骤（跳板、工具、命令、成功判定），不要写 Burp Repeater 十二步套话，不要把复现步骤改写成机密性/完整性/可用性三段论。
- 「修复方式」针对本条根因（例如弱口令、未授权接口、拼接 SQL），不要泛泛的「使用参数化查询」。
- 禁止把邻题 IP、本机网段、平台控制台写进正文。

只输出 JSON：
{
  "summary": "漏洞简介（120～280 字：什么入口、怎么触发、验证看到了什么）",
  "impact": "对本项目的危害（120～280 字：影响到哪台主机/哪种数据/是否已证明命令执行或数据接管）",
  "rating": "NVD CVSS 3.1（先写 CVSS:3.1 向量和基础分，再写 NVD 定性：低危/中危/高危/严重，以及八项为什么这样打）",
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


def report_from(src: Any) -> dict[str, str]:
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


def has_page(finding: dict | None) -> bool:
    if not isinstance(finding, dict):
        return False
    need = ("report_summary", "report_impact", "report_repro", "report_fix")
    if not all(_clean(finding.get(k)) for k in need):
        return False
    rating = _clean(finding.get("report_rating")) or _clean(finding.get("redteam_rating_rationale"))
    return bool(rating)


def parse_page(text: str) -> dict[str, str]:
    """从模型回复里取出五个板块。用解码器读完整对象，避免正文里的花括号把 JSON 截断。"""
    raw = (text or "").strip()
    if not raw:
        return {}
    decoder = json.JSONDecoder()
    best: dict | None = None
    best_n = 0
    for i, ch in enumerate(raw):
        if ch != "{":
            continue
        try:
            data, _end = decoder.raw_decode(raw[i:])
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        n = sum(1 for k in _JSON_KEYS if _clean(data.get(k)))
        if n > best_n:
            best = data
            best_n = n
            if n >= 4:
                break
    if not best:
        return {}
    return report_from(best)


async def save_page(fid: str, spec: dict[str, str]) -> None:
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
        "verification_status": finding.get("verification_status") or "",
        "secondary_verified": bool(finding.get("secondary_verified")),
        "related_node": finding.get("related_node"),
    }


async def compose_page(finding: dict, *, project: dict | None = None) -> dict[str, str]:
    """二次验证完成后，用无工具一次性 Pi 撰写五个板块。"""
    if not bool(getattr(settings, "report_ai", True)):
        return {}
    from atkbrain_native import query_text, role_model

    facts = _facts_blob(finding, project)
    failed = str(finding.get("verification_status") or "").lower() == "excluded"
    lead = (
        "下面这条的二次验证没有复现同样危害。仍按首次事实撰写五个板块，不要写成已经二次验证通过。"
        if failed else
        "下面是本项目里已经二次验证过的一条漏洞事实包。"
    )
    prompt = (
        lead
        + "请按系统要求撰写漏洞页五个板块，只使用这些事实。\n\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)[:80000]
    )
    model = role_model(
        getattr(settings, "report_model", None),
        getattr(settings, "supervisor_model", None),
    )
    wait = float(getattr(settings, "report_timeout_sec", 90) or 90)
    blob = await asyncio.to_thread(
        query_text,
        _page_system(project),
        prompt,
        str(settings.data_dir),
        max(20.0, wait),
        False,
        model,
        "finding-page",
        str(finding.get("project_id") or (project or {}).get("id") or ""),
    )
    return parse_page(blob)


async def ensure_page(
    project_id: str,
    finding: dict,
    *,
    project: dict | None = None,
) -> dict:
    """二次完成才写五段；二次开关关掉时，有评级或首次入库即可写页。"""
    out = dict(finding or {})
    fid = str(out.get("id") or "")
    if has_page(out):
        return out
    if not out.get("secondary_verified"):
        failed = str(out.get("verification_status") or "").lower() == "excluded"
        from ..review.flags import get_review_flags
        if get_review_flags()["secondary_verify"] and not failed:
            return out
    if not fid:
        return out
    async with _lock_for(fid):
        row = await db.fetchone("SELECT * FROM findings WHERE id=? AND project_id=?", (fid, project_id))
        if not row:
            return out
        merged = {**out, **{k: (row.get(k) or out.get(k)) for k in PAGE_KEYS}}
        if has_page(merged):
            for k in PAGE_KEYS:
                out[k] = merged.get(k) or ""
            return out
        merged["project_id"] = project_id
        try:
            spec = await compose_page(merged, project=project)
        except Exception:
            spec = {}
        if spec:
            await save_page(fid, spec)
            out.update(spec)
    return out


def page_activity(fid: str) -> str:
    """writing：这条的撰写任务还在跑。failed：上一轮没写出五段。idle：还没挂任务。"""
    if fid in _SCHEDULED:
        return "writing"
    if fid in _FAILED:
        return "failed"
    return "idle"


def clear_page_failure(fid: str) -> None:
    _FAILED.discard(fid)


def schedule_page(project_id: str, fid: str) -> None:
    """二次已完成但五段还空时补写。同一条只挂一个任务，并保住任务引用。"""
    if not project_id or not fid or fid in _SCHEDULED:
        return
    _SCHEDULED.add(fid)
    _FAILED.discard(fid)

    async def _run() -> None:
        outcome = "fail"
        try:
            row = await db.fetchone(
                "SELECT * FROM findings WHERE id=? AND project_id=?",
                (fid, project_id),
            )
            if not row:
                outcome = "skip"
                return
            data = dict(row)
            if has_page(data):
                outcome = "ok"
                return
            from ..review.flags import get_review_flags
            failed = str(data.get("verification_status") or "").lower() == "excluded"
            if not data.get("secondary_verified") and get_review_flags()["secondary_verify"] and not failed:
                outcome = "skip"
                return
            from atkbrain_native import get_project
            proj = get_project(project_id)
            got = await ensure_page(project_id, data, project=proj)
            if has_page(got):
                outcome = "ok"
            else:
                log.warning("finding page was not written pid=%s fid=%s", project_id, fid)
        except Exception:
            log.exception("finding page write failed pid=%s fid=%s", project_id, fid)
            outcome = "fail"
        finally:
            if outcome == "ok":
                _FAILED.discard(fid)
            elif outcome == "fail":
                _FAILED.add(fid)
            _SCHEDULED.discard(fid)

    try:
        task = asyncio.get_running_loop().create_task(_run())
    except RuntimeError:
        _SCHEDULED.discard(fid)
        _FAILED.add(fid)
        return
    _PAGE_TASKS.add(task)
    task.add_done_callback(_PAGE_TASKS.discard)


async def fill_missing_pages(project_id: str, *, project: dict | None = None) -> int:
    """收口复核会话：给已达到写页门槛但还没写页的洞补撰写。"""
    from ..review.flags import get_review_flags
    if get_review_flags()["secondary_verify"]:
        sql = """SELECT * FROM findings WHERE project_id=?
                 AND (secondary_verified=1 OR lower(IFNULL(verification_status,''))='excluded')
                 AND (report_summary IS NULL OR TRIM(report_summary)='')"""
    else:
        sql = """SELECT * FROM findings WHERE project_id=?
                 AND (report_summary IS NULL OR TRIM(report_summary)='')"""
    rows = await db.fetchall(sql, (project_id,))
    n = 0
    for row in rows or []:
        data = dict(row)
        if has_page(data):
            continue
        got = await ensure_page(project_id, data, project=project)
        if has_page(got):
            n += 1
    return n
