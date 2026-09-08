"""交付报告导出任务：母版填槽 + 可选 Claude 撰写槽位内容 + 同源 PDF。"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from ..config import settings
from ..db import new_id
from . import generator as report_gen
from .pdf_print import html_to_pdf
from .slots import (
    PROMPT_REV,
    assemble_deliverable,
    cache_stem,
    facts_digest,
    parse_claude_enrich,
)
from .writeup import real_poc_text

CLAUDE_SYSTEM = f"""你为授权渗透测试交付报告填写内容槽位，不输出完整 HTML 文档，不写 <style>，不改版式。
提示词版本 {PROMPT_REV}。母版已固定：封面 tag/h1/meta、执行摘要 sum-grid、8 张 KPI、条形图+验证环、path-board（pn/parrow）、资产卡片、清单表、vf 卡片（①简介/技术成因 ②利用方式 ③修复 now/root）。你只填文字。

只输出 JSON：
{{
  "title_line": "封面主标题（机构或项目名）",
  "title_accent": "域名或目标，可空",
  "sub": "封面一两句概述，可点出入口与是否已拿权限",
  "goal_text": "若已拿权限则写「权限已获取」，否则空字符串",
  "goal_detail": "权限落地的一句话补充，可空",
  "summary_overview": "执行摘要左侧 HTML（p/ul/li/b/code/span），写清攻击链，不要产品名",
  "summary_conclusions": "执行摘要右侧 HTML，优先 <ul class=\\"concl\\"><li><span class=\\"tag-sev crit|high|med\\">等级</span><span>结论</span></li></ul>",
  "verify_note": "验证说明纯文本",
  "path_note": "攻击路径说明一句（会同时用作路径区导语与 caption）",
  "findings": {{
    "vuln-01": {{
      "intro": "①简介 / 技术成因（可多段，用换行分段）",
      "impact": "危害影响（会接在简介后）",
      "steps": ["②利用方式 逐步操作"],
      "prerequisites": "前置条件一句",
      "fixes_now": ["立即缓解"],
      "fixes_root": ["根治"],
      "fixes": ["若未分 now/root，可仍用此列表"],
      "verify": "修复验证一句话"
    }}
  }}
}}

硬约束
- 只使用事实包。没有的写「未采集」。禁止编造 URL / payload / CVE。
- 禁止出现内部引擎字段、时间线、附录、产品内部名称。
- 严重/高危必须写透简介、利用、修复。
- findings 的键用事实包里的 slot_id（vuln-01 …）。
"""

_jobs: dict[str, dict] = {}


def _job_public(job: dict) -> dict:
    return {
        "id": job["id"],
        "project_id": job["project_id"],
        "format": job["format"],
        "status": job["status"],
        "percent": int(job.get("percent") or 0),
        "message": job.get("message") or "",
        "error": job.get("error"),
        "filename": job.get("filename"),
        "cached": bool(job.get("cached")),
        "claude": bool(job.get("claude")),
        "claude_error": job.get("claude_error") or None,
    }


def get_export_job(project_id: str, job_id: str) -> dict | None:
    job = _jobs.get(job_id)
    if not job or job.get("project_id") != project_id:
        return None
    return _job_public(job)


def export_file_path(job_id: str, project_id: str) -> Path | None:
    job = _jobs.get(job_id)
    if not job or job.get("project_id") != project_id:
        return None
    fmt = job.get("format") or "html"
    if fmt == "pdf":
        p = job.get("pdf_path") or job.get("html_path")
    else:
        p = job.get("html_path")
    return Path(p) if p else None


def _set_job(job: dict, percent: int, message: str, status: str = "running") -> None:
    job["percent"] = max(0, min(100, int(percent)))
    job["message"] = message
    job["status"] = status


def _enrich_usable(enrich: dict | None) -> bool:
    if not isinstance(enrich, dict) or not enrich:
        return False
    findings = enrich.get("findings")
    return bool(
        enrich.get("title_line")
        or enrich.get("summary_overview")
        or enrich.get("sub")
        or (isinstance(findings, dict) and findings)
    )


def _compact_findings(findings: list[dict], *, limit: int = 24) -> list[dict]:
    out = []
    for i, f in enumerate(findings[:limit], 1):
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        out.append({
            "slot_id": f"vuln-{i:02d}",
            "title": f.get("title"),
            "severity": f.get("severity"),
            "category": f.get("category"),
            "verification": f.get("verification_status"),
            "description": (f.get("description") or "")[:2500],
            "root_cause": (f.get("root_cause") or "")[:3500],
            "mechanism": (f.get("mechanism") or "")[:2000],
            "impact_detail": (f.get("impact_detail") or "")[:2500],
            "manual_steps": (f.get("manual_steps") or [])[:18],
            "evidence": (f.get("evidence") or "")[:4000],
            "poc_curl": real_poc_text(poc.get("curl") or f.get("poc_curl"))[:2500],
            "proof_url": f.get("proof_url"),
        })
    return out


def _facts_payload(data: dict) -> dict:
    p = data.get("project") or {}
    g = data.get("graph") or {}
    return {
        "project": {"name": p.get("name"), "target": p.get("target")},
        "has_shell": data.get("has_shell"),
        "generated_at": str(data.get("generated_at") or "")[:10],
        "rce_path_titles": [
            next((n.get("title") for n in (g.get("nodes") or []) if n.get("key") == k), k)
            for k in ((g.get("rce_path") or {}).get("path") or [])[:10]
        ],
        "assets": [
            {"title": a.get("title"), "kind": a.get("kind"), "detail": a.get("detail")}
            for sec in (data.get("sections") or [])
            for a in (sec.get("assets") or [])
        ][:40],
        "findings": _compact_findings(data.get("findings") or []),
        "finding_count": len(data.get("findings") or []),
    }


async def _claude_enrich(facts: dict) -> dict:
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    from ..agents.session import _get_spawn_sem

    prompt = "# 渗透测试事实包（只填槽，禁止整页 HTML）\n" + json.dumps(facts, ensure_ascii=False, indent=2)[:100000]
    model = (getattr(settings, "report_model", None) or "").strip() or (
        (getattr(settings, "supervisor_model", None) or "").strip() or settings.claude_model
    )
    wait = max(60.0, float(getattr(settings, "report_timeout_sec", 90) or 90) * 2)
    wait = min(wait, 240.0)
    opts = ClaudeAgentOptions(
        tools=[],
        allowed_tools=[],
        disallowed_tools=["Bash", "WebFetch", "Read", "Write", "Edit", "Grep", "Glob", "WebSearch", "TodoWrite", "Task"],
        system_prompt=CLAUDE_SYSTEM,
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

    sem = _get_spawn_sem()
    async with sem:
        await asyncio.wait_for(_run(), timeout=wait)
    return parse_claude_enrich("\n".join(texts))


def _safe_name(pid: str, p: dict) -> str:
    raw = str(p.get("name") or pid)
    raw = re.sub(r"[\\/:*?\"<>|]+", "_", raw).strip() or pid
    return raw[:80]


async def run_export_job(job: dict) -> None:
    pid = job["project_id"]
    fmt = job["format"]
    try:
        _set_job(job, 8, "装配母版…")
        data = await report_gen.build_report_data(pid, enrich_ai=False)
        digest = facts_digest(data)
        out_dir = Path(settings.reports_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        stem = cache_stem(pid, digest)
        html_path = out_dir / f"{stem}.html"
        p = data.get("project") or {}
        fname_base = _safe_name(pid, p)

        force = bool(job.get("force", True))
        cached = (not force) and html_path.exists() and html_path.stat().st_size > 200
        if cached:
            _set_job(job, 72, "命中缓存，跳过 Claude 填槽…")
            html_doc = html_path.read_text(encoding="utf-8")
            job["cached"] = True
            job["claude"] = False
        else:
            _set_job(job, 22, "Claude 正在撰写槽位…")
            enrich: dict = {}
            claude_err = ""
            try:
                _set_job(job, 40, "Claude 正在撰写槽位…")
                enrich = await _claude_enrich(_facts_payload(data)) or {}
            except Exception as e:
                claude_err = str(e)[:400]
                enrich = {}
            if not _enrich_usable(enrich):
                if not claude_err:
                    claude_err = "Claude 未返回可用槽位 JSON"
                job["claude"] = False
                job["claude_error"] = claude_err
                _set_job(job, 58, f"Claude 填槽未成功，套入本地骨架（{claude_err[:160]}）")
                enrich = {}
            else:
                job["claude"] = True
                job["claude_error"] = None
                _set_job(job, 62, "套入母版槽位…")
            try:
                html_doc = assemble_deliverable(data, enrich=enrich or None)
            except Exception:
                _set_job(job, 70, "校验未过，回退本地模板…")
                html_doc = assemble_deliverable(data, enrich=None)
                job["claude"] = False
            _set_job(job, 82, "写入报告…")
            html_path.write_text(html_doc, encoding="utf-8")
            job["cached"] = False

        job["html_path"] = str(html_path)
        if fmt == "pdf":
            _set_job(job, 90, "渲染 PDF…")
            pdf_path = out_dir / f"{stem}.pdf"
            pdf_path.write_bytes(html_to_pdf(html_path.read_text(encoding="utf-8")))
            job["pdf_path"] = str(pdf_path)
            job["filename"] = f"{fname_base}.pdf"
        else:
            job["filename"] = f"{fname_base}.html"
        if job.get("claude"):
            done_msg = "报告已生成（Claude 已填槽）"
        elif job.get("claude_error"):
            done_msg = f"报告已生成（未走 Claude：{str(job.get('claude_error') or '')[:120]}）"
        elif job.get("cached"):
            done_msg = "报告已生成（命中缓存）"
        else:
            done_msg = "报告已生成"
        _set_job(job, 100, done_msg, status="done")
    except Exception as e:
        job["error"] = str(e)
        _set_job(job, int(job.get("percent") or 0), f"失败：{e}", status="error")


async def start_export_job(project_id: str, fmt: str, *, force: bool = True) -> dict:
    fmt = (fmt or "html").lower().strip()
    if fmt == "md":
        raise ProjectReportMdGone("项目总报告请改用 HTML 或 PDF 导出")
    if fmt not in ("html", "pdf"):
        raise ValueError("format 仅支持 html|pdf")
    job_id = new_id("rpt_")
    job = {
        "id": job_id,
        "project_id": project_id,
        "format": fmt,
        "status": "running",
        "percent": 1,
        "message": "已排队，准备调用 Claude 填槽…",
        "error": None,
        "filename": None,
        "cached": False,
        "claude": False,
        "claude_error": None,
        "force": bool(force),
    }
    _jobs[job_id] = job
    asyncio.create_task(run_export_job(job))
    return _job_public(job)


class ProjectReportMdGone(ValueError):
    """项目总报告不再提供 Markdown。"""


# 兼容旧测试名：不再生成整页 HTML / MD
def parse_claude_docs(text: str) -> tuple[str, str]:
    d = parse_claude_enrich(text)
    return str(d.get("html_body") or d.get("summary_overview") or ""), str(d.get("markdown") or "")


def wrap_html(data, **_kw) -> str:
    return assemble_deliverable(data, enrich=None)


def wrap_markdown(data, **_kw) -> str:
    raise ProjectReportMdGone("项目总报告请改用 HTML 或 PDF 导出")
