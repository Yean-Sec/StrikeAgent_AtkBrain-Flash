"""单漏洞详细报告：全量详情序列化 + Markdown 渲染。"""
from __future__ import annotations

from typing import Any

from atkbrain_native import display_finding_severity, redteam_rating_block
from .poc import poc_for_finding
from .writeup import real_poc_text


def _row_get(row: Any, key: str, default=None):
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default if not isinstance(row, dict) else row.get(key, default)


_REMEDIATION: dict[str, dict[str, str]] = {
    "rce": {"impact": "攻击者可能在目标进程权限范围内执行任意命令，并进一步读取数据、横向移动或持续控制。", "prerequisites": "攻击者可访问对应输入点，且目标路径/解释器/执行条件满足。", "remediation": "移除动态命令拼接；使用参数化 API 与严格 allowlist；关闭不必要执行能力；以最小权限运行服务并修补相关组件。"},
    "command_injection": {"impact": "攻击者可借助系统命令调用突破应用逻辑边界。", "prerequisites": "可控输入进入 shell、命令解释器或不安全的子进程调用。", "remediation": "避免 shell=True 与字符串拼接；使用参数数组调用；对输入采用 allowlist；限制子进程权限与网络访问。"},
    "sqli": {"impact": "可能读取、修改或删除数据库数据，并在特定配置下扩大到服务权限。", "prerequisites": "可控参数进入 SQL 查询且未使用参数化绑定。", "remediation": "使用预编译/参数化查询；移除拼接 SQL；收紧数据库账号权限；增加统一输入验证与异常审计。"},
    "file_upload": {"impact": "攻击者可能上传可执行或敏感文件，形成代码执行或数据覆盖风险。", "prerequisites": "上传入口可访问，且服务端仅依赖文件名、MIME 或前端校验。", "remediation": "对内容做服务端验证与重编码；上传目录置于 Web 根目录外；使用随机文件名、最小权限和下载白名单。"},
    "auth_bypass": {"impact": "攻击者可能绕过认证进入受保护功能或取得高权限会话。", "prerequisites": "攻击者可触达认证流程、令牌校验或权限分支。", "remediation": "统一服务端鉴权；校验令牌签名、有效期与受众；移除前端信任逻辑；为关键操作增加二次校验和审计。"},
    "idor": {"impact": "攻击者可能读取或修改其他用户/租户的对象。", "prerequisites": "已认证低权限用户可构造或枚举对象标识。", "remediation": "每次对象访问都在服务端执行主体、租户与对象级授权；避免以可枚举 ID 作为唯一控制。"},
}


def finding_guidance(finding: dict) -> dict[str, str]:
    cat = str(finding.get("category") or "").lower()
    guidance = _REMEDIATION.get(cat) or {
        "impact": "影响以已验证证据为准；应结合关联资产与权限边界进行复核。",
        "prerequisites": "攻击前置条件见验证证据、PoC 与关联节点。",
        "remediation": "修复根因、限制攻击面、补充服务端校验，并在修复后使用相同证据路径回归验证。",
    }
    cvss = "CVSS 未提供；严重度由已验证的影响与可利用性综合判定。" if finding.get("cvss") is None else f"CVSS {finding['cvss']}；分值应结合部署环境、权限与影响范围复核。"
    return {**guidance, "cvss_explanation": cvss}


def serialize_finding_full(row: Any, *, related_node: dict | None = None,
                           related_edges: list | None = None) -> dict:
    """DB 行 → 不截断的 finding 详情（供弹层 / MD）。"""
    sev = display_finding_severity(row)
    cat = row["category"]
    st = _row_get(row, "verification_status") or "verified"
    out = {
        "id": row["id"],
        "project_id": row["project_id"],
        "node_key": row["node_key"],
        "severity": sev,
        "category": cat,
        "title": row["title"],
        "description": row["description"],
        "evidence": row["evidence"],
        "poc_curl": row["poc_curl"],
        "poc_python": row["poc_python"],
        "cvss": row["cvss"],
        "created_at": row["created_at"],
        "critical": sev == "critical",
        "verification_status": st,
        "verified_at": _row_get(row, "verified_at"),
        "proof_type": _row_get(row, "proof_type"),
        "proof_canary": _row_get(row, "proof_canary"),
        "proof_url": _row_get(row, "proof_url"),
        "proof_detail": _row_get(row, "proof_detail"),
        "secondary_verified": bool(_row_get(row, "secondary_verified") or 0),
        "redteam_rating": _row_get(row, "redteam_rating"),
        "redteam_rating_rationale": _row_get(row, "redteam_rating_rationale"),
        "report_summary": _row_get(row, "report_summary"),
        "report_impact": _row_get(row, "report_impact"),
        "report_rating": _row_get(row, "report_rating"),
        "report_repro": _row_get(row, "report_repro"),
        "report_fix": _row_get(row, "report_fix"),
        "related_node": related_node,
        "related_edges": related_edges or [],
    }
    return out


def _verify_label(st: str | None, lang: str | None = None) -> str:
    from atkbrain_native import lab, normalize_locale
    s = (st or "verified").lower()
    loc = normalize_locale(lang)
    extra = {
        "zh": {
            "verified": "已验证",
            "pending": "未验证 / 待复核",
            "flaky": "不稳定（曾复现）",
            "rejected": "已驳回",
            "excluded": "二次验证失败",
        },
        "en": {
            "verified": "Verified",
            "pending": "Unverified / pending",
            "flaky": "Flaky (previously reproduced)",
            "rejected": "Rejected",
            "excluded": "Secondary verification failed",
        },
    }
    return extra.get(loc, extra["zh"]).get(s) or lab("intel", loc) or s


def exclusion_reason(finding: dict) -> str:
    """二次验证失败时，复核写下的原因。漏洞页五段照写。"""
    return (
        str(finding.get("redteam_rating_rationale") or "").strip()
        or str(finding.get("proof_detail") or "").strip()
    )


def _secondary_failed(finding: dict) -> bool:
    return str(finding.get("verification_status") or "").lower() == "excluded"


def _has_verified_body(finding: dict) -> bool:
    """二次已经写下的结论。有这些就不能再显示「正在撰写」。"""
    keys = (
        "description", "evidence", "proof_detail", "poc_curl", "poc_python",
        "redteam_rating_rationale",
        "report_summary", "report_impact", "report_rating", "report_repro", "report_fix",
    )
    return any(str(finding.get(k) or "").strip() for k in keys)


def _page_state(finding: dict) -> str:
    """pending：二次还没完成。
    ready：二次已有结论。五段没落库时也展示验证写下的信息，不再盖成「正在撰写」。
    writing：二次还没有可展示的正文。
    """
    from .finding_page import has_page
    from ..review.flags import get_review_flags

    need_sec = bool(get_review_flags().get("secondary_verify", True))
    sec = bool(finding.get("secondary_verified"))
    failed = _secondary_failed(finding)
    if need_sec and not sec and not failed:
        return "pending"
    if has_page(finding) or ((sec or failed) and _has_verified_body(finding)):
        return "ready"
    return "writing"


def _apply_verified_facts(out: dict) -> None:
    """五段还没写完时，详情直接用这次验证留下的正文。"""
    def clean(value) -> str:
        return str(value or "").strip()

    if not clean(out.get("report_summary")):
        out["report_summary"] = clean(out.get("description")) or clean(out.get("title"))
    if not clean(out.get("report_impact")):
        out["report_impact"] = clean(out.get("evidence")) or clean(out.get("proof_detail"))
    if not clean(out.get("report_rating")):
        out["report_rating"] = clean(out.get("redteam_rating_rationale"))
        if not clean(out.get("report_rating")) and clean(out.get("redteam_rating")):
            out["report_rating"] = f"NVD CVSS 3.1：{clean(out.get('redteam_rating'))}"
    if not clean(out.get("report_repro")):
        parts = [clean(out.get("proof_detail")), clean(out.get("poc_curl")), clean(out.get("poc_python"))]
        out["report_repro"] = "\n\n".join(part for part in parts if part)


def prepare_finding_report(finding: dict, *, poc: dict | None = None, progress: str | None = None) -> dict:
    """二次有结论后立刻展示验证正文。五段没写完时用描述、证据、复核说明和 PoC，不再盖成「正在撰写」。

    progress=failed：二次还没有任何正文、撰写也失败了，才显示撰写失败。
    """
    from .finding_page import FAILED_COPY, PENDING_COPY, WRITING_COPY

    out = dict(finding)
    _ = poc
    state = _page_state(out)
    if state == "writing" and progress == "failed":
        state = "failed"
    if state == "ready":
        _apply_verified_facts(out)
    out["report_state"] = state
    out["report_pending"] = state != "ready"
    if _secondary_failed(out):
        out["exclusion_reason"] = exclusion_reason(out)
    if state != "ready":
        if state == "writing":
            note = WRITING_COPY
        elif state == "failed":
            note = FAILED_COPY
        else:
            note = PENDING_COPY
        out["impact_detail"] = note
        out["impact"] = note
        out["secondary_review"] = note
        out["manual_repro"] = note
        out["manual_steps"] = []
        out["remediation"] = note
        return out
    summary = (out.get("report_summary") or "").strip()
    impact = (out.get("report_impact") or "").strip()
    rating = (out.get("report_rating") or "").strip()
    repro = (out.get("report_repro") or "").strip()
    fix = (out.get("report_fix") or "").strip()
    if summary:
        out["description"] = summary
    if impact:
        out["impact_detail"] = impact
        out["impact"] = impact
    if rating:
        out["secondary_review"] = rating
    if repro:
        out["manual_repro"] = repro
        out["manual_steps"] = [ln.strip() for ln in repro.splitlines() if ln.strip()]
    else:
        out["manual_repro"] = ""
        out["manual_steps"] = []
    out["remediation"] = fix
    return out


def manual_verification_steps(finding: dict, poc: dict | None = None) -> list[str]:
    """兼容旧调用名：详细手动复现步骤。"""
    from .writeup import manual_reproduction_steps
    return manual_reproduction_steps(finding, poc)


def _md_block(text: str | None, empty: str = "_未采集_") -> list[str]:
    t = (text or "").strip()
    if not t:
        return [empty, ""]
    return [t, ""]


def render_finding_markdown(
    project: dict | None,
    finding: dict,
    *,
    poc: dict | None = None,
    heading: str = "#",
    lang: str | None = None,
    progress: str | None = None,
) -> str:
    """单漏洞 Markdown：简介、危害、红队评级、手动复现、修复方式。"""
    from atkbrain_native import normalize_locale
    loc = normalize_locale(lang)
    heads = {
        "zh": {
            "cat": "类别", "status": "验证状态", "id": "漏洞 ID",
            "summary": "漏洞简介", "impact": "危害", "rating": "NVD CVSS 3.1",
            "repro": "手动复现", "fix": "修复方式", "uncat": "未分类",
            "why": "二次验证失败原因",
            "why_empty": "二次验证失败原因没有写入。",
            "empty": "_未采集_",
            "no_poc": "_未采集可执行 PoC（无真实 poc_curl / poc_python）。_",
            "no_synth": "_系统拒绝为高危项合成假利用脚本。_",
        },
        "en": {
            "cat": "Category", "status": "Verification", "id": "Finding ID",
            "summary": "Summary", "impact": "Impact", "rating": "Red-team rating",
            "repro": "Manual reproduction", "fix": "Remediation", "uncat": "Uncategorized",
            "why": "Why secondary verification failed",
            "why_empty": "The secondary-verification failure reason was not written.",
            "empty": "_Not collected_",
            "no_poc": "_No executable PoC collected (no real poc_curl / poc_python)._",
            "no_synth": "_The system refused to synthesize an exploit script for a high/critical item._",
        },
    }[loc]
    p = project or {}
    target = p.get("target") or ""
    poc = poc or poc_for_finding(finding, target if isinstance(target, str) else "")
    finding = prepare_finding_report(finding, poc=poc, progress=progress)
    sev = display_finding_severity(finding).upper()
    cat = finding.get("category") or ""
    title = finding.get("title") or finding.get("id") or "finding"
    vs = finding.get("verification_status") or "verified"
    h2 = heading + "#" if heading else "##"
    lines = [
        f"{heading} [{sev}] {title}",
        "",
        f"- {heads['cat']}: `{cat or heads['uncat']}`",
        f"- {heads['status']}: **{_verify_label(vs, loc)}**",
        f"- {heads['id']}: `{finding.get('id', '')}`",
        "",
        f"{h2} {heads['summary']}",
        "",
    ]
    ready = finding.get("report_state") == "ready"
    note = (finding.get("impact_detail") or "").strip()
    if ready:
        lines += _md_block(finding.get("description") or finding.get("title"), heads["empty"])
    else:
        lines += _md_block(note, heads["empty"])
    lines += [f"{h2} {heads['impact']}", ""]
    if ready:
        lines += _md_block(finding.get("impact_detail") or finding.get("impact"), heads["empty"])
    else:
        lines += _md_block(note, heads["empty"])
    lines += [f"{h2} {heads['rating']}", ""]
    if ready:
        lines += _md_block(finding.get("secondary_review") or redteam_rating_block(finding), heads["empty"])
    else:
        lines += _md_block(note, heads["empty"])
    lines += [f"{h2} {heads['repro']}", ""]
    if ready:
        repro = (finding.get("manual_repro") or "").strip()
        if repro:
            lines += _md_block(repro, heads["empty"])
        else:
            for s in finding.get("manual_steps") or []:
                lines.append(s)
            if not finding.get("manual_steps"):
                lines += _md_block("", heads["empty"])
        curl = real_poc_text(poc.get("curl") or finding.get("poc_curl"))
        py = real_poc_text(poc.get("python") or finding.get("poc_python"))
        raw_curl = (poc.get("curl") or finding.get("poc_curl") or "").strip()
        raw_py = (poc.get("python") or finding.get("poc_python") or "").strip()
        if curl:
            lines += ["```bash", curl, "```", ""]
        if py:
            lines += ["```python", py, "```", ""]
        if not curl and not py:
            lines += [heads["no_poc"], ""]
            if raw_curl or raw_py:
                lines.append(heads["no_synth"])
    else:
        lines += _md_block(note, heads["empty"])
    lines += [f"{h2} {heads['fix']}", ""]
    if ready:
        lines += _md_block(finding.get("remediation") or finding.get("report_fix"), heads["empty"])
    else:
        lines += _md_block(note, heads["empty"])
    if _secondary_failed(finding):
        lines += [f"{h2} {heads['why']}", ""]
        lines += _md_block(exclusion_reason(finding), heads["why_empty"])
    return "\n".join(lines)


def is_reportable_finding(row: Any) -> bool:
    """非 rejected 即可出完整详情与 MD（含低/中危与未验证）。"""
    st = str(_row_get(row, "verification_status") or "verified").lower()
    return st != "rejected"
