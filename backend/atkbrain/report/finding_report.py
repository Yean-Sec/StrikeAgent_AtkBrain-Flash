"""单漏洞详细报告：全量详情序列化 + Markdown 渲染。"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from ..graph.model import display_finding_severity, secondary_review_narrative
from .poc import poc_for_finding
from .writeup import apply_deterministic_writeup, real_poc_text


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
        "related_node": related_node,
        "related_edges": related_edges or [],
    }
    out.update(finding_guidance(out))
    return out


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return ""
    try:
        return _dt.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(ts)


def _verify_label(st: str | None) -> str:
    s = (st or "verified").lower()
    return {
        "verified": "已验证",
        "pending": "未验证 / 待复核",
        "flaky": "不稳定（曾复现）",
        "rejected": "已驳回",
    }.get(s, s)


def prepare_finding_report(finding: dict, *, poc: dict | None = None) -> dict:
    """补齐成因/危害/手动复现，供弹层与导出共用。"""
    out = dict(finding)
    if "impact" not in out:
        out.update(finding_guidance(out))
    return apply_deterministic_writeup(out, poc=poc)


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
) -> str:
    """单漏洞 Markdown 报告（成因、危害、手动复现、证据、PoC）。"""
    p = project or {}
    target = p.get("target") or ""
    poc = poc or poc_for_finding(finding, target if isinstance(target, str) else "")
    finding = prepare_finding_report(finding, poc=poc)
    sev = display_finding_severity(finding).upper()
    cat = finding.get("category") or ""
    title = finding.get("title") or finding.get("id") or "finding"
    node = finding.get("related_node") or {}
    vs = finding.get("verification_status") or "verified"
    h2 = heading + "#" if heading else "##"
    h3 = h2 + "#"
    lines = [
        f"{heading} [{sev}] {title}",
        "",
        f"- 项目：`{p.get('name', '')}`（`{p.get('id', '')}`）",
        f"- 目标：`{target or '（见关联节点）'}`",
        f"- 类别：`{cat or '未分类'}`",
        f"- 严重度：`{sev.lower()}`（以红队二次验证评级为准）"
        + (f" · CVSS {finding.get('cvss')}" if finding.get("cvss") is not None else ""),
        f"- 验证状态：**{_verify_label(vs)}**（`{vs}`）",
        f"- 漏洞 ID：`{finding.get('id', '')}`",
        f"- 关联节点：`{finding.get('node_key') or '-'}`"
        + (f"（{node.get('title')}）" if node.get("title") else ""),
        f"- 生成时间：{_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"{h2} 基本信息",
        "",
        f"- 位置 / node_key：`{finding.get('node_key') or '未关联节点'}`",
        f"- 前置条件：{(finding.get('prerequisites') or '见证据与关联节点。').strip()}",
        "",
        f"{h2} 漏洞原理",
        "",
    ]
    lines += _md_block(finding.get("mechanism"))
    lines += [f"{h2} 漏洞说明", ""]
    lines += _md_block(finding.get("root_cause") or finding.get("description"))
    lines += [f"{h2} 危害与影响", ""]
    lines += _md_block(finding.get("impact_detail") or finding.get("impact"))
    lines += [f"{h2} 影响资产与攻击入口", ""]
    lines += _md_block(finding.get("affected_scope"))
    if finding.get("param_analysis"):
        lines += [f"{h2} 参数与可控点", "", finding["param_analysis"], ""]
    http_raw = (finding.get("http_raw") or "").strip()
    if http_raw:
        lines += [f"{h2} 原始 HTTP 请求", "", "将以下内容粘贴到 Burp Repeater：", "", "```http", http_raw, "```", ""]
    if finding.get("expected_result") or finding.get("expected_signals"):
        lines += [f"{h2} 复现成功判定", ""]
        if finding.get("expected_result"):
            lines += [str(finding.get("expected_result")), ""]
        for s in finding.get("expected_signals") or []:
            lines.append(f"- {s}")
        lines.append("")
    lines += [f"{h2} 手动复现", "", "按下列步骤在授权环境中复现。不要使用报告未给出的 payload。工具以 Burp Repeater + curl 为准。", ""]
    for s in finding.get("manual_steps") or []:
        lines.append(s)
    lines += ["", f"{h2} 二次验证与红队评级", ""]
    lines += _md_block(finding.get("secondary_review") or secondary_review_narrative(finding))
    lines += [f"{h2} 证明材料", ""]
    lines.append(f"- 状态：**{_verify_label(vs)}**")
    if finding.get("verified_at"):
        lines.append(f"- 验证时间：{_fmt_ts(finding.get('verified_at'))}")
    if finding.get("proof_type"):
        lines.append(f"- 证明类型：`{finding.get('proof_type')}`")
    if finding.get("proof_canary"):
        lines.append(f"- Canary：`{finding.get('proof_canary')}`")
    if finding.get("proof_url"):
        lines.append(f"- 证明 URL：{finding.get('proof_url')}")
    if finding.get("proof_detail"):
        lines += ["", f"{h3} 证明详情", "", "```", str(finding["proof_detail"]), "```"]
    if not any(finding.get(k) for k in ("proof_type", "proof_canary", "proof_url", "proof_detail")):
        lines.append("- 无独立 proof 字段；以证据与 PoC 为准。")
    lines += ["", f"{h2} 完整证据", ""]
    ev = (finding.get("evidence") or "").strip()
    if ev:
        lines += ["```", ev, "```"]
    else:
        lines.append("_未采集 evidence_")
    lines += ["", f"{h2} PoC", ""]
    curl = real_poc_text(poc.get("curl") or finding.get("poc_curl"))
    py = real_poc_text(poc.get("python") or finding.get("poc_python"))
    raw_curl = (poc.get("curl") or finding.get("poc_curl") or "").strip()
    raw_py = (poc.get("python") or finding.get("poc_python") or "").strip()
    if curl:
        lines += [f"{h3} curl", "", "```bash", curl, "```", ""]
    if py:
        lines += [f"{h3} python", "", "```python", py, "```", ""]
    if not curl and not py:
        lines.append("_未采集可执行 PoC（无真实 poc_curl / poc_python）。_")
        if raw_curl or raw_py:
            lines.append("_系统拒绝为高危项合成假利用脚本。_")
    lines += ["", f"{h2} 修复建议", ""]
    lines += _md_block(finding.get("remediation"))
    if finding.get("cvss_explanation"):
        lines += [f"{h2} 风险说明", "", str(finding.get("cvss_explanation")), ""]
    lines += [f"{h2} 关联攻击图", ""]
    if node:
        lines.append(
            f"- `{node.get('key')}` [{node.get('type')}/{node.get('severity')}] "
            f"{node.get('title')} (risk={node.get('risk_score')})"
        )
        detail = finding.get("node_detail_unique")
        if detail is None:
            detail = node.get("detail")
        if isinstance(detail, str) and detail.strip():
            lines += ["", "```", detail, "```"]
    else:
        lines.append(f"- `{finding.get('node_key') or '-'}`")
    edges = finding.get("related_edges") or []
    if edges:
        lines += ["", f"{h3} 相关边", ""]
        for e in edges:
            if not isinstance(e, dict):
                continue
            frm = e.get("from") or e.get("src") or ""
            to = e.get("to") or e.get("dst") or ""
            rel = e.get("relation") or ""
            why = e.get("rationale") or ""
            lines.append(f"- `{frm}` --{rel}--> `{to}`" + (f"：{why}" if why else ""))
    lines.append("")
    return "\n".join(lines)


def is_reportable_finding(row: Any) -> bool:
    """非 rejected 即可出完整详情与 MD（含低/中危与未验证）。"""
    st = str(_row_get(row, "verification_status") or "verified").lower()
    return st != "rejected"
