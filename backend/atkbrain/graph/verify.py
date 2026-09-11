"""发现入库：有真实性证据才标已验证；二次验证与红队评级单独记。"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import CRITICAL_CATEGORIES, FindingIn, SEVERITY_ORDER, normalize_severity

# 崩溃/可用性类：可上报、可见，但不能当「已验证可利用资产」去收口。
NON_EXPLOIT_FINDING_CATS = frozenset({
    "availability", "dos", "crash", "error_handling", "misconfig",
})


def is_non_exploit_finding_category(category: str | None) -> bool:
    return str(category or "").strip().lower() in NON_EXPLOIT_FINDING_CATS


def finding_has_authenticity_proof(finding: FindingIn) -> bool:
    """是否有可核真实性的材料：证据、PoC 或证明字段。"""
    for v in (
        finding.evidence, finding.poc_curl, finding.poc_python,
        finding.proof_detail, finding.proof_canary, finding.proof_url,
    ):
        if str(v or "").strip():
            return True
    return False


@dataclass
class VerifyResult:
    status: str
    reason: str
    proof_type: str | None = None
    proof_canary: str | None = None
    proof_url: str | None = None
    proof_detail: str | None = None


def is_high_severity(severity: str | None, category: str | None) -> bool:
    """高危/严重：导出 PoC 时只用上报原文，不合成利用模板。"""
    sev = normalize_severity(category, severity)
    if SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER["high"]:
        return True
    return bool(category and category.lower() in CRITICAL_CATEGORIES)


def infer_canary(finding: FindingIn) -> str | None:
    raw = (finding.proof_canary or "").strip()
    return raw or None


def accept_secondary_review(vr: VerifyResult, secondary: bool) -> VerifyResult:
    """专职复核 Pi 收口后，二次验证本身就是真实性结论；不再维持 pending。"""
    if not secondary:
        return vr
    if vr.status == "verified":
        return vr
    return VerifyResult(
        status="verified",
        reason="secondary_review",
        proof_type=vr.proof_type,
        proof_canary=vr.proof_canary,
        proof_url=vr.proof_url,
        proof_detail=vr.proof_detail,
    )


async def verify_finding(
    finding: FindingIn, project_id: str | None = None,
) -> VerifyResult:
    """核真实性：无证据/PoC 不得标已验证。专职二次验证收口后另见 accept_secondary_review。"""
    _ = project_id
    detail = (finding.proof_detail or "").strip()
    canary = infer_canary(finding)
    proof_url = (finding.proof_url or "").strip() or None
    proof_type = (finding.proof_type or "").strip().lower() or None
    base = dict(
        proof_type=proof_type,
        proof_canary=canary,
        proof_url=proof_url,
        proof_detail=detail or None,
    )
    if is_non_exploit_finding_category(getattr(finding, "category", None)):
        return VerifyResult(status="pending", reason="availability_not_exploit", **base)
    if not finding_has_authenticity_proof(finding):
        return VerifyResult(status="pending", reason="no_proof", **base)
    return VerifyResult(status="verified", reason="accepted", **base)


def is_visible_finding(row: dict | Any) -> bool:
    """用户可见发现：非 rejected 即展示。"""
    try:
        st = row["verification_status"] if not isinstance(row, dict) else row.get("verification_status")
    except (KeyError, TypeError, IndexError):
        st = None
    if st is None or st == "":
        return True
    return str(st).lower() in ("verified", "flaky", "pending")
