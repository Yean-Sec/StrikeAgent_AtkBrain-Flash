//! 二次验证的纯判定。真正复验会话留在 Python。

use pyo3::prelude::*;
use pyo3::types::PyDict;
use crate::findings::{normalize_severity, sev_rank_pub};

const NON_EXPLOIT: &[&str] = &["availability", "dos", "crash", "error_handling", "misconfig"];
const CRITICAL: &[&str] = &[
    "rce", "command_injection", "deserialization", "file_write", "file_upload",
    "arbitrary_file_read", "file_read", "lfi", "sqli", "db_access",
    "auth_bypass", "authz", "unauth", "idor", "admin_access", "privilege_escalation",
    "ssrf_internal",
];

#[pyfunction]
pub fn verify_non_exploit(category: Option<&str>) -> bool {
    NON_EXPLOIT.contains(&category.unwrap_or("").trim().to_ascii_lowercase().as_str())
}

#[pyfunction]
pub fn verify_has_proof(
    evidence: Option<&str>,
    poc_curl: Option<&str>,
    poc_python: Option<&str>,
    proof_detail: Option<&str>,
    proof_canary: Option<&str>,
    proof_url: Option<&str>,
) -> bool {
    [evidence, poc_curl, poc_python, proof_detail, proof_canary, proof_url]
        .iter()
        .any(|v| v.unwrap_or("").trim().len() > 0)
}

#[pyfunction]
pub fn verify_is_high(severity: Option<&str>, category: Option<&str>) -> bool {
    let sev = normalize_severity(category, severity);
    if sev_rank_pub(&sev) >= sev_rank_pub("high") {
        return true;
    }
    category.map(|c| CRITICAL.contains(&c.to_ascii_lowercase().as_str())).unwrap_or(false)
}

#[pyfunction]
pub fn verify_infer_canary(proof_canary: Option<&str>) -> Option<String> {
    let raw = proof_canary.unwrap_or("").trim();
    if raw.is_empty() { None } else { Some(raw.to_string()) }
}

#[pyfunction]
pub fn verify_accept_secondary(
    py: Python<'_>,
    status: &str,
    reason: &str,
    proof_type: Option<&str>,
    proof_canary: Option<&str>,
    proof_url: Option<&str>,
    proof_detail: Option<&str>,
    secondary: bool,
) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    if !secondary || status == "verified" {
        d.set_item("status", status)?;
        d.set_item("reason", reason)?;
    } else {
        d.set_item("status", "verified")?;
        d.set_item("reason", "secondary_review")?;
    }
    d.set_item("proof_type", proof_type)?;
    d.set_item("proof_canary", proof_canary)?;
    d.set_item("proof_url", proof_url)?;
    d.set_item("proof_detail", proof_detail)?;
    Ok(d.unbind())
}

fn contains_any(text: &str, marks: &[&str]) -> bool {
    marks.iter().any(|m| text.contains(m))
}

#[pyfunction]
pub fn verify_rating_left_alone(rationale: Option<&str>) -> bool {
    let text = rationale.unwrap_or("");
    contains_any(text, &[
        "保持原状", "未再动手", "未改二次验证", "不要改二次验证",
        "只做 NVD", "只做红队评级", "本轮未再", "未做二次验证",
    ])
}

#[pyfunction]
pub fn verify_secondary_failed(rationale: Option<&str>) -> bool {
    let text = rationale.unwrap_or("");
    contains_any(text, &[
        "未复现", "未能复现", "无法复现", "没有复现", "打不出",
        "未观察到", "未能证明", "没有证明", "未看到同样", "假阳性",
    ])
}

#[pyfunction]
pub fn verify_recheck_skipped(rationale: Option<&str>) -> bool {
    let text = rationale.unwrap_or("");
    contains_any(text, &["本条意图已经写回", "不再改打别的类型", "这次会话不再"])
}

#[pyfunction]
pub fn verify_real_secondary_failure(rationale: Option<&str>) -> bool {
    if verify_rating_left_alone(rationale) || verify_recheck_skipped(rationale) {
        return false;
    }
    let text = rationale.unwrap_or("");
    if text.contains("二次验证失败") || verify_secondary_failed(Some(text)) {
        return true;
    }
    text.contains("没看到") || text.contains("没有看到") || text.contains("没有独立证明")
}

#[pyfunction]
pub fn verify_merge_status(
    prev_status: Option<&str>,
    prev_secondary: bool,
    incoming_status: Option<&str>,
    incoming_secondary: bool,
    rationale: Option<&str>,
) -> (String, bool) {
    let prev = {
        let p = prev_status.unwrap_or("pending").trim().to_ascii_lowercase();
        if p.is_empty() { "pending".into() } else { p }
    };
    if prev == "excluded" {
        return ("excluded".into(), false);
    }
    let incoming = incoming_status.unwrap_or("").trim().to_ascii_lowercase();
    if incoming == "excluded" && verify_real_secondary_failure(rationale) && !incoming_secondary {
        return ("excluded".into(), false);
    }
    if incoming_secondary && !verify_rating_left_alone(rationale) {
        return ("verified".into(), true);
    }
    if prev == "verified" {
        return ("verified".into(), prev_secondary);
    }
    let status = if prev.is_empty() || prev == "pending" { "pending".into() } else { prev };
    (status, prev_secondary)
}

#[pyfunction]
pub fn verify_visible(status: Option<&str>) -> bool {
    match status.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        None => true,
        Some(st) => ["verified", "flaky", "pending", "excluded"].contains(&st.to_ascii_lowercase().as_str()),
    }
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_non_exploit, m)?)?;
    m.add_function(wrap_pyfunction!(verify_has_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_is_high, m)?)?;
    m.add_function(wrap_pyfunction!(verify_infer_canary, m)?)?;
    m.add_function(wrap_pyfunction!(verify_accept_secondary, m)?)?;
    m.add_function(wrap_pyfunction!(verify_rating_left_alone, m)?)?;
    m.add_function(wrap_pyfunction!(verify_secondary_failed, m)?)?;
    m.add_function(wrap_pyfunction!(verify_recheck_skipped, m)?)?;
    m.add_function(wrap_pyfunction!(verify_real_secondary_failure, m)?)?;
    m.add_function(wrap_pyfunction!(verify_merge_status, m)?)?;
    m.add_function(wrap_pyfunction!(verify_visible, m)?)?;
    Ok(())
}
