//! 漏洞去重、严重度下限、风险分。不写 SQLite。

use fancy_regex::Regex as Fancy;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

const SEV: &[(&str, i64)] = &[("info", 0), ("low", 1), ("medium", 2), ("high", 3), ("critical", 4)];
const BASE: &[(&str, f64)] = &[("info", 5.0), ("low", 20.0), ("medium", 45.0), ("high", 72.0), ("critical", 92.0)];
const FLOOR: &[(&str, &str)] = &[
    ("rce", "critical"), ("command_injection", "critical"), ("deserialization", "critical"),
    ("file_write", "high"), ("file_upload", "high"), ("arbitrary_file_read", "high"),
    ("file_read", "high"), ("lfi", "high"), ("sqli", "high"), ("db_access", "high"),
    ("auth_bypass", "high"), ("admin_access", "high"), ("privilege_escalation", "high"),
    ("unauth", "high"), ("authz", "high"), ("idor", "medium"), ("ssrf", "medium"),
    ("xss", "medium"), ("info", "info"),
    ("business_logic", "high"), ("account_takeover", "high"),
    ("source_leak", "high"), ("backup_leak", "high"), ("hardcoded_secret", "high"),
    ("key_leak", "high"), ("mass_pii", "high"), ("cloud_credential", "high"),
    ("sensitive_data_exposure", "high"), ("credential_dump", "high"), ("secrets_leak", "high"),
];
const CRITICAL: &[&str] = &[
    "rce", "command_injection", "deserialization", "file_write", "file_upload",
    "arbitrary_file_read", "file_read", "lfi", "sqli", "db_access",
    "auth_bypass", "authz", "unauth", "idor", "admin_access", "privilege_escalation",
    "ssrf_internal",
];
const RCE_CATS: &[&str] = &["rce", "command_injection", "deserialization", "ssti", "code_execution"];

static CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)cve-\d{4}-\d{4,}").unwrap());
static ENDPOINT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)https?://([^/\s'\"?#]+)([^\s'\"?#]*)"#).unwrap());
static BARE: LazyLock<Fancy> = LazyLock::new(|| Fancy::new(r"(?i)(?<![\w./-])(/[a-z0-9_./~-]{2,160})").unwrap());
static AJAX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)fusion_form_submit_ajax|fusion_form_update_view|action=fusion_form_[a-z0-9_]+").unwrap());
static EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bwhoami\b|uid=\d+|www-data|phpinfo\s*\(|\bshell_exec\b|command executed|命令执行成功|canary_ok").unwrap());
static NO_EXEC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)未打成执行|未证明\s*rce|尚未证明|未获得代码执行|rce\s*未证明|upload_failed|未打通|没有解释器|未复现|版本命中|不给\s*rce|不标\s*rce|不能评.{0,8}rce|未打成.{0,6}执行").unwrap());
static WRITE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)upload|file_write|file write|写入|上传|fusion-forms").unwrap());
static CAND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[（(]\s*候选\s*RCE\s*[)）]|候选\s*RCE").unwrap());
static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s{2,}").unwrap());

pub fn sev_rank_pub(s: &str) -> i64 {
    sev_rank(s)
}

fn sev_rank(s: &str) -> i64 {
    SEV.iter().find(|(k, _)| *k == s).map(|(_, n)| *n).unwrap_or(0)
}

pub fn normalize_severity(category: Option<&str>, severity: Option<&str>) -> String {
    let mut sev = severity.unwrap_or("").to_string();
    if SEV.iter().all(|(k, _)| *k != sev) {
        sev = "info".into();
    }
    if let Some(cat) = category {
        if let Some((_, floor)) = FLOOR.iter().find(|(k, _)| *k == cat.to_ascii_lowercase()) {
            if sev_rank(floor) > sev_rank(&sev) {
                sev = (*floor).into();
            }
        }
    }
    sev
}

fn rating_alias(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "严重" => "critical",
        "高危" => "high",
        "中危" => "medium",
        "低危" => "low",
        "信息" => "info",
        "crit" | "c" => "critical",
        "h" => "high",
        "m" => "medium",
        "l" => "low",
        _ => return None,
    })
}

pub fn normalize_rating(raw: Option<&str>) -> Option<String> {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() {
        return None;
    }
    let mapped = rating_alias(s).or_else(|| rating_alias(&s.to_ascii_lowercase()));
    let s = mapped.unwrap_or(s).to_ascii_lowercase();
    if ["critical", "high", "medium", "low", "info"].contains(&s.as_str()) {
        Some(s)
    } else {
        None
    }
}

fn py_truth(v: &Bound<PyAny>) -> bool {
    v.is_truthy().unwrap_or(false)
}

fn field_str(row: &Bound<PyAny>, key: &str) -> String {
    if let Ok(d) = row.downcast::<PyDict>() {
        return d.get_item(key).ok().flatten().map(|v| {
            if v.is_none() { String::new() } else { v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() }
        }).unwrap_or_default();
    }
    String::new()
}

#[pyfunction]
pub fn findings_normalize_severity(category: Option<&str>, severity: Option<&str>) -> String {
    normalize_severity(category, severity)
}

#[pyfunction]
pub fn findings_normalize_rating(raw: Option<&str>) -> Option<String> {
    normalize_rating(raw)
}

#[pyfunction]
pub fn findings_display_severity(row: &Bound<PyAny>) -> String {
    if let Some(rt) = normalize_rating(Some(&field_str(row, "redteam_rating"))) {
        return rt;
    }
    let sev = field_str(row, "severity").trim().to_ascii_lowercase();
    let sev = if sev.is_empty() { "info".into() } else { sev };
    if SEV.iter().any(|(k, _)| *k == sev) { sev } else { "info".into() }
}

#[pyfunction]
pub fn findings_risk_score(severity: &str, node_type: &str, is_rce: bool, category: Option<&str>) -> f64 {
    let sev = normalize_severity(category, Some(severity));
    let mut score = BASE.iter().find(|(k, _)| *k == sev).map(|(_, n)| *n).unwrap_or(5.0);
    if is_rce || node_type == "foothold" || node_type == "goal" {
        score = score.max(90.0) + 6.0;
    }
    if node_type == "vuln" || node_type == "danger" {
        score += 4.0;
    }
    if category.map(|c| CRITICAL.contains(&c.to_ascii_lowercase().as_str())).unwrap_or(false) {
        score += 4.0;
    }
    if node_type == "honeypot" {
        score = score.min(15.0);
    }
    let capped = score.min(100.0);
    (capped * 10.0).round() / 10.0
}

#[pyfunction]
pub fn findings_is_critical(severity: &str, category: Option<&str>) -> bool {
    let sev = normalize_severity(category, Some(severity));
    sev_rank(&sev) >= sev_rank("high")
        || category.map(|c| CRITICAL.contains(&c.to_ascii_lowercase().as_str())).unwrap_or(false)
}

#[pyfunction]
pub fn findings_scrub_label(text: Option<&str>) -> String {
    let mut s = text.unwrap_or("").to_string();
    if !s.contains("候选") {
        return s;
    }
    s = CAND.replace_all(&s, "").into_owned();
    s = SPACES.replace_all(&s, " ").into_owned();
    s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '-' || c == '—' || c == '·' || c == '/' || c == '|').to_string()
}

fn blob(parts: &[String]) -> String {
    parts.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")
}

#[pyfunction]
pub fn findings_execution_proven(parts: Vec<String>) -> bool {
    let blob = blob(&parts);
    if NO_EXEC.is_match(&blob) && !EXEC.is_match(&blob) {
        return false;
    }
    EXEC.is_match(&blob)
}

#[pyfunction]
pub fn findings_claims_rce(parts: Vec<String>, category: &str) -> bool {
    let cat = category.trim().to_ascii_lowercase();
    if RCE_CATS.contains(&cat.as_str()) {
        return true;
    }
    let blob = blob(&parts).to_ascii_lowercase();
    blob.contains("rce") || blob.contains("命令执行") || blob.contains("getshell")
}

fn norm_endpoint(parts: &[String]) -> String {
    let blob = blob(parts);
    if let Some(c) = ENDPOINT.captures(&blob) {
        let host = c.get(1).map(|m| m.as_str().to_ascii_lowercase().trim_end_matches('.').to_string()).unwrap_or_default();
        let mut path = c.get(2).map(|m| m.as_str()).unwrap_or("/").trim_end_matches('/').to_string();
        if path.is_empty() {
            path = "/".into();
        }
        if path == "/" {
            return String::new();
        }
        return format!("{host}{}", path.to_ascii_lowercase());
    }
    if let Ok(Some(c)) = BARE.captures(&blob) {
        let mut path = c.get(1).map(|m| m.as_str()).unwrap_or("/").trim_end_matches('/').to_string();
        if path.is_empty() {
            path = "/".into();
        }
        if path == "/" {
            return String::new();
        }
        return path.to_ascii_lowercase();
    }
    String::new()
}

#[pyfunction]
pub fn findings_dedup_keys(py: Python<'_>, parts: Vec<String>, category: &str, endpoint_parts: Option<Vec<String>>) -> PyResult<Py<PyList>> {
    let blob = blob(&parts).to_ascii_lowercase();
    let mut keys = Vec::new();
    for m in CVE.find_iter(&blob) {
        keys.push(format!("cve:{}", m.as_str().to_ascii_lowercase()));
    }
    for m in AJAX.find_iter(&blob) {
        let cleaned: String = m.as_str().to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        keys.push(format!("ep:{cleaned}"));
    }
    if blob.contains("fusion-forms") || blob.contains("fusion_form") {
        keys.push("ep:fusion_form_upload".into());
    }
    let src = endpoint_parts.as_ref().unwrap_or(&parts);
    let path = norm_endpoint(src);
    let cat: String = category.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if !path.is_empty() && !cat.is_empty() {
        keys.push(format!("pc:{path}|{cat}"));
    }
    Ok(PyList::new(py, keys)?.unbind())
}

#[pyfunction]
pub fn findings_coerce_rce(
    category: Option<&str>,
    severity: Option<&str>,
    redteam_rating: Option<&str>,
    title: &str,
    description: &str,
    evidence: &str,
    poc_curl: &str,
    poc_python: &str,
) -> (String, String, Option<String>) {
    let mut cat = {
        let c = category.unwrap_or("info").trim().to_ascii_lowercase();
        if c.is_empty() { "info".into() } else { c }
    };
    let parts = vec![
        title.to_string(), description.to_string(), evidence.to_string(),
        poc_curl.to_string(), poc_python.to_string(), cat.clone(),
    ];
    let proven = findings_execution_proven(parts.clone());
    let rce_claim = findings_claims_rce(parts.clone(), &cat);
    if rce_claim && !proven {
        let blob = blob(&parts);
        cat = if WRITE.is_match(&blob) { "file_write".into() } else { "vuln".into() };
    }
    let mut sev = normalize_severity(Some(&cat), severity);
    let mut rating = normalize_rating(redteam_rating);
    if rce_claim && !proven {
        if sev_rank(&sev) > sev_rank("medium") {
            sev = "medium".into();
        }
        if matches!(rating.as_deref(), Some("high") | Some("critical")) {
            rating = Some("medium".into());
        }
    }
    (cat, sev, rating)
}

fn secondary_flag(v: &str) -> bool {
    !matches!(v.trim(), "" | "0" | "false" | "False")
}

#[pyfunction]
pub fn findings_collapse(rows: &Bound<PyList>) -> PyResult<Vec<usize>> {
    let n = rows.len();
    if n <= 1 {
        return Ok((0..n).collect());
    }
    let mut keys: Vec<BTreeSet<String>> = Vec::new();
    for row in rows.iter() {
        let title = field_str(&row, "title");
        let category = field_str(&row, "category");
        let endpoint = vec![
            field_str(&row, "proof_url"), field_str(&row, "node_key"), field_str(&row, "poc_curl"),
            field_str(&row, "description"), field_str(&row, "evidence"),
        ];
        let mut parts = vec![title, category.clone()];
        parts.extend(endpoint.clone());
        parts.push(field_str(&row, "poc_python"));
        let py = rows.py();
        let list = findings_dedup_keys(py, parts, &category, Some(endpoint))?;
        let mut set = BTreeSet::new();
        for item in list.bind(py).iter() {
            set.insert(item.extract::<String>()?);
        }
        keys.push(set);
    }
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    for i in 0..n {
        if keys[i].is_empty() { continue; }
        for j in (i + 1)..n {
            if !keys[j].is_empty() && keys[i].intersection(&keys[j]).next().is_some() {
                let ra = find(&mut parent, i);
                let rb = find(&mut parent, j);
                if ra != rb { parent[rb] = ra; }
            }
        }
    }
    let mut order: Vec<usize> = Vec::new();
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        if let Some(pos) = order.iter().position(|x| *x == r) {
            clusters[pos].push(i);
        } else {
            order.push(r);
            clusters.push(vec![i]);
        }
    }
    let mut out = Vec::new();
    for members in &clusters {
        let mut best = members[0];
        let mut best_key = canonical_key(&rows.get_item(best)?);
        for &idx in members.iter().skip(1) {
            let key = canonical_key(&rows.get_item(idx)?);
            if key < best_key {
                best = idx;
                best_key = key;
            }
        }
        out.push(best);
    }
    Ok(out)
}

fn canonical_key(row: &Bound<PyAny>) -> (i64, f64, String) {
    let sec = if secondary_flag(&field_str(row, "secondary_verified")) { 1 } else { 0 };
    let ts: f64 = field_str(row, "created_at").parse().unwrap_or(0.0);
    let id = field_str(row, "id");
    (-sec, ts, id)
}

fn why_len(rationale: Option<&str>) -> usize {
    rationale.unwrap_or("").trim().chars().count()
}

#[pyfunction]
pub fn findings_secondary_error(
    secondary_verified: bool,
    rating: Option<&str>,
    rationale: Option<&str>,
    status: Option<&str>,
) -> Option<String> {
    let has_rating = normalize_rating(rating).is_some();
    let n = why_len(rationale);
    if status.unwrap_or("").to_ascii_lowercase() == "excluded" {
        if secondary_verified {
            return Some("二次验证失败时 secondary_verified 必须为 false。失败只表示本条没被二次证明，不是否定这类漏洞。".into());
        }
        if n < 40 {
            return Some("二次验证失败须写清二次打了什么、没有看到什么危害，至少 40 字。".into());
        }
        return None;
    }
    let why = rationale.unwrap_or("").trim();
    if !secondary_verified && !has_rating && why.is_empty() {
        return None;
    }
    if secondary_verified && has_rating {
        if n < 40 {
            return Some("redteam_rating_rationale 须同时阐述二次验证过程（换通道/重放 PoC/对照预期）和进攻侧评级理由，不要只写「高危」。".into());
        }
        return None;
    }
    if secondary_verified {
        if n < 40 {
            return Some("二次验证须写清怎么再打的（换通道/重放 PoC/对照预期），redteam_rating_rationale 至少 40 字。".into());
        }
        return None;
    }
    if has_rating {
        if n < 40 {
            return Some("红队评级须写清为何是这个级，redteam_rating_rationale 至少 40 字。".into());
        }
        return None;
    }
    Some("只写了理由但既未 secondary_verified=true 也未给出 redteam_rating。".into())
}

#[pyfunction]
pub fn findings_review_need(row: &Bound<PyAny>, want_secondary: bool, want_rating: bool) -> Option<String> {
    let has_rating = normalize_rating(Some(&field_str(row, "redteam_rating"))).is_some();
    if field_str(row, "verification_status").to_ascii_lowercase() == "excluded" {
        if want_rating && !has_rating {
            return Some("rating".into());
        }
        return None;
    }
    let done_sec = py_truth_field(row, "secondary_verified");
    let need_sec = want_secondary && !done_sec;
    let need_rate = want_rating && !has_rating;
    if need_sec && need_rate { return Some("both".into()); }
    if need_sec { return Some("secondary".into()); }
    if need_rate { return Some("rating".into()); }
    None
}

fn py_truth_field(row: &Bound<PyAny>, key: &str) -> bool {
    if let Ok(d) = row.downcast::<PyDict>() {
        if let Ok(Some(v)) = d.get_item(key) {
            return py_truth(&v);
        }
    }
    false
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(findings_normalize_severity, m)?)?;
    m.add_function(wrap_pyfunction!(findings_normalize_rating, m)?)?;
    m.add_function(wrap_pyfunction!(findings_display_severity, m)?)?;
    m.add_function(wrap_pyfunction!(findings_risk_score, m)?)?;
    m.add_function(wrap_pyfunction!(findings_is_critical, m)?)?;
    m.add_function(wrap_pyfunction!(findings_scrub_label, m)?)?;
    m.add_function(wrap_pyfunction!(findings_execution_proven, m)?)?;
    m.add_function(wrap_pyfunction!(findings_claims_rce, m)?)?;
    m.add_function(wrap_pyfunction!(findings_dedup_keys, m)?)?;
    m.add_function(wrap_pyfunction!(findings_coerce_rce, m)?)?;
    m.add_function(wrap_pyfunction!(findings_collapse, m)?)?;
    m.add_function(wrap_pyfunction!(findings_secondary_error, m)?)?;
    m.add_function(wrap_pyfunction!(findings_review_need, m)?)?;
    Ok(())
}
