//! 赛道归一化与收工条件。提示词仍留在 Python。

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList};
use regex::Regex;
use std::sync::LazyLock;

pub fn normalize_objective(obj: Option<&str>) -> &'static str {
    let o = obj.unwrap_or("").trim().to_ascii_lowercase();
    if o == "flag" || o == "ctf" {
        "flag"
    } else {
        "agent"
    }
}

#[pyfunction]
pub fn objective_normalize(obj: Option<&str>) -> &'static str {
    normalize_objective(obj)
}

#[pyfunction]
pub fn objective_allows_flag(obj: Option<&str>) -> bool {
    normalize_objective(obj) == "flag"
}

#[pyfunction]
pub fn objective_is_agent(obj: Option<&str>) -> bool {
    normalize_objective(obj) == "agent"
}

#[pyfunction]
pub fn objective_is_src(obj: Option<&str>) -> bool {
    objective_is_agent(obj)
}

#[pyfunction]
pub fn objective_cfg_is_lab_src(cfg: Option<&Bound<PyDict>>) -> bool {
    // 与现实现一致：normalize 只返回 agent/flag，永远不等于字面量 src。
    let Some(cfg) = cfg else { return false };
    let raw = cfg
        .get_item("objective")
        .ok()
        .flatten()
        .or_else(|| cfg.get_item("track").ok().flatten());
    let text = raw.map(|v| v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
    if normalize_objective(text.as_deref()) != "src" {
        return false;
    }
    false
}

#[pyfunction]
pub fn objective_canon_goal(name: Option<&str>) -> String {
    let n = name.unwrap_or("").trim().to_ascii_lowercase();
    match n.as_str() {
        "db_access" | "mass_data_leak" => "data_access".into(),
        _ => n,
    }
}

#[pyfunction]
pub fn objective_ctf_needed(flags_needed: Option<i64>, flag_count: Option<i64>) -> i64 {
    for v in [flags_needed, flag_count] {
        if let Some(n) = v {
            if n > 0 {
                return n;
            }
        }
    }
    1
}

#[pyfunction]
pub fn objective_ctf_full_score(flags_correct: i64, flags_needed: Option<i64>, flag_count: Option<i64>) -> bool {
    let needed = objective_ctf_needed(flags_needed, flag_count);
    flags_correct >= needed
}

#[pyfunction]
pub fn objective_redteam_reached(achievements: Option<&Bound<PyAny>>) -> bool {
    achievements
        .map(|a| iter_str(a).iter().any(|s| objective_canon_goal(Some(s.as_str())) == "getshell"))
        .unwrap_or(false)
}

fn iter_str(obj: &Bound<PyAny>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(it) = obj.try_iter() {
        for x in it {
            if let Ok(v) = x {
                if let Ok(s) = v.extract::<String>() {
                    out.push(s);
                } else if let Ok(s) = v.str() {
                    out.push(s.to_string_lossy().into_owned());
                }
            }
        }
    }
    out
}

#[pyfunction]
pub fn objective_redteam_new(now: Option<&Bound<PyAny>>, baseline: Option<&Bound<PyAny>>) -> bool {
    if !objective_redteam_reached(now) {
        return false;
    }
    let has = |obj: Option<&Bound<PyAny>>| {
        obj.map(|a| iter_str(a).iter().any(|s| objective_canon_goal(Some(s.as_str())) == "getshell"))
            .unwrap_or(false)
    };
    has(now) && !has(baseline)
}

#[pyfunction]
pub fn objective_run_complete(
    obj: Option<&str>,
    flags_correct: i64,
    flags_needed: Option<i64>,
    flag_count: Option<i64>,
    achievements: Option<&Bound<PyAny>>,
) -> bool {
    if normalize_objective(obj) == "flag" {
        objective_ctf_full_score(flags_correct, flags_needed, flag_count)
    } else {
        objective_redteam_reached(achievements)
    }
}

#[pyfunction]
pub fn objective_hard_stop_exempt(
    obj: Option<&str>,
    flags_correct: i64,
    verified_high: i64,
    verified_critical: i64,
    untested_types: Option<i64>,
) -> bool {
    if normalize_objective(obj) == "flag" {
        return flags_correct > 0;
    }
    if let Some(n) = untested_types {
        if n > 0 {
            return false;
        }
    }
    verified_high + verified_critical > 0
}

static TRIVIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)resteasy|jax-?rs|echo\s*reflector|private\s*ipv4|pod\s*ipv4|(?:404|错误页).{0,48}(?:内网|私网|pod).{0,16}(?:ip|地址|端口)|(?:内网|私网|pod)\s*(?:ip|地址).{0,24}(?:错误页|404|回显)",
    )
    .unwrap()
});
static REAL_LEAK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)password|passwd|secret|api[_-]?key|access[_-]?key|credential|jdbc:|mysql://|\.env\b|private[_-]?key|aws_secret|db[_-]?pass|heapdump|id_rsa|\.git\b|口令|密码|密钥|连接串",
    )
    .unwrap()
});

const SKIP: &[&str] = &[
    "csrf", "open_redirect", "redirect", "phpinfo", "tech-stack", "tech_stack", "banner",
    "version", "path_disclosure", "directory_listing", "fingerprint",
];
const INFO: &[&str] = &[
    "info_disclosure", "information_disclosure", "info", "info_leak", "path_disclosure",
    "banner", "version", "fingerprint", "phpinfo",
];

#[pyfunction]
pub fn objective_skip_category(category: Option<&str>) -> bool {
    SKIP.contains(&category.unwrap_or("").trim().to_ascii_lowercase().as_str())
}

#[pyfunction]
pub fn objective_non_vuln(category: Option<&str>, title: Option<&str>) -> bool {
    let cat = category.unwrap_or("").trim().to_ascii_lowercase();
    if SKIP.contains(&cat.as_str()) {
        return true;
    }
    if !INFO.contains(&cat.as_str()) {
        return false;
    }
    let title = title.unwrap_or("");
    if REAL_LEAK.is_match(title) {
        return false;
    }
    TRIVIAL.is_match(title)
}

#[pyfunction]
pub fn objective_skip_finding(category: Option<&str>, title: Option<&str>) -> bool {
    objective_skip_category(category) || objective_non_vuln(category, title)
}

static IMPACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)uid=\d+\(|www-data|nt authority|root:[^:\n]*:0:0:|领取成功|兑换成功|发放成功|下单成功|支付成功|订单已").unwrap()
});
static ERROR_ONLY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)角色不存在|参数不完整|活动未配置|没有获奖记录|游戏未配置|Error parsing ObjectId|the \$sort key specification").unwrap()
});
static EMPTY_DATA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""data"\s*:\s*(\{\s*\}|\[\s*\])"#).unwrap());
static DATA_SPAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?s)"data"\s*:\s*(\{.*?\}|\[.*?\])"#).unwrap());

fn row_field(row: &Bound<PyAny>, key: &str) -> String {
    if let Ok(d) = row.downcast::<PyDict>() {
        if let Ok(Some(v)) = d.get_item(key) {
            if v.is_none() {
                return String::new();
            }
            return v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        }
        return String::new();
    }
    if let Ok(v) = row.getattr(key) {
        if v.is_none() {
            return String::new();
        }
        return v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    }
    String::new()
}

fn json_payload(blob: &str) -> bool {
    for c in DATA_SPAN.captures_iter(blob) {
        let raw = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let compact: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
        if compact == "{}" || compact == "[]" || compact == "null" {
            continue;
        }
        if compact.len() >= 8 {
            return true;
        }
    }
    false
}

#[pyfunction]
pub fn objective_impact_proven(row: Option<&Bound<PyAny>>) -> bool {
    let Some(row) = row else { return false };
    let evidence = row_field(row, "evidence");
    let proof_detail = row_field(row, "proof_detail");
    let proof_canary = row_field(row, "proof_canary");
    let proof_url = row_field(row, "proof_url");
    let proof_type = row_field(row, "proof_type").trim().to_ascii_lowercase();
    let blob = [evidence, proof_detail.clone(), proof_canary.clone(), proof_url.clone()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let blob_ok = !blob.trim().is_empty();
    if !blob_ok && !(matches!(proof_type.as_str(), "impact_extract" | "write_txt") && (!proof_canary.is_empty() || !proof_url.is_empty() || !proof_detail.is_empty())) {
        return false;
    }
    if IMPACT.is_match(&blob) {
        return true;
    }
    if ERROR_ONLY.is_match(&blob) {
        return false;
    }
    if matches!(proof_type.as_str(), "impact_extract" | "write_txt")
        && (!proof_canary.is_empty() || !proof_url.is_empty() || !proof_detail.is_empty())
    {
        return true;
    }
    if blob.trim().is_empty() {
        return false;
    }
    json_payload(&blob) && !EMPTY_DATA.is_match(&blob)
}

#[pyfunction]
pub fn objective_user_visible(verification_status: Option<&str>) -> bool {
    verification_status.unwrap_or("verified").trim().to_ascii_lowercase() != "rejected"
}

#[pyfunction]
pub fn objective_awarded_sum(captured: Option<&Bound<PyList>>) -> f64 {
    let mut total = 0.0;
    let Some(list) = captured else { return 0.0 };
    for x in list.iter() {
        let Ok(d) = x.downcast::<PyDict>() else { continue };
        let correct = d.get_item("correct").ok().flatten().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false);
        if !correct {
            continue;
        }
        if let Some(v) = d.get_item("awarded").ok().flatten() {
            if let Ok(f) = v.extract::<f64>() {
                total += f;
            } else if let Ok(i) = v.extract::<i64>() {
                total += i as f64;
            }
        }
    }
    total
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(objective_normalize, m)?)?;
    m.add_function(wrap_pyfunction!(objective_allows_flag, m)?)?;
    m.add_function(wrap_pyfunction!(objective_is_agent, m)?)?;
    m.add_function(wrap_pyfunction!(objective_is_src, m)?)?;
    m.add_function(wrap_pyfunction!(objective_cfg_is_lab_src, m)?)?;
    m.add_function(wrap_pyfunction!(objective_canon_goal, m)?)?;
    m.add_function(wrap_pyfunction!(objective_ctf_needed, m)?)?;
    m.add_function(wrap_pyfunction!(objective_ctf_full_score, m)?)?;
    m.add_function(wrap_pyfunction!(objective_redteam_reached, m)?)?;
    m.add_function(wrap_pyfunction!(objective_redteam_new, m)?)?;
    m.add_function(wrap_pyfunction!(objective_run_complete, m)?)?;
    m.add_function(wrap_pyfunction!(objective_hard_stop_exempt, m)?)?;
    m.add_function(wrap_pyfunction!(objective_skip_category, m)?)?;
    m.add_function(wrap_pyfunction!(objective_non_vuln, m)?)?;
    m.add_function(wrap_pyfunction!(objective_skip_finding, m)?)?;
    m.add_function(wrap_pyfunction!(objective_impact_proven, m)?)?;
    m.add_function(wrap_pyfunction!(objective_user_visible, m)?)?;
    m.add_function(wrap_pyfunction!(objective_awarded_sum, m)?)?;
    Ok(())
}
