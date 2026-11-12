//! 节点类型、占位和报告短文。评分函数在 findings.rs。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet};

fn tags_of(tags: Option<&Bound<PyAny>>) -> Vec<String> {
    let Some(tags) = tags else { return Vec::new() };
    tags.try_iter()
        .map(|it| it.flatten().map(|v| v.to_string()).map(|s| s.to_ascii_lowercase()).collect())
        .unwrap_or_default()
}

fn has_tag(tags: &[String], name: &str) -> bool {
    tags.iter().any(|t| t == name)
}

#[pyfunction]
#[pyo3(signature = (key, tags=None))]
fn is_achieved_shell_goal(key: &str, tags: Option<&Bound<PyAny>>) -> bool {
    let key = key.trim();
    let tags = tags_of(tags);
    key.starts_with("goal:shell") || has_tag(&tags, "getshell")
}

#[pyfunction]
#[pyo3(signature = (ntype, key="", tags=None, is_rce=false))]
fn node_is_landed_shell(ntype: &str, key: &str, tags: Option<&Bound<PyAny>>, is_rce: bool) -> bool {
    if ntype != "foothold" && ntype != "goal" {
        return false;
    }
    let tags = tags_of(tags);
    is_rce || has_tag(&tags, "getshell") || key.starts_with("goal:shell") || key.starts_with("foothold:shell")
}

#[pyfunction]
#[pyo3(signature = (key, tags=None))]
fn is_achieved_flag_goal(key: &str, tags: Option<&Bound<PyAny>>) -> bool {
    let tags = tags_of(tags);
    key.starts_with("goal:flag") || has_tag(&tags, "flag") || has_tag(&tags, "getflag")
}

#[pyfunction]
#[pyo3(signature = (key, ntype, tags=None))]
fn coerce_goal_node_type(key: &str, ntype: &str, tags: Option<&Bound<PyAny>>) -> String {
    if ntype != "goal" {
        return ntype.to_string();
    }
    if is_achieved_shell_goal(key, tags) || is_achieved_flag_goal(key, tags) {
        "goal".into()
    } else {
        "danger".into()
    }
}

fn infer(key: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("target:", "target"),
        ("svc:", "service"),
        ("service:", "service"),
        ("danger:", "danger"),
        ("vuln:", "vuln"),
        ("cred:", "credential"),
        ("credential:", "credential"),
        ("foothold:", "foothold"),
        ("honeypot:", "honeypot"),
        ("goal:", "goal"),
    ];
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() {
        return None;
    }
    PREFIXES.iter().find(|(p, _)| k.starts_with(p)).map(|(_, t)| *t)
}

fn rank(name: &str) -> i64 {
    match name {
        "service" => 1,
        "danger" | "honeypot" => 2,
        "credential" => 3,
        "vuln" => 4,
        "foothold" => 5,
        "target" => 6,
        "goal" => 7,
        _ => 0,
    }
}

#[pyfunction]
fn infer_node_type_from_key(key: &str) -> Option<String> {
    infer(key).map(|s| s.to_string())
}

#[pyfunction]
fn humanize_node_key(key: &str) -> String {
    let raw = key.trim();
    if raw.is_empty() || infer(raw).is_none() {
        return raw.to_string();
    }
    let rest = raw.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    if rest.is_empty() { raw.to_string() } else { rest.to_string() }
}

#[pyfunction]
#[pyo3(signature = (key, ntype, tags=None))]
fn coerce_declared_node_type(key: &str, ntype: &str, tags: Option<&Bound<PyAny>>) -> String {
    let declared = coerce_goal_node_type(key, if ntype.is_empty() { "info" } else { ntype }, tags);
    let Some(inferred) = infer(key) else {
        return if declared.is_empty() { "info".into() } else { declared };
    };
    if inferred == "goal" {
        return coerce_goal_node_type(key, "goal", tags);
    }
    let tagset = tags_of(tags);
    if inferred == "vuln" && has_tag(&tagset, "placeholder") {
        if rank(if declared.is_empty() { "info" } else { declared.as_str() }) <= rank("vuln") {
            return "danger".into();
        }
        return if declared.is_empty() { "danger".into() } else { declared };
    }
    let declared_rank = rank(if declared.is_empty() { "info" } else { declared.as_str() });
    if declared_rank < rank(inferred) {
        inferred.into()
    } else if declared.is_empty() {
        inferred.into()
    } else {
        declared
    }
}

#[pyfunction]
fn placeholder_node_spec(py: Python<'_>, key: &str) -> PyResult<(String, String, String, Py<PyList>)> {
    let inferred = infer(key).unwrap_or("info");
    let title = humanize_node_key(key);
    let (ntype, sev) = if inferred == "vuln" {
        ("danger".to_string(), "medium".to_string())
    } else {
        let ntype = coerce_declared_node_type(key, inferred, None);
        let sev = if ntype == "foothold" || ntype == "goal" {
            "critical"
        } else if ntype == "danger" {
            "medium"
        } else {
            "info"
        };
        (ntype, sev.to_string())
    };
    let tags = PyList::new(py, ["placeholder"])?;
    Ok((ntype, title, sev, tags.unbind()))
}

#[pyfunction]
fn is_merged_duplicate_title(title: Option<&str>) -> bool {
    let text = title.unwrap_or("");
    text.contains("重复节点") || text.contains("已并入")
}

fn detail_empty(detail: Option<&Bound<PyAny>>) -> bool {
    let Some(detail) = detail else { return true };
    if detail.is_none() {
        return true;
    }
    if let Ok(s) = detail.extract::<String>() {
        return s.trim().is_empty();
    }
    if detail.downcast::<PyDict>().map(|d| d.is_empty()).unwrap_or(false) {
        return true;
    }
    if detail.downcast::<PyList>().map(|d| d.is_empty()).unwrap_or(false) {
        return true;
    }
    false
}

#[pyfunction]
#[pyo3(signature = (key, title=None, detail=None, tags=None))]
fn is_placeholder_node(key: &str, title: Option<&str>, detail: Option<&Bound<PyAny>>, tags: Option<&Bound<PyAny>>) -> bool {
    if has_tag(&tags_of(tags), "placeholder") {
        return true;
    }
    let title = title.unwrap_or("");
    let human = humanize_node_key(key);
    detail_empty(detail) && (title == key || title == human)
}

#[pyfunction]
#[pyo3(signature = (key, ntype, tags=None))]
fn agent_goal_reserved_error(key: &str, ntype: &str, tags: Option<&Bound<PyAny>>) -> Option<String> {
    if ntype != "goal" {
        return None;
    }
    if is_achieved_shell_goal(key, tags) {
        return Some("命令执行达成请用 report_shell，不要 add_node(type=goal)".into());
    }
    if is_achieved_flag_goal(key, tags) {
        return Some("夺旗请用 report_flag，不要 add_node(type=goal)".into());
    }
    None
}

fn row_get(row: &Bound<PyAny>, key: &str) -> Option<Py<PyAny>> {
    if let Ok(d) = row.downcast::<PyDict>() {
        return d.get_item(key).ok().flatten().filter(|v| !v.is_none()).map(|v| v.unbind());
    }
    if let Ok(v) = row.getattr(key) {
        if !v.is_none() {
            return Some(v.unbind());
        }
    }
    if let Ok(v) = row.call_method1("get", (key,)) {
        if !v.is_none() {
            return Some(v.unbind());
        }
    }
    None
}

fn row_str(py: Python<'_>, row: &Bound<PyAny>, key: &str) -> String {
    row_get(row, key)
        .and_then(|v| {
            let b = v.bind(py);
            if b.is_none() { None } else { b.str().ok().map(|s| s.to_string_lossy().into_owned()) }
        })
        .unwrap_or_default()
}

fn rating_label(raw: Option<&str>) -> String {
    match crate::findings::findings_normalize_rating(raw).as_deref() {
        Some("critical") => "严重".into(),
        Some("high") => "高危".into(),
        Some("medium") => "中危".into(),
        Some("low") => "低危".into(),
        Some("info") => "信息".into(),
        Some(other) => other.into(),
        None => "未评级".into(),
    }
}

#[pyfunction]
fn redteam_rating_label(raw: Option<&str>) -> String {
    rating_label(raw)
}

#[pyfunction]
fn secondary_review_narrative(py: Python<'_>, row: &Bound<PyAny>) -> String {
    let done = row_get(row, "secondary_verified").map(|v| v.bind(py).is_truthy().unwrap_or(false)).unwrap_or(false);
    let rating_raw = row_str(py, row, "redteam_rating");
    let rating = crate::findings::findings_normalize_rating(if rating_raw.is_empty() { None } else { Some(rating_raw.as_str()) });
    let why = row_str(py, row, "redteam_rating_rationale").trim().to_string();
    let mut lines = Vec::new();
    if !done && rating.is_none() && why.is_empty() {
        lines.push("【二次验证】未做。本条仍是首次观测入库，尚未换通道或重放 PoC 做二次验证。".to_string());
        lines.push("【红队评级】未评级。展示严重度暂用入库 severity。二次验证与红队评级须同一轮完成，并在本节写清过程与理由。".to_string());
        return lines.join("\n");
    }
    if done {
        lines.push("【二次验证】已做。须与红队评级同一轮：独立再打一遍（换观测通道 / 重放 PoC / 对照预期回显），不能只把首次观测再贴一遍。".into());
    } else {
        lines.push("【二次验证】未做。已出现评级或理由但未完成二次验证，报告视为不完整。".into());
    }
    let score = row_get(row, "cvss");
    if let Some(rating) = rating.as_deref() {
        if let Some(score) = score {
            let bound = score.bind(py);
            let shown = bound.extract::<f64>().ok().map(|n| format!("{n:.1}")).unwrap_or_else(|| bound.to_string());
            let band = if rating == "info" { "无".into() } else { rating_label(Some(rating)) };
            lines.push(format!("【NVD CVSS 3.1】基础分 **{shown}**，定性 **{band}**（`{rating}`）。展示严重度以 NVD 基础分为准。"));
        } else {
            let band = rating_label(Some(rating));
            lines.push(format!("【红队评级】**{band}**（`{rating}`）。展示严重度以该评级为准。"));
        }
    } else {
        lines.push("【NVD CVSS 3.1】未评分。二次验证完成后按 NVD 的八项基础指标计算基础分。".into());
    }
    if why.is_empty() {
        lines.push("【阐述】未写。二次验证过程（怎么打、看到什么）和评级理由必须写在 redteam_rating_rationale。".into());
    } else {
        lines.push(format!("【阐述】\n{why}"));
    }
    lines.join("\n")
}

#[pyfunction]
fn redteam_rating_block(py: Python<'_>, row: &Bound<PyAny>) -> String {
    let rating_raw = row_str(py, row, "redteam_rating");
    let rating = crate::findings::findings_normalize_rating(if rating_raw.is_empty() { None } else { Some(rating_raw.as_str()) });
    let why = row_str(py, row, "redteam_rating_rationale").trim().to_string();
    let head = if let Some(rating) = rating.as_deref() {
        if let Some(score) = row_get(row, "cvss") {
            let bound = score.bind(py);
            let shown = bound.extract::<f64>().ok().map(|n| format!("{n:.1}")).unwrap_or_else(|| bound.to_string());
            let band = if rating == "info" { "无".into() } else { rating_label(Some(rating)) };
            format!("NVD CVSS 3.1 基础分：**{shown}**（{band}）")
        } else {
            format!("级别：**{}**（`{rating}`）", rating_label(Some(rating)))
        }
    } else {
        "级别：未评级".into()
    };
    if why.is_empty() {
        format!("{head}\n为什么是这个级：未写理由。")
    } else {
        format!("{head}\n为什么是这个级：{why}")
    }
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    let order = PyDict::new(m.py());
    for (name, rank) in [("info", 0), ("low", 1), ("medium", 2), ("high", 3), ("critical", 4)] {
        order.set_item(name, rank)?;
    }
    m.add("SEVERITY_ORDER", order)?;
    let crit = PySet::new(m.py(), [
        "rce", "command_injection", "deserialization", "file_write", "file_upload",
        "arbitrary_file_read", "file_read", "lfi", "sqli", "db_access",
        "auth_bypass", "authz", "unauth", "idor", "admin_access", "privilege_escalation",
        "ssrf_internal",
    ])?;
    m.add("CRITICAL_CATEGORIES", crit)?;
    m.add_function(wrap_pyfunction!(is_achieved_shell_goal, m)?)?;
    m.add_function(wrap_pyfunction!(node_is_landed_shell, m)?)?;
    m.add_function(wrap_pyfunction!(is_achieved_flag_goal, m)?)?;
    m.add_function(wrap_pyfunction!(coerce_goal_node_type, m)?)?;
    m.add_function(wrap_pyfunction!(infer_node_type_from_key, m)?)?;
    m.add_function(wrap_pyfunction!(humanize_node_key, m)?)?;
    m.add_function(wrap_pyfunction!(coerce_declared_node_type, m)?)?;
    m.add_function(wrap_pyfunction!(placeholder_node_spec, m)?)?;
    m.add_function(wrap_pyfunction!(is_merged_duplicate_title, m)?)?;
    m.add_function(wrap_pyfunction!(is_placeholder_node, m)?)?;
    m.add_function(wrap_pyfunction!(agent_goal_reserved_error, m)?)?;
    m.add_function(wrap_pyfunction!(redteam_rating_label, m)?)?;
    m.add_function(wrap_pyfunction!(secondary_review_narrative, m)?)?;
    m.add_function(wrap_pyfunction!(redteam_rating_block, m)?)?;
    Ok(())
}
