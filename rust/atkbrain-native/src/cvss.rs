//! NVD CVSS v3.1 基础分。进位与 Python Decimal ROUND_HALF_UP 一致。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use rust_decimal::Decimal;
use rust_decimal::RoundingStrategy;
use std::collections::BTreeMap;
use std::str::FromStr;

const BASE_KEYS: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

fn dec(s: &str) -> Decimal {
    Decimal::from_str(s).unwrap_or(Decimal::ZERO)
}

fn roundup(value: Decimal) -> Decimal {
    let scaled = (value * dec("100000")).round_dp_with_strategy(0, RoundingStrategy::MidpointAwayFromZero);
    let int_input = i64::try_from(scaled).unwrap_or(0);
    if int_input % 10000 == 0 {
        Decimal::from(int_input) / dec("100000")
    } else {
        Decimal::from(int_input / 10000 + 1) / dec("10")
    }
}

fn qualitative(score: Decimal) -> &'static str {
    if score <= Decimal::ZERO {
        "info"
    } else if score <= dec("3.9") {
        "low"
    } else if score <= dec("6.9") {
        "medium"
    } else if score <= dec("8.9") {
        "high"
    } else {
        "critical"
    }
}

fn band_zh(score: Decimal) -> &'static str {
    match qualitative(score) {
        "info" => "无",
        "low" => "低危",
        "medium" => "中危",
        "high" => "高危",
        "critical" => "严重",
        _ => "无",
    }
}

fn av(code: &str) -> Option<Decimal> {
    Some(match code {
        "N" => dec("0.85"),
        "A" => dec("0.62"),
        "L" => dec("0.55"),
        "P" => dec("0.20"),
        _ => return None,
    })
}
fn ac(code: &str) -> Option<Decimal> {
    Some(match code {
        "L" => dec("0.77"),
        "H" => dec("0.44"),
        _ => return None,
    })
}
fn ui(code: &str) -> Option<Decimal> {
    Some(match code {
        "N" => dec("0.85"),
        "R" => dec("0.62"),
        _ => return None,
    })
}
fn cia(code: &str) -> Option<Decimal> {
    Some(match code {
        "H" => dec("0.56"),
        "L" => dec("0.22"),
        "N" => Decimal::ZERO,
        _ => return None,
    })
}
fn pr(code: &str, scope_changed: bool) -> Option<Decimal> {
    Some(match code {
        "N" => dec("0.85"),
        "L" if scope_changed => dec("0.68"),
        "L" => dec("0.62"),
        "H" if scope_changed => dec("0.50"),
        "H" => dec("0.27"),
        _ => return None,
    })
}

fn word_code(raw: &str) -> Option<&'static str> {
    let up = raw.trim().to_ascii_uppercase();
    let s = raw.trim();
    Some(match up.as_str() {
        "NETWORK" | "网络" => "N",
        "ADJACENT" | "相邻" => "A",
        "LOCAL" | "本地" => "L",
        "PHYSICAL" | "物理" => "P",
        "LOW" | "低" => "L",
        "HIGH" | "高" => "H",
        "NONE" | "无" => "N",
        "REQUIRED" | "需要" => "R",
        "UNCHANGED" | "不变" => "U",
        "CHANGED" | "改变" => "C",
        _ => return word_cn(s),
    })
}

fn word_cn(s: &str) -> Option<&'static str> {
    Some(match s {
        "网络" => "N",
        "相邻" => "A",
        "本地" => "L",
        "物理" => "P",
        "低" => "L",
        "高" => "H",
        "无" => "N",
        "需要" => "R",
        "不变" => "U",
        "改变" => "C",
        _ => return None,
    })
}

fn allowed(key: &str) -> &'static [&'static str] {
    match key {
        "AV" => &["N", "A", "L", "P"],
        "AC" => &["L", "H"],
        "PR" => &["N", "L", "H"],
        "UI" => &["N", "R"],
        "S" => &["U", "C"],
        "C" | "I" | "A" => &["H", "L", "N"],
        _ => &[],
    }
}

fn code_of(raw: &str, key: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let up = s.to_ascii_uppercase();
    if allowed(key).contains(&up.as_str()) {
        return Some(up);
    }
    let word = word_code(s).or_else(|| word_code(&up))?;
    if allowed(key).contains(&word) {
        Some(word.to_string())
    } else {
        None
    }
}

pub fn normalize_metrics(raw: &BTreeMap<String, String>) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for key in BASE_KEYS {
        let code = code_of(raw.get(key).map(|s| s.as_str()).unwrap_or(""), key)?;
        out.insert(key.to_string(), code);
    }
    Some(out)
}

pub fn base_score(metrics: &BTreeMap<String, String>) -> Option<(String, f64, String, String)> {
    let av = av(metrics.get("AV")?)?;
    let ac = ac(metrics.get("AC")?)?;
    let ui = ui(metrics.get("UI")?)?;
    let scope_changed = metrics.get("S")? == "C";
    let pr = pr(metrics.get("PR")?, scope_changed)?;
    let c = cia(metrics.get("C")?)?;
    let i = cia(metrics.get("I")?)?;
    let a = cia(metrics.get("A")?)?;
    let one = Decimal::ONE;
    let iss = one - ((one - c) * (one - i) * (one - a));
    let impact = if scope_changed {
        dec("7.52") * (iss - dec("0.029")) - dec("3.25") * pow_i(iss - dec("0.02"), 15)
    } else {
        dec("6.42") * iss
    };
    let exploitability = dec("8.22") * av * ac * pr * ui;
    let score = if impact <= Decimal::ZERO {
        Decimal::ZERO
    } else if scope_changed {
        roundup((dec("1.08") * (impact + exploitability)).min(dec("10")))
    } else {
        roundup((impact + exploitability).min(dec("10")))
    };
    let vector = format!(
        "CVSS:3.1/{}",
        BASE_KEYS
            .iter()
            .map(|k| format!("{k}:{}", metrics.get(*k).map(|s| s.as_str()).unwrap_or("")))
            .collect::<Vec<_>>()
            .join("/")
    );
    let shown = score.round_dp_with_strategy(1, RoundingStrategy::MidpointAwayFromZero);
    let score_f = f64::from_str(&shown.normalize().to_string()).unwrap_or(0.0);
    // 与 Python float(Decimal 一位小数) 对齐：用字符串再解析。
    let score_f = shown.to_string().parse::<f64>().unwrap_or(score_f);
    Some((vector, score_f, qualitative(shown).to_string(), band_zh(shown).to_string()))
}

fn pow_i(base: Decimal, exp: u32) -> Decimal {
    let mut acc = Decimal::ONE;
    for _ in 0..exp {
        acc *= base;
    }
    acc
}

pub fn parse_vector(text: &str) -> Option<BTreeMap<String, String>> {
    let mut raw = BTreeMap::new();
    for part in text.trim().split('/') {
        if part.is_empty() || part.to_ascii_uppercase().starts_with("CVSS:") {
            continue;
        }
        if let Some((k, v)) = part.split_once(':') {
            raw.insert(k.trim().to_ascii_uppercase(), v.trim().to_string());
        }
    }
    if !BASE_KEYS.iter().all(|k| raw.get(*k).map(|s| !s.is_empty()).unwrap_or(false)) {
        return None;
    }
    normalize_metrics(&raw)
}

fn py_str(v: &Bound<PyAny>) -> String {
    if v.is_none() {
        return String::new();
    }
    v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn map_from_pydict(d: &Bound<PyDict>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in d.iter() {
        let key = py_str(&k);
        out.insert(key, py_str(&v));
    }
    out
}

fn map_to_pydict<'py>(py: Python<'py>, m: &BTreeMap<String, String>) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for (k, v) in m {
        d.set_item(k, v)?;
    }
    Ok(d)
}

#[pyfunction]
pub fn cvss_roundup(raw: &str) -> PyResult<String> {
    let v = Decimal::from_str(raw.trim()).unwrap_or(Decimal::ZERO);
    Ok(roundup(v).to_string())
}

#[pyfunction]
pub fn cvss_qualitative(raw: &str) -> PyResult<String> {
    let v = Decimal::from_str(raw.trim()).unwrap_or(Decimal::ZERO);
    Ok(qualitative(v).to_string())
}

#[pyfunction]
pub fn cvss_band_zh(raw: &str) -> PyResult<String> {
    let v = Decimal::from_str(raw.trim()).unwrap_or(Decimal::ZERO);
    Ok(band_zh(v).to_string())
}

#[pyfunction]
pub fn cvss_base_score(py: Python<'_>, metrics: &Bound<PyDict>) -> PyResult<Py<PyDict>> {
    let map = map_from_pydict(metrics);
    let (vector, score, rating, band) = base_score(&map).unwrap_or_else(|| {
        (String::new(), 0.0, "info".into(), "无".into())
    });
    let d = PyDict::new(py);
    d.set_item("vector", vector)?;
    d.set_item("score", score)?;
    d.set_item("rating", rating)?;
    d.set_item("band_zh", band)?;
    Ok(d.unbind())
}

#[pyfunction]
pub fn cvss_parse_vector(py: Python<'_>, text: &str) -> PyResult<Option<Py<PyDict>>> {
    match parse_vector(text) {
        Some(m) => Ok(Some(map_to_pydict(py, &m)?.unbind())),
        None => Ok(None),
    }
}

#[pyfunction]
pub fn cvss_normalize_metrics(py: Python<'_>, raw: &Bound<PyDict>) -> PyResult<Option<Py<PyDict>>> {
    let map = map_from_pydict(raw);
    match normalize_metrics(&map) {
        Some(m) => Ok(Some(map_to_pydict(py, &m)?.unbind())),
        None => Ok(None),
    }
}

#[pyfunction]
pub fn cvss_metrics_from_args(py: Python<'_>, args: &Bound<PyDict>) -> PyResult<(Option<Py<PyDict>>, bool)> {
    let get = |k: &str| -> String {
        args.get_item(k)
            .ok()
            .flatten()
            .map(|v| py_str(&v))
            .unwrap_or_default()
    };
    let fields = ["cvss_av", "cvss_ac", "cvss_pr", "cvss_ui", "cvss_s", "cvss_c", "cvss_i", "cvss_a"];
    let keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
    let vals: Vec<String> = fields.iter().map(|k| get(k)).collect();
    let touched = vals.iter().any(|v| !v.trim().is_empty()) || !get("cvss_vector").trim().is_empty();
    let rating = !get("redteam_rating").trim().is_empty();
    if !touched && !rating {
        return Ok((None, false));
    }
    if vals.iter().all(|v| !v.trim().is_empty()) {
        let mut raw = BTreeMap::new();
        for (k, v) in keys.iter().zip(vals.iter()) {
            raw.insert((*k).to_string(), v.clone());
        }
        let got = normalize_metrics(&raw);
        return Ok((
            got.map(|m| map_to_pydict(py, &m).unwrap().unbind()),
            true,
        ));
    }
    if let Some(parsed) = parse_vector(&get("cvss_vector")) {
        return Ok((Some(map_to_pydict(py, &parsed)?.unbind()), true));
    }
    Ok((None, true))
}

#[pyfunction]
pub fn cvss_nvd_reject_reason(metrics: &Bound<PyDict>) -> Option<String> {
    let m = map_from_pydict(metrics);
    if m.get("C").map(|s| s.as_str()) == Some("N")
        && m.get("I").map(|s| s.as_str()) == Some("N")
        && m.get("A").map(|s| s.as_str()) == Some("N")
    {
        Some(
            "NVD 不对三项影响都是 None 的向量打分。这条如果确实没有机密性、完整性或可用性影响，不要当作漏洞评级。"
                .to_string(),
        )
    } else {
        None
    }
}

#[pyfunction]
pub fn cvss_attach_vector(rationale: Option<&str>, vector: &str, score: f64, band: &str) -> String {
    let text = rationale.unwrap_or("").trim().to_string();
    let line = format!("NVD {vector} 基础分 {score:.1}，定性 {band}。");
    if text.contains(vector) {
        text
    } else if text.is_empty() {
        line
    } else {
        format!("{line}\n{text}")
    }
}

#[allow(dead_code)]
pub fn _list_unused(py: Python<'_>) -> PyResult<Bound<PyList>> {
    Ok(PyList::empty(py))
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(cvss_roundup, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_qualitative, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_band_zh, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_base_score, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_parse_vector, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_normalize_metrics, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_metrics_from_args, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_nvd_reject_reason, m)?)?;
    m.add_function(wrap_pyfunction!(cvss_attach_vector, m)?)?;
    Ok(())
}
