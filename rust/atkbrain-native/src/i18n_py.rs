//! 文案函数交给 Rust。占位符仍用命名参数，例如 msg("job_fail", err=...)。

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::PyDict;

fn vars_of(kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Vec<(String, String)>> {
    let Some(kwargs) = kwargs else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    for (key, value) in kwargs.iter() {
        let name = key.extract::<String>()?;
        let text = if value.is_none() {
            String::new()
        } else {
            value.str()?.to_string_lossy().into_owned()
        };
        out.push((name, text));
    }
    Ok(out)
}

fn fill<'a>(owned: &'a [(String, String)]) -> Vec<(&'a str, &'a str)> {
    owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

fn map_of(src: HashMap<&'static str, String>) -> HashMap<String, String> {
    src.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

#[pyfunction]
#[pyo3(signature = (raw=None))]
fn normalize_locale(raw: Option<&str>) -> &'static str {
    atkbrain_core::i18n::normalize_locale(raw)
}

#[pyfunction]
#[pyo3(signature = (raw=None))]
fn set_locale(raw: Option<&str>) -> &'static str {
    atkbrain_core::i18n::set_locale(raw)
}

#[pyfunction]
fn get_locale() -> &'static str {
    atkbrain_core::i18n::get_locale()
}

#[pyfunction]
#[pyo3(signature = (raw=None))]
fn set_report_lang(raw: Option<&str>) -> &'static str {
    atkbrain_core::i18n::set_report_lang(raw)
}

#[pyfunction]
fn get_report_lang() -> &'static str {
    atkbrain_core::i18n::get_report_lang()
}

#[pyfunction]
fn config_output_lang(_cfg: &Bound<'_, PyAny>) -> &'static str {
    "zh"
}

#[pyfunction]
fn locale_from_request(_request: &Bound<'_, PyAny>) -> &'static str {
    "zh"
}

#[pyfunction]
#[pyo3(signature = (key, lang=None, **kwargs))]
fn msg(key: &str, lang: Option<&str>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<String> {
    let owned = vars_of(kwargs)?;
    Ok(atkbrain_core::i18n::msg(key, lang, &fill(&owned)))
}

#[pyfunction]
#[pyo3(signature = (key, lang=None, **kwargs))]
fn lab(key: &str, lang: Option<&str>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<String> {
    let owned = vars_of(kwargs)?;
    Ok(atkbrain_core::i18n::lab(key, lang, &fill(&owned)))
}

#[pyfunction]
#[pyo3(signature = (lang=None))]
fn output_lang_contract(lang: Option<&str>) -> &'static str {
    atkbrain_core::i18n::output_lang_contract(lang)
}

#[pyfunction]
#[pyo3(signature = (prompt=None, lang=None))]
fn with_output_lang(prompt: Option<&str>, lang: Option<&str>) -> String {
    atkbrain_core::i18n::with_output_lang(prompt, lang)
}

#[pyfunction]
#[pyo3(signature = (lang=None, chinese_system=""))]
fn export_system_prompt(lang: Option<&str>, chinese_system: &str) -> String {
    atkbrain_core::i18n::export_system_prompt(lang, chinese_system)
}

#[pyfunction]
#[pyo3(signature = (lang=None))]
fn sev_map(lang: Option<&str>) -> HashMap<String, String> {
    map_of(atkbrain_core::i18n::sev_map(lang))
}

#[pyfunction]
#[pyo3(signature = (lang=None))]
fn verify_map(lang: Option<&str>) -> HashMap<String, String> {
    map_of(atkbrain_core::i18n::verify_map(lang))
}

#[pyfunction]
#[pyo3(signature = (lang=None))]
fn kind_map(lang: Option<&str>) -> HashMap<String, String> {
    map_of(atkbrain_core::i18n::kind_map(lang))
}

#[pyfunction]
#[pyo3(signature = (lang=None))]
fn pn_map(lang: Option<&str>) -> HashMap<String, String> {
    map_of(atkbrain_core::i18n::pn_map(lang))
}

#[pyfunction]
#[pyo3(signature = (html, lang=None))]
fn apply_shell_chrome(html: &str, lang: Option<&str>) -> String {
    atkbrain_core::i18n::apply_shell_chrome(html, lang)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_locale, m)?)?;
    m.add_function(wrap_pyfunction!(set_locale, m)?)?;
    m.add_function(wrap_pyfunction!(get_locale, m)?)?;
    m.add_function(wrap_pyfunction!(set_report_lang, m)?)?;
    m.add_function(wrap_pyfunction!(get_report_lang, m)?)?;
    m.add_function(wrap_pyfunction!(config_output_lang, m)?)?;
    m.add_function(wrap_pyfunction!(locale_from_request, m)?)?;
    m.add_function(wrap_pyfunction!(msg, m)?)?;
    m.add_function(wrap_pyfunction!(lab, m)?)?;
    m.add_function(wrap_pyfunction!(output_lang_contract, m)?)?;
    m.add_function(wrap_pyfunction!(with_output_lang, m)?)?;
    m.add_function(wrap_pyfunction!(export_system_prompt, m)?)?;
    m.add_function(wrap_pyfunction!(sev_map, m)?)?;
    m.add_function(wrap_pyfunction!(verify_map, m)?)?;
    m.add_function(wrap_pyfunction!(kind_map, m)?)?;
    m.add_function(wrap_pyfunction!(pn_map, m)?)?;
    m.add_function(wrap_pyfunction!(apply_shell_chrome, m)?)?;
    Ok(())
}
