//! 账密字面量的 Python 入口。

use std::collections::BTreeSet;

use atkbrain_core::creds::{self, SuppliedAuth};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet};

fn text_of(obj: &Bound<'_, PyAny>) -> String {
    obj.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn field(obj: &Bound<'_, PyDict>, keys: &[&str]) -> String {
    for key in keys {
        if let Ok(Some(value)) = obj.get_item(*key) {
            if !value.is_none() { return text_of(&value); }
        }
    }
    String::new()
}

pub(crate) fn auth_of(obj: Option<&Bound<'_, PyAny>>) -> SuppliedAuth {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return SuppliedAuth::default() };
    let Ok(row) = obj.downcast::<PyDict>() else { return SuppliedAuth::default() };
    creds::normalize_supplied_auth(&field(row, &["user", "username"]), &field(row, &["password", "pass"]), &field(row, &["token", "auth_token"]))
}

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    py.import("json")?.call_method1("loads", (text,))
}

pub(crate) fn nodes_of(graph: Option<&Bound<'_, PyAny>>) -> Vec<(String, String)> {
    let Some(graph) = graph.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(row) = graph.downcast::<PyDict>() else { return Vec::new() };
    let Ok(Some(nodes)) = row.get_item("nodes") else { return Vec::new() };
    let Ok(list) = nodes.downcast::<PyList>() else { return Vec::new() };
    list.iter().filter_map(|item| item.downcast::<PyDict>().ok().cloned()).map(|row| (field(&row, &["title"]), field(&row, &["detail"]))).collect()
}

#[pyfunction]
#[pyo3(signature = (text, max_pairs=10))]
fn credential_candidates_from_brief(text: &str, max_pairs: usize) -> Vec<String> {
    creds::credential_candidates_from_brief(text, max_pairs)
}

fn strings_of(obj: Option<&Bound<'_, PyAny>>) -> Vec<String> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(iter) = obj.try_iter() else { return Vec::new() };
    iter.flatten().map(|v| text_of(&v)).collect()
}

#[pyfunction]
fn format_cred_hint(cands: Option<&Bound<'_, PyAny>>) -> String {
    creds::format_cred_hint(&strings_of(cands))
}

#[pyfunction]
fn password_values(py: Python<'_>, cands: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PySet>> {
    let values = creds::password_values(&strings_of(cands));
    Ok(PySet::new(py, values)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (graph=None, limit=3000))]
fn graph_cred_blob(graph: Option<&Bound<'_, PyAny>>, limit: usize) -> String {
    creds::graph_cred_blob(&nodes_of(graph), limit)
}

#[pyfunction]
fn normalize_supplied_auth<'py>(py: Python<'py>, raw: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &auth_of(raw).to_json())
}

#[pyfunction]
fn merge_supplied_auth<'py>(py: Python<'py>, existing: Option<&Bound<'_, PyAny>>, incoming: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &creds::merge_supplied_auth(&auth_of(existing), &auth_of(incoming)).to_json())
}

#[pyfunction]
fn extract_supplied_auth<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &creds::extract_supplied_auth(text).to_json())
}

#[pyfunction]
#[pyo3(signature = (existing=None, messages=None))]
fn merge_steering_supplied_auth<'py>(py: Python<'py>, existing: Option<&Bound<'_, PyAny>>, messages: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &creds::merge_steering_supplied_auth(&auth_of(existing), &strings_of(messages)).to_json())
}

#[pyfunction]
fn secrets_from_supplied_auth(py: Python<'_>, auth: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PySet>> {
    Ok(PySet::new(py, creds::secrets_from_supplied_auth(&auth_of(auth)))?.unbind())
}

#[pyfunction]
#[pyo3(signature = (auth=None, *, src=false))]
fn format_supplied_auth_brief(auth: Option<&Bound<'_, PyAny>>, src: bool) -> String {
    creds::format_supplied_auth_brief(&auth_of(auth), src)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add("CREDS_MODE", creds::CREDS_MODE)?;
    m.add_function(wrap_pyfunction!(credential_candidates_from_brief, m)?)?;
    m.add_function(wrap_pyfunction!(format_cred_hint, m)?)?;
    m.add_function(wrap_pyfunction!(password_values, m)?)?;
    m.add_function(wrap_pyfunction!(graph_cred_blob, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_supplied_auth, m)?)?;
    m.add_function(wrap_pyfunction!(merge_supplied_auth, m)?)?;
    m.add_function(wrap_pyfunction!(extract_supplied_auth, m)?)?;
    m.add_function(wrap_pyfunction!(merge_steering_supplied_auth, m)?)?;
    m.add_function(wrap_pyfunction!(secrets_from_supplied_auth, m)?)?;
    m.add_function(wrap_pyfunction!(format_supplied_auth_brief, m)?)?;
    Ok(())
}

pub fn allowed_secrets(brief: &str, nodes: &[(String, String)], auth: &SuppliedAuth) -> BTreeSet<String> {
    let blob = format!("{brief}\n{}", creds::graph_cred_blob(nodes, 3000));
    let mut secrets = creds::password_values(&creds::credential_candidates_from_brief(&blob, 10));
    secrets.extend(creds::secrets_from_supplied_auth(auth));
    secrets
}
