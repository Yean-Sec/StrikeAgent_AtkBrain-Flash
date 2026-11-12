//! HTTP 交换记录走 Rust，库文件用当前 settings.db_path。

use std::path::PathBuf;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

fn db_path(py: Python<'_>) -> PyResult<PathBuf> {
    let cfg = py.import("atkbrain.config")?;
    let settings = cfg.getattr("settings")?;
    let text = settings.getattr("db_path")?.str()?;
    Ok(PathBuf::from(text.to_string_lossy().as_ref()))
}

fn open_db(py: Python<'_>) -> PyResult<atkbrain_core::db::Db> {
    atkbrain_core::db::Db::open(&db_path(py)?).map_err(PyRuntimeError::new_err)
}

fn dumps(value: &Bound<'_, PyAny>) -> PyResult<String> {
    if value.is_none() {
        return Ok(String::new());
    }
    if let Ok(text) = value.extract::<String>() {
        return Ok(text);
    }
    let json = pyo3::types::PyModule::import(value.py(), "json")?;
    json.call_method1("dumps", (value,))?.extract()
}

fn loads<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyAny>> {
    let json = pyo3::types::PyModule::import(py, "json")?;
    json.call_method1("loads", (text,))
}

#[pyfunction]
#[pyo3(signature = (project_id, *, run_id=None, method="GET", url="", request_headers=None, request_body="", status=None, response_headers=None, response_body=""))]
fn record_exchange(
    py: Python<'_>,
    project_id: &str,
    run_id: Option<&str>,
    method: &str,
    url: &str,
    request_headers: Option<&Bound<'_, PyAny>>,
    request_body: Option<&str>,
    status: Option<&Bound<'_, PyAny>>,
    response_headers: Option<&Bound<'_, PyAny>>,
    response_body: Option<&str>,
) -> PyResult<String> {
    let db = open_db(py)?;
    let req_headers = match request_headers {
        Some(value) => dumps(value)?,
        None => String::new(),
    };
    let resp_headers = match response_headers {
        Some(value) => dumps(value)?,
        None => String::new(),
    };
    let status = status.and_then(|value| value.extract::<i64>().ok()).unwrap_or(0);
    atkbrain_core::http_log::record_exchange(
        &db,
        project_id,
        run_id,
        method,
        url,
        &req_headers,
        request_body.unwrap_or(""),
        status,
        &resp_headers,
        response_body.unwrap_or(""),
    )
    .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (finding_id, refs=None))]
fn bind_finding(py: Python<'_>, finding_id: &str, refs: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let raw = match refs {
        Some(value) if !value.is_none() => dumps(value)?,
        _ => "[]".into(),
    };
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap_or_default();
    let result = atkbrain_core::http_log::bind_finding(&db, finding_id, &parsed).map_err(PyRuntimeError::new_err)?;
    Ok(loads(py, &result.to_string())?.unbind())
}

#[pyfunction]
fn bound_exchanges(py: Python<'_>, finding_id: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = atkbrain_core::http_log::bound_exchanges(&db, finding_id).map_err(PyRuntimeError::new_err)?;
    let text = serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into());
    Ok(loads(py, &text)?.unbind())
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(record_exchange, m)?)?;
    m.add_function(wrap_pyfunction!(bind_finding, m)?)?;
    m.add_function(wrap_pyfunction!(bound_exchanges, m)?)?;
    Ok(())
}
