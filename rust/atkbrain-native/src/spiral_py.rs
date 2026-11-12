//! 螺旋账本的 Python 入口。

use atkbrain_core::spiral;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    py.import("json")?.call_method1("loads", (text,))
}

fn to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() { return Ok(Value::Null); }
    let text: String = obj.py().import("json")?.call_method1("dumps", (obj,))?.extract()?;
    serde_json::from_str(&text).map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
}

fn empty_cap(py: Python<'_>, limit: Option<i64>) -> i64 {
    if let Some(limit) = limit { return limit.max(1); }
    let Ok(cfg) = py.import("atkbrain.config") else { return 6 };
    let Ok(settings) = cfg.getattr("settings") else { return 6 };
    let Ok(value) = settings.getattr("loop_spiral_empty_plans") else { return 6 };
    value.extract::<i64>().unwrap_or(6).max(1)
}

fn texts(obj: Option<&Bound<'_, PyAny>>) -> Vec<String> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(iter) = obj.try_iter() else { return Vec::new() };
    iter.flatten().filter_map(|v| v.str().ok().map(|s| s.to_string_lossy().into_owned())).collect()
}

fn as_text(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    if let Ok(text) = obj.extract::<String>() {
        return Ok(text);
    }
    Ok(obj.str()?.to_string_lossy().into_owned())
}

#[pyfunction]
fn load_ledger<'py>(py: Python<'py>, workspace: &Bound<'_, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &spiral::load_ledger(&as_text(workspace)?))
}

#[pyfunction]
#[pyo3(signature = (workspace, *, grew, infra=false, limit=None))]
fn note_empty_plan<'py>(py: Python<'py>, workspace: &Bound<'_, PyAny>, grew: bool, infra: bool, limit: Option<i64>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &spiral::note_empty_plan(&as_text(workspace)?, grew, infra, empty_cap(py, limit)))
}

#[pyfunction]
#[pyo3(signature = (workspace, command, *, stdout=""))]
fn record_command<'py>(py: Python<'py>, workspace: &Bound<'_, PyAny>, command: &str, stdout: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
    match spiral::record_command(&as_text(workspace)?, command, stdout) {
        Some(value) => Ok(Some(to_py(py, &value)?)),
        None => Ok(None),
    }
}

#[pyfunction]
#[pyo3(signature = (workspace, *, face, tier, target="", hits=None, attacked=None))]
fn note_coverage<'py>(
    py: Python<'py>,
    workspace: &Bound<'_, PyAny>,
    face: &str,
    tier: &str,
    target: &str,
    hits: Option<&Bound<'_, PyAny>>,
    attacked: Option<&Bound<'_, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let hits = texts(hits);
    let attacked = match attacked.filter(|v| !v.is_none()) {
        Some(obj) => {
            let value = to_value(obj)?;
            value.as_array().cloned().unwrap_or_default()
        }
        None => Vec::new(),
    };
    to_py(py, &spiral::note_coverage(&as_text(workspace)?, face, tier, target, &hits, &attacked))
}

#[pyfunction]
#[pyo3(signature = (ledger, *, objective=None))]
fn scan_ban_repeats(py: Python<'_>, ledger: &Bound<'_, PyAny>, objective: Option<&str>) -> PyResult<Py<PyList>> {
    let value = to_value(ledger)?;
    let rows = spiral::scan_ban_repeats(&value, objective);
    let list = PyList::empty(py);
    for row in rows { list.append(row)?; }
    Ok(list.unbind())
}

#[pyfunction]
#[pyo3(signature = (ledger, *, objective=None))]
fn format_coverage_brief(py: Python<'_>, ledger: &Bound<'_, PyAny>, objective: Option<&str>) -> PyResult<String> {
    let value = to_value(ledger)?;
    Ok(spiral::format_coverage_brief(&value, objective, empty_cap(py, None)))
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    let labels = PyDict::new(m.py());
    labels.set_item(1, "小")?;
    labels.set_item(2, "中")?;
    labels.set_item(3, "大")?;
    m.add("RING_LABELS", labels)?;
    m.add_function(wrap_pyfunction!(load_ledger, m)?)?;
    m.add_function(wrap_pyfunction!(note_empty_plan, m)?)?;
    m.add_function(wrap_pyfunction!(record_command, m)?)?;
    m.add_function(wrap_pyfunction!(note_coverage, m)?)?;
    m.add_function(wrap_pyfunction!(scan_ban_repeats, m)?)?;
    m.add_function(wrap_pyfunction!(format_coverage_brief, m)?)?;
    Ok(())
}
