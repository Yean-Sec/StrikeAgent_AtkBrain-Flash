//! 项目的创建、修改和删除。调用方不再经过 projects.py。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use atkbrain_core::config::Settings;
use atkbrain_core::projects::{self, clean_target};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{Map, Value};

fn live_db_path(py: Python<'_>) -> PyResult<PathBuf> {
    if let Ok(module) = py.import("atkbrain.db") {
        if let Ok(db) = module.getattr("db") {
            if let Ok(path) = db.getattr("path") {
                if let Ok(text) = path.str() {
                    let path = PathBuf::from(text.to_string_lossy().as_ref());
                    if !path.as_os_str().is_empty() {
                        return Ok(path);
                    }
                }
            }
        }
    }
    let cfg = py.import("atkbrain.config")?;
    let text = cfg.getattr("settings")?.getattr("db_path")?.str()?;
    Ok(PathBuf::from(text.to_string_lossy().as_ref()))
}

fn open_db(py: Python<'_>) -> PyResult<atkbrain_core::db::Db> {
    atkbrain_core::db::Db::open(&live_db_path(py)?).map_err(|e| PyRuntimeError::new_err(e))
}

fn settings_now() -> Settings {
    let env: HashMap<String, String> = std::env::vars_os()
        .map(|(key, value)| (key.to_string_lossy().into_owned(), value.to_string_lossy().into_owned()))
        .collect();
    Settings::from_map(&env, Path::new("."))
}

fn val(message: String) -> PyErr {
    PyValueError::new_err(message)
}

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    let json = pyo3::types::PyModule::import(py, "json")?;
    json.call_method1("loads", (text,))
}

fn to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    let json = pyo3::types::PyModule::import(obj.py(), "json")?;
    let text: String = json.call_method1("dumps", (obj,))?.extract()?;
    serde_json::from_str(&text).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

fn string_list(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<String>> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(Vec::new()) };
    if let Ok(iter) = obj.try_iter() {
        let mut out = Vec::new();
        for item in iter {
            let item = item?;
            if item.is_none() {
                continue;
            }
            out.push(item.str()?.to_string_lossy().into_owned());
        }
        return Ok(out);
    }
    Ok(vec![obj.str()?.to_string_lossy().into_owned()])
}

fn ports_of(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Vec<i64>>> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(None) };
    let mut out = Vec::new();
    for item in obj.try_iter()? {
        out.push(item?.extract::<i64>()?);
    }
    Ok(Some(out))
}

fn stamp_hard_stop(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<()> {
    if obj.is_instance_of::<pyo3::types::PyList>() {
        for item in obj.try_iter()? {
            stamp_hard_stop(py, &item?)?;
        }
        return Ok(());
    }
    if !obj.is_instance_of::<PyDict>() {
        return Ok(());
    }
    let kind = obj.call_method1("get", ("kind", py.None()))?;
    if kind.is_none() {
        return Ok(());
    }
    let cfg = obj.call_method1("get", ("config", py.None()))?;
    let objective = if cfg.is_none() {
        py.None().into_bound(py)
    } else {
        cfg.call_method1("get", ("objective", py.None()))?
    };
    let info = match py.import("atkbrain_native").and_then(|m| m.getattr("hunt_hard_stop_info")).and_then(|f| f.call1((objective,))) {
        Ok(info) => info,
        Err(err) => { let _ = err.value(py); return Ok(()); }
    };
    obj.set_item("hard_stop", info)?;
    Ok(())
}

fn project_out<'py>(py: Python<'py>, value: Value) -> PyResult<Bound<'py, PyAny>> {
    let obj = to_py(py, &value)?;
    stamp_hard_stop(py, &obj)?;
    Ok(obj)
}

#[pyfunction]
fn assert_safe_project_target(py: Python<'_>, target: &str) -> PyResult<String> {
    let (host, _) = clean_target(target);
    if host.is_empty() {
        return Err(val("目标不能为空".into()));
    }
    let reason = py.import("atkbrain_native")?.getattr("forbidden_project_target_reason")?.call1((&host,))?;
    if !reason.is_none() {
        return Err(val(reason.str()?.to_string_lossy().into_owned()));
    }
    Ok(host)
}

#[pyfunction]
fn ensure_project_target_safe(py: Python<'_>, pid: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let project = projects::ensure_project_target_safe(&db, &settings_now(), pid).map_err(val)?;
    let target = project.get("target").and_then(Value::as_str).unwrap_or("");
    if !target.is_empty() {
        assert_safe_project_target(py, target)?;
    }
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
fn resolve_project_host(host: &str) -> Vec<String> {
    projects::resolve_host(host)
}

#[pyfunction]
#[pyo3(signature = (host, ips, objective=None))]
fn filter_scope_ips(host: &str, ips: Vec<String>, objective: Option<&str>) -> (Vec<String>, Option<String>) {
    projects::filter_scope_ips(host, &ips, objective)
}

#[pyfunction]
#[pyo3(signature = (name, config=None))]
fn create_offline_ctf_project(py: Python<'_>, name: &str, config: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let cfg = config.map(to_value).transpose()?.unwrap_or(Value::Null);
    let project = projects::create_offline_ctf_project(&db, &settings_now(), name, cfg).map_err(val)?;
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (name, target, ports=None, *, allow_subdomains=false, mode="strict", config=None, parent_id=None, extra_targets=None, extra_ips=None))]
fn create_single_project(
    py: Python<'_>,
    name: &str,
    target: &str,
    ports: Option<&Bound<'_, PyAny>>,
    allow_subdomains: bool,
    mode: &str,
    config: Option<&Bound<'_, PyAny>>,
    parent_id: Option<&str>,
    extra_targets: Option<&Bound<'_, PyAny>>,
    extra_ips: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    assert_safe_project_target(py, target)?;
    for extra in string_list(extra_targets)? {
        assert_safe_project_target(py, &extra)?;
    }
    let db = open_db(py)?;
    let ports = ports_of(ports)?;
    let cfg = config.map(to_value).transpose()?.unwrap_or(Value::Object(Map::new()));
    let extras = string_list(extra_targets)?;
    let ips = string_list(extra_ips)?;
    let parent = parent_id.filter(|s| !s.is_empty());
    let project = projects::create_single_project_full(
        &db,
        &settings_now(),
        name,
        target,
        ports.as_deref(),
        allow_subdomains,
        mode,
        cfg,
        parent,
        &extras,
        &ips,
    ).map_err(val)?;
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (name, assets, config=None))]
fn create_cluster_project(
    py: Python<'_>,
    name: &str,
    assets: &Bound<'_, PyAny>,
    config: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let cluster = py.import("atkbrain.cluster")?;
    let lines = cluster.getattr("parse_asset_lines")?.call1((assets,))?;
    let mut cleaned = Vec::new();
    let mut rejected = Vec::new();
    for item in lines.try_iter()? {
        let raw = item?.extract::<String>()?;
        match assert_safe_project_target(py, &raw) {
            Ok(_) => cleaned.push(raw),
            Err(err) => {
                let _ = err.value(py);
                rejected.push(raw);
            }
        }
    }
    let pair = cluster.getattr("compact_assets_by_host")?.call1((cleaned,))?;
    let mut compacted = Vec::new();
    for item in pair.get_item(0)?.try_iter()? {
        compacted.push(item?.extract::<String>()?);
    }
    let db = open_db(py)?;
    let cfg = config.map(to_value).transpose()?.unwrap_or(Value::Object(Map::new()));
    let project = projects::create_cluster_project(&db, &settings_now(), name, &compacted, &rejected, cfg).map_err(val)?;
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (name, base_url, token, config=None))]
fn create_benchmark_project(
    py: Python<'_>,
    name: &str,
    base_url: &str,
    token: &str,
    config: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let cfg = config.map(to_value).transpose()?.unwrap_or(Value::Object(Map::new()));
    let project = projects::create_benchmark_project(&db, &settings_now(), name, base_url, token, cfg).map_err(val)?;
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (kind=None, config=None))]
fn project_track(kind: Option<&str>, config: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    let cfg = match config {
        Some(obj) if !obj.is_none() => to_value(obj)?,
        _ => Value::Null,
    };
    Ok(atkbrain_core::graph::project_track(kind, &cfg))
}

#[pyfunction]
fn get_project(py: Python<'_>, pid: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    match projects::get_project(&db, &settings_now(), pid).map_err(|e| PyRuntimeError::new_err(e))? {
        Some(project) => Ok(project_out(py, project)?.unbind()),
        None => Ok(py.None()),
    }
}

#[pyfunction]
fn list_projects(py: Python<'_>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = projects::list_projects(&db, &settings_now()).map_err(|e| PyRuntimeError::new_err(e))?;
    Ok(project_out(py, Value::Array(rows))? .unbind())
}

#[pyfunction]
fn list_child_ids(py: Python<'_>, pid: &str) -> PyResult<Vec<String>> {
    let db = open_db(py)?;
    projects::list_child_ids(&db, pid).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn list_child_projects(py: Python<'_>, pid: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = projects::list_child_projects(&db, &settings_now(), pid).map_err(|e| PyRuntimeError::new_err(e))?;
    Ok(project_out(py, Value::Array(rows))?.unbind())
}

#[pyfunction]
fn update_status(py: Python<'_>, pid: &str, status: &str) -> PyResult<()> {
    let db = open_db(py)?;
    projects::update_status(&db, pid, status).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn update_config(py: Python<'_>, pid: &str, config: &Bound<'_, PyAny>) -> PyResult<()> {
    let db = open_db(py)?;
    projects::update_config(&db, pid, &to_value(config)?).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn update_scope_and_config(py: Python<'_>, pid: &str, scope: &Bound<'_, PyAny>, config: &Bound<'_, PyAny>) -> PyResult<()> {
    let db = open_db(py)?;
    projects::update_scope_and_config(&db, pid, &to_value(scope)?, &to_value(config)?).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn rename_project(py: Python<'_>, pid: &str, name: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let project = projects::rename_project(&db, &settings_now(), pid, name).map_err(val)?;
    Ok(project_out(py, project)?.unbind())
}

#[pyfunction]
fn delete_project(py: Python<'_>, pid: &str) -> PyResult<()> {
    let db = open_db(py)?;
    projects::delete_project(&db, pid).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn delete_projects(py: Python<'_>, ids: Vec<String>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = projects::delete_projects(&db, &settings_now(), &ids).map_err(|e| PyRuntimeError::new_err(e))?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
fn unstick_transient_resource_errors(py: Python<'_>) -> PyResult<i64> {
    let db = open_db(py)?;
    projects::unstick_transient_resource_errors(&db).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn reclassify_hunt_failures(py: Python<'_>) -> PyResult<i64> {
    let db = open_db(py)?;
    projects::reclassify_hunt_failures(&db).map_err(|e| PyRuntimeError::new_err(e))
}

#[pyfunction]
fn build_scope(py: Python<'_>, project: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let scope = if let Ok(dict) = project.downcast::<PyDict>() {
        dict.get_item("scope")?.unwrap_or_else(|| py.None().into_bound(py))
    } else {
        project.call_method1("get", ("scope", py.None()))?
    };
    let native = py.import("atkbrain_native")?;
    Ok(native.getattr("Scope")?.call_method1("from_dict", (scope,))?.unbind())
}

#[pyfunction]
fn advance_model_chain(py: Python<'_>, project_id: &str) -> PyResult<Option<String>> {
    let db = open_db(py)?;
    projects::advance_model_chain(&db, &settings_now(), project_id).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
fn looks_like_model_failure(message: &str) -> bool {
    projects::looks_like_model_failure(message)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(assert_safe_project_target, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_project_target_safe, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_project_host, m)?)?;
    m.add_function(wrap_pyfunction!(filter_scope_ips, m)?)?;
    m.add_function(wrap_pyfunction!(create_offline_ctf_project, m)?)?;
    m.add_function(wrap_pyfunction!(create_single_project, m)?)?;
    m.add_function(wrap_pyfunction!(create_cluster_project, m)?)?;
    m.add_function(wrap_pyfunction!(create_benchmark_project, m)?)?;
    m.add_function(wrap_pyfunction!(project_track, m)?)?;
    m.add_function(wrap_pyfunction!(get_project, m)?)?;
    m.add_function(wrap_pyfunction!(list_projects, m)?)?;
    m.add_function(wrap_pyfunction!(list_child_ids, m)?)?;
    m.add_function(wrap_pyfunction!(list_child_projects, m)?)?;
    m.add_function(wrap_pyfunction!(update_status, m)?)?;
    m.add_function(wrap_pyfunction!(update_config, m)?)?;
    m.add_function(wrap_pyfunction!(update_scope_and_config, m)?)?;
    m.add_function(wrap_pyfunction!(rename_project, m)?)?;
    m.add_function(wrap_pyfunction!(delete_project, m)?)?;
    m.add_function(wrap_pyfunction!(delete_projects, m)?)?;
    m.add_function(wrap_pyfunction!(unstick_transient_resource_errors, m)?)?;
    m.add_function(wrap_pyfunction!(reclassify_hunt_failures, m)?)?;
    m.add_function(wrap_pyfunction!(build_scope, m)?)?;
    m.add_function(wrap_pyfunction!(advance_model_chain, m)?)?;
    m.add_function(wrap_pyfunction!(looks_like_model_failure, m)?)?;
    Ok(())
}
