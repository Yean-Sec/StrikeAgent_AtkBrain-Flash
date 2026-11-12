//! 攻击图的 Python 入口。库路径跟当前 `atkbrain.db.db.path` 走，测试换临时库仍然有效。

use std::path::PathBuf;

use atkbrain_core::graph::{EdgeIn, FindingIn, IntentIn, NodeIn};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::PyErr;
use pyo3::types::PyDict;
use serde_json::Value;

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
    atkbrain_core::db::Db::open(&live_db_path(py)?).map_err(PyRuntimeError::new_err)
}

fn dumps(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    if obj.hasattr("model_dump")? {
        let dumped = obj.call_method0("model_dump")?;
        let json = pyo3::types::PyModule::import(obj.py(), "json")?;
        return json.call_method1("dumps", (dumped,))?.extract();
    }
    let json = pyo3::types::PyModule::import(obj.py(), "json")?;
    json.call_method1("dumps", (obj,))?.extract()
}

fn to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    let text = dumps(obj)?;
    serde_json::from_str(&text).map_err(|err| PyRuntimeError::new_err(err.to_string()))
}

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    let json = pyo3::types::PyModule::import(py, "json")?;
    json.call_method1("loads", (text,))
}

fn err(message: String) -> PyErr {
    PyRuntimeError::new_err(message)
}

fn node_in(obj: &Bound<'_, PyAny>) -> PyResult<NodeIn> {
    serde_json::from_value(to_value(obj)?).map_err(|e| err(e.to_string()))
}

fn edge_in(obj: &Bound<'_, PyAny>) -> PyResult<EdgeIn> {
    serde_json::from_value(to_value(obj)?).map_err(|e| err(e.to_string()))
}

fn finding_in(obj: &Bound<'_, PyAny>) -> PyResult<FindingIn> {
    serde_json::from_value(to_value(obj)?).map_err(|e| err(e.to_string()))
}

fn intent_in(obj: &Bound<'_, PyAny>) -> PyResult<IntentIn> {
    serde_json::from_value(to_value(obj)?).map_err(|e| err(e.to_string()))
}

fn string_list(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<String>> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(Vec::new()) };
    let value = to_value(obj)?;
    Ok(match value {
        Value::Array(items) => items.into_iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        Value::String(s) => vec![s],
        _ => Vec::new(),
    })
}

#[pyfunction]
#[pyo3(signature = (project_id, heal=false))]
fn get_graph(py: Python<'_>, project_id: &str, heal: bool) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::get_graph(&db, project_id, heal).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
fn get_stats(py: Python<'_>, project_id: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::get_stats(&db, project_id).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
fn get_stats_batch(py: Python<'_>, project_ids: Vec<String>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::get_stats_batch(&db, &project_ids).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (*, q="", project="", category="", severity="", track="", page=1, page_size=30))]
fn list_library_findings(
    py: Python<'_>,
    q: &str,
    project: &str,
    category: &str,
    severity: &str,
    track: &str,
    page: i64,
    page_size: i64,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::list_library_findings(&db, q, project, category, severity, track, page, page_size).map_err(err)?;
    let obj = to_py(py, &value)?;
    let items = match obj.get_item("items") {
        Ok(items) => items,
        Err(err) => { let _ = err.value(py); return Ok(obj.unbind()); }
    };
    let jobs = match py.import("atkbrain.review.jobs") {
        Ok(jobs) => jobs,
        Err(err) => { let _ = err.value(py); return Ok(obj.unbind()); }
    };
    let state_fn = match jobs.getattr("review_state") {
        Ok(func) => func,
        Err(err) => { let _ = err.value(py); return Ok(obj.unbind()); }
    };
    if let Ok(iter) = items.try_iter() {
        for item in iter.flatten() {
            let pid: String = item.call_method1("get", ("project_id", "")).and_then(|v| v.extract()).unwrap_or_default();
            let fid: String = item.call_method1("get", ("id", "")).and_then(|v| v.extract()).unwrap_or_default();
            let state = match state_fn.call1((pid, fid)) {
                Ok(state) => state,
                Err(err) => { let _ = err.value(py); continue; }
            };
            let sec = state.call_method1("get", ("secondary",))?;
            let rate = state.call_method1("get", ("rating",))?;
            let sec_run = !sec.is_none() && sec.call_method1("get", ("status", "")).and_then(|v| v.extract::<String>()).unwrap_or_default() == "running";
            let rate_run = !rate.is_none() && rate.call_method1("get", ("status", "")).and_then(|v| v.extract::<String>()).unwrap_or_default() == "running";
            item.set_item("review_secondary", sec)?;
            item.set_item("review_rating", rate)?;
            item.set_item("reviewing_secondary", sec_run)?;
            item.set_item("reviewing_rating", rate_run)?;
        }
    }
    Ok(obj.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, node, run_id=None))]
fn upsert_node(py: Python<'_>, project_id: &str, node: &Bound<'_, PyAny>, run_id: Option<&str>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::upsert_node(&db, project_id, node_in(node)?, run_id).map_err(err)?;
    Ok(to_py(py, &serde_json::Value::Object(row))?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, edge, run_id=None))]
fn add_edge(py: Python<'_>, project_id: &str, edge: &Bound<'_, PyAny>, run_id: Option<&str>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::add_edge(&db, project_id, &edge_in(edge)?, run_id).map_err(err)?;
    Ok(to_py(py, &serde_json::Value::Object(row))?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, finding, run_id=None))]
fn add_finding(py: Python<'_>, project_id: &str, finding: &Bound<'_, PyAny>, run_id: Option<&str>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::add_finding(&db, project_id, finding_in(finding)?, run_id).map_err(err)?;
    let obj = to_py(py, &row)?;
    schedule_webhook(py, project_id, &obj);
    Ok(obj.unbind())
}

fn schedule_webhook(py: Python<'_>, project_id: &str, finding: &Bound<'_, PyAny>) {
    let notify = match py.import("atkbrain.notify") {
        Ok(module) => module,
        Err(err) => { let _ = err.value(py); return; }
    };
    let func = match notify.getattr("enqueue_finding") {
        Ok(func) => func,
        Err(err) => { let _ = err.value(py); return; }
    };
    let coro = match func.call1((project_id, finding)) {
        Ok(coro) => coro,
        Err(err) => { let _ = err.value(py); return; }
    };
    let asyncio = match py.import("asyncio") {
        Ok(module) => module,
        Err(err) => { let _ = err.value(py); return; }
    };
    match asyncio.getattr("get_running_loop").and_then(|f| f.call0()) {
        Ok(loop_) => { let _ = loop_.call_method1("create_task", (coro,)); }
        Err(err) => {
            let _ = err.value(py);
            let _ = asyncio.call_method1("run", (coro,));
        }
    }
    if let Some(err) = PyErr::take(py) {
        let _ = err.value(py);
    }
}

#[pyfunction]
#[pyo3(signature = (project_id, limit=30))]
fn list_open_intents(py: Python<'_>, project_id: &str, limit: i64) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = atkbrain_core::graph::list_open_intents(&db, project_id, limit).map_err(err)?;
    Ok(to_py(py, &rows)?.unbind())
}

#[pyfunction]
fn quality_progress_delta(py: Python<'_>, prev: Vec<i64>, curr: Vec<i64>, graph: &Bound<'_, PyAny>) -> PyResult<String> {
    Ok(atkbrain_core::graph::quality_progress_delta(&prev, &curr, &to_value(graph)?))
}

#[pyfunction]
fn clear_graph(py: Python<'_>, project_id: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::clear_graph(&db, project_id).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, host, scope_detail=None, run_id=None, keep_hosts=None))]
fn adopt_entry_host(
    py: Python<'_>,
    project_id: &str,
    host: &str,
    scope_detail: Option<&Bound<'_, PyAny>>,
    run_id: Option<&str>,
    keep_hosts: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let detail = scope_detail.map(to_value).transpose()?;
    let keep = string_list(keep_hosts)?;
    let value = atkbrain_core::graph::adopt_entry_host(&db, project_id, host, detail.as_ref(), run_id, &keep).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None, force=false))]
fn refresh_derived_intents(py: Python<'_>, project_id: &str, run_id: Option<&str>, force: bool) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let value = atkbrain_core::graph::refresh_derived_intents(&db, project_id, run_id, force).map_err(err)?;
    Ok(to_py(py, &value)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None))]
fn reopen_live_hop_auth(py: Python<'_>, project_id: &str, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::reopen_live_hop_auth(&db, project_id, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None))]
fn reopen_false_disproved_hop_auth(py: Python<'_>, project_id: &str, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::reopen_false_disproved_hop_auth(&db, project_id, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, tactics, run_id=None))]
fn reopen_advisor_deferred_tactics(py: Python<'_>, project_id: &str, tactics: Vec<String>, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::reopen_advisor_deferred_tactics(&db, project_id, &tactics, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, needs_oracle, run_id=None))]
fn reopen_false_closed_oracle(py: Python<'_>, project_id: &str, needs_oracle: bool, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::reopen_false_closed_oracle(&db, project_id, needs_oracle, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None))]
fn defer_local_closeout_for_remaining_flags(py: Python<'_>, project_id: &str, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::defer_local_closeout_for_remaining_flags(&db, project_id, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, *, limit=8, exclude=None, prefer=None))]
fn list_frontier_intents(
    py: Python<'_>,
    project_id: &str,
    limit: i64,
    exclude: Option<&Bound<'_, PyAny>>,
    prefer: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let exclude: std::collections::HashSet<String> = string_list(exclude)?.into_iter().collect();
    let prefer: std::collections::HashSet<String> = string_list(prefer)?.into_iter().collect();
    let rows = atkbrain_core::graph::list_frontier_intents(&db, project_id, limit, &exclude, &prefer).map_err(err)?;
    Ok(to_py(py, &rows)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, intent_ids, run_id=None))]
fn claim_intents(py: Python<'_>, project_id: &str, intent_ids: Vec<String>, run_id: Option<&str>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = atkbrain_core::graph::claim_intents(&db, project_id, &intent_ids, run_id).map_err(err)?;
    Ok(to_py(py, &rows)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, intent_id, status, result_summary=None, failure_fingerprint=None, run_id=None))]
fn set_intent_status(
    py: Python<'_>,
    project_id: &str,
    intent_id: &str,
    status: &str,
    result_summary: Option<&str>,
    failure_fingerprint: Option<&str>,
    run_id: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::set_intent_status(&db, project_id, intent_id, status, result_summary, failure_fingerprint, run_id).map_err(err)?;
    Ok(to_py(py, &row)?.unbind())
}

#[pyfunction]
fn has_verified_internal_vantage(py: Python<'_>, project_id: &str) -> PyResult<bool> {
    let db = open_db(py)?;
    atkbrain_core::graph::has_verified_internal_vantage(&db, project_id).map_err(err)
}

#[pyfunction]
fn find_pivot_vuln(py: Python<'_>, project_id: &str, from_host: &str, mechanism: &str) -> PyResult<String> {
    let db = open_db(py)?;
    atkbrain_core::graph::find_pivot_vuln(&db, project_id, from_host, mechanism).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, host, title, run_id=None, live=None, extra_tags=None))]
fn ensure_host_target(
    py: Python<'_>,
    project_id: &str,
    host: &str,
    title: &str,
    run_id: Option<&str>,
    live: Option<bool>,
    extra_tags: Option<&Bound<'_, PyAny>>,
) -> PyResult<String> {
    let db = open_db(py)?;
    let tags = string_list(extra_tags)?;
    atkbrain_core::graph::ensure_host_target(&db, project_id, host, title, run_id, live, &tags).map_err(err)
}

#[pyfunction]
fn is_verified_lateral_pivot(py: Python<'_>, project_id: &str, src: &str, dst: &str) -> PyResult<bool> {
    let db = open_db(py)?;
    atkbrain_core::graph::is_verified_lateral_pivot(&db, project_id, src, dst).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, key, title=None, detail=None, severity=None, ntype=None, run_id=None))]
fn fill_source_node(
    py: Python<'_>,
    project_id: &str,
    key: &str,
    title: Option<&str>,
    detail: Option<&str>,
    severity: Option<&str>,
    ntype: Option<&str>,
    run_id: Option<&str>,
) -> PyResult<()> {
    let db = open_db(py)?;
    atkbrain_core::graph::fill_source_node(&db, project_id, key, title, detail, severity, ntype, run_id).map_err(err)
}

#[pyfunction]
fn find_host_source(py: Python<'_>, project_id: &str, host: &str) -> PyResult<String> {
    let db = open_db(py)?;
    atkbrain_core::graph::find_host_source(&db, project_id, host).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, intent, run_id=None))]
fn add_intent(py: Python<'_>, project_id: &str, intent: &Bound<'_, PyAny>, run_id: Option<&str>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::add_intent(&db, project_id, &intent_in(intent)?, run_id).map_err(err)?;
    Ok(to_py(py, &row)?.unbind())
}

#[pyfunction]
fn get_intent(py: Python<'_>, project_id: &str, intent_id: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::get_intent(&db, project_id, intent_id).map_err(err)?;
    Ok(to_py(py, &row)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, intent_id, verified, summary=None, failure_fingerprint=None, run_id=None))]
fn resolve_intent(
    py: Python<'_>,
    project_id: &str,
    intent_id: &str,
    verified: bool,
    summary: Option<&str>,
    failure_fingerprint: Option<&str>,
    run_id: Option<&str>,
) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let row = atkbrain_core::graph::resolve_intent(&db, project_id, intent_id, verified, summary, failure_fingerprint, run_id).map_err(err)?;
    Ok(to_py(py, &row)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None))]
fn nudge_hop_auth_frontier(py: Python<'_>, project_id: &str, run_id: Option<&str>) -> PyResult<String> {
    let db = open_db(py)?;
    atkbrain_core::graph::nudge_hop_auth_frontier(&db, project_id, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, want_secondary=None, want_rating=None))]
fn findings_pending_review(py: Python<'_>, project_id: &str, want_secondary: Option<bool>, want_rating: Option<bool>) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = atkbrain_core::graph::findings_pending_review(&db, project_id, want_secondary, want_rating).map_err(err)?;
    Ok(to_py(py, &rows)?.unbind())
}

#[pyfunction]
fn findings_pending_secondary(py: Python<'_>, project_id: &str) -> PyResult<Py<PyAny>> {
    let db = open_db(py)?;
    let rows = atkbrain_core::graph::findings_pending_secondary(&db, project_id).map_err(err)?;
    Ok(to_py(py, &rows)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (project_id, run_id=None))]
fn promote_orphan_vuln_nodes(py: Python<'_>, project_id: &str, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::promote_orphan_vuln_nodes(&db, project_id, run_id).map_err(err)
}

#[pyfunction]
#[pyo3(signature = (project_id, strategy_key, reason="", run_id=None))]
fn defer_strategy_family(py: Python<'_>, project_id: &str, strategy_key: &str, reason: &str, run_id: Option<&str>) -> PyResult<i64> {
    let db = open_db(py)?;
    atkbrain_core::graph::defer_strategy_family(&db, project_id, strategy_key, reason, run_id).map_err(err)
}

#[pyfunction]
fn invalidate_graph_cache(project_id: Option<&str>) {
    atkbrain_core::graph::invalidate_graph_cache(project_id);
}

#[pyfunction]
fn serialize_finding(py: Python<'_>, row: &Bound<'_, PyDict>) -> PyResult<Py<PyAny>> {
    let value = to_value(row)?;
    let Some(map) = value.as_object() else {
        return Ok(to_py(py, &value)?.unbind());
    };
    Ok(to_py(py, &atkbrain_core::graph::serialize_finding(map))?.unbind())
}

#[pyfunction]
fn should_promote_intranet_host(host: &str, tags: Vec<String>, primary: &str) -> bool {
    atkbrain_core::graph::should_promote_intranet_host(host, &tags, primary)
}

#[pyfunction]
fn host_from_asset_key(key: &str) -> String {
    atkbrain_core::graph::host_from_asset_key(key)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_graph, m)?)?;
    m.add_function(wrap_pyfunction!(get_stats, m)?)?;
    m.add_function(wrap_pyfunction!(get_stats_batch, m)?)?;
    m.add_function(wrap_pyfunction!(list_library_findings, m)?)?;
    m.add_function(wrap_pyfunction!(upsert_node, m)?)?;
    m.add_function(wrap_pyfunction!(add_edge, m)?)?;
    m.add_function(wrap_pyfunction!(add_finding, m)?)?;
    m.add_function(wrap_pyfunction!(list_open_intents, m)?)?;
    m.add_function(wrap_pyfunction!(quality_progress_delta, m)?)?;
    m.add_function(wrap_pyfunction!(clear_graph, m)?)?;
    m.add_function(wrap_pyfunction!(adopt_entry_host, m)?)?;
    m.add_function(wrap_pyfunction!(refresh_derived_intents, m)?)?;
    m.add_function(wrap_pyfunction!(reopen_live_hop_auth, m)?)?;
    m.add_function(wrap_pyfunction!(reopen_false_disproved_hop_auth, m)?)?;
    m.add_function(wrap_pyfunction!(reopen_advisor_deferred_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(reopen_false_closed_oracle, m)?)?;
    m.add_function(wrap_pyfunction!(defer_local_closeout_for_remaining_flags, m)?)?;
    m.add_function(wrap_pyfunction!(list_frontier_intents, m)?)?;
    m.add_function(wrap_pyfunction!(claim_intents, m)?)?;
    m.add_function(wrap_pyfunction!(set_intent_status, m)?)?;
    m.add_function(wrap_pyfunction!(has_verified_internal_vantage, m)?)?;
    m.add_function(wrap_pyfunction!(find_pivot_vuln, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_host_target, m)?)?;
    m.add_function(wrap_pyfunction!(is_verified_lateral_pivot, m)?)?;
    m.add_function(wrap_pyfunction!(fill_source_node, m)?)?;
    m.add_function(wrap_pyfunction!(find_host_source, m)?)?;
    m.add_function(wrap_pyfunction!(add_intent, m)?)?;
    m.add_function(wrap_pyfunction!(get_intent, m)?)?;
    m.add_function(wrap_pyfunction!(resolve_intent, m)?)?;
    m.add_function(wrap_pyfunction!(nudge_hop_auth_frontier, m)?)?;
    m.add_function(wrap_pyfunction!(findings_pending_review, m)?)?;
    m.add_function(wrap_pyfunction!(findings_pending_secondary, m)?)?;
    m.add_function(wrap_pyfunction!(promote_orphan_vuln_nodes, m)?)?;
    m.add_function(wrap_pyfunction!(defer_strategy_family, m)?)?;
    m.add_function(wrap_pyfunction!(invalidate_graph_cache, m)?)?;
    m.add_function(wrap_pyfunction!(serialize_finding, m)?)?;
    m.add_function(wrap_pyfunction!(should_promote_intranet_host, m)?)?;
    m.add_function(wrap_pyfunction!(host_from_asset_key, m)?)?;
    Ok(())
}
