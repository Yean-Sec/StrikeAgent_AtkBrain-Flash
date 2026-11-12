//! 猎面调度的 Python 入口。事件仍推到现有的 `events.emit`。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use atkbrain_core::config::Settings;
use atkbrain_core::db::Db;
use atkbrain_core::engine::{self, RunManager};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::Value;

fn lossy(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().into_owned()
}

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

fn live_settings(py: Python<'_>) -> Settings {
    let env: HashMap<String, String> = std::env::vars_os()
        .map(|(key, value)| (lossy(&key), lossy(&value)))
        .collect();
    let mut settings = Settings::from_map(&env, Path::new("."));
    let Ok(module) = py.import("atkbrain.config") else { return settings };
    let Ok(src) = module.getattr("settings") else { return settings };
    if let Ok(path) = src.getattr("data_dir") {
        if let Ok(text) = path.str() {
            let path = text.to_string_lossy().into_owned();
            if !path.is_empty() {
                settings.data_dir = PathBuf::from(path);
            }
        }
    }
    if let Ok(value) = src.getattr("port") {
        if let Ok(port) = value.extract::<u16>() {
            settings.port = port;
        }
    }
    settings
}

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    py.import("json")?.call_method1("loads", (text,))
}

fn discard(py: Python<'_>, err: PyErr) {
    let _ = err.value(py);
}

fn remember_loop(py: Python<'_>) {
    let Ok(asyncio) = py.import("asyncio") else { return };
    match asyncio.call_method0("get_running_loop") {
        Ok(loop_) => *lock_loop().lock().unwrap_or_else(|e| e.into_inner()) = Some(loop_.unbind()),
        Err(err) => discard(py, err),
    }
}

fn lock_loop() -> &'static std::sync::Mutex<Option<Py<PyAny>>> {
    static LOOP: OnceLock<std::sync::Mutex<Option<Py<PyAny>>>> = OnceLock::new();
    LOOP.get_or_init(|| std::sync::Mutex::new(None))
}

fn current_loop(py: Python<'_>) -> Option<Py<PyAny>> {
    lock_loop().lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|item| item.clone_ref(py))
}

fn manager() -> &'static RunManager {
    static MANAGER: OnceLock<RunManager> = OnceLock::new();
    MANAGER.get_or_init(|| {
        let (db, settings) = Python::with_gil(|py| {
            let path = live_db_path(py).unwrap_or_else(|_| PathBuf::from("atkbrain.db"));
            let db = Db::open(&path).unwrap_or_else(|_| Db::open(Path::new(":memory:")).expect("memory db"));
            (Arc::new(db), live_settings(py))
        });
        let manager = RunManager::new(db, settings);
        engine::set_emit_hook(Some(Arc::new(|project, kind, payload, run_id| {
            Python::with_gil(|py| publish_event(py, project, kind, payload, run_id));
        })));
        engine::set_consult_hook(Some(Arc::new(|project, turn, summary, run_id| {
            Python::with_gil(|py| consult(py, project, turn, summary, run_id)).unwrap_or_default()
        })));
        manager
    })
}

fn publish_event(py: Python<'_>, project: &str, kind: &str, payload: &Value, run_id: Option<&str>) {
    let Ok(events) = py.import("atkbrain.events") else { return };
    let Ok(func) = events.getattr("emit") else { return };
    let Ok(body) = to_py(py, payload) else { return };
    let kwargs = PyDict::new(py);
    if let Some(run_id) = run_id {
        let _ = kwargs.set_item("run_id", run_id);
    }
    let _ = kwargs.set_item("persist", false);
    let Ok(coro) = func.call((project, kind, body), Some(&kwargs)) else { return };
    let Some(loop_) = current_loop(py) else {
        let _ = coro.call_method0("close");
        return;
    };
    if let Ok(asyncio) = py.import("asyncio") {
        let _ = asyncio.call_method1("run_coroutine_threadsafe", (coro, loop_.bind(py)));
    }
}

fn consult(py: Python<'_>, project: &str, turn: i64, summary: &str, run_id: &str) -> PyResult<String> {
    let module = py.import("atkbrain.engine.supervise")?;
    let func = module.getattr("consult_after_turn")?;
    let coro = func.call1((project, turn, summary, run_id))?;
    let Some(loop_) = current_loop(py) else { return Ok(String::new()) };
    let asyncio = py.import("asyncio")?;
    let future = asyncio.call_method1("run_coroutine_threadsafe", (coro, loop_.bind(py)))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let done: bool = future.call_method0("done")?.extract()?;
        if done {
            let out = future.call_method0("result")?;
            if out.is_none() {
                return Ok(String::new());
            }
            return Ok(out.str()?.to_string_lossy().into_owned());
        }
        if std::time::Instant::now() >= deadline {
            return Ok(String::new());
        }
        py.allow_threads(|| std::thread::sleep(Duration::from_millis(40)));
    }
}

#[pyclass]
struct SemView {
    #[pyo3(get)]
    limit: i64,
}

#[pyclass]
struct HuntCtx {
    project_id: String,
    #[pyo3(get)]
    cmd_inflight: i64,
}

#[pymethods]
impl HuntCtx {
    #[getter]
    fn goal_reached(&self) -> bool {
        false
    }

    #[setter]
    fn set_goal_reached(&self, value: bool) {
        if value {
            manager().request_goal(&self.project_id);
        }
    }
}

#[pyclass]
struct HuntAgent {
    project_id: String,
}

#[pymethods]
impl HuntAgent {
    #[getter]
    fn ctx(&self, py: Python<'_>) -> PyResult<Py<HuntCtx>> {
        Py::new(py, HuntCtx { project_id: self.project_id.clone(), cmd_inflight: 0 })
    }

    #[pyo3(signature = (halt=true))]
    fn interrupt(&self, py: Python<'_>, halt: bool) {
        let _ = py;
        if halt {
            manager().stop(&self.project_id);
        } else {
            manager().request_goal(&self.project_id);
        }
    }
}

#[pyclass]
struct HuntHandle {
    project_id: String,
    run_id: String,
}

#[pymethods]
impl HuntHandle {
    #[getter]
    fn run_id(&self) -> Option<String> {
        if self.run_id.is_empty() { None } else { Some(self.run_id.clone()) }
    }

    #[getter]
    fn agent(&self, py: Python<'_>) -> PyResult<Py<HuntAgent>> {
        Py::new(py, HuntAgent { project_id: self.project_id.clone() })
    }
}

#[pyclass]
struct HuntManager;

#[pymethods]
impl HuntManager {
    #[pyo3(signature = (project_id, *, hard_restart=false))]
    fn start(&self, py: Python<'_>, project_id: &str, hard_restart: bool) -> PyResult<Py<HuntHandle>> {
        remember_loop(py);
        let _ = py.allow_threads(|| manager().start(project_id, hard_restart));
        self.get(py, project_id)?.ok_or_else(|| PyRuntimeError::new_err("未能开始"))
    }

    fn stop(&self, py: Python<'_>, project_id: &str) -> bool {
        remember_loop(py);
        py.allow_threads(|| manager().stop(project_id))
    }

    #[pyo3(signature = (project_id, *, reason="user_stop"))]
    fn halt(&self, py: Python<'_>, project_id: &str, reason: &str) -> bool {
        remember_loop(py);
        py.allow_threads(|| manager().halt(project_id, reason))
    }

    fn is_running(&self, py: Python<'_>, project_id: &str) -> bool {
        remember_loop(py);
        manager().is_running(project_id)
    }

    fn is_queued(&self, py: Python<'_>, project_id: &str) -> bool {
        remember_loop(py);
        manager().is_queued(project_id)
    }

    #[pyo3(signature = (project_id, message, intent_id=None))]
    fn steer(&self, py: Python<'_>, project_id: &str, message: &str, intent_id: Option<&str>) -> bool {
        remember_loop(py);
        manager().steer(project_id, message, intent_id)
    }

    fn has_pending_human(&self, project_id: &str) -> bool {
        manager().has_pending_human(project_id)
    }

    fn snapshot(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        remember_loop(py);
        Ok(to_py(py, &manager().snapshot())?.unbind())
    }

    #[pyo3(signature = (value, *, track="redteam"))]
    fn set_concurrency(&self, py: Python<'_>, value: i64, track: &str) -> i64 {
        remember_loop(py);
        manager().set_concurrency(value, track)
    }

    fn set_claude_per_project(&self, value: i64) -> i64 {
        manager().set_pi_per_project(value)
    }

    #[pyo3(signature = (timeout=8.0))]
    fn checkpoint_for_shutdown(&self, py: Python<'_>, timeout: f64) {
        remember_loop(py);
        manager().set_shutting_down(true);
        py.allow_threads(|| manager().checkpoint_for_shutdown(Duration::from_secs_f64(timeout.max(0.5))));
    }

    #[setter]
    fn set_shutting_down(&self, value: bool) {
        manager().set_shutting_down(value);
    }

    fn get(&self, py: Python<'_>, project_id: &str) -> PyResult<Option<Py<HuntHandle>>> {
        if manager().run_id_of(project_id).is_empty() && !manager().is_running(project_id) && !manager().is_queued(project_id) {
            return Ok(None);
        }
        Ok(Some(Py::new(py, HuntHandle {
            project_id: project_id.to_string(),
            run_id: manager().run_id_of(project_id),
        })?))
    }

    #[getter]
    fn redteam_sem(&self, py: Python<'_>) -> PyResult<Py<SemView>> {
        Py::new(py, SemView { limit: manager().redteam_limit() })
    }

    #[getter]
    fn ctf_sem(&self, py: Python<'_>) -> PyResult<Py<SemView>> {
        Py::new(py, SemView { limit: manager().ctf_limit() })
    }

    fn start_saved_hunts(&self, py: Python<'_>, db_running: Vec<String>) -> Vec<String> {
        remember_loop(py);
        py.allow_threads(|| engine::start_saved_hunts(manager(), &db_running))
    }

    fn resume_queued(&self, py: Python<'_>) -> usize {
        remember_loop(py);
        py.allow_threads(|| engine::resume_queued(manager()))
    }
}

#[pyfunction]
fn run_review_job(py: Python<'_>, project: &Bound<'_, PyAny>, finding: &Bound<'_, PyAny>, mode: &str, job_id: &str) -> PyResult<()> {
    remember_loop(py);
    let project: Value = serde_json::from_str(&py.import("json")?.call_method1("dumps", (project,))?.extract::<String>()?).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let finding: Value = serde_json::from_str(&py.import("json")?.call_method1("dumps", (finding,))?.extract::<String>()?).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    py.allow_threads(|| engine::run_review_job(manager(), &project, &finding, mode, job_id)).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
fn running_peers_same_entry(project_id: &str, host: &str) -> PyResult<Vec<String>> {
    engine::running_peers_same_entry(manager().db(), project_id, host).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (project=None, graph=None))]
fn build_brief(py: Python<'_>, project: Option<&Bound<'_, PyAny>>, graph: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    let load = |obj: Option<&Bound<'_, PyAny>>| -> PyResult<Value> {
        let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(Value::Null) };
        let text: String = py.import("json")?.call_method1("dumps", (obj,))?.extract()?;
        serde_json::from_str(&text).map_err(|e| PyRuntimeError::new_err(e.to_string()))
    };
    let project = load(project)?;
    let graph = load(graph)?;
    let empty = serde_json::json!({});
    let project_ref = if project.is_null() { &empty } else { &project };
    let graph_ref = if graph.is_null() { None } else { Some(&graph) };
    Ok(engine::build_brief(project_ref, graph_ref))
}

#[pyfunction]
fn hunt_slot_kind(py: Python<'_>, project: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    let value = match project {
        Some(obj) if !obj.is_none() => {
            let text: String = py.import("json")?.call_method1("dumps", (obj,))?.extract()?;
            serde_json::from_str::<Value>(&text).unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    Ok(engine::hunt_slot_kind(if value.is_null() { None } else { Some(&value) }, None))
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<HuntManager>()?;
    m.add_class::<HuntHandle>()?;
    m.add_class::<HuntAgent>()?;
    m.add_class::<HuntCtx>()?;
    m.add_class::<SemView>()?;
    m.add("hunt_manager", Py::new(m.py(), HuntManager)?)?;
    m.add_function(wrap_pyfunction!(run_review_job, m)?)?;
    m.add_function(wrap_pyfunction!(hunt_slot_kind, m)?)?;
    m.add_function(wrap_pyfunction!(build_brief, m)?)?;
    m.add_function(wrap_pyfunction!(running_peers_same_entry, m)?)?;
    m.add_function(wrap_pyfunction!(gate_intent, m)?)?;
    m.add_function(wrap_pyfunction!(maybe_confirm_command, m)?)?;
    m.add_function(wrap_pyfunction!(decide_command, m)?)?;
    m.add_function(wrap_pyfunction!(cancel_project_status, m)?)?;
    Ok(())
}

fn string_list(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<String>> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(Vec::new()) };
    if let Ok(iter) = obj.try_iter() {
        let mut out = Vec::new();
        for item in iter {
            let item = item?;
            if item.is_none() { continue; }
            let text = item.str()?.to_string_lossy().into_owned();
            if !text.trim().is_empty() { out.push(text); }
        }
        return Ok(out);
    }
    Ok(vec![obj.str()?.to_string_lossy().into_owned()])
}

#[pyfunction]
#[pyo3(signature = (project_id, intent_closed=false, hop_id="", bound_ids=None, role=""))]
fn gate_intent(py: Python<'_>, project_id: &str, intent_closed: bool, hop_id: &str, bound_ids: Option<&Bound<'_, PyAny>>, role: &str) -> PyResult<Option<String>> {
    remember_loop(py);
    let bound = string_list(bound_ids)?;
    py.allow_threads(|| engine::gate_intent(manager().db(), project_id, intent_closed, hop_id, &bound, role)).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (project_id, command, needs, hop_id="", bound_ids=None))]
fn maybe_confirm_command(py: Python<'_>, project_id: &str, command: &str, needs: bool, hop_id: &str, bound_ids: Option<&Bound<'_, PyAny>>) -> PyResult<Option<String>> {
    remember_loop(py);
    let bound = string_list(bound_ids)?;
    let intent = engine::bound_intent_id(hop_id, &bound);
    py.allow_threads(|| engine::maybe_confirm_command(manager().db(), project_id, &intent, command, needs)).map_err(PyRuntimeError::new_err)
}

#[pyfunction]
#[pyo3(signature = (confirm_id, *, allow, reason=""))]
fn decide_command(confirm_id: &str, allow: bool, reason: &str) {
    engine::decide_command(confirm_id, allow, reason);
}

#[pyfunction]
#[pyo3(signature = (*, user_stop, handle_status, slot_held))]
fn cancel_project_status(user_stop: bool, handle_status: &str, slot_held: bool) -> Option<&'static str> {
    engine::cancel_project_status(user_stop, handle_status, slot_held)
}
