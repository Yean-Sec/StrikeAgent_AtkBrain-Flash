//! Pi 运行时的 Python 入口。设置读当前进程里的 `atkbrain.config.settings`。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use atkbrain_core::config::Settings;
use atkbrain_core::pi::{self, PiSession};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use serde_json::Value;

fn lossy(value: &std::ffi::OsStr) -> String {
    value.to_string_lossy().into_owned()
}

fn live_settings(py: Python<'_>) -> Settings {
    let env: HashMap<String, String> = std::env::vars_os()
        .map(|(key, value)| (lossy(&key), lossy(&value)))
        .collect();
    let mut settings = Settings::from_map(&env, Path::new("."));
    let Ok(module) = py.import("atkbrain.config") else { return settings };
    let Ok(src) = module.getattr("settings") else { return settings };
    if let Some(path) = attr_string(&src, "data_dir") {
        if !path.is_empty() {
            settings.data_dir = PathBuf::from(path);
        }
    }
    if let Some(text) = attr_string(&src, "pi_model") {
        settings.pi_model = text;
    }
    if let Some(text) = attr_string(&src, "claude_model") {
        settings.claude_model = text;
    }
    if let Some(text) = attr_string(&src, "pi_bin") {
        settings.pi_bin = text;
    }
    if let Some(text) = attr_string(&src, "pi_provider") {
        settings.pi_provider = text;
    }
    if let Some(text) = attr_string(&src, "api_token") {
        settings.api_token = text;
    }
    if let Some(n) = attr_i64(&src, "port") {
        settings.port = n as u16;
    }
    if let Some(n) = attr_i64(&src, "pi_max_live") {
        settings.pi_max_live = n;
    }
    if let Some(n) = attr_i64(&src, "pi_max_live_cap") {
        settings.pi_max_live_cap = n;
    }
    if let Some(n) = attr_i64(&src, "pi_per_project") {
        settings.pi_per_project = n;
    }
    if let Some(n) = attr_i64(&src, "pi_per_project_cap") {
        settings.pi_per_project_cap = n;
    }
    if let Some(n) = attr_i64(&src, "claude_per_project") {
        settings.claude_per_project = n;
    }
    if let Some(n) = attr_i64(&src, "claude_per_project_cap") {
        settings.claude_per_project_cap = n;
    }
    settings
}

fn attr_string(obj: &Bound<'_, PyAny>, name: &str) -> Option<String> {
    let value = obj.getattr(name).ok()?;
    if value.is_none() {
        return None;
    }
    Some(value.str().ok()?.to_string_lossy().into_owned())
}

fn attr_i64(obj: &Bound<'_, PyAny>, name: &str) -> Option<i64> {
    let value = obj.getattr(name).ok()?;
    if value.is_none() {
        return None;
    }
    value.extract::<i64>().ok()
}

fn to_py<'py>(py: Python<'py>, value: &impl serde::Serialize) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    py.import("json")?.call_method1("loads", (text,))
}

fn val(message: String) -> PyErr {
    PyValueError::new_err(message)
}

fn discard(py: Python<'_>, err: PyErr) {
    let _ = err.value(py);
}

fn capture_loop(py: Python<'_>) -> Option<Py<PyAny>> {
    let Ok(asyncio) = py.import("asyncio") else { return None };
    match asyncio.call_method0("get_running_loop") {
        Ok(loop_) => Some(loop_.unbind()),
        Err(err) => {
            discard(py, err);
            None
        }
    }
}

fn schedule_emit(
    py: Python<'_>,
    func: &Py<PyAny>,
    loop_obj: &Option<Py<PyAny>>,
    project: &str,
    kind: &str,
    payload: &Value,
    run_id: Option<&str>,
) -> PyResult<()> {
    let body = to_py(py, payload)?;
    let run = match run_id {
        Some(text) if !text.is_empty() => text.to_object(py),
        _ => py.None(),
    };
    let kwargs = PyDict::new(py);
    kwargs.set_item("run_id", run)?;
    let coro = func.bind(py).call((project, kind, body), Some(&kwargs))?;
    if coro.hasattr("__await__")? {
        if let Some(loop_) = loop_obj {
            let _ = py.import("asyncio")?.call_method1("run_coroutine_threadsafe", (coro, loop_.bind(py)))?;
        }
    }
    Ok(())
}

#[pyclass(name = "PiSession")]
struct PyPiSession {
    inner: PiSession,
    emit: Option<Py<PyAny>>,
    loop_obj: Option<Py<PyAny>>,
    on_activity: Option<Py<PyAny>>,
}

#[pymethods]
impl PyPiSession {
    #[new]
    #[pyo3(signature = (*, cwd, system_prompt="", project_id="", role="lead", tools=true, emit=None, run_id=None, on_activity=None, model=""))]
    fn new(
        py: Python<'_>,
        cwd: &str,
        system_prompt: &str,
        project_id: &str,
        role: &str,
        tools: bool,
        emit: Option<&Bound<'_, PyAny>>,
        run_id: Option<&str>,
        on_activity: Option<&Bound<'_, PyAny>>,
        model: &str,
    ) -> PyResult<Self> {
        let inner = PiSession::new(cwd, system_prompt, project_id, role, tools, model);
        if let Some(run_id) = run_id {
            inner.set_run_id(run_id);
        }
        let mut sess = Self {
            inner,
            emit: None,
            loop_obj: capture_loop(py),
            on_activity: None,
        };
        sess.install_emit(py, emit)?;
        sess.install_activity(py, on_activity)?;
        Ok(sess)
    }

    fn command_line(&self, py: Python<'_>) -> Vec<String> {
        self.inner.command_line(&live_settings(py))
    }

    fn alive(&self) -> bool {
        self.inner.alive()
    }

    #[getter]
    fn pid(&self) -> i64 {
        self.inner.pid().unwrap_or(0) as i64
    }

    #[getter]
    fn tool_uses(&self) -> u64 {
        self.inner.tool_uses()
    }

    #[getter]
    fn idle_turns(&self) -> u64 {
        self.inner.idle_turns()
    }

    #[setter]
    fn set_idle_turns(&self, n: u64) {
        self.inner.set_idle_turns(n);
    }

    #[getter]
    fn run_id(&self) -> String {
        self.inner.run_id()
    }

    #[setter]
    fn set_run_id(&self, run_id: &str) {
        self.inner.set_run_id(run_id);
    }

    #[getter]
    fn review_job_id(&self) -> String {
        self.inner.review_job_id()
    }

    #[setter]
    fn set_review_job_id(&self, job_id: &str) {
        self.inner.set_review_job(job_id);
    }

    #[setter]
    fn set_emit(&mut self, py: Python<'_>, emit: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        self.install_emit(py, emit)
    }

    #[setter]
    fn set_on_activity(&mut self, py: Python<'_>, hook: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        self.install_activity(py, hook)
    }

    #[getter]
    fn texts(&self, py: Python<'_>) -> PyResult<Py<PyList>> {
        Ok(PyList::new(py, self.inner.texts())?.unbind())
    }

    fn is_settled(&self) -> bool {
        self.inner.is_settled()
    }

    fn on_event(&self, py: Python<'_>, event: &Bound<'_, PyAny>) -> PyResult<()> {
        let text: String = py.import("json")?.call_method1("dumps", (event,))?.extract()?;
        let value: Value = serde_json::from_str(&text).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        self.inner.on_event(&value);
        Ok(())
    }

    fn start(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(found) = capture_loop(py) {
            self.loop_obj = Some(found);
        }
        self.install_emit(py, None)?;
        let settings = live_settings(py);
        py.allow_threads(|| self.inner.start(&settings)).map_err(PyRuntimeError::new_err)
    }

    #[pyo3(signature = (message, timeout=0.0))]
    fn prompt(&self, py: Python<'_>, message: &str, timeout: f64) -> PyResult<String> {
        let limit = if timeout <= 0.0 { Duration::from_secs(3600) } else { Duration::from_secs_f64(timeout) };
        py.allow_threads(|| self.inner.prompt(message, limit, Duration::ZERO)).map_err(PyRuntimeError::new_err)
    }

    fn close(&self, py: Python<'_>) {
        py.allow_threads(|| self.inner.close());
    }
}

impl PyPiSession {
    fn install_emit(&mut self, py: Python<'_>, emit: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        if let Some(emit) = emit.filter(|item| !item.is_none()) {
            self.emit = Some(emit.clone().unbind());
        }
        let Some(func) = self.emit.as_ref().map(|item| item.clone_ref(py)) else {
            return Ok(());
        };
        let loop_obj = self.loop_obj.as_ref().map(|item| item.clone_ref(py));
        let hook = Arc::new(move |project: &str, kind: &str, payload: &Value, run_id: Option<&str>| {
            Python::with_gil(|py| {
                if let Err(err) = schedule_emit(py, &func, &loop_obj, project, kind, payload, run_id) {
                    discard(py, err);
                }
            });
        });
        self.inner.set_emit(hook);
        Ok(())
    }

    fn install_activity(&mut self, py: Python<'_>, hook: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        if let Some(hook) = hook.filter(|item| !item.is_none()) {
            self.on_activity = Some(hook.clone().unbind());
        }
        let Some(func) = self.on_activity.as_ref().map(|item| item.clone_ref(py)) else {
            self.inner.set_activity_hook(None);
            return Ok(());
        };
        let _ = py;
        self.inner.set_activity_hook(Some(Arc::new(move || {
            Python::with_gil(|py| {
                if let Err(err) = func.bind(py).call0() {
                    discard(py, err);
                }
            });
        })));
        Ok(())
    }
}

#[pyfunction]
fn pi_max_live_limit(py: Python<'_>) -> i64 {
    pi::pi_max_live_limit(&live_settings(py))
}

#[pyfunction]
fn pi_per_project_limit(py: Python<'_>) -> i64 {
    pi::pi_per_project_limit(&live_settings(py))
}

#[pyfunction]
#[pyo3(signature = (roles, *, per_project=None))]
fn cap_hunt_workers(py: Python<'_>, roles: Vec<String>, per_project: Option<i64>) -> Vec<String> {
    let refs: Vec<&str> = roles.iter().map(String::as_str).collect();
    pi::cap_hunt_workers(&live_settings(py), &refs, per_project)
}

#[pyfunction]
fn live_pi_count() -> i64 {
    pi::live_pi_count()
}

#[pyfunction]
#[pyo3(signature = (project_id, *, hunt_only=false))]
fn live_pi_for_project(project_id: &str, hunt_only: bool) -> i64 {
    pi::live_pi_for_project(project_id, hunt_only)
}

#[pyfunction]
#[pyo3(signature = (project_id, *, keep_roles=None))]
fn kill_live_for_project(project_id: &str, keep_roles: Option<&Bound<'_, PyAny>>) -> PyResult<i32> {
    let mut owned = Vec::new();
    if let Some(keep) = keep_roles.filter(|item| !item.is_none()) {
        for item in keep.try_iter()? {
            owned.push(item?.str()?.to_string_lossy().into_owned());
        }
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    Ok(pi::kill_live_for_project(project_id, &refs))
}

#[pyfunction]
fn extension_path() -> String {
    pi::extension_path().display().to_string()
}

#[pyfunction]
fn tools_base_url(py: Python<'_>) -> PyResult<String> {
    let settings = live_settings(py);
    let mut prefix = String::new();
    if let Ok(module) = py.import("atkbrain.auth.entry") {
        if let Ok(func) = module.getattr("entry_prefix") {
            match func.call0() {
                Ok(value) if !value.is_none() => {
                    prefix = value.str()?.to_string_lossy().into_owned();
                }
                Ok(_) => {}
                Err(err) => discard(py, err),
            }
        }
    }
    if prefix.is_empty() {
        prefix = atkbrain_core::console_auth::entry_prefix(&settings).unwrap_or_default();
    }
    if !prefix.is_empty() && !prefix.starts_with('/') {
        prefix = format!("/{prefix}");
    }
    Ok(format!("http://127.0.0.1:{}{prefix}", settings.port))
}

#[pyfunction]
fn pi_bin(py: Python<'_>) -> String {
    pi::pi_bin(&live_settings(py))
}

#[pyfunction]
fn pi_runtime_status(py: Python<'_>) -> PyResult<Py<PyAny>> {
    Ok(to_py(py, &pi::pi_runtime_status(&live_settings(py)))?.unbind())
}

#[pyfunction]
fn pi_models_text(py: Python<'_>) -> String {
    pi::pi_models_text(&live_settings(py))
}

#[pyfunction]
fn save_pi_models_text(py: Python<'_>, text: &str) -> PyResult<Py<PyAny>> {
    let data = pi::save_pi_models_text(&live_settings(py), text).map_err(val)?;
    Ok(to_py(py, &data)?.unbind())
}

#[pyfunction]
fn load_pi_models(py: Python<'_>) -> PyResult<Py<PyAny>> {
    Ok(to_py(py, &pi::load_pi_models(&live_settings(py)))?.unbind())
}

#[pyfunction]
fn llm_api_key(py: Python<'_>) -> String {
    pi::llm_api_key(&live_settings(py))
}

#[pyfunction]
fn llm_api_key_configured(py: Python<'_>) -> bool {
    pi::llm_api_key_configured(&live_settings(py))
}

#[pyfunction]
fn llm_key_missing_message() -> String {
    pi::llm_key_missing_message()
}

#[pyfunction]
fn usable_api_key(raw: &str) -> String {
    pi::usable_api_key(raw)
}

#[pyfunction]
fn llm_profile(py: Python<'_>) -> PyResult<Py<PyAny>> {
    Ok(to_py(py, &pi::llm_profile(&live_settings(py)))?.unbind())
}

#[pyfunction]
#[pyo3(signature = (model, base_url, api_key, fmt=""))]
fn save_llm_profile(py: Python<'_>, model: &str, base_url: &str, api_key: &str, fmt: &str) -> PyResult<Py<PyAny>> {
    let view = pi::save_llm_profile(&live_settings(py), model, base_url, api_key, fmt).map_err(val)?;
    Ok(to_py(py, &view)?.unbind())
}

#[pyfunction]
fn llm_probe_url(fmt: &str, base_url: &str) -> String {
    pi::llm_probe_url(fmt, base_url)
}

#[pyfunction]
#[pyo3(signature = (model, base_url, api_key, fmt=""))]
fn probe_llm(py: Python<'_>, model: &str, base_url: &str, api_key: &str, fmt: &str) -> PyResult<Py<PyAny>> {
    let settings = live_settings(py);
    let view = py.allow_threads(move || pi::probe_llm(&settings, model, base_url, api_key, fmt));
    Ok(to_py(py, &view)?.unbind())
}

#[pyfunction]
fn pi_model(py: Python<'_>) -> String {
    pi::pi_model(&live_settings(py))
}

#[pyfunction]
fn env_pi_model(py: Python<'_>) -> String {
    let settings = live_settings(py);
    let pi_name = settings.pi_model.trim();
    let claude = settings.claude_model.trim();
    let builtin = "deepseek-flash";
    if !pi_name.is_empty() && pi_name != builtin {
        return pi_name.to_string();
    }
    if !claude.is_empty() && claude != builtin {
        return claude.to_string();
    }
    if !pi_name.is_empty() {
        pi_name.to_string()
    } else if !claude.is_empty() {
        claude.to_string()
    } else {
        builtin.to_string()
    }
}

#[pyfunction]
fn console_model(py: Python<'_>) -> String {
    pi::console_model(&live_settings(py))
}

#[pyfunction]
fn project_model(py: Python<'_>, explicit: Option<&str>) -> String {
    pi::project_model(&live_settings(py), explicit.unwrap_or(""))
}

#[pyfunction]
#[pyo3(signature = (*candidates))]
fn role_model(py: Python<'_>, candidates: &Bound<'_, PyTuple>) -> PyResult<String> {
    let mut owned = Vec::new();
    for item in candidates.iter() {
        if item.is_none() {
            owned.push(String::new());
        } else {
            owned.push(item.str()?.to_string_lossy().into_owned());
        }
    }
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    Ok(pi::role_model(&live_settings(py), &refs))
}

#[pyfunction]
#[pyo3(signature = (*, hosted=None))]
fn ensure_pi_agent_dir(py: Python<'_>, hosted: Option<bool>) -> PyResult<String> {
    let path = pi::ensure_pi_agent_dir(&live_settings(py), hosted).map_err(PyRuntimeError::new_err)?;
    Ok(path.display().to_string())
}

#[pyfunction]
#[pyo3(signature = (system_prompt, user_prompt, cwd=None, timeout=90.0, tools=false, model=None, role="oneshot", project_id=""))]
fn query_text(
    py: Python<'_>,
    system_prompt: &str,
    user_prompt: &str,
    cwd: Option<&str>,
    timeout: f64,
    tools: bool,
    model: Option<&str>,
    role: &str,
    project_id: &str,
) -> PyResult<String> {
    let settings = live_settings(py);
    let cwd = cwd.unwrap_or("").to_string();
    let model = model.unwrap_or("").to_string();
    let role = role.to_string();
    let project_id = project_id.to_string();
    let system_prompt = system_prompt.to_string();
    let user_prompt = user_prompt.to_string();
    let limit = Duration::from_secs_f64(timeout.max(1.0));
    py.allow_threads(move || {
        pi::query_text(&settings, &system_prompt, &user_prompt, &cwd, limit, tools, &model, &role, &project_id, None)
    })
    .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
fn is_backend_cmd(cmd: &[u8]) -> bool {
    pi::is_backend_cmd(cmd)
}

#[pyfunction]
fn is_protected_cmd(cmd: &[u8]) -> bool {
    pi::is_protected_cmd(cmd)
}

#[pyfunction]
#[pyo3(signature = (hook=None))]
fn set_llm_http_hook(py: Python<'_>, hook: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
    let Some(hook) = hook.filter(|item| !item.is_none()) else {
        pi::set_probe_hook(None);
        return Ok(());
    };
    let func: Py<PyAny> = hook.clone().unbind();
    pi::set_probe_hook(Some(Arc::new(move |url, headers, body| {
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            for (key, value) in headers {
                dict.set_item(key, value).map_err(|err| err.to_string())?;
            }
            let out = func.bind(py).call1((url, dict, body)).map_err(|err| err.to_string())?;
            let status: u16 = out.get_item(0).map_err(|err| err.to_string())?.extract().map_err(|err: PyErr| err.to_string())?;
            let text: String = out.get_item(1).map_err(|err| err.to_string())?.extract().map_err(|err: PyErr| err.to_string())?;
            Ok((status, text))
        })
    })));
    Ok(())
}

#[pyfunction]
fn is_retryable_connect_error(text: &str) -> bool {
    pi::is_retryable_connect_error(text)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyPiSession>()?;
    m.add_function(wrap_pyfunction!(pi_max_live_limit, m)?)?;
    m.add_function(wrap_pyfunction!(pi_per_project_limit, m)?)?;
    m.add_function(wrap_pyfunction!(cap_hunt_workers, m)?)?;
    m.add_function(wrap_pyfunction!(live_pi_count, m)?)?;
    m.add_function(wrap_pyfunction!(live_pi_for_project, m)?)?;
    m.add_function(wrap_pyfunction!(kill_live_for_project, m)?)?;
    m.add_function(wrap_pyfunction!(extension_path, m)?)?;
    m.add_function(wrap_pyfunction!(tools_base_url, m)?)?;
    m.add_function(wrap_pyfunction!(pi_bin, m)?)?;
    m.add_function(wrap_pyfunction!(pi_runtime_status, m)?)?;
    m.add_function(wrap_pyfunction!(pi_models_text, m)?)?;
    m.add_function(wrap_pyfunction!(save_pi_models_text, m)?)?;
    m.add_function(wrap_pyfunction!(load_pi_models, m)?)?;
    m.add_function(wrap_pyfunction!(llm_api_key, m)?)?;
    m.add_function(wrap_pyfunction!(llm_api_key_configured, m)?)?;
    m.add_function(wrap_pyfunction!(llm_key_missing_message, m)?)?;
    m.add_function(wrap_pyfunction!(usable_api_key, m)?)?;
    m.add_function(wrap_pyfunction!(llm_profile, m)?)?;
    m.add_function(wrap_pyfunction!(save_llm_profile, m)?)?;
    m.add_function(wrap_pyfunction!(llm_probe_url, m)?)?;
    m.add_function(wrap_pyfunction!(probe_llm, m)?)?;
    m.add_function(wrap_pyfunction!(pi_model, m)?)?;
    m.add_function(wrap_pyfunction!(env_pi_model, m)?)?;
    m.add_function(wrap_pyfunction!(console_model, m)?)?;
    m.add_function(wrap_pyfunction!(project_model, m)?)?;
    m.add_function(wrap_pyfunction!(role_model, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_pi_agent_dir, m)?)?;
    m.add_function(wrap_pyfunction!(query_text, m)?)?;
    m.add_function(wrap_pyfunction!(is_backend_cmd, m)?)?;
    m.add_function(wrap_pyfunction!(is_protected_cmd, m)?)?;
    m.add_function(wrap_pyfunction!(set_llm_http_hook, m)?)?;
    m.add_function(wrap_pyfunction!(is_retryable_connect_error, m)?)?;
    Ok(())
}
