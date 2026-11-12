//! 过门判定的 Python 入口。

use atkbrain_core::hop;
use pyo3::prelude::*;
use pyo3::types::PyDict;

fn text_of(obj: Option<&Bound<'_, PyAny>>) -> String {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return String::new() };
    obj.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn opt_i64(obj: Option<&Bound<'_, PyAny>>) -> Option<i64> {
    let obj = obj.filter(|v| !v.is_none())?;
    if let Ok(n) = obj.extract::<i64>() { return Some(n); }
    obj.extract::<f64>().ok().map(|n| n as i64)
}

fn string_list(obj: Option<&Bound<'_, PyAny>>) -> Vec<String> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(iter) = obj.try_iter() else { return Vec::new() };
    iter.flatten().filter(|v| !v.is_none()).filter_map(|v| v.str().ok().map(|s| s.to_string_lossy().into_owned())).collect()
}

fn strategy_of(intent: Option<&Bound<'_, PyAny>>) -> String {
    let Some(intent) = intent.filter(|v| !v.is_none()) else { return String::new() };
    let Ok(value) = intent.get_item("strategy_key") else { return String::new() };
    if value.is_none() { return String::new() }
    value.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

#[pyfunction]
fn sshpass_password_from_cmd(command: Option<&str>) -> Option<String> {
    hop::sshpass_password_from_cmd(command.unwrap_or(""))
}

#[pyfunction]
#[pyo3(signature = (workspace_dir, host, port=None, output=""))]
fn remember_ssh_banner(workspace_dir: &str, host: &str, port: Option<&Bound<'_, PyAny>>, output: &str) -> bool {
    hop::remember_ssh_banner(workspace_dir, host, opt_i64(port), output)
}

#[pyfunction]
#[pyo3(signature = (command, stderr, stdout=""))]
fn command_timeout_note(command: &str, stderr: &str, stdout: &str) -> String {
    hop::command_timeout_note(command, stderr, stdout)
}

#[pyfunction]
#[pyo3(signature = (method, data=None, body=None, status=None))]
fn http_login_notes(method: &str, data: Option<&str>, body: Option<&str>, status: Option<&Bound<'_, PyAny>>) -> String {
    hop::http_login_notes(method, data.unwrap_or(""), body.unwrap_or(""), opt_i64(status))
}

#[pyfunction]
#[pyo3(signature = (workspace_dir, *, method, data=None, url="", hop_host=""))]
fn maybe_record_http_delivery(workspace_dir: &str, method: &str, data: Option<&str>, url: &str, hop_host: &str) -> bool {
    let blob = format!("{url} {}", data.unwrap_or(""));
    let hosts = crate::intranet::intra_private_hosts(&blob, 8);
    hop::maybe_record_http_delivery(workspace_dir, method, data.unwrap_or(""), url, hop_host, &hosts)
}

#[pyfunction]
#[pyo3(signature = (workspace_dir, command, *, host, port=None, allowed_secrets=None))]
fn maybe_record_ssh_delivery(
    workspace_dir: &str,
    command: &str,
    host: &str,
    port: Option<&Bound<'_, PyAny>>,
    allowed_secrets: Option<&Bound<'_, PyAny>>,
) -> bool {
    hop::maybe_record_ssh_delivery(workspace_dir, command, host, opt_i64(port), &string_list(allowed_secrets))
}

#[pyfunction]
#[pyo3(signature = (*, situation, workspace_dir="", hop_host="", allowed_secrets=None))]
fn hop_auth_followup_note(
    situation: bool,
    workspace_dir: &str,
    hop_host: &str,
    allowed_secrets: Option<&Bound<'_, PyAny>>,
) -> String {
    hop::hop_auth_followup_note(situation, workspace_dir, hop_host, &string_list(allowed_secrets))
}

#[pyfunction]
#[pyo3(signature = (intent=None, *, verified=false, summary=None, fingerprint=None, graph=None))]
fn refuse_hop_auth_disprove(
    py: Python<'_>,
    intent: Option<&Bound<'_, PyAny>>,
    verified: bool,
    summary: Option<&Bound<'_, PyAny>>,
    fingerprint: Option<&Bound<'_, PyAny>>,
    graph: Option<&Bound<'_, PyAny>>,
) -> PyResult<Option<String>> {
    let (present, has) = match graph.filter(|g| !g.is_none()) {
        Some(graph) => {
            let dict = graph.downcast::<PyDict>().ok();
            (true, crate::reach::has_verified_precondition(py, dict))
        }
        None => (false, false),
    };
    Ok(hop::refuse_hop_auth_disprove(
        &strategy_of(intent),
        verified,
        &text_of(summary),
        &text_of(fingerprint),
        present,
        has,
    ).map(|s| s.to_string()))
}

#[pyfunction]
fn apply_kali_direct_reason(py: Python<'_>, host: &str, guard: &Bound<'_, PyAny>) -> Option<String> {
    let scope = guard.getattr("scope").ok();
    let scope_ref = scope.as_ref().filter(|v| !v.is_none());
    let primary = scope_ref.and_then(|scope| scope.getattr("targets").ok()).map(|targets| {
        targets.try_iter().ok().and_then(|mut it| it.next()).and_then(|v| v.ok()).map(|v| v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()).unwrap_or_default()
    }).unwrap_or_default();
    let primary = primary.split(':').next().unwrap_or("").to_string();
    let own = guard.getattr("own_addrs").ok();
    let via = guard.getattr("via_capability_hosts").ok();
    let has = guard.getattr("has_intranet_precondition").ok().and_then(|v| v.extract::<bool>().ok()).unwrap_or(false);
    crate::reach::kali_direct_intranet_reason(
        py,
        host,
        &primary,
        own.as_ref(),
        scope_ref,
        has,
        via.as_ref(),
    )
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sshpass_password_from_cmd, m)?)?;
    m.add_function(wrap_pyfunction!(remember_ssh_banner, m)?)?;
    m.add_function(wrap_pyfunction!(command_timeout_note, m)?)?;
    m.add_function(wrap_pyfunction!(http_login_notes, m)?)?;
    m.add_function(wrap_pyfunction!(maybe_record_http_delivery, m)?)?;
    m.add_function(wrap_pyfunction!(maybe_record_ssh_delivery, m)?)?;
    m.add_function(wrap_pyfunction!(hop_auth_followup_note, m)?)?;
    m.add_function(wrap_pyfunction!(refuse_hop_auth_disprove, m)?)?;
    m.add_function(wrap_pyfunction!(apply_kali_direct_reason, m)?)?;
    Ok(())
}
