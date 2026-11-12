//! 给还在 Python 里的调用方用的原函数名。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet, PyTuple};

fn alias(m: &Bound<PyModule>, public: &str, internal: &str) -> PyResult<()> {
    let func = m.getattr(internal)?;
    m.add(public, func)?;
    Ok(())
}

fn setting(py: Python<'_>, name: &str, default: i64) -> i64 {
    let Ok(cfg) = py.import("atkbrain.config") else { return default };
    let Ok(settings) = cfg.getattr("settings") else { return default };
    let Ok(value) = settings.getattr(name) else { return default };
    if value.is_none() {
        return default;
    }
    if let Ok(i) = value.extract::<i64>() {
        return i.max(0);
    }
    if let Ok(f) = value.extract::<f64>() {
        if f.is_finite() {
            return (f as i64).max(0);
        }
    }
    default
}

fn clocks_of(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    for key in [
        "runtime_hard_stop_sec", "runtime_hard_stop_pass2_sec", "runtime_hard_stop_pass3_sec",
        "runtime_hard_stop_pass_step_sec", "agent_runtime_hard_stop_sec", "loop_max_turns",
        "loop_max_turns_agent", "turn_hang_sec", "benchmark_entry_down_yield_sec",
        "graph_idle_empty_plans",
    ] {
        let default = match key {
            "runtime_hard_stop_sec" => 40 * 60,
            "runtime_hard_stop_pass2_sec" => 120 * 60,
            "runtime_hard_stop_pass3_sec" => 180 * 60,
            "runtime_hard_stop_pass_step_sec" => 60 * 60,
            "agent_runtime_hard_stop_sec" => 6 * 60 * 60,
            "turn_hang_sec" => 8 * 60,
            "benchmark_entry_down_yield_sec" => 8 * 60,
            "graph_idle_empty_plans" => 6,
            _ => 0,
        };
        d.set_item(key, setting(py, key, default))?;
    }
    Ok(d.unbind())
}

#[pyfunction]
#[pyo3(signature = (objective=None))]
fn uses_ctf_hunt_clocks(objective: Option<&str>) -> bool {
    crate::status::status_uses_ctf(objective)
}

#[pyfunction]
#[pyo3(signature = (pass_n=None))]
fn ctf_pass_hard_stop_sec(py: Python<'_>, pass_n: Option<i64>) -> PyResult<i64> {
    Ok(crate::status::status_ctf_pass_sec(pass_n, &clocks_of(py)?.bind(py)))
}

#[pyfunction]
#[pyo3(signature = (*, ended_real_attempts=0))]
fn ctf_pass_index(ended_real_attempts: i64) -> i64 {
    crate::status::status_ctf_pass_index(ended_real_attempts)
}

#[pyfunction]
#[pyo3(signature = (objective=None, *, pass_n=None))]
fn hunt_runtime_hard_stop_sec(py: Python<'_>, objective: Option<&str>, pass_n: Option<i64>) -> PyResult<i64> {
    Ok(crate::status::status_runtime_hard_stop(objective, pass_n, &clocks_of(py)?.bind(py)))
}

#[pyfunction]
#[pyo3(signature = (objective=None, *, is_benchmark=false))]
fn hunt_max_turns(py: Python<'_>, objective: Option<&str>, is_benchmark: bool) -> PyResult<i64> {
    let _ = is_benchmark;
    Ok(crate::status::status_max_turns(objective, &clocks_of(py)?.bind(py)))
}

#[pyfunction]
#[pyo3(signature = (sec, lang=None))]
fn format_duration(py: Python<'_>, sec: Option<f64>, lang: Option<&str>) -> PyResult<String> {
    let loc = match lang {
        Some(l) if l == "en" || l.starts_with("en") => "en",
        Some(_) => "zh",
        None => atkbrain_core::i18n::get_locale()
    };
    let value = sec.unwrap_or(0.0);
    Ok(crate::status::status_format_duration(value, loc))
}

#[pyfunction]
fn format_duration_zh(py: Python<'_>, sec: Option<f64>) -> PyResult<String> {
    format_duration(py, sec, Some("zh"))
}

#[pyfunction]
#[pyo3(signature = (db_status=None, *, running=false, queued=false))]
fn displayed_status(db_status: Option<&str>, running: bool, queued: bool) -> String {
    crate::status::status_displayed(db_status, running, queued)
}

#[pyfunction]
#[pyo3(signature = (*, goal, exhausted=false, pause_reason=None))]
fn final_project_status(goal: bool, exhausted: bool, pause_reason: Option<&str>) -> String {
    crate::status::status_final(goal, exhausted, pause_reason)
}

#[pyfunction]
#[pyo3(signature = (hunt=None, *, running=false, run_started_at=None, now_ts=None))]
fn anchor_hunt_elapsed(
    py: Python<'_>,
    hunt: Option<&Bound<PyDict>>,
    running: bool,
    run_started_at: Option<f64>,
    now_ts: Option<f64>,
) -> PyResult<Py<PyDict>> {
    let now = now_ts.unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    });
    crate::status::status_anchor_elapsed(py, hunt, running, run_started_at, now)
}

#[pyfunction]
#[pyo3(signature = (objective=None, *, pass_n=None, lang=None))]
fn hunt_hard_stop_info(
    py: Python<'_>,
    objective: Option<&str>,
    pass_n: Option<i64>,
    lang: Option<&str>,
) -> PyResult<Py<PyDict>> {
    let loc = match lang {
        Some("en") => "en",
        Some(l) if l.starts_with("en") => "en",
        Some(_) => "zh",
        None => "zh",
    };
    crate::status::status_hard_stop_info(py, objective, pass_n, loc, &clocks_of(py)?.bind(py))
}

#[pyfunction]
#[pyo3(signature = (*, hard_restart, completion_reason=None, has_live_foothold=false))]
fn hunt_should_reset(hard_restart: bool, completion_reason: Option<&str>, has_live_foothold: bool) -> bool {
    crate::clocks::clocks_hunt_should_reset(hard_restart, completion_reason, has_live_foothold)
}

#[pyfunction]
fn parse_hunt(py: Python<'_>, cfg: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    crate::clocks::clocks_parse_hunt(py, cfg)
}

#[pyfunction]
fn empty_hunt(py: Python<'_>) -> PyResult<Py<PyDict>> {
    crate::clocks::clocks_empty(py)
}

#[pyfunction]
#[pyo3(signature = (*, last_run=None, last_turn=0, now_ts))]
fn reconstruct_hunt(py: Python<'_>, last_run: Option<&Bound<PyDict>>, last_turn: i64, now_ts: f64) -> PyResult<Py<PyDict>> {
    crate::clocks::clocks_reconstruct_hunt(py, last_run, last_turn, now_ts)
}

#[pyfunction]
#[pyo3(signature = (hunt=None, *, reconstructed=None))]
fn fill_hunt_from_last_run(py: Python<'_>, hunt: Option<&Bound<PyDict>>, reconstructed: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    crate::clocks::clocks_fill_hunt(py, hunt, reconstructed)
}

#[pyfunction]
#[pyo3(signature = (*, persisted_turn, supervised_turns=None))]
fn resume_completed_turn(persisted_turn: i64, supervised_turns: Option<&Bound<PyList>>) -> i64 {
    crate::clocks::clocks_resume_completed_turn(persisted_turn, supervised_turns)
}

#[pyfunction]
#[pyo3(signature = (*, turn, elapsed_sec, reviewed_elapsed_sec=None, idle_sec, idle_plans=0, empty_rounds=0))]
fn snapshot_hunt(
    py: Python<'_>,
    turn: i64,
    elapsed_sec: f64,
    reviewed_elapsed_sec: Option<f64>,
    idle_sec: f64,
    idle_plans: i64,
    empty_rounds: i64,
) -> PyResult<Py<PyDict>> {
    crate::clocks::clocks_snapshot(py, turn, elapsed_sec, reviewed_elapsed_sec, idle_sec, idle_plans, empty_rounds)
}

#[pyfunction]
fn workspace_has_fresh_artifact(path: Option<&str>, since_wall: f64) -> bool {
    crate::clocks::clocks_workspace_fresh(path, since_wall)
}

#[pyfunction]
#[pyo3(signature = (*, probe, tcp_ok, marked=false, closed_hits=0, confirm_need=2))]
fn env_probe_halt_reason(probe: &str, tcp_ok: bool, marked: bool, closed_hits: i64, confirm_need: i64) -> (Option<String>, i64) {
    crate::clocks::clocks_env_probe(probe, tcp_ok, marked, closed_hits, confirm_need)
}

#[pyfunction]
fn should_mark_parent_env_closed(halt_env: Option<&str>) -> bool {
    crate::clocks::clocks_mark_parent_closed(halt_env)
}

#[pyfunction]
#[pyo3(signature = (*, node_grew, new_flag_event, local_progress=false))]
fn should_reset_graph_idle(node_grew: bool, new_flag_event: bool, local_progress: bool) -> bool {
    crate::clocks::clocks_should_reset_graph_idle(node_grew, new_flag_event, local_progress)
}

#[pyfunction]
#[pyo3(signature = (text, *, tool_uses=0))]
fn looks_like_api_key_missing(text: &str, tool_uses: i64) -> bool {
    crate::clocks::clocks_api_key_missing(text, tool_uses)
}

#[pyfunction]
#[pyo3(signature = (*, elapsed_sec, min_hunt_sec, goal_reached=false, env_closed=false))]
fn should_end_hunt_fault(elapsed_sec: f64, min_hunt_sec: f64, goal_reached: bool, env_closed: bool) -> bool {
    crate::clocks::clocks_end_hunt_fault(elapsed_sec, min_hunt_sec, goal_reached, env_closed)
}

#[pyfunction]
#[pyo3(signature = (*, empty_streak, elapsed_sec, min_hunt_sec, goal_reached=false, env_closed=false, streak_limit=5))]
fn should_end_empty_streak(empty_streak: i64, elapsed_sec: f64, min_hunt_sec: f64, goal_reached: bool, env_closed: bool, streak_limit: i64) -> bool {
    crate::clocks::clocks_end_empty_streak(empty_streak, elapsed_sec, min_hunt_sec, goal_reached, env_closed, streak_limit)
}

#[pyfunction]
fn graph_idle_pause_due(idle_for: f64, limit: f64) -> bool {
    crate::clocks::clocks_graph_idle_pause(idle_for, limit)
}

#[pyfunction]
fn graph_idle_plans_due(empty_plans: i64, limit: i64) -> bool {
    crate::clocks::clocks_graph_idle_plans(empty_plans, limit)
}

#[pyfunction]
#[pyo3(signature = (*, idle_plans, pivots, last_counted_pivots, progressed))]
fn note_graph_idle_plans(idle_plans: i64, pivots: i64, last_counted_pivots: i64, progressed: bool) -> (i64, i64) {
    crate::clocks::clocks_note_idle_plans(idle_plans, pivots, last_counted_pivots, progressed)
}

#[pyfunction]
#[pyo3(signature = (*, idle_for, hang_sec, cmd_inflight=0))]
fn session_hang_due(idle_for: f64, hang_sec: f64, cmd_inflight: i64) -> bool {
    crate::clocks::clocks_session_hang(idle_for, hang_sec, cmd_inflight)
}

#[pyfunction]
#[pyo3(signature = (*, now_wall, turn_started_wall, last_event_ts=None))]
fn turn_event_idle_sec(now_wall: f64, turn_started_wall: f64, last_event_ts: Option<f64>) -> f64 {
    crate::clocks::clocks_turn_event_idle(now_wall, turn_started_wall, last_event_ts.unwrap_or(0.0))
}

#[pyclass]
struct CvssBase {
    #[pyo3(get)]
    vector: String,
    #[pyo3(get)]
    score: f64,
    #[pyo3(get)]
    rating: String,
    #[pyo3(get)]
    band_zh: String,
}

#[pyfunction]
fn base_score(py: Python<'_>, metrics: &Bound<PyDict>) -> PyResult<Py<CvssBase>> {
    let raw = crate::cvss::cvss_base_score(py, metrics)?;
    let d = raw.bind(py);
    Py::new(py, CvssBase {
        vector: d.get_item("vector")?.unwrap().extract()?,
        score: d.get_item("score")?.unwrap().extract()?,
        rating: d.get_item("rating")?.unwrap().extract()?,
        band_zh: d.get_item("band_zh")?.unwrap().extract()?,
    })
}

#[pyfunction]
fn roundup(raw: &Bound<PyAny>) -> PyResult<String> {
    let text = if let Ok(s) = raw.extract::<String>() { s } else { raw.str()?.to_string_lossy().into_owned() };
    crate::cvss::cvss_roundup(&text)
}

#[pyfunction]
fn qualitative(raw: &Bound<PyAny>) -> PyResult<String> {
    let text = if let Ok(s) = raw.extract::<String>() { s } else { raw.str()?.to_string_lossy().into_owned() };
    crate::cvss::cvss_qualitative(&text)
}

#[pyfunction]
fn band_zh(raw: &Bound<PyAny>) -> PyResult<String> {
    let text = if let Ok(s) = raw.extract::<String>() { s } else { raw.str()?.to_string_lossy().into_owned() };
    crate::cvss::cvss_band_zh(&text)
}

#[pyfunction]
#[pyo3(signature = (password))]
fn password_policy_code(password: &str) -> Option<&'static str> {
    crate::auth::auth_password_policy_code(Some(password))
}

#[pyfunction]
fn password_policy_error(password: &str) -> Option<&'static str> {
    crate::auth::auth_password_policy_error(Some(password))
}

#[pyfunction]
#[pyo3(signature = (n=8))]
fn generate_bootstrap_password(n: i64) -> String {
    crate::auth::auth_bootstrap_password(n)
}

#[pyfunction]
#[pyo3(signature = (*, flags_correct=0, flags_needed=None, flag_count=None, flags_score=0.0, total_score=None))]
fn ctf_full_score(flags_correct: i64, flags_needed: Option<i64>, flag_count: Option<i64>, flags_score: f64, total_score: Option<f64>) -> bool {
    let _ = (flags_score, total_score);
    crate::objective::objective_ctf_full_score(flags_correct, flags_needed, flag_count)
}

#[pyfunction]
#[pyo3(signature = (*, flags_needed=None, flag_count=None))]
fn ctf_needed_flags(flags_needed: Option<i64>, flag_count: Option<i64>) -> i64 {
    crate::objective::objective_ctf_needed(flags_needed, flag_count)
}

#[pyfunction]
#[pyo3(signature = (obj, *, flags_correct=0, flags_needed=None, flag_count=None, flags_score=0.0, total_score=None, achievements=None))]
fn is_run_complete(
    obj: Option<&str>,
    flags_correct: i64,
    flags_needed: Option<i64>,
    flag_count: Option<i64>,
    flags_score: f64,
    total_score: Option<f64>,
    achievements: Option<&Bound<PyAny>>,
) -> bool {
    let _ = (flags_score, total_score);
    crate::objective::objective_run_complete(obj, flags_correct, flags_needed, flag_count, achievements)
}

#[pyfunction]
#[pyo3(signature = (obj, *, flags_correct=0, achievements=None, verified_high=0, verified_critical=0, untested_types=None))]
fn hard_stop_exempt(
    obj: Option<&str>,
    flags_correct: i64,
    achievements: Option<&Bound<PyAny>>,
    verified_high: i64,
    verified_critical: i64,
    untested_types: Option<i64>,
) -> bool {
    let _ = achievements;
    crate::objective::objective_hard_stop_exempt(obj, flags_correct, verified_high, verified_critical, untested_types)
}

#[pyfunction]
#[pyo3(signature = (*, category=None, title=None, description=None, evidence=None))]
fn src_is_non_vuln_finding(category: Option<&str>, title: Option<&str>, description: Option<&str>, evidence: Option<&str>) -> bool {
    let _ = (description, evidence);
    crate::objective::objective_non_vuln(category, title)
}

#[pyfunction]
#[pyo3(signature = (category, *, title=None, description=None, evidence=None))]
fn src_should_skip_finding(category: Option<&str>, title: Option<&str>, description: Option<&str>, evidence: Option<&str>) -> bool {
    let _ = (description, evidence);
    crate::objective::objective_skip_finding(category, title)
}

#[pyfunction]
#[pyo3(signature = (obj=None, *, severity=None, verification_status="verified", category=None, title=None, description=None, evidence=None, proof_type=None, proof_canary=None, proof_url=None, proof_detail=None))]
fn user_visible_finding(
    obj: Option<&str>,
    severity: Option<&str>,
    verification_status: Option<&str>,
    category: Option<&str>,
    title: Option<&str>,
    description: Option<&str>,
    evidence: Option<&str>,
    proof_type: Option<&str>,
    proof_canary: Option<&str>,
    proof_url: Option<&str>,
    proof_detail: Option<&str>,
) -> bool {
    let _ = (obj, severity, category, title, description, evidence, proof_type, proof_canary, proof_url, proof_detail);
    crate::objective::objective_user_visible(verification_status)
}

#[pyfunction]
fn finding_row_visible(obj: Option<&str>, row: &Bound<PyAny>) -> bool {
    let _ = obj;
    let status = row_get(row, "verification_status");
    let status = status.trim();
    crate::objective::objective_user_visible(if status.is_empty() { None } else { Some(status) })
}

fn row_get(row: &Bound<PyAny>, key: &str) -> String {
    if let Ok(d) = row.downcast::<PyDict>() {
        return d.get_item(key).ok().flatten().and_then(|v| if v.is_none() { None } else { v.extract::<String>().ok().or_else(|| v.str().ok().map(|s| s.to_string_lossy().into_owned())) }).unwrap_or_default();
    }
    if let Ok(v) = row.call_method1("get", (key,)) {
        if !v.is_none() {
            if let Ok(s) = v.extract::<String>() { return s; }
            if let Ok(s) = v.str() { return s.to_string_lossy().into_owned(); }
        }
    }
    String::new()
}

#[pyfunction]
fn forbidden_project_target_reason(host: &str) -> Option<String> {
    crate::scope::scope_forbidden_target(host, crate::osnet::attacker_hosts(&[]))
}

#[pyfunction]
#[pyo3(signature = (*texts))]
fn public_hosts_in_text(texts: &Bound<PyTuple>) -> PyResult<Vec<String>> {
    let mut parts = Vec::new();
    for item in texts.iter() {
        parts.push(item.str()?.to_string_lossy().into_owned());
    }
    Ok(crate::scope::scope_public_hosts(parts))
}

#[pyfunction]
#[pyo3(signature = (text, *, limit=8))]
fn private_hosts_from_text(text: &str, limit: i64) -> Vec<String> {
    crate::intranet::intra_private_hosts(text, limit)
}

#[pyfunction]
#[pyo3(signature = (*, url="", data="", command="", output=""))]
fn hosts_from_capability_observation(url: &str, data: &str, command: &str, output: &str) -> Vec<String> {
    crate::intranet::intra_capability_hosts(url, data, command, output)
}

#[pyfunction]
#[pyo3(signature = (*, command="", output=""))]
fn clue_hosts_from_observation(command: &str, output: &str) -> Vec<String> {
    crate::intranet::intra_clue_hosts(command, output)
}

#[pyfunction]
#[pyo3(signature = (secondary_verified, rating=None, rationale=None, status=None))]
fn secondary_review_error(secondary_verified: bool, rating: Option<&str>, rationale: Option<&str>, status: Option<&str>) -> Option<String> {
    crate::findings::findings_secondary_error(secondary_verified, rating, rationale, status)
}

#[pyfunction]
#[pyo3(signature = (severity, node_type="info", is_rce=false, category=None))]
fn compute_risk_score(severity: &str, node_type: &str, is_rce: bool, category: Option<&str>) -> f64 {
    crate::findings::findings_risk_score(severity, node_type, is_rce, category)
}

#[pyfunction]
#[pyo3(signature = (*parts))]
fn execution_impact_proven(parts: &Bound<PyTuple>) -> PyResult<bool> {
    let mut texts = Vec::new();
    for item in parts.iter() {
        texts.push(if item.is_none() { String::new() } else { item.str()?.to_string_lossy().into_owned() });
    }
    Ok(crate::findings::findings_execution_proven(texts))
}

#[pyfunction]
#[pyo3(signature = (*parts, category=""))]
fn claims_rce(parts: &Bound<PyTuple>, category: &str) -> PyResult<bool> {
    let mut texts = Vec::new();
    for item in parts.iter() {
        texts.push(if item.is_none() { String::new() } else { item.str()?.to_string_lossy().into_owned() });
    }
    Ok(crate::findings::findings_claims_rce(texts, category))
}

#[pyfunction]
#[pyo3(signature = (*, category=None, severity=None, redteam_rating=None, title="", description="", evidence="", poc_curl="", poc_python=""))]
fn coerce_unproven_rce_claim(
    category: Option<&str>,
    severity: Option<&str>,
    redteam_rating: Option<&str>,
    title: &str,
    description: &str,
    evidence: &str,
    poc_curl: &str,
    poc_python: &str,
) -> (String, String, Option<String>) {
    crate::findings::findings_coerce_rce(category, severity, redteam_rating, title, description, evidence, poc_curl, poc_python)
}

#[pyfunction]
#[pyo3(signature = (row=None, **kwargs))]
fn src_impact_proven(row: Option<&Bound<PyAny>>, kwargs: Option<&Bound<PyDict>>) -> bool {
    if let Some(row) = row {
        return crate::objective::objective_impact_proven(Some(row));
    }
    if let Some(kwargs) = kwargs {
        return crate::objective::objective_impact_proven(Some(kwargs.as_any()));
    }
    false
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<CvssBase>()?;
    m.add_function(wrap_pyfunction!(base_score, m)?)?;
    m.add_function(wrap_pyfunction!(roundup, m)?)?;
    m.add_function(wrap_pyfunction!(qualitative, m)?)?;
    m.add_function(wrap_pyfunction!(band_zh, m)?)?;
    alias(m, "parse_vector", "cvss_parse_vector")?;
    alias(m, "normalize_metrics", "cvss_normalize_metrics")?;
    alias(m, "metrics_from_args", "cvss_metrics_from_args")?;
    alias(m, "nvd_reject_reason", "cvss_nvd_reject_reason")?;
    alias(m, "attach_vector", "cvss_attach_vector")?;
    m.add_function(wrap_pyfunction!(password_policy_code, m)?)?;
    m.add_function(wrap_pyfunction!(password_policy_error, m)?)?;
    m.add_function(wrap_pyfunction!(generate_bootstrap_password, m)?)?;
    m.add_function(wrap_pyfunction!(uses_ctf_hunt_clocks, m)?)?;
    m.add_function(wrap_pyfunction!(ctf_pass_hard_stop_sec, m)?)?;
    m.add_function(wrap_pyfunction!(ctf_pass_index, m)?)?;
    m.add_function(wrap_pyfunction!(hunt_runtime_hard_stop_sec, m)?)?;
    m.add_function(wrap_pyfunction!(hunt_max_turns, m)?)?;
    m.add_function(wrap_pyfunction!(format_duration, m)?)?;
    m.add_function(wrap_pyfunction!(format_duration_zh, m)?)?;
    m.add_function(wrap_pyfunction!(displayed_status, m)?)?;
    m.add_function(wrap_pyfunction!(final_project_status, m)?)?;
    m.add_function(wrap_pyfunction!(anchor_hunt_elapsed, m)?)?;
    m.add_function(wrap_pyfunction!(hunt_hard_stop_info, m)?)?;
    m.add_function(wrap_pyfunction!(hunt_should_reset, m)?)?;
    m.add_function(wrap_pyfunction!(parse_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(empty_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(reconstruct_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(fill_hunt_from_last_run, m)?)?;
    m.add_function(wrap_pyfunction!(resume_completed_turn, m)?)?;
    m.add_function(wrap_pyfunction!(snapshot_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(workspace_has_fresh_artifact, m)?)?;
    m.add_function(wrap_pyfunction!(env_probe_halt_reason, m)?)?;
    m.add_function(wrap_pyfunction!(should_mark_parent_env_closed, m)?)?;
    m.add_function(wrap_pyfunction!(should_reset_graph_idle, m)?)?;
    m.add_function(wrap_pyfunction!(looks_like_api_key_missing, m)?)?;
    m.add_function(wrap_pyfunction!(should_end_hunt_fault, m)?)?;
    m.add_function(wrap_pyfunction!(should_end_empty_streak, m)?)?;
    m.add_function(wrap_pyfunction!(graph_idle_pause_due, m)?)?;
    m.add_function(wrap_pyfunction!(graph_idle_plans_due, m)?)?;
    m.add_function(wrap_pyfunction!(note_graph_idle_plans, m)?)?;
    m.add_function(wrap_pyfunction!(session_hang_due, m)?)?;
    m.add_function(wrap_pyfunction!(turn_event_idle_sec, m)?)?;
    m.add_function(wrap_pyfunction!(ctf_full_score, m)?)?;
    m.add_function(wrap_pyfunction!(ctf_needed_flags, m)?)?;
    m.add_function(wrap_pyfunction!(is_run_complete, m)?)?;
    m.add_function(wrap_pyfunction!(hard_stop_exempt, m)?)?;
    m.add_function(wrap_pyfunction!(src_is_non_vuln_finding, m)?)?;
    m.add_function(wrap_pyfunction!(src_should_skip_finding, m)?)?;
    m.add_function(wrap_pyfunction!(user_visible_finding, m)?)?;
    m.add_function(wrap_pyfunction!(finding_row_visible, m)?)?;
    alias(m, "normalize_objective", "objective_normalize")?;
    alias(m, "objective_allows_flag", "objective_allows_flag")?;
    alias(m, "objective_is_agent", "objective_is_agent")?;
    alias(m, "objective_is_src", "objective_is_src")?;
    alias(m, "cfg_is_lab_src", "objective_cfg_is_lab_src")?;
    alias(m, "canon_goal", "objective_canon_goal")?;
    alias(m, "redteam_ultimate_reached", "objective_redteam_reached")?;
    alias(m, "redteam_new_ultimate", "objective_redteam_new")?;
    alias(m, "src_should_skip_category", "objective_skip_category")?;
    alias(m, "awarded_sum", "objective_awarded_sum")?;
    alias(m, "normalize_severity", "findings_normalize_severity")?;
    alias(m, "normalize_redteam_rating", "findings_normalize_rating")?;
    alias(m, "display_finding_severity", "findings_display_severity")?;
    alias(m, "is_critical", "findings_is_critical")?;
    alias(m, "scrub_candidate_rce_label", "findings_scrub_label")?;
    alias(m, "finding_review_need", "findings_review_need")?;
    alias(m, "is_non_exploit_finding_category", "verify_non_exploit")?;
    alias(m, "is_high_severity", "verify_is_high")?;
    alias(m, "merge_verification_status", "verify_merge_status")?;
    alias(m, "is_real_secondary_failure", "verify_real_secondary_failure")?;
    alias(m, "rating_left_verification_alone", "verify_rating_left_alone")?;
    alias(m, "secondary_claim_failed", "verify_secondary_failed")?;
    alias(m, "recheck_did_not_run", "verify_recheck_skipped")?;
    alias(m, "_norm_host", "scope_norm")?;
    alias(m, "is_loopback", "scope_is_loopback")?;
    alias(m, "is_private", "scope_is_private")?;
    alias(m, "is_private_ip", "scope_is_private_ip")?;
    alias(m, "is_single_label", "scope_is_single_label")?;
    alias(m, "is_internal_tld", "scope_is_internal_tld")?;
    alias(m, "registrable_domain", "scope_registrable")?;
    alias(m, "canonical_host", "scope_canonical")?;
    alias(m, "sensitive_domain_reason", "scope_sensitive_domain")?;
    alias(m, "sensitive_attack_reason", "scope_sensitive_attack")?;
    alias(m, "private_out_of_scope_hint", "scope_private_hint")?;
    alias(m, "public_out_of_scope_hint", "scope_public_hint")?;
    alias(m, "is_oob_or_infra_host", "scope_oob")?;
    alias(m, "extract_hosts", "guard_extract_hosts")?;
    alias(m, "extract_host_ports", "guard_extract_host_ports")?;
    alias(m, "target_destructive_reason", "guard_destructive")?;
    alias(m, "mega_wordlist_reason", "guard_mega_wordlist")?;
    alias(m, "ctf_mega_dict_reason", "guard_ctf_mega")?;
    alias(m, "is_ssrf_canary_host", "intra_is_canary")?;
    alias(m, "ssrf_evidence_is_oracle_only", "intra_oracle_only")?;
    alias(m, "looks_like_live_observation", "intra_live_observation")?;
    alias(m, "is_broadcast_or_net", "intra_broadcast")?;
    alias(m, "is_hosts_file_command", "intra_hosts_file_cmd")?;
    alias(m, "should_absorb_from_command", "intra_should_absorb_cmd")?;
    alias(m, "node_is_live_intranet", "intra_node_live")?;
    alias(m, "node_is_capability_intranet", "intra_node_capability")?;
    alias(m, "hop_auth_eligible", "intra_hop_eligible")?;
    alias(m, "intent_private_hosts", "intra_intent_hosts")?;
    alias(m, "hash_password", "auth_hash_password")?;
    alias(m, "verify_password", "auth_verify_password")?;
    alias(m, "local_self_hosts", "local_self_hosts_py")?;
    alias(m, "enumerate_local_ipv4s", "enumerate_local_ipv4s_py")?;
    alias(m, "enumerate_local_gateways", "enumerate_local_gateways_py")?;
    alias(m, "attacker_identity_hosts", "attacker_identity_hosts_py")?;
    alias(m, "is_attacker_identity", "is_attacker_identity_py")?;
    alias(m, "on_local_docker_bridge", "on_local_docker_bridge_py")?;
    alias(m, "autopilot_env_gate_action", "clocks_autopilot_action")?;
    alias(m, "parent_keep_alive_status", "clocks_parent_keep_alive")?;
    alias(m, "note_autopilot_watchdog", "clocks_watchdog")?;
    m.add_function(wrap_pyfunction!(forbidden_project_target_reason, m)?)?;
    m.add_function(wrap_pyfunction!(public_hosts_in_text, m)?)?;
    m.add_function(wrap_pyfunction!(private_hosts_from_text, m)?)?;
    m.add_function(wrap_pyfunction!(hosts_from_capability_observation, m)?)?;
    m.add_function(wrap_pyfunction!(clue_hosts_from_observation, m)?)?;
    m.add_function(wrap_pyfunction!(secondary_review_error, m)?)?;
    m.add_function(wrap_pyfunction!(compute_risk_score, m)?)?;
    m.add_function(wrap_pyfunction!(execution_impact_proven, m)?)?;
    m.add_function(wrap_pyfunction!(claims_rce, m)?)?;
    m.add_function(wrap_pyfunction!(coerce_unproven_rce_claim, m)?)?;
    m.add_function(wrap_pyfunction!(src_impact_proven, m)?)?;
    let failed = PySet::new(m.py(), ["graph_idle", "runtime_cap", "turn_cap", "empty_rounds"])?;
    m.add("HUNT_FAILED_REASONS", failed)?;
    m.add("EMPTY_ROUND_STOP", 30)?;
    m.add("MAX_WALL_SEC", 72 * 60 * 60)?;
    m.add("FLAG", "flag")?;
    m.add("AGENT", "agent")?;
    m.add("REDTEAM", "redteam")?;
    m.add("SRC", "src")?;
    m.add("RT_ADMIN_ACCESS", "admin_access")?;
    m.add("RT_ADMIN_AND_KEY", "admin_and_key")?;
    m.add("RT_KEY_LEAK", "key_leak")?;
    m.add("RT_DATA_ACCESS", "data_access")?;
    m.add("KIND_SHELL", "shell")?;
    m.add("KIND_SSRF", "ssrf")?;
    m.add("KIND_TUNNEL", "tunnel")?;
    m.add("TAG_LIVE", "via-live")?;
    m.add("TAG_CLUE", "clue-only")?;
    let non = PySet::new(m.py(), ["availability", "dos", "crash", "error_handling", "misconfig"])?;
    m.add("NON_EXPLOIT_FINDING_CATS", non)?;
    let data = PySet::new(m.py(), ["db_access", "db_dump", "dump", "data_leak", "mass_data_leak", "mass_disclosure"])?;
    m.add("DATA_ACCESS_CATEGORIES", data)?;
    let keys = PySet::new(m.py(), [
        "source_leak", "backup_leak", "hardcoded_secret", "cloud_credential", "mass_pii",
        "sensitive_data_exposure", "credential_dump", "secrets_leak", "key_leak",
    ])?;
    m.add("KEY_LEAK_CATEGORIES", keys)?;
    let trivial = PySet::new(m.py(), [
        "info_disclosure", "information_disclosure", "info", "info_leak", "tech-stack", "tech_stack",
        "banner", "version", "phpinfo", "path_disclosure", "directory_listing",
    ])?;
    m.add("TRIVIAL_INFO_CATEGORIES", trivial)?;
    let goals = PyDict::new(m.py());
    goals.set_item("flag", ("getflag",))?;
    goals.set_item("agent", ("getshell",))?;
    goals.set_item("redteam", ("getshell",))?;
    goals.set_item("src", ("getshell",))?;
    m.add("ULTIMATE_GOALS", goals)?;
    let _ = PyList::empty(m.py());
    Ok(())
}
