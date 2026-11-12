//! 猎面钟判断与设置钳制。不读写配置文件。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeSet;

const RESET: &[&str] = &[
    "runtime_cap",
    "turn_cap",
    "empty_rounds",
    "graph_idle",
    "goal_reached",
    "entry_dead",
    "env_closed",
    "env_unreachable",
    "runtime_review_stop",
];

const CLOCK_KEYS: &[&str] = &[
    "loop_max_turns",
    "loop_max_turns_agent",
    "loop_max_turns_src",
    "loop_max_turns_redteam",
    "agent_runtime_hard_stop_sec",
    "src_runtime_hard_stop_sec",
    "redteam_runtime_hard_stop_sec",
    "runtime_hard_stop_sec",
    "runtime_hard_stop_pass2_sec",
    "runtime_hard_stop_pass3_sec",
    "runtime_hard_stop_pass_step_sec",
    "graph_idle_empty_plans",
    "loop_stall_limit_agent",
    "loop_stall_limit_redteam",
    "loop_stall_limit_src",
];

fn py_str(v: &Bound<PyAny>) -> String {
    if v.is_none() {
        return String::new();
    }
    v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn as_i64(v: &Bound<PyAny>, default: i64) -> i64 {
    if v.is_none() {
        return default;
    }
    if let Ok(b) = v.extract::<bool>() {
        return if b { 1 } else { 0 };
    }
    if let Ok(i) = v.extract::<i64>() {
        return i;
    }
    if let Ok(f) = v.extract::<f64>() {
        if f.is_finite() {
            return f as i64;
        }
        return default;
    }
    let s = py_str(v);
    if s.is_empty() {
        return default;
    }
    s.parse::<i64>().unwrap_or(default)
}

fn as_f64(v: &Bound<PyAny>, default: f64) -> f64 {
    if v.is_none() {
        return default;
    }
    if let Ok(b) = v.extract::<bool>() {
        return if b { 1.0 } else { 0.0 };
    }
    if let Ok(i) = v.extract::<i64>() {
        return i as f64;
    }
    if let Ok(f) = v.extract::<f64>() {
        if f.is_finite() {
            return f;
        }
        return default;
    }
    let s = py_str(v);
    if s.is_empty() {
        return default;
    }
    s.parse::<f64>().unwrap_or(default)
}

fn put_hunt(py: Python<'_>, turn: i64, elapsed: f64, reviewed: Option<f64>, idle: f64, plans: i64, empty: i64) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    d.set_item("turn", turn.max(0))?;
    d.set_item("elapsed_sec", elapsed.max(0.0))?;
    if let Some(v) = reviewed {
        d.set_item("reviewed_elapsed_sec", v.max(0.0))?;
    } else {
        d.set_item("reviewed_elapsed_sec", py.None())?;
    }
    d.set_item("idle_sec", idle.max(0.0))?;
    d.set_item("idle_plans", plans.max(0))?;
    d.set_item("empty_rounds", empty.max(0))?;
    Ok(d.unbind())
}

fn hunt_from(py: Python<'_>, raw: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    let base_turn = 0i64;
    let mut elapsed = 0.0;
    let mut reviewed: Option<f64> = None;
    let mut idle = 0.0;
    let mut plans = 0i64;
    let mut empty = 0i64;
    let mut turn = base_turn;
    if let Some(raw) = raw {
        if let Ok(Some(v)) = raw.get_item("turn") {
            turn = as_i64(&v, 0).max(0);
        }
        if let Ok(Some(v)) = raw.get_item("elapsed_sec") {
            elapsed = as_f64(&v, 0.0).max(0.0);
        }
        if let Ok(Some(v)) = raw.get_item("reviewed_elapsed_sec") {
            if !v.is_none() {
                reviewed = Some(as_f64(&v, 0.0).max(0.0));
            }
        }
        if let Ok(Some(v)) = raw.get_item("idle_sec") {
            idle = as_f64(&v, 0.0).max(0.0);
        }
        if let Ok(Some(v)) = raw.get_item("idle_plans") {
            plans = as_i64(&v, 0).max(0);
        }
        if let Ok(Some(v)) = raw.get_item("empty_rounds") {
            empty = as_i64(&v, 0).max(0);
        }
    }
    put_hunt(py, turn, elapsed, reviewed, idle, plans, empty)
}

#[pyfunction]
pub fn clocks_hunt_should_reset(hard_restart: bool, completion_reason: Option<&str>, has_live_foothold: bool) -> bool {
    if hard_restart {
        return true;
    }
    let reason = completion_reason.unwrap_or("");
    if reason == "entry_dead" && has_live_foothold {
        return false;
    }
    RESET.contains(&reason)
}

#[pyfunction]
pub fn clocks_parse_hunt(py: Python<'_>, cfg: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    let hunt = cfg.and_then(|c| c.get_item("hunt").ok().flatten());
    if let Some(v) = hunt {
        if let Ok(d) = v.downcast::<PyDict>() {
            return hunt_from(py, Some(d));
        }
    }
    hunt_from(py, None)
}

#[pyfunction]
pub fn clocks_reconstruct_hunt(
    py: Python<'_>,
    last_run: Option<&Bound<PyDict>>,
    last_turn: i64,
    now_ts: f64,
) -> PyResult<Py<PyDict>> {
    let run_turns = last_run
        .and_then(|r| r.get_item("turns").ok().flatten())
        .map(|v| as_i64(&v, 0))
        .unwrap_or(0);
    let turn = run_turns.max(last_turn).max(0);
    if last_run.is_none() {
        return put_hunt(py, turn, 0.0, None, 0.0, 0, 0);
    }
    let run = last_run.unwrap();
    let started = run
        .get_item("started_at")
        .ok()
        .flatten()
        .map(|v| as_f64(&v, 0.0))
        .unwrap_or(0.0);
    let ended = match run.get_item("ended_at").ok().flatten() {
        Some(v) if !v.is_none() => as_f64(&v, now_ts),
        _ => now_ts,
    };
    let elapsed = if started > 0.0 && ended >= started { ended - started } else { 0.0 };
    put_hunt(py, turn, elapsed, None, 0.0, 0, 0)
}

#[pyfunction]
pub fn clocks_fill_hunt(py: Python<'_>, hunt: Option<&Bound<PyDict>>, reconstructed: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    let h = hunt_from(py, hunt)?;
    let r = hunt_from(py, reconstructed)?;
    let hb = h.bind(py);
    let rb = r.bind(py);
    let cur_turn = as_i64(&hb.get_item("turn")?.unwrap(), 0);
    let recon_turn = as_i64(&rb.get_item("turn")?.unwrap(), 0);
    let cur_el = as_f64(&hb.get_item("elapsed_sec")?.unwrap(), 0.0);
    let recon_el = as_f64(&rb.get_item("elapsed_sec")?.unwrap(), 0.0);
    let turn = if cur_turn <= 0 && recon_turn > 0 { recon_turn } else { cur_turn };
    let elapsed = if cur_turn <= 0 { cur_el.max(recon_el).max(0.0) } else { cur_el };
    let reviewed = hb.get_item("reviewed_elapsed_sec")?.filter(|v| !v.is_none()).map(|v| as_f64(&v, 0.0));
    let idle = as_f64(&hb.get_item("idle_sec")?.unwrap(), 0.0);
    let plans = as_i64(&hb.get_item("idle_plans")?.unwrap(), 0);
    let empty = as_i64(&hb.get_item("empty_rounds")?.unwrap(), 0);
    put_hunt(py, turn, elapsed, reviewed, idle, plans, empty)
}

#[pyfunction]
pub fn clocks_resume_completed_turn(persisted_turn: i64, supervised: Option<&Bound<PyList>>) -> i64 {
    let t = persisted_turn.max(0);
    let mut have = BTreeSet::new();
    if let Some(list) = supervised {
        for x in list.iter() {
            let n = as_i64(&x, 0);
            if n > 0 {
                have.insert(n);
            }
        }
    }
    if t <= 0 {
        return have.iter().next_back().copied().unwrap_or(0);
    }
    if !have.contains(&t) {
        return t - 1;
    }
    t
}

#[pyfunction]
pub fn clocks_should_reset_graph_idle(node_grew: bool, new_flag_event: bool, local_progress: bool) -> bool {
    node_grew || new_flag_event || local_progress
}

#[pyfunction]
pub fn clocks_elapsed_meets_min(elapsed_sec: f64, min_sec: f64) -> bool {
    if min_sec <= 0.0 {
        return true;
    }
    elapsed_sec >= min_sec
}

#[pyfunction]
pub fn clocks_api_key_missing(text: &str, tool_uses: i64) -> bool {
    if tool_uses > 0 {
        return false;
    }
    let t = text.trim().to_ascii_lowercase();
    if t.is_empty() || t.len() >= 400 {
        return false;
    }
    if t.contains("deepseek_api_key") {
        return true;
    }
    if t.contains("api key") || t.contains("apikey") {
        return ["missing", "not set", "not configured", "invalid", "unauthorized"]
            .iter()
            .any(|x| t.contains(x));
    }
    false
}

#[pyfunction]
pub fn clocks_end_hunt_fault(elapsed_sec: f64, min_hunt_sec: f64, goal_reached: bool, env_closed: bool) -> bool {
    if goal_reached || env_closed {
        return true;
    }
    clocks_elapsed_meets_min(elapsed_sec, min_hunt_sec)
}

#[pyfunction]
pub fn clocks_end_empty_streak(
    empty_streak: i64,
    elapsed_sec: f64,
    min_hunt_sec: f64,
    goal_reached: bool,
    env_closed: bool,
    streak_limit: i64,
) -> bool {
    let mut limit = if streak_limit <= 0 { 5 } else { streak_limit };
    if limit <= 0 {
        limit = 5;
    }
    if empty_streak < limit {
        return false;
    }
    if goal_reached || env_closed {
        return true;
    }
    clocks_elapsed_meets_min(elapsed_sec, min_hunt_sec)
}

#[pyfunction]
pub fn clocks_env_probe(
    probe: &str,
    tcp_ok: bool,
    marked: bool,
    closed_hits: i64,
    confirm_need: i64,
) -> (Option<String>, i64) {
    let p = probe.trim().to_ascii_lowercase();
    let mut hits = closed_hits.max(0);
    let need = if confirm_need < 2 { 2 } else { confirm_need };
    if p == "ok" {
        return (None, 0);
    }
    if p == "closed" {
        hits += 1;
        if marked {
            return (Some("env_closed".into()), hits);
        }
        if tcp_ok {
            return (None, hits);
        }
        if hits >= need {
            return (Some("env_closed".into()), hits);
        }
        return (None, hits);
    }
    if p == "unreachable" {
        if marked && !tcp_ok {
            return (Some("env_unreachable".into()), hits);
        }
        return (None, hits);
    }
    (None, hits)
}

#[pyfunction]
pub fn clocks_mark_parent_closed(halt_env: Option<&str>) -> bool {
    halt_env.unwrap_or("").trim() == "env_closed"
}

#[pyfunction]
pub fn clocks_autopilot_action(marked_closed: bool, probe: &str) -> String {
    if !marked_closed {
        return "continue".into();
    }
    if probe.trim() == "ok" {
        "resume".into()
    } else {
        "drain".into()
    }
}

#[pyfunction]
pub fn clocks_parent_keep_alive(status: Option<&str>, env_closed: bool, has_unfinished: bool) -> Option<String> {
    if env_closed || !has_unfinished {
        return None;
    }
    let st = status.unwrap_or("").trim().to_ascii_lowercase();
    if st == "completed" || st == "error" {
        Some("idle".into())
    } else {
        None
    }
}

#[pyfunction]
pub fn clocks_watchdog(running: i64, started: i64, remaining_fresh: i64, prev_ticks: i64, trip_after: i64) -> (i64, bool) {
    if remaining_fresh > 0 && running <= 0 && started <= 0 {
        let ticks = prev_ticks + 1;
        return (ticks, trip_after > 0 && ticks >= trip_after);
    }
    (0, false)
}

#[pyfunction]
pub fn clocks_session_hang(idle_for: f64, hang_sec: f64, cmd_inflight: i64) -> bool {
    if cmd_inflight > 0 || hang_sec <= 0.0 {
        return false;
    }
    idle_for >= hang_sec
}

#[pyfunction]
pub fn clocks_turn_event_idle(now_wall: f64, turn_started_wall: f64, last_event_ts: f64) -> f64 {
    if last_event_ts < turn_started_wall - 1.0 {
        return (now_wall - turn_started_wall).max(0.0);
    }
    (now_wall - last_event_ts).max(0.0)
}

#[pyfunction]
pub fn clocks_graph_idle_pause(idle_for: f64, limit: f64) -> bool {
    if limit <= 0.0 {
        return false;
    }
    idle_for >= limit
}

#[pyfunction]
pub fn clocks_graph_idle_plans(empty_plans: i64, limit: i64) -> bool {
    if limit <= 0 {
        return false;
    }
    empty_plans >= limit
}

#[pyfunction]
pub fn clocks_note_idle_plans(idle_plans: i64, pivots: i64, last_counted_pivots: i64, progressed: bool) -> (i64, i64) {
    let mut n = idle_plans.max(0);
    let p = pivots.max(0);
    let last = last_counted_pivots.max(0);
    if progressed {
        return (0, p);
    }
    if p > last {
        n += p - last;
    }
    (n, p)
}

fn clamp_wall(sec: i64) -> i64 {
    if sec < 0 { 0 } else { sec.min(72 * 60 * 60) }
}
fn clamp_turns(n: i64) -> i64 {
    if n < 0 { 0 } else { n.min(9999) }
}
fn clamp_plans(n: i64) -> i64 {
    if n <= 0 { 1 } else { n.clamp(1, 100) }
}
fn clamp_stall(n: i64) -> i64 {
    if n < 0 { 0 } else { n.min(9999) }
}

#[pyfunction]
pub fn clocks_normalize(py: Python<'_>, raw: Option<&Bound<PyDict>>, live: &Bound<PyDict>) -> PyResult<Py<PyDict>> {
    let out = PyDict::new(py);
    for key in CLOCK_KEYS {
        let live_v = live.get_item(*key)?.map(|v| as_i64(&v, 0)).unwrap_or(0);
        let val = match raw.and_then(|r| r.get_item(*key).ok().flatten()) {
            Some(v) if !v.is_none() => as_i64(&v, live_v),
            _ => live_v,
        };
        let clamped = if key.ends_with("_sec") {
            clamp_wall(val)
        } else if *key == "graph_idle_empty_plans" {
            clamp_plans(val)
        } else if key.starts_with("loop_stall") {
            clamp_stall(val)
        } else {
            clamp_turns(val)
        };
        out.set_item(*key, clamped)?;
    }
    let pick = |agent: &str, src: &str, red: &str| -> PyResult<i64> {
        let present = |k: &str| -> bool {
            raw.and_then(|r| r.get_item(k).ok().flatten()).map(|v| !v.is_none()).unwrap_or(false)
        };
        if present(agent) {
            return Ok(as_i64(&out.get_item(agent)?.unwrap(), 0));
        }
        if present(src) {
            return Ok(as_i64(&out.get_item(src)?.unwrap(), 0));
        }
        if present(red) {
            return Ok(as_i64(&out.get_item(red)?.unwrap(), 0));
        }
        Ok(as_i64(&out.get_item(agent)?.unwrap(), 0))
    };
    let wall = pick("agent_runtime_hard_stop_sec", "src_runtime_hard_stop_sec", "redteam_runtime_hard_stop_sec")?;
    let turns = pick("loop_max_turns_agent", "loop_max_turns_src", "loop_max_turns_redteam")?;
    let stall = pick("loop_stall_limit_agent", "loop_stall_limit_src", "loop_stall_limit_redteam")?;
    for k in ["agent_runtime_hard_stop_sec", "src_runtime_hard_stop_sec", "redteam_runtime_hard_stop_sec"] {
        out.set_item(k, wall)?;
    }
    for k in ["loop_max_turns_agent", "loop_max_turns_src", "loop_max_turns_redteam"] {
        out.set_item(k, turns)?;
    }
    for k in ["loop_stall_limit_agent", "loop_stall_limit_src", "loop_stall_limit_redteam"] {
        out.set_item(k, stall)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
pub fn clocks_empty(py: Python<'_>) -> PyResult<Py<PyDict>> {
    put_hunt(py, 0, 0.0, None, 0.0, 0, 0)
}

#[pyfunction]
#[pyo3(signature = (*, turn, elapsed_sec, reviewed_elapsed_sec=None, idle_sec, idle_plans=0, empty_rounds=0))]
pub fn clocks_snapshot(
    py: Python<'_>,
    turn: i64,
    elapsed_sec: f64,
    reviewed_elapsed_sec: Option<f64>,
    idle_sec: f64,
    idle_plans: i64,
    empty_rounds: i64,
) -> PyResult<Py<PyDict>> {
    put_hunt(py, turn, elapsed_sec, reviewed_elapsed_sec, idle_sec, idle_plans, empty_rounds)
}

#[pyfunction]
pub fn clocks_workspace_fresh(path: Option<&str>, since_wall: f64) -> bool {
    let root = path.unwrap_or("").trim();
    if root.is_empty() || since_wall <= 0.0 {
        return false;
    }
    let skip_dir = ["__pycache__", ".git", ".claude", ".agents", "skills", "agent-transcripts", ".pycache"];
    fn walk(dir: &std::path::Path, cutoff: f64, skip_dir: &[&str]) -> bool {
        let Ok(rd) = std::fs::read_dir(dir) else { return false };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let path = ent.path();
            if path.is_dir() {
                if skip_dir.contains(&name.as_str()) {
                    continue;
                }
                if walk(&path, cutoff, skip_dir) {
                    return true;
                }
            } else {
                if name == "shells.json" || name.ends_with(".pyc") || name.ends_with(".pyo") || name.ends_with(".log") {
                    continue;
                }
                if let Ok(meta) = ent.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                            if dur.as_secs_f64() >= cutoff {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    walk(std::path::Path::new(root), since_wall, &skip_dir)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(clocks_hunt_should_reset, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_parse_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_reconstruct_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_fill_hunt, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_resume_completed_turn, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_should_reset_graph_idle, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_elapsed_meets_min, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_api_key_missing, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_end_hunt_fault, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_end_empty_streak, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_env_probe, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_mark_parent_closed, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_autopilot_action, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_parent_keep_alive, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_watchdog, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_session_hang, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_turn_event_idle, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_graph_idle_pause, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_graph_idle_plans, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_note_idle_plans, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_normalize, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_empty, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_snapshot, m)?)?;
    m.add_function(wrap_pyfunction!(clocks_workspace_fresh, m)?)?;
    Ok(())
}
