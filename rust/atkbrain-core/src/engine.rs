//! 猎面调度、续跑和项目循环。
//! 进程由 `pi` 拉起。攻击步骤、扫描命令和回放提示留在 Python，这里不重写。

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::ToSql;
use serde_json::{json, Map, Value};

use crate::config::Settings;
use crate::db::{new_id, now, Db};
use crate::pi::{self, EmitFn, PiSession};
use crate::projects::{assert_safe_project_target, get_project};
use crate::review::{self, findings_pending_review};

const RESET_REASONS: &[&str] = &[
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
const HUNT_FAILED: &[&str] = &["graph_idle", "runtime_cap", "turn_cap", "empty_rounds"];
const EMPTY_ROUND_STOP: i64 = 30;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn wall_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn normalize_objective(obj: Option<&str>) -> &'static str {
    let o = obj.unwrap_or("").trim().to_ascii_lowercase();
    if o == "flag" || o == "ctf" {
        "flag"
    } else {
        "agent"
    }
}

pub fn objective_allows_flag(obj: Option<&str>) -> bool {
    normalize_objective(obj) == "flag"
}

pub fn objective_is_src(obj: Option<&str>) -> bool {
    normalize_objective(obj) == "agent"
}

pub fn objective_ctf_needed(flags_needed: Option<i64>, flag_count: Option<i64>) -> i64 {
    for v in [flags_needed, flag_count] {
        if let Some(n) = v {
            if n > 0 {
                return n;
            }
        }
    }
    1
}

pub fn objective_ctf_full_score(
    flags_correct: i64,
    flags_needed: Option<i64>,
    flag_count: Option<i64>,
) -> bool {
    flags_correct >= objective_ctf_needed(flags_needed, flag_count)
}

pub fn hunt_should_reset(
    hard_restart: bool,
    completion_reason: Option<&str>,
    has_live_foothold: bool,
) -> bool {
    if hard_restart {
        return true;
    }
    let reason = completion_reason.unwrap_or("");
    if reason == "entry_dead" && has_live_foothold {
        return false;
    }
    RESET_REASONS.contains(&reason)
}

pub fn resume_completed_turn(persisted_turn: i64, supervised: &[i64]) -> i64 {
    let t = persisted_turn.max(0);
    let mut have = BTreeSet::new();
    for n in supervised {
        if *n > 0 {
            have.insert(*n);
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

pub fn supervised_turns_from_payloads(payloads: &[Value]) -> Vec<i64> {
    let mut out = Vec::new();
    for payload in payloads {
        let turn = payload.get("turn").and_then(|v| v.as_i64()).unwrap_or(0);
        if turn > 0 && !out.contains(&turn) {
            out.push(turn);
        }
    }
    out.sort_unstable();
    out
}

pub fn turn_must_close(elapsed_sec: f64, cap_sec: f64) -> bool {
    cap_sec > 0.0 && elapsed_sec >= cap_sec
}

pub fn clocks_elapsed_meets_min(elapsed_sec: f64, min_sec: f64) -> bool {
    if min_sec <= 0.0 {
        true
    } else {
        elapsed_sec >= min_sec
    }
}

pub fn clocks_graph_idle_plans(empty_plans: i64, limit: i64) -> bool {
    limit > 0 && empty_plans >= limit
}

pub fn clocks_end_empty_streak(
    empty_streak: i64,
    elapsed_sec: f64,
    min_hunt_sec: f64,
    goal_reached: bool,
    env_closed: bool,
    streak_limit: i64,
) -> bool {
    let limit = if streak_limit <= 0 { 5 } else { streak_limit };
    if empty_streak < limit {
        return false;
    }
    if goal_reached || env_closed {
        return true;
    }
    clocks_elapsed_meets_min(elapsed_sec, min_hunt_sec)
}

pub fn should_consult_after_exec_fault(reason: &str, has_active_plan: bool) -> bool {
    if reason == "hang" {
        return false;
    }
    if reason == "empty_turn" {
        return !has_active_plan;
    }
    false
}

pub fn uses_ctf_clocks(objective: Option<&str>) -> bool {
    normalize_objective(objective) == "flag"
}

pub fn runtime_hard_stop_sec(settings: &Settings, objective: Option<&str>, pass_n: i64) -> i64 {
    if uses_ctf_clocks(objective) {
        let n = pass_n.max(1);
        if n <= 1 {
            settings.runtime_hard_stop_sec
        } else if n == 2 {
            settings.runtime_hard_stop_pass2_sec
        } else if n == 3 {
            settings.runtime_hard_stop_pass3_sec
        } else {
            settings.runtime_hard_stop_pass3_sec
                + (n - 3) * settings.runtime_hard_stop_pass_step_sec
        }
    } else {
        settings.agent_runtime_hard_stop_sec
    }
}

pub fn max_turns_for(settings: &Settings, objective: Option<&str>) -> i64 {
    if uses_ctf_clocks(objective) {
        settings.loop_max_turns
    } else {
        settings.loop_max_turns_agent
    }
}

pub fn final_project_status(
    goal: bool,
    exhausted: bool,
    pause_reason: Option<&str>,
) -> &'static str {
    if goal {
        return "completed";
    }
    let failed = matches!(
        pause_reason.unwrap_or(""),
        "graph_idle" | "runtime_cap" | "turn_cap" | "empty_rounds"
    );
    if exhausted || failed {
        "error"
    } else {
        "idle"
    }
}

pub fn cancel_project_status(
    user_stop: bool,
    handle_status: &str,
    slot_held: bool,
) -> Option<&'static str> {
    if handle_status == "zombie" {
        return None;
    }
    if user_stop || handle_status == "stopping" {
        return Some("idle");
    }
    if slot_held {
        return Some("running");
    }
    None
}

pub fn is_transient_resource_error(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    [
        "too many open files",
        "unable to open database",
        "disk i/o error",
        "database is locked",
        "cantopen",
        "emfile",
        "enfile",
    ]
    .iter()
    .any(|n| low.contains(n))
}

#[derive(Clone, Debug)]
pub struct HuntClock {
    pub turn: i64,
    pub elapsed_sec: f64,
    pub reviewed_elapsed_sec: Option<f64>,
    pub idle_sec: f64,
    pub idle_plans: i64,
    pub empty_rounds: i64,
}

impl HuntClock {
    pub fn empty() -> Self {
        Self {
            turn: 0,
            elapsed_sec: 0.0,
            reviewed_elapsed_sec: None,
            idle_sec: 0.0,
            idle_plans: 0,
            empty_rounds: 0,
        }
    }

    pub fn from_config(cfg: &Value) -> Self {
        let hunt = cfg.get("hunt").unwrap_or(&Value::Null);
        let num = |k: &str| {
            hunt.get(k)
                .and_then(|v| v.as_i64())
                .or_else(|| hunt.get(k).and_then(|v| v.as_f64()).map(|n| n as i64))
                .unwrap_or(0)
                .max(0)
        };
        let flt = |k: &str| {
            hunt.get(k)
                .and_then(|v| v.as_f64())
                .or_else(|| hunt.get(k).and_then(|v| v.as_i64()).map(|n| n as f64))
                .unwrap_or(0.0)
                .max(0.0)
        };
        let reviewed = hunt.get("reviewed_elapsed_sec").and_then(|v| {
            if v.is_null() {
                None
            } else {
                v.as_f64().or_else(|| v.as_i64().map(|n| n as f64))
            }
        });
        Self {
            turn: num("turn"),
            elapsed_sec: flt("elapsed_sec"),
            reviewed_elapsed_sec: reviewed,
            idle_sec: flt("idle_sec"),
            idle_plans: num("idle_plans"),
            empty_rounds: num("empty_rounds"),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "turn": self.turn.max(0),
            "elapsed_sec": self.elapsed_sec.max(0.0),
            "reviewed_elapsed_sec": self.reviewed_elapsed_sec,
            "idle_sec": self.idle_sec.max(0.0),
            "idle_plans": self.idle_plans.max(0),
            "empty_rounds": self.empty_rounds.max(0),
        })
    }
}

fn val_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn row_str(row: &Map<String, Value>, key: &str) -> String {
    row.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn emit(db: &Db, project_id: &str, kind: &str, payload: &Value, run_id: Option<&str>) {
    let ts = now();
    let blob = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
    let rid = run_id.map(|s| s.to_string());
    let _ = db.execute(
        "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES (?1,?2,?3,?4,?5)",
        &[
            &project_id as &dyn ToSql,
            &rid as &dyn ToSql,
            &ts,
            &kind,
            &blob,
        ],
    );
    if let Some(hook) = lock(&EMIT_HOOK).clone() {
        hook(project_id, kind, payload, run_id);
    }
}

type EmitHook = Arc<dyn Fn(&str, &str, &Value, Option<&str>) + Send + Sync>;
type ConsultHook = Arc<dyn Fn(&str, i64, &str, &str) -> String + Send + Sync>;
static EMIT_HOOK: Mutex<Option<EmitHook>> = Mutex::new(None);
static CONSULT_HOOK: Mutex<Option<ConsultHook>> = Mutex::new(None);

pub fn set_emit_hook(hook: Option<EmitHook>) {
    *lock(&EMIT_HOOK) = hook;
}

pub fn set_consult_hook(hook: Option<ConsultHook>) {
    *lock(&CONSULT_HOOK) = hook;
}

pub fn update_status(db: &Db, pid: &str, status: &str) -> Result<(), String> {
    let ts = now();
    if status == "queued" {
        db.execute(
            "UPDATE projects SET status=?1, updated_at=?2, queued_at=COALESCE(queued_at, ?3) WHERE id=?4",
            &[&status as &dyn ToSql, &ts, &ts, &pid],
        )
    } else {
        db.execute(
            "UPDATE projects SET status=?1, updated_at=?2, queued_at=NULL WHERE id=?3",
            &[&status as &dyn ToSql, &ts, &pid],
        )
    }
}

pub fn read_config(db: &Db, pid: &str) -> Value {
    let Ok(Some(row)) = db.query_one(
        "SELECT config FROM projects WHERE id=?1",
        &[&pid as &dyn ToSql],
    ) else {
        return json!({});
    };
    match row.get("config") {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(json!({})),
        Some(Value::Object(_)) => row.get("config").cloned().unwrap_or(json!({})),
        _ => json!({}),
    }
}

pub fn write_config(db: &Db, pid: &str, cfg: &Value) -> Result<(), String> {
    let blob = serde_json::to_string(cfg).unwrap_or_else(|_| "{}".into());
    let ts = now();
    db.execute(
        "UPDATE projects SET config=?1, updated_at=?2 WHERE id=?3",
        &[&blob as &dyn ToSql, &ts, &pid],
    )
}

fn create_run(db: &Db, project_id: &str) -> Result<String, String> {
    let rid = new_id("run_");
    let ts = now();
    let status = "running";
    db.execute(
        "INSERT INTO runs(id, project_id, status, started_at) VALUES (?1,?2,?3,?4)",
        &[&rid as &dyn ToSql, &project_id, &status, &ts],
    )?;
    Ok(rid)
}

fn finish_run(db: &Db, rid: &str, status: &str, goal: bool, turns: i64, summary: &str) {
    if rid.is_empty() {
        return;
    }
    let ts = now();
    let goal_i = if goal { 1 } else { 0 };
    let _ = db.execute(
        "UPDATE runs SET status=?1, goal_reached=?2, turns=?3, summary=?4, ended_at=?5 WHERE id=?6",
        &[&status as &dyn ToSql, &goal_i, &turns, &summary, &ts, &rid],
    );
}

pub fn load_supervised_turns(db: &Db, project_id: &str) -> Result<Vec<i64>, String> {
    if project_id.is_empty() {
        return Ok(Vec::new());
    }
    let rows = db.query(
        "SELECT payload FROM events WHERE project_id=?1 AND type='supervisor'",
        &[&project_id as &dyn ToSql],
    )?;
    let mut payloads = Vec::new();
    for row in rows {
        let payload = match row.get("payload") {
            Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
            Some(other) => other.clone(),
            None => Value::Null,
        };
        payloads.push(payload);
    }
    Ok(supervised_turns_from_payloads(&payloads))
}

fn graph_has_getshell(db: &Db, project_id: &str) -> bool {
    let Ok(rows) = db.query(
        "SELECT type, key, tags, is_rce FROM nodes WHERE project_id=?1",
        &[&project_id as &dyn ToSql],
    ) else {
        return false;
    };
    rows.iter().any(confirmed_control)
}

fn tagset(raw: Option<&Value>) -> HashSet<String> {
    let mut out = HashSet::new();
    let items: Vec<String> = match raw {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Some(Value::String(s)) => {
            serde_json::from_str::<Vec<String>>(s).unwrap_or_else(|_| vec![s.clone()])
        }
        _ => Vec::new(),
    };
    for item in items {
        out.insert(item.to_ascii_lowercase());
    }
    out
}

fn confirmed_control(row: &Map<String, Value>) -> bool {
    let ntype = row_str(row, "type");
    let key = row_str(row, "key");
    let tags = tagset(row.get("tags"));
    let is_rce = row.get("is_rce").and_then(|v| v.as_i64()).unwrap_or(0) != 0;
    if ntype == "goal" && (is_rce || key.starts_with("goal:shell") || tags.contains("getshell")) {
        return true;
    }
    if ntype == "foothold" {
        return is_rce || tags.contains("getshell");
    }
    false
}

fn counts(db: &Db, project_id: &str) -> (i64, i64, i64) {
    let n = |sql: &str| -> i64 {
        db.query_one(sql, &[&project_id as &dyn ToSql])
            .ok()
            .flatten()
            .and_then(|r| r.get("n").and_then(|v| v.as_i64()))
            .unwrap_or(0)
    };
    (
        n("SELECT COUNT(*) AS n FROM nodes WHERE project_id=?1"),
        n("SELECT COUNT(*) AS n FROM edges WHERE project_id=?1"),
        n("SELECT COUNT(*) AS n FROM findings WHERE project_id=?1"),
    )
}

fn previous_run(db: &Db, project_id: &str, current: &str) -> Option<Map<String, Value>> {
    db.query(
        "SELECT id, status, turns, started_at, ended_at FROM runs WHERE project_id=?1 AND id!=?2 ORDER BY started_at DESC LIMIT 1",
        &[&project_id as &dyn ToSql, &current as &dyn ToSql],
    )
    .ok()
    .and_then(|rows| rows.into_iter().next())
}

fn last_status_turn(db: &Db, project_id: &str, run_id: &str) -> i64 {
    if run_id.is_empty() {
        return 0;
    }
    let Ok(rows) = db.query(
        "SELECT payload FROM events WHERE project_id=?1 AND run_id=?2 AND type='status' ORDER BY ts DESC LIMIT 40",
        &[&project_id as &dyn ToSql, &run_id as &dyn ToSql],
    ) else {
        return 0;
    };
    let mut best = 0;
    for row in rows {
        let payload = match row.get("payload") {
            Some(Value::String(s)) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
            Some(other) => other.clone(),
            None => Value::Null,
        };
        let n = payload
            .get("turn")
            .or_else(|| payload.get("turns"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if n > best {
            best = n;
        }
    }
    best
}

fn is_benchmark_sub(project: &Value) -> bool {
    let parent = project
        .get("parent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if parent.is_empty() {
        return false;
    }
    project
        .get("config")
        .and_then(|c| c.get("benchmark"))
        .map(|v| !v.is_null())
        .unwrap_or(false)
}

fn parent_env_closed(db: &Db, settings: &Settings, project: &Value) -> bool {
    let cfg = project.get("config").cloned().unwrap_or(json!({}));
    if cfg
        .get("env_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return true;
    }
    let parent = project
        .get("parent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if parent.is_empty() {
        return false;
    }
    get_project(db, settings, parent)
        .ok()
        .flatten()
        .and_then(|p| {
            p.get("config")
                .and_then(|c| c.get("env_closed"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
}

fn gate_closed_env(db: &Db, settings: &Settings, project: &Value) -> Option<String> {
    let kind = val_str(project, "kind");
    if !(is_benchmark_sub(project) || kind == "benchmark") {
        return None;
    }
    if parent_env_closed(db, settings, project) {
        Some("评测环境已结束或平台不可达，已停止测试与验证。".into())
    } else {
        None
    }
}

fn json_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.trim().to_string(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Null) | None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().unwrap_or(0.0) != 0.0,
        Some(Value::String(text)) => !text.trim().is_empty() && text != "0",
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(obj)) => !obj.is_empty(),
    }
}

fn project_names(project: &Value) -> Vec<String> {
    let cfg = project.get("config").cloned().unwrap_or(json!({}));
    let scope = project.get("scope").cloned().unwrap_or(json!({}));
    let raw = cfg.get("vhosts").filter(|v| v.is_array()).or_else(|| scope.get("targets"));
    let mut names: Vec<String> = raw.and_then(|v| v.as_array()).map(|items| items.iter().map(|v| json_text(Some(v))).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
    let target = json_text(project.get("target"));
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if !target.is_empty() { names.insert(0, target); }
    for name in names {
        let key = name.trim_end_matches('.').to_ascii_lowercase();
        if !key.is_empty() && seen.insert(key) { out.push(name); }
    }
    out
}

fn project_ports(project: &Value) -> Vec<i64> {
    let mut out = Vec::new();
    let Some(items) = project.get("ports").and_then(|v| v.as_array()) else { return out };
    for item in items {
        let n = item.as_i64().or_else(|| item.as_f64().map(|n| n as i64)).or_else(|| item.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
        if n > 0 && !out.contains(&n) { out.push(n); }
    }
    out
}

pub fn running_peers_same_entry(db: &Db, project_id: &str, host: &str) -> Result<Vec<String>, String> {
    let host = host.trim();
    if host.is_empty() { return Ok(Vec::new()); }
    let rows = db.query(
        "SELECT id, name, target FROM projects WHERE status='running' AND id != ?1",
        &[&project_id as &dyn ToSql],
    )?;
    let mut peers = Vec::new();
    for row in rows {
        let target = row_str(&row, "target");
        let other = target.split(':').next().unwrap_or("").trim();
        if !other.is_empty() && other == host {
            let name = row_str(&row, "name");
            peers.push(if name.is_empty() { row_str(&row, "id") } else { name });
        }
    }
    Ok(peers)
}

pub fn build_brief(project: &Value, graph: Option<&Value>) -> String {
    let cfg = project.get("config").cloned().unwrap_or(json!({}));
    let desc = json_text(cfg.get("description"));
    let hint = if json_text(cfg.get("hint")).is_empty() { json_text(cfg.get("tip")) } else { json_text(cfg.get("hint")) };
    let entry = json_text(cfg.get("entry_url"));
    let objective = cfg.get("objective").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let track = cfg.get("track").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
    let obj_or_track = objective.or(track);
    let vhosts = project_names(project);
    let ports = project_ports(project);
    let machine = vhosts.len() > 1 || (!vhosts.is_empty() && !ports.is_empty());
    let auth = match cfg.get("supplied_auth") {
        Some(Value::Object(obj)) => crate::creds::normalize_supplied_auth(
            obj.get("user").or_else(|| obj.get("username")).and_then(|v| v.as_str()).unwrap_or(""),
            obj.get("password").or_else(|| obj.get("pass")).and_then(|v| v.as_str()).unwrap_or(""),
            obj.get("token").or_else(|| obj.get("auth_token")).and_then(|v| v.as_str()).unwrap_or(""),
        ),
        _ => crate::creds::SuppliedAuth::default(),
    };
    let supplied_block = crate::creds::format_supplied_auth_brief(&auth, objective_is_src(obj_or_track));
    let ctf_block = if objective_allows_flag(obj_or_track) {
        let names: Vec<String> = cfg.get("attachments").and_then(|v| v.as_array()).map(|items| items.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
        crate::ctf_prompts::brief_for_category(cfg.get("ctf_category").and_then(|v| v.as_str()).unwrap_or(""), &names, cfg.get("offline").and_then(|v| v.as_bool()).unwrap_or(false))
    } else {
        String::new()
    };
    if desc.is_empty() && hint.is_empty() && entry.is_empty() && !machine && supplied_block.is_empty() && ctf_block.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut meta = Vec::new();
    if truthy(cfg.get("flag_count")) && (objective.is_none() || objective_allows_flag(objective)) {
        meta.push(format!("flag 数={}", json_text(cfg.get("flag_count"))));
    }
    let diff = json_text(cfg.get("difficulty"));
    if !diff.is_empty() { meta.push(format!("难度={diff}")); }
    if truthy(cfg.get("total_score")) { meta.push(format!("总分={}", json_text(cfg.get("total_score")))); }
    let meta_line = if meta.is_empty() { String::new() } else { format!("（{}）", meta.join("、")) };
    if !desc.is_empty() { parts.push(format!("{desc}{meta_line}")); }
    if !hint.is_empty() { parts.push(format!("平台提示：{hint}")); }
    if !entry.is_empty() { parts.push(format!("入口 URL：{entry}")); }
    if machine {
        let ips: Vec<String> = project.get("scope").and_then(|v| v.get("ips")).and_then(|v| v.as_array()).map(|items| items.iter().map(|v| json_text(Some(v))).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
        let ip_txt = if ips.is_empty() { "本机 IP".into() } else { format!("源站 IP {}", ips.join(", ")) };
        let port_txt = if ports.is_empty() { "全端口".into() } else { ports.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",") };
        let scan_note = if objective_allows_flag(cfg.get("objective").and_then(|v| v.as_str())) {
            "先看入口源码/注释/robots/题面路径，像 flag 立刻交。立刻打题面功能，不要先扫描。没有旗再 recon：nmap --top-ports 1000、目录中型字典。不要螺旋升圈。禁止开局 -p-。评测邻题始终越界。"
        } else {
            "第 1 圈（小）只打当前入口：nmap --top-ports 100，目录 common.txt，旁站关。打过或空转再升第 2 圈（中）top-1000/中档。第 3 圈才 -p-；目录大圈是递归/扩展名不是更大词表。禁止开局 -p-。"
        };
        parts.push(format!("同机资产：vhost={}；端口={port_txt}；{ip_txt}。{scan_note}", vhosts.join(",")));
    }
    let nodes: Vec<(String, String)> = graph.and_then(|g| g.get("nodes")).and_then(|v| v.as_array()).map(|items| {
        items.iter().filter_map(|n| n.as_object()).map(|n| (json_text(n.get("title")), json_text(n.get("detail")))).collect()
    }).unwrap_or_default();
    let extra = crate::creds::graph_cred_blob(&nodes, 3000);
    let blob = [desc.clone(), hint.clone(), extra, supplied_block.clone()].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n");
    let cands = crate::creds::credential_candidates_from_brief(&blob, 10);
    if !cands.is_empty() {
        parts.push(format!("题面已出现的账密（禁止合成、禁止扩字典）：{}", cands.iter().take(8).cloned().collect::<Vec<_>>().join("；")));
    }
    if !supplied_block.is_empty() { parts.push(supplied_block); }
    if !ctf_block.is_empty() { parts.push(ctf_block); }
    let pending: Vec<String> = graph.and_then(|g| g.get("findings")).and_then(|v| v.as_array()).map(|items| {
        items.iter().filter(|f| f.as_object().is_some() && !truthy(f.get("secondary_verified"))).take(6).map(|f| {
            let title = json_text(f.get("title"));
            let title = if title.is_empty() { json_text(f.get("id")) } else { title };
            let title = if title.is_empty() { "finding".into() } else { title };
            title.chars().take(40).collect()
        }).collect()
    }).unwrap_or_default();
    if !pending.is_empty() {
        parts.push(format!("未二次验证（pending_review，不能当已结案）：{}", pending.join("；")));
    }
    parts.join("\n")
}

pub fn attach_parent_brief_hint(project: &Value, parent: Option<&Value>) -> Value {
    let Some(project_obj) = project.as_object() else {
        return project.clone();
    };
    let Some(parent) = parent else {
        return project.clone();
    };
    let ph = parent
        .get("config")
        .and_then(|c| c.get("hint").or_else(|| c.get("tip")))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if ph.is_empty() {
        return project.clone();
    }
    let mut out = project_obj.clone();
    let mut cfg = out
        .get("config")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let child = cfg
        .get("hint")
        .or_else(|| cfg.get("tip"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if child.contains(&ph) {
        return project.clone();
    }
    let merged = if child.is_empty() {
        ph
    } else {
        format!("{child}\n{ph}")
    };
    cfg.insert("hint".into(), json!(merged));
    out.insert("config".into(), Value::Object(cfg));
    Value::Object(out)
}

pub fn lead_system_prompt(workspace: &str, objective: &str, brief: &str) -> String {
    let mut body = format!("工作目录：{workspace}\n赛道：{objective}\n");
    if !brief.trim().is_empty() {
        body.push_str(brief.trim());
        body.push('\n');
    }
    crate::i18n::with_output_lang(Some(&body), Some(crate::i18n::config_output_lang(())))
}

const REVIEW_COMMON: &str = "\
你不是猎洞工人，也不写漏洞页长文。\
不要扫目录、不要开新意图、不要 report_shell / report_flag、不要再开子进程。\
禁止新建漏洞条目：report_finding 必须带清单里的 finding_id 和原来的 node_key；\
禁止换 node_key/标题把同一 CVE 或同一上传接口再报一条。\
不要写 report_summary/report_impact/report_rating/report_repro/report_fix，页面另有撰稿补。\
版本命中或仅白名单文件写不是命令执行：没打成执行就不要报 rce，影响三项也不能按完全失控来打。\
命令用 run_cmd，Web 用 http_request。";

const CVSS31_REVIEW: &str = "\
二次验证的级别按 NVD 的 CVSS v3.1 评价（https://nvd.nist.gov/vuln-metrics/cvss）。不要用旧四级表，不要自己算分。\n\
NVD 只公布基础分，不要填时间分或环境分。八项基础指标都要填，系统按 NVD 的 CVSS v3.1 计算器写入分数和定性：\n\
低危 Low 0.1–3.9，中危 Medium 4.0–6.9，高危 High 7.0–8.9，严重 Critical 9.0–10.0。\n\
三项影响都是 N 时 NVD 不打分，不要提交。\n\
细节不够判断某一项时，按 NVD 的最坏情况取值。公开信息完全没有技术细节时，NVD 记 10.0（Critical）。已经能判断影响范围时，按这个漏洞本身打，不要把已知的有限影响改成 10.0。\n\
攻击者本来就懂这个洞，不算攻击复杂度高。所需权限是打之前就有的，不是打完拿到的。\n\
没有命令执行回显时，不要按代码执行的完全失控来打；能读全部数据、改全部数据或让服务不可用，仍然可以是 High。\n\
\n\
AV 攻击向量：N 跨网络（从内网其它机器远程打也算 N），A 必须在同一链路或相邻管理域，L 本地能力或要别人打开文件，P 要物理接触。\n\
AC 攻击复杂度：L 可以重复打成，H 还要攻击者控制不了的条件（竞态、中间人、先摸清目标环境）。\n\
PR 所需权限：N 未授权，L 普通用户，H 管理员。\n\
UI 用户交互：N 不需要别人配合，R 需要其他用户先做动作。\n\
S 范围：U 影响停在同一个安全域；C 打穿到另一个安全域。只给这个应用用的数据库仍算 U。\n\
C/I/A：H 这一类影响基本全部失去，或后果直接且严重；L 有限或部分；N 没有。只记相对攻击前新增加的影响。\n";

pub fn review_system_prompt(workspace: &str, mode: &str) -> String {
    let mode = mode.trim().to_ascii_lowercase();
    let body = if mode == "secondary" {
        format!(
            "你是本项目专职的漏洞二次验证员，本回合只做二次验证，不要给红队评级。{REVIEW_COMMON}\
只处理清单里尚未二次验证的已入库漏洞。\
对每一条独立再打一遍（换观测通道 / 重放 PoC / 对照预期回显），不能只把首次 evidence 再贴一遍，也不能只凭 HTTP 200。\
只有再次看到同样的危害才算证明。证明了才 report_finding：必须带原来的 finding_id 和 node_key，\
secondary_verified=true，redteam_rating_rationale 至少 40 字写清这次新看到了什么。不要填 redteam_rating。\
没有独立证明就记二次验证失败：verification_status=excluded，secondary_verified=false，\
理由至少 40 字。工具若只回「本条意图已经写回，这次会话不再改打别的类型」，\
这一步没有执行，不是没打出危害，不要写 excluded，保持未验证。\
失败只针对这一条，不要写成这类漏洞不存在。用户可见文字写「二次验证失败」，不要写「排除」。"
        )
    } else if mode == "rating" {
        format!(
            "你是本项目专职的红队评级员，本回合只做红队评级，不要去做二次验证动手。{REVIEW_COMMON}\
只处理清单里还没有合法 redteam_rating 的已入库漏洞。\
根据已有 evidence、PoC 和二次验证叙述填写 NVD CVSS 3.1 八项基础指标；\
report_finding 必须带原来的 finding_id 和 node_key。\
不要手填 redteam_rating 或 cvss 分数。redteam_rating_rationale 至少 40 字，写清八项为什么这样打。\
不要传 verification_status，不要改 secondary_verified。未验证保持未验证，二次验证失败保持失败。\
没打成命令执行不要按代码执行打分；已确认的数据读取或篡改仍可按 NVD 打成 High。\n{CVSS31_REVIEW}"
        )
    } else {
        format!(
            "你是本项目专职的漏洞二次验证与红队评级员。{REVIEW_COMMON}\
只处理清单里未二次验证或缺红队评级的已入库漏洞。\
对每一条先独立再打一遍（换观测通道 / 重放 PoC / 对照预期回显），不能只把首次 evidence 再贴一遍，也不能只凭 HTTP 200。\
只有再次看到同样的危害（文件内容、命令回显、越权数据、凭证明文等，且不是把首次证据抄一遍）才算证明。\
证明了才 report_finding：必须带原来的 finding_id（有则必填）和 node_key，\
secondary_verified=true，并填齐 NVD CVSS 3.1 八项基础指标（cvss_av/ac/pr/ui/s/c/i/a）。\
不要手填 redteam_rating 或 cvss 分数，系统按规范公式写入级别。\
redteam_rating_rationale 至少 40 字，写清这次新看到了什么，以及八项为什么这样打。\
没有独立证明同样危害就记二次验证失败：verification_status=excluded，secondary_verified=false，\
理由至少 40 字写清打了什么、没看到什么。工具若只回「本条意图已经写回，这次会话不再改打别的类型」，\
这一步没有执行，不是没打出危害，不要写 excluded，保持未验证。\
八项基础指标仍按实际打到的影响填齐。\
失败只针对这一条，不要写成这类漏洞不存在，也不要删条目。用户可见文字写「二次验证失败」，不要写「排除」。\n{CVSS31_REVIEW}"
        )
    };
    let text = format!(
        "{body}\n工作目录：{workspace}\n可用工具：run_cmd, http_request, report_finding, note。\n"
    );
    crate::i18n::with_output_lang(Some(&text), Some(crate::i18n::config_output_lang(())))
}

fn clip_field(finding: &Value, key: &str, n: usize) -> String {
    let raw = finding.get(key).and_then(|v| v.as_str()).unwrap_or("").trim();
    raw.chars().take(n).collect()
}

pub fn review_instruction(finding: &Value, mode: &str) -> String {
    let mode = mode.trim().to_ascii_lowercase();
    let mode = if mode.is_empty() { "both".to_string() } else { mode };
    let mut lines = if mode == "secondary" {
        vec![
            "本回合只二次验证下列已入库漏洞。".to_string(),
            "逐条动手后用 report_finding 回写同一条：必须带下面的 finding_id，不要新建标题或换 node_key。".to_string(),
            "只有再次看到同样危害才回写 secondary_verified=true，理由至少 40 字写清这次新看到了什么。不要填红队评级。不要写漏洞页五段。".to_string(),
            "没证明则 verification_status=excluded 且 secondary_verified=false，理由写清没看到什么。用户可见文字写二次验证失败，不要写排除。".to_string(),
        ]
    } else if mode == "rating" {
        vec![
            "本回合只给下列已入库漏洞做 NVD CVSS 3.1 基础分。".to_string(),
            "逐条用 report_finding 回写同一条：必须带下面的 finding_id，不要新建标题或换 node_key。".to_string(),
            "回写 NVD CVSS 3.1 八项基础指标和至少 40 字理由。不要手填级别或分数。不要传 verification_status，不要改 secondary_verified。未验证保持未验证，二次验证失败保持失败。不要写漏洞页五段。".to_string(),
        ]
    } else {
        vec![
            "本回合处理下列已入库漏洞：按每条任务做二次验证、NVD CVSS 3.1 基础分，或两件事一起做。".to_string(),
            "逐条动手后用 report_finding 回写同一条：必须带下面的 finding_id，不要新建标题或换 node_key。".to_string(),
            "同一 CVE / 同一上传接口禁止再报一条。级别只按 NVD CVSS 3.1 八项基础指标，由系统算分。".to_string(),
            "没打成命令执行不要标 rce，也不要按代码执行打成完全失控。".to_string(),
            "不要写漏洞页五段，页面另补。".to_string(),
        ]
    };
    lines.push(String::new());
    let title = finding.get("title").and_then(|v| v.as_str()).unwrap_or("(无标题)");
    let id = finding.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let node = finding.get("node_key").and_then(|v| v.as_str()).unwrap_or("");
    let severity = finding.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    let category = finding.get("category").and_then(|v| v.as_str()).unwrap_or("");
    lines.push(format!("### 1. {title}"));
    lines.push(format!("- finding_id: `{id}`"));
    lines.push(format!("- node_key: `{node}`"));
    lines.push(format!("- severity/category: {severity} / {category}"));
    if mode == "secondary" {
        lines.push("- 本条任务：只做二次验证。证明了才 secondary_verified=true；没证明则 verification_status=excluded 且 secondary_verified=false，理由写二次验证失败原因。不要填红队评级。".into());
    } else if mode == "rating" {
        lines.push("- 本条任务：只做 NVD CVSS 3.1 基础分。填齐八项，理由≥40字。不要手填级别。不要传 verification_status，不要改 secondary_verified。未验证保持未验证。".into());
    } else {
        lines.push("- 本条任务：二次验证与 NVD CVSS 3.1 基础分同一轮写齐。没独立证明则 verification_status=excluded、secondary_verified=false，并写二次验证失败原因；八项仍按实际影响填写。".into());
    }
    let evidence = clip_field(finding, "evidence", 500);
    if !evidence.is_empty() {
        lines.push(format!("- 首次 evidence: {evidence}"));
    }
    let poc_curl = clip_field(finding, "poc_curl", 600);
    let poc_py = clip_field(finding, "poc_python", 600);
    let poc = if !poc_curl.is_empty() { poc_curl } else { poc_py };
    if !poc.is_empty() {
        lines.push(format!("- PoC: {poc}"));
    }
    lines.push(String::new());
    lines.push("全部复核完即可结束本回合。".into());
    lines.join("\n")
}

pub fn build_turn_instruction(
    turn: i64,
    target: &str,
    graph_summary: &str,
    intents: &str,
    steering: &str,
    brief: &str,
    has_human: bool,
) -> String {
    let brief_line = if brief.trim().is_empty() {
        String::new()
    } else {
        format!("\n## 题目简报\n{brief}\n")
    };
    let steer = steering.trim();
    let steer_block = if steer.is_empty() {
        String::new()
    } else if has_human {
        format!("\n## 人工强制指令\n{steer}\n")
    } else {
        format!("\n## 纠偏\n{steer}\n")
    };
    let intents = if intents.trim().is_empty() {
        "（无）"
    } else {
        intents
    };
    let graph = if graph_summary.trim().is_empty() {
        "（空，尚未开始）"
    } else {
        graph_summary
    };
    format!(
        "[StrikeAgent_AtkBrain-Flash 编排器 · 第 {turn} 轮]\n{brief_line}## 当前目标\n目标：{target}\n\n## 当前图快照\n{graph}\n\n## 开放意图\n{intents}\n{steer_block}"
    )
}

fn intents_text(db: &Db, project_id: &str) -> String {
    let Ok(rows) = db.query(
        "SELECT id, description, status FROM intents WHERE project_id=?1 AND status IN ('open','active','deferred') ORDER BY priority DESC LIMIT 12",
        &[&project_id as &dyn ToSql],
    ) else {
        return String::new();
    };
    rows.iter()
        .map(|row| {
            let desc: String = row_str(row, "description").chars().take(180).collect();
            format!(
                "- {} {} {}",
                row_str(row, "id"),
                row_str(row, "status"),
                desc
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn hunt_slot_kind(project: Option<&Value>, objective: Option<&str>) -> String {
    let obj = objective.map(|s| s.to_string()).or_else(|| {
        project
            .and_then(|p| p.get("config"))
            .and_then(|c| c.get("objective").or_else(|| c.get("track")))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    if objective_is_src(obj.as_deref()) && normalize_objective(obj.as_deref()) != "flag" {
        return "redteam".into();
    }
    if project.map(is_benchmark_sub).unwrap_or(false) {
        return "ctf".into();
    }
    if objective_allows_flag(obj.as_deref()) {
        "ctf".into()
    } else {
        "redteam".into()
    }
}

fn resume_path(settings: &Settings) -> PathBuf {
    settings.data_dir.join("hunt_resume.json")
}

fn resume_file_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

fn read_ids(path: &PathBuf) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let raw = if let Some(obj) = value.as_object() {
        obj.get("ids").cloned().unwrap_or(Value::Null)
    } else {
        value
    };
    let Some(list) = raw.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for item in list {
        let pid = item.as_str().unwrap_or("").trim().to_string();
        if !pid.is_empty() && seen.insert(pid.clone()) {
            out.push(pid);
        }
    }
    out
}

fn write_ids(path: &PathBuf, ids: &[String]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let tmp = path.with_extension("json.tmp");
    if fs::write(
        &tmp,
        serde_json::to_string(&json!({"ids": ids})).unwrap_or_else(|_| "{\"ids\":[]}".into()),
    )
    .is_ok()
    {
        let _ = fs::rename(&tmp, path);
    }
}

pub fn remember_resume(settings: &Settings, pid: &str) {
    let pid = pid.trim();
    if pid.is_empty() {
        return;
    }
    let _g = lock(resume_file_lock());
    let path = resume_path(settings);
    let mut ids = read_ids(&path);
    if !ids.iter().any(|x| x == pid) {
        ids.push(pid.to_string());
    }
    write_ids(&path, &ids);
}

pub fn forget_resume(settings: &Settings, pid: &str) {
    let pid = pid.trim();
    if pid.is_empty() {
        return;
    }
    let _g = lock(resume_file_lock());
    let path = resume_path(settings);
    if !path.exists() {
        return;
    }
    let ids: Vec<String> = read_ids(&path).into_iter().filter(|x| x != pid).collect();
    if ids.is_empty() {
        let _ = fs::remove_file(path);
    } else {
        write_ids(&path, &ids);
    }
}

pub fn save_resume_ids(settings: &Settings, ids: &[String]) {
    let mut cleaned = Vec::new();
    let mut seen = HashSet::new();
    for item in ids {
        let pid = item.trim();
        if !pid.is_empty() && seen.insert(pid.to_string()) {
            cleaned.push(pid.to_string());
        }
    }
    let _g = lock(resume_file_lock());
    let path = resume_path(settings);
    if cleaned.is_empty() {
        let _ = fs::remove_file(path);
    } else {
        write_ids(&path, &cleaned);
    }
}

pub fn take_resume_ids(settings: &Settings) -> Vec<String> {
    let _g = lock(resume_file_lock());
    let path = resume_path(settings);
    let ids = read_ids(&path);
    let _ = fs::remove_file(path);
    ids
}

pub fn pick_resume_ids(db_running: &[String], saved: &[String], cap: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for pid in saved.iter().chain(db_running.iter()) {
        let pid = pid.trim();
        if pid.is_empty() || !seen.insert(pid.to_string()) {
            continue;
        }
        out.push(pid.to_string());
        if cap > 0 && out.len() >= cap {
            break;
        }
    }
    out
}

pub fn should_autoresume(project: Option<&Value>) -> bool {
    let Some(project) = project else { return false };
    if val_str(project, "kind") == "cluster" {
        return false;
    }
    let status = val_str(project, "status");
    if status == "completed" || status == "error" {
        return false;
    }
    let cfg = project.get("config").cloned().unwrap_or(json!({}));
    if cfg
        .get("env_closed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    let reason = cfg
        .get("completion_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if matches!(
        reason,
        "env_closed" | "env_unreachable" | "runtime_review_stop"
    ) || HUNT_FAILED.contains(&reason)
    {
        return false;
    }
    if objective_allows_flag(
        cfg.get("objective")
            .or_else(|| cfg.get("track"))
            .and_then(|v| v.as_str()),
    ) {
        let got = cfg
            .get("benchmark")
            .and_then(|b| b.get("correct_flag_count"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let flag_count = cfg.get("flag_count").and_then(|v| v.as_i64());
        if got > 0 && objective_ctf_full_score(got, None, flag_count) {
            return false;
        }
    }
    true
}

struct Waiter {
    ready: Mutex<bool>,
    cv: Condvar,
}

fn decisions() -> &'static Mutex<HashMap<String, (bool, String)>> {
    static D: OnceLock<Mutex<HashMap<String, (bool, String)>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

fn waiters() -> &'static Mutex<HashMap<String, Arc<Waiter>>> {
    static W: OnceLock<Mutex<HashMap<String, Arc<Waiter>>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(HashMap::new()))
}

thread_local! {
    static TOOL_ROLE: std::cell::RefCell<String> = std::cell::RefCell::new(String::new());
}

pub fn set_tool_caller_role(role: &str) {
    TOOL_ROLE.with(|r| *r.borrow_mut() = role.to_string());
}

fn tool_caller_role() -> String {
    TOOL_ROLE.with(|r| r.borrow().clone())
}

pub fn bound_intent_id(hop_id: &str, bound_ids: &[String]) -> String {
    let hop = hop_id.trim();
    if !hop.is_empty() {
        return hop.to_string();
    }
    let mut ids: Vec<String> = bound_ids
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    ids.sort();
    ids.into_iter().next().unwrap_or_default()
}

pub fn gate_intent(
    db: &Db,
    project_id: &str,
    intent_closed: bool,
    hop_id: &str,
    bound_ids: &[String],
    role: &str,
) -> Result<Option<String>, String> {
    let role = if role.trim().is_empty() {
        tool_caller_role()
    } else {
        role.to_string()
    };
    if intent_closed && !pi::is_review_role(&role) {
        return Ok(Some("本条意图已经写回，这次会话不再改打别的类型。".into()));
    }
    let iid = bound_intent_id(hop_id, bound_ids);
    if iid.is_empty() {
        return Ok(None);
    }
    let row = db.query_one(
        "SELECT paused, pending_steer FROM intents WHERE id=?1 AND project_id=?2",
        &[&iid as &dyn ToSql, &project_id as &dyn ToSql],
    )?;
    let Some(row) = row else { return Ok(None) };
    if row.get("paused").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
        return Ok(Some("这条意图已暂停。其它意图继续。".into()));
    }
    let steer = row_str(&row, "pending_steer");
    if !steer.trim().is_empty() {
        let ts = now();
        db.execute(
            "UPDATE intents SET pending_steer=NULL, updated_at=?1 WHERE id=?2",
            &[&ts as &dyn ToSql, &iid],
        )?;
        return Ok(Some(format!(
            "纠偏（先按这句调整，本步工具未执行）：{}",
            steer.trim()
        )));
    }
    Ok(None)
}

pub fn decide_command(confirm_id: &str, allow: bool, reason: &str) {
    lock(decisions()).insert(confirm_id.to_string(), (allow, reason.trim().to_string()));
    let waiter = {
        let mut map = lock(waiters());
        map.entry(confirm_id.to_string())
            .or_insert_with(|| {
                Arc::new(Waiter {
                    ready: Mutex::new(false),
                    cv: Condvar::new(),
                })
            })
            .clone()
    };
    *lock(&waiter.ready) = true;
    waiter.cv.notify_all();
}

pub fn maybe_confirm_command(
    db: &Db,
    project_id: &str,
    intent_id: &str,
    command: &str,
    needs: bool,
) -> Result<Option<String>, String> {
    if !needs {
        return Ok(None);
    }
    let cid = new_id("cmd_");
    let ts = now();
    let pending = "pending";
    let iid = if intent_id.trim().is_empty() {
        None
    } else {
        Some(intent_id.to_string())
    };
    db.execute(
        "INSERT INTO command_confirms(id, project_id, intent_id, command, status, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        &[&cid as &dyn ToSql, &project_id, &iid as &dyn ToSql, &command, &pending, &ts],
    )?;
    let waiter = {
        let mut map = lock(waiters());
        map.entry(cid.clone())
            .or_insert_with(|| {
                Arc::new(Waiter {
                    ready: Mutex::new(false),
                    cv: Condvar::new(),
                })
            })
            .clone()
    };
    if lock(decisions()).contains_key(&cid) {
        *lock(&waiter.ready) = true;
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut ready = lock(&waiter.ready);
    while !*ready {
        let now_at = Instant::now();
        if now_at >= deadline {
            drop(ready);
            let ts = now();
            let status = "timeout";
            let reason = "无人确认";
            let _ = db.execute(
                "UPDATE command_confirms SET status=?1, reason=?2, decided_at=?3 WHERE id=?4",
                &[&status as &dyn ToSql, &reason, &ts, &cid],
            );
            lock(waiters()).remove(&cid);
            return Ok(Some("无人确认，这条命令没有执行。".into()));
        }
        let (g, _) = waiter
            .cv
            .wait_timeout(ready, deadline - now_at)
            .unwrap_or_else(|e| e.into_inner());
        ready = g;
    }
    drop(ready);
    let decision = lock(decisions())
        .remove(&cid)
        .unwrap_or((false, String::new()));
    lock(waiters()).remove(&cid);
    if decision.0 {
        Ok(None)
    } else if decision.1.is_empty() {
        Ok(Some("这条命令被拒绝。".into()))
    } else {
        Ok(Some(decision.1))
    }
}

struct SemState {
    limit: i64,
    active: i64,
}

pub struct DynamicSemaphore {
    state: Mutex<SemState>,
    cv: Condvar,
}

impl DynamicSemaphore {
    fn new(limit: i64) -> Self {
        Self {
            state: Mutex::new(SemState {
                limit: limit.max(1),
                active: 0,
            }),
            cv: Condvar::new(),
        }
    }

    pub fn limit(&self) -> i64 {
        lock(&self.state).limit
    }

    pub fn active(&self) -> i64 {
        lock(&self.state).active
    }

    pub fn set_limit(&self, value: i64) {
        let mut g = lock(&self.state);
        g.limit = value.max(1);
        self.cv.notify_all();
    }

    pub fn acquire(&self, stop: &AtomicBool) -> bool {
        let mut g = lock(&self.state);
        while g.active >= g.limit {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            let (ng, _) = self
                .cv
                .wait_timeout(g, Duration::from_millis(200))
                .unwrap_or_else(|e| e.into_inner());
            g = ng;
        }
        if stop.load(Ordering::SeqCst) {
            return false;
        }
        g.active += 1;
        true
    }

    pub fn release(&self) {
        let mut g = lock(&self.state);
        g.active = (g.active - 1).max(0);
        self.cv.notify_all();
    }

    pub fn force_active(&self, n: i64) {
        lock(&self.state).active = n.max(0);
        self.cv.notify_all();
    }
}

struct Slot {
    handle: Arc<RunHandle>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

pub struct RunHandle {
    pub project_id: String,
    pub hard_restart: bool,
    pub user_stop: AtomicBool,
    pub human_interrupt: AtomicBool,
    pub cancel: Arc<AtomicBool>,
    pub status: Mutex<String>,
    pub run_id: Mutex<String>,
    pub slot_held: AtomicBool,
    pub slot_kind: Mutex<String>,
    pub agent: Mutex<Option<Arc<ProjectAgent>>>,
    pub steering: Mutex<VecDeque<String>>,
    pub finished: AtomicBool,
    pub goal_stop: AtomicBool,
}

impl RunHandle {
    fn new(project_id: &str, hard_restart: bool) -> Self {
        Self {
            project_id: project_id.to_string(),
            hard_restart,
            user_stop: AtomicBool::new(false),
            human_interrupt: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            status: Mutex::new("starting".into()),
            run_id: Mutex::new(String::new()),
            slot_held: AtomicBool::new(false),
            slot_kind: Mutex::new("redteam".into()),
            agent: Mutex::new(None),
            steering: Mutex::new(VecDeque::new()),
            finished: AtomicBool::new(false),
            goal_stop: AtomicBool::new(false),
        }
    }
}

struct Inner {
    db: Arc<Db>,
    settings: Arc<Mutex<Settings>>,
    redteam: DynamicSemaphore,
    ctf: DynamicSemaphore,
    slots: Mutex<HashMap<String, Slot>>,
    queue: Mutex<()>,
    shutting_down: AtomicBool,
}

#[derive(Clone)]
pub struct RunManager {
    inner: Arc<Inner>,
}

impl RunManager {
    pub fn new(db: Arc<Db>, settings: Settings) -> Self {
        let rt = settings
            .max_redteam_concurrency
            .min(settings.max_redteam_concurrency_cap)
            .max(1);
        let ctf = settings.benchmark_slot_limit().max(1);
        Self {
            inner: Arc::new(Inner {
                db,
                settings: Arc::new(Mutex::new(settings)),
                redteam: DynamicSemaphore::new(rt),
                ctf: DynamicSemaphore::new(ctf),
                slots: Mutex::new(HashMap::new()),
                queue: Mutex::new(()),
                shutting_down: AtomicBool::new(false),
            }),
        }
    }

    pub fn db(&self) -> &Db {
        self.inner.db.as_ref()
    }

    pub fn settings_snapshot(&self) -> Settings {
        lock(&self.inner.settings).clone()
    }

    pub fn shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::SeqCst)
    }

    fn sem(&self, kind: &str) -> &DynamicSemaphore {
        if kind == "ctf" {
            &self.inner.ctf
        } else {
            &self.inner.redteam
        }
    }

    fn reap(&self) {
        let mut slots = lock(&self.inner.slots);
        let done: Vec<String> = slots
            .iter()
            .filter(|(_, s)| s.handle.finished.load(Ordering::SeqCst))
            .map(|(k, _)| k.clone())
            .collect();
        for id in done {
            if let Some(slot) = slots.remove(&id) {
                if let Some(join) = lock(&slot.thread).take() {
                    drop(slots);
                    let _ = join.join();
                    slots = lock(&self.inner.slots);
                }
            }
        }
    }

    fn slot(&self, project_id: &str) -> Option<Arc<RunHandle>> {
        lock(&self.inner.slots)
            .get(project_id)
            .map(|s| s.handle.clone())
    }

    pub fn set_shutting_down(&self, value: bool) {
        self.inner.shutting_down.store(value, Ordering::SeqCst);
    }

    pub fn redteam_limit(&self) -> i64 {
        self.inner.redteam.limit()
    }

    pub fn ctf_limit(&self) -> i64 {
        self.inner.ctf.limit()
    }

    pub fn request_goal(&self, project_id: &str) {
        let Some(handle) = self.slot(project_id) else { return };
        handle.goal_stop.store(true, Ordering::SeqCst);
        let agent = { lock(&handle.agent).clone() };
        if let Some(agent) = agent {
            agent.interrupt(false);
        }
    }

    pub fn run_id_of(&self, project_id: &str) -> String {
        self.slot(project_id)
            .map(|handle| lock(&handle.run_id).clone())
            .unwrap_or_default()
    }

    pub fn is_running(&self, project_id: &str) -> bool {
        self.reap();
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        if handle.finished.load(Ordering::SeqCst) {
            return false;
        }
        let status = lock(&handle.status).clone();
        !matches!(status.as_str(), "done" | "stopping" | "zombie")
    }

    pub fn is_queued(&self, project_id: &str) -> bool {
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        if handle.finished.load(Ordering::SeqCst) {
            return false;
        }
        let status = lock(&handle.status).clone();
        status == "starting"
    }

    pub fn live_agent(&self, project_id: &str) -> Option<Arc<ProjectAgent>> {
        if !self.is_running(project_id) {
            return None;
        }
        let handle = self.slot(project_id)?;
        let agent = lock(&handle.agent).clone()?;
        if agent.stopped() {
            None
        } else {
            Some(agent)
        }
    }

    pub fn start(&self, project_id: &str, hard_restart: bool) -> Arc<RunHandle> {
        self.reap();
        if self.is_running(project_id) {
            if let Some(handle) = self.slot(project_id) {
                return handle;
            }
        }
        if let Some(old) = lock(&self.inner.slots).remove(project_id) {
            if !old.handle.finished.load(Ordering::SeqCst) {
                *lock(&old.handle.status) = "zombie".into();
                old.handle.cancel.store(true, Ordering::SeqCst);
                self.release_slot(&old.handle);
            }
            if let Some(join) = lock(&old.thread).take() {
                thread::spawn(move || {
                    let _ = join.join();
                });
            }
        }
        let handle = Arc::new(RunHandle::new(project_id, hard_restart));
        lock(&self.inner.slots).insert(
            project_id.to_string(),
            Slot {
                handle: handle.clone(),
                thread: Mutex::new(None),
            },
        );
        let manager = self.clone();
        let worker = handle.clone();
        let join = thread::Builder::new()
            .name(format!("hunt-{project_id}"))
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_project_loop(&manager, &worker)
                }));
                worker.finished.store(true, Ordering::SeqCst);
            });
        if let Ok(join) = join {
            if let Some(slot) = lock(&self.inner.slots).get(project_id) {
                *lock(&slot.thread) = Some(join);
            }
        } else {
            handle.finished.store(true, Ordering::SeqCst);
        }
        handle
    }

    fn release_slot(&self, handle: &RunHandle) {
        if handle.slot_held.swap(false, Ordering::SeqCst) {
            let kind = lock(&handle.slot_kind).clone();
            self.sem(&kind).release();
        }
    }

    pub fn stop(&self, project_id: &str) -> bool {
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        handle.user_stop.store(true, Ordering::SeqCst);
        *lock(&handle.status) = "stopping".into();
        handle.cancel.store(true, Ordering::SeqCst);
        forget_resume(&self.settings_snapshot(), project_id);
        if let Some(agent) = lock(&handle.agent).clone() {
            agent.interrupt(true);
        }
        pi::kill_live_for_project(project_id, &["finding-review"]);
        let start = Instant::now();
        while !handle.finished.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(12) {
            thread::sleep(Duration::from_millis(50));
        }
        if !handle.finished.load(Ordering::SeqCst) {
            *lock(&handle.status) = "zombie".into();
            pi::kill_live_for_project(project_id, &["finding-review"]);
            self.release_slot(&handle);
            let _ = update_status(self.db(), project_id, "idle");
            return true;
        }
        self.release_slot(&handle);
        self.reap();
        true
    }

    pub fn halt(&self, project_id: &str, reason: &str) -> bool {
        forget_resume(&self.settings_snapshot(), project_id);
        pi::kill_live_for_project(project_id, &["finding-review"]);
        let had = self.slot(project_id).is_some();
        if had {
            let _ = self.stop(project_id);
            pi::kill_live_for_project(project_id, &["finding-review"]);
        }
        let _ = update_status(self.db(), project_id, "idle");
        emit(
            self.db(),
            project_id,
            "status",
            &json!({"status": "stopped", "reason": reason}),
            None,
        );
        if let Ok(Some(project)) = get_project(self.db(), &self.settings_snapshot(), project_id) {
            review::schedule_drain(self, &project);
        }
        true
    }

    pub fn steer(&self, project_id: &str, message: &str, intent_id: Option<&str>) -> bool {
        if !self.is_running(project_id) {
            return false;
        }
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        let iid = intent_id.unwrap_or("").trim();
        if !iid.is_empty() {
            let ts = now();
            let text: String = message.trim().chars().take(2000).collect();
            let _ = self.db().execute(
                "UPDATE intents SET pending_steer=?1, updated_at=?2 WHERE id=?3",
                &[&text as &dyn ToSql, &ts, &iid],
            );
            return true;
        }
        let mut queue = lock(&handle.steering);
        if queue.len() >= 100 {
            return false;
        }
        queue.push_back(message.to_string());
        drop(queue);
        handle.human_interrupt.store(true, Ordering::SeqCst);
        if let Some(agent) = lock(&handle.agent).clone() {
            agent.interrupt(false);
        }
        true
    }

    pub fn has_pending_human(&self, project_id: &str) -> bool {
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        handle.human_interrupt.load(Ordering::SeqCst) || !lock(&handle.steering).is_empty()
    }

    pub fn take_human_interrupt(&self, project_id: &str) -> bool {
        let Some(handle) = self.slot(project_id) else {
            return false;
        };
        if !handle.human_interrupt.swap(false, Ordering::SeqCst) {
            return false;
        }
        true
    }

    pub fn drain_steering(&self, project_id: &str) -> Vec<String> {
        let Some(handle) = self.slot(project_id) else {
            return Vec::new();
        };
        let mut queue = lock(&handle.steering);
        queue.drain(..).collect()
    }

    pub fn snapshot(&self) -> Value {
        self.reap();
        let settings = self.settings_snapshot();
        let slots = lock(&self.inner.slots);
        let mut live_rt = Vec::new();
        let mut live_ctf = Vec::new();
        let mut queued = Vec::new();
        for (pid, slot) in slots.iter() {
            let status = lock(&slot.handle.status).clone();
            if slot.handle.finished.load(Ordering::SeqCst) {
                continue;
            }
            if status == "starting" {
                queued.push(pid.clone());
            }
            if status == "running" && slot.handle.slot_held.load(Ordering::SeqCst) {
                if lock(&slot.handle.slot_kind).as_str() == "ctf" {
                    live_ctf.push(pid.clone());
                } else {
                    live_rt.push(pid.clone());
                }
            }
        }
        drop(slots);
        if self.inner.redteam.active() != live_rt.len() as i64 {
            self.inner.redteam.force_active(live_rt.len() as i64);
        }
        if self.inner.ctf.active() != live_ctf.len() as i64 {
            self.inner.ctf.force_active(live_ctf.len() as i64);
        }
        let mut live = live_rt.clone();
        live.extend(live_ctf.iter().cloned());
        let rt_cap = settings.max_redteam_concurrency_cap;
        let ctf_cap = settings.max_ctf_concurrency_cap.max(1);
        json!({
            "concurrency_limit": self.inner.redteam.limit() + self.inner.ctf.limit(),
            "active": live.len(),
            "cap": rt_cap + ctf_cap,
            "running": live,
            "queued": queued,
            "redteam": {"active": live_rt.len(), "limit": self.inner.redteam.limit(), "cap": rt_cap},
            "ctf": {"active": live_ctf.len(), "limit": self.inner.ctf.limit(), "cap": ctf_cap},
            "projects": {"active": live_rt.len() + live_ctf.len(), "limit": self.inner.redteam.limit() + self.inner.ctf.limit(), "cap": rt_cap + ctf_cap},
            "claude": {
                "active": pi::live_pi_count(),
                "limit": pi::pi_max_live_limit(&settings),
                "cap": settings.pi_max_live_cap.max(1),
                "per_project": pi::pi_per_project_limit(&settings),
            }
        })
    }

    pub fn set_pi_per_project(&self, value: i64) -> i64 {
        let mut settings = lock(&self.inner.settings);
        let cap = if settings.pi_per_project_cap <= 0 { 8 } else { settings.pi_per_project_cap };
        let n = value.clamp(1, cap);
        settings.pi_per_project = n;
        settings.claude_per_project = n;
        n
    }

    pub fn set_concurrency(&self, value: i64, track: &str) -> i64 {
        if matches!(
            track.trim().to_ascii_lowercase().as_str(),
            "ctf" | "flag" | "benchmark"
        ) {
            self.set_ctf_concurrency(value)
        } else {
            self.set_redteam_concurrency(value)
        }
    }

    pub fn set_redteam_concurrency(&self, value: i64) -> i64 {
        let cap = self.settings_snapshot().max_redteam_concurrency_cap.max(1);
        let value = value.clamp(1, cap);
        self.inner.redteam.set_limit(value);
        value
    }

    pub fn set_ctf_concurrency(&self, value: i64) -> i64 {
        let mut cap = self.settings_snapshot().max_ctf_concurrency_cap;
        if cap <= 0 {
            cap = 20;
        }
        let value = value.clamp(1, cap);
        self.inner.ctf.set_limit(value);
        lock(&self.inner.settings).benchmark_max_concurrency = value;
        value
    }

    pub fn set_claude_per_project(&self, value: i64) -> i64 {
        let mut settings = lock(&self.inner.settings);
        let mut cap = settings.pi_per_project_cap;
        if cap == 0 {
            cap = settings.claude_per_project_cap;
        }
        if cap <= 0 {
            cap = 8;
        }
        let n = if value <= 0 { 4 } else { value }.clamp(1, cap);
        settings.pi_per_project = n;
        settings.claude_per_project = n;
        pi::pi_per_project_limit(&settings)
    }

    pub fn checkpoint_for_shutdown(&self, timeout: Duration) {
        self.inner.shutting_down.store(true, Ordering::SeqCst);
        let snap = self.snapshot();
        let running = snap
            .get("running")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let ids: Vec<String> = running
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !ids.is_empty() {
            save_resume_ids(&self.settings_snapshot(), &ids);
        }
        let handles: Vec<Arc<RunHandle>> = lock(&self.inner.slots)
            .values()
            .map(|s| s.handle.clone())
            .collect();
        for handle in &handles {
            handle.cancel.store(true, Ordering::SeqCst);
        }
        let start = Instant::now();
        while handles.iter().any(|h| !h.finished.load(Ordering::SeqCst))
            && start.elapsed() < timeout.max(Duration::from_millis(500))
        {
            thread::sleep(Duration::from_millis(50));
        }
        self.reap();
    }

    fn acquire_slot(&self, project_id: &str, kind: &str, stop: &AtomicBool) -> bool {
        let sem = self.sem(kind);
        loop {
            if stop.load(Ordering::SeqCst) {
                return false;
            }
            let head = {
                let _queue = lock(&self.inner.queue);
                let row = self.db().query_one(
                    "SELECT id FROM projects WHERE status='queued' AND IFNULL(archived,0)=0 ORDER BY COALESCE(queued_at, updated_at) ASC LIMIT 1",
                    &[],
                );
                let head = row
                    .ok()
                    .flatten()
                    .map(|r| row_str(&r, "id"))
                    .unwrap_or_default();
                if head.is_empty() || head == project_id {
                    return sem.acquire(stop);
                }
                head
            };
            let _ = head;
            thread::sleep(Duration::from_millis(250));
        }
    }
}

pub struct TurnResult {
    pub text: String,
    pub tool_uses: u64,
}

pub struct ProjectAgent {
    db: Arc<Db>,
    settings: Arc<Mutex<Settings>>,
    project_id: String,
    workspace: String,
    objective: String,
    model: String,
    brief: String,
    stop: Arc<AtomicBool>,
    run_id: Mutex<String>,
    pool: Mutex<HashMap<String, PiSession>>,
    sessions: Mutex<Vec<PiSession>>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    review_on: AtomicBool,
    stopped: AtomicBool,
    emit: EmitFn,
}

impl ProjectAgent {
    fn open(
        db: Arc<Db>,
        settings: Arc<Mutex<Settings>>,
        project: &Value,
        stop: Arc<AtomicBool>,
    ) -> Self {
        let project_id = val_str(project, "id");
        let snap = lock(&settings).clone();
        let workspace = snap.workspaces_dir.join(&project_id);
        let _ = fs::create_dir_all(&workspace);
        let _ = fs::create_dir_all(workspace.join("loot"));
        let cfg = project.get("config").cloned().unwrap_or(json!({}));
        let objective = cfg
            .get("objective")
            .and_then(|v| v.as_str())
            .unwrap_or(&snap.default_objective)
            .to_string();
        let model = pi::project_model(
            &snap,
            cfg.get("model").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let brief = build_brief(project, None);
        if !brief.is_empty() {
            let _ = fs::write(
                workspace.join("BRIEF.md"),
                format!("# 题目简报\n\n{brief}\n"),
            );
        }
        let db_emit = db.clone();
        let emit: EmitFn = Arc::new(move |project_id, kind, payload, run_id| {
            emit(&db_emit, project_id, kind, payload, run_id);
        });
        Self {
            db,
            settings,
            project_id,
            workspace: workspace.display().to_string(),
            objective,
            model,
            brief,
            stop,
            run_id: Mutex::new(String::new()),
            pool: Mutex::new(HashMap::new()),
            sessions: Mutex::new(Vec::new()),
            locks: Mutex::new(HashMap::new()),
            review_on: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            emit,
        }
    }

    pub fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn cmd_inflight(&self) -> i64 {
        0
    }

    fn set_run(&self, run_id: &str) {
        *lock(&self.run_id) = run_id.to_string();
    }

    fn role_lock(&self, role: &str) -> Arc<Mutex<()>> {
        let mut map = lock(&self.locks);
        map.entry(role.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn acquire(&self, role: &str, system_prompt: &str, tools: bool) -> Result<PiSession, String> {
        let role_lock = self.role_lock(role);
        let _held = lock(&role_lock);
        if let Some(sess) = lock(&self.pool).get(role) {
            if sess.alive() {
                sess.set_run_id(&lock(&self.run_id));
                return Ok(sess.clone());
            }
        }
        if let Some(old) = lock(&self.pool).remove(role) {
            old.close();
            lock(&self.sessions).retain(|s| s.role() != role);
        }
        let settings = lock(&self.settings).clone();
        let sess = PiSession::with_stop(
            &self.workspace,
            system_prompt,
            &self.project_id,
            role,
            tools,
            &self.model,
            self.stop.clone(),
        );
        sess.set_emit(self.emit.clone());
        sess.set_run_id(&lock(&self.run_id));
        sess.start(&settings)?;
        lock(&self.pool).insert(role.to_string(), sess.clone());
        lock(&self.sessions).push(sess.clone());
        Ok(sess)
    }

    fn run_one(
        &self,
        role: &str,
        system_prompt: &str,
        instruction: &str,
        job_id: &str,
        timeout: Duration,
        hang: Duration,
        tools: bool,
    ) -> Result<TurnResult, String> {
        let sess = self.acquire(role, system_prompt, tools)?;
        if !job_id.is_empty() {
            sess.set_review_job(job_id);
            if let Some(pid) = sess.pid() {
                review::note_review_pid(job_id, pid);
            }
            review::mark_running(job_id, "等待模型回复");
        }
        let dedicated = pi::is_review_role(role) && role != "finding-review";
        let result = sess.prompt(instruction, timeout, hang);
        sess.set_review_job("");
        if dedicated {
            lock(&self.pool).remove(role);
            lock(&self.sessions).retain(|s| s.role() != role);
            sess.close();
        } else if result
            .as_ref()
            .err()
            .map(|e| pi::is_dead_cli_error(e))
            .unwrap_or(false)
        {
            lock(&self.pool).remove(role);
            lock(&self.sessions).retain(|s| s.role() != role);
            sess.close();
        }
        result.map(|text| TurnResult {
            text,
            tool_uses: sess.tool_uses(),
        })
    }

    pub fn review_one(&self, finding: &Value, mode: &str, job_id: &str) -> Result<(), String> {
        let fid = finding.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let mode_l = mode.trim().to_ascii_lowercase();
        let role = if mode_l == "secondary" || mode_l == "rating" {
            format!("finding-review:{fid}:{mode_l}")
        } else {
            "finding-review".into()
        };
        let settings = lock(&self.settings).clone();
        let hang = Duration::from_secs(settings.turn_hang_sec.max(0) as u64);
        self.run_one(
            &role,
            &review_system_prompt(&self.workspace, &mode_l),
            &review_instruction(finding, &mode_l),
            job_id,
            Duration::ZERO,
            hang,
            true,
        )?;
        Ok(())
    }

    pub fn run_turn(&self, instruction: &str) -> Result<TurnResult, String> {
        self.abort_prompts(false);
        let settings = lock(&self.settings).clone();
        let timeout = if uses_ctf_clocks(Some(&self.objective)) && settings.turn_must_close_sec > 0
        {
            Duration::from_secs(settings.turn_must_close_sec as u64)
        } else {
            Duration::ZERO
        };
        let hang = if settings.turn_hang_sec > 0 {
            Duration::from_secs(settings.turn_hang_sec as u64)
        } else {
            Duration::ZERO
        };
        let system = lead_system_prompt(&self.workspace, &self.objective, &self.brief);
        let result = self.run_one("lead", &system, instruction, "", timeout, hang, true);
        self.reap_idle(&settings);
        result
    }

    fn abort_prompts(&self, halt: bool) {
        let sessions = lock(&self.sessions).clone();
        for sess in sessions {
            if !halt && pi::is_review_role(&sess.role()) {
                continue;
            }
            let _ = sess.abort();
        }
    }

    pub fn interrupt(&self, halt: bool) {
        if halt {
            self.stopped.store(true, Ordering::SeqCst);
        }
        self.abort_prompts(halt);
        if halt {
            self.close_sessions(false);
        }
    }

    fn close_sessions(&self, keep_review: bool) {
        let sessions = lock(&self.sessions).clone();
        let mut keep = Vec::new();
        for sess in sessions {
            if keep_review && pi::is_review_role(&sess.role()) {
                keep.push(sess);
            } else {
                lock(&self.pool).remove(&sess.role());
                sess.close();
            }
        }
        *lock(&self.sessions) = keep;
    }

    fn reap_idle(&self, settings: &Settings) {
        let idle_sec = if settings.pi_worker_idle_sec <= 0.0 {
            180.0
        } else {
            settings.pi_worker_idle_sec
        };
        let idle_turns = settings.pi_worker_idle_turns.max(1);
        let mut drop_roles = Vec::new();
        for (role, sess) in lock(&self.pool).iter() {
            if role == "lead" || pi::is_review_role(role) {
                continue;
            }
            let aged = sess
                .last_prompt_elapsed()
                .map(|d| d.as_secs_f64() >= idle_sec)
                .unwrap_or(false);
            let turns = sess.bump_idle_turns();
            if turns >= idle_turns as u64 || aged {
                drop_roles.push(role.clone());
            }
        }
        for role in drop_roles {
            if let Some(sess) = lock(&self.pool).remove(&role) {
                lock(&self.sessions).retain(|s| s.role() != role);
                sess.close();
            }
        }
    }

    pub fn close(&self, manager: &RunManager) {
        let project = get_project(&self.db, &lock(&self.settings), &self.project_id)
            .ok()
            .flatten();
        self.stopped.store(true, Ordering::SeqCst);
        self.close_sessions(false);
        if !manager.shutting_down() {
            if let Some(project) = project {
                review::schedule_drain(manager, &project);
            }
        }
    }
}

pub fn kick_review(agent: Arc<ProjectAgent>, manager: RunManager) {
    if agent.stopped() {
        return;
    }
    if agent.review_on.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::spawn(move || {
        let mut attempts: HashMap<(String, String), i64> = HashMap::new();
        while !agent.stopped() && !manager.shutting_down() {
            let pending = findings_pending_review(
                manager.db(),
                &manager.settings_snapshot(),
                &agent.project_id,
            )
            .unwrap_or_default();
            let mut chosen = None;
            for finding in &pending {
                let fid = finding.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let raw = finding
                    .get("_review_mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("both");
                let modes: Vec<&str> = if raw == "both" {
                    vec!["secondary", "rating"]
                } else {
                    vec![raw]
                };
                for cand in modes {
                    if review::review_attempt_open(&attempts, fid, cand) {
                        chosen = Some((finding.clone(), cand.to_string(), fid.to_string()));
                        break;
                    }
                }
                if chosen.is_some() {
                    break;
                }
            }
            let Some((mut finding, mode, fid)) = chosen else {
                break;
            };
            let Some(job) = review::try_claim(&agent.project_id, &fid, &mode, "auto") else {
                review::note_review_attempt(&mut attempts, &fid, &mode);
                continue;
            };
            let jid = job
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            finding["_job_id"] = json!(jid);
            match agent.review_one(&finding, &mode, &jid) {
                Ok(()) => review::release(&jid, "done", ""),
                Err(e) => review::release(&jid, "error", &e.chars().take(240).collect::<String>()),
            }
        }
        agent.review_on.store(false, Ordering::SeqCst);
    });
}

pub fn run_review_job(
    manager: &RunManager,
    project: &Value,
    finding: &Value,
    mode: &str,
    job_id: &str,
) -> Result<(), String> {
    let pid = val_str(project, "id");
    if let Some(agent) = manager.live_agent(&pid) {
        return agent.review_one(finding, mode, job_id);
    }
    let agent = Arc::new(ProjectAgent::open(
        manager.inner.db.clone(),
        Arc::clone(&manager.inner.settings),
        project,
        Arc::new(AtomicBool::new(false)),
    ));
    let result = agent.review_one(finding, mode, job_id);
    agent.close(manager);
    result
}

fn conclude(
    manager: &RunManager,
    handle: &RunHandle,
    agent: Option<&ProjectAgent>,
    rid: &str,
    goal: bool,
    turn: i64,
    summary: &str,
    pause: &str,
) {
    let status_now = lock(&handle.status).clone();
    let user_stop = handle.user_stop.load(Ordering::SeqCst);
    let project_id = &handle.project_id;
    if handle.cancel.load(Ordering::SeqCst) && pause.is_empty() {
        match cancel_project_status(
            user_stop,
            &status_now,
            handle.slot_held.load(Ordering::SeqCst),
        ) {
            None => {}
            Some("running") => {
                remember_resume(&manager.settings_snapshot(), project_id);
                finish_run(
                    manager.db(),
                    rid,
                    "stopped",
                    goal,
                    turn,
                    if summary.is_empty() {
                        "后端重启，将自动续跑"
                    } else {
                        summary
                    },
                );
                let _ = update_status(manager.db(), project_id, "running");
                emit(
                    manager.db(),
                    project_id,
                    "log",
                    &json!({"level": "info", "message": "后端重启，本猎将自动续跑（不是人工停止）"}),
                    if rid.is_empty() { None } else { Some(rid) },
                );
            }
            Some("idle") => {
                forget_resume(&manager.settings_snapshot(), project_id);
                finish_run(
                    manager.db(),
                    rid,
                    "stopped",
                    goal,
                    turn,
                    if summary.is_empty() {
                        "已被人工停止"
                    } else {
                        summary
                    },
                );
                let _ = update_status(manager.db(), project_id, "idle");
                emit(
                    manager.db(),
                    project_id,
                    "status",
                    &json!({"status": "stopped", "turns": turn}),
                    if rid.is_empty() { None } else { Some(rid) },
                );
            }
            Some(_) => {}
        }
    } else if !rid.is_empty() || !pause.is_empty() {
        let project_status = if user_stop {
            "idle"
        } else {
            final_project_status(
                goal,
                false,
                if pause.is_empty() { None } else { Some(pause) },
            )
        };
        let run_status = if project_status == "error" {
            "error"
        } else if project_status == "completed" {
            "completed"
        } else {
            "stopped"
        };
        finish_run(manager.db(), rid, run_status, goal, turn, summary);
        let _ = update_status(manager.db(), project_id, project_status);
        if !pause.is_empty() || goal {
            let mut cfg = read_config(manager.db(), project_id);
            if let Some(obj) = cfg.as_object_mut() {
                if goal {
                    obj.insert("completion_reason".into(), json!("goal_reached"));
                } else if HUNT_FAILED.contains(&pause)
                    || matches!(
                        pause,
                        "env_closed" | "env_unreachable" | "runtime_review_stop"
                    )
                {
                    obj.insert("completion_reason".into(), json!(pause));
                }
                let _ = write_config(manager.db(), project_id, &cfg);
            }
        }
        emit(
            manager.db(),
            project_id,
            "status",
            &json!({"status": run_status, "goal_reached": goal, "turns": turn, "reason": if pause.is_empty() { Value::Null } else { json!(pause) }}),
            if rid.is_empty() { None } else { Some(rid) },
        );
    }
    manager.release_slot(handle);
    if let Some(agent) = agent {
        agent.close(manager);
    }
    pi::kill_live_for_project(project_id, &["finding-review"]);
    *lock(&handle.status) = "done".into();
}

pub fn run_project_loop(manager: &RunManager, handle: &Arc<RunHandle>) {
    let project_id = handle.project_id.clone();
    let settings = manager.settings_snapshot();
    let Some(project) = get_project(manager.db(), &settings, &project_id)
        .ok()
        .flatten()
    else {
        *lock(&handle.status) = "done".into();
        return;
    };
    if let Some(reason) = gate_closed_env(manager.db(), &settings, &project) {
        *lock(&handle.status) = "done".into();
        let _ = update_status(manager.db(), &project_id, "idle");
        emit(
            manager.db(),
            &project_id,
            "log",
            &json!({"level": "warn", "message": reason}),
            None,
        );
        emit(
            manager.db(),
            &project_id,
            "status",
            &json!({"status": "stopped", "reason": "env_closed"}),
            None,
        );
        return;
    }
    let target = val_str(&project, "target");
    let benchmark = is_benchmark_sub(&project);
    if !target.trim().is_empty() && !benchmark {
        if let Err(e) = assert_safe_project_target(&target) {
            *lock(&handle.status) = "done".into();
            let _ = update_status(manager.db(), &project_id, "error");
            emit(
                manager.db(),
                &project_id,
                "log",
                &json!({"level": "error", "message": e}),
                None,
            );
            emit(
                manager.db(),
                &project_id,
                "status",
                &json!({"status": "error", "reason": "unsafe_target"}),
                None,
            );
            return;
        }
    }
    if !pi::llm_api_key_configured(&settings) {
        *lock(&handle.status) = "done".into();
        let _ = update_status(manager.db(), &project_id, "error");
        emit(
            manager.db(),
            &project_id,
            "log",
            &json!({"level": "error", "message": pi::llm_key_missing_message()}),
            None,
        );
        emit(
            manager.db(),
            &project_id,
            "status",
            &json!({"status": "error", "reason": "llm_key_missing"}),
            None,
        );
        return;
    }
    let _ = update_status(manager.db(), &project_id, "queued");
    emit(
        manager.db(),
        &project_id,
        "status",
        &json!({"status": "queued", "reason": "concurrency"}),
        None,
    );
    let objective = project
        .get("config")
        .and_then(|c| c.get("objective"))
        .and_then(|v| v.as_str())
        .unwrap_or(&settings.default_objective)
        .to_string();
    let kind = hunt_slot_kind(Some(&project), Some(&objective));
    *lock(&handle.slot_kind) = kind.clone();
    if !manager.acquire_slot(&project_id, &kind, &handle.cancel) {
        *lock(&handle.status) = "done".into();
        return;
    }
    handle.slot_held.store(true, Ordering::SeqCst);
    let rid = match create_run(manager.db(), &project_id) {
        Ok(rid) => rid,
        Err(e) => {
            let transient = is_transient_resource_error(&e);
            conclude(
                manager,
                handle,
                None,
                "",
                false,
                0,
                &e,
                if transient { "" } else { "error" },
            );
            if transient {
                let _ = update_status(manager.db(), &project_id, "idle");
            }
            return;
        }
    };
    *lock(&handle.run_id) = rid.clone();
    *lock(&handle.status) = "running".into();
    let _ = update_status(manager.db(), &project_id, "running");
    let mut cfg = read_config(manager.db(), &project_id);
    let prev_reason = cfg
        .get("completion_reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if let Some(obj) = cfg.as_object_mut() {
        obj.remove("completion_reason");
        let _ = write_config(manager.db(), &project_id, &cfg);
    }
    emit(
        manager.db(),
        &project_id,
        "status",
        &json!({"status": "running", "run_id": rid}),
        Some(&rid),
    );
    let mut project = project;
    if let Some(parent_id) = project
        .get("parent_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        if let Ok(Some(parent)) =
            get_project(manager.db(), &manager.settings_snapshot(), &parent_id)
        {
            project = attach_parent_brief_hint(&project, Some(&parent));
        }
    }
    let agent = Arc::new(ProjectAgent::open(
        manager.inner.db.clone(),
        Arc::clone(&manager.inner.settings),
        &project,
        handle.cancel.clone(),
    ));
    agent.set_run(&rid);
    *lock(&handle.agent) = Some(agent.clone());
    let foothold = graph_has_getshell(manager.db(), &project_id);
    let reset = hunt_should_reset(
        handle.hard_restart,
        if prev_reason.is_empty() {
            None
        } else {
            Some(prev_reason.as_str())
        },
        foothold,
    );
    let mut hunt = if reset {
        HuntClock::empty()
    } else {
        HuntClock::from_config(&read_config(manager.db(), &project_id))
    };
    if !reset && hunt.turn <= 0 {
        if let Some(prev) = previous_run(manager.db(), &project_id, &rid) {
            let last = last_status_turn(manager.db(), &project_id, &row_str(&prev, "id"));
            let run_turns = prev.get("turns").and_then(|v| v.as_i64()).unwrap_or(0);
            hunt.turn = run_turns.max(last).max(hunt.turn);
        }
    }
    if !reset {
        if let Ok(supervised) = load_supervised_turns(manager.db(), &project_id) {
            hunt.turn = resume_completed_turn(hunt.turn, &supervised);
        }
    }
    let mut turn = hunt.turn;
    let mut empty_rounds = if reset { 0 } else { hunt.empty_rounds };
    let mut idle_plans = if reset { 0 } else { hunt.idle_plans };
    let (mut nodes, _, mut findings) = counts(manager.db(), &project_id);
    let started = Instant::now()
        .checked_sub(Duration::from_secs_f64(if reset {
            0.0
        } else {
            hunt.elapsed_sec
        }))
        .unwrap_or_else(Instant::now);
    let settings = manager.settings_snapshot();
    let hard = runtime_hard_stop_sec(&settings, Some(&objective), 1).max(0);
    let max_turns = max_turns_for(&settings, Some(&objective));
    let plans_limit = settings.graph_idle_empty_plans;
    let mut summary = String::new();
    let mut pause = String::new();
    while !handle.cancel.load(Ordering::SeqCst) {
        if handle.goal_stop.load(Ordering::SeqCst) {
            pause = "goal_reached".into();
            break;
        }
        let elapsed = started.elapsed().as_secs_f64();
        if hard > 0 && elapsed >= hard as f64 {
            pause = "runtime_cap".into();
            break;
        }
        if max_turns > 0 && turn >= max_turns {
            pause = "turn_cap".into();
            break;
        }
        turn += 1;
        let (n2, e2, f2) = counts(manager.db(), &project_id);
        let graph_summary = format!("节点 {n2} · 边 {e2} · 发现 {f2}");
        let human = manager.take_human_interrupt(&project_id);
        let steering = manager.drain_steering(&project_id).join("\n");
        let instruction = build_turn_instruction(
            turn,
            &target,
            &graph_summary,
            &intents_text(manager.db(), &project_id),
            &steering,
            &agent.brief,
            human,
        );
        match agent.run_turn(&instruction) {
            Ok(result) => {
                summary = result.text;
                let (n3, _, f3) = counts(manager.db(), &project_id);
                if n3 > nodes || f3 > findings {
                    empty_rounds = 0;
                    idle_plans = 0;
                } else if !human {
                    empty_rounds += 1;
                    idle_plans += 1;
                }
                nodes = n3;
                findings = f3;
            }
            Err(e) if e == "stopped" || handle.cancel.load(Ordering::SeqCst) => break,
            Err(e) if is_transient_resource_error(&e) => {
                pause.clear();
                summary = e;
                let _ = update_status(manager.db(), &project_id, "idle");
                break;
            }
            Err(e) => {
                summary = e;
                empty_rounds += 1;
                idle_plans += 1;
            }
        }
        let consulted = if let Some(hook) = lock(&CONSULT_HOOK).clone() {
            let steer = hook(&project_id, turn, &summary, &rid);
            if !steer.trim().is_empty() {
                let mut queue = lock(&handle.steering);
                if queue.len() < 100 {
                    queue.push_back(steer);
                }
            }
            true
        } else {
            false
        };
        if !consulted {
            emit(
                manager.db(),
                &project_id,
                "supervisor",
                &json!({"kind": "skip", "turn": turn, "reason": "recorded"}),
                Some(&rid),
            );
        }
        hunt.turn = turn;
        hunt.elapsed_sec = started.elapsed().as_secs_f64();
        hunt.empty_rounds = empty_rounds;
        hunt.idle_plans = idle_plans;
        let mut stamped = hunt.to_json();
        if let Some(obj) = stamped.as_object_mut() {
            obj.insert("elapsed_as_of".into(), json!(wall_now()));
        }
        let mut cfg = read_config(manager.db(), &project_id);
        if let Some(obj) = cfg.as_object_mut() {
            obj.insert("hunt".into(), stamped);
            let _ = write_config(manager.db(), &project_id, &cfg);
        }
        let turns_now = turn;
        let _ = manager.db().execute(
            "UPDATE runs SET turns=?1 WHERE id=?2",
            &[&turns_now as &dyn ToSql, &rid],
        );
        if empty_rounds >= EMPTY_ROUND_STOP {
            pause = "empty_rounds".into();
            emit(
                manager.db(),
                &project_id,
                "log",
                &json!({"level": "warn", "message": format!("已连续 {empty_rounds} 轮没有新节点也没有新漏洞")}),
                Some(&rid),
            );
            break;
        }
        if clocks_graph_idle_plans(idle_plans, plans_limit) {
            pause = "graph_idle".into();
            break;
        }
        kick_review(agent.clone(), manager.clone());
    }
    conclude(
        manager,
        handle,
        Some(agent.as_ref()),
        &rid,
        false,
        turn,
        &summary,
        &pause,
    );
}

pub fn resume_queued(manager: &RunManager) -> usize {
    let Ok(rows) = manager.db().query(
        "SELECT id FROM projects WHERE status='queued' AND IFNULL(archived,0)=0 ORDER BY COALESCE(queued_at, updated_at) ASC",
        &[],
    ) else {
        return 0;
    };
    let mut started = 0;
    for row in rows {
        let pid = row_str(&row, "id");
        if pid.is_empty() || manager.is_running(&pid) || manager.is_queued(&pid) {
            continue;
        }
        manager.start(&pid, false);
        started += 1;
    }
    started
}

pub fn start_saved_hunts(manager: &RunManager, db_running: &[String]) -> Vec<String> {
    let saved = take_resume_ids(&manager.settings_snapshot());
    let rt_cap = manager.inner.redteam.limit().max(1);
    let ctf_cap = manager.inner.ctf.limit().max(1);
    let mut picked = Vec::new();
    let mut idle_ids = Vec::new();
    let mut rt_n = 0;
    let mut ctf_n = 0;
    for pid in pick_resume_ids(db_running, &saved, 0) {
        let proj = get_project(manager.db(), &manager.settings_snapshot(), &pid)
            .ok()
            .flatten();
        if !should_autoresume(proj.as_ref()) {
            if proj.as_ref().map(|p| val_str(p, "status")).as_deref() == Some("running") {
                idle_ids.push(pid);
            }
            continue;
        }
        if proj.as_ref().map(|p| val_str(p, "status")).as_deref() != Some("running") {
            continue;
        }
        if let Some(parent_id) = proj
            .as_ref()
            .and_then(|p| p.get("parent_id"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Ok(Some(parent)) = get_project(manager.db(), &manager.settings_snapshot(), parent_id) {
                let pcfg = parent.get("config").cloned().unwrap_or(json!({}));
                let closed = pcfg.get("env_closed").and_then(|v| v.as_bool()).unwrap_or(false);
                let reason = pcfg.get("completion_reason").and_then(|v| v.as_str()).unwrap_or("");
                if closed || reason == "env_closed" || reason == "env_unreachable" {
                    idle_ids.push(pid);
                    continue;
                }
            }
        }
        let kind = hunt_slot_kind(proj.as_ref(), None);
        if kind == "ctf" {
            if ctf_n >= ctf_cap {
                idle_ids.push(pid);
                continue;
            }
            ctf_n += 1;
        } else if rt_n >= rt_cap {
            idle_ids.push(pid);
            continue;
        } else {
            rt_n += 1;
        }
        picked.push(pid);
    }
    for pid in db_running {
        if !picked.contains(pid) && !idle_ids.contains(pid) {
            idle_ids.push(pid.clone());
        }
    }
    for pid in &idle_ids {
        let _ = update_status(manager.db(), pid, "idle");
    }
    for pid in &picked {
        manager.start(pid, false);
    }
    for pid in picked.iter().chain(db_running.iter()) {
        if manager.is_running(pid) || manager.is_queued(pid) {
            continue;
        }
        let _ = update_status(manager.db(), pid, "idle");
    }
    picked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::collections::HashMap;

    fn temp_pair() -> (Arc<Db>, Settings) {
        let dir =
            std::env::temp_dir().join(format!("atk-eng-{}-{}", std::process::id(), new_id("t")));
        let _ = fs::create_dir_all(&dir);
        let mut env = HashMap::new();
        env.insert("ATKBRAIN_DATA_DIR".into(), dir.display().to_string());
        env.insert(
            "ATKBRAIN_DB_PATH".into(),
            dir.join("t.db").display().to_string(),
        );
        env.insert(
            "ATKBRAIN_WORKSPACES_DIR".into(),
            dir.join("ws").display().to_string(),
        );
        let settings = Settings::from_map(&env, &dir);
        let db = Db::open(&settings.db_path).unwrap();
        (Arc::new(db), settings)
    }

    #[test]
    fn supervised_turns_are_a_list_not_a_set() {
        let payloads = vec![
            json!({"turn": 2}),
            json!({"turn": 1}),
            json!({"turn": 2}),
            json!({"turn": 0}),
            json!({"kind": "skip"}),
        ];
        let list: Vec<i64> = supervised_turns_from_payloads(&payloads);
        assert_eq!(list, vec![1, 2]);
        assert_eq!(list[0], 1);
        assert!(list.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(resume_completed_turn(2, &list), 2);
        assert_eq!(resume_completed_turn(4, &list), 3);
        assert_eq!(resume_completed_turn(0, &list), 2);
        let (db, _) = temp_pair();
        let pid = "p-turns";
        for turn in [2, 1, 2] {
            emit(
                &db,
                pid,
                "supervisor",
                &json!({"turn": turn, "kind": "skip"}),
                None,
            );
        }
        let loaded: Vec<i64> = load_supervised_turns(&db, pid).unwrap();
        assert_eq!(loaded, vec![1, 2]);
        assert_eq!(
            std::any::type_name_of_val(&loaded),
            std::any::type_name::<Vec<i64>>()
        );
    }

    #[test]
    fn unsafe_target_stops_before_process_start() {
        let (db, settings) = temp_pair();
        let before = pi::live_pi_count();
        let ts = now();
        let id = "p-loop";
        let status = "idle";
        let kind = "single";
        let name = "loop";
        let target = "127.0.0.1";
        let ports = "[]";
        let scope = "{}";
        let cfg = "{\"objective\":\"agent\"}";
        db.execute(
            "INSERT INTO projects(id, name, kind, target, ports, scope, config, status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            &[&id as &dyn ToSql, &name, &kind, &target, &ports, &scope, &cfg, &status, &ts],
        )
        .unwrap();
        let manager = RunManager::new(db.clone(), settings);
        let handle = manager.start(id, false);
        let start = Instant::now();
        while !handle.finished.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(handle.finished.load(Ordering::SeqCst));
        let row = db
            .query_one(
                "SELECT status FROM projects WHERE id=?1",
                &[&id as &dyn ToSql],
            )
            .unwrap()
            .unwrap();
        assert_eq!(row.get("status").and_then(|v| v.as_str()), Some("error"));
        assert_eq!(pi::live_pi_count(), before);
    }

    #[test]
    fn cap_snapshot_and_cancel_status() {
        let (db, settings) = temp_pair();
        let manager = RunManager::new(db, settings);
        assert_eq!(manager.set_claude_per_project(6), 6);
        assert_eq!(manager.snapshot()["claude"]["per_project"], 6);
        assert_eq!(manager.set_claude_per_project(99), 8);
        assert_eq!(manager.snapshot()["claude"]["limit"], 32);
        assert_eq!(cancel_project_status(false, "zombie", true), None);
        assert_eq!(cancel_project_status(true, "running", true), Some("idle"));
        assert_eq!(
            cancel_project_status(false, "running", true),
            Some("running")
        );
        assert!(!should_consult_after_exec_fault("hang", false));
        assert!(should_consult_after_exec_fault("empty_turn", false));
    }
}
