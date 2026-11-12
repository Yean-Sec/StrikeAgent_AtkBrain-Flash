//! 复核任务队列、开关，以及控制台右下角说明。
//! 说明助手不带工具，并且不给新的命令。
//! 二次验证提示里要求重放 PoC、再打一遍的正文没有移植。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use crate::config::Settings;
use crate::db::Db;
use crate::engine::RunManager;
use crate::i18n::{self, msg};
use crate::pi::PiSession;

const KEY_SECONDARY: &str = "finding_secondary_verify";
const KEY_RATING: &str = "finding_redteam_rating";
pub const REVIEW_ATTEMPT_CAP: i64 = 3;
const WAIT_DETAILS: &[&str] = &["已拉起 Pi，等待模型", "等待模型回复"];
const EXPLAIN_SYSTEM: &str = "你是控制台右下角的说明助手，这条 Pi 会话一直留着。\n只用下面给出的统计和记录回答，数字不要自己推测。\n问数量就先给数字。用中文两三句话，直接回答这一问。\n不要建议下一步，不要给出新的命令，不要提及其他项目。";

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

struct Book {
    jobs: HashMap<String, Map<String, Value>>,
    active: HashMap<(String, String, String), String>,
    draining: HashSet<String>,
}

fn book() -> &'static Mutex<Book> {
    static B: OnceLock<Mutex<Book>> = OnceLock::new();
    B.get_or_init(|| {
        Mutex::new(Book {
            jobs: HashMap::new(),
            active: HashMap::new(),
            draining: HashSet::new(),
        })
    })
}

fn explain_slot() -> &'static Mutex<Option<PiSession>> {
    static S: OnceLock<Mutex<Option<PiSession>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

fn explain_lock() -> &'static Mutex<()> {
    static L: OnceLock<Mutex<()>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

#[derive(Debug)]
pub struct ReviewBusy(pub String);

impl std::fmt::Display for ReviewBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn as_bool(value: Option<&Value>, default: bool) -> bool {
    match value {
        None | Some(Value::Null) => default,
        Some(Value::Bool(v)) => *v,
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0 || n.as_f64().unwrap_or(0.0) != 0.0,
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        Some(_) => default,
    }
}

fn settings_path(settings: &Settings) -> PathBuf {
    settings.data_dir.join("proxy-settings.json")
}

fn read_settings_file(settings: &Settings) -> Map<String, Value> {
    let path = settings_path(settings);
    let Ok(text) = fs::read_to_string(path) else {
        return Map::new();
    };
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn merge_settings_file(settings: &Settings, updates: &Map<String, Value>) {
    let path = settings_path(settings);
    let mut data = read_settings_file(settings);
    for (k, v) in updates {
        data.insert(k.clone(), v.clone());
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(text) = serde_json::to_string_pretty(&Value::Object(data)) {
        let _ = fs::write(path, format!("{text}\n"));
    }
}

pub fn get_review_flags(settings: &Settings) -> Value {
    let data = read_settings_file(settings);
    json!({
        "secondary_verify": as_bool(data.get(KEY_SECONDARY), true),
        "redteam_rating": as_bool(data.get(KEY_RATING), true),
    })
}

pub fn set_review_flags(
    settings: &Settings,
    secondary_verify: Option<bool>,
    redteam_rating: Option<bool>,
) -> Value {
    let mut updates = Map::new();
    if let Some(v) = secondary_verify {
        updates.insert(KEY_SECONDARY.into(), json!(v));
    }
    if let Some(v) = redteam_rating {
        updates.insert(KEY_RATING.into(), json!(v));
    }
    if !updates.is_empty() {
        merge_settings_file(settings, &updates);
    }
    get_review_flags(settings)
}

fn modes_conflict(held: &str, want: &str) -> bool {
    held == want || held == "both" || want == "both"
}

fn busy_for(book: &Book, pid: &str, fid: &str, mode: &str) -> Option<String> {
    for ((p, f, m), jid) in &book.active {
        if p == pid && f == fid && modes_conflict(m, mode) {
            return Some(jid.clone());
        }
    }
    None
}

fn job_value(job: &Map<String, Value>) -> Value {
    Value::Object(job.clone())
}

pub fn snapshot(job_id: &str) -> Option<Value> {
    let book = lock(book());
    book.jobs.get(job_id).map(job_value)
}

pub fn list_active() -> Vec<Value> {
    let book = lock(book());
    let mut out = Vec::new();
    for jid in book.active.values() {
        if let Some(job) = book.jobs.get(jid) {
            let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("");
            if status == "queued" || status == "running" {
                out.push(job_value(job));
            }
        }
    }
    out
}

fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn note_review_pid(job_id: &str, pid: i32) {
    if pid <= 0 {
        return;
    }
    let mut book = lock(book());
    if let Some(job) = book.jobs.get_mut(job_id) {
        job.insert("pi_pid".into(), json!(pid));
    }
}

pub fn pulse_review(job_id: &str) {
    let mut book = lock(book());
    let Some(job) = book.jobs.get_mut(job_id) else {
        return;
    };
    if job.get("status").and_then(|v| v.as_str()) != Some("running") {
        return;
    }
    job.insert("updated_at".into(), json!(now_secs()));
    let cur = job
        .get("detail")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if cur.is_empty() || WAIT_DETAILS.contains(&cur.as_str()) {
        job.insert("detail".into(), json!("等待模型回复"));
    }
}

pub fn note_review_beat(job_id: &str, detail: &str) {
    let text = detail.trim();
    if text.is_empty() {
        return;
    }
    let mut book = lock(book());
    let Some(job) = book.jobs.get_mut(job_id) else {
        return;
    };
    if job.get("status").and_then(|v| v.as_str()) != Some("running") {
        return;
    }
    let clipped: String = text.chars().take(80).collect();
    job.insert("detail".into(), json!(clipped));
    job.insert("updated_at".into(), json!(now_secs()));
}

pub fn mark_running(job_id: &str, detail: &str) {
    let mut book = lock(book());
    let Some(job) = book.jobs.get_mut(job_id) else {
        return;
    };
    let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if status != "queued" && status != "running" {
        return;
    }
    let now = now_secs();
    job.insert("status".into(), json!("running"));
    if job
        .get("started_at")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
        <= 0.0
    {
        job.insert("started_at".into(), json!(now));
    }
    let text = detail.trim();
    if !text.is_empty() {
        let clipped: String = text.chars().take(80).collect();
        job.insert("detail".into(), json!(clipped));
    }
    job.insert("updated_at".into(), json!(now));
}

pub fn review_state(pid: &str, fid: &str) -> Value {
    let mut jobs = lock(book());
    let mut out = Map::new();
    let now = now_secs();
    let keys: Vec<((String, String, String), String)> = jobs
        .active
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for ((p, f, m), jid) in keys {
        if p != pid || f != fid {
            continue;
        }
        let Some(job) = jobs.jobs.get(&jid).cloned() else {
            continue;
        };
        let status = job.get("status").and_then(|v| v.as_str()).unwrap_or("");
        if status != "queued" && status != "running" {
            continue;
        }
        let created = job
            .get("created_at")
            .and_then(|v| v.as_f64())
            .unwrap_or(now);
        let started = job
            .get("started_at")
            .and_then(|v| v.as_f64())
            .filter(|n| *n > 0.0)
            .unwrap_or(created);
        let updated = job
            .get("updated_at")
            .and_then(|v| v.as_f64())
            .unwrap_or(created);
        let mut status = status.to_string();
        let mut detail = job
            .get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pi_pid = job.get("pi_pid").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
        if status == "running" && pi_pid > 0 && !pid_alive(pi_pid) {
            status = "dead".into();
            detail = "Pi 进程已退出".into();
            drop(jobs);
            release(&jid, "error", "pi exited");
            jobs = lock(book());
        }
        let view = json!({
            "status": status,
            "started_at": if status == "running" { started } else { created },
            "updated_at": updated,
            "detail": detail,
        });
        let modes: Vec<&str> = if m == "both" {
            vec!["secondary", "rating"]
        } else {
            vec![m.as_str()]
        };
        for mode in modes {
            if mode == "secondary" || mode == "rating" {
                out.insert(mode.to_string(), view.clone());
            }
        }
    }
    Value::Object(out)
}

pub fn claim(pid: &str, fid: &str, mode: &str, source: &str) -> Result<Value, ReviewBusy> {
    let mode = mode.trim().to_ascii_lowercase();
    if mode != "secondary" && mode != "rating" && mode != "both" {
        return Err(ReviewBusy("mode".into()));
    }
    let mut book = lock(book());
    if busy_for(&book, pid, fid, &mode).is_some() {
        return Err(ReviewBusy(msg(
            "review_busy",
            Some(i18n::get_locale()),
            &[],
        )));
    }
    let jid = crate::db::new_id("");
    let jid = if jid.len() > 16 {
        jid.chars().take(16).collect()
    } else {
        jid
    };
    let now = now_secs();
    let mut job = Map::new();
    job.insert("id".into(), json!(jid));
    job.insert("job_id".into(), json!(jid));
    job.insert("project_id".into(), json!(pid));
    job.insert("finding_id".into(), json!(fid));
    job.insert("mode".into(), json!(mode));
    job.insert("source".into(), json!(source));
    job.insert("status".into(), json!("queued"));
    job.insert("error".into(), json!(""));
    job.insert("detail".into(), json!("排队，尚未拉起 Pi"));
    job.insert("created_at".into(), json!(now));
    job.insert("updated_at".into(), json!(now));
    job.insert("started_at".into(), json!(0.0));
    let view = job_value(&job);
    book.jobs.insert(jid.clone(), job);
    book.active
        .insert((pid.to_string(), fid.to_string(), mode), jid);
    Ok(view)
}

pub fn try_claim(pid: &str, fid: &str, mode: &str, source: &str) -> Option<Value> {
    claim(pid, fid, mode, source).ok()
}

pub fn release(job_id: &str, status: &str, error: &str) {
    let mut book = lock(book());
    let Some(job) = book.jobs.get_mut(job_id) else {
        return;
    };
    job.insert("status".into(), json!(status));
    job.insert("error".into(), json!(error));
    job.insert("updated_at".into(), json!(now_secs()));
    let key = (
        job.get("project_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        job.get("finding_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        job.get("mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    );
    if book.active.get(&key).map(|s| s.as_str()) == Some(job_id) {
        book.active.remove(&key);
    }
}

pub fn review_attempt_open(
    attempts: &HashMap<(String, String), i64>,
    fid: &str,
    mode: &str,
) -> bool {
    attempts
        .get(&(fid.to_string(), mode.to_string()))
        .copied()
        .unwrap_or(0)
        < REVIEW_ATTEMPT_CAP
}

pub fn note_review_attempt(
    attempts: &mut HashMap<(String, String), i64>,
    fid: &str,
    mode: &str,
) -> i64 {
    let key = (fid.to_string(), mode.to_string());
    let n = attempts.get(&key).copied().unwrap_or(0) + 1;
    attempts.insert(key, n);
    n
}

fn row_str(row: &Map<String, Value>, key: &str) -> String {
    row.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn findings_pending_review(
    db: &Db,
    settings: &Settings,
    project_id: &str,
) -> Result<Vec<Value>, String> {
    let flags = get_review_flags(settings);
    let do_sec = flags
        .get("secondary_verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let do_rate = flags
        .get("redteam_rating")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if !do_sec && !do_rate {
        return Ok(Vec::new());
    }
    let rows = db.query(
        "SELECT id, title, severity, category, verification_status, secondary_verified, redteam_rating, node_key, description, evidence, poc_curl, poc_python FROM findings WHERE project_id=?1 ORDER BY created_at DESC",
        &[&project_id as &dyn rusqlite::ToSql],
    )?;
    let mut out = Vec::new();
    for row in rows {
        let status = row_str(&row, "verification_status");
        let secondary = row
            .get("secondary_verified")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            != 0;
        let rating = row_str(&row, "redteam_rating");
        let need_sec = do_sec && !secondary && status != "excluded";
        let need_rate = do_rate && rating.trim().is_empty();
        if !need_sec && !need_rate {
            continue;
        }
        let mode = if need_sec && need_rate {
            "both"
        } else if need_sec {
            "secondary"
        } else {
            "rating"
        };
        out.push(json!({
            "id": row.get("id").cloned().unwrap_or(Value::Null),
            "title": row.get("title").cloned().unwrap_or(Value::Null),
            "severity": row.get("severity").cloned().unwrap_or(Value::Null),
            "category": row.get("category").cloned().unwrap_or(Value::Null),
            "verification_status": status,
            "secondary_verified": secondary,
            "redteam_rating": rating,
            "node_key": row.get("node_key").cloned().unwrap_or(Value::Null),
            "description": row.get("description").cloned().unwrap_or(Value::Null),
            "evidence": row.get("evidence").cloned().unwrap_or(Value::Null),
            "poc_curl": row.get("poc_curl").cloned().unwrap_or(Value::Null),
            "poc_python": row.get("poc_python").cloned().unwrap_or(Value::Null),
            "_review_mode": mode,
        }));
    }
    Ok(out)
}

pub fn schedule_drain(manager: &RunManager, project: &Value) {
    let pid = project
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if pid.is_empty() {
        return;
    }
    {
        let book = lock(book());
        if book.draining.contains(&pid) {
            return;
        }
    }
    if manager.shutting_down() {
        return;
    }
    if let Some(agent) = manager.live_agent(&pid) {
        crate::engine::kick_review(agent, manager.clone());
        return;
    }
    {
        let mut book = lock(book());
        if !book.draining.insert(pid.clone()) {
            return;
        }
    }
    let manager = manager.clone();
    let project = project.clone();
    thread::spawn(move || {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drain(&manager, &project)));
        let _ = result;
        lock(book()).draining.remove(&pid);
    });
}

fn drain(manager: &RunManager, project: &Value) {
    let pid = project.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut attempts: HashMap<(String, String), i64> = HashMap::new();
    let mut announced = false;
    loop {
        if manager.shutting_down() {
            return;
        }
        if let Some(agent) = manager.live_agent(pid) {
            crate::engine::kick_review(agent, manager.clone());
            return;
        }
        let settings = manager.settings_snapshot();
        let pending = findings_pending_review(manager.db(), &settings, pid).unwrap_or_default();
        let mut picked_item = None;
        let mut picked_mode = String::new();
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
                if (cand == "secondary" || cand == "rating")
                    && review_attempt_open(&attempts, fid, cand)
                {
                    picked_item = Some(finding.clone());
                    picked_mode = cand.to_string();
                    break;
                }
            }
            if picked_item.is_some() {
                break;
            }
        }
        let Some(mut item) = picked_item else { return };
        if !announced {
            announced = true;
            crate::engine::emit(
                manager.db(),
                pid,
                "log",
                &json!({"level": "info", "message": "猎面已停，未完成的二次验证会继续做到队列结束。"}),
                None,
            );
        }
        let fid = item
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let Some(job) = try_claim(pid, &fid, &picked_mode, "auto") else {
            note_review_attempt(&mut attempts, &fid, &picked_mode);
            continue;
        };
        let jid = job
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        item["_review_mode"] = json!(picked_mode);
        item["_job_id"] = json!(jid);
        match crate::engine::run_review_job(manager, project, &item, &picked_mode, &jid) {
            Ok(()) => release(&jid, "done", ""),
            Err(e) => release(&jid, "error", &e.chars().take(240).collect::<String>()),
        }
        let settings = manager.settings_snapshot();
        let still = findings_pending_review(manager.db(), &settings, pid).unwrap_or_default();
        let still_needs = still.iter().any(|row| {
            row.get("id").and_then(|v| v.as_str()) == Some(fid.as_str()) && {
                let need = row
                    .get("_review_mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("both");
                need == picked_mode || need == "both"
            }
        });
        if still_needs {
            let _ = note_review_attempt(&mut attempts, &fid, &picked_mode);
        }
    }
}

pub fn resume_pending_reviews(manager: &RunManager) {
    if manager.shutting_down() {
        return;
    }
    let Ok(rows) = manager.db().query("SELECT id, status FROM projects", &[]) else {
        return;
    };
    for row in rows {
        if row.get("status").and_then(|v| v.as_str()).unwrap_or("") == "running" {
            continue;
        }
        let pid = row_str(&row, "id");
        if pid.is_empty() {
            continue;
        }
        let settings = manager.settings_snapshot();
        let Ok(pending) = findings_pending_review(manager.db(), &settings, &pid) else {
            continue;
        };
        if pending.is_empty() {
            continue;
        }
        if let Ok(Some(project)) = crate::projects::get_project(manager.db(), &settings, &pid) {
            schedule_drain(manager, &project);
        }
    }
}

pub fn start_manual(
    manager: &RunManager,
    project: &Value,
    finding: &Value,
    mode: &str,
) -> Result<Value, ReviewBusy> {
    let pid = project.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let fid = finding.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let job = claim(pid, fid, mode, "manual")?;
    let jid = job
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let manager = manager.clone();
    let project = project.clone();
    let finding = finding.clone();
    let mode = mode.to_string();
    thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::engine::run_review_job(&manager, &project, &finding, &mode, &jid)
        }));
        match result {
            Ok(Ok(())) => release(&jid, "done", ""),
            Ok(Err(e)) => release(&jid, "error", &e.chars().take(240).collect::<String>()),
            Err(_) => release(&jid, "error", "review panicked"),
        }
    });
    Ok(snapshot(&job.get("id").and_then(|v| v.as_str()).unwrap_or("")).unwrap_or(job))
}

fn payload_of(row: &Map<String, Value>) -> Value {
    match row.get("payload") {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

fn summary(payload: &Value) -> String {
    let command = payload
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !command.is_empty() {
        return command.chars().take(500).collect();
    }
    let url = payload
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let method = payload
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !url.is_empty() {
        return format!("{method} {url}").trim().chars().take(500).collect();
    }
    payload
        .get("tool")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(80)
        .collect()
}

pub fn open_tool(manager: &RunManager, project_id: &str) -> Option<Value> {
    if !manager.is_running(project_id) {
        return None;
    }
    let rows = manager
        .db()
        .query(
            "SELECT id, type, ts, payload FROM events WHERE project_id=?1 AND type IN ('tool', 'tool_result') ORDER BY id DESC LIMIT 80",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .unwrap_or_default();
    let mut open_rows: Vec<(Value, Value)> = Vec::new();
    for row in rows.into_iter().rev() {
        let kind = row_str(&row, "type");
        let payload = payload_of(&row);
        if kind == "tool" {
            open_rows.push((row.get("ts").cloned().unwrap_or(Value::Null), payload));
            continue;
        }
        if kind != "tool_result" {
            continue;
        }
        let name = payload.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let mut idx = None;
        for i in (0..open_rows.len()).rev() {
            let have = open_rows[i]
                .1
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name.is_empty() || have == name {
                idx = Some(i);
                break;
            }
        }
        if let Some(i) = idx {
            open_rows.remove(i);
        }
    }
    let inflight = manager
        .live_agent(project_id)
        .map(|a| a.cmd_inflight())
        .unwrap_or(0);
    if open_rows.is_empty() && inflight <= 0 {
        return None;
    }
    let (ts, chosen) = open_rows
        .last()
        .cloned()
        .unwrap_or((Value::Null, Value::Null));
    Some(json!({
        "tool": chosen.get("tool").and_then(|v| v.as_str()).unwrap_or("run_cmd"),
        "command": summary(&chosen),
        "cmd_inflight": if inflight > 0 { inflight } else { chosen.get("cmd_inflight").and_then(|v| v.as_i64()).unwrap_or(1) },
        "ts": ts,
    }))
}

fn state_label(raw: &str) -> String {
    match raw {
        "idle" => "空闲",
        "running" => "运行中",
        "done" => "已结束",
        "error" => "出错",
        "stopping" => "正在停止",
        "queued" => "排队中",
        "starting" => "正在启动",
        other => other,
    }
    .to_string()
}

pub fn plain_reply(name: &str, state: &str, lines: &[String]) -> String {
    let title = if name.trim().is_empty() {
        "这个项目"
    } else {
        name.trim()
    };
    let last = lines.last().map(|s| s.as_str()).unwrap_or("还没有执行记录");
    let head = if state == "运行中" {
        format!("「{title}」正在运行，当前没有未结束的长时间命令。")
    } else if state == "排队中" {
        format!("「{title}」在排队，命令还没开始。")
    } else {
        format!("「{title}」现在没有在跑命令，状态是{state}。")
    };
    format!("{head}最近记录：{last}")
}

fn clip(value: &str, limit: usize) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

fn recent_line(kind: &str, payload: &Value) -> String {
    if kind == "tool" {
        return format!(
            "开始 {}：{}",
            clip(
                payload
                    .get("tool")
                    .and_then(|v| v.as_str())
                    .unwrap_or("工具"),
                40
            ),
            summary(payload).chars().take(120).collect::<String>()
        );
    }
    if kind == "tool_result" {
        let err = clip(
            payload.get("error").and_then(|v| v.as_str()).unwrap_or(""),
            80,
        );
        let base = format!(
            "结束 {}",
            clip(
                payload
                    .get("tool")
                    .and_then(|v| v.as_str())
                    .unwrap_or("工具"),
                40
            )
        );
        return if err.is_empty() {
            base
        } else {
            format!("{base}，出错：{err}")
        };
    }
    if kind == "text" {
        return format!(
            "说明：{}",
            clip(
                payload.get("text").and_then(|v| v.as_str()).unwrap_or(""),
                120
            )
        );
    }
    if kind == "log" || kind == "thought" {
        return format!(
            "记录：{}",
            clip(
                payload
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                120
            )
        );
    }
    if kind == "shell" {
        return "记录：会话状态有更新".into();
    }
    String::new()
}

pub fn project_glance(manager: &RunManager, project_id: &str) -> Value {
    let row = manager
        .db()
        .query_one(
            "SELECT name, status FROM projects WHERE id=?1",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .ok()
        .flatten();
    let Some(row) = row else {
        return json!({"missing": true, "name": "", "state": "", "lines": []});
    };
    let state = if manager.is_running(project_id) {
        "运行中".into()
    } else if manager.is_queued(project_id) {
        "排队中".into()
    } else {
        state_label(row.get("status").and_then(|v| v.as_str()).unwrap_or("idle"))
    };
    let rows = manager
        .db()
        .query(
            "SELECT type, payload FROM events WHERE project_id=?1 ORDER BY id DESC LIMIT 12",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .unwrap_or_default();
    let mut lines = Vec::new();
    for item in rows.into_iter().rev() {
        let text = recent_line(&row_str(&item, "type"), &payload_of(&item));
        if !text.is_empty() {
            lines.push(text);
        }
    }
    if lines.len() > 8 {
        lines = lines[lines.len() - 8..].to_vec();
    }
    json!({"missing": false, "name": row.get("name").and_then(|v| v.as_str()).unwrap_or(""), "state": state, "lines": lines})
}

pub fn project_facts(manager: &RunManager, project_id: &str) -> String {
    let row = manager
        .db()
        .query_one(
            "SELECT name, status FROM projects WHERE id=?1",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .ok()
        .flatten();
    let Some(row) = row else { return String::new() };
    let findings = manager
        .db()
        .query(
            "SELECT title, severity, verification_status, secondary_verified FROM findings WHERE project_id=?1",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .unwrap_or_default();
    let nodes = manager
        .db()
        .query_one(
            "SELECT COUNT(*) AS n FROM nodes WHERE project_id=?1",
            &[&project_id as &dyn rusqlite::ToSql],
        )
        .ok()
        .flatten();
    let node_n = nodes
        .as_ref()
        .and_then(|r| r.get("n"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let total = findings.len();
    let secondary = findings
        .iter()
        .filter(|item| {
            item.get("secondary_verified")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                != 0
        })
        .count();
    let pending = findings
        .iter()
        .filter(|item| item.get("verification_status").and_then(|v| v.as_str()) == Some("pending"))
        .count();
    let excluded = findings
        .iter()
        .filter(|item| item.get("verification_status").and_then(|v| v.as_str()) == Some("excluded"))
        .count();
    let mut by_sev: HashMap<String, i64> = HashMap::new();
    let mut titles = Vec::new();
    for item in &findings {
        let sev = item
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("info")
            .to_string();
        *by_sev.entry(sev).or_insert(0) += 1;
        let title = item
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if !title.is_empty() {
            titles.push(title.chars().take(80).collect::<String>());
        }
    }
    let mut sev_pairs: Vec<_> = by_sev.into_iter().collect();
    sev_pairs.sort();
    let sev_text = if sev_pairs.is_empty() {
        "无".into()
    } else {
        sev_pairs
            .iter()
            .map(|(n, c)| format!("{n} {c}"))
            .collect::<Vec<_>>()
            .join("、")
    };
    let title_text = if titles.is_empty() {
        "无".into()
    } else {
        titles.into_iter().take(12).collect::<Vec<_>>().join("；")
    };
    let run_state = if manager.is_running(project_id) {
        "运行中".into()
    } else if manager.is_queued(project_id) {
        "排队中".into()
    } else {
        row.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("idle")
            .to_string()
    };
    format!(
        "项目：{}\n运行：{run_state}\n图上节点：{node_n}\n漏洞库条目：{total}\n其中已二次验证：{secondary}，待验证：{pending}，二次验证失败：{excluded}\n严重级别：{sev_text}\n漏洞标题：{title_text}",
        row.get("name").and_then(|v| v.as_str()).unwrap_or(project_id)
    )
}

fn explain_session(manager: &RunManager) -> Result<PiSession, String> {
    {
        let current = lock(explain_slot());
        if let Some(sess) = current.as_ref() {
            if sess.alive() {
                return Ok(sess.clone());
            }
        }
    }
    if let Some(old) = lock(explain_slot()).take() {
        old.close();
    }
    let settings = manager.settings_snapshot();
    let work = settings.data_dir.join("explain-pi");
    let _ = fs::create_dir_all(&work);
    let sess = PiSession::with_stop(
        work.to_str().unwrap_or("/tmp"),
        EXPLAIN_SYSTEM,
        "",
        "console-explain",
        false,
        "",
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
    sess.start(&settings)?;
    *lock(explain_slot()) = Some(sess.clone());
    Ok(sess)
}

fn ask_resident(manager: &RunManager, prompt: &str) -> Result<String, String> {
    let _hold = lock(explain_lock());
    let first = (|| {
        let sess = explain_session(manager)?;
        sess.prompt(
            prompt,
            std::time::Duration::from_secs(180),
            std::time::Duration::ZERO,
        )
    })();
    let text = match first {
        Ok(text) => text,
        Err(first) => {
            if let Some(old) = lock(explain_slot()).take() {
                old.close();
            }
            let sess =
                explain_session(manager)
                    .map_err(|e| if e.is_empty() { first.clone() } else { e })?;
            sess.prompt(
                prompt,
                std::time::Duration::from_secs(180),
                std::time::Duration::ZERO,
            )
            .map_err(|second| {
                let msg = if second.is_empty() { first } else { second };
                msg.chars().take(240).collect::<String>()
            })?
        }
    };
    let reply = text.trim().to_string();
    if reply.is_empty() {
        return Err("模型没有返回说明。".into());
    }
    Ok(reply)
}

pub fn explain(
    manager: &RunManager,
    project_id: &str,
    question: &str,
    command: &str,
    output: &str,
    page: &str,
    path: &str,
) -> Result<String, String> {
    let ask = question.trim();
    if ask.is_empty() {
        return Err("需要一个问题".into());
    }
    let mut parts = vec![format!(
        "页面：{}",
        page.chars()
            .chain(if page.is_empty() { path } else { "" }.chars())
            .take(120)
            .collect::<String>()
    )];
    if page.is_empty() && path.is_empty() {
        parts[0] = "页面：当前页".into();
    } else if !page.is_empty() {
        parts[0] = format!("页面：{}", page.chars().take(120).collect::<String>());
    }
    if !path.is_empty() {
        parts.push(format!(
            "路径：{}",
            path.chars().take(180).collect::<String>()
        ));
    }
    let shown_command = command.trim();
    if !project_id.is_empty() {
        let facts = project_facts(manager, project_id);
        if facts.is_empty() {
            return Ok("当前页面上的这个项目不存在。".into());
        }
        parts.push(facts);
        let running = open_tool(manager, project_id);
        let running = if running.is_none() && !shown_command.is_empty() {
            Some(json!({"tool": "run_cmd", "command": shown_command}))
        } else {
            running
        };
        if let Some(running) = running {
            let shown = if !shown_command.is_empty() {
                shown_command.to_string()
            } else {
                running
                    .get("command")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let tool = running
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or("run_cmd");
            parts.push(format!(
                "未结束命令：{tool} {}",
                shown.chars().take(500).collect::<String>()
            ));
            let snippet: String = output.trim().chars().take(800).collect();
            if !snippet.is_empty() {
                parts.push(format!("最近输出：\n{snippet}"));
            }
        } else {
            parts.push("当前没有未结束的长时间命令。".into());
        }
    } else {
        parts.push("这一页没有项目里的长时间命令。".into());
    }
    let ask: String = ask.chars().take(800).collect();
    parts.push(format!("问题：{ask}"));
    ask_resident(manager, &parts.join("\n\n"))
}

pub fn explain_system() -> &'static str {
    EXPLAIN_SYSTEM
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::collections::HashMap;

    fn temp_manager() -> (RunManager, Settings) {
        let dir = std::env::temp_dir().join(format!(
            "atk-rev-{}-{}",
            std::process::id(),
            crate::db::new_id("t")
        ));
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
        let db = ArcDb::open(&settings.db_path).unwrap();
        (
            RunManager::new(std::sync::Arc::new(db), settings.clone()),
            settings,
        )
    }

    use crate::db::Db as ArcDb;

    #[test]
    fn claim_conflicts_and_release() {
        let pid = crate::db::new_id("p");
        let fid = crate::db::new_id("f");
        let job = claim(&pid, &fid, "secondary", "manual").unwrap();
        let jid = job["id"].as_str().unwrap().to_string();
        assert!(claim(&pid, &fid, "secondary", "manual").is_err());
        assert!(claim(&pid, &fid, "both", "manual").is_err());
        release(&jid, "done", "");
        let again = claim(&pid, &fid, "rating", "manual").unwrap();
        release(again["id"].as_str().unwrap(), "done", "");
        assert!(claim(&pid, &fid, "rating", "manual").is_ok());
        let snap = list_active();
        for job in snap {
            if job.get("project_id").and_then(|v| v.as_str()) == Some(pid.as_str()) {
                release(
                    job.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    "done",
                    "",
                );
            }
        }
    }

    #[test]
    fn flags_roundtrip_and_plain_reply() {
        let (_mgr, settings) = temp_manager();
        let flags = set_review_flags(&settings, Some(false), Some(true));
        assert_eq!(
            flags.get("secondary_verify").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            flags.get("redteam_rating").and_then(|v| v.as_bool()),
            Some(true)
        );
        let text = plain_reply("演示", "运行中", &["开始 记录".into()]);
        assert!(text.contains("正在运行"));
        assert!(text.contains("开始 记录"));
        assert!(explain_system().contains("不要给出新的命令"));
    }

    #[test]
    fn missing_project_explain_does_not_need_a_model() {
        let (mgr, _) = temp_manager();
        let text = explain(&mgr, "missing-project", "现在怎样", "", "", "", "").unwrap();
        assert_eq!(text, "当前页面上的这个项目不存在。");
        assert!(explain(&mgr, "", "", "", "", "", "").is_err());
    }
}
