//! Pi RPC：拉起 `pi --mode rpc --no-session`，用 LF JSONL 对话。
//! 从者带扩展；`console-explain` 属于一次性角色，工具关闭。
//! 无工具回复先收流式碎片再收整段，整段已包含碎片时不拼两次。

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::config::{repo_root, Settings};
use crate::console_auth::entry_prefix;
use crate::gateway::{hosted_enabled, rewrite_llm_url_for_gateway};
use crate::i18n::{self, msg};

const BUILTIN_MODEL: &str = "deepseek-flash";
const REVIEW_ROLE: &str = "finding-review";
const ONESHOT: &[&str] = &[
    "supervisor",
    "evolve",
    "finding-page",
    "report-export",
    "oneshot",
    "console-explain",
];
const GRAPH_TOOLS: &[&str] = &[
    "run_cmd",
    "http_request",
    "add_node",
    "add_edge",
    "report_finding",
    "report_shell",
    "report_pivot_capability",
    "propose_intents",
    "resolve_intent",
    "mark_honeypot",
    "note",
    "report_flag",
    "request_hint",
    "note_scan_coverage",
];
const TURN_MARKS: &[&str] = &[
    "本轮完成",
    "已完成本轮",
    "本轮小结",
    "本轮从者已完成",
    "收尾如下",
    "收尾结论",
    "本轮结束",
    "结束本轮",
    "round complete",
    "finished this turn",
    "wrapping up this turn",
];

pub type EmitFn = Arc<dyn Fn(&str, &str, &Value, Option<&str>) + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Gate {
    live: HashMap<i32, (String, String)>,
    reserved: Vec<(String, String)>,
}

fn gate() -> &'static (Mutex<Gate>, Condvar) {
    static G: OnceLock<(Mutex<Gate>, Condvar)> = OnceLock::new();
    G.get_or_init(|| {
        (
            Mutex::new(Gate {
                live: HashMap::new(),
                reserved: Vec::new(),
            }),
            Condvar::new(),
        )
    })
}

pub fn is_oneshot_role(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    ONESHOT.iter().any(|x| *x == r)
}

pub fn is_review_role(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    r == REVIEW_ROLE || r.starts_with(&format!("{REVIEW_ROLE}:"))
}

fn counts_toward_per_project(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    !r.is_empty() && !is_oneshot_role(&r) && !is_review_role(&r)
}

pub fn role_wrote_turn_done(text: &str, role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    if r == REVIEW_ROLE || r.starts_with(&format!("{REVIEW_ROLE}:")) {
        return false;
    }
    if text.trim().is_empty() {
        return false;
    }
    let low = text.to_ascii_lowercase();
    for mark in TURN_MARKS {
        if mark.is_ascii() {
            if low.contains(&mark.to_ascii_lowercase()) {
                return true;
            }
        } else if text.contains(mark) {
            return true;
        }
    }
    false
}

pub fn usable_api_key(raw: &str) -> String {
    let key = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    if key.is_empty() || key.starts_with('$') {
        return String::new();
    }
    if matches!(
        key.to_ascii_lowercase().as_str(),
        "changeme" | "your-api-key" | "your_api_key" | "sk-xxx"
    ) {
        return String::new();
    }
    key
}

fn expand_api_key(raw: &str) -> String {
    let text = raw.trim().trim_matches('"').trim_matches('\'').to_string();
    if let Some(rest) = text.strip_prefix('$') {
        let mut name = rest.trim().to_string();
        if name.starts_with('{') && name.ends_with('}') && name.len() >= 2 {
            name = name[1..name.len() - 1].trim().to_string();
        }
        if name.is_empty() {
            return String::new();
        }
        return std::env::var(name).unwrap_or_default();
    }
    text
}

pub fn pi_max_live_limit(settings: &Settings) -> i64 {
    let n = if settings.pi_max_live <= 0 {
        32
    } else {
        settings.pi_max_live
    };
    let cap = if settings.pi_max_live_cap <= 0 {
        96
    } else {
        settings.pi_max_live_cap
    };
    n.min(cap).max(1)
}

pub fn pi_per_project_limit(settings: &Settings) -> i64 {
    let mut n = settings.pi_per_project;
    if n == 0 {
        n = settings.claude_per_project;
    }
    if n <= 0 {
        n = 4;
    }
    let mut cap = settings.pi_per_project_cap;
    if cap == 0 {
        cap = settings.claude_per_project_cap;
    }
    if cap <= 0 {
        cap = 8;
    }
    n.min(cap).max(1)
}

pub fn cap_hunt_workers(
    settings: &Settings,
    roles: &[&str],
    per_project: Option<i64>,
) -> Vec<String> {
    let limit = per_project.unwrap_or_else(|| pi_per_project_limit(settings));
    let n = limit - 1;
    if n <= 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in roles {
        let name = raw.trim().to_ascii_lowercase();
        if name.is_empty()
            || seen.contains(&name)
            || is_oneshot_role(&name)
            || is_review_role(&name)
        {
            continue;
        }
        seen.insert(name.clone());
        out.push(name);
        if out.len() as i64 >= n {
            break;
        }
    }
    out
}

fn pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn reap_dead(g: &mut Gate) {
    let dead: Vec<i32> = g
        .live
        .keys()
        .copied()
        .filter(|pid| !pid_alive(*pid))
        .collect();
    for pid in dead {
        g.live.remove(&pid);
    }
}

pub fn live_pi_count() -> i64 {
    let (mtx, _) = gate();
    let mut g = lock(mtx);
    reap_dead(&mut g);
    g.live.len() as i64
}

pub fn live_pi_for_project(project_id: &str, hunt_only: bool) -> i64 {
    let want = project_id.trim();
    if want.is_empty() {
        return 0;
    }
    let (mtx, _) = gate();
    let mut g = lock(mtx);
    reap_dead(&mut g);
    g.live
        .values()
        .filter(|rec| rec.0 == want && (!hunt_only || counts_toward_per_project(&rec.1)))
        .count() as i64
}

fn signal_pid(pid: i32, sig: i32) {
    if pid <= 0 {
        return;
    }
    let flag = if sig == 15 { "-TERM" } else { "-KILL" };
    let _ = Command::new("kill")
        .args([flag, &format!("-{pid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("kill")
        .args([flag, &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn proc_ppid(pid: i32) -> i32 {
    let path = format!("/proc/{pid}/status");
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("PPid:") {
                return rest
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            }
        }
    }
    0
}

fn children_map() -> HashMap<i32, Vec<i32>> {
    let mut out: HashMap<i32, Vec<i32>> = HashMap::new();
    if Path::new("/proc").is_dir() {
        if let Ok(rd) = fs::read_dir("/proc") {
            let mut any = false;
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if !name.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                any = true;
                let pid: i32 = name.parse().unwrap_or(0);
                let ppid = proc_ppid(pid);
                if ppid > 0 {
                    out.entry(ppid).or_default().push(pid);
                }
            }
            if any {
                return out;
            }
        }
    }
    if let Ok(output) = Command::new("ps").args(["-axo", "pid=,ppid="]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            let pid: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let ppid: i32 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            if pid > 0 && ppid > 0 {
                out.entry(ppid).or_default().push(pid);
            }
        }
    }
    out
}

fn descendants(root: i32, cmap: &HashMap<i32, Vec<i32>>) -> Vec<i32> {
    let mut found = Vec::new();
    let mut stack = cmap.get(&root).cloned().unwrap_or_default();
    while let Some(pid) = stack.pop() {
        found.push(pid);
        if let Some(kids) = cmap.get(&pid) {
            stack.extend(kids.iter().copied());
        }
    }
    found
}

fn kill_tree(root: i32, sig: i32) {
    let cmap = children_map();
    let kids = descendants(root, &cmap);
    for pid in kids.into_iter().rev() {
        signal_pid(pid, sig);
    }
    signal_pid(root, sig);
}

fn proc_cmdline(pid: i32) -> Vec<u8> {
    let path = format!("/proc/{pid}/cmdline");
    if let Ok(buf) = fs::read(path) {
        if !buf.is_empty() {
            return buf;
        }
    }
    Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .map(|o| o.stdout)
        .unwrap_or_default()
}

fn proc_env_value(pid: i32, key: &str) -> String {
    let path = format!("/proc/{pid}/environ");
    let Ok(env) = fs::read(path) else {
        return String::new();
    };
    let needle = format!("{key}=").into_bytes();
    let Some(i) = env
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
    else {
        return String::new();
    };
    if i > 0 && env[i - 1] != 0 {
        return String::new();
    }
    let rest = &env[i + needle.len()..];
    let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
    String::from_utf8_lossy(&rest[..end]).trim().to_string()
}

pub fn is_backend_cmd(cmd: &[u8]) -> bool {
    cmd.windows(b"atkbrain.main".len())
        .any(|w| w == b"atkbrain.main")
        || cmd
            .windows(b"atkbrain-backend".len())
            .any(|w| w == b"atkbrain-backend")
}

pub fn is_protected_cmd(cmd: &[u8]) -> bool {
    if cmd.is_empty() || is_backend_cmd(cmd) {
        return true;
    }
    let blob = String::from_utf8_lossy(cmd)
        .replace('\0', " ")
        .to_ascii_lowercase();
    let first = cmd.split(|b| *b == 0).next().unwrap_or(cmd);
    let base = String::from_utf8_lossy(first)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(base.as_str(), "caddy" | "caddy.exe" | "uvicorn") {
        return true;
    }
    blob.contains("uvicorn")
}

#[allow(dead_code)]
fn is_pi_cmdline(cmd: &[u8]) -> bool {
    if cmd.is_empty() || is_backend_cmd(cmd) {
        return false;
    }
    let blob = String::from_utf8_lossy(cmd)
        .replace('\0', " ")
        .to_ascii_lowercase();
    if blob.contains("--mode") && blob.contains("rpc") {
        return true;
    }
    if blob.contains("pi-coding-agent") {
        return true;
    }
    let first = cmd.split(|b| *b == 0).next().unwrap_or(cmd);
    let base = String::from_utf8_lossy(first)
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(base.as_str(), "pi" | "pi.exe")
}

fn scan_pi_pids(project_id: &str, role: &str) -> Vec<i32> {
    let want_p = project_id.trim();
    let want_r = role.trim();
    if want_p.is_empty() && want_r.is_empty() {
        return Vec::new();
    }
    let mut found = Vec::new();
    let Ok(rd) = fs::read_dir("/proc") else {
        return found;
    };
    let cmap = children_map();
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = name.parse().unwrap_or(0);
        let cmd = proc_cmdline(pid);
        if is_protected_cmd(&cmd) {
            continue;
        }
        let env_p = proc_env_value(pid, "ATKBRAIN_PROJECT_ID");
        let env_r = proc_env_value(pid, "ATKBRAIN_PI_ROLE");
        let matched = if !want_p.is_empty() && !want_r.is_empty() {
            env_p == want_p && env_r == want_r
        } else if !want_p.is_empty() {
            env_p == want_p
        } else {
            env_r == want_r
        };
        if !matched {
            continue;
        }
        if !found.contains(&pid) {
            found.push(pid);
        }
        for kid in descendants(pid, &cmap) {
            if !found.contains(&kid) {
                found.push(kid);
            }
        }
    }
    found
}

fn untrack_dead(pid: i32) -> bool {
    if pid <= 0 {
        return true;
    }
    let (mtx, _) = gate();
    let mut g = lock(mtx);
    if pid_alive(pid) {
        return false;
    }
    g.live.remove(&pid);
    true
}

fn notify_spawn() {
    let (_, cv) = gate();
    cv.notify_all();
}

fn can_spawn(g: &Gate, settings: &Settings, project_id: &str, role: &str) -> bool {
    if (g.live.len() + g.reserved.len()) as i64 >= pi_max_live_limit(settings) {
        return false;
    }
    if counts_toward_per_project(role) && !project_id.trim().is_empty() {
        let mut n = g
            .live
            .values()
            .filter(|rec| rec.0 == project_id && counts_toward_per_project(&rec.1))
            .count();
        n += g
            .reserved
            .iter()
            .filter(|rec| rec.0 == project_id && counts_toward_per_project(&rec.1))
            .count();
        if n as i64 >= pi_per_project_limit(settings) {
            return false;
        }
    }
    true
}

pub fn wait_spawn_slot(
    settings: &Settings,
    project_id: &str,
    role: &str,
    timeout: Duration,
    stop: &AtomicBool,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout.max(Duration::from_secs(1));
    let (mtx, cv) = gate();
    let mut g = lock(mtx);
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err("stopped".into());
        }
        reap_dead(&mut g);
        if can_spawn(&g, settings, project_id, role) {
            g.reserved
                .push((project_id.trim().to_string(), role.trim().to_string()));
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Pi 进程闸已满（全局 {} / 项目 {}），放弃拉起 {}",
                pi_max_live_limit(settings),
                pi_per_project_limit(settings),
                if role.is_empty() { "pi" } else { role }
            ));
        }
        let (ng, _) = cv
            .wait_timeout(g, Duration::from_secs(1))
            .unwrap_or_else(|e| e.into_inner());
        g = ng;
    }
}

fn note_spawned(pid: i32, project_id: &str, role: &str) {
    let rec = (project_id.trim().to_string(), role.trim().to_string());
    let (mtx, cv) = gate();
    let mut g = lock(mtx);
    if let Some(i) = g.reserved.iter().position(|x| x == &rec) {
        g.reserved.remove(i);
    } else if !g.reserved.is_empty() {
        g.reserved.remove(0);
    }
    g.live.insert(pid, rec);
    cv.notify_all();
}

fn note_spawn_failed(project_id: &str, role: &str) {
    let rec = (project_id.trim().to_string(), role.trim().to_string());
    let (mtx, cv) = gate();
    let mut g = lock(mtx);
    if let Some(i) = g.reserved.iter().position(|x| x == &rec) {
        g.reserved.remove(i);
    } else if !g.reserved.is_empty() {
        g.reserved.remove(0);
    }
    cv.notify_all();
}

pub fn kill_live_for_project(project_id: &str, keep_roles: &[&str]) -> i32 {
    let want = project_id.trim();
    if want.is_empty() {
        return 0;
    }
    let keep: Vec<String> = keep_roles
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let spare = |role: &str| -> bool {
        if keep.iter().any(|k| k == role) {
            return true;
        }
        keep.iter().any(|k| k == REVIEW_ROLE) && is_review_role(role)
    };
    let (mtx, _) = gate();
    let mut targets = Vec::new();
    {
        let mut g = lock(mtx);
        reap_dead(&mut g);
        let cmap = children_map();
        for (pid, rec) in g.live.iter() {
            if rec.0 != want || spare(&rec.1) {
                continue;
            }
            if !targets.contains(pid) {
                targets.push(*pid);
            }
            for kid in descendants(*pid, &cmap) {
                if !targets.contains(&kid) {
                    targets.push(kid);
                }
            }
        }
    }
    for pid in scan_pi_pids(want, "") {
        if !keep.is_empty() && spare(&proc_env_value(pid, "ATKBRAIN_PI_ROLE")) {
            continue;
        }
        if !targets.contains(&pid) {
            targets.push(pid);
        }
    }
    for pid in &targets {
        kill_tree(*pid, 9);
    }
    thread::sleep(Duration::from_millis(50));
    {
        let mut g = lock(mtx);
        for pid in &targets {
            if !pid_alive(*pid) {
                g.live.remove(pid);
            }
        }
    }
    notify_spawn();
    targets.len() as i32
}

pub fn extension_path() -> PathBuf {
    let p = repo_root()
        .join("pi")
        .join("extensions")
        .join("atkbrain-tools.ts");
    if p.is_file() {
        return p;
    }
    PathBuf::from("pi")
        .join("extensions")
        .join("atkbrain-tools.ts")
}

pub fn tools_base_url(settings: &Settings) -> String {
    let mut prefix = entry_prefix(settings).unwrap_or_default();
    if !prefix.is_empty() && !prefix.starts_with('/') {
        prefix = format!("/{prefix}");
    }
    format!("http://127.0.0.1:{}{prefix}", settings.port)
}

pub fn pi_bin(settings: &Settings) -> String {
    let s = settings.pi_bin.trim();
    if !s.is_empty() {
        return s.to_string();
    }
    std::env::var("ATKBRAIN_PI_BIN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pi".into())
}

fn which(bin: &str) -> String {
    if bin.contains('/') && Path::new(bin).is_file() {
        return bin.to_string();
    }
    let Ok(path) = std::env::var("PATH") else {
        return String::new();
    };
    for dir in std::env::split_paths(&path) {
        let p = dir.join(bin);
        if p.is_file() {
            return p.display().to_string();
        }
    }
    String::new()
}

pub fn pi_runtime_status(settings: &Settings) -> Value {
    if !llm_api_key_configured(settings) {
        return json!({"state": "unavailable", "label": "未配置大模型密钥", "error": "DEEPSEEK_API_KEY missing"});
    }
    let path = which(&pi_bin(settings));
    if path.is_empty() {
        return json!({"state": "unavailable", "label": "Pi 不可用", "error": "pi not found"});
    }
    json!({"state": "ready", "label": "Pi 就绪", "version": "", "bin": path})
}

fn env_pi_model(settings: &Settings) -> String {
    let pi = settings.pi_model.trim();
    let claude = settings.claude_model.trim();
    if !pi.is_empty() && pi != BUILTIN_MODEL {
        return pi.to_string();
    }
    if !claude.is_empty() && claude != BUILTIN_MODEL {
        return claude.to_string();
    }
    if !pi.is_empty() {
        pi.to_string()
    } else if !claude.is_empty() {
        claude.to_string()
    } else {
        BUILTIN_MODEL.to_string()
    }
}

fn env_pi_provider(settings: &Settings) -> String {
    let p = settings.pi_provider.trim();
    if p.is_empty() {
        "deepseek".into()
    } else {
        p.to_string()
    }
}

pub fn pi_models_file(settings: &Settings) -> PathBuf {
    settings.data_dir.join("pi-models.json")
}

fn harness_models_file(settings: &Settings) -> PathBuf {
    settings.data_dir.join("harness-models.json")
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, format!("{text}\n")).map_err(|e| e.to_string())
}

pub fn default_pi_models(settings: &Settings) -> Value {
    json!({
        "defaultProvider": env_pi_provider(settings),
        "defaultModel": env_pi_model(settings),
        "providers": {
            "deepseek": {
                "baseUrl": "https://api.deepseek.com",
                "api": "openai-completions",
                "apiKey": "$DEEPSEEK_API_KEY",
                "models": [{
                    "id": "deepseek-flash",
                    "name": "deepseek-flash",
                    "contextWindow": 1000000,
                    "maxTokens": 384000,
                    "input": ["text"],
                    "reasoning": true,
                    "thinkingLevelMap": {"minimal": null, "low": null, "medium": null, "high": "high", "xhigh": "max"},
                    "cost": {"input": 0.14, "output": 0.28, "cacheRead": 0.028, "cacheWrite": 0},
                    "compat": {
                        "requiresReasoningContentOnAssistantMessages": true,
                        "thinkingFormat": "deepseek",
                        "reasoningEffortMap": {"minimal": "high", "low": "high", "medium": "high", "high": "high", "xhigh": "max"}
                    }
                }]
            }
        }
    })
}

fn from_harness(settings: &Settings, raw: &Map<String, Value>) -> Value {
    let mut data = default_pi_models(settings);
    let model = raw
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let model = if model.is_empty() {
        data.get("defaultModel")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    } else {
        model
    };
    let base = raw
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_string();
    let base = if base.is_empty() {
        "https://api.deepseek.com".into()
    } else {
        base
    };
    let key = raw
        .get("api_key")
        .and_then(|v| v.as_str())
        .unwrap_or("$DEEPSEEK_API_KEY");
    if let Some(obj) = data.as_object_mut() {
        obj.insert("defaultProvider".into(), json!(env_pi_provider(settings)));
        obj.insert("defaultModel".into(), json!(model));
        if let Some(deep) = obj
            .get_mut("providers")
            .and_then(|p| p.get_mut("deepseek"))
            .and_then(|v| v.as_object_mut())
        {
            deep.insert("baseUrl".into(), json!(base));
            deep.insert("apiKey".into(), json!(key));
            let mut models = deep
                .get("models")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if !model.is_empty()
                && !models
                    .iter()
                    .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(model.as_str()))
            {
                models.insert(0, json!({"id": model, "name": model, "contextWindow": 1000000, "maxTokens": 384000, "input": ["text"]}));
            }
            deep.insert("models".into(), Value::Array(models));
        }
    }
    data
}

pub fn load_pi_models(settings: &Settings) -> Value {
    let path = pi_models_file(settings);
    let mut data = None;
    if path.is_file() {
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) {
                if map.get("providers").and_then(|v| v.as_object()).is_some() {
                    data = Some(Value::Object(map));
                }
            }
        }
    }
    if data.is_none() && harness_models_file(settings).is_file() {
        if let Ok(text) = fs::read_to_string(harness_models_file(settings)) {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&text) {
                if map
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    data = Some(from_harness(settings, &map));
                }
            }
        }
    }
    let mut data = data.unwrap_or_else(|| default_pi_models(settings));
    if let Some(obj) = data.as_object_mut() {
        obj.entry("defaultProvider")
            .or_insert(json!(env_pi_provider(settings)));
        obj.entry("defaultModel")
            .or_insert(json!(env_pi_model(settings)));
    }
    if !path.is_file() {
        let _ = write_json(&path, &data);
    }
    data
}

pub fn pi_models_text(settings: &Settings) -> String {
    let text =
        serde_json::to_string_pretty(&load_pi_models(settings)).unwrap_or_else(|_| "{}".into());
    format!("{text}\n")
}

pub fn save_pi_models_text(settings: &Settings, text: &str) -> Result<Value, String> {
    let data: Value = serde_json::from_str(text).map_err(|e| format!("JSON 不合法：{e}"))?;
    let obj = data.as_object().ok_or("需要包含非空 providers 对象")?;
    let providers = obj
        .get("providers")
        .and_then(|v| v.as_object())
        .ok_or("需要包含非空 providers 对象")?;
    if providers.is_empty() {
        return Err("需要包含非空 providers 对象".into());
    }
    let provider = obj
        .get("defaultProvider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let model = obj
        .get("defaultModel")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if provider.is_empty() || model.is_empty() {
        return Err("需要 defaultProvider 和 defaultModel".into());
    }
    if !providers.contains_key(provider) {
        return Err("defaultProvider 不在 providers 里".into());
    }
    write_json(&pi_models_file(settings), &data)?;
    let _ = ensure_pi_agent_dir(settings, None);
    Ok(data)
}

fn profile_format(api: &str, provider: &str) -> &'static str {
    let blob = format!("{api} {provider}").to_ascii_lowercase();
    if blob.contains("anthropic") {
        "anthropic"
    } else {
        "openai"
    }
}

fn key_hint(raw: &str) -> (bool, String) {
    let usable = usable_api_key(&expand_api_key(raw));
    if usable.is_empty() {
        return (false, String::new());
    }
    let tail = if usable.len() >= 4 {
        &usable[usable.len() - 4..]
    } else {
        usable.as_str()
    };
    (true, format!("…{tail}"))
}

pub fn llm_api_key(settings: &Settings) -> String {
    let env = usable_api_key(
        &std::env::var("DEEPSEEK_API_KEY")
            .unwrap_or_else(|_| std::env::var("ANTHROPIC_AUTH_TOKEN").unwrap_or_default()),
    );
    if !env.is_empty() {
        return env;
    }
    let data = load_pi_models(settings);
    let providers = data.get("providers").and_then(|v| v.as_object());
    let Some(providers) = providers else {
        return String::new();
    };
    let mut order = Vec::new();
    if let Some(name) = data.get("defaultProvider").and_then(|v| v.as_str()) {
        if !name.trim().is_empty() {
            order.push(name.trim().to_string());
        }
    }
    for k in providers.keys() {
        if !order.iter().any(|x| x == k) {
            order.push(k.clone());
        }
    }
    for name in order {
        let Some(prov) = providers.get(&name).and_then(|v| v.as_object()) else {
            continue;
        };
        let key = usable_api_key(prov.get("apiKey").and_then(|v| v.as_str()).unwrap_or(""));
        if !key.is_empty() {
            return key;
        }
    }
    String::new()
}

pub fn llm_api_key_configured(settings: &Settings) -> bool {
    !llm_api_key(settings).is_empty()
}

pub fn llm_key_missing_message() -> String {
    msg("llm_key_missing", Some(i18n::get_locale()), &[])
}

pub fn llm_profile(settings: &Settings) -> Value {
    let data = load_pi_models(settings);
    let providers = data.get("providers").and_then(|v| v.as_object());
    let name = data
        .get("defaultProvider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let prov = providers
        .and_then(|p| p.get(name))
        .and_then(|v| v.as_object());
    let fmt = profile_format(
        prov.and_then(|p| p.get("api"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        name,
    );
    let mut base = prov
        .and_then(|p| p.get("baseUrl"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if base.is_empty() {
        base = "https://api.deepseek.com".into();
    }
    let (set, hint) = key_hint(
        prov.and_then(|p| p.get("apiKey"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    );
    json!({
        "format": fmt,
        "model": data.get("defaultModel").and_then(|v| v.as_str()).unwrap_or("").trim(),
        "base_url": base,
        "api_key_set": set,
        "api_key_hint": hint,
    })
}

pub fn save_llm_profile(
    settings: &Settings,
    model: &str,
    base_url: &str,
    api_key: &str,
    fmt: &str,
) -> Result<Value, String> {
    if fmt.trim().eq_ignore_ascii_case("anthropic") {
        return Err("只支持 DeepSeek 官方接口和兼容的 Base URL".into());
    }
    let model_id = model.trim();
    if model_id.is_empty() || model_id.chars().count() > 200 {
        return Err("需要填写模型".into());
    }
    let base = base_url.trim().trim_end_matches('/');
    let low = base.to_ascii_lowercase();
    if !(low.starts_with("http://") || low.starts_with("https://")) || base.contains(' ') {
        return Err("Base URL 需要以 http:// 或 https:// 开头".into());
    }
    let existing = load_pi_models(settings);
    let provider = env_pi_provider(settings);
    let providers = existing.get("providers").and_then(|v| v.as_object());
    let mut block = providers
        .and_then(|p| p.get(&provider))
        .cloned()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| {
            default_pi_models(settings)
                .get("providers")
                .and_then(|p| p.get("deepseek"))
                .cloned()
                .unwrap_or(json!({}))
        });
    let old_key = block
        .get("apiKey")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let key = if api_key.trim().is_empty() {
        old_key
    } else {
        api_key.trim().to_string()
    };
    if let Some(obj) = block.as_object_mut() {
        obj.insert("baseUrl".into(), json!(base));
        obj.insert("api".into(), json!("openai-completions"));
        obj.insert("apiKey".into(), json!(key));
        let mut models: Vec<Value> = obj
            .get("models")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|v| v.is_object())
            .collect();
        if !models
            .iter()
            .any(|item| item.get("id").and_then(|v| v.as_str()) == Some(model_id))
        {
            let mut template = models.first().cloned().unwrap_or_else(
                || json!({"contextWindow": 1000000, "maxTokens": 384000, "input": ["text"]}),
            );
            if let Some(t) = template.as_object_mut() {
                t.insert("id".into(), json!(model_id));
                t.insert("name".into(), json!(model_id));
            }
            models.insert(0, template);
        }
        obj.insert("models".into(), Value::Array(models));
    }
    let data = json!({"defaultProvider": provider, "defaultModel": model_id, "providers": {provider: block}});
    save_pi_models_text(
        settings,
        &serde_json::to_string(&data).unwrap_or_else(|_| "{}".into()),
    )?;
    Ok(llm_profile(settings))
}

pub fn llm_probe_url(fmt: &str, base_url: &str) -> String {
    let base = base_url.trim().trim_end_matches('/').to_string();
    if fmt.trim().eq_ignore_ascii_case("anthropic") {
        if base.ends_with("/messages") {
            return base;
        }
        if base.ends_with("/v1") {
            return format!("{base}/messages");
        }
        return format!("{base}/v1/messages");
    }
    if base.ends_with("/chat/completions") {
        base
    } else {
        format!("{base}/chat/completions")
    }
}

fn probe_reply(fmt: &str, body: &Value, limit: usize) -> String {
    let Some(obj) = body.as_object() else {
        return String::new();
    };
    if fmt == "anthropic" {
        let Some(content) = obj.get("content").and_then(|v| v.as_array()) else {
            return String::new();
        };
        let text = content
            .iter()
            .filter_map(|item| item.get("text").and_then(|v| v.as_str()))
            .filter(|s| !s.trim().is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        return text.chars().take(limit).collect();
    }
    let Some(choice) = obj
        .get("choices")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    else {
        return String::new();
    };
    choice
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .chars()
        .take(limit)
        .collect()
}

fn probe_error(body: &Value, text: &str) -> String {
    if let Some(err) = body.get("error") {
        if let Some(obj) = err.as_object() {
            let msg = obj
                .get("message")
                .or_else(|| obj.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if !msg.is_empty() {
                return msg.chars().take(400).collect();
            }
        }
        if let Some(s) = err.as_str() {
            if !s.trim().is_empty() {
                return s.trim().chars().take(400).collect();
            }
        }
    }
    text.trim().chars().take(400).collect()
}

fn redact(text: &str, key: &str) -> String {
    if !key.is_empty() && text.contains(key) {
        text.replace(key, "***")
    } else {
        text.to_string()
    }
}

type ProbeHook = Arc<dyn Fn(&str, &[(String, String)], &str) -> Result<(u16, String), String> + Send + Sync>;
static PROBE_HOOK: Mutex<Option<ProbeHook>> = Mutex::new(None);

pub fn set_probe_hook(hook: Option<ProbeHook>) {
    *lock(&PROBE_HOOK) = hook;
}

fn snapshot_env() -> HashMap<String, String> {
    std::env::vars_os()
        .map(|(key, value)| (key.to_string_lossy().into_owned(), value.to_string_lossy().into_owned()))
        .collect()
}

fn http_post(
    url: &str,
    headers: &[(&str, String)],
    body: &str,
    timeout_secs: u64,
) -> Result<(u16, String), String> {
    if let Some(hook) = lock(&PROBE_HOOK).clone() {
        let owned: Vec<(String, String)> = headers.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect();
        return hook(url, &owned, body);
    }
    let write_out = format!("\n__ATK_STATUS_{}__", std::process::id());
    let mut cmd = Command::new("curl");
    cmd.args([
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--location",
        "--max-time",
        &timeout_secs.to_string(),
        "--connect-timeout",
        "10",
        "-w",
        &write_out,
        "-X",
        "POST",
        "--data-binary",
        body,
    ]);
    for (k, v) in headers {
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    cmd.arg(url);
    let output = cmd.output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if text.is_empty() && !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "连接失败".into()
        } else {
            err
        });
    }
    let (body, code) = if let Some(i) = text.rfind(&write_out) {
        let code: u16 = text[i + write_out.len()..].trim().parse().unwrap_or(0);
        (text[..i].to_string(), code)
    } else {
        (text, if output.status.success() { 200 } else { 0 })
    };
    Ok((code, body))
}

pub fn probe_llm(
    settings: &Settings,
    model: &str,
    base_url: &str,
    api_key: &str,
    fmt: &str,
) -> Value {
    let kind = fmt.trim().to_ascii_lowercase();
    if kind == "anthropic" || !(kind.is_empty() || kind == "openai") {
        return json!({"ok": false, "error": "只支持 DeepSeek 官方接口和兼容的 Base URL"});
    }
    let model_id = model.trim();
    let base = base_url.trim();
    if model_id.is_empty() {
        return json!({"ok": false, "error": "需要填写模型"});
    }
    let low = base.to_ascii_lowercase();
    if !(low.starts_with("http://") || low.starts_with("https://")) {
        return json!({"ok": false, "error": "Base URL 需要以 http:// 或 https:// 开头"});
    }
    let existing = load_pi_models(settings);
    let providers = existing.get("providers").and_then(|v| v.as_object());
    let current_name = existing
        .get("defaultProvider")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let current = providers
        .and_then(|p| p.get(current_name))
        .and_then(|v| v.as_object());
    let explicit = api_key.trim();
    let stored = current
        .and_then(|p| p.get("apiKey"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let mut key = usable_api_key(&expand_api_key(if explicit.is_empty() {
        stored
    } else {
        explicit
    }));
    if key.is_empty() {
        key = llm_api_key(settings);
    }
    if key.is_empty() {
        return json!({"ok": false, "error": "未配置 API Key"});
    }
    let url = llm_probe_url("openai", base);
    let mut payload = json!({"model": model_id, "messages": [{"role": "user", "content": "Reply with the single word OK."}], "max_tokens": 16});
    let headers = [
        ("Authorization", format!("Bearer {key}")),
        ("Content-Type", "application/json".into()),
    ];
    let started = Instant::now();
    let first = match http_post(&url, &headers, &payload.to_string(), 20) {
        Ok(v) => v,
        Err(e) => {
            return json!({"ok": false, "error": redact(&e, &key).chars().take(400).collect::<String>()})
        }
    };
    let (status, text) = if status_is_max_tokens(first.0, &first.1) {
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("max_tokens");
            obj.insert("max_completion_tokens".into(), json!(16));
        }
        match http_post(&url, &headers, &payload.to_string(), 20) {
            Ok(v) => v,
            Err(e) => {
                return json!({"ok": false, "error": redact(&e, &key).chars().take(400).collect::<String>()})
            }
        }
    } else {
        first
    };
    let latency = started.elapsed().as_millis() as i64;
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if status >= 400 || status == 0 {
        let mut detail = redact(&probe_error(&body, &text), &key);
        if detail.is_empty() {
            detail = format!("HTTP {status}");
        }
        return json!({"ok": false, "latency_ms": latency, "error": detail});
    }
    json!({"ok": true, "latency_ms": latency, "model": model_id, "reply": probe_reply("openai", &body, 200)})
}

fn status_is_max_tokens(status: u16, text: &str) -> bool {
    status == 400 && text.contains("max_tokens")
}

pub fn complete_text(settings: &Settings, prompt: &str, max_tokens: i64) -> Value {
    let profile = llm_profile(settings);
    let model_id = profile
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let base = profile
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let low = base.to_ascii_lowercase();
    if model_id.is_empty() || !(low.starts_with("http://") || low.starts_with("https://")) {
        return json!({"ok": false, "error": "模型还没配好"});
    }
    let key = llm_api_key(settings);
    if key.is_empty() {
        return json!({"ok": false, "error": "未配置 API Key"});
    }
    let url = llm_probe_url("openai", &base);
    let clipped: String = prompt.chars().take(6000).collect();
    let mut payload = json!({"model": model_id, "messages": [{"role": "user", "content": clipped}], "max_tokens": max_tokens});
    let headers = [
        ("Authorization", format!("Bearer {key}")),
        ("Content-Type", "application/json".into()),
    ];
    let first = match http_post(&url, &headers, &payload.to_string(), 40) {
        Ok(v) => v,
        Err(e) => {
            return json!({"ok": false, "error": redact(&e, &key).chars().take(400).collect::<String>()})
        }
    };
    let (status, text) = if status_is_max_tokens(first.0, &first.1) {
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("max_tokens");
            obj.insert("max_completion_tokens".into(), json!(max_tokens));
        }
        match http_post(&url, &headers, &payload.to_string(), 40) {
            Ok(v) => v,
            Err(e) => {
                return json!({"ok": false, "error": redact(&e, &key).chars().take(400).collect::<String>()})
            }
        }
    } else {
        first
    };
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if status >= 400 || status == 0 {
        return json!({"ok": false, "error": redact(&probe_error(&body, &text), &key)});
    }
    json!({"ok": true, "reply": probe_reply("openai", &body, 1200)})
}

pub fn pi_model(settings: &Settings) -> String {
    let model = load_pi_models(settings)
        .get("defaultModel")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if model.is_empty() {
        env_pi_model(settings)
    } else {
        model
    }
}

pub fn pi_provider(settings: &Settings) -> String {
    let provider = load_pi_models(settings)
        .get("defaultProvider")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if provider.is_empty() {
        env_pi_provider(settings)
    } else {
        provider
    }
}

fn legacy_model_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.is_empty() || matches!(n.as_str(), "sonnet" | "haiku" | "opus") || n.starts_with("claude")
}

pub fn console_model(settings: &Settings) -> String {
    pi_model(settings)
}

pub fn project_model(settings: &Settings, explicit: &str) -> String {
    let raw = explicit.trim();
    if !raw.is_empty() && !legacy_model_name(raw) {
        raw.to_string()
    } else {
        console_model(settings)
    }
}

pub fn role_model(settings: &Settings, candidates: &[&str]) -> String {
    let chosen = console_model(settings);
    for item in candidates {
        let raw = item.trim();
        if legacy_model_name(raw) {
            continue;
        }
        if raw == BUILTIN_MODEL && !chosen.is_empty() && chosen != BUILTIN_MODEL {
            continue;
        }
        return raw.to_string();
    }
    chosen
}

pub fn ensure_pi_agent_dir(settings: &Settings, hosted: Option<bool>) -> Result<PathBuf, String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let agent = PathBuf::from(home).join(".pi").join("agent");
    fs::create_dir_all(&agent).map_err(|e| e.to_string())?;
    let settings_path = agent.join("settings.json");
    if !settings_path.is_file() {
        write_json(
            &settings_path,
            &json!({"enableInstallTelemetry": false, "defaultProjectTrust": "always"}),
        )?;
    } else {
        let mut data = fs::read_to_string(&settings_path)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .unwrap_or(json!({}));
        if let Some(obj) = data.as_object_mut() {
            obj.entry("enableInstallTelemetry").or_insert(json!(false));
            obj.insert("defaultProjectTrust".into(), json!("always"));
            let _ = write_json(&settings_path, &Value::Object(obj.clone()));
        }
    }
    let env = snapshot_env();
    let use_gw = hosted.unwrap_or_else(|| hosted_enabled(&env));
    let mut models = load_pi_models(settings);
    if use_gw {
        let mut base = rewrite_llm_url_for_gateway("https://api.deepseek.com");
        if !base.contains(".tsecbench.gw") {
            base = "http://api.deepseek.com.tsecbench.gw".into();
        }
        if let Some(deep) = models
            .get_mut("providers")
            .and_then(|p| p.get_mut("deepseek"))
            .and_then(|v| v.as_object_mut())
        {
            deep.insert("baseUrl".into(), json!(base));
        }
    }
    write_json(&agent.join("models.json"), &models)?;
    Ok(agent)
}

fn child_env(settings: &Settings, project_id: &str, role: &str) -> HashMap<String, String> {
    let mut env = snapshot_env();
    let key = llm_api_key(settings);
    if !key.is_empty() {
        env.insert("DEEPSEEK_API_KEY".into(), key.clone());
        env.entry("ANTHROPIC_AUTH_TOKEN".into()).or_insert(key);
    }
    env.insert("PI_TELEMETRY".into(), "0".into());
    env.insert("PI_SKIP_VERSION_CHECK".into(), "1".into());
    env.insert("PI_OFFLINE".into(), "1".into());
    let home = env.get("HOME").cloned().unwrap_or_else(|| "/root".into());
    env.entry("PI_CODING_AGENT_DIR".into()).or_insert(
        PathBuf::from(home)
            .join(".pi")
            .join("agent")
            .display()
            .to_string(),
    );
    if !project_id.is_empty() {
        let base = tools_base_url(settings);
        env.insert("ATKBRAIN_PROJECT_ID".into(), project_id.to_string());
        env.insert("ATKBRAIN_TOOLS_BASE".into(), base.clone());
        env.insert("ATKBRAIN_API".into(), base);
    }
    if !role.is_empty() {
        env.insert("ATKBRAIN_PI_ROLE".into(), role.to_string());
    }
    let token = settings.api_token.trim();
    if !token.is_empty() {
        env.insert("ATKBRAIN_API_TOKEN".into(), token.to_string());
    }
    for k in [
        "http_proxy",
        "https_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "all_proxy",
    ] {
        env.remove(k);
    }
    env
}

pub fn collapse_duplicate(text: &str) -> String {
    let mut s = text.trim().to_string();
    for _ in 0..2 {
        if s.chars().count() < 12 {
            break;
        }
        let mut found = String::new();
        let len = s.chars().count();
        for delta in -8i32..=8 {
            let cut = (len as i32) / 2 + delta;
            if cut < 6 || cut > (len as i32) - 6 {
                continue;
            }
            let cut = cut as usize;
            let left: String = s.chars().take(cut).collect::<String>().trim().to_string();
            let right: String = s.chars().skip(cut).collect::<String>().trim().to_string();
            if !left.is_empty() && left == right {
                found = left;
                break;
            }
        }
        if found.is_empty() {
            break;
        }
        s = found;
    }
    s
}

fn assistant_text(msg: &Value) -> String {
    let Some(obj) = msg.as_object() else {
        return String::new();
    };
    if obj.get("role").and_then(|v| v.as_str()).unwrap_or("") != "assistant" {
        return String::new();
    }
    let mut parts = Vec::new();
    match obj.get("content") {
        Some(Value::String(s)) => parts.push(s.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(s) = item.as_str() {
                    parts.push(s.to_string());
                } else if let Some(o) = item.as_object() {
                    let typ = o.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if typ.is_empty() || typ == "text" {
                        parts.push(
                            o.get("text")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
        }
        _ => {}
    }
    parts.join("").trim().to_string()
}

pub fn reply_text(tools: bool, texts: &[String]) -> String {
    let chunks: Vec<String> = texts
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if chunks.is_empty() {
        return String::new();
    }
    if tools {
        return texts.concat().trim().to_string();
    }
    let mut text = texts.concat().trim().to_string();
    if chunks.len() >= 2 {
        let tail = chunks
            .last()
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let head = chunks[..chunks.len() - 1]
            .iter()
            .cloned()
            .collect::<String>()
            .trim()
            .to_string();
        if !tail.is_empty() && (head == tail || head.ends_with(&tail) || tail.starts_with(&head)) {
            text = tail;
        }
    }
    collapse_duplicate(&text)
}

struct Ack {
    epoch: u64,
    value: Option<bool>,
}

struct Inner {
    cwd: String,
    system_prompt: Mutex<String>,
    project_id: String,
    role: String,
    tools: bool,
    model: String,
    run_id: Mutex<String>,
    review_job_id: Mutex<String>,
    emit: Mutex<Option<EmitFn>>,
    stop: Arc<AtomicBool>,
    child: Mutex<Option<Child>>,
    stdin: Mutex<Option<ChildStdin>>,
    texts: Mutex<Vec<String>>,
    tool_uses: AtomicU64,
    settled: Mutex<bool>,
    settled_cv: Condvar,
    ack: Mutex<Ack>,
    ack_cv: Condvar,
    closed: AtomicBool,
    text_acc: Mutex<Vec<String>>,
    thought_acc: Mutex<Vec<String>>,
    last_text: Mutex<String>,
    last_thought: Mutex<String>,
    turn_closed: AtomicBool,
    last_prompt: Mutex<Option<Instant>>,
    idle_turns: AtomicU64,
    activity: AtomicU64,
    activity_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    reader: Mutex<Option<JoinHandle<()>>>,
    stderr_thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct PiSession {
    inner: Arc<Inner>,
}

impl PiSession {
    pub fn new(
        cwd: &str,
        system_prompt: &str,
        project_id: &str,
        role: &str,
        tools: bool,
        model: &str,
    ) -> Self {
        Self::with_stop(
            cwd,
            system_prompt,
            project_id,
            role,
            tools,
            model,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn with_stop(
        cwd: &str,
        system_prompt: &str,
        project_id: &str,
        role: &str,
        tools: bool,
        model: &str,
        stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                cwd: cwd.to_string(),
                system_prompt: Mutex::new(system_prompt.to_string()),
                project_id: project_id.to_string(),
                role: role.to_string(),
                tools,
                model: model.trim().to_string(),
                run_id: Mutex::new(String::new()),
                review_job_id: Mutex::new(String::new()),
                emit: Mutex::new(None),
                stop,
                child: Mutex::new(None),
                stdin: Mutex::new(None),
                texts: Mutex::new(Vec::new()),
                tool_uses: AtomicU64::new(0),
                settled: Mutex::new(false),
                settled_cv: Condvar::new(),
                ack: Mutex::new(Ack {
                    epoch: 0,
                    value: None,
                }),
                ack_cv: Condvar::new(),
                closed: AtomicBool::new(false),
                text_acc: Mutex::new(Vec::new()),
                thought_acc: Mutex::new(Vec::new()),
                last_text: Mutex::new(String::new()),
                last_thought: Mutex::new(String::new()),
                turn_closed: AtomicBool::new(false),
                last_prompt: Mutex::new(None),
                idle_turns: AtomicU64::new(0),
                activity: AtomicU64::new(0),
                activity_hook: Mutex::new(None),
                reader: Mutex::new(None),
                stderr_thread: Mutex::new(None),
            }),
        }
    }

    pub fn role(&self) -> String {
        self.inner.role.clone()
    }

    pub fn tools(&self) -> bool {
        self.inner.tools
    }

    pub fn set_run_id(&self, run_id: &str) {
        *lock(&self.inner.run_id) = run_id.to_string();
    }

    pub fn run_id(&self) -> String {
        lock(&self.inner.run_id).clone()
    }

    pub fn review_job_id(&self) -> String {
        lock(&self.inner.review_job_id).clone()
    }

    pub fn set_emit(&self, emit: EmitFn) {
        *lock(&self.inner.emit) = Some(emit);
    }

    pub fn set_review_job(&self, job_id: &str) {
        *lock(&self.inner.review_job_id) = job_id.to_string();
    }

    pub fn set_system_prompt(&self, text: &str) {
        *lock(&self.inner.system_prompt) = text.to_string();
    }

    pub fn texts(&self) -> Vec<String> {
        lock(&self.inner.texts).clone()
    }

    pub fn set_idle_turns(&self, n: u64) {
        self.inner.idle_turns.store(n, Ordering::SeqCst);
    }

    pub fn set_activity_hook(&self, hook: Option<Arc<dyn Fn() + Send + Sync>>) {
        *lock(&self.inner.activity_hook) = hook;
    }

    pub fn tool_uses(&self) -> u64 {
        self.inner.tool_uses.load(Ordering::SeqCst)
    }

    pub fn idle_turns(&self) -> u64 {
        self.inner.idle_turns.load(Ordering::SeqCst)
    }

    pub fn reset_idle_turns(&self) {
        self.inner.idle_turns.store(0, Ordering::SeqCst);
    }

    pub fn bump_idle_turns(&self) -> u64 {
        self.inner.idle_turns.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn last_prompt_elapsed(&self) -> Option<Duration> {
        lock(&self.inner.last_prompt).map(|t| t.elapsed())
    }

    pub fn is_settled(&self) -> bool {
        *lock(&self.inner.settled)
    }

    pub fn command_line(&self, settings: &Settings) -> Vec<String> {
        let _ = fs::create_dir_all(&self.inner.cwd);
        let prompt_path =
            Path::new(&self.inner.cwd).join(format!(".pi-system-{}.txt", self.inner.role));
        let prompt = lock(&self.inner.system_prompt).clone();
        let _ = fs::write(&prompt_path, prompt);
        let model = if self.inner.model.is_empty() {
            pi_model(settings)
        } else {
            self.inner.model.clone()
        };
        let mut cmd = vec![
            pi_bin(settings),
            "--mode".into(),
            "rpc".into(),
            "--no-session".into(),
            "--offline".into(),
            "--provider".into(),
            pi_provider(settings),
            "--model".into(),
            model,
            "--system-prompt".into(),
            "StrikeAgent_AtkBrain-Flash".into(),
            "--append-system-prompt".into(),
            prompt_path.display().to_string(),
        ];
        if self.inner.tools {
            cmd.extend([
                "--no-context-files".into(),
                "--no-extensions".into(),
                "-e".into(),
                extension_path().display().to_string(),
                "--no-skills".into(),
                "--no-builtin-tools".into(),
            ]);
        } else {
            cmd.extend([
                "--no-tools".into(),
                "--no-builtin-tools".into(),
                "--no-extensions".into(),
                "--no-skills".into(),
                "--no-context-files".into(),
            ]);
        }
        cmd
    }

    pub fn start(&self, settings: &Settings) -> Result<(), String> {
        let _ = ensure_pi_agent_dir(settings, None);
        let cmd = self.command_line(settings);
        wait_spawn_slot(
            settings,
            &self.inner.project_id,
            &self.inner.role,
            Duration::from_secs(180),
            &self.inner.stop,
        )?;
        let mut command = Command::new(&cmd[0]);
        command
            .args(&cmd[1..])
            .current_dir(&self.inner.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(child_env(
                settings,
                &self.inner.project_id,
                &self.inner.role,
            ));
        for k in [
            "http_proxy",
            "https_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "all_proxy",
        ] {
            command.env_remove(k);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                note_spawn_failed(&self.inner.project_id, &self.inner.role);
                return Err(e.to_string());
            }
        };
        let pid = child.id() as i32;
        if pid > 0 {
            note_spawned(pid, &self.inner.project_id, &self.inner.role);
        } else {
            note_spawn_failed(&self.inner.project_id, &self.inner.role);
        }
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        *lock(&self.inner.child) = Some(child);
        *lock(&self.inner.stdin) = stdin;
        self.inner.closed.store(false, Ordering::SeqCst);
        let reader_self = self.clone();
        *lock(&self.inner.reader) = Some(thread::spawn(move || reader_self.read_loop(stdout)));
        let err_self = self.clone();
        *lock(&self.inner.stderr_thread) =
            Some(thread::spawn(move || err_self.drain_stderr(stderr)));
        Ok(())
    }

    fn drain_stderr(&self, stderr: Option<impl Read>) {
        let Some(mut stderr) = stderr else { return };
        let path = Path::new(&self.inner.cwd).join("logs");
        let _ = fs::create_dir_all(&path);
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.join(format!("pi-{}.err.log", self.inner.role)))
            .ok();
        let mut buf = [0u8; 4096];
        loop {
            let n = match stderr.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if let Some(f) = file.as_mut() {
                let _ = f.write_all(&buf[..n]);
                let _ = f.flush();
            }
            let text = String::from_utf8_lossy(&buf[..n]);
            let trimmed = text.trim();
            if trimmed.contains("Unknown option")
                || trimmed.to_ascii_lowercase().contains("unknown option")
                || trimmed.contains("Failed to load extension")
            {
                let msg = format!(
                    "Pi 启动失败：{}",
                    trimmed.chars().take(300).collect::<String>()
                );
                self.emit_log("error", &msg);
            }
        }
    }

    fn read_loop(&self, stdout: Option<impl Read>) {
        let Some(mut stdout) = stdout else {
            self.mark_settled();
            return;
        };
        let mut buf: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let n = match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let mut raw: Vec<u8> = buf.drain(..=i).collect();
                raw.pop();
                if raw.last() == Some(&b'\r') {
                    raw.pop();
                }
                if raw.iter().all(|b| b.is_ascii_whitespace()) {
                    continue;
                }
                let text = String::from_utf8_lossy(&raw);
                if let Ok(event) = serde_json::from_str::<Value>(&text) {
                    if event.is_object() {
                        self.on_event(&event);
                    }
                }
            }
        }
        self.mark_settled();
        self.finish_ack(false);
    }

    fn review_job(&self) -> String {
        lock(&self.inner.review_job_id).clone()
    }

    fn review_beat(&self, typ: &str, event: &Value) {
        let jid = self.review_job();
        if jid.is_empty() {
            return;
        }
        let detail = if typ == "message_update" {
            let ev = event
                .get("assistantMessageEvent")
                .cloned()
                .unwrap_or(Value::Null);
            let et = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if matches!(
                et,
                "text_delta" | "text_end" | "thinking_delta" | "thinking_end"
            ) {
                "模型生成中".into()
            } else if et == "toolcall_start" {
                let name = ev
                    .get("toolName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if name.is_empty() {
                    "正在调用工具".into()
                } else {
                    format!("正在调用 {name}")
                }
            } else {
                String::new()
            }
        } else if typ == "tool_execution_start" {
            let name = event
                .get("toolName")
                .or_else(|| event.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                "正在调用工具".into()
            } else {
                format!("正在调用 {name}")
            }
        } else if typ == "compaction_start" {
            "正在压缩上下文".into()
        } else {
            String::new()
        };
        if detail.is_empty() {
            return;
        }
        crate::review::note_review_beat(&jid, &detail);
    }

    fn pulse_review(&self) {
        let jid = self.review_job();
        if !jid.is_empty() {
            crate::review::pulse_review(&jid);
        }
    }

    pub fn on_event(&self, event: &Value) {
        let typ = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if typ == "response" {
            if event.get("command").and_then(|v| v.as_str()) == Some("prompt") {
                self.finish_ack(
                    event
                        .get("success")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                );
            }
            return;
        }
        self.inner.activity.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = lock(&self.inner.activity_hook).clone() {
            hook();
        }
        self.review_beat(typ, event);
        if typ == "agent_settled" {
            self.flush_streams();
            self.mark_settled();
            return;
        }
        if typ == "message_end" || typ == "turn_end" {
            self.flush_streams();
            let msg = event.get("message").cloned().unwrap_or(Value::Null);
            if !self.inner.tools && msg.get("role").and_then(|v| v.as_str()) == Some("assistant") {
                let text = assistant_text(&msg);
                if !text.is_empty() {
                    let mut texts = lock(&self.inner.texts);
                    if texts.last().map(|s| s != &text).unwrap_or(true) {
                        texts.push(text);
                    }
                }
                let stop = msg.get("stopReason").and_then(|v| v.as_str()).unwrap_or("");
                if stop != "aborted" {
                    self.mark_settled();
                }
            }
            return;
        }
        if typ == "agent_end" && event.get("willRetry").and_then(|v| v.as_bool()) != Some(true) {
            if !self.inner.tools {
                self.flush_streams();
                if let Some(items) = event.get("messages").and_then(|v| v.as_array()) {
                    for item in items {
                        let text = assistant_text(item);
                        if text.is_empty() {
                            continue;
                        }
                        let mut texts = lock(&self.inner.texts);
                        if texts.last().map(|s| s != &text).unwrap_or(true) {
                            texts.push(text);
                        }
                    }
                }
                self.mark_settled();
            }
            return;
        }
        if typ == "message_update" {
            let ev = event
                .get("assistantMessageEvent")
                .cloned()
                .unwrap_or(Value::Null);
            let et = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match et {
                "text_delta" => {
                    let d = ev.get("delta").and_then(|v| v.as_str()).unwrap_or("");
                    if !d.is_empty() {
                        lock(&self.inner.texts).push(d.to_string());
                        lock(&self.inner.text_acc).push(d.to_string());
                    }
                }
                "text_end" => {
                    self.flush_text(ev.get("content").and_then(|v| v.as_str()).unwrap_or(""))
                }
                "thinking_delta" => {
                    let d = ev.get("delta").and_then(|v| v.as_str()).unwrap_or("");
                    if !d.is_empty() {
                        lock(&self.inner.thought_acc).push(d.to_string());
                    }
                }
                "thinking_end" => {
                    self.flush_thought(ev.get("content").and_then(|v| v.as_str()).unwrap_or(""))
                }
                "toolcall_start" => {
                    self.flush_streams();
                    let name = ev.get("toolName").and_then(|v| v.as_str()).unwrap_or("");
                    if !name.is_empty() && !is_graph_tool(name) {
                        self.inner.tool_uses.fetch_add(1, Ordering::SeqCst);
                        self.emit_event("tool", json!({"tool": name, "role": self.inner.role}));
                    }
                }
                _ => {}
            }
            return;
        }
        if typ == "tool_execution_start" {
            let name = event
                .get("toolName")
                .or_else(|| event.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if is_graph_tool(name) {
                self.inner.tool_uses.fetch_add(1, Ordering::SeqCst);
            }
            return;
        }
        if typ == "compaction_start" {
            self.emit_log("info", "Pi 上下文接近上限，正在自动压缩。");
        }
    }

    fn flush_text(&self, content: &str) {
        let acc = {
            let mut g = lock(&self.inner.text_acc);
            let joined = g.concat();
            g.clear();
            joined
        };
        let text = if content.is_empty() {
            acc
        } else {
            content.to_string()
        };
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }
        {
            let mut last = lock(&self.inner.last_text);
            if *last == text {
                return;
            }
            *last = text.clone();
        }
        let shown: String = text.chars().take(8000).collect();
        self.emit_event("text", json!({"text": shown, "role": self.inner.role}));
        if !self.inner.turn_closed.load(Ordering::SeqCst)
            && !is_oneshot_role(&self.inner.role)
            && role_wrote_turn_done(&text, &self.inner.role)
        {
            self.inner.turn_closed.store(true, Ordering::SeqCst);
            let who = if self.inner.role == "lead" {
                "从者".to_string()
            } else {
                format!("工人 {}", self.inner.role)
            };
            self.emit_log(
                "info",
                &format!("{who}已写本轮收尾，结束该会话以让御主开口。"),
            );
            let _ = self.abort();
        }
    }

    fn flush_thought(&self, content: &str) {
        let acc = {
            let mut g = lock(&self.inner.thought_acc);
            let joined = g.concat();
            g.clear();
            joined
        };
        let text = if content.is_empty() {
            acc
        } else {
            content.to_string()
        };
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }
        {
            let mut last = lock(&self.inner.last_thought);
            if *last == text {
                return;
            }
            *last = text.clone();
        }
        let shown: String = text.chars().take(8000).collect();
        self.emit_event(
            "thought",
            json!({"message": shown, "kind": "reasoning", "role": self.inner.role}),
        );
    }

    fn flush_streams(&self) {
        self.flush_thought("");
        self.flush_text("");
    }

    fn emit_log(&self, level: &str, message: &str) {
        self.emit_event("log", json!({"level": level, "message": message}));
    }

    fn emit_event(&self, kind: &str, payload: Value) {
        if self.inner.project_id.is_empty() {
            return;
        }
        let emit = lock(&self.inner.emit).clone();
        let Some(emit) = emit else { return };
        let run = lock(&self.inner.run_id).clone();
        let run_id = if run.is_empty() { None } else { Some(run) };
        emit(&self.inner.project_id, kind, &payload, run_id.as_deref());
    }

    fn send(&self, obj: &Value) -> Result<(), String> {
        let line = serde_json::to_string(obj).map_err(|e| e.to_string())?;
        let mut stdin = lock(&self.inner.stdin);
        let Some(stdin) = stdin.as_mut() else {
            return Err("pi rpc stdin closed".into());
        };
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .map_err(|e| e.to_string())?;
        stdin.flush().map_err(|e| e.to_string())
    }

    pub fn alive(&self) -> bool {
        if self.inner.closed.load(Ordering::SeqCst) {
            return false;
        }
        let mut child = lock(&self.inner.child);
        let Some(child) = child.as_mut() else {
            return false;
        };
        matches!(child.try_wait(), Ok(None))
    }

    pub fn pid(&self) -> Option<i32> {
        lock(&self.inner.child).as_ref().map(|c| c.id() as i32)
    }

    pub fn prompt(
        &self,
        message: &str,
        timeout: Duration,
        hang: Duration,
    ) -> Result<String, String> {
        *lock(&self.inner.texts) = Vec::new();
        *lock(&self.inner.text_acc) = Vec::new();
        *lock(&self.inner.thought_acc) = Vec::new();
        *lock(&self.inner.last_text) = String::new();
        *lock(&self.inner.last_thought) = String::new();
        self.reset_settled();
        self.inner.turn_closed.store(false, Ordering::SeqCst);
        *lock(&self.inner.last_prompt) = Some(Instant::now());
        self.inner.idle_turns.store(0, Ordering::SeqCst);
        let epoch = {
            let mut ack = lock(&self.inner.ack);
            ack.epoch += 1;
            ack.value = None;
            ack.epoch
        };
        self.send(&json!({"id": format!("p{epoch}"), "type": "prompt", "message": message}))?;
        let ack_ok = self.wait_ack(epoch, Duration::from_secs(30));
        let mut wait = timeout;
        if !self.inner.tools && !ack_ok {
            wait = if timeout.is_zero() {
                Duration::from_secs(15)
            } else {
                timeout.min(Duration::from_secs(15))
            };
        }
        match self.wait_settled(wait, hang) {
            Err(e) if e == "timeout" => {
                let text = self.current_reply();
                let _ = self.abort();
                if !text.is_empty() {
                    return Ok(text);
                }
                Err(e)
            }
            Err(e) => Err(e),
            Ok(()) => Ok(self.current_reply()),
        }
    }

    pub fn current_reply(&self) -> String {
        let texts = lock(&self.inner.texts).clone();
        reply_text(self.inner.tools, &texts)
    }

    fn wait_ack(&self, epoch: u64, dur: Duration) -> bool {
        let deadline = Instant::now() + dur;
        let mut g = lock(&self.inner.ack);
        loop {
            if g.epoch == epoch {
                if let Some(v) = g.value {
                    return v;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (ng, _) = self
                .inner
                .ack_cv
                .wait_timeout(g, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            g = ng;
        }
    }

    fn finish_ack(&self, ok: bool) {
        let mut g = lock(&self.inner.ack);
        if g.value.is_none() {
            g.value = Some(ok);
        }
        self.inner.ack_cv.notify_all();
    }

    fn wait_settled(&self, timeout: Duration, hang: Duration) -> Result<(), String> {
        let start = Instant::now();
        let mut seen = self.inner.activity.load(Ordering::SeqCst);
        let mut last = Instant::now();
        loop {
            self.pulse_review();
            if *lock(&self.inner.settled) {
                return Ok(());
            }
            if self.inner.stop.load(Ordering::SeqCst) {
                return Err("stopped".into());
            }
            let now_act = self.inner.activity.load(Ordering::SeqCst);
            if now_act != seen {
                seen = now_act;
                last = Instant::now();
            }
            if !timeout.is_zero() && start.elapsed() >= timeout {
                return Err("timeout".into());
            }
            if !hang.is_zero() && last.elapsed() >= hang {
                return Err("hang".into());
            }
            let slice = {
                let mut slice = Duration::from_secs(8);
                if !timeout.is_zero() {
                    let left = timeout.saturating_sub(start.elapsed());
                    slice = slice.min(left.max(Duration::from_millis(100)));
                }
                if !hang.is_zero() {
                    let left = hang.saturating_sub(last.elapsed());
                    slice = slice.min(left.max(Duration::from_millis(100)));
                }
                slice
            };
            let g = lock(&self.inner.settled);
            if *g {
                return Ok(());
            }
            let (g, _) = self
                .inner
                .settled_cv
                .wait_timeout(g, slice)
                .unwrap_or_else(|e| e.into_inner());
            if *g {
                return Ok(());
            }
            drop(g);
            if !self.alive() {
                return Err("pi process exited".into());
            }
        }
    }

    pub fn abort(&self) -> Result<(), String> {
        let sent = self.send(&json!({"type": "abort"}));
        self.mark_settled();
        self.finish_ack(false);
        sent
    }

    fn mark_settled(&self) {
        *lock(&self.inner.settled) = true;
        self.inner.settled_cv.notify_all();
    }

    fn reset_settled(&self) {
        *lock(&self.inner.settled) = false;
    }

    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.flush_streams();
        let _ = self.abort();
        {
            let mut stdin = lock(&self.inner.stdin);
            if let Some(mut stdin) = stdin.take() {
                let _ = stdin.flush();
            }
        }
        let pid = self.pid().unwrap_or(0);
        if pid > 0 {
            kill_tree(pid, 15);
        }
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(4) && self.alive() {
            thread::sleep(Duration::from_millis(50));
        }
        if self.alive() && pid > 0 {
            kill_tree(pid, 9);
            for extra in scan_pi_pids(&self.inner.project_id, &self.inner.role) {
                kill_tree(extra, 9);
            }
            if let Some(child) = lock(&self.inner.child).as_mut() {
                let _ = child.kill();
            }
        }
        if let Some(reader) = lock(&self.inner.reader).take() {
            let start = Instant::now();
            while !reader.is_finished() && start.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(20));
            }
            if reader.is_finished() {
                let _ = reader.join();
            }
        }
        if pid > 0 && pid_alive(pid) {
            kill_tree(pid, 9);
            thread::sleep(Duration::from_millis(80));
        }
        if pid > 0 && !untrack_dead(pid) {
            for extra in scan_pi_pids(&self.inner.project_id, &self.inner.role) {
                kill_tree(extra, 9);
            }
            thread::sleep(Duration::from_millis(50));
            let _ = untrack_dead(pid);
        }
        *lock(&self.inner.child) = None;
        notify_spawn();
    }
}

pub fn query_text(
    settings: &Settings,
    system_prompt: &str,
    user_prompt: &str,
    cwd: &str,
    timeout: Duration,
    tools: bool,
    model: &str,
    role: &str,
    project_id: &str,
    emit: Option<EmitFn>,
) -> Result<String, String> {
    let work = if cwd.is_empty() {
        settings.data_dir.display().to_string()
    } else {
        cwd.to_string()
    };
    let _ = fs::create_dir_all(&work);
    let role = if role.trim().is_empty() {
        "oneshot"
    } else {
        role.trim()
    };
    let sess = PiSession::new(&work, system_prompt, project_id, role, tools, model);
    if let Some(emit) = emit {
        sess.set_emit(emit);
    }
    let started = Instant::now();
    sess.start(settings)?;
    let remain = timeout
        .saturating_sub(started.elapsed())
        .max(Duration::from_secs(5));
    let result = sess.prompt(user_prompt, remain, Duration::ZERO);
    sess.close();
    result
}

pub fn is_dead_cli_error(text: &str) -> bool {
    let low = text.to_ascii_lowercase();
    low.contains("cannot write to terminated process")
        || low.contains("terminated process")
        || low.contains("sigsegv")
        || low.contains("broken pipe")
        || low.contains("connection reset")
        || low.contains("pi rpc stdin closed")
        || low.contains("exit code:")
}

pub fn is_retryable_connect_error(text: &str) -> bool {
    is_dead_cli_error(text)
        || text.to_ascii_lowercase().contains("pi ")
        || text.to_ascii_lowercase().contains("rpc")
}

fn is_graph_tool(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    GRAPH_TOOLS.iter().any(|t| *t == low)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn temp_settings() -> Settings {
        let dir = std::env::temp_dir().join(format!(
            "atk-pi-{}-{}",
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
        Settings::from_map(&env, &dir)
    }

    #[test]
    fn reply_text_does_not_duplicate_stream_and_full_message() {
        let chunks = vec!["hel".into(), "lo".into(), "hello".into()];
        assert_eq!(reply_text(false, &chunks), "hello");
        assert_eq!(reply_text(true, &chunks), "hellohello");
        let doubled = "abcdefghijkl".repeat(2);
        assert_eq!(collapse_duplicate(&doubled), "abcdefghijkl");
        assert_eq!(collapse_duplicate("short"), "short");
        let settings = temp_settings();
        let dir = settings.data_dir.join("cwd");
        let _ = fs::create_dir_all(&dir);
        let s = PiSession::new(
            dir.to_str().unwrap_or("/tmp"),
            "x",
            "",
            "supervisor",
            false,
            "deepseek-flash",
        );
        s.on_event(&json!({"type": "message_update", "assistantMessageEvent": {"type": "text_delta", "delta": "hel"}}));
        s.on_event(&json!({"type": "message_update", "assistantMessageEvent": {"type": "text_delta", "delta": "lo"}}));
        s.on_event(&json!({"type": "message_end", "message": {"role": "assistant", "content": [{"type": "text", "text": "hello"}]}}));
        assert_eq!(s.current_reply(), "hello");
        assert!(s.is_settled());
    }

    #[test]
    fn command_line_uses_rpc_and_no_session() {
        let settings = temp_settings();
        assert_eq!(pi_per_project_limit(&settings), 4);
        assert_eq!(pi_max_live_limit(&settings), 32);
        let roles = ["web-exploit", "recon", "rce-hunt", "privesc", "lateral"];
        assert_eq!(
            cap_hunt_workers(&settings, &roles, Some(4)),
            vec!["web-exploit", "recon", "rce-hunt"]
        );
        assert!(cap_hunt_workers(&settings, &roles, Some(1)).is_empty());
        let mixed = [
            "finding-review",
            "supervisor",
            "console-explain",
            "web-exploit",
            "recon",
        ];
        assert_eq!(
            cap_hunt_workers(&settings, &mixed, Some(4)),
            vec!["web-exploit", "recon"]
        );
        let dir = settings.data_dir.join("launch");
        let _ = fs::create_dir_all(&dir);
        let s = PiSession::new(
            dir.to_str().unwrap_or("/tmp"),
            "x",
            "p",
            "lead",
            true,
            "deepseek-flash",
        );
        let cmd = s.command_line(&settings);
        let joined = cmd.join(" ");
        assert!(joined.contains("--mode rpc"), "{joined}");
        assert!(cmd.iter().any(|p| p == "--no-session"), "{joined}");
        assert!(cmd.iter().any(|p| p == "--no-skills"));
        assert!(cmd.iter().any(|p| p == "--no-builtin-tools"));
        assert!(!cmd.iter().any(|p| p == "--skill"));
        assert!(!joined.contains("deepseek_harness"));
        let provider = cmd
            .iter()
            .position(|p| p == "--provider")
            .expect("provider");
        assert_eq!(cmd[provider + 1], "deepseek");
        let explain = PiSession::new(
            dir.to_str().unwrap_or("/tmp"),
            "x",
            "",
            "console-explain",
            false,
            "deepseek-flash",
        );
        let explain_cmd = explain.command_line(&settings);
        assert!(explain_cmd.windows(2).any(|w| w == ["--mode", "rpc"]));
        assert!(explain_cmd.iter().any(|p| p == "--no-session"));
        assert!(explain_cmd.iter().any(|p| p == "--no-tools"));
        assert!(is_oneshot_role("console-explain"));
        assert!(!counts_toward_per_project("console-explain"));
    }

    #[test]
    fn oneshot_assistant_settles_and_user_echo_does_not() {
        let s = PiSession::new("/tmp", "x", "", "supervisor", false, "m");
        s.on_event(&json!({"type": "message_end", "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]}}));
        assert!(!s.is_settled());
        s.on_event(&json!({"type": "message_end", "message": {"role": "assistant", "content": [{"type": "text", "text": "{\"diagnosis\":\"ok\"}"}]}}));
        assert!(s.is_settled());
        assert!(s.current_reply().contains("{\"diagnosis\":\"ok\"}"));
        let aborted = PiSession::new("/tmp", "x", "", "supervisor", false, "m");
        aborted.on_event(&json!({"type": "message_end", "message": {"role": "assistant", "stopReason": "aborted", "content": []}}));
        assert!(!aborted.is_settled());
        let tools = PiSession::new("/tmp", "x", "", "lead", true, "m");
        tools.on_event(&json!({"type": "message_end", "message": {"role": "assistant", "content": [{"type": "text", "text": "still working"}]}}));
        assert!(!tools.is_settled());
        tools.on_event(&json!({"type": "agent_settled"}));
        assert!(tools.is_settled());
    }

    #[test]
    fn placeholder_api_key_is_not_configured() {
        assert!(usable_api_key("").is_empty());
        assert!(usable_api_key("$DEEPSEEK_API_KEY").is_empty());
        assert!(usable_api_key("changeme").is_empty());
        assert_eq!(usable_api_key("sk-real"), "sk-real");
    }
}
