//! 环境变量前缀 ATKBRAIN_。空字符串不当成真。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::gateway::{apply_llm_gateway, apply_platform_env_aliases, gateway_enabled};

#[derive(Clone, Debug)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub frontend_port: u16,
    pub data_dir: PathBuf,
    pub db_path: PathBuf,
    pub workspaces_dir: PathBuf,
    pub loot_dir: PathBuf,
    pub reports_dir: PathBuf,
    pub max_redteam_concurrency: i64,
    pub max_redteam_concurrency_cap: i64,
    pub max_ctf_concurrency: i64,
    pub max_ctf_concurrency_cap: i64,
    pub max_project_concurrency: i64,
    pub max_project_concurrency_cap: i64,
    pub max_concurrency: i64,
    pub max_concurrency_cap: i64,
    pub pi_max_live: i64,
    pub pi_max_live_cap: i64,
    pub pi_per_project: i64,
    pub pi_per_project_cap: i64,
    pub claude_per_project: i64,
    pub claude_per_project_cap: i64,
    pub claude_spawn_max_concurrent: i64,
    pub pi_worker_idle_sec: f64,
    pub pi_worker_idle_turns: i64,
    pub claude_spawn_jitter_max_sec: f64,
    pub claude_spawn_settle_ms: i64,
    pub claude_connect_retries: i64,
    pub claude_add_repo_dir: bool,
    pub loop_max_turns: i64,
    pub loop_max_turns_agent: i64,
    pub loop_max_turns_src: i64,
    pub loop_max_turns_redteam: i64,
    pub agent_runtime_hard_stop_sec: i64,
    pub src_runtime_hard_stop_sec: i64,
    pub loop_max_turns_benchmark: i64,
    pub loop_stall_limit: i64,
    pub loop_stall_limit_agent: i64,
    pub loop_stall_limit_redteam: i64,
    pub loop_stall_limit_src: i64,
    pub loop_stall_limit_flag: i64,
    pub loop_spiral_empty_plans: i64,
    pub loop_supervise_soft_turns: i64,
    pub loop_supervise_hard_turns: i64,
    pub advisor_first_turns: i64,
    pub advisor_min_turn_interval: i64,
    pub advisor_hold_turns: i64,
    pub advisor_bind_refresh_misses: i64,
    pub supervisor_model: String,
    pub supervisor_timeout_sec: i64,
    pub supervisor_attempt_timeout_sec: i64,
    pub supervisor_consult_max_attempts: i64,
    pub supervisor_consult_retry_base_sec: f64,
    pub supervisor_cooldown_sec: f64,
    pub supervisor_fail_cooldown_sec: f64,
    pub supervisor_plan_dwell_turns: i64,
    pub supervisor_consult_stall_turns: i64,
    pub evolve_ai: bool,
    pub evolve_model: String,
    pub evolve_timeout_sec: i64,
    pub report_ai: bool,
    pub report_model: String,
    pub report_timeout_sec: i64,
    pub turn_max_agent_turns: i64,
    pub turn_max_seconds: i64,
    pub turn_advisor_yield_sec: i64,
    pub turn_must_close_sec: i64,
    pub turn_hang_sec: i64,
    pub cmd_timeout: i64,
    pub graph_idle_pause_sec: i64,
    pub graph_idle_empty_plans: i64,
    pub graph_idle_cmd_progress_sec: i64,
    pub runtime_review_after_sec: i64,
    pub runtime_review_interval_sec: i64,
    pub runtime_hard_stop_sec: i64,
    pub runtime_hard_stop_pass2_sec: i64,
    pub runtime_hard_stop_pass3_sec: i64,
    pub runtime_hard_stop_pass_step_sec: i64,
    pub redteam_runtime_hard_stop_sec: i64,
    pub entry_unreachable_yield_sec: i64,
    pub claude_model: String,
    pub claude_fallback_model: String,
    pub pi_bin: String,
    pub pi_provider: String,
    pub pi_model: String,
    pub default_objective: String,
    pub api_token: String,
    pub admin_user: String,
    pub admin_password: String,
    pub admin_password_reset: bool,
    pub auth_no_auth: String,
    pub security_entry: String,
    pub cors_origins: String,
    pub force_https: bool,
    pub public_origin: String,
    pub session_max_age_sec: i64,
    pub github_repo: String,
    pub github_token: String,
    pub benchmark_base_url: String,
    pub benchmark_token: String,
    pub benchmark_max_concurrency: i64,
    pub benchmark_max_concurrency_cap: i64,
    pub benchmark_run_budget_sec: i64,
    pub benchmark_run_budget_cap: i64,
    pub benchmark_autopilot: bool,
    pub benchmark_autopilot_interval_sec: i64,
    pub benchmark_autopilot_resume: bool,
    pub benchmark_no_flag_rotate_sec: i64,
    pub benchmark_hard_no_flag_rotate_sec: i64,
    pub benchmark_first_pass_dwell_sec: i64,
    pub benchmark_coverage_dwell_floor_sec: i64,
    pub benchmark_coverage_grow_grace_sec: i64,
    pub benchmark_min_attempt_sec: i64,
    pub benchmark_min_hunt_sec: i64,
    pub benchmark_entry_ready_sec: i64,
    pub benchmark_watchdog_idle_ticks: i64,
    pub lab_src_rotate_sec: i64,
    pub benchmark_entry_down_rebind_sec: i64,
    pub benchmark_entry_down_yield_sec: i64,
    pub redteam_entry_down_yield_sec: i64,
    pub benchmark_autopilot_second_pass: bool,
    pub benchmark_max_attempts: i64,
    pub benchmark_multiflag_threshold: i64,
    pub benchmark_max_multiflag_concurrent: i64,
    pub benchmark_focus_codes: String,
}

pub fn repo_root() -> PathBuf {
    if let Ok(p) = std::env::var("ATKBRAIN_REPO_ROOT") {
        if !p.trim().is_empty() {
            return PathBuf::from(p);
        }
    }
    let mut dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for _ in 0..8 {
        if dir.join("compose.yaml").is_file() && dir.join("backend").is_dir() {
            return dir;
        }
        if !dir.pop() {
            break;
        }
    }
    PathBuf::from(".")
}

impl Settings {
    pub fn from_env() -> Self {
        let root = repo_root();
        let mut env: HashMap<String, String> = std::env::vars().collect();
        load_dotenv(&root.join(".env"), &mut env);
        let mapped = apply_platform_env_aliases(&mut env);
        let changed = if gateway_enabled(&env) {
            apply_llm_gateway(&mut env)
        } else {
            HashMap::new()
        };
        for key in mapped.into_keys().chain(changed.keys().cloned()) {
            if let Some(val) = env.get(&key) {
                std::env::set_var(&key, val);
            }
        }
        if !changed.is_empty() {
            let keys: Vec<_> = changed.keys().cloned().collect();
            println!("[config] LLM API 已改写为 tsecbench 网关: {}", keys.join(", "));
        }
        Self::from_map(&env, &root)
    }

    pub fn from_map(env: &HashMap<String, String>, root: &Path) -> Self {
        let data_default = root.join("backend").join("data");
        let data_dir = path_or(env, "DATA_DIR", &data_default);
        let db_path = path_or(env, "DB_PATH", &data_default.join("atkbrain.db"));
        let workspaces_dir = path_or(env, "WORKSPACES_DIR", &data_default.join("workspaces"));
        let loot_dir = path_or(env, "LOOT_DIR", &data_default.join("loot"));
        let reports_dir = path_or(env, "REPORTS_DIR", &data_default.join("reports"));
        Self {
            host: string_or(env, "HOST", "127.0.0.1"),
            port: u16_or(env, "PORT", 2333),
            frontend_port: u16_or(env, "FRONTEND_PORT", 2334),
            data_dir,
            db_path,
            workspaces_dir,
            loot_dir,
            reports_dir,
            max_redteam_concurrency: i64_or(env, "MAX_REDTEAM_CONCURRENCY", 5),
            max_redteam_concurrency_cap: i64_or(env, "MAX_REDTEAM_CONCURRENCY_CAP", 20),
            max_ctf_concurrency: i64_or(env, "MAX_CTF_CONCURRENCY", 3),
            max_ctf_concurrency_cap: i64_or(env, "MAX_CTF_CONCURRENCY_CAP", 20),
            max_project_concurrency: i64_or(env, "MAX_PROJECT_CONCURRENCY", 5),
            max_project_concurrency_cap: i64_or(env, "MAX_PROJECT_CONCURRENCY_CAP", 20),
            max_concurrency: i64_or(env, "MAX_CONCURRENCY", 8),
            max_concurrency_cap: i64_or(env, "MAX_CONCURRENCY_CAP", 40),
            pi_max_live: i64_or(env, "PI_MAX_LIVE", 32),
            pi_max_live_cap: i64_or(env, "PI_MAX_LIVE_CAP", 96),
            pi_per_project: i64_or(env, "PI_PER_PROJECT", 4),
            pi_per_project_cap: i64_or(env, "PI_PER_PROJECT_CAP", 8),
            claude_per_project: i64_or(env, "CLAUDE_PER_PROJECT", 4),
            claude_per_project_cap: i64_or(env, "CLAUDE_PER_PROJECT_CAP", 8),
            claude_spawn_max_concurrent: i64_or(env, "CLAUDE_SPAWN_MAX_CONCURRENT", 32),
            pi_worker_idle_sec: f64_or(env, "PI_WORKER_IDLE_SEC", 180.0),
            pi_worker_idle_turns: i64_or(env, "PI_WORKER_IDLE_TURNS", 2),
            claude_spawn_jitter_max_sec: f64_or(env, "CLAUDE_SPAWN_JITTER_MAX_SEC", 0.0),
            claude_spawn_settle_ms: i64_or(env, "CLAUDE_SPAWN_SETTLE_MS", 0),
            claude_connect_retries: i64_or(env, "CLAUDE_CONNECT_RETRIES", 4),
            claude_add_repo_dir: bool_or(env, "CLAUDE_ADD_REPO_DIR", false),
            loop_max_turns: i64_or(env, "LOOP_MAX_TURNS", 0),
            loop_max_turns_agent: i64_or(env, "LOOP_MAX_TURNS_AGENT", 0),
            loop_max_turns_src: i64_or(env, "LOOP_MAX_TURNS_SRC", 0),
            loop_max_turns_redteam: i64_or(env, "LOOP_MAX_TURNS_REDTEAM", 0),
            agent_runtime_hard_stop_sec: i64_or(env, "AGENT_RUNTIME_HARD_STOP_SEC", 6 * 60 * 60),
            src_runtime_hard_stop_sec: i64_or(env, "SRC_RUNTIME_HARD_STOP_SEC", 6 * 60 * 60),
            loop_max_turns_benchmark: i64_or(env, "LOOP_MAX_TURNS_BENCHMARK", 0),
            loop_stall_limit: i64_or(env, "LOOP_STALL_LIMIT", 10),
            loop_stall_limit_agent: i64_or(env, "LOOP_STALL_LIMIT_AGENT", 10),
            loop_stall_limit_redteam: i64_or(env, "LOOP_STALL_LIMIT_REDTEAM", 10),
            loop_stall_limit_src: i64_or(env, "LOOP_STALL_LIMIT_SRC", 10),
            loop_stall_limit_flag: i64_or(env, "LOOP_STALL_LIMIT_FLAG", 0),
            loop_spiral_empty_plans: i64_or(env, "LOOP_SPIRAL_EMPTY_PLANS", 6),
            loop_supervise_soft_turns: i64_or(env, "LOOP_SUPERVISE_SOFT_TURNS", 3),
            loop_supervise_hard_turns: i64_or(env, "LOOP_SUPERVISE_HARD_TURNS", 10),
            advisor_first_turns: i64_or(env, "ADVISOR_FIRST_TURNS", 2),
            advisor_min_turn_interval: i64_or(env, "ADVISOR_MIN_TURN_INTERVAL", 3),
            advisor_hold_turns: i64_or(env, "ADVISOR_HOLD_TURNS", 3),
            advisor_bind_refresh_misses: i64_or(env, "ADVISOR_BIND_REFRESH_MISSES", 3),
            supervisor_model: string_or(env, "SUPERVISOR_MODEL", "deepseek-flash"),
            supervisor_timeout_sec: i64_or(env, "SUPERVISOR_TIMEOUT_SEC", 360),
            supervisor_attempt_timeout_sec: i64_or(env, "SUPERVISOR_ATTEMPT_TIMEOUT_SEC", 90),
            supervisor_consult_max_attempts: i64_or(env, "SUPERVISOR_CONSULT_MAX_ATTEMPTS", 0),
            supervisor_consult_retry_base_sec: f64_or(env, "SUPERVISOR_CONSULT_RETRY_BASE_SEC", 4.0),
            supervisor_cooldown_sec: f64_or(env, "SUPERVISOR_COOLDOWN_SEC", 8.0),
            supervisor_fail_cooldown_sec: f64_or(env, "SUPERVISOR_FAIL_COOLDOWN_SEC", 0.0),
            supervisor_plan_dwell_turns: i64_or(env, "SUPERVISOR_PLAN_DWELL_TURNS", 2),
            supervisor_consult_stall_turns: i64_or(env, "SUPERVISOR_CONSULT_STALL_TURNS", 2),
            evolve_ai: bool_or(env, "EVOLVE_AI", true),
            evolve_model: string_or(env, "EVOLVE_MODEL", "deepseek-flash"),
            evolve_timeout_sec: i64_or(env, "EVOLVE_TIMEOUT_SEC", 90),
            report_ai: bool_or(env, "REPORT_AI", true),
            report_model: string_or(env, "REPORT_MODEL", "deepseek-flash"),
            report_timeout_sec: i64_or(env, "REPORT_TIMEOUT_SEC", 90),
            turn_max_agent_turns: i64_or(env, "TURN_MAX_AGENT_TURNS", 60),
            turn_max_seconds: i64_or(env, "TURN_MAX_SECONDS", 0),
            turn_advisor_yield_sec: i64_or(env, "TURN_ADVISOR_YIELD_SEC", 0),
            turn_must_close_sec: i64_or(env, "TURN_MUST_CLOSE_SEC", 15 * 60),
            turn_hang_sec: i64_or(env, "TURN_HANG_SEC", 8 * 60),
            cmd_timeout: i64_or(env, "CMD_TIMEOUT", 0),
            graph_idle_pause_sec: i64_or(env, "GRAPH_IDLE_PAUSE_SEC", 0),
            graph_idle_empty_plans: i64_or(env, "GRAPH_IDLE_EMPTY_PLANS", 6),
            graph_idle_cmd_progress_sec: i64_or(env, "GRAPH_IDLE_CMD_PROGRESS_SEC", 60),
            runtime_review_after_sec: i64_or(env, "RUNTIME_REVIEW_AFTER_SEC", 0),
            runtime_review_interval_sec: i64_or(env, "RUNTIME_REVIEW_INTERVAL_SEC", 0),
            runtime_hard_stop_sec: i64_or(env, "RUNTIME_HARD_STOP_SEC", 40 * 60),
            runtime_hard_stop_pass2_sec: i64_or(env, "RUNTIME_HARD_STOP_PASS2_SEC", 120 * 60),
            runtime_hard_stop_pass3_sec: i64_or(env, "RUNTIME_HARD_STOP_PASS3_SEC", 180 * 60),
            runtime_hard_stop_pass_step_sec: i64_or(env, "RUNTIME_HARD_STOP_PASS_STEP_SEC", 60 * 60),
            redteam_runtime_hard_stop_sec: i64_or(env, "REDTEAM_RUNTIME_HARD_STOP_SEC", 6 * 60 * 60),
            entry_unreachable_yield_sec: i64_or(env, "ENTRY_UNREACHABLE_YIELD_SEC", 0),
            claude_model: string_or(env, "CLAUDE_MODEL", "deepseek-flash"),
            claude_fallback_model: string_or(env, "CLAUDE_FALLBACK_MODEL", "deepseek-flash"),
            pi_bin: string_or(env, "PI_BIN", "pi"),
            pi_provider: string_or(env, "PI_PROVIDER", "deepseek"),
            pi_model: string_or(env, "PI_MODEL", "deepseek-flash"),
            default_objective: string_or(env, "DEFAULT_OBJECTIVE", "agent"),
            api_token: string_or(env, "API_TOKEN", ""),
            admin_user: string_or(env, "ADMIN_USER", "admin"),
            admin_password: string_or(env, "ADMIN_PASSWORD", ""),
            admin_password_reset: bool_or(env, "ADMIN_PASSWORD_RESET", false),
            auth_no_auth: string_or(env, "AUTH_NO_AUTH", ""),
            security_entry: string_or(env, "SECURITY_ENTRY", ""),
            cors_origins: string_or(env, "CORS_ORIGINS", "https://127.0.0.1:2334,https://localhost:2334"),
            force_https: bool_or(env, "FORCE_HTTPS", true),
            public_origin: public_origin(env.get("ATKBRAIN_PUBLIC_ORIGIN").map(String::as_str).unwrap_or("")),
            session_max_age_sec: i64_or(env, "SESSION_MAX_AGE_SEC", 24 * 3600),
            github_repo: string_or(env, "GITHUB_REPO", "Yean-Sec/StrikeAgent_AtkBrain-Flash"),
            github_token: string_or(env, "GITHUB_TOKEN", ""),
            benchmark_base_url: string_or(env, "BENCHMARK_BASE_URL", ""),
            benchmark_token: string_or(env, "BENCHMARK_TOKEN", ""),
            benchmark_max_concurrency: i64_or(env, "BENCHMARK_MAX_CONCURRENCY", 3),
            benchmark_max_concurrency_cap: i64_or(env, "BENCHMARK_MAX_CONCURRENCY_CAP", 20),
            benchmark_run_budget_sec: i64_or(env, "BENCHMARK_RUN_BUDGET_SEC", 0),
            benchmark_run_budget_cap: i64_or(env, "BENCHMARK_RUN_BUDGET_CAP", 0),
            benchmark_autopilot: bool_or(env, "BENCHMARK_AUTOPILOT", true),
            benchmark_autopilot_interval_sec: i64_or(env, "BENCHMARK_AUTOPILOT_INTERVAL_SEC", 15),
            benchmark_autopilot_resume: bool_or(env, "BENCHMARK_AUTOPILOT_RESUME", false),
            benchmark_no_flag_rotate_sec: i64_or(env, "BENCHMARK_NO_FLAG_ROTATE_SEC", 0),
            benchmark_hard_no_flag_rotate_sec: i64_or(env, "BENCHMARK_HARD_NO_FLAG_ROTATE_SEC", 0),
            benchmark_first_pass_dwell_sec: i64_or(env, "BENCHMARK_FIRST_PASS_DWELL_SEC", 40 * 60),
            benchmark_coverage_dwell_floor_sec: i64_or(env, "BENCHMARK_COVERAGE_DWELL_FLOOR_SEC", 40 * 60),
            benchmark_coverage_grow_grace_sec: i64_or(env, "BENCHMARK_COVERAGE_GROW_GRACE_SEC", 8 * 60),
            benchmark_min_attempt_sec: i64_or(env, "BENCHMARK_MIN_ATTEMPT_SEC", 120),
            benchmark_min_hunt_sec: i64_or(env, "BENCHMARK_MIN_HUNT_SEC", 180),
            benchmark_entry_ready_sec: i64_or(env, "BENCHMARK_ENTRY_READY_SEC", 45),
            benchmark_watchdog_idle_ticks: i64_or(env, "BENCHMARK_WATCHDOG_IDLE_TICKS", 3),
            lab_src_rotate_sec: i64_or(env, "LAB_SRC_ROTATE_SEC", 60 * 60),
            benchmark_entry_down_rebind_sec: i64_or(env, "BENCHMARK_ENTRY_DOWN_REBIND_SEC", 90),
            benchmark_entry_down_yield_sec: i64_or(env, "BENCHMARK_ENTRY_DOWN_YIELD_SEC", 8 * 60),
            redteam_entry_down_yield_sec: i64_or(env, "REDTEAM_ENTRY_DOWN_YIELD_SEC", 0),
            benchmark_autopilot_second_pass: bool_or(env, "BENCHMARK_AUTOPILOT_SECOND_PASS", true),
            benchmark_max_attempts: i64_or(env, "BENCHMARK_MAX_ATTEMPTS", 8),
            benchmark_multiflag_threshold: i64_or(env, "BENCHMARK_MULTIFLAG_THRESHOLD", 3),
            benchmark_max_multiflag_concurrent: i64_or(env, "BENCHMARK_MAX_MULTIFLAG_CONCURRENT", 1),
            benchmark_focus_codes: string_or(env, "BENCHMARK_FOCUS_CODES", ""),
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for p in [&self.data_dir, &self.workspaces_dir, &self.loot_dir, &self.reports_dir] {
            std::fs::create_dir_all(p)?;
        }
        Ok(())
    }

    pub fn benchmark_slot_limit(&self) -> i64 {
        let n = if self.benchmark_max_concurrency == 0 { 3 } else { self.benchmark_max_concurrency };
        let mut cap = if self.max_ctf_concurrency_cap > 0 {
            self.max_ctf_concurrency_cap
        } else if self.benchmark_max_concurrency_cap > 0 {
            self.benchmark_max_concurrency_cap
        } else {
            20
        };
        if cap <= 0 {
            cap = 20;
        }
        n.clamp(1, cap)
    }
}

pub fn load_dotenv(path: &Path, env: &mut HashMap<String, String>) {
    let Ok(text) = std::fs::read_to_string(path) else { return };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim().trim_start_matches("export ").trim();
        if k.is_empty() || env.contains_key(k) {
            continue;
        }
        let v = v.trim();
        let v = if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
            &v[1..v.len() - 1]
        } else {
            v
        };
        env.insert(k.to_string(), v.to_string());
    }
}

fn raw<'a>(env: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    env.get(&format!("ATKBRAIN_{key}")).map(String::as_str)
}

fn string_or(env: &HashMap<String, String>, key: &str, default: &str) -> String {
    match raw(env, key) {
        Some(v) => v.to_string(),
        None => default.to_string(),
    }
}

fn i64_or(env: &HashMap<String, String>, key: &str, default: i64) -> i64 {
    match raw(env, key).map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v.parse().unwrap_or(default),
        None => default,
    }
}

fn u16_or(env: &HashMap<String, String>, key: &str, default: u16) -> u16 {
    i64_or(env, key, i64::from(default)).clamp(0, i64::from(u16::MAX)) as u16
}

fn f64_or(env: &HashMap<String, String>, key: &str, default: f64) -> f64 {
    match raw(env, key).map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v.parse().unwrap_or(default),
        None => default,
    }
}

fn bool_or(env: &HashMap<String, String>, key: &str, default: bool) -> bool {
    match raw(env, key).map(str::trim) {
        None => default,
        Some("") => false,
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

fn path_or(env: &HashMap<String, String>, key: &str, default: &Path) -> PathBuf {
    match raw(env, key).map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => PathBuf::from(v),
        None => default.to_path_buf(),
    }
}

pub fn public_origin(raw: &str) -> String {
    let mut s = raw.trim().trim_end_matches('/').to_string();
    if s.is_empty() {
        return String::new();
    }
    let low = s.to_ascii_lowercase();
    if low.starts_with("http://") {
        s = format!("https://{}", &s["http://".len()..]);
    } else if !low.starts_with("https://") {
        s = format!("https://{s}");
    }
    s.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bool_is_false_and_origin_is_https() {
        let env = HashMap::from([
            ("ATKBRAIN_ADMIN_PASSWORD_RESET".into(), "".into()),
            ("ATKBRAIN_FORCE_HTTPS".into(), "".into()),
            ("ATKBRAIN_PUBLIC_ORIGIN".into(), "example.com/".into()),
            ("ATKBRAIN_BENCHMARK_MAX_CONCURRENCY".into(), "50".into()),
        ]);
        let s = Settings::from_map(&env, Path::new("/tmp/atkbrain-missing"));
        assert!(!s.admin_password_reset);
        assert!(!s.force_https);
        assert_eq!(s.public_origin, "https://example.com");
        assert_eq!(s.benchmark_slot_limit(), 20);
        assert_eq!(s.port, 2333);
    }
}
