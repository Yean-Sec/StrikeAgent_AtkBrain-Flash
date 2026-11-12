use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use serde_json::{json, Map, Value};

use crate::auth::{self, Session};
use crate::dto::*;
use crate::error::ApiError;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    user: String,
    password: String,
    sessions: HashMap<String, Session>,
    fails: HashMap<String, (u32, u64)>,
    tickets: HashMap<String, u64>,
    pending: HashMap<String, String>,
    totp_secret: Option<Vec<u8>>,
    totp_enabled: bool,
    setups: HashMap<String, Vec<u8>>,
    review: ReviewSettings,
    clocks: Map<String, Value>,
    concurrency: i64,
    webhook: Webhook,
    proxy_enabled: bool,
    proxy_nodes: Vec<String>,
    pi_models: String,
    llm: LlmProfile,
    llm_key: String,
    changed: bool,
    projects: HashMap<String, Project>,
    langs: HashMap<String, String>,
    findings: HashMap<String, Finding>,
    events: HashMap<String, Vec<RtEvent>>,
    jobs: HashMap<String, ExportJob>,
    templates: HashMap<String, Template>,
    seq: u64,
}

impl AppState {
    pub fn new() -> Self {
        let user = std::env::var("ATKBRAIN_OPERATOR_USER").unwrap_or_else(|_| "operator".into());
        let password = std::env::var("ATKBRAIN_OPERATOR_PASSWORD").unwrap_or_else(|_| "operator".into());
        let mut clocks = Map::new();
        clocks.insert("loop_max_turns".into(), json!(30));
        clocks.insert("runtime_hard_stop_sec".into(), json!(2400));
        Self {
            inner: Arc::new(Mutex::new(Inner {
                user,
                password,
                sessions: HashMap::new(),
                fails: HashMap::new(),
                tickets: HashMap::new(),
                pending: HashMap::new(),
                totp_secret: None,
                totp_enabled: false,
                setups: HashMap::new(),
                review: ReviewSettings { secondary_verify: true, redteam_rating: true },
                clocks,
                concurrency: 3,
                webhook: Webhook { url: String::new(), severities: vec![], projects: vec![], assets: vec![] },
                proxy_enabled: false,
                proxy_nodes: vec![],
                pi_models: String::new(),
                llm: LlmProfile {
                    format: "openai".into(),
                    model: String::new(),
                    base_url: String::new(),
                    api_key_set: false,
                    api_key_hint: String::new(),
                    api_key: None,
                    ok: None,
                },
                llm_key: String::new(),
                changed: false,
                projects: HashMap::new(),
                langs: HashMap::new(),
                findings: HashMap::new(),
                events: HashMap::new(),
                jobs: HashMap::new(),
                templates: HashMap::new(),
                seq: 1,
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("state")
    }

    pub fn session(&self, headers: &HeaderMap) -> Result<Session, ApiError> {
        let id = auth::cookie_value(headers).ok_or_else(ApiError::unauthorized)?;
        self.lock().sessions.get(&id).cloned().ok_or_else(ApiError::unauthorized)
    }

    pub fn ready(&self, headers: &HeaderMap) -> Result<Session, ApiError> {
        let s = self.session(headers)?;
        if s.must_change_password {
            return Err(ApiError::forbidden());
        }
        Ok(s)
    }

    pub fn me(&self, headers: &HeaderMap) -> AuthMe {
        match self.session(headers) {
            Ok(s) => AuthMe {
                required: true,
                authenticated: true,
                username: Some(s.username),
                totp_enabled: s.totp_enabled,
                must_change_password: s.must_change_password,
            },
            Err(_) => AuthMe {
                required: true,
                authenticated: false,
                username: None,
                totp_enabled: false,
                must_change_password: false,
            },
        }
    }

    pub fn pubkey(&self) -> Pubkey {
        let ticket = format!("t{}", now_ms());
        self.lock().tickets.insert(ticket.clone(), now_secs() + 300);
        Pubkey {
            alg: "RSA-OAEP-SHA256".into(),
            pem: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----".into(),
            ticket,
            ttl: 300,
        }
    }

    pub fn login(&self, body: &LoginRequest) -> Result<(LoginResult, String), ApiError> {
        if body.username.trim().is_empty() || body.password.is_empty() {
            return Err(ApiError::invalid("用户名和口令不能为空"));
        }
        let mut g = self.lock();
        let key = body.username.trim().to_ascii_lowercase();
        if let Some((n, until)) = g.fails.get(&key).copied() {
            if n >= 5 && until > now_secs() {
                return Err(ApiError::locked());
            }
        }
        if !body.ticket.is_empty() && !g.tickets.contains_key(&body.ticket) {
            return Err(ApiError::unauthorized());
        }
        if let Some(pid) = body.pending_id.clone() {
            let user = g.pending.get(&pid).cloned().ok_or_else(ApiError::unauthorized)?;
            let secret = g.totp_secret.clone().unwrap_or_default();
            let code = body.totp.clone().unwrap_or_default();
            if !auth::totp_matches(&secret, &code) {
                return Err(ApiError::unauthorized());
            }
            g.pending.remove(&pid);
            let id = g.next_id("s");
            let sess = Session { id: id.clone(), username: user.clone(), must_change_password: false, totp_enabled: true };
            g.sessions.insert(id.clone(), sess);
            g.fails.remove(&key);
            return Ok((LoginResult {
                ok: true,
                username: Some(user),
                totp_enabled: Some(true),
                must_change_password: Some(false),
                need_totp: None,
                pending_id: None,
            }, auth::set_cookie(&id)));
        }
        if body.username != g.user || body.password != g.password {
            let entry = g.fails.entry(key).or_insert((0, 0));
            entry.0 += 1;
            if entry.0 >= 5 {
                entry.1 = now_secs() + 60;
                return Err(ApiError::locked());
            }
            return Err(ApiError::unauthorized());
        }
        if g.totp_enabled && body.totp.clone().unwrap_or_default().is_empty() {
            let user = g.user.clone();
            let pid = g.next_id("p");
            g.pending.insert(pid.clone(), user);
            return Ok((LoginResult {
                ok: false,
                username: None,
                totp_enabled: Some(true),
                must_change_password: None,
                need_totp: Some(true),
                pending_id: Some(pid),
            }, String::new()));
        }
        let must = !g.changed;
        let id = g.next_id("s");
        let username = g.user.clone();
        let totp = g.totp_enabled;
        g.sessions.insert(id.clone(), Session { id: id.clone(), username: username.clone(), must_change_password: must, totp_enabled: totp });
        g.fails.remove(&key);
        Ok((LoginResult {
            ok: true,
            username: Some(username),
            totp_enabled: Some(totp),
            must_change_password: Some(must),
            need_totp: None,
            pending_id: None,
        }, auth::set_cookie(&id)))
    }

    pub fn logout(&self, headers: &HeaderMap) -> Result<String, ApiError> {
        let s = self.session(headers)?;
        self.lock().sessions.remove(&s.id);
        Ok(auth::clear_cookie())
    }

    pub fn change_password(&self, headers: &HeaderMap, body: &PasswordRequest) -> Result<PasswordResult, ApiError> {
        let s = self.session(headers)?;
        if !auth::password_ok(&body.new_password) {
            return Err(ApiError::invalid("口令至少 8 位，并包含大小写字母和数字"));
        }
        let mut g = self.lock();
        if body.old_password != g.password {
            return Err(ApiError::unauthorized());
        }
        g.password = body.new_password.clone();
        g.mark_changed();
        if let Some(sess) = g.sessions.get_mut(&s.id) {
            sess.must_change_password = false;
        }
        Ok(PasswordResult { ok: true, must_change_password: false })
    }

    pub fn totp_setup(&self, headers: &HeaderMap) -> Result<TotpSetup, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        let secret = format!("secret{}", g.seq);
        g.seq += 1;
        let id = g.next_id("otp");
        g.setups.insert(id.clone(), secret.as_bytes().to_vec());
        Ok(TotpSetup {
            otpauth_url: format!("otpauth://totp/atkbrain:operator?secret={secret}&issuer=atkbrain"),
            secret,
            setup_id: id,
        })
    }

    pub fn totp_confirm(&self, headers: &HeaderMap, body: &TotpConfirmRequest) -> Result<TotpConfirmResult, ApiError> {
        let s = self.ready(headers)?;
        if body.code.trim().len() != 6 || !body.code.trim().chars().all(|c| c.is_ascii_digit()) {
            return Err(ApiError::invalid("验证码为 6 位数字"));
        }
        let mut g = self.lock();
        let secret = g.setups.get(&body.setup_id).cloned().ok_or_else(|| ApiError::invalid("setup_id 无效"))?;
        if !auth::totp_matches(&secret, &body.code) {
            return Err(ApiError::invalid("验证码不正确"));
        }
        g.totp_secret = Some(secret);
        g.totp_enabled = true;
        if let Some(sess) = g.sessions.get_mut(&s.id) {
            sess.totp_enabled = true;
        }
        Ok(TotpConfirmResult { ok: true, totp_enabled: true })
    }

    pub fn settings(&self, headers: &HeaderMap) -> Result<Settings, ApiError> {
        let _ = self.ready(headers)?;
        let g = self.lock();
        Ok(Settings { review: g.review.clone(), hunt_clocks: g.clocks.clone(), concurrency: g.concurrency })
    }

    pub fn set_review(&self, headers: &HeaderMap, body: ReviewSettings) -> Result<ReviewSettings, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().review = body.clone();
        Ok(body)
    }

    pub fn set_clocks(&self, headers: &HeaderMap, body: Map<String, Value>) -> Result<HuntClocksResult, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        for (k, v) in body {
            if !v.is_number() {
                return Err(ApiError::invalid("时钟必须是数字"));
            }
            g.clocks.insert(k, v);
        }
        Ok(HuntClocksResult { hunt_clocks: g.clocks.clone() })
    }

    pub fn set_concurrency(&self, headers: &HeaderMap, body: ConcurrencyRequest) -> Result<ConcurrencyResult, ApiError> {
        let _ = self.ready(headers)?;
        if body.value < 1 || body.value > 20 || body.track.trim().is_empty() {
            return Err(ApiError::invalid("并发取值 1 到 20"));
        }
        self.lock().concurrency = body.value;
        Ok(ConcurrencyResult { ok: true, value: body.value, track: body.track })
    }

    pub fn set_webhook(&self, headers: &HeaderMap, body: Webhook) -> Result<WebhookResult, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().webhook = body.clone();
        Ok(WebhookResult { webhook: body })
    }

    pub fn retry_webhook(&self, headers: &HeaderMap) -> Result<WebhookRetry, ApiError> {
        let _ = self.ready(headers)?;
        Ok(WebhookRetry { sent: 0, failed: 0 })
    }

    pub fn proxy_status(&self, headers: &HeaderMap) -> Result<ProxyStatus, ApiError> {
        let _ = self.ready(headers)?;
        let g = self.lock();
        Ok(ProxyStatus { enabled: g.proxy_enabled, nodes: g.proxy_nodes.clone() })
    }

    pub fn proxy_pool(&self, headers: &HeaderMap) -> Result<ProxyPoolResult, ApiError> {
        let st = self.proxy_status(headers)?;
        Ok(ProxyPoolResult { ok: true, enabled: st.enabled, nodes: st.nodes })
    }

    pub fn set_proxy_enabled(&self, headers: &HeaderMap, body: ProxyEnabledRequest) -> Result<ProxyEnabledResult, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().proxy_enabled = body.enabled;
        Ok(ProxyEnabledResult { enabled: body.enabled })
    }

    pub fn set_proxy_pool(&self, headers: &HeaderMap, body: ProxyPoolRequest) -> Result<OkBody, ApiError> {
        let _ = self.ready(headers)?;
        let nodes: Vec<String> = body.custom_text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        self.lock().proxy_nodes = nodes;
        Ok(OkBody { ok: true })
    }

    pub fn verify_proxy(&self, headers: &HeaderMap) -> Result<ProxyVerify, ApiError> {
        let _ = self.ready(headers)?;
        let n = self.lock().proxy_nodes.len() as i64;
        Ok(ProxyVerify { ok: true, alive: n })
    }

    pub fn pi_models(&self, headers: &HeaderMap) -> Result<TextBody, ApiError> {
        let _ = self.ready(headers)?;
        Ok(TextBody { text: self.lock().pi_models.clone() })
    }

    pub fn set_pi_models(&self, headers: &HeaderMap, body: TextBody) -> Result<TextResult, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().pi_models = body.text.clone();
        Ok(TextResult { ok: true, text: body.text })
    }

    pub fn llm(&self, headers: &HeaderMap) -> Result<LlmProfile, ApiError> {
        let _ = self.ready(headers)?;
        let mut p = self.lock().llm.clone();
        p.api_key = None;
        Ok(p)
    }

    pub fn set_llm(&self, headers: &HeaderMap, mut body: LlmProfile) -> Result<LlmProfile, ApiError> {
        let _ = self.ready(headers)?;
        if body.format.trim().is_empty() || body.model.trim().is_empty() {
            return Err(ApiError::invalid("模型和格式不能为空"));
        }
        let mut g = self.lock();
        if let Some(key) = body.api_key.clone() {
            if !key.is_empty() {
                g.llm_key = key;
            }
        }
        body.api_key_set = !g.llm_key.is_empty();
        body.api_key_hint = hint(&g.llm_key);
        body.api_key = None;
        body.ok = Some(true);
        g.llm = body.clone();
        Ok(body)
    }

    pub fn test_llm(&self, headers: &HeaderMap, body: LlmProfile) -> Result<LlmTestResult, ApiError> {
        let _ = self.ready(headers)?;
        if body.base_url.trim().is_empty() {
            return Ok(LlmTestResult { ok: false, latency_ms: None, model: Some(body.model), reply: None, error: Some("base_url 为空".into()) });
        }
        Ok(LlmTestResult { ok: true, latency_ms: Some(1), model: Some(body.model), reply: Some("pong".into()), error: None })
    }

    pub fn version(&self, headers: &HeaderMap) -> Result<VersionInfo, ApiError> {
        let _ = self.ready(headers)?;
        Ok(VersionInfo { version: env!("CARGO_PKG_VERSION").into(), update_available: false })
    }

    pub fn apply_version(&self, headers: &HeaderMap) -> Result<VersionApply, ApiError> {
        let _ = self.ready(headers)?;
        Ok(VersionApply { ok: true })
    }

    pub fn list_projects(&self, headers: &HeaderMap) -> Result<Vec<Project>, ApiError> {
        let _ = self.ready(headers)?;
        let mut rows: Vec<Project> = self.lock().projects.values().cloned().collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(rows)
    }

    pub fn create_project(&self, headers: &HeaderMap, body: CreateProject) -> Result<Project, ApiError> {
        let _ = self.ready(headers)?;
        if body.name.trim().is_empty() {
            return Err(ApiError::invalid("名称不能为空"));
        }
        if body.objective != "agent" && body.objective != "flag" {
            return Err(ApiError::invalid("objective 只能是 agent 或 flag"));
        }
        if body.targets.iter().any(|t| t.trim().is_empty()) {
            return Err(ApiError::invalid("目标不能为空"));
        }
        let mut g = self.lock();
        let id = g.next_id("prj");
        let row = Project { id: id.clone(), name: body.name.trim().to_string(), status: "idle".into(), objective: body.objective, kind: "hunt".into() };
        g.projects.insert(id, row.clone());
        Ok(row)
    }

    pub fn project(&self, headers: &HeaderMap, id: &str) -> Result<Project, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().projects.get(id).cloned().ok_or_else(ApiError::not_found)
    }

    pub fn patch_project(&self, headers: &HeaderMap, id: &str, body: PatchProject) -> Result<Project, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        let row = g.projects.get_mut(id).ok_or_else(ApiError::not_found)?;
        if let Some(name) = body.name {
            if name.trim().is_empty() { return Err(ApiError::invalid("名称不能为空")); }
            row.name = name;
        }
        if let Some(status) = body.status {
            if !["idle", "running", "stopped", "archived"].contains(&status.as_str()) {
                return Err(ApiError::invalid("状态不合法"));
            }
            if row.status == "archived" && status == "running" {
                return Err(ApiError::conflict());
            }
            row.status = status;
        }
        Ok(row.clone())
    }

    pub fn set_lang(&self, headers: &HeaderMap, id: &str, body: OutputLangRequest) -> Result<OutputLangResult, ApiError> {
        let _ = self.ready(headers)?;
        if body.output_lang != "zh" && body.output_lang != "en" {
            return Err(ApiError::invalid("output_lang 只能是 zh 或 en"));
        }
        let mut g = self.lock();
        if !g.projects.contains_key(id) { return Err(ApiError::not_found()); }
        g.langs.insert(id.to_string(), body.output_lang.clone());
        Ok(OutputLangResult { ok: true, output_lang: body.output_lang })
    }

    pub fn delete_project(&self, headers: &HeaderMap, id: &str) -> Result<OkBody, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        if g.projects.remove(id).is_none() { return Err(ApiError::not_found()); }
        Ok(OkBody { ok: true })
    }

    pub fn batch(&self, headers: &HeaderMap, ids: Vec<String>, op: &str, confirm: bool) -> Result<IdsResult, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        for id in &ids {
            let row = g.projects.get_mut(id).ok_or_else(ApiError::not_found)?;
            match op {
                "delete" => {}
                "start" => {
                    if row.status == "running" && !confirm { return Err(ApiError::conflict()); }
                    if row.status == "archived" { return Err(ApiError::conflict()); }
                }
                "stop" => {}
                _ => return Err(ApiError::invalid("未知批量操作")),
            }
        }
        if op == "delete" {
            for id in &ids { g.projects.remove(id); }
        } else {
            for id in &ids {
                if let Some(row) = g.projects.get_mut(id) {
                    row.status = if op == "start" { "running".into() } else { "stopped".into() };
                }
            }
        }
        Ok(IdsResult { ok: true, ids })
    }

    pub fn start(&self, headers: &HeaderMap, id: &str, confirm: bool) -> Result<StatusResult, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        let row = g.projects.get_mut(id).ok_or_else(ApiError::not_found)?;
        if row.status == "archived" { return Err(ApiError::conflict()); }
        if row.status == "running" && !confirm { return Err(ApiError::conflict()); }
        row.status = "running".into();
        let status = row.status.clone();
        g.push_event(id, "status", json!({"status": "running"}));
        Ok(StatusResult { ok: true, status })
    }

    pub fn stop(&self, headers: &HeaderMap, id: &str) -> Result<StatusResult, ApiError> {
        let _ = self.ready(headers)?;
        let mut g = self.lock();
        let row = g.projects.get_mut(id).ok_or_else(ApiError::not_found)?;
        row.status = "stopped".into();
        let status = row.status.clone();
        g.push_event(id, "status", json!({"status": "stopped"}));
        Ok(StatusResult { ok: true, status })
    }

    pub fn steer(&self, headers: &HeaderMap, id: &str, body: SteerRequest) -> Result<OkBody, ApiError> {
        let _ = self.ready(headers)?;
        if body.message.trim().is_empty() { return Err(ApiError::invalid("消息不能为空")); }
        let mut g = self.lock();
        if !g.projects.contains_key(id) { return Err(ApiError::not_found()); }
        g.push_event(id, "steer", json!({"message": body.message}));
        Ok(OkBody { ok: true })
    }

    pub fn graph(&self, headers: &HeaderMap, id: &str) -> Result<Graph, ApiError> {
        let _ = self.ready(headers)?;
        let g = self.lock();
        if !g.projects.contains_key(id) { return Err(ApiError::not_found()); }
        let findings: Vec<Value> = g.findings.values().filter(|f| f.project_id == id).map(|f| serde_json::to_value(f).unwrap_or(Value::Null)).collect();
        let count = findings.len() as i64;
        Ok(Graph {
            nodes: vec![],
            edges: vec![],
            findings,
            intents: vec![],
            frontier: Map::new(),
            rce_path: RcePath { path: vec![], likelihood: 0.0 },
            stats: GraphStats { nodes: 0, edges: 0, findings: count, critical: 0, has_shell: false, frontier_open: 0 },
        })
    }

    pub fn events(&self, headers: &HeaderMap, id: &str, after: f64) -> Result<Vec<RtEvent>, ApiError> {
        let _ = self.ready(headers)?;
        let g = self.lock();
        if !g.projects.contains_key(id) { return Err(ApiError::not_found()); }
        Ok(g.events.get(id).map(|rows| rows.iter().filter(|e| e.ts > after).cloned().collect()).unwrap_or_default())
    }

    pub fn runs(&self, headers: &HeaderMap, id: &str) -> Result<Vec<Value>, ApiError> {
        self.ensure(headers, id)?;
        Ok(vec![])
    }

    pub fn memory(&self, headers: &HeaderMap, id: &str) -> Result<Memory, ApiError> {
        self.ensure(headers, id)?;
        Ok(Memory { episodes: vec![], playbook: vec![] })
    }

    pub fn flags(&self, headers: &HeaderMap, id: &str) -> Result<Vec<Value>, ApiError> {
        self.ensure(headers, id)?;
        Ok(vec![])
    }

    pub fn subprojects(&self, headers: &HeaderMap, id: &str) -> Result<Vec<Project>, ApiError> {
        self.ensure(headers, id)?;
        Ok(vec![])
    }

    pub fn import_progress(&self, headers: &HeaderMap, id: &str) -> Result<ImportProgress, ApiError> {
        self.ensure(headers, id)?;
        Ok(ImportProgress { status: "idle".into(), done: 0, total: 0 })
    }

    pub fn scoreboard(&self, headers: &HeaderMap, id: &str) -> Result<Scoreboard, ApiError> {
        self.ensure(headers, id)?;
        Ok(Scoreboard { rows: vec![] })
    }

    pub fn report(&self, headers: &HeaderMap, id: &str, format: String) -> Result<ReportBody, ApiError> {
        let project = self.project(headers, id)?;
        Ok(ReportBody { format, body: format!("# {}\n", project.name) })
    }

    pub fn export(&self, headers: &HeaderMap, id: &str) -> Result<ExportJob, ApiError> {
        self.ensure(headers, id)?;
        let mut g = self.lock();
        let job_id = g.next_id("job");
        let job = ExportJob { job_id: job_id.clone(), status: "pending".into() };
        g.jobs.insert(job_id, job.clone());
        Ok(job)
    }

    pub fn export_status(&self, headers: &HeaderMap, id: &str, job_id: &str) -> Result<ExportJob, ApiError> {
        self.ensure(headers, id)?;
        self.lock().jobs.get(job_id).cloned().ok_or_else(ApiError::not_found)
    }

    pub fn export_file(&self, headers: &HeaderMap, id: &str, job_id: &str) -> Result<String, ApiError> {
        let job = self.export_status(headers, id, job_id)?;
        if job.status != "ready" { return Err(ApiError::conflict()); }
        Ok(format!("# export {job_id}\n"))
    }

    pub fn findings(&self, headers: &HeaderMap) -> Result<Vec<Finding>, ApiError> {
        let _ = self.ready(headers)?;
        Ok(self.lock().findings.values().cloned().collect())
    }

    pub fn finding(&self, headers: &HeaderMap, pid: &str, fid: &str) -> Result<Finding, ApiError> {
        self.ensure(headers, pid)?;
        let row = self.lock().findings.get(fid).cloned().ok_or_else(ApiError::not_found)?;
        if row.project_id != pid { return Err(ApiError::not_found()); }
        Ok(row)
    }

    pub fn review(&self, headers: &HeaderMap, pid: &str, fid: &str, body: ReviewRequest) -> Result<Finding, ApiError> {
        self.ensure(headers, pid)?;
        if (body.secondary_verified || !body.redteam_rating.trim().is_empty()) && body.redteam_rating_rationale.chars().count() < 40 {
            return Err(ApiError::invalid("理由至少 40 字"));
        }
        let mut g = self.lock();
        let row = g.findings.get_mut(fid).ok_or_else(ApiError::not_found)?;
        if row.project_id != pid { return Err(ApiError::not_found()); }
        row.secondary_verified = body.secondary_verified;
        row.redteam_rating = body.redteam_rating;
        row.redteam_rating_rationale = body.redteam_rating_rationale;
        if body.secondary_verified { row.verification_status = "verified".into(); }
        Ok(row.clone())
    }

    pub fn review_job(&self, headers: &HeaderMap, job_id: &str) -> Result<ReviewJob, ApiError> {
        let job = self.export_status_any(headers, job_id)?;
        Ok(ReviewJob { job_id: job.job_id, status: job.status })
    }

    pub fn poc(&self, headers: &HeaderMap, pid: &str, fid: &str) -> Result<Poc, ApiError> {
        let row = self.finding(headers, pid, fid)?;
        Ok(Poc { curl: format!("curl https://{}/{}", row.project_id, row.id), python: "print('poc')\n".into() })
    }

    pub fn retest(&self, headers: &HeaderMap, pid: &str, fid: &str) -> Result<RetestResult, ApiError> {
        let _ = self.finding(headers, pid, fid)?;
        let mut g = self.lock();
        let job_id = g.next_id("job");
        g.jobs.insert(job_id.clone(), ExportJob { job_id: job_id.clone(), status: "pending".into() });
        Ok(RetestResult { ok: true, job_id })
    }

    pub fn simple(&self, headers: &HeaderMap, id: &str) -> Result<OkBody, ApiError> {
        self.ensure(headers, id)?;
        Ok(OkBody { ok: true })
    }

    pub fn preview(&self, headers: &HeaderMap, body: AssetPreviewRequest) -> Result<AssetPreview, ApiError> {
        let _ = self.ready(headers)?;
        if body.objective != "agent" && body.objective != "flag" {
            return Err(ApiError::invalid("objective 只能是 agent 或 flag"));
        }
        let lines: Vec<String> = body.text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && !s.starts_with('#')).collect();
        let groups = lines.iter().take(20).map(|line| AssetGroup { primary: line.clone(), zone: String::new(), vhosts: vec![], ports: vec![] }).collect::<Vec<_>>();
        let n = groups.len() as i64;
        Ok(AssetPreview { group_count: n, hosts: n, lines_kept: n, skipped_dup_count: 0, skipped_header: vec![], groups })
    }

    pub fn add_assets(&self, headers: &HeaderMap, id: &str, body: AssetPreviewRequest) -> Result<FilesResult, ApiError> {
        self.ensure(headers, id)?;
        let files: Vec<String> = body.text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        Ok(FilesResult { ok: true, files })
    }

    pub fn challenge_files(&self, headers: &HeaderMap, id: &str) -> Result<FilesResult, ApiError> {
        self.ensure(headers, id)?;
        Ok(FilesResult { ok: true, files: vec![] })
    }

    pub fn archive_one(&self, headers: &HeaderMap, id: &str) -> Result<ArchiveResult, ApiError> {
        let row = self.patch_project(headers, id, PatchProject { name: None, status: Some("archived".into()) })?;
        Ok(ArchiveResult { ok: true, archived: vec![row.id] })
    }

    pub fn archive_many(&self, headers: &HeaderMap, ids: Vec<String>) -> Result<ArchiveResult, ApiError> {
        for id in &ids {
            self.patch_project(headers, id, PatchProject { name: None, status: Some("archived".into()) })?;
        }
        Ok(ArchiveResult { ok: true, archived: ids })
    }

    pub fn save_template(&self, headers: &HeaderMap, id: &str, name: String) -> Result<TemplateResult, ApiError> {
        self.ensure(headers, id)?;
        if name.trim().is_empty() { return Err(ApiError::invalid("名称不能为空")); }
        let mut g = self.lock();
        let tid = g.next_id("tpl");
        let row = Template { id: tid.clone(), name: name.trim().to_string() };
        g.templates.insert(tid.clone(), row.clone());
        Ok(TemplateResult { id: row.id, name: row.name })
    }

    pub fn templates(&self, headers: &HeaderMap) -> Result<Vec<Template>, ApiError> {
        let _ = self.ready(headers)?;
        Ok(self.lock().templates.values().cloned().collect())
    }

    pub fn from_template(&self, headers: &HeaderMap, body: FromTemplate) -> Result<Project, ApiError> {
        let _ = self.ready(headers)?;
        if body.name.trim().is_empty() { return Err(ApiError::invalid("名称不能为空")); }
        let mut g = self.lock();
        if !g.templates.contains_key(&body.template_id) { return Err(ApiError::not_found()); }
        let id = g.next_id("prj");
        let row = Project { id: id.clone(), name: body.name.trim().to_string(), status: "idle".into(), objective: "agent".into(), kind: "hunt".into() };
        g.projects.insert(id, row.clone());
        Ok(row)
    }

    pub fn intent_cmd(&self, headers: &HeaderMap, pid: &str) -> Result<OkBody, ApiError> {
        self.ensure(headers, pid)
    }

    pub fn command(&self, headers: &HeaderMap, pid: &str, _allow: bool) -> Result<OkBody, ApiError> {
        self.ensure(headers, pid)
    }

    pub fn tick(&self) {
        let mut g = self.lock();
        let running: Vec<String> = g.projects.iter().filter(|(_, p)| p.status == "running").map(|(id, _)| id.clone()).collect();
        let ready: Vec<String> = g.jobs.iter().filter(|(_, j)| j.status == "pending").map(|(id, _)| id.clone()).collect();
        for id in running {
            g.push_event(&id, "tick", json!({"ok": true}));
        }
        for id in ready {
            if let Some(job) = g.jobs.get_mut(&id) {
                job.status = "ready".into();
            }
        }
    }

    fn ensure(&self, headers: &HeaderMap, id: &str) -> Result<OkBody, ApiError> {
        let _ = self.ready(headers)?;
        if !self.lock().projects.contains_key(id) { return Err(ApiError::not_found()); }
        Ok(OkBody { ok: true })
    }

    fn export_status_any(&self, headers: &HeaderMap, job_id: &str) -> Result<ExportJob, ApiError> {
        let _ = self.ready(headers)?;
        self.lock().jobs.get(job_id).cloned().ok_or_else(ApiError::not_found)
    }
}

impl Inner {
    fn next_id(&mut self, prefix: &str) -> String {
        self.seq += 1;
        format!("{prefix}_{}", self.seq)
    }
    fn mark_changed(&mut self) {
        self.changed = true;
    }
    fn push_event(&mut self, project_id: &str, kind: &str, payload: Value) {
        let id = self.next_id("ev");
        let map = payload.as_object().cloned().unwrap_or_default();
        let row = RtEvent { id, kind: kind.into(), payload: map, ts: now_ms() as f64 };
        self.events.entry(project_id.to_string()).or_default().push(row);
    }
}

fn hint(key: &str) -> String {
    if key.len() <= 4 { return String::new(); }
    format!("…{}", &key[key.len() - 4..])
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}
