//! SQLite 上的控制台 HTTP。登录、项目和健康检查走现有库，不使用内存草稿。

use std::sync::Arc;

use atkbrain_core::config::Settings;
use atkbrain_core::console_auth::{
    apply_session_cookie, assert_not_locked, auth_ok, auth_public_path, bootstrap_admin,
    clear_fails, clear_session_cookie, client_ip, consume_bootstrap_login, cookie_secure,
    create_session, decrypt_password_blob_current, dummy_verify, entry_prefix, generate_bootstrap_password,
    get_user, hash_password, mark_bootstrap_login_done, new_session_token, origin_ok, public_pem,
    put_challenge, record_login_fail, revoke_session, security_entry_middleware, session_from_request,
    session_must_change, session_ttl_sec, take_challenge, totp_verify_now, user_by_id, user_flag,
    write_bootstrap_secret, EntryAction, HttpView, Scope,
};
use atkbrain_core::db::Db;
use atkbrain_core::projects::{self, create_single_project, delete_project, get_project, list_projects, rename_project};
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

const TICKET_TTL: f64 = 120.0;

#[derive(Clone)]
pub struct LiveState {
    pub db: Arc<Db>,
    pub settings: Arc<Settings>,
}

pub fn router(state: LiveState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/me", get(me))
        .route("/api/auth/pubkey", get(pubkey))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/projects", get(projects_list).post(projects_create))
        .route("/api/projects/{pid}", get(project_one).patch(project_patch).delete(project_delete))
        .route("/api/projects/{pid}/graph", get(project_graph))
        .route("/api/projects/{pid}/events", get(project_events))
        .route("/api/findings", get(findings_library))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_layer))
        .layer(axum::middleware::from_fn_with_state(state.clone(), entry_layer))
        .with_state(state)
}

pub fn open_state(settings: Settings) -> Result<LiveState, String> {
    let _ = settings.ensure_dirs();
    let db = Db::open(&settings.db_path)?;
    bootstrap_admin(&db, &settings)?;
    Ok(LiveState { db: Arc::new(db), settings: Arc::new(settings) })
}

async fn health() -> Json<Value> {
    Json(json!({"ok": true}))
}

fn view_from(req: &Request) -> HttpView {
    let headers = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    HttpView {
        scheme: "http".into(),
        path,
        query,
        hostname: "127.0.0.1".into(),
        client_host: "127.0.0.1".into(),
        headers,
        cookies: Vec::new(),
    }
}

async fn entry_layer(State(st): State<LiveState>, mut req: Request, next: Next) -> Response {
    let mut scope = Scope {
        kind: "http".into(),
        method: req.method().to_string(),
        path: req.uri().path().to_string(),
        raw_path: None,
        client_host: "127.0.0.1".into(),
    };
    match security_entry_middleware(&mut scope, &st.settings) {
        Ok(EntryAction::Continue) => {
            if let Ok(uri) = scope.path.parse() {
                *req.uri_mut() = uri;
            }
            next.run(req).await
        }
        Ok(EntryAction::Respond(reply)) => {
            let mut res = Response::builder().status(reply.status);
            for (k, v) in reply.headers {
                if let (Ok(name), Ok(value)) = (header::HeaderName::try_from(k), header::HeaderValue::try_from(v)) {
                    res = res.header(name, value);
                }
            }
            res.body(Body::from(reply.body)).unwrap_or_else(|_| StatusCode::NOT_FOUND.into_response())
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn auth_layer(State(st): State<LiveState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path == "/api/health" || auth_public_path(&path) || !path.starts_with("/api/") {
        return next.run(req).await;
    }
    let view = view_from(&req);
    match auth_ok(&st.db, &st.settings, &view) {
        Ok(true) => {
            if let Ok(Some(sess)) = session_from_request(&st.db, &st.settings, &view) {
                if session_must_change(Some(&sess)) && !atkbrain_core::console_auth::must_change_path_allowed(&path) {
                    return (StatusCode::FORBIDDEN, Json(json!({"detail": "must-change-password"}))).into_response();
                }
            }
            next.run(req).await
        }
        Ok(false) => (StatusCode::UNAUTHORIZED, Json(json!({"detail": "login-required"}))).into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"detail": err}))).into_response(),
    }
}

async fn me(State(st): State<LiveState>, headers: HeaderMap) -> Json<Value> {
    let req = Request::builder().uri("/api/auth/me").body(Body::empty()).unwrap();
    let mut req = req;
    *req.headers_mut() = headers;
    let view = view_from(&req);
    let sess = session_from_request(&st.db, &st.settings, &view).ok().flatten();
    let user = sess.as_ref().map(|s| s.user.clone());
    let any_u = user.clone().or_else(|| atkbrain_core::console_auth::any_user(&st.db).ok().flatten());
    let show_defaults = !user_flag(any_u.as_ref(), "bootstrap_login_done");
    let required = atkbrain_core::console_auth::login_required(&st.settings);
    Json(json!({
        "required": required,
        "authenticated": user.is_some(),
        "username": user.as_ref().and_then(|u| u.get("username")).cloned().unwrap_or(Value::Null),
        "totp_enabled": user_flag(user.as_ref(), "totp_enabled"),
        "must_change_password": user_flag(user.as_ref(), "must_change_password"),
        "show_default_creds": show_defaults && required && user.is_none(),
        "default_username": if show_defaults && user.is_none() { Value::String(st.settings.admin_user.clone()) } else { Value::Null },
    }))
}

async fn pubkey(State(st): State<LiveState>) -> Result<Json<Value>, StatusCode> {
    let pem = public_pem(&st.settings.data_dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ticket = put_challenge(&st.db, "login", "1", TICKET_TTL, None).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({"alg": "RSA-OAEP-SHA256", "pem": pem, "ticket": ticket, "ttl": TICKET_TTL})))
}

#[derive(Deserialize)]
struct LoginBody {
    username: Option<String>,
    password_cipher: Option<String>,
    ticket: Option<String>,
    totp: Option<String>,
    pending_id: Option<String>,
}

fn fail() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"detail": "用户名或口令不正确"}))).into_response()
}

async fn login(State(st): State<LiveState>, headers: HeaderMap, Json(body): Json<LoginBody>) -> Response {
    let mut req = Request::builder().uri("/api/auth/login").body(Body::empty()).unwrap();
    *req.headers_mut() = headers;
    let view = view_from(&req);
    if !origin_ok(&view, &st.settings) {
        return fail();
    }
    let ip = client_ip(&view);
    let username = body.username.unwrap_or_default();
    let locked = assert_not_locked(&st.db, &[&format!("ip:{ip}"), &format!("user:{}", username.to_ascii_lowercase())]).unwrap_or(0.0);
    if locked > 0.0 {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"detail": "locked", "until": locked}))).into_response();
    }
    if let Some(pending_id) = body.pending_id.filter(|s| !s.is_empty()) {
        return finish_totp(&st, &view, &ip, &pending_id, body.totp.unwrap_or_default());
    }
    let ticket = body.ticket.unwrap_or_default();
    if take_challenge(&st.db, &ticket, "login").ok().flatten().is_none() {
        let _ = record_login_fail(&st.db, &ip, &username);
        return fail();
    }
    let blob = match decrypt_password_blob_current(&st.settings.data_dir, body.password_cipher.as_deref().unwrap_or("")) {
        Ok(blob) => blob,
        Err(_) => {
            let _ = record_login_fail(&st.db, &ip, &username);
            return fail();
        }
    };
    if blob.c != ticket {
        let _ = record_login_fail(&st.db, &ip, &username);
        return fail();
    }
    let Some(user) = get_user(&st.db, username.trim()).ok().flatten() else {
        dummy_verify(&blob.p);
        let _ = record_login_fail(&st.db, &ip, &username);
        return fail();
    };
    let hash = user.get("password_hash").and_then(Value::as_str).unwrap_or("");
    if !atkbrain_core::console_auth::verify_password(&blob.p, hash) {
        let _ = record_login_fail(&st.db, &ip, &username);
        return fail();
    }
    if user_flag(Some(&user), "totp_enabled") && user.get("totp_secret").and_then(Value::as_str).unwrap_or("") != "" {
        let mut extra = serde_json::Map::new();
        extra.insert("username".into(), user.get("username").cloned().unwrap_or(Value::Null));
        extra.insert("bootstrap_rotate".into(), json!(blob.p == factory_password(&st.settings)));
        let pending = put_challenge(&st.db, "pending", "1", 120.0, Some(&extra)).unwrap_or_default();
        return Json(json!({"ok": false, "need_totp": true, "pending_id": pending})).into_response();
    }
    let _ = clear_fails(&st.db, &[&format!("ip:{ip}"), &format!("user:{}", username.to_ascii_lowercase())]);
    finish_login(&st, &view, user, blob.p == factory_password(&st.settings))
}

fn factory_password(settings: &Settings) -> String {
    let p = settings.admin_password.trim();
    if p.is_empty() { "admin".into() } else { p.to_string() }
}

fn finish_totp(st: &LiveState, view: &HttpView, ip: &str, pending_id: &str, code: String) -> Response {
    let Some(pending) = take_challenge(&st.db, pending_id, "pending").ok().flatten() else {
        let _ = record_login_fail(&st.db, ip, "");
        return fail();
    };
    let extra: Value = serde_json::from_str(pending.get("extra").and_then(Value::as_str).unwrap_or("{}")).unwrap_or(json!({}));
    let username = extra.get("username").and_then(Value::as_str).unwrap_or("");
    let Some(user) = get_user(&st.db, username).ok().flatten() else { return fail() };
    let secret = user.get("totp_secret").and_then(Value::as_str).unwrap_or("");
    if !totp_verify_now(secret, code.trim()) {
        let _ = record_login_fail(&st.db, ip, username);
        return fail();
    }
    let _ = clear_fails(&st.db, &[&format!("ip:{ip}"), &format!("user:{}", username.to_ascii_lowercase())]);
    let rotate = extra.get("bootstrap_rotate").and_then(Value::as_bool).unwrap_or(false);
    finish_login(st, view, user, rotate)
}

fn finish_login(st: &LiveState, view: &HttpView, mut user: serde_json::Map<String, Value>, used_default: bool) -> Response {
    if !user_flag(Some(&user), "bootstrap_login_done") {
        let uid = user.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        if !uid.is_empty() {
            if used_default {
                let plain = generate_bootstrap_password(8);
                if let Ok(hashed) = hash_password(&plain) {
                    if consume_bootstrap_login(&st.db, &uid, &hashed).unwrap_or(false) {
                        let _ = write_bootstrap_secret(&st.settings, &plain);
                    }
                }
            } else {
                let _ = mark_bootstrap_login_done(&st.db, &uid);
            }
            if let Ok(Some(fresh)) = user_by_id(&st.db, &uid) {
                user = fresh;
            }
        }
    }
    let token = new_session_token();
    let max_age = session_ttl_sec(&st.settings) as f64;
    let _ = create_session(&st.db, &st.settings, user.get("id").and_then(Value::as_str).unwrap_or(""), &token, max_age);
    let spec = apply_session_cookie(&st.settings, view, &token, None);
    let secure = if spec.secure || cookie_secure(view) { "; Secure" } else { "" };
    let cookie = format!(
        "{}={}; HttpOnly; Max-Age={}; Path={}; SameSite=Lax{secure}",
        spec.key, spec.value, spec.max_age, spec.path
    );
    let mut res = Json(json!({
        "ok": true,
        "username": user.get("username").cloned().unwrap_or(Value::Null),
        "totp_enabled": user_flag(Some(&user), "totp_enabled"),
        "must_change_password": user_flag(Some(&user), "must_change_password"),
    }))
    .into_response();
    if let Ok(value) = cookie.parse() {
        res.headers_mut().insert(header::SET_COOKIE, value);
    }
    res
}

async fn logout(State(st): State<LiveState>, headers: HeaderMap) -> Response {
    let mut req = Request::builder().uri("/api/auth/logout").body(Body::empty()).unwrap();
    *req.headers_mut() = headers;
    let view = view_from(&req);
    if let Ok(Some(sess)) = session_from_request(&st.db, &st.settings, &view) {
        let _ = revoke_session(&st.db, &st.settings, &sess.token);
    }
    let cleared = clear_session_cookie(&st.settings, &view);
    let mut res = Json(json!({"ok": true})).into_response();
    let cookie = format!("{}=; HttpOnly; Max-Age=0; Path={}", cleared.empty.key, cleared.empty.path);
    if let Ok(value) = cookie.parse() {
        res.headers_mut().insert(header::SET_COOKIE, value);
    }
    res
}

async fn projects_list(State(st): State<LiveState>) -> Result<Json<Value>, StatusCode> {
    let rows = list_projects(&st.db, &st.settings).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!(rows)))
}

#[derive(Deserialize)]
struct CreateProject {
    name: Option<String>,
    target: Option<String>,
    objective: Option<String>,
}

async fn projects_create(State(st): State<LiveState>, Json(body): Json<CreateProject>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match create_single_project(
        &st.db,
        &st.settings,
        body.name.as_deref().unwrap_or(""),
        body.target.as_deref().unwrap_or(""),
        None,
        false,
        body.objective.as_deref().unwrap_or("agent"),
    ) {
        Ok(project) => Ok(Json(project)),
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(json!({"detail": err})))),
    }
}

async fn project_one(State(st): State<LiveState>, Path(pid): Path<String>) -> Result<Json<Value>, StatusCode> {
    get_project(&st.db, &st.settings, &pid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.map(Json).ok_or(StatusCode::NOT_FOUND)
}

#[derive(Deserialize)]
struct PatchProject {
    name: Option<String>,
}

async fn project_patch(State(st): State<LiveState>, Path(pid): Path<String>, Json(body): Json<PatchProject>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some(name) = body.name {
        return rename_project(&st.db, &st.settings, &pid, &name).map(Json).map_err(|err| (StatusCode::BAD_REQUEST, Json(json!({"detail": err}))));
    }
    project_one(State(st), Path(pid)).await.map_err(|code| (code, Json(json!({"detail": "not found"}))))
}

async fn project_delete(State(st): State<LiveState>, Path(pid): Path<String>) -> Result<Json<Value>, StatusCode> {
    delete_project(&st.db, &pid).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({"ok": true})))
}

fn json_cell(row: &serde_json::Map<String, Value>, key: &str) -> Value {
    match row.get(key) {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::String(s.clone())),
        Some(other) => other.clone(),
        None => Value::Null,
    }
}

fn clip_text(value: Option<&Value>, n: usize) -> Value {
    let Some(text) = value.and_then(Value::as_str) else { return Value::Null };
    if text.chars().count() <= n {
        return Value::String(text.to_string());
    }
    Value::String(format!("{}…", text.chars().take(n).collect::<String>()))
}

async fn project_graph(State(st): State<LiveState>, Path(pid): Path<String>) -> Result<Json<Value>, StatusCode> {
    let nodes = st.db.query("SELECT * FROM nodes WHERE project_id=?1 ORDER BY created_at", &[&pid as &dyn rusqlite::ToSql]).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let edges = st.db.query("SELECT * FROM edges WHERE project_id=?1", &[&pid as &dyn rusqlite::ToSql]).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let findings = st.db.query("SELECT * FROM findings WHERE project_id=?1 AND IFNULL(verification_status,'verified') != 'rejected'", &[&pid as &dyn rusqlite::ToSql]).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let node_json: Vec<Value> = nodes.iter().map(|row| json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "key": row.get("key").cloned().unwrap_or(Value::Null),
        "type": row.get("type").cloned().unwrap_or(Value::Null),
        "title": row.get("title").cloned().unwrap_or(Value::Null),
        "detail": json_cell(row, "detail"),
        "severity": row.get("severity").cloned().unwrap_or(json!("info")),
        "is_rce": row.get("is_rce").and_then(Value::as_i64).unwrap_or(0) != 0,
        "risk_score": row.get("risk_score").cloned().unwrap_or(json!(0)),
        "tags": json_cell(row, "tags"),
        "status": row.get("status").cloned().unwrap_or(json!("open")),
    })).collect();
    let edge_json: Vec<Value> = edges.iter().map(|row| json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "from": row.get("src").cloned().unwrap_or(Value::Null),
        "to": row.get("dst").cloned().unwrap_or(Value::Null),
        "relation": row.get("relation").cloned().unwrap_or(json!("LEADS_TO")),
        "weight": row.get("weight").cloned().unwrap_or(json!(0.5)),
        "rationale": row.get("rationale").cloned().unwrap_or(Value::Null),
        "on_rce_path": row.get("on_rce_path").and_then(Value::as_i64).unwrap_or(0) != 0,
    })).collect();
    let finding_json: Vec<Value> = findings.iter().map(|row| json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "node_key": row.get("node_key").cloned().unwrap_or(Value::Null),
        "severity": row.get("severity").cloned().unwrap_or(json!("info")),
        "category": row.get("category").cloned().unwrap_or(Value::Null),
        "title": row.get("title").cloned().unwrap_or(Value::Null),
        "description": clip_text(row.get("description"), 800),
        "verification_status": row.get("verification_status").cloned().unwrap_or(json!("verified")),
        "secondary_verified": row.get("secondary_verified").and_then(Value::as_i64).unwrap_or(0),
        "redteam_rating": row.get("redteam_rating").cloned().unwrap_or(Value::Null),
    })).collect();
    Ok(Json(json!({
        "nodes": node_json,
        "edges": edge_json,
        "findings": finding_json,
        "intents": [],
        "disproved": [],
        "frontier": {},
        "rce_path": {"path": [], "likelihood": 0.0},
        "stats": {"nodes": node_json.len(), "edges": edge_json.len(), "findings": finding_json.len()}
    })))
}

async fn project_events(State(st): State<LiveState>, Path(pid): Path<String>) -> Result<Json<Value>, StatusCode> {
    let rows = st.db.query(
        "SELECT * FROM (SELECT * FROM events WHERE project_id=?1 ORDER BY id DESC LIMIT 800) t ORDER BY id ASC",
        &[&pid as &dyn rusqlite::ToSql],
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<Value> = rows.iter().map(|row| json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "type": row.get("type").cloned().unwrap_or(Value::Null),
        "ts": row.get("ts").cloned().unwrap_or(Value::Null),
        "run_id": row.get("run_id").cloned().unwrap_or(Value::Null),
        "payload": json_cell(row, "payload"),
    })).collect();
    Ok(Json(json!(items)))
}

async fn findings_library(State(st): State<LiveState>) -> Result<Json<Value>, StatusCode> {
    let rows = st.db.query(
        "SELECT f.*, p.name AS project_name FROM findings f JOIN projects p ON p.id=f.project_id WHERE IFNULL(f.verification_status,'verified') != 'rejected' ORDER BY f.created_at DESC LIMIT 100",
        &[],
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let items: Vec<Value> = rows.iter().map(|row| json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "project_id": row.get("project_id").cloned().unwrap_or(Value::Null),
        "project_name": row.get("project_name").cloned().unwrap_or(Value::Null),
        "title": row.get("title").cloned().unwrap_or(Value::Null),
        "severity": row.get("severity").cloned().unwrap_or(json!("info")),
        "category": row.get("category").cloned().unwrap_or(Value::Null),
        "verification_status": row.get("verification_status").cloned().unwrap_or(json!("verified")),
        "secondary_verified": row.get("secondary_verified").and_then(Value::as_i64).unwrap_or(0),
    })).collect();
    Ok(Json(json!({"items": items, "total": items.len(), "page": 1, "page_size": 100})))
}

pub fn entry_hint(settings: &Settings) -> String {
    entry_prefix(settings).unwrap_or_default()
}

#[allow(dead_code)]
fn _keep(settings: &Settings) -> bool {
    projects::forbidden_project_target_reason("").is_some() && settings.port > 0
}
