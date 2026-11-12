//! 控制台登录：安全入口、Cookie、限流、会话、引导口令、HTTPS 跳转、Argon2id 与 TOTP。
//! 不记录口令或入口令牌。

use std::net::UdpSocket;
use std::path::{Component, Path, PathBuf};

use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::Sha256;

use crate::config::{self, Settings};
use crate::db::{self, Db};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
pub type Row = Map<String, Value>;

pub const ENTRY_LEN: usize = 8;
pub const ENTRY_ALPHABET: &str = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
pub const COOKIE_NAME: &str = "atkbrain_session";
pub const DEFAULT_SESSION_TTL_SEC: i64 = 24 * 3600;
pub const FAIL_LIMIT_USER: i64 = 5;
pub const FAIL_WINDOW_USER: f64 = 15.0 * 60.0;
pub const LOCK_USER: f64 = 15.0 * 60.0;
pub const FAIL_LIMIT_IP: i64 = 20;
pub const FAIL_WINDOW_IP: f64 = 60.0 * 60.0;
pub const LOCK_IP: f64 = 60.0 * 60.0;
pub const TOTP_DIGITS: u32 = 6;
pub const TOTP_PERIOD: u64 = 30;
pub const TOTP_WINDOW: i64 = 1;

const BLOB_TTL: f64 = 120.0;
const BLOB_MAX_PASSWORD: usize = 96;
/// 配置口令为空时的出厂占位。只写入哈希和 0600 文件，不进日志。
const FACTORY_PASSWORD: &str = "admin";
const EXTRA_MIME: &[(&str, &str)] = &[
    (".js", "text/javascript; charset=utf-8"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".css", "text/css; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".html", "text/html; charset=utf-8"),
    (".txt", "text/plain; charset=utf-8"),
];

#[derive(Clone, Default)]
pub struct HttpView {
    pub scheme: String,
    pub path: String,
    pub query: String,
    pub hostname: String,
    pub client_host: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
}

impl HttpView {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    }

    pub fn cookie(&self, name: &str) -> String {
        if let Some((_, v)) = self.cookies.iter().find(|(k, _)| k == name) {
            return v.clone();
        }
        for part in self.header("cookie").split(';') {
            let Some((k, v)) = part.trim().split_once('=') else {
                continue;
            };
            if k.trim() == name {
                return v.trim().to_string();
            }
        }
        String::new()
    }
}

#[derive(Clone)]
pub struct Scope {
    pub kind: String,
    pub method: String,
    pub path: String,
    pub raw_path: Option<Vec<u8>>,
    pub client_host: String,
}

#[derive(Clone)]
pub struct CookieSpec {
    pub key: String,
    pub value: String,
    pub max_age: i64,
    pub http_only: bool,
    pub same_site: String,
    pub secure: bool,
    pub path: String,
}

pub struct ClearCookies {
    pub empty: CookieSpec,
    pub delete_paths: Vec<String>,
}

pub struct DecoyReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub enum EntryAction {
    Continue,
    WebsocketClose { code: u16 },
    Respond(DecoyReply),
}

pub struct PasswordBlob {
    pub p: String,
    pub n: String,
    pub c: String,
    pub t: f64,
}

pub struct SessionAuth {
    pub session: Row,
    pub user: Row,
    pub token: String,
}

pub struct Redirect {
    pub status: u16,
    pub location: String,
}

fn row_f64(row: &Row, key: &str) -> f64 {
    match row.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn row_i64(row: &Row, key: &str) -> i64 {
    match row.get(key) {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn row_str(row: &Row, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn set_mode_600(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn text_tmp(path: &Path) -> PathBuf {
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) => path.with_extension(format!("{ext}.tmp")),
        None => path.with_extension("tmp"),
    }
}

fn atomic_write(path: &Path, data: &[u8], tmp: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    if let Err(e) = std::fs::write(tmp, data) {
        let _ = std::fs::remove_file(tmp);
        return Err(e.to_string());
    }
    set_mode_600(tmp)?;
    if let Err(e) = std::fs::rename(tmp, path) {
        let _ = std::fs::remove_file(tmp);
        return Err(e.to_string());
    }
    set_mode_600(path)
}

fn atomic_write_text(path: &Path, text: &str) -> Result<(), String> {
    let tmp = text_tmp(path);
    atomic_write(path, text.as_bytes(), &tmp)
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    atomic_write(path, data, &tmp)
}

pub fn entry_disabled(settings: &Settings) -> bool {
    matches!(
        settings.security_entry.trim().to_ascii_lowercase().as_str(),
        "off" | "0" | "false" | "no" | "disable" | "disabled"
    )
}

fn sanitize_entry(raw: &str) -> String {
    raw.trim()
        .trim_matches('/')
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(32)
        .collect()
}

fn entry_file(settings: &Settings) -> PathBuf {
    settings.data_dir.join("security_entry")
}

fn generate_entry() -> String {
    let alphabet = ENTRY_ALPHABET.as_bytes();
    let limit = (256 / alphabet.len()) * alphabet.len();
    let mut out = String::with_capacity(ENTRY_LEN);
    let mut rng = OsRng;
    while out.len() < ENTRY_LEN {
        let mut byte = [0u8; 1];
        rng.fill_bytes(&mut byte);
        let n = byte[0] as usize;
        if n < limit {
            out.push(alphabet[n % alphabet.len()] as char);
        }
    }
    out
}

pub fn load_or_create_entry(settings: &Settings) -> Result<String, String> {
    if entry_disabled(settings) {
        return Ok(String::new());
    }
    let path = entry_file(settings);
    if path.is_file() {
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let got = sanitize_entry(&text);
        if got.chars().count() >= 4 {
            return Ok(got);
        }
    }
    let token = generate_entry();
    atomic_write_text(&path, &format!("{token}\n"))?;
    Ok(token)
}

pub fn security_entry(settings: &Settings) -> Result<String, String> {
    if entry_disabled(settings) {
        return Ok(String::new());
    }
    let path = entry_file(settings);
    if !path.is_file() {
        return Ok(String::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let got = sanitize_entry(&text);
    if got.chars().count() >= 4 {
        Ok(got)
    } else {
        Ok(String::new())
    }
}

pub fn entry_prefix(settings: &Settings) -> Result<String, String> {
    let token = security_entry(settings)?;
    if token.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("/{token}"))
    }
}

pub fn cookie_path_prefix(settings: &Settings) -> Result<String, String> {
    let prefix = entry_prefix(settings)?;
    if prefix.is_empty() {
        Ok("/".into())
    } else {
        Ok(format!("{prefix}/"))
    }
}

pub fn peer_host(client_host: &str) -> String {
    client_host.to_string()
}

pub fn is_loopback_peer(host: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    matches!(h.as_str(), "127.0.0.1" | "::1" | "testclient" | "localhost")
        || h.starts_with("127.")
        || h == "::ffff:127.0.0.1"
}

pub fn path_has_entry(path: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    let path = if path.is_empty() { "/" } else { path };
    let prefix = format!("/{token}");
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

pub fn strip_entry_path(path: &str, token: &str) -> String {
    if token.is_empty() {
        return if path.is_empty() {
            "/".into()
        } else {
            path.to_string()
        };
    }
    let path = if path.is_empty() { "/" } else { path };
    let prefix = format!("/{token}");
    if path == prefix {
        return "/".into();
    }
    let marked = format!("{prefix}/");
    if let Some(rest) = path.strip_prefix(&marked) {
        if rest.is_empty() {
            "/".into()
        } else {
            format!("/{rest}")
        }
    } else {
        path.to_string()
    }
}

fn from_latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|b| char::from(*b)).collect()
}

fn to_latin1(text: &str) -> Vec<u8> {
    text.chars().map(|c| c as u8).collect()
}

fn apply_strip(scope: &mut Scope, token: &str) {
    if !path_has_entry(&scope.path, token) {
        return;
    }
    let prefix = format!("/{token}");
    scope.path = strip_entry_path(&scope.path, token);
    // 不写 root_path。静态文件会把 root_path 再叠到 path 上，变成 assets/assets。
    let Some(raw) = scope.raw_path.clone() else {
        return;
    };
    let raw_s = from_latin1(&raw);
    if let Some(rest) = raw_s.strip_prefix(&prefix) {
        let rest = if rest.is_empty() { "/" } else { rest };
        scope.raw_path = Some(to_latin1(rest));
    }
}

pub fn rewrite_scope_entry(scope: &mut Scope, settings: &Settings) -> Result<bool, String> {
    if scope.kind != "http" && scope.kind != "websocket" {
        return Ok(true);
    }
    if entry_disabled(settings) {
        return Ok(true);
    }
    let token = security_entry(settings)?;
    if token.is_empty() {
        return Ok(true);
    }
    if !path_has_entry(&scope.path, &token) {
        return Ok(false);
    }
    apply_strip(scope, &token);
    Ok(true)
}

pub fn decoy_dir() -> PathBuf {
    config::repo_root()
        .join("backend")
        .join("atkbrain")
        .join("decoy_web")
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn decoy_file_in(root: &Path, url_path: &str) -> Option<PathBuf> {
    let raw = url_path.split('?').next().unwrap_or("/");
    if raw.is_empty() || raw == "/" {
        let index = root.join("index.html");
        return index.is_file().then_some(index);
    }
    let rel = raw.trim_start_matches('/');
    if rel.is_empty() || rel.ends_with('/') || rel.contains('\\') {
        return None;
    }
    if rel == "favicon.svg" || rel == "favicon.ico" {
        let path = root.join(rel);
        return path.is_file().then_some(path);
    }
    let Some(name) = rel.strip_prefix("assets/") else {
        return None;
    };
    if rel.matches('/').count() != 1 || name.is_empty() || name == "." || name == ".." {
        return None;
    }
    let assets = root.join("assets");
    let candidate = lexical_normalize(&assets.join(name));
    if !candidate.starts_with(&lexical_normalize(&assets)) {
        return None;
    }
    candidate.is_file().then_some(candidate)
}

pub fn decoy_file(url_path: &str) -> Option<PathBuf> {
    decoy_file_in(&decoy_dir(), url_path)
}

fn decoy_content_type(path: &Path) -> String {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let dotted = format!(".{}", ext.to_ascii_lowercase());
    if let Some((_, mime)) = EXTRA_MIME.iter().find(|(k, _)| *k == dotted) {
        return (*mime).to_string();
    }
    match dotted.as_str() {
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".ico" => "image/x-icon",
        ".json" | ".map" => "application/json",
        ".woff" => "font/woff",
        ".woff2" => "font/woff2",
        ".ttf" => "font/ttf",
        ".xml" => "application/xml",
        ".pdf" => "application/pdf",
        ".wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn decoy_headers(content_type: &str, len: usize) -> Vec<(String, String)> {
    vec![
        ("content-type".into(), content_type.into()),
        (
            "cache-control".into(),
            "no-store, no-cache, must-revalidate".into(),
        ),
        ("x-content-type-options".into(), "nosniff".into()),
        ("content-length".into(), len.to_string()),
    ]
}

pub fn decoy_reply(scope: &Scope) -> DecoyReply {
    let Some(path) = decoy_file(&scope.path) else {
        return DecoyReply {
            status: 404,
            headers: decoy_headers("text/html; charset=utf-8", 0),
            body: Vec::new(),
        };
    };
    let body = std::fs::read(&path).unwrap_or_default();
    let headers = decoy_headers(&decoy_content_type(&path), body.len());
    let body = if scope.method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else {
        body
    };
    DecoyReply {
        status: 200,
        headers,
        body,
    }
}

pub fn security_entry_middleware(
    scope: &mut Scope,
    settings: &Settings,
) -> Result<EntryAction, String> {
    if scope.kind != "http" && scope.kind != "websocket" {
        return Ok(EntryAction::Continue);
    }
    if rewrite_scope_entry(scope, settings)? {
        return Ok(EntryAction::Continue);
    }
    if scope.kind == "websocket" {
        return Ok(EntryAction::WebsocketClose { code: 4404 });
    }
    Ok(EntryAction::Respond(decoy_reply(scope)))
}

pub fn guess_lan_ip() -> String {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
        return "127.0.0.1".into();
    };
    if socket.connect("8.8.8.8:80").is_err() {
        return "127.0.0.1".into();
    }
    match socket.local_addr() {
        Ok(addr) => {
            let ip = addr.ip().to_string();
            if !ip.is_empty() && !ip.starts_with("127.") {
                ip
            } else {
                "127.0.0.1".into()
            }
        }
        Err(_) => "127.0.0.1".into(),
    }
}

pub fn public_console_url(
    settings: &Settings,
    host: Option<&str>,
    port: Option<u16>,
) -> Result<String, String> {
    let prefix = entry_prefix(settings)?;
    let origin = settings
        .public_origin
        .trim()
        .trim_end_matches('/')
        .to_string();
    if origin.to_ascii_lowercase().starts_with("https://") {
        return Ok(format!("{origin}{prefix}/login"));
    }
    let host = host
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(guess_lan_ip);
    let host = if host.is_empty() {
        "127.0.0.1".to_string()
    } else {
        host
    };
    let port = match port {
        Some(port) => port,
        None if settings.frontend_port == 0 => 2334,
        None => settings.frontend_port,
    };
    let scheme = if settings.force_https {
        "https"
    } else {
        "http"
    };
    if scheme == "https" && (port == 80 || port == 443) {
        return Ok(format!("https://{host}{prefix}/login"));
    }
    Ok(format!("{scheme}://{host}:{port}{prefix}/login"))
}

pub fn session_ttl_sec(settings: &Settings) -> i64 {
    if settings.session_max_age_sec > 0 {
        settings.session_max_age_sec
    } else {
        DEFAULT_SESSION_TTL_SEC
    }
}

pub fn remaining_cookie_max_age(settings: &Settings, expires_at: Option<f64>) -> i64 {
    let Some(expires_at) = expires_at else {
        return session_ttl_sec(settings);
    };
    if !expires_at.is_finite() {
        return 0;
    }
    let left = expires_at - db::now();
    if !left.is_finite() {
        return 0;
    }
    (left.trunc() as i64).max(0)
}

pub fn cookie_secure(request: &HttpView) -> bool {
    if request.scheme == "https" {
        return true;
    }
    request
        .header("x-forwarded-proto")
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case("https")
}

fn cookie_path(settings: &Settings) -> String {
    if entry_disabled(settings) {
        return "/".into();
    }
    cookie_path_prefix(settings).unwrap_or_else(|_| "/".into())
}

pub fn cookie_spec(
    settings: &Settings,
    request: &HttpView,
    value: &str,
    max_age: Option<i64>,
) -> CookieSpec {
    let mut max_age = max_age.unwrap_or_else(|| session_ttl_sec(settings));
    if max_age < 0 {
        max_age = 0;
    }
    CookieSpec {
        key: COOKIE_NAME.into(),
        value: value.into(),
        max_age,
        http_only: true,
        same_site: "lax".into(),
        secure: cookie_secure(request),
        path: cookie_path(settings),
    }
}

pub fn apply_session_cookie(
    settings: &Settings,
    request: &HttpView,
    token: &str,
    expires_at: Option<f64>,
) -> CookieSpec {
    let max_age = expires_at.map(|_| remaining_cookie_max_age(settings, expires_at));
    cookie_spec(settings, request, token, max_age)
}

pub fn clear_session_cookie(settings: &Settings, request: &HttpView) -> ClearCookies {
    let mut empty = cookie_spec(settings, request, "", None);
    let path = empty.path.clone();
    empty.max_age = 0;
    empty.value.clear();
    let mut delete_paths = vec![path.clone()];
    if path != "/" {
        delete_paths.push("/".into());
    }
    ClearCookies {
        empty,
        delete_paths,
    }
}

fn check_rate(limit: i64, window: f64, lock_for: f64) -> Result<(), String> {
    if limit < 1 || !window.is_finite() || window <= 0.0 || !lock_for.is_finite() || lock_for < 0.0
    {
        return Err("illegal rate".into());
    }
    Ok(())
}

pub fn locked_until(db: &Db, key: &str) -> Result<f64, String> {
    let row = db.query_one(
        "SELECT locked_until FROM auth_lockouts WHERE key=?",
        &[&key],
    )?;
    let Some(row) = row else {
        return Ok(0.0);
    };
    let until = row_f64(&row, "locked_until");
    if until > db::now() {
        Ok(until)
    } else {
        Ok(0.0)
    }
}

pub fn assert_not_locked(db: &Db, keys: &[&str]) -> Result<f64, String> {
    let mut latest = 0.0f64;
    for key in keys {
        latest = latest.max(locked_until(db, key)?);
    }
    if latest > db::now() {
        Ok(latest)
    } else {
        Ok(0.0)
    }
}

pub fn record_fail(
    db: &Db,
    key: &str,
    limit: i64,
    window: f64,
    lock_for: f64,
) -> Result<f64, String> {
    check_rate(limit, window, lock_for)?;
    let now = db::now();
    let row = db.query_one(
        "SELECT fails, window_start, locked_until FROM auth_lockouts WHERE key=?",
        &[&key],
    )?;
    if let Some(row) = &row {
        let locked = row_f64(row, "locked_until");
        if locked > now {
            return Ok(locked);
        }
    }
    let mut fails = 0i64;
    let mut start = now;
    if let Some(row) = &row {
        let raw_start = row_f64(row, "window_start");
        start = if raw_start == 0.0 { now } else { raw_start };
        fails = row_i64(row, "fails");
        if now - start > window {
            fails = 0;
            start = now;
        }
    }
    fails += 1;
    let mut until = 0.0;
    if fails >= limit {
        until = now + lock_for;
        fails = 0;
        start = now;
    }
    db.execute(
        "INSERT INTO auth_lockouts(key, fails, window_start, locked_until)
         VALUES(?,?,?,?)
         ON CONFLICT(key) DO UPDATE SET
           fails=excluded.fails,
           window_start=excluded.window_start,
           locked_until=excluded.locked_until",
        &[&key, &fails, &start, &until],
    )?;
    Ok(until)
}

pub fn record_login_fail(db: &Db, ip: &str, username: &str) -> Result<f64, String> {
    let ip_until = record_fail(
        db,
        &format!("ip:{ip}"),
        FAIL_LIMIT_IP,
        FAIL_WINDOW_IP,
        LOCK_IP,
    )?;
    let user = username.trim().to_ascii_lowercase();
    let user_until = record_fail(
        db,
        &format!("user:{user}"),
        FAIL_LIMIT_USER,
        FAIL_WINDOW_USER,
        LOCK_USER,
    )?;
    Ok(ip_until.max(user_until))
}

pub fn clear_fails(db: &Db, keys: &[&str]) -> Result<(), String> {
    for key in keys {
        db.execute("DELETE FROM auth_lockouts WHERE key=?", &[key])?;
    }
    Ok(())
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

pub fn secrets_compare(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        let _ = std::hint::black_box(ct_eq(left, left));
        return false;
    }
    ct_eq(left, right)
}

pub fn password_policy_code(password: &str) -> Option<&'static str> {
    if password.chars().count() < 8 {
        return Some("len");
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Some("upper");
    }
    if !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Some("lower");
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Some("digit");
    }
    None
}

pub fn password_policy_error(password: &str) -> Option<&'static str> {
    match password_policy_code(password) {
        Some("len") => Some("口令至少 8 位"),
        Some("upper") => Some("口令须含大写字母"),
        Some("lower") => Some("口令须含小写字母"),
        Some("digit") => Some("口令须含数字"),
        _ => None,
    }
}

fn argon() -> Argon2<'static> {
    let params = Params::new(65_536, 3, 2, Some(32)).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| e.to_string())?;
    Ok(hash.to_string())
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

pub fn dummy_verify(password: &str) {
    let _ = verify_password(
        password,
        "$argon2id$v=19$m=65536,t=3,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
}

pub fn generate_bootstrap_password(n: i64) -> String {
    let size = n.max(4) as usize;
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    loop {
        let password: String = (0..size)
            .map(|_| alphabet[rand::random::<usize>() % alphabet.len()] as char)
            .collect();
        if password.chars().any(|c| c.is_ascii_lowercase())
            && password.chars().any(|c| c.is_ascii_uppercase())
        {
            return password;
        }
    }
}

pub fn auth_token_hash(token: &str, key: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(token.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn session_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth-session.key")
}

fn hmac_key(data_dir: &Path) -> Result<Vec<u8>, String> {
    let path = session_key_path(data_dir);
    if path.is_file() {
        let data = std::fs::read(&path).map_err(|e| e.to_string())?;
        if data.len() >= 32 {
            return Ok(data);
        }
    }
    let key: [u8; 32] = rand::random();
    atomic_write_bytes(&path, &key)?;
    Ok(key.to_vec())
}

pub fn token_hash(data_dir: &Path, token: &str) -> Result<String, String> {
    auth_token_hash(token, &hmac_key(data_dir)?)
}

pub fn auth_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("auth-rsa.pem")
}

fn load_private(data_dir: &Path) -> Result<RsaPrivateKey, String> {
    let path = auth_key_path(data_dir);
    if path.is_file() {
        let pem = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        return RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| e.to_string());
    }
    let key = RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| e.to_string())?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    atomic_write_bytes(&path, pem.as_bytes())?;
    Ok(key)
}

pub fn ensure_auth_keys(data_dir: &Path) -> Result<(), String> {
    load_private(data_dir)?;
    hmac_key(data_dir)?;
    Ok(())
}

pub fn public_pem(data_dir: &Path) -> Result<String, String> {
    let key = load_private(data_dir)?;
    key.to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| e.to_string())
}

pub fn new_session_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

fn private_from_pem(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| e.to_string())
}

fn parse_blob(obj: &Value, now: f64) -> Result<PasswordBlob, String> {
    let password = obj.get("p").and_then(Value::as_str).unwrap_or("");
    let nonce = obj.get("n").and_then(Value::as_str).unwrap_or("");
    let challenge = obj.get("c").and_then(Value::as_str).unwrap_or("");
    let when = obj.get("t").and_then(|v| {
        v.as_f64()
            .or_else(|| v.as_i64().map(|n| n as f64))
            .or_else(|| v.as_u64().map(|n| n as f64))
    });
    if password.is_empty() || password.chars().count() > BLOB_MAX_PASSWORD {
        return Err("bad blob".into());
    }
    let nlen = nonce.chars().count();
    if !(8..=32).contains(&nlen) || challenge.is_empty() {
        return Err("bad blob".into());
    }
    let Some(when) = when else {
        return Err("bad blob".into());
    };
    if !when.is_finite() || (now - when).abs() > BLOB_TTL {
        return Err(if !when.is_finite() {
            "bad blob"
        } else {
            "stale blob"
        }
        .into());
    }
    Ok(PasswordBlob {
        p: password.to_string(),
        n: nonce.to_string(),
        c: challenge.to_string(),
        t: when,
    })
}

pub fn encrypt_password_blob(
    password: &str,
    challenge_id: &str,
    pem: &str,
    nonce: Option<&str>,
    ts: Option<f64>,
) -> Result<String, String> {
    let when = ts.unwrap_or_else(db::now) as i64;
    let nonce = match nonce {
        Some(nonce) => nonce.to_string(),
        None => hex::encode(rand::random::<[u8; 8]>()),
    };
    let payload = serde_json::json!({
        "p": password,
        "n": nonce,
        "c": challenge_id,
        "t": when,
    });
    let raw = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let key = private_from_pem(pem)?;
    let public = RsaPublicKey::from(&key);
    let encrypted = public
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &raw)
        .map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(encrypted))
}

pub fn decrypt_password_blob(
    cipher_b64: &str,
    pem: &str,
    now: f64,
) -> Result<PasswordBlob, String> {
    let raw = STANDARD
        .decode(cipher_b64.trim())
        .map_err(|_| "bad blob".to_string())?;
    let key = private_from_pem(pem)?;
    let plain = key
        .decrypt(Oaep::new::<Sha256>(), &raw)
        .map_err(|_| "bad blob".to_string())?;
    let text = String::from_utf8(plain).map_err(|_| "bad blob".to_string())?;
    let obj: Value = serde_json::from_str(&text).map_err(|_| "bad blob".to_string())?;
    parse_blob(&obj, now)
}

pub fn encrypt_password_blob_current(
    data_dir: &Path,
    password: &str,
    challenge_id: &str,
    nonce: Option<&str>,
    ts: Option<f64>,
) -> Result<String, String> {
    let key = load_private(data_dir)?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    encrypt_password_blob(password, challenge_id, pem.as_ref(), nonce, ts)
}

pub fn decrypt_password_blob_current(
    data_dir: &Path,
    cipher_b64: &str,
) -> Result<PasswordBlob, String> {
    let key = load_private(data_dir)?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    decrypt_password_blob(cipher_b64, pem.as_ref(), db::now())
}

fn base32_decode(secret: &str) -> Result<Vec<u8>, ()> {
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for ch in secret.chars() {
        if ch == '=' {
            break;
        }
        let upper = ch.to_ascii_uppercase();
        let value = match upper {
            'A'..='Z' => upper as u32 - 'A' as u32,
            '2'..='7' => upper as u32 - '2' as u32 + 26,
            _ => return Err(()),
        };
        bits = (bits << 5) | value;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= if nbits == 0 { 0 } else { (1u32 << nbits) - 1 };
        }
    }
    if out.is_empty() {
        Err(())
    } else {
        Ok(out)
    }
}

fn hotp6(key: &[u8], counter: u64) -> Result<String, String> {
    let mut mac = HmacSha1::new_from_slice(key).map_err(|e| e.to_string())?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let bin = (u32::from(hash[offset] & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    let modulus = 10u32.pow(TOTP_DIGITS);
    Ok(format!(
        "{:0width$}",
        bin % modulus,
        width = TOTP_DIGITS as usize
    ))
}

pub fn totp_code(secret: &str, unix_time: u64) -> Result<String, String> {
    let key = base32_decode(secret).map_err(|_| "bad totp secret".to_string())?;
    hotp6(&key, unix_time / TOTP_PERIOD)
}

pub fn totp_verify(secret: &str, code: &str, unix_time: u64) -> bool {
    let Ok(key) = base32_decode(secret) else {
        return false;
    };
    let counter = (unix_time / TOTP_PERIOD) as i64;
    let mut ok = false;
    for delta in -TOTP_WINDOW..=TOTP_WINDOW {
        let step = counter + delta;
        if step < 0 {
            continue;
        }
        let Ok(expect) = hotp6(&key, step as u64) else {
            continue;
        };
        if secrets_compare(code, &expect) {
            ok = true;
        }
    }
    ok
}

pub fn totp_verify_now(secret: &str, code: &str) -> bool {
    let now = db::now();
    if now < 0.0 {
        return false;
    }
    totp_verify(secret, code, now as u64)
}

pub fn random_base32() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

fn percent_encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        let plain = matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~')
            || (keep_slash && byte == b'/');
        if plain {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

pub fn provisioning_uri(secret: &str, name: &str, issuer: &str) -> String {
    let name = if name.is_empty() { "Secret" } else { name };
    let label = if issuer.is_empty() {
        percent_encode(name, true)
    } else {
        format!(
            "{}:{}",
            percent_encode(issuer, true),
            percent_encode(name, true)
        )
    };
    let mut query = format!("secret={}", percent_encode(secret, false));
    if !issuer.is_empty() {
        query.push_str("&issuer=");
        query.push_str(&percent_encode(issuer, false));
    }
    format!("otpauth://totp/{label}?{query}")
}

pub fn get_user(db: &Db, username: &str) -> Result<Option<Row>, String> {
    let name = username.trim();
    if name.is_empty() {
        return Ok(None);
    }
    db.query_one("SELECT * FROM auth_users WHERE username=?", &[&name])
}

pub fn any_user(db: &Db) -> Result<Option<Row>, String> {
    db.query_one(
        "SELECT * FROM auth_users ORDER BY created_at LIMIT 1",
        &[] as &[&dyn rusqlite::ToSql],
    )
}

pub fn upsert_admin(db: &Db, username: &str, password_hash: &str) -> Result<Row, String> {
    let ts = db::now();
    if let Some(existing) = get_user(db, username)? {
        let id = row_str(&existing, "id");
        db.execute(
            "UPDATE auth_users SET password_hash=?, updated_at=? WHERE id=?",
            &[&password_hash, &ts, &id],
        )?;
        return Ok(db
            .query_one("SELECT * FROM auth_users WHERE id=?", &[&id])?
            .unwrap_or(existing));
    }
    let uid = db::new_id("u_");
    let secret: Option<&str> = None;
    db.execute(
        "INSERT INTO auth_users(id, username, password_hash, totp_secret, totp_enabled, must_change_password, bootstrap_login_done, created_at, updated_at)
         VALUES(?,?,?,?,0,0,0,?,?)",
        &[&uid, &username, &password_hash, &secret, &ts, &ts],
    )?;
    Ok(db
        .query_one("SELECT * FROM auth_users WHERE id=?", &[&uid])?
        .unwrap_or_else(|| {
            let mut row = Row::new();
            row.insert("id".into(), Value::String(uid));
            row.insert("username".into(), Value::String(username.to_string()));
            row
        }))
}

pub fn set_totp_secret(
    db: &Db,
    user_id: &str,
    secret: Option<&str>,
    enabled: bool,
) -> Result<(), String> {
    let secret = secret.map(str::to_string);
    let flag: i64 = if enabled { 1 } else { 0 };
    let ts = db::now();
    db.execute(
        "UPDATE auth_users SET totp_secret=?, totp_enabled=?, updated_at=? WHERE id=?",
        &[&secret, &flag, &ts, &user_id],
    )
}

pub fn put_challenge(
    db: &Db,
    kind: &str,
    secret: &str,
    ttl: f64,
    extra: Option<&Row>,
) -> Result<String, String> {
    let cid = db::new_id("c_");
    let ts = db::now();
    let expires = ts + ttl;
    let empty = Row::new();
    let extra_json = serde_json::to_string(extra.unwrap_or(&empty)).map_err(|e| e.to_string())?;
    db.execute(
        "INSERT INTO auth_challenges(id, kind, secret, expires_at, consumed, extra, created_at) VALUES(?,?,?,?,0,?,?)",
        &[&cid, &kind, &secret, &expires, &extra_json, &ts],
    )?;
    Ok(cid)
}

pub fn peek_challenge(db: &Db, cid: &str, kind: &str) -> Result<Option<Row>, String> {
    let Some(mut row) = db.query_one(
        "SELECT * FROM auth_challenges WHERE id=? AND kind=?",
        &[&cid, &kind],
    )?
    else {
        return Ok(None);
    };
    if row_i64(&row, "consumed") != 0 || row_f64(&row, "expires_at") < db::now() {
        return Ok(None);
    }
    let extra = match row.get("extra") {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(Value::String(text)) => serde_json::from_str::<Value>(text)
            .ok()
            .filter(Value::is_object)
            .unwrap_or_else(|| Value::Object(Row::new())),
        _ => Value::Object(Row::new()),
    };
    row.insert("extra".into(), extra);
    Ok(Some(row))
}

pub fn take_challenge(db: &Db, cid: &str, kind: &str) -> Result<Option<Row>, String> {
    let Some(row) = peek_challenge(db, cid, kind)? else {
        return Ok(None);
    };
    db.execute("UPDATE auth_challenges SET consumed=1 WHERE id=?", &[&cid])?;
    Ok(Some(row))
}

pub fn create_session(
    db: &Db,
    settings: &Settings,
    user_id: &str,
    token: &str,
    max_age: f64,
) -> Result<(), String> {
    let sid = db::new_id("s_");
    let ts = db::now();
    let expires = ts + max_age;
    let hashed = token_hash(&settings.data_dir, token)?;
    db.execute(
        "INSERT INTO auth_sessions(id, token_hash, user_id, expires_at, created_at, last_seen) VALUES(?,?,?,?,?,?)",
        &[&sid, &hashed, &user_id, &expires, &ts, &ts],
    )
}

pub fn get_session(db: &Db, settings: &Settings, token: &str) -> Result<Option<Row>, String> {
    if token.is_empty() {
        return Ok(None);
    }
    let hashed = token_hash(&settings.data_dir, token)?;
    let Some(row) = db.query_one("SELECT * FROM auth_sessions WHERE token_hash=?", &[&hashed])?
    else {
        return Ok(None);
    };
    if row_f64(&row, "expires_at") < db::now() {
        let id = row_str(&row, "id");
        db.execute("DELETE FROM auth_sessions WHERE id=?", &[&id])?;
        return Ok(None);
    }
    Ok(Some(row))
}

pub fn touch_session(db: &Db, session_id: &str, _max_age: Option<f64>) -> Result<(), String> {
    let ts = db::now();
    db.execute(
        "UPDATE auth_sessions SET last_seen=? WHERE id=?",
        &[&ts, &session_id],
    )
}

pub fn revoke_session(db: &Db, settings: &Settings, token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Ok(());
    }
    let hashed = token_hash(&settings.data_dir, token)?;
    db.execute("DELETE FROM auth_sessions WHERE token_hash=?", &[&hashed])
}

pub fn user_by_id(db: &Db, user_id: &str) -> Result<Option<Row>, String> {
    db.query_one("SELECT * FROM auth_users WHERE id=?", &[&user_id])
}

pub fn user_flag(user: Option<&Row>, name: &str) -> bool {
    let Some(user) = user else {
        return false;
    };
    match user.get(name) {
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => {
            if let Some(value) = number.as_i64() {
                value != 0
            } else {
                number.as_f64().unwrap_or(0.0) as i64 != 0
            }
        }
        Some(Value::String(text)) => text.trim().parse::<i64>().unwrap_or(0) != 0,
        _ => false,
    }
}

pub fn set_password_hash(
    db: &Db,
    user_id: &str,
    password_hash: &str,
    must_change: Option<bool>,
) -> Result<(), String> {
    let ts = db::now();
    if let Some(flag) = must_change {
        let flag: i64 = if flag { 1 } else { 0 };
        db.execute(
            "UPDATE auth_users SET password_hash=?, must_change_password=?, updated_at=? WHERE id=?",
            &[&password_hash, &flag, &ts, &user_id],
        )
    } else {
        db.execute(
            "UPDATE auth_users SET password_hash=?, updated_at=? WHERE id=?",
            &[&password_hash, &ts, &user_id],
        )
    }
}

pub fn set_must_change(db: &Db, user_id: &str, value: bool) -> Result<(), String> {
    let flag: i64 = if value { 1 } else { 0 };
    let ts = db::now();
    db.execute(
        "UPDATE auth_users SET must_change_password=?, updated_at=? WHERE id=?",
        &[&flag, &ts, &user_id],
    )
}

pub fn consume_bootstrap_login(
    db: &Db,
    user_id: &str,
    password_hash: &str,
) -> Result<bool, String> {
    let ts = db::now();
    let rows = db.query(
        "UPDATE auth_users
         SET password_hash=?1, must_change_password=1, bootstrap_login_done=1, updated_at=?2
         WHERE id=?3 AND IFNULL(bootstrap_login_done,0)=0
         RETURNING id",
        &[&password_hash, &ts, &user_id],
    )?;
    Ok(!rows.is_empty())
}

pub fn mark_bootstrap_login_done(db: &Db, user_id: &str) -> Result<(), String> {
    let ts = db::now();
    db.execute(
        "UPDATE auth_users SET bootstrap_login_done=1, updated_at=? WHERE id=? AND IFNULL(bootstrap_login_done,0)=0",
        &[&ts, &user_id],
    )
}

pub fn env_truthy(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn env_no_auth(settings: &Settings) -> bool {
    env_truthy(&settings.auth_no_auth)
}

pub fn login_required(settings: &Settings) -> bool {
    !env_no_auth(settings)
}

pub fn bootstrap_secret_path(settings: &Settings) -> PathBuf {
    settings.data_dir.join("admin_bootstrap.secret")
}

pub fn write_bootstrap_secret(settings: &Settings, password: &str) -> Result<(), String> {
    atomic_write_text(&bootstrap_secret_path(settings), password)
}

pub fn read_bootstrap_secret(settings: &Settings) -> String {
    let path = bootstrap_secret_path(settings);
    if !path.is_file() {
        return String::new();
    }
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

pub fn clear_bootstrap_secret(settings: &Settings) {
    let path = bootstrap_secret_path(settings);
    if path.is_file() {
        let _ = std::fs::remove_file(path);
    }
}

pub fn bootstrap_admin(db: &Db, settings: &Settings) -> Result<(), String> {
    if let Err(err) = ensure_auth_keys(&settings.data_dir) {
        println!("[startup] 认证密钥生成失败：{err}");
        return Err(err);
    }
    let user = {
        let name = settings.admin_user.trim();
        if name.is_empty() {
            "admin".to_string()
        } else {
            name.to_string()
        }
    };
    let reset = settings.admin_password_reset;
    let existing = match get_user(db, &user)? {
        Some(row) => Some(row),
        None => any_user(db)?,
    };
    if existing.is_some() && !reset {
        return Ok(());
    }
    let mut password = settings.admin_password.trim().to_string();
    if password.is_empty() {
        password = FACTORY_PASSWORD.to_string();
        if existing.is_some() && reset {
            println!("[startup] ATKBRAIN_ADMIN_PASSWORD_RESET 已开但没有新口令，跳过");
            return Ok(());
        }
    }
    let hashed = hash_password(&password)?;
    upsert_admin(db, &user, &hashed)?;
    write_bootstrap_secret(settings, &password)?;
    println!("[startup] 管理员已写入（用户 {user}；哈希进库，明文仅本机 0600）");
    Ok(())
}

pub fn client_ip(request: &HttpView) -> String {
    let forwarded = request
        .header("x-forwarded-for")
        .split(',')
        .next()
        .unwrap_or("")
        .trim();
    if !forwarded.is_empty() {
        return forwarded.chars().take(64).collect();
    }
    if !request.client_host.is_empty() {
        return request.client_host.clone();
    }
    "0.0.0.0".into()
}

pub fn extract_api_token(request: &HttpView) -> String {
    let header = request.header("x-api-token").trim();
    if !header.is_empty() {
        return header.to_string();
    }
    let auth = request.header("authorization").trim();
    if auth.len() >= 7 && auth.is_char_boundary(7) && auth[..7].eq_ignore_ascii_case("bearer ") {
        return auth[7..].trim().to_string();
    }
    String::new()
}

pub fn cookie_token(request: &HttpView) -> String {
    request.cookie(COOKIE_NAME).trim().to_string()
}

pub fn session_from_request(
    db: &Db,
    settings: &Settings,
    request: &HttpView,
) -> Result<Option<SessionAuth>, String> {
    let token = cookie_token(request);
    let Some(session) = get_session(db, settings, &token)? else {
        return Ok(None);
    };
    touch_session(db, &row_str(&session, "id"), None)?;
    let Some(user) = user_by_id(db, &row_str(&session, "user_id"))? else {
        return Ok(None);
    };
    Ok(Some(SessionAuth {
        session,
        user,
        token,
    }))
}

pub fn api_token_ok(settings: &Settings, request: &HttpView) -> bool {
    let expected = settings.api_token.trim();
    if expected.is_empty() {
        return false;
    }
    let got = extract_api_token(request);
    if got.is_empty() {
        return false;
    }
    secrets_compare(&got, expected)
}

pub fn auth_ok(db: &Db, settings: &Settings, request: &HttpView) -> Result<bool, String> {
    if env_no_auth(settings) {
        return Ok(true);
    }
    if session_from_request(db, settings, request)?.is_some() {
        return Ok(true);
    }
    if api_token_ok(settings, request) {
        return Ok(true);
    }
    if !login_required(settings) {
        return Ok(settings.api_token.trim().is_empty());
    }
    Ok(false)
}

fn url_netloc(url: &str) -> String {
    let url = url.trim();
    let rest = if let Some((_, rest)) = url.split_once("://") {
        rest
    } else if let Some(rest) = url.strip_prefix("//") {
        rest
    } else {
        return String::new();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].to_ascii_lowercase()
}

fn host_name(value: &str) -> String {
    let host = value.trim().to_ascii_lowercase();
    if let Some(rest) = host.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return format!("[{}]", &rest[..end]);
        }
        return host;
    }
    if host.chars().filter(|c| *c == ':').count() == 1 {
        return host
            .split_once(':')
            .map(|(name, _)| name.to_string())
            .unwrap_or(host);
    }
    host
}

pub fn origin_ok(request: &HttpView, settings: &Settings) -> bool {
    let origin = request.header("origin").trim();
    let referer = request.header("referer").trim();
    let host = request.header("host").trim().to_ascii_lowercase();
    if origin.is_empty() && referer.is_empty() {
        return true;
    }
    let got = if !origin.is_empty() {
        url_netloc(origin)
    } else {
        url_netloc(referer)
    };
    if got.is_empty() {
        return true;
    }
    if !host.is_empty() && (got == host || host_name(&got) == host_name(&host)) {
        return true;
    }
    settings.cors_origins.split(',').any(|item| {
        let item = item.trim();
        !item.is_empty() && url_netloc(item) == got
    })
}

pub fn must_change_path_allowed(path: &str) -> bool {
    matches!(
        path,
        "/api/auth/me" | "/api/auth/logout" | "/api/auth/password" | "/api/auth/pubkey"
    )
}

pub fn auth_public_path(path: &str) -> bool {
    matches!(
        path,
        "/api/auth/me" | "/api/auth/pubkey" | "/api/auth/login" | "/api/auth/logout"
    )
}

pub fn session_must_change(sess: Option<&SessionAuth>) -> bool {
    sess.map(|sess| user_flag(Some(&sess.user), "must_change_password"))
        .unwrap_or(false)
}

pub fn https_redirect_target(request: &HttpView, settings: &Settings) -> Option<String> {
    if !settings.force_https
        || cookie_secure(request)
        || is_loopback_peer(&peer_host(&request.client_host))
    {
        return None;
    }
    let origin = settings
        .public_origin
        .trim()
        .trim_end_matches('/')
        .to_string();
    let base = if origin.to_ascii_lowercase().starts_with("https://") {
        origin
    } else {
        let raw = {
            let host = request.header("host");
            if host.is_empty() {
                request.hostname.clone()
            } else {
                host.to_string()
            }
        };
        let host = raw.split(':').next().unwrap_or("").trim();
        if host.is_empty() {
            return None;
        }
        format!("https://{host}:2334")
    };
    let path = if request.path.is_empty() {
        "/"
    } else {
        request.path.as_str()
    };
    let mut url = format!("{base}{path}");
    if !request.query.is_empty() {
        url.push('?');
        url.push_str(&request.query);
    }
    Some(url)
}

pub fn https_redirect_response(request: &HttpView, settings: &Settings) -> Option<Redirect> {
    https_redirect_target(request, settings).map(|location| Redirect {
        status: 301,
        location,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new() -> Self {
            let dir =
                std::env::temp_dir().join(format!("atkbrain-console-auth-{}", db::new_id("t")));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn settings_with(dir: &Path, security_entry: &str) -> Settings {
        let mut env = HashMap::new();
        env.insert(
            "ATKBRAIN_DATA_DIR".into(),
            dir.to_string_lossy().into_owned(),
        );
        env.insert(
            "ATKBRAIN_DB_PATH".into(),
            dir.join("not-the-console.db")
                .to_string_lossy()
                .into_owned(),
        );
        env.insert("ATKBRAIN_SECURITY_ENTRY".into(), security_entry.into());
        Settings::from_map(&env, dir)
    }

    #[test]
    fn entry_disabled() {
        let tmp = Tmp::new();
        for flag in [
            "off", "0", "false", "no", "disable", "disabled", " OFF ", "Disabled",
        ] {
            let settings = settings_with(&tmp.0, flag);
            assert!(super::entry_disabled(&settings), "{flag}");
            assert_eq!(security_entry(&settings).unwrap(), "");
            assert_eq!(load_or_create_entry(&settings).unwrap(), "");
        }
        assert!(!tmp.0.join("security_entry").exists());
        assert!(!super::entry_disabled(&settings_with(&tmp.0, "")));
        assert!(!super::entry_disabled(&settings_with(&tmp.0, "Abcd2345")));
    }

    #[test]
    fn tag_like_sanitize() {
        assert_eq!(
            sanitize_entry("<script>Ab12cd34</script>"),
            "scriptAb12cd34script"
        );
        assert_eq!(sanitize_entry("  /<tag>ZZ99</tag>/  "), "tagZZ99tag");
        assert_eq!(sanitize_entry("../AbCdef12"), "AbCdef12");
        let long = format!("<b>{}</b>", "a".repeat(40));
        let got = sanitize_entry(&long);
        assert_eq!(got.chars().count(), 32);
        assert!(got.starts_with('b'));
        let tmp = Tmp::new();
        let settings = settings_with(&tmp.0, "");
        fs::write(tmp.0.join("security_entry"), "<script>Ab12cd34</script>\n").unwrap();
        assert_eq!(security_entry(&settings).unwrap(), "scriptAb12cd34script");
    }

    #[test]
    fn readonly_security_file_is_not_created() {
        let parent =
            std::env::temp_dir().join(format!("atkbrain-console-auth-missing-{}", db::new_id("t")));
        let _guard = TmpGuard(parent.clone());
        assert!(!parent.exists());
        let settings = settings_with(&parent, "");
        assert_eq!(security_entry(&settings).unwrap(), "");
        assert!(!parent.exists());
        assert!(!parent.join("security_entry").exists());
        assert!(!parent.join("security_entry.tmp").exists());
    }

    struct TmpGuard(PathBuf);
    impl Drop for TmpGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn password_verify_roundtrip_on_temp_hash() {
        assert_eq!(password_policy_code("short"), Some("len"));
        assert_eq!(password_policy_code("alllower1"), Some("upper"));
        assert_eq!(password_policy_code("ALLUPPER1"), Some("lower"));
        assert_eq!(password_policy_code("NoDigitsX"), Some("digit"));
        assert_eq!(password_policy_code("GoodPass1"), None);
        assert_eq!(password_policy_error("short"), Some("口令至少 8 位"));
        let mut password = generate_bootstrap_password(16);
        password.push('7');
        let hashed = hash_password(&password).unwrap();
        assert!(verify_password(&password, &hashed), "roundtrip");
        assert!(
            !verify_password(&format!("{password}x"), &hashed),
            "mismatch"
        );
        assert!(!verify_password(&password, "not-a-hash"), "garbage");
        assert!(hashed.starts_with("$argon2id$"), "argon2id");
        assert!(hashed.contains("m=65536,t=3,p=2"), "params");
    }

    #[test]
    fn illegal_rates() {
        let tmp = Tmp::new();
        let db_path = tmp.0.join("rates.db");
        assert!(db_path.starts_with(std::env::temp_dir()));
        let db = Db::open(&db_path).unwrap();
        for (limit, window, lock_for) in [
            (0, 60.0, 60.0),
            (-1, 60.0, 60.0),
            (5, 0.0, 60.0),
            (5, -1.0, 60.0),
            (5, f64::NAN, 60.0),
            (5, 60.0, -0.1),
        ] {
            let err = record_fail(&db, "ip:203.0.113.10", limit, window, lock_for).unwrap_err();
            assert!(err.contains("illegal"), "{err}");
        }
        let rows = db
            .query(
                "SELECT key FROM auth_lockouts",
                &[] as &[&dyn rusqlite::ToSql],
            )
            .unwrap();
        assert!(rows.is_empty());
        let mut until = 0.0;
        for _ in 0..FAIL_LIMIT_USER {
            until = record_fail(
                &db,
                "user:ada",
                FAIL_LIMIT_USER,
                FAIL_WINDOW_USER,
                LOCK_USER,
            )
            .unwrap();
        }
        assert!(until > db::now());
        assert!(assert_not_locked(&db, &["user:ada"]).unwrap() > db::now());
    }

    #[test]
    fn totp_rfc6238_sha1_window() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_code(secret, 59).unwrap(), "287082");
        assert_eq!(totp_code(secret, 1_111_111_109).unwrap(), "081804");
        assert!(totp_verify(secret, "287082", 59));
        let prev = totp_code(secret, 60).unwrap();
        let next = totp_code(secret, 120).unwrap();
        let older = totp_code(secret, 30).unwrap();
        assert!(totp_verify(secret, &prev, 100));
        assert!(totp_verify(secret, &next, 100));
        assert!(!totp_verify(secret, &older, 100));
        assert!(!totp_verify(secret, "000000", 59));
        assert!(!totp_verify("!!!", "287082", 59));
        assert_eq!(
            provisioning_uri("ABCD2345", "admin", "StrikeAgent"),
            "otpauth://totp/StrikeAgent:admin?secret=ABCD2345&issuer=StrikeAgent"
        );
        let random = random_base32();
        assert_eq!(random.chars().count(), 32);
        assert!(random
            .chars()
            .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)));
    }

    #[test]
    fn entry_file_is_stable_and_not_pinned() {
        let tmp = Tmp::new();
        let settings = settings_with(&tmp.0, "FixedTok1");
        let first = load_or_create_entry(&settings).unwrap();
        let second = load_or_create_entry(&settings).unwrap();
        assert!(first == second, "entry stable");
        assert_eq!(first.chars().count(), ENTRY_LEN);
        assert!(first.chars().all(|c| ENTRY_ALPHABET.contains(c)));
        assert!(first != "FixedTok1", "env cannot pin entry");
        assert!(security_entry(&settings).unwrap() == first, "read matches");
        let path = tmp.0.join("security_entry");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let text = fs::read_to_string(&path).unwrap();
        assert!(text == format!("{first}\n"), "file body");
    }

    #[test]
    fn bootstrap_secret_file_mode_600() {
        let tmp = Tmp::new();
        let settings = settings_with(&tmp.0, "off");
        let password = generate_bootstrap_password(12);
        write_bootstrap_secret(&settings, &password).unwrap();
        assert!(
            read_bootstrap_secret(&settings) == password,
            "secret roundtrip"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(bootstrap_secret_path(&settings))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        clear_bootstrap_secret(&settings);
        assert!(read_bootstrap_secret(&settings).is_empty());
    }

    #[test]
    fn consume_bootstrap_login_once() {
        let tmp = Tmp::new();
        let db = Db::open(&tmp.0.join("auth.db")).unwrap();
        let user = upsert_admin(&db, "admin", "hash-one").unwrap();
        let id = row_str(&user, "id");
        assert!(consume_bootstrap_login(&db, &id, "hash-two").unwrap());
        assert!(!consume_bootstrap_login(&db, &id, "hash-three").unwrap());
        let row = user_by_id(&db, &id).unwrap().unwrap();
        assert_eq!(row_i64(&row, "bootstrap_login_done"), 1);
        assert_eq!(row_i64(&row, "must_change_password"), 1);
        assert_eq!(row_str(&row, "password_hash"), "hash-two");
    }

    #[test]
    fn decoy_blocks_traversal() {
        let tmp = Tmp::new();
        fs::write(tmp.0.join("index.html"), b"<html>StrikeAgent</html>").unwrap();
        fs::create_dir_all(tmp.0.join("assets")).unwrap();
        fs::write(tmp.0.join("assets").join("app.css"), b"body{}").unwrap();
        fs::write(tmp.0.join("SOURCE.txt"), b"hidden").unwrap();
        assert!(decoy_file_in(&tmp.0, "/").unwrap().ends_with("index.html"));
        assert!(decoy_file_in(&tmp.0, "/assets/app.css").is_some());
        assert!(decoy_file_in(&tmp.0, "/../../etc/passwd").is_none());
        assert!(decoy_file_in(&tmp.0, "/login").is_none());
        assert!(decoy_file_in(&tmp.0, "/api/health").is_none());
        assert!(decoy_file_in(&tmp.0, "/assets/").is_none());
        assert!(decoy_file_in(&tmp.0, "/SOURCE.txt").is_none());
        assert!(decoy_file_in(&tmp.0, "/assets/../index.html").is_none());
    }

    #[test]
    fn entry_strip_loopback_and_https() {
        let token = "AbCdef12";
        assert!(path_has_entry(&format!("/{token}"), token));
        assert!(path_has_entry(&format!("/{token}/login"), token));
        assert!(!path_has_entry("/login", token));
        assert_eq!(strip_entry_path(&format!("/{token}"), token), "/");
        assert_eq!(
            strip_entry_path(&format!("/{token}/api/health"), token),
            "/api/health"
        );
        assert!(is_loopback_peer("127.0.0.1"));
        assert!(is_loopback_peer("::1"));
        assert!(is_loopback_peer("::ffff:127.0.0.1"));
        assert!(!is_loopback_peer("8.8.8.8"));

        let tmp = Tmp::new();
        fs::write(tmp.0.join("security_entry"), format!("{token}\n")).unwrap();
        let mut settings = settings_with(&tmp.0, "");
        let mut scope = Scope {
            kind: "http".into(),
            method: "GET".into(),
            path: format!("/{token}/api/health"),
            raw_path: Some(format!("/{token}/api/health").into_bytes()),
            client_host: "203.0.113.9".into(),
        };
        assert!(rewrite_scope_entry(&mut scope, &settings).unwrap());
        assert_eq!(scope.path, "/api/health");
        assert_eq!(scope.raw_path.unwrap(), b"/api/health".to_vec());
        let mut blocked = Scope {
            kind: "http".into(),
            method: "GET".into(),
            path: "/login".into(),
            raw_path: Some(b"/login".to_vec()),
            client_host: "127.0.0.1".into(),
        };
        assert!(!rewrite_scope_entry(&mut blocked, &settings).unwrap());
        assert_eq!(blocked.path, "/login");

        settings.force_https = false;
        settings.public_origin = "https://atkbrain.example.com".into();
        let wan = HttpView {
            scheme: "http".into(),
            path: format!("/{token}/login"),
            query: "x=1".into(),
            client_host: "203.0.113.1".into(),
            ..HttpView::default()
        };
        assert!(https_redirect_target(&wan, &settings).is_none());
        settings.force_https = true;
        let loopback = HttpView {
            client_host: "127.0.0.1".into(),
            path: "/".into(),
            ..HttpView::default()
        };
        assert!(https_redirect_target(&loopback, &settings).is_none());
        assert_eq!(
            https_redirect_target(&wan, &settings).as_deref(),
            Some("https://atkbrain.example.com/AbCdef12/login?x=1")
        );
        let no_origin = HttpView {
            scheme: "http".into(),
            path: format!("/{token}/login"),
            client_host: "203.0.113.1".into(),
            headers: vec![("host".into(), "203.0.113.9:2333".into())],
            ..HttpView::default()
        };
        settings.public_origin.clear();
        assert_eq!(
            https_redirect_target(&no_origin, &settings).as_deref(),
            Some("https://203.0.113.9:2334/AbCdef12/login")
        );
        assert_eq!(
            https_redirect_response(&no_origin, &settings)
                .unwrap()
                .status,
            301
        );
        let forwarded = HttpView {
            scheme: "http".into(),
            client_host: "203.0.113.1".into(),
            headers: vec![("x-forwarded-proto".into(), "https, http".into())],
            ..HttpView::default()
        };
        settings.public_origin = "https://atkbrain.example.com".into();
        assert!(cookie_secure(&forwarded));
        assert!(https_redirect_target(&forwarded, &settings).is_none());

        let same = HttpView {
            headers: vec![
                ("host".into(), "10.0.0.5:2334".into()),
                ("origin".into(), "http://10.0.0.5:2334".into()),
            ],
            ..HttpView::default()
        };
        assert!(origin_ok(&same, &settings));
        let evil = HttpView {
            headers: vec![
                ("host".into(), "10.0.0.5:2334".into()),
                ("origin".into(), "http://evil.example".into()),
            ],
            ..HttpView::default()
        };
        assert!(!origin_ok(&evil, &settings));
        let bare = HttpView {
            headers: vec![("host".into(), "10.0.0.5:2334".into())],
            ..HttpView::default()
        };
        assert!(origin_ok(&bare, &settings));
        let proxy = HttpView {
            headers: vec![
                ("host".into(), "43.133.167.198".into()),
                ("origin".into(), "https://43.133.167.198:2334".into()),
            ],
            ..HttpView::default()
        };
        assert!(origin_ok(&proxy, &settings));

        let left = remaining_cookie_max_age(&settings, Some(db::now() + 90.0));
        assert!((80..=90).contains(&left));
        assert_eq!(
            remaining_cookie_max_age(&settings, Some(db::now() - 10.0)),
            0
        );
        let https = HttpView {
            scheme: "https".into(),
            ..HttpView::default()
        };
        let spec = apply_session_cookie(&settings, &https, "session-token", None);
        assert!(spec.secure && spec.http_only);
        assert_eq!(spec.same_site, "lax");
        assert_eq!(spec.key, COOKIE_NAME);
        assert_eq!(spec.path, "/AbCdef12/");
        let cleared = clear_session_cookie(&settings, &https);
        assert_eq!(cleared.empty.max_age, 0);
        assert!(cleared.empty.value.is_empty());
        assert!(cleared.delete_paths.iter().any(|p| p == "/AbCdef12/"));
        assert!(cleared.delete_paths.iter().any(|p| p == "/"));
    }
}
