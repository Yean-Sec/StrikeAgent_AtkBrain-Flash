//! 题面已出现的账密字面量。只摘录，不合成。

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

pub const CREDS_MODE: &str = "literal_only";

const USER_MAX: usize = 200;
const PASS_MAX: usize = 500;
const TOKEN_MAX: usize = 8000;
const USER_STOP: &[&str] = &["http", "https", "www", "ftp", "ssh", "tcp", "udp", "api", "url"];
const PASS_STOP: &[&str] = &["http", "https", "html", "com", "org", "net", "php", "asp", "jsp"];

fn rx(pattern: &str) -> Regex { Regex::new(pattern).expect("creds regex") }
fn explicit_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"\b([A-Za-z][A-Za-z0-9._-]{1,20})\s*[:/=]\s*([A-Za-z0-9@._!#$%^*+-]{3,32})\b")) }
fn leaked_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r#"(?i)(?:password|passwd|口令|密码)\s*[=:]\s*['"]?([A-Za-z0-9@._!#$%^*+-]{3,200})"#)) }
fn user_labeled_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r#"(?i)(?:\buser(?:name)?\b|账号|用户名|账户)\s*[:=]\s*['"]?([A-Za-z0-9._@+-]{1,80})"#)) }
fn user_cn_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?:账号|用户名|账户)\s+([A-Za-z0-9._@+-]{1,80})")) }
fn pass_cn_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?:密码|口令)\s+([^\s]{3,200})")) }
fn bearer_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)(?:authorization\s*[:=]\s*)?bearer\s+([A-Za-z0-9._\-+=/]{8,})")) }
fn cookie_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?im)\bcookie\s*[:=]\s*(.+)$")) }
fn api_key_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r#"(?i)(?:\bapi[_-]?key\b|\baccess[_-]?token\b|\bx-api-key\b|\bjwt\b)\s*[:=]\s*['"]?(\S{6,})"#)) }
fn jwt_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")) }
fn authz_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?im)authorization\s*[:=]\s*(.+)$")) }
fn bench_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)benchmark")) }

fn stopped(value: &str, table: &[&str]) -> bool { table.iter().any(|item| item.eq_ignore_ascii_case(value)) }

pub fn graph_cred_blob(nodes: &[(String, String)], limit: usize) -> String {
    let limit = if limit == 0 { 3000 } else { limit };
    let mut parts = Vec::new();
    for (title, detail) in nodes {
        let blob = format!("{title} {detail}").trim().to_string();
        if !blob.is_empty() { parts.push(blob); }
    }
    parts.join("\n").chars().take(limit).collect()
}

fn explicit_pairs(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for caps in explicit_re().captures_iter(text) {
        let user = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let pw = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        if stopped(user, USER_STOP) || stopped(pw, PASS_STOP) { continue; }
        if format!("{user}/{pw}").contains("//") || stopped(user, &["http", "https"]) { continue; }
        let key = format!("{user}/{pw}").to_ascii_lowercase();
        if !seen.insert(key) { continue; }
        out.push(format!("{user}/{pw}"));
        if out.len() >= 6 { break; }
    }
    out
}

fn leaked_secrets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for caps in leaked_re().captures_iter(text) {
        let pw = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        if pw.is_empty() || stopped(pw, PASS_STOP) || !seen.insert(pw.to_ascii_lowercase()) { continue; }
        out.push(pw.to_string());
        if out.len() >= 6 { break; }
    }
    out
}

fn token_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut add = |item: &str| {
        let s = item.trim().trim_end_matches([',', ';']);
        if s.len() < 8 || !seen.insert(s.to_ascii_lowercase()) || bench_re().is_match(s) { return; }
        out.push(s.to_string());
    };
    for caps in bearer_re().captures_iter(text) { add(&format!("Bearer {}", caps.get(1).map(|m| m.as_str().trim()).unwrap_or(""))); }
    for caps in cookie_re().captures_iter(text) { add(&format!("Cookie: {}", caps.get(1).map(|m| m.as_str().trim()).unwrap_or(""))); }
    for caps in api_key_re().captures_iter(text) { add(caps.get(1).map(|m| m.as_str().trim()).unwrap_or("")); }
    for m in jwt_re().find_iter(text) { add(m.as_str()); }
    for caps in authz_re().captures_iter(text) {
        let rest = caps.get(1).map(|m| m.as_str().trim()).unwrap_or("");
        if rest.to_ascii_lowercase().starts_with("bearer ") { continue; }
        add(&format!("Authorization: {rest}"));
    }
    out.truncate(8);
    out
}

pub fn credential_candidates_from_brief(text: &str, max_pairs: usize) -> Vec<String> {
    let blob = text.trim();
    if blob.is_empty() { return Vec::new(); }
    let limit = max_pairs.clamp(1, 10);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut add = |item: &str| {
        let s = item.trim();
        if s.is_empty() || !seen.insert(s.to_ascii_lowercase()) { return; }
        out.push(s.to_string());
    };
    for item in explicit_pairs(blob) { add(&item); }
    for item in leaked_secrets(blob) { add(&item); }
    for item in token_literals(blob) { add(&item); }
    out.truncate(limit);
    out
}

pub fn format_cred_hint(cands: &[String]) -> String {
    let items: Vec<&str> = cands.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).take(8).collect();
    if items.is_empty() { return String::new(); }
    format!("；题面已出现的账密（禁止合成、禁止扩字典）：{}", items.join("、"))
}

pub fn password_values(cands: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in cands {
        let s = raw.trim();
        if s.is_empty() { continue; }
        let low = s.to_ascii_lowercase();
        out.insert(low.clone());
        if s.contains('/') && !low.starts_with("http://") && !low.starts_with("https://") && !low.starts_with("bearer ") && !low.starts_with("cookie:") {
            out.insert(s.split_once('/').map(|(_, rest)| rest.to_ascii_lowercase()).unwrap_or_default());
        }
        if low.starts_with("bearer ") { out.insert(s.split_once(char::is_whitespace).map(|(_, rest)| rest.to_ascii_lowercase()).unwrap_or_default()); }
        if low.starts_with("cookie:") { out.insert(s.split_once(':').map(|(_, rest)| rest.trim().to_ascii_lowercase()).unwrap_or_default()); }
        if low.starts_with("authorization:") {
            let rest = s.split_once(':').map(|(_, rest)| rest.trim().to_string()).unwrap_or_default();
            out.insert(rest.to_ascii_lowercase());
            if rest.to_ascii_lowercase().starts_with("bearer ") {
                out.insert(rest.split_once(char::is_whitespace).map(|(_, tail)| tail.to_ascii_lowercase()).unwrap_or_default());
            }
        }
    }
    out.remove("");
    out
}

fn clip(val: &str, n: usize) -> String {
    let s = val.trim().trim_matches(|c| c == '\'' || c == '"');
    if s.is_empty() { return String::new(); }
    s.chars().take(n.max(1)).collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SuppliedAuth {
    pub user: String,
    pub password: String,
    pub token: String,
}

impl SuppliedAuth {
    pub fn is_empty(&self) -> bool { self.user.is_empty() && self.password.is_empty() && self.token.is_empty() }
    pub fn to_json(&self) -> Value {
        let mut obj = Map::new();
        if !self.user.is_empty() { obj.insert("user".into(), json!(self.user)); }
        if !self.password.is_empty() { obj.insert("password".into(), json!(self.password)); }
        if !self.token.is_empty() { obj.insert("token".into(), json!(self.token)); }
        Value::Object(obj)
    }
}

pub fn normalize_supplied_auth(user: &str, password: &str, token: &str) -> SuppliedAuth {
    SuppliedAuth {
        user: clip(user, USER_MAX),
        password: clip(password, PASS_MAX),
        token: clip(token, TOKEN_MAX),
    }
}

pub fn merge_supplied_auth(existing: &SuppliedAuth, incoming: &SuppliedAuth) -> SuppliedAuth {
    SuppliedAuth {
        user: if incoming.user.is_empty() { existing.user.clone() } else { incoming.user.clone() },
        password: if incoming.password.is_empty() { existing.password.clone() } else { incoming.password.clone() },
        token: if incoming.token.is_empty() { existing.token.clone() } else { incoming.token.clone() },
    }
}

pub fn extract_supplied_auth(text: &str) -> SuppliedAuth {
    let blob = text;
    if blob.trim().is_empty() { return SuppliedAuth::default(); }
    let mut user = String::new();
    let mut password = String::new();
    if let Some(caps) = user_labeled_re().captures(blob).or_else(|| user_cn_re().captures(blob)) {
        user = clip(caps.get(1).map(|m| m.as_str()).unwrap_or(""), USER_MAX);
    }
    if let Some(caps) = leaked_re().captures(blob).or_else(|| pass_cn_re().captures(blob)) {
        password = clip(caps.get(1).map(|m| m.as_str()).unwrap_or(""), PASS_MAX);
    }
    if user.is_empty() || password.is_empty() {
        if let Some(pair) = explicit_pairs(blob).into_iter().find(|p| p.contains('/')) {
            let (u, pw) = pair.split_once('/').unwrap_or(("", ""));
            if user.is_empty() { user = clip(u, USER_MAX); }
            if password.is_empty() { password = clip(pw, PASS_MAX); }
        }
    }
    let mut token = String::new();
    if let Some(caps) = bearer_re().captures(blob) { token = clip(caps.get(1).map(|m| m.as_str()).unwrap_or(""), TOKEN_MAX); }
    if token.is_empty() {
        if let Some(caps) = cookie_re().captures(blob) { token = clip(&format!("Cookie: {}", caps.get(1).map(|m| m.as_str().trim()).unwrap_or("")), TOKEN_MAX); }
    }
    if token.is_empty() {
        if let Some(caps) = api_key_re().captures(blob) {
            if !bench_re().is_match(caps.get(0).map(|m| m.as_str()).unwrap_or("")) {
                token = clip(caps.get(1).map(|m| m.as_str()).unwrap_or(""), TOKEN_MAX);
            }
        }
    }
    if token.is_empty() {
        if let Some(m) = jwt_re().find(blob) { token = clip(m.as_str(), TOKEN_MAX); }
    }
    if token.is_empty() {
        if let Some(caps) = authz_re().captures(blob) {
            if !bench_re().is_match(caps.get(0).map(|m| m.as_str()).unwrap_or("")) {
                token = clip(caps.get(1).map(|m| m.as_str()).unwrap_or(""), TOKEN_MAX);
            }
        }
    }
    normalize_supplied_auth(&user, &password, &token)
}

pub fn merge_steering_supplied_auth(existing: &SuppliedAuth, messages: &[String]) -> SuppliedAuth {
    let mut acc = existing.clone();
    for raw in messages { acc = merge_supplied_auth(&acc, &extract_supplied_auth(raw)); }
    acc
}

pub fn secrets_from_supplied_auth(auth: &SuppliedAuth) -> BTreeSet<String> {
    let auth = normalize_supplied_auth(&auth.user, &auth.password, &auth.token);
    let mut out = BTreeSet::new();
    for value in [&auth.user, &auth.password, &auth.token] {
        let v = value.trim();
        if v.is_empty() { continue; }
        let low = v.to_ascii_lowercase();
        out.insert(low.clone());
        for pfx in ["bearer ", "cookie: ", "authorization: "] {
            if low.starts_with(pfx) {
                let rest = v[pfx.len()..].trim();
                if !rest.is_empty() {
                    out.insert(rest.to_ascii_lowercase());
                    if rest.to_ascii_lowercase().starts_with("bearer ") {
                        out.insert(rest.split_once(char::is_whitespace).map(|(_, tail)| tail.to_ascii_lowercase()).unwrap_or_default());
                    }
                }
            }
        }
    }
    if !auth.user.is_empty() && !auth.password.is_empty() {
        out.insert(format!("{}/{}", auth.user, auth.password).to_ascii_lowercase());
    }
    out.remove("");
    out
}

pub fn format_supplied_auth_brief(auth: &SuppliedAuth, src: bool) -> String {
    let auth = normalize_supplied_auth(&auth.user, &auth.password, &auth.token);
    if auth.is_empty() { return String::new(); }
    let mut lines = vec!["授权测试身份（必须先登录或在请求头携带 Authorization/Cookie 再测越权/IDOR；禁止 hydra 施射；这些口令不当前台弱口令洞报；无请求体的空 POST 不能否证登录失败）：".to_string()];
    if !auth.user.is_empty() { lines.push(format!("user={}", auth.user)); }
    if !auth.password.is_empty() { lines.push(format!("password={}", auth.password)); }
    if !auth.token.is_empty() {
        let low = auth.token.to_ascii_lowercase();
        if low.starts_with("bearer ") || low.starts_with("cookie:") || low.starts_with("authorization:") {
            lines.push(auth.token);
        } else {
            lines.push(format!("Authorization: Bearer {}", auth.token));
        }
    }
    if src { lines.push("给定身份只用来做授权后的读面/越权证明；禁止真改生产、禁止 getshell 收工。".into()); }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_and_bench() {
        let got = extract_supplied_auth("账号 admin 密码 P@ssw0rd");
        assert_eq!(got.user, "admin");
        assert_eq!(got.password, "P@ssw0rd");
        let bench = extract_supplied_auth("BENCHMARK_TOKEN=a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert!(bench.token.is_empty());
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let tok = extract_supplied_auth(&format!("Authorization: Bearer {jwt}"));
        assert_eq!(tok.token, jwt);
    }
}
