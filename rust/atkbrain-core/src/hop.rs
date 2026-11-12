//! 过门判定。假否证不能关 hop_auth。句子与原先 Python 相同。

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

pub const HOP_AUTH_FALSE_DISPROVE_MSG: &str = "未证明认证处理接口收到方法与请求体（或 SSH 尚未出 banner）之前，不能否证 hop_auth。";
pub const HOP_AUTH_NUDGE_MSG: &str = "经已验证跳板看到活着的邻机后，本轮主线是 hop_auth：用图上或简报已有字面量账密/token（含授权测试身份），经该跳板把认证请求体送到邻机处理接口。无请求体的空 POST 不能否证。禁止本机直连，禁止喷字典，禁止再把扫段空号扩进 Scope。";
pub const HOP_AUTH_NO_PRECONDITION_MSG: &str = "没有可达前置条件，尚未碰到该跳身份面，不能否证 hop_auth。";
pub const SSH_NEED_BANNER_MSG: &str = "该入口转发端口还没有 SSH 横幅。先用 nc 或 ssh -o BatchMode 取 banner，不要把超时当成口令失败。";
pub const SSH_NEED_LITERAL_MSG: &str = "sshpass 只用题面或图上已经出现的口令字面量；没有字面量时禁止喷口令。";
pub const SSH_NO_SPRAY_MSG: &str = "禁止用 hydra/medusa/ncrack 喷 SSH。banner 通了只试已出现的字面量。";
pub const TIMEOUT_NOT_PASSWORD_NOTE: &str = "【系统】通道超时不是口令否证，不能 resolve_intent 关掉 hop_auth。先修转发。";

const CHANNEL_FILE: &str = ".atkbrain_ssh_channel.json";
const DELIVERY_FILE: &str = ".atkbrain_hop_delivery.json";

fn wrapperish() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)外壳|根路径|无请求体|没有(?:请求)?体|登录页|未登录|timeout|超时|短转发|通道(?:死|不通)|只收公钥|publickey").expect("hop regex"))
}
fn delivered() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)认证(?:处理)?接口.{0,24}(?:收到|送达).{0,24}(?:请求体|body)|表单\s*action.{0,16}(?:收到|送达)|banner.{0,16}(?:已通|已出|SSH-)|字面量.{0,24}Permission denied|请求体.{0,16}已(?:收到|送达)").expect("hop regex"))
}
fn banner_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)SSH-[12]\.\d+").expect("hop regex"))
}
fn sshpass_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\bsshpass\b").expect("hop regex"))
}
fn spray_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\b(?:hydra|medusa|ncrack)\b").expect("hop regex"))
}
fn ssh_bin_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(?:^|[/\s])ssh(?:\s|$)").expect("hop regex"))
}
fn timeout_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)timeout after\s+\d+s").expect("hop regex"))
}
fn login_page_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)type\s*=\s*["']password|name\s*=\s*["']pass(?:word)?|<form[^>]{0,80}(?:login|登录)|(?:用户名|密码|登录)(?:</|\s)"#).expect("hop regex"))
}
fn intent_hop_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(?:^|::)hop_auth$").expect("hop regex"))
}
fn auth_method_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)^(?:POST|PUT|PATCH)$").expect("hop regex"))
}
fn nc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\bnc\b").expect("hop regex"))
}
fn sshpass_pw_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(?i)\bsshpass\b(?:\s+-\w)*\s+-p\s*(?:'([^']*)'|"([^"]*)"|(\S+))"#).expect("hop regex"))
}

pub fn sshpass_password_from_cmd(command: &str) -> Option<String> {
    let caps = sshpass_pw_re().captures(command)?;
    let pw = caps.get(1).or_else(|| caps.get(2)).or_else(|| caps.get(3)).map(|m| m.as_str().trim().to_string()).unwrap_or_default();
    if pw.is_empty() { None } else { Some(pw) }
}

pub fn is_hop_auth_intent(strategy_key: &str) -> bool {
    let sk = strategy_key.trim();
    let tac = sk.rsplit("::").next().unwrap_or(sk);
    tac == "hop_auth" || intent_hop_re().is_match(sk)
}

pub fn false_hop_auth_disprove_reason(summary: &str, fingerprint: &str) -> Option<&'static str> {
    let blob = format!("{summary} {fingerprint}");
    let got = delivered().is_match(&blob);
    let wrap = wrapperish().is_match(&blob);
    if got && !wrap { None } else { Some(HOP_AUTH_FALSE_DISPROVE_MSG) }
}

pub fn refuse_hop_auth_disprove(
    strategy_key: &str,
    verified: bool,
    summary: &str,
    fingerprint: &str,
    graph_present: bool,
    has_precondition: bool,
) -> Option<&'static str> {
    if verified || !is_hop_auth_intent(strategy_key) {
        return None;
    }
    if graph_present && !has_precondition {
        return Some(HOP_AUTH_NO_PRECONDITION_MSG);
    }
    false_hop_auth_disprove_reason(summary, fingerprint)
}

fn read_obj(path: &Path) -> Map<String, Value> {
    let Ok(text) = fs::read_to_string(path) else { return Map::new() };
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(obj)) => obj,
        _ => Map::new(),
    }
}

fn write_obj(path: &Path, obj: &Map<String, Value>) -> bool {
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() { return false; }
    }
    let text = serde_json::to_string(&Value::Object(obj.clone())).unwrap_or_else(|_| "{}".into());
    fs::write(path, text).is_ok()
}

fn channel_path(workspace: &str) -> std::path::PathBuf {
    Path::new(workspace).join(CHANNEL_FILE)
}
fn delivery_path(workspace: &str) -> std::path::PathBuf {
    Path::new(workspace).join(DELIVERY_FILE)
}

pub fn load_ssh_banners(workspace: &str) -> Map<String, Value> {
    if workspace.is_empty() { return Map::new(); }
    read_obj(&channel_path(workspace))
}

pub fn remember_ssh_banner(workspace: &str, host: &str, port: Option<i64>, output: &str) -> bool {
    if workspace.is_empty() || !banner_re().is_match(output) { return false; }
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() { return false; }
    let mut data = load_ssh_banners(workspace);
    if let Some(port) = port.filter(|n| *n != 0) {
        data.insert(format!("{host}:{port}"), json!({"banner": true}));
        data.insert(host, json!({"banner": true}));
    } else {
        data.insert(host, json!({"banner": true}));
    }
    write_obj(&channel_path(workspace), &data)
}

pub fn banner_ok(workspace: &str, host: &str, port: Option<i64>) -> bool {
    let data = load_ssh_banners(workspace);
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() { return false; }
    let flagged = |key: &str| data.get(key).and_then(|v| v.get("banner")).and_then(|v| v.as_bool()).unwrap_or(false);
    if let Some(port) = port.filter(|n| *n != 0) {
        if flagged(&format!("{host}:{port}")) { return true; }
    }
    flagged(&host)
}

pub fn looks_like_ssh_spray(command: &str) -> bool { spray_re().is_match(command) }

pub fn looks_like_ssh_auth(command: &str) -> bool {
    if sshpass_re().is_match(command) || looks_like_ssh_spray(command) { return true; }
    ssh_bin_re().is_match(command) && !command.contains("BatchMode")
}

pub fn looks_like_ssh_probe(command: &str) -> bool {
    if sshpass_re().is_match(command) || looks_like_ssh_spray(command) { return false; }
    nc_re().is_match(command) || command.contains("BatchMode")
}

pub fn looks_like_timeout_transport(stderr: &str, stdout: &str) -> bool {
    timeout_re().is_match(&format!("{stderr} {stdout}"))
}

pub fn ssh_auth_block_reason(command: &str, host: &str, port: Option<i64>, workspace: &str, allowed_secrets: &[String]) -> Option<&'static str> {
    if looks_like_ssh_spray(command) { return Some(SSH_NO_SPRAY_MSG); }
    if !looks_like_ssh_auth(command) { return None; }
    if !banner_ok(workspace, host, port) { return Some(SSH_NEED_BANNER_MSG); }
    if !sshpass_re().is_match(command) { return None; }
    let Some(pw) = sshpass_password_from_cmd(command) else { return Some(SSH_NEED_LITERAL_MSG); };
    let allowed: Vec<String> = allowed_secrets.iter().map(|s| s.to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    if !allowed.iter().any(|s| s == &pw.to_ascii_lowercase()) { Some(SSH_NEED_LITERAL_MSG) } else { None }
}

pub fn command_timeout_note(command: &str, stderr: &str, stdout: &str) -> String {
    if !looks_like_timeout_transport(stderr, stdout) { return String::new(); }
    if sshpass_re().is_match(command) || ssh_bin_re().is_match(command) || nc_re().is_match(command) {
        TIMEOUT_NOT_PASSWORD_NOTE.into()
    } else {
        String::new()
    }
}

pub fn http_login_notes(method: &str, data: &str, body: &str, status: Option<i64>) -> String {
    let mut notes = Vec::new();
    let method = if method.trim().is_empty() { "GET" } else { method.trim() };
    if method.eq_ignore_ascii_case("POST") && data.trim().is_empty() {
        notes.push("【系统】无请求体的 POST 不能作为口令否证，不能关闭 hop_auth。");
    }
    if login_page_re().is_match(body) {
        notes.push("【系统】响应仍像登录页，未过身份门，不能否证 hop_auth。");
    } else if matches!(status, Some(301) | Some(302) | Some(303) | Some(307) | Some(308)) && login_page_re().is_match(body) {
        notes.push("【系统】重定向后仍像未登录，不能否证 hop_auth。");
    }
    notes.join("\n")
}

pub fn load_hop_deliveries(workspace: &str) -> Map<String, Value> {
    if workspace.is_empty() { return Map::new(); }
    read_obj(&delivery_path(workspace))
}

pub fn hop_delivered(workspace: &str, host: &str) -> bool {
    let data = load_hop_deliveries(workspace);
    if data.is_empty() { return false; }
    let marked = |rec: &Value| rec.get("http").and_then(|v| v.as_bool()).unwrap_or(false) || rec.get("ssh").and_then(|v| v.as_bool()).unwrap_or(false);
    if !host.trim().is_empty() {
        let h = host.trim().to_ascii_lowercase();
        return data.get(&h).map(marked).unwrap_or(false);
    }
    data.values().any(marked)
}

pub fn remember_hop_delivery(workspace: &str, host: &str, kind: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    if workspace.is_empty() || host.is_empty() || (kind != "http" && kind != "ssh") { return false; }
    let mut data = load_hop_deliveries(workspace);
    let mut rec = data.get(&host).and_then(|v| v.as_object()).cloned().unwrap_or_default();
    rec.insert(kind.into(), json!(true));
    data.insert(host, Value::Object(rec));
    write_obj(&delivery_path(workspace), &data)
}

pub fn looks_like_http_auth_delivery(method: &str, data: &str, url: &str, hop_host: &str, private_hosts: &[String]) -> bool {
    if !auth_method_re().is_match(method.trim()) { return false; }
    if data.trim().is_empty() { return false; }
    if hop_host.trim().is_empty() { return true; }
    let h = hop_host.trim().to_ascii_lowercase();
    private_hosts.is_empty() || private_hosts.iter().any(|x| x == &h) || url.to_ascii_lowercase().contains(&h)
}

pub fn maybe_record_http_delivery(workspace: &str, method: &str, data: &str, url: &str, hop_host: &str, private_hosts: &[String]) -> bool {
    if !looks_like_http_auth_delivery(method, data, url, hop_host, private_hosts) { return false; }
    let mut host = hop_host.trim().to_ascii_lowercase();
    if host.is_empty() { host = private_hosts.first().cloned().unwrap_or_default(); }
    if host.is_empty() { return false; }
    remember_hop_delivery(workspace, &host, "http")
}

pub fn maybe_record_ssh_delivery(workspace: &str, command: &str, host: &str, port: Option<i64>, allowed: &[String]) -> bool {
    if !looks_like_ssh_auth(command) || looks_like_ssh_spray(command) { return false; }
    if ssh_auth_block_reason(command, host, port, workspace, allowed).is_some() { return false; }
    if !sshpass_re().is_match(command) { return false; }
    remember_hop_delivery(workspace, host, "ssh")
}

pub fn hop_auth_followup_note(situation: bool, workspace: &str, hop_host: &str, allowed_secrets: &[String]) -> String {
    if !situation { return String::new(); }
    if hop_delivered(workspace, hop_host) { return String::new(); }
    let extra = if hop_host.trim().is_empty() { String::new() } else { format!("目标邻机 {hop_host}。") };
    let mut note = format!("【系统】{extra}{HOP_AUTH_NUDGE_MSG}");
    if allowed_secrets.iter().any(|s| !s.trim().is_empty()) {
        note.push_str("有授权测试身份时第一动作必须用这组字面量过登录口。");
    }
    note
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn false_disprove_needs_delivery() {
        assert!(false_hop_auth_disprove_reason("超时", "").is_some());
        assert!(false_hop_auth_disprove_reason("认证接口收到请求体", "").is_none());
    }

    #[test]
    fn sshpass_literal() {
        assert_eq!(sshpass_password_from_cmd("sshpass -p 'secret' ssh root@h").as_deref(), Some("secret"));
        assert!(sshpass_password_from_cmd("ssh -o BatchMode yes").is_none());
    }
}
