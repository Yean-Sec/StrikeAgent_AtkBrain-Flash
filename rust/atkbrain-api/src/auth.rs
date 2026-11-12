use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::ApiError;

pub const COOKIE: &str = "atkbrain_session";

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub must_change_password: bool,
    pub totp_enabled: bool,
}

pub fn cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if kv.next()?.trim() == COOKIE {
            return Some(kv.next().unwrap_or("").trim().to_string());
        }
    }
    None
}

pub fn set_cookie(id: &str) -> String {
    format!("{COOKIE}={id}; HttpOnly; Path=/; SameSite=Lax")
}

pub fn clear_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0")
}

pub fn password_ok(next: &str) -> bool {
    let chars: Vec<char> = next.chars().collect();
    chars.len() >= 8
        && chars.iter().any(|c| c.is_ascii_uppercase())
        && chars.iter().any(|c| c.is_ascii_lowercase())
        && chars.iter().any(|c| c.is_ascii_digit())
}

pub fn totp_now(secret: &[u8]) -> String {
    let step = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 30).unwrap_or(0);
    format!("{:06}", hotp(secret, step) % 1_000_000)
}

pub fn totp_matches(secret: &[u8], code: &str) -> bool {
    let step = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / 30).unwrap_or(0);
    let code = code.trim();
    (step.saturating_sub(1)..=step).any(|n| format!("{:06}", hotp(secret, n) % 1_000_000) == code)
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("hmac");
    mac.update(&counter.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let off = (bytes[19] & 0xf) as usize;
    let bin = u32::from_be_bytes([bytes[off] & 0x7f, bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    bin
}

pub fn require_login(message: &str) -> ApiError {
    let _ = message;
    ApiError::unauthorized()
}
