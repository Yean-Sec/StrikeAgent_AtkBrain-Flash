//! 口令策略、Argon2id、会话 HMAC、RSA-OAEP。密钥文件仍由 Python 读写。

use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const BLOB_TTL: f64 = 120.0;
const BLOB_MAX_PASSWORD: usize = 96;

fn policy_code(password: &str) -> Option<&'static str> {
    let pw = password;
    if pw.chars().count() < 8 {
        return Some("len");
    }
    if !pw.chars().any(|c| c.is_ascii_uppercase()) {
        return Some("upper");
    }
    if !pw.chars().any(|c| c.is_ascii_lowercase()) {
        return Some("lower");
    }
    if !pw.chars().any(|c| c.is_ascii_digit()) {
        return Some("digit");
    }
    None
}

#[pyfunction]
pub fn auth_password_policy_code(password: Option<&str>) -> Option<&'static str> {
    policy_code(password.unwrap_or(""))
}

#[pyfunction]
pub fn auth_password_policy_error(password: Option<&str>) -> Option<&'static str> {
    match policy_code(password.unwrap_or("")) {
        Some("len") => Some("口令至少 8 位"),
        Some("upper") => Some("口令须含大写字母"),
        Some("lower") => Some("口令须含小写字母"),
        Some("digit") => Some("口令须含数字"),
        _ => None,
    }
}

fn argon() -> Argon2<'static> {
    let params = Params::new(65536, 3, 2, Some(32)).expect("argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[pyfunction]
pub fn auth_hash_password(password: &str) -> PyResult<String> {
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let hash = argon()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(hash.to_string())
}

#[pyfunction]
pub fn auth_verify_password(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

#[pyfunction]
pub fn auth_token_hash(token: &str, key: &[u8]) -> PyResult<String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| PyValueError::new_err(e.to_string()))?;
    mac.update(token.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn parse_blob(obj: &serde_json::Value, now: f64) -> Result<(String, String, String, f64), String> {
    let password = obj.get("p").and_then(|v| v.as_str()).unwrap_or("");
    let nonce = obj.get("n").and_then(|v| v.as_str()).unwrap_or("");
    let challenge = obj.get("c").and_then(|v| v.as_str()).unwrap_or("");
    let when = obj.get("t").and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|n| n as f64)));
    if password.is_empty() || password.chars().count() > BLOB_MAX_PASSWORD {
        return Err("bad blob".into());
    }
    let nlen = nonce.chars().count();
    if !(8..=32).contains(&nlen) || challenge.is_empty() {
        return Err("bad blob".into());
    }
    let Some(when) = when else { return Err("bad blob".into()); };
    if !when.is_finite() || (now - when).abs() > BLOB_TTL {
        return Err(if !when.is_finite() { "bad blob" } else { "stale blob" }.into());
    }
    Ok((password.to_string(), nonce.to_string(), challenge.to_string(), when))
}

fn private_from_pem(pem: &str) -> PyResult<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub fn auth_encrypt_password_blob(
    password: &str,
    challenge_id: &str,
    pem: &str,
    nonce: Option<&str>,
    ts: Option<f64>,
) -> PyResult<String> {
    let when = ts.unwrap_or_else(now_secs) as i64;
    let n = nonce
        .map(|s| s.to_string())
        .unwrap_or_else(|| hex::encode(rand::random::<[u8; 8]>()));
    let payload = serde_json::json!({
        "p": password,
        "n": n,
        "c": challenge_id,
        "t": when,
    });
    let raw = serde_json::to_vec(&payload).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let key = private_from_pem(pem)?;
    let pub_key = RsaPublicKey::from(&key);
    let enc = pub_key
        .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &raw)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(STANDARD.encode(enc))
}

#[pyfunction]
pub fn auth_decrypt_password_blob(py: Python<'_>, cipher_b64: &str, pem: &str, now: f64) -> PyResult<Py<PyDict>> {
    let raw = STANDARD
        .decode(cipher_b64.trim())
        .map_err(|_| PyValueError::new_err("bad blob"))?;
    let key = private_from_pem(pem)?;
    let plain = key
        .decrypt(Oaep::new::<Sha256>(), &raw)
        .map_err(|_| PyValueError::new_err("bad blob"))?;
    let text = String::from_utf8(plain).map_err(|_| PyValueError::new_err("bad blob"))?;
    let obj: serde_json::Value = serde_json::from_str(&text).map_err(|_| PyValueError::new_err("bad blob"))?;
    let (p, n, c, t) = parse_blob(&obj, now).map_err(PyValueError::new_err)?;
    let d = PyDict::new(py);
    d.set_item("p", p)?;
    d.set_item("n", n)?;
    d.set_item("c", c)?;
    d.set_item("t", t)?;
    Ok(d.unbind())
}

#[allow(dead_code)]
fn _pub_pem(key: &RsaPrivateKey) -> String {
    key.to_public_key().to_public_key_pem(rsa::pkcs8::LineEnding::LF).unwrap_or_default()
}

#[pyfunction]
#[pyo3(signature = (n=8))]
pub fn auth_bootstrap_password(n: i64) -> String {
    let size = n.max(4) as usize;
    let alphabet: Vec<u8> = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec();
    loop {
        let pw: String = (0..size)
            .map(|_| alphabet[rand::random::<usize>() % alphabet.len()] as char)
            .collect();
        if pw.chars().any(|c| c.is_ascii_lowercase()) && pw.chars().any(|c| c.is_ascii_uppercase()) {
            return pw;
        }
    }
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(auth_password_policy_code, m)?)?;
    m.add_function(wrap_pyfunction!(auth_password_policy_error, m)?)?;
    m.add_function(wrap_pyfunction!(auth_hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(auth_verify_password, m)?)?;
    m.add_function(wrap_pyfunction!(auth_token_hash, m)?)?;
    m.add_function(wrap_pyfunction!(auth_encrypt_password_blob, m)?)?;
    m.add_function(wrap_pyfunction!(auth_decrypt_password_blob, m)?)?;
    m.add_function(wrap_pyfunction!(auth_bootstrap_password, m)?)?;
    Ok(())
}
