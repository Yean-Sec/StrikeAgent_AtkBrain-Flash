//! 删掉 Python 文件后，调用方还要用的原名。

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet};
use regex::Regex;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::RsaPrivateKey;

use crate::cvss::cvss_attach_vector;
use crate::findings::findings_collapse;

static KEY_DIR: Mutex<Option<PathBuf>> = Mutex::new(None);

fn data_dir(py: Python<'_>) -> PathBuf {
    if let Ok(guard) = KEY_DIR.lock() {
        if let Some(dir) = guard.as_ref() {
            return dir.clone();
        }
    }
    py.import("atkbrain.config")
        .and_then(|m| m.getattr("settings"))
        .and_then(|s| s.getattr("data_dir"))
        .and_then(|p| p.str().map(|t| PathBuf::from(t.to_string_lossy().as_ref())))
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn atomic(path: &std::path::Path, data: &[u8]) -> PyResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| PyValueError::new_err(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data).map_err(|e| PyValueError::new_err(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| PyValueError::new_err(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_private(py: Python<'_>) -> PyResult<RsaPrivateKey> {
    let path = data_dir(py).join("auth-rsa.pem");
    if path.is_file() {
        let pem = fs::read_to_string(&path).map_err(|e| PyValueError::new_err(e.to_string()))?;
        return RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| PyValueError::new_err(e.to_string()));
    }
    let key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| PyValueError::new_err(e.to_string()))?;
    atomic(&path, pem.as_bytes())?;
    Ok(key)
}

fn hmac_key(py: Python<'_>) -> PyResult<Vec<u8>> {
    let path = data_dir(py).join("auth-session.key");
    if path.is_file() {
        let data = fs::read(&path).map_err(|e| PyValueError::new_err(e.to_string()))?;
        if data.len() >= 32 {
            return Ok(data);
        }
    }
    let key: [u8; 32] = rand::random();
    atomic(&path, &key)?;
    Ok(key.to_vec())
}

#[pyfunction]
fn auth_use_dir(path: &str) {
    if let Ok(mut guard) = KEY_DIR.lock() {
        *guard = if path.is_empty() { None } else { Some(PathBuf::from(path)) };
    }
}

#[pyfunction]
fn ensure_auth_keys(py: Python<'_>) -> PyResult<()> {
    load_private(py)?;
    hmac_key(py)?;
    Ok(())
}

#[pyfunction]
fn public_pem(py: Python<'_>) -> PyResult<String> {
    let key = load_private(py)?;
    key.to_public_key().to_public_key_pem(LineEnding::LF).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
fn new_session_token() -> String {
    let raw: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(raw)
}

#[pyfunction]
fn token_hash(py: Python<'_>, token: &str) -> PyResult<String> {
    crate::auth::auth_token_hash(token, &hmac_key(py)?)
}

#[pyfunction]
fn dummy_verify(py: Python<'_>, password: &str) -> PyResult<()> {
    let _ = (py, password);
    let _ = crate::auth::auth_verify_password(password, "$argon2id$v=19$m=65536,t=3,p=2$aaaaaaaaaaaaaaaaaaaaaa$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (password, challenge_id, *, nonce=None, ts=None))]
fn encrypt_password_blob(py: Python<'_>, password: &str, challenge_id: &str, nonce: Option<&str>, ts: Option<f64>) -> PyResult<String> {
    let key = load_private(py)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| PyValueError::new_err(e.to_string()))?;
    crate::auth::auth_encrypt_password_blob(password, challenge_id, pem.as_ref(), nonce, ts)
}

#[pyfunction]
fn decrypt_password_blob(py: Python<'_>, cipher_b64: &str) -> PyResult<Py<PyDict>> {
    let key = load_private(py)?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0);
    crate::auth::auth_decrypt_password_blob(py, cipher_b64, pem.as_ref(), now)
}

#[pyfunction]
fn auth_key_path(py: Python<'_>) -> String {
    data_dir(py).join("auth-rsa.pem").to_string_lossy().into_owned()
}

#[pyclass]
struct IpRe;

#[pymethods]
impl IpRe {
    #[pyo3(name = "match")]
    fn match_py(&self, text: &str) -> bool {
        crate::net::is_dotted_v4(text)
    }
    fn sub(&self, repl: &str, text: &str) -> String {
        let re = regex::Regex::new(r"\d{1,3}(?:\.\d{1,3}){3}").unwrap();
        re.replace_all(text, repl).into_owned()
    }
}

fn settings_path(py: Python<'_>) -> PathBuf {
    py.import("atkbrain.proxy.pool")
        .and_then(|m| m.getattr("_settings_path"))
        .and_then(|f| f.call0())
        .and_then(|p| p.str().map(|s| PathBuf::from(s.to_string_lossy().as_ref())))
        .unwrap_or_else(|_| PathBuf::from("proxy-settings.json"))
}

fn live_clocks(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let cfg = py.import("atkbrain.config")?;
    let settings = cfg.getattr("settings")?;
    let d = PyDict::new(py);
    for key in [
        "loop_max_turns", "loop_max_turns_agent", "loop_max_turns_src", "loop_max_turns_redteam",
        "agent_runtime_hard_stop_sec", "src_runtime_hard_stop_sec", "redteam_runtime_hard_stop_sec",
        "runtime_hard_stop_sec", "runtime_hard_stop_pass2_sec", "runtime_hard_stop_pass3_sec",
        "runtime_hard_stop_pass_step_sec", "graph_idle_empty_plans",
        "loop_stall_limit_agent", "loop_stall_limit_redteam", "loop_stall_limit_src",
    ] {
        let value = settings.getattr(key).ok().and_then(|v| v.extract::<i64>().ok()).unwrap_or(0);
        d.set_item(key, value)?;
    }
    Ok(d.unbind())
}

fn apply_clocks(py: Python<'_>, clocks: &Bound<PyDict>) -> PyResult<()> {
    let settings = py.import("atkbrain.config")?.getattr("settings")?;
    for (k, v) in clocks.iter() {
        let key: String = k.extract()?;
        settings.setattr(key, v)?;
    }
    let stall = clocks.get_item("loop_stall_limit_agent")?.and_then(|v| v.extract::<i64>().ok()).unwrap_or(10);
    settings.setattr("loop_stall_limit", stall)?;
    Ok(())
}

#[pyfunction]
fn get_hunt_clocks(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let path = settings_path(py);
    let raw = fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    let file = PyDict::new(py);
    if let Some(serde_json::Value::Object(map)) = raw {
        for (k, v) in map {
            if let Some(n) = v.as_i64() {
                file.set_item(k, n)?;
            }
        }
    }
    let live = live_clocks(py)?;
    let got = crate::clocks::clocks_normalize(py, Some(&file), &live.bind(py))?;
    apply_clocks(py, &got.bind(py))?;
    Ok(got)
}

#[pyfunction]
#[pyo3(signature = (updates=None))]
fn set_hunt_clocks(py: Python<'_>, updates: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    let cur = get_hunt_clocks(py)?;
    let merged = PyDict::new(py);
    for (k, v) in cur.bind(py).iter() {
        merged.set_item(k, v)?;
    }
    if let Some(updates) = updates {
        for key in ["agent_runtime_hard_stop_sec", "loop_max_turns_agent", "loop_stall_limit_agent"] {
            let src = key.replace("agent", "src").replace("loop_max_turns_agent", "loop_max_turns_src").replace("loop_stall_limit_agent", "loop_stall_limit_src");
            let _ = src;
        }
        if updates.get_item("agent_runtime_hard_stop_sec")?.map(|v| v.is_none()).unwrap_or(true)
            && (updates.contains("src_runtime_hard_stop_sec")? || updates.contains("redteam_runtime_hard_stop_sec")?)
        {
            merged.del_item("agent_runtime_hard_stop_sec")?;
        }
        if updates.get_item("loop_max_turns_agent")?.map(|v| v.is_none()).unwrap_or(true)
            && (updates.contains("loop_max_turns_src")? || updates.contains("loop_max_turns_redteam")?)
        {
            merged.del_item("loop_max_turns_agent")?;
        }
        if updates.get_item("loop_stall_limit_agent")?.map(|v| v.is_none()).unwrap_or(true)
            && (updates.contains("loop_stall_limit_src")? || updates.contains("loop_stall_limit_redteam")?)
        {
            merged.del_item("loop_stall_limit_agent")?;
        }
        for (k, v) in updates.iter() {
            if !v.is_none() {
                merged.set_item(k, v)?;
            }
        }
    }
    let live = live_clocks(py)?;
    let got = crate::clocks::clocks_normalize(py, Some(&merged), &live.bind(py))?;
    let path = settings_path(py);
    let mut data: serde_json::Value = fs::read_to_string(&path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_else(|| serde_json::json!({}));
    if let Some(obj) = data.as_object_mut() {
        for (k, v) in got.bind(py).iter() {
            let key = k.extract::<String>()?;
            let val = v.extract::<i64>().unwrap_or(0);
            obj.insert(key, serde_json::json!(val));
        }
    }
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, serde_json::to_string_pretty(&data).unwrap_or_else(|_| "{}".into()) + "\n");
    apply_clocks(py, &got.bind(py))?;
    Ok(got)
}

#[pyfunction]
#[pyo3(signature = (clocks=None))]
fn apply_hunt_clocks_to_settings(py: Python<'_>, clocks: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    if let Some(clocks) = clocks {
        apply_clocks(py, clocks)?;
        return Ok(clocks.clone().unbind());
    }
    get_hunt_clocks(py)
}

#[pyfunction]
#[pyo3(signature = (raw=None))]
fn _normalize(py: Python<'_>, raw: Option<&Bound<PyDict>>) -> PyResult<Py<PyDict>> {
    let live = live_clocks(py)?;
    crate::clocks::clocks_normalize(py, raw, &live.bind(py))
}

#[pyfunction]
#[pyo3(signature = (rationale, scored))]
fn attach_vector(py: Python<'_>, rationale: Option<&str>, scored: &Bound<PyAny>) -> PyResult<String> {
    let vector: String = scored.getattr("vector")?.extract()?;
    let score: f64 = scored.getattr("score")?.extract()?;
    let band: String = scored.getattr("band_zh")?.extract()?;
    let _ = py;
    Ok(cvss_attach_vector(rationale, &vector, score, &band))
}

#[pyfunction]
fn collapse_duplicate_findings(py: Python<'_>, rows: &Bound<PyList>) -> PyResult<Py<PyList>> {
    let idxs = findings_collapse(rows)?;
    let out = PyList::empty(py);
    for i in idxs {
        out.append(rows.get_item(i)?)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
#[pyo3(signature = (*parts, category="", endpoint_parts=None))]
fn finding_dedup_keys(py: Python<'_>, parts: &Bound<pyo3::types::PyTuple>, category: &str, endpoint_parts: Option<Vec<String>>) -> PyResult<Py<pyo3::types::PySet>> {
    let mut texts = Vec::new();
    for item in parts.iter() {
        texts.push(if item.is_none() { String::new() } else { item.str()?.to_string_lossy().into_owned() });
    }
    let keys = crate::findings::findings_dedup_keys(py, texts, category, endpoint_parts)?;
    let set = pyo3::types::PySet::empty(py)?;
    for item in keys.bind(py).iter() {
        set.add(item)?;
    }
    Ok(set.unbind())
}

#[pyfunction]
fn finding_dedup_keys_from_row(py: Python<'_>, row: &Bound<PyAny>) -> PyResult<Py<pyo3::types::PySet>> {
    let get = |k: &str| -> String {
        if let Ok(d) = row.downcast::<PyDict>() {
            return d.get_item(k).ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        }
        String::new()
    };
    let endpoint = vec![get("proof_url"), get("node_key"), get("poc_curl"), get("description"), get("evidence")];
    let mut parts = vec![get("title"), get("category")];
    parts.extend(endpoint.clone());
    parts.push(get("poc_python"));
    finding_dedup_keys(py, &pyo3::types::PyTuple::new(py, parts)?, &get("category"), Some(endpoint))
}

#[pyfunction]
fn is_visible_finding(row: &Bound<PyAny>) -> bool {
    let status = if let Ok(d) = row.downcast::<PyDict>() {
        d.get_item("verification_status").ok().flatten().and_then(|v| v.extract::<String>().ok())
    } else {
        None
    };
    match status.as_deref() {
        None | Some("") => true,
        Some(st) => ["verified", "flaky", "pending", "excluded"].contains(&st.to_ascii_lowercase().as_str()),
    }
}

#[pyfunction]
#[pyo3(signature = (finding, project_id=None))]
fn verify_finding(py: Python<'_>, finding: &Bound<PyAny>, project_id: Option<&str>) -> PyResult<Py<VerifyResult>> {
    let _ = project_id;
    let get = |k: &str| finding.getattr(k).ok().and_then(|v| if v.is_none() { None } else { Some(v) });
    let text = |k: &str| get(k).and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let category = text("category");
    let non = crate::verify::verify_non_exploit(Some(&category));
    let proof = crate::verify::verify_has_proof(
        Some(&text("evidence")), Some(&text("poc_curl")), Some(&text("poc_python")),
        Some(&text("proof_detail")), Some(&text("proof_canary")), Some(&text("proof_url")),
    );
    let d = PyDict::new(py);
    let (status, reason) = if non { ("pending", "availability_not_exploit") } else if !proof { ("pending", "no_proof") } else { ("verified", "accepted") };
    let _ = d;
    Py::new(py, VerifyResult {
        status: status.into(),
        reason: reason.into(),
        proof_type: Some(text("proof_type")).filter(|s| !s.is_empty()),
        proof_canary: Some(text("proof_canary")).filter(|s| !s.is_empty()),
        proof_url: Some(text("proof_url")).filter(|s| !s.is_empty()),
        proof_detail: Some(text("proof_detail")).filter(|s| !s.is_empty()),
    })
}

#[pyclass]
struct VerifyResult {
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    reason: String,
    #[pyo3(get)]
    proof_type: Option<String>,
    #[pyo3(get)]
    proof_canary: Option<String>,
    #[pyo3(get)]
    proof_url: Option<String>,
    #[pyo3(get)]
    proof_detail: Option<String>,
}

#[pymethods]
impl VerifyResult {
    #[new]
    #[pyo3(signature = (status, reason, proof_type=None, proof_canary=None, proof_url=None, proof_detail=None))]
    fn new(
        status: String,
        reason: String,
        proof_type: Option<String>,
        proof_canary: Option<String>,
        proof_url: Option<String>,
        proof_detail: Option<String>,
    ) -> Self {
        Self { status, reason, proof_type, proof_canary, proof_url, proof_detail }
    }
}

#[pyfunction]
fn accept_secondary_review(py: Python<'_>, vr: &Bound<PyAny>, secondary: bool) -> PyResult<Py<VerifyResult>> {
    let status: String = vr.getattr("status")?.extract().unwrap_or_default();
    let reason: String = vr.getattr("reason")?.extract().unwrap_or_default();
    let pick = |k: &str| vr.getattr(k).ok().and_then(|v| v.extract::<Option<String>>().ok()).flatten();
    let (status, reason) = if !secondary || status == "verified" { (status, reason) } else { ("verified".into(), "secondary_review".into()) };
    Py::new(py, VerifyResult {
        status, reason,
        proof_type: pick("proof_type"),
        proof_canary: pick("proof_canary"),
        proof_url: pick("proof_url"),
        proof_detail: pick("proof_detail"),
    })
}

#[pyfunction]
#[pyo3(signature = (guard, graph=None, *, brief="", supplied_auth=None))]
fn apply_gate_to_guard(py: Python<'_>, guard: &Bound<PyAny>, graph: Option<&Bound<PyDict>>, brief: &str, supplied_auth: Option<&Bound<PyAny>>) -> PyResult<()> {
    if guard.is_none() {
        return Ok(());
    }
    let kinds = crate::reach::precondition_kinds(py, graph);
    guard.setattr("has_intranet_precondition", !kinds.is_empty())?;
    let scope = guard.getattr("scope").ok();
    let hosts = if let Some(scope) = scope.as_ref() {
        crate::reach::via_capability_hosts(py, graph, Some(scope))
    } else {
        crate::reach::via_capability_hosts(py, graph, None)
    };
    guard.setattr("via_capability_hosts", PyList::new(py, hosts)?)?;
    let nodes = crate::creds_py::nodes_of(graph.map(|item| item.as_any()));
    let auth = crate::creds_py::auth_of(supplied_auth);
    let secrets: Vec<String> = crate::creds_py::allowed_secrets(brief, &nodes, &auth).into_iter().collect();
    let _ = guard.setattr("allowed_secrets", PySet::new(py, secrets)?);
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (host, *, self_hosts=None, self_networks=None, authorized=None))]
fn attacker_lan_forbidden(host: &str, self_hosts: Option<&Bound<PyAny>>, self_networks: Option<&Bound<PyAny>>, authorized: Option<&Bound<PyAny>>) -> Option<String> {
    let _ = (self_networks, authorized);
    let extra = strings_of(self_hosts);
    crate::scope::scope_lan_forbidden(host, crate::osnet::attacker_hosts(&extra))
}

#[pyfunction]
#[pyo3(signature = (host, *, authorized=None))]
fn attacker_loopback_forbidden(host: &str, authorized: Option<&Bound<PyList>>) -> Option<String> {
    crate::scope::scope_loopback_forbidden(host, authorized)
}

#[pyfunction]
#[pyo3(signature = (host, port=None, *, primary="", primary_port=None, peer_addrs=None, peers=None, own_addrs=None))]
fn unauthorized_peer_endpoint(
    host: &str,
    port: Option<i64>,
    primary: &str,
    primary_port: Option<i64>,
    peer_addrs: Option<&Bound<PyList>>,
    peers: Option<&Bound<PyList>>,
    own_addrs: Option<&Bound<PyList>>,
) -> Option<String> {
    crate::scope::scope_peer_endpoint(host, port, primary, primary_port, peer_addrs, peers, own_addrs)
}

#[pyfunction]
#[pyo3(signature = (host, graph=None))]
fn junk_hop_auth_host(host: &str, graph: Option<&Bound<PyAny>>) -> bool {
    let _ = graph;
    crate::intranet::intra_junk_hop(host)
}

fn strings_of(value: Option<&Bound<PyAny>>) -> Vec<String> {
    let Some(value) = value else { return Vec::new() };
    value.try_iter().map(|it| it.flatten().filter_map(|x| x.extract::<String>().ok()).collect()).unwrap_or_default()
}

fn row_field(row: &Bound<PyAny>, key: &str) -> String {
    if let Ok(d) = row.downcast::<PyDict>() {
        return d.get_item(key).ok().flatten().and_then(|v| if v.is_none() { None } else { v.str().ok().map(|s| s.to_string()) }).unwrap_or_default();
    }
    row.getattr(key).ok().and_then(|v| if v.is_none() { None } else { v.extract::<String>().ok() }).unwrap_or_default()
}

fn finding_family(category: &str) -> String {
    match category.trim().to_ascii_lowercase().as_str() {
        "lfi" | "arbitrary_file_read" | "path_traversal" => "file_read".into(),
        "command_injection" | "file_write" | "file_upload" => "rce".into(),
        other => other.to_string(),
    }
}

fn finding_path_key(title: &str, category: &str) -> String {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)/api/[A-Za-z0-9_./-]+").unwrap());
    re.find(&format!("{title} {category}")).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default()
}

#[pyfunction]
fn sort_findings_by_severity(py: Python<'_>, rows: &Bound<PyList>) -> PyResult<Py<PyList>> {
    let mut items: Vec<(i64, f64, usize, Py<PyAny>)> = Vec::new();
    for (i, row) in rows.iter().enumerate() {
        let sev = crate::findings::findings_display_severity(&row);
        let ts = row_field(&row, "created_at").parse::<f64>().unwrap_or(0.0);
        items.push((-crate::findings::sev_rank_pub(&sev), -ts, i, row.unbind()));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)).then(a.2.cmp(&b.2)));
    let out = PyList::empty(py);
    for item in items {
        out.append(item.3)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
fn listed_finding_rows(py: Python<'_>, rows: &Bound<PyList>) -> PyResult<Py<PyList>> {
    let items: Vec<_> = rows.iter().collect();
    let mut verified_keys = std::collections::HashSet::new();
    let mut verified_fam = std::collections::HashSet::new();
    for row in &items {
        let vs = row_field(row, "verification_status").trim().to_ascii_lowercase();
        if vs.is_empty() || vs == "verified" {
            let key = finding_path_key(&row_field(row, "title"), &row_field(row, "category"));
            if !key.is_empty() {
                verified_keys.insert(key);
            }
            let fam = finding_family(&row_field(row, "category"));
            if !fam.is_empty() {
                verified_fam.insert(fam);
            }
        }
    }
    let mut kept = Vec::new();
    for row in &items {
        let vs = row_field(row, "verification_status").trim().to_ascii_lowercase();
        let vs = if vs.is_empty() { "verified" } else { vs.as_str() };
        if vs == "rejected" {
            continue;
        }
        if vs == "pending" {
            let title = row_field(row, "title");
            let cat = row_field(row, "category");
            let key = finding_path_key(&title, &cat);
            if !key.is_empty() && verified_keys.contains(&key) {
                continue;
            }
            if key.is_empty() && verified_fam.contains(&finding_family(&cat)) {
                continue;
            }
        }
        kept.push(row.clone());
    }
    let list = PyList::new(py, kept)?;
    sort_findings_by_severity(py, &list)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<IpRe>()?;
    m.add("_IP_RE", Py::new(m.py(), IpRe)?)?;
    m.add_class::<VerifyResult>()?;
    m.add_function(wrap_pyfunction!(auth_use_dir, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_auth_keys, m)?)?;
    m.add_function(wrap_pyfunction!(public_pem, m)?)?;
    m.add_function(wrap_pyfunction!(new_session_token, m)?)?;
    m.add_function(wrap_pyfunction!(token_hash, m)?)?;
    m.add_function(wrap_pyfunction!(dummy_verify, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_password_blob, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_password_blob, m)?)?;
    m.add_function(wrap_pyfunction!(auth_key_path, m)?)?;
    m.add_function(wrap_pyfunction!(get_hunt_clocks, m)?)?;
    m.add_function(wrap_pyfunction!(set_hunt_clocks, m)?)?;
    m.add_function(wrap_pyfunction!(apply_hunt_clocks_to_settings, m)?)?;
    m.add_function(wrap_pyfunction!(_normalize, m)?)?;
    m.add_function(wrap_pyfunction!(attach_vector, m)?)?;
    m.add_function(wrap_pyfunction!(collapse_duplicate_findings, m)?)?;
    m.add_function(wrap_pyfunction!(finding_dedup_keys, m)?)?;
    m.add_function(wrap_pyfunction!(finding_dedup_keys_from_row, m)?)?;
    m.add_function(wrap_pyfunction!(is_visible_finding, m)?)?;
    m.add_function(wrap_pyfunction!(verify_finding, m)?)?;
    m.add_function(wrap_pyfunction!(accept_secondary_review, m)?)?;
    m.add_function(wrap_pyfunction!(apply_gate_to_guard, m)?)?;
    m.add_function(wrap_pyfunction!(attacker_lan_forbidden, m)?)?;
    m.add_function(wrap_pyfunction!(attacker_loopback_forbidden, m)?)?;
    m.add_function(wrap_pyfunction!(unauthorized_peer_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(junk_hop_auth_host, m)?)?;
    m.add_function(wrap_pyfunction!(sort_findings_by_severity, m)?)?;
    m.add_function(wrap_pyfunction!(listed_finding_rows, m)?)?;
    m.add("CLOCK_KEYS", PyList::new(m.py(), [
        "loop_max_turns", "loop_max_turns_agent", "loop_max_turns_src", "loop_max_turns_redteam",
        "agent_runtime_hard_stop_sec", "src_runtime_hard_stop_sec", "redteam_runtime_hard_stop_sec",
        "runtime_hard_stop_sec", "runtime_hard_stop_pass2_sec", "runtime_hard_stop_pass3_sec",
        "runtime_hard_stop_pass_step_sec", "graph_idle_empty_plans",
        "loop_stall_limit_agent", "loop_stall_limit_redteam", "loop_stall_limit_src",
    ])?)?;
    Ok(())
}
