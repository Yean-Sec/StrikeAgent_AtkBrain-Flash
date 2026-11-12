//! 内网可达分类与 SSRF 金丝雀。不写攻击图。

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict, PyList, PySet};
use regex::Regex;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::LazyLock;

use crate::net::{ip_is_private_or_loop_or_link, is_dotted_v4, is_loopback_host, norm_host, parse_ip};

static IPV4: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3})\b").unwrap());
static HOSTS_CMD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:cat\s+/etc/hosts|getent\s+hosts)\b").unwrap());
static RECON: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:arp|nmap|ping|ip\s+(?:neigh|a|addr|route)|hostname\s+-I)\b").unwrap());
static LIVE_LINE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:open|http|https|ssh|登录|login|ssh-2\.0|\b220[\s-]|banner)\b").unwrap());
static LIVE_BODY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<form|登录|login|ssh-2\.0|\b220[\s-]|username|password|set-cookie|www-authenticate").unwrap());
static DEAD_BODY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)connection timed out|no route to host|empty reply|connection refused|timed?\s*out").unwrap());
static IDENTITY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)登录|login|ssh(?:-|\b)|/22\b|\b22/tcp|password|pass(?:wd|word)|认证|口令").unwrap());
static NIP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:^|\.)(?:nip\.io|sslip\.io)$").unwrap());
static LOOT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)文件读|任意文件|信息泄露|directory traversal|local file").unwrap());

const DOC_V4: &[&str] = &["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
const IMDS_HOSTS: &[&str] = &["metadata.google.internal", "metadata", "instance-data"];
const ABSORB_STUB: &str = "via verified capability output";
const LOOT_CATS: &[&str] = &[
    "file_read", "lfi", "information_disclosure", "info_disclosure", "path_traversal", "arbitrary_file_read",
];

fn in_cidr_v4(ip: std::net::Ipv4Addr, cidr: &str) -> bool {
    crate::net::NetV4::parse(cidr).map(|n| n.contains(ip)).unwrap_or(false)
}

fn in_doc(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => DOC_V4.iter().any(|c| in_cidr_v4(v4, c)),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

#[pyfunction]
pub fn intra_is_canary(host: &str) -> bool {
    let h = norm_host(host);
    if h.is_empty() {
        return false;
    }
    if is_loopback_host(&h) || h == "localhost" || h == "0.0.0.0" || h == "host.docker.internal" {
        return true;
    }
    if IMDS_HOSTS.contains(&h.as_str()) {
        return true;
    }
    if h.contains("metadata") && (h.ends_with(".internal") || h.contains("google")) {
        return true;
    }
    if let Some(ip) = parse_ip(&h) {
        let link = match ip {
            IpAddr::V4(v4) => v4.is_link_local() || v4.is_multicast() || v4.is_unspecified(),
            IpAddr::V6(v6) => {
                let seg = v6.segments()[0];
                ((seg & 0xffc0) == 0xfe80) || v6.is_multicast() || v6.is_unspecified()
            }
        };
        if link || ip.to_string() == "100.100.100.200" || in_doc(ip) {
            return true;
        }
    }
    if NIP.is_match(&h) {
        let dotted = h.replace('-', ".");
        for c in IPV4.captures_iter(&dotted) {
            let inner = c.get(1).map(|m| m.as_str()).unwrap_or("");
            if !inner.is_empty() && inner != h && intra_is_canary(inner) {
                return true;
            }
        }
    }
    false
}

#[pyfunction]
pub fn intra_live_observation(output: &str) -> bool {
    let text = output.trim();
    if text.chars().count() < 40 {
        return false;
    }
    if LIVE_BODY.is_match(text) {
        return true;
    }
    if DEAD_BODY.is_match(text) {
        return false;
    }
    text.chars().count() >= 400
}

#[pyfunction]
pub fn intra_oracle_only(evidence: &str) -> bool {
    let text = evidence.trim();
    if text.is_empty() || text == ABSORB_STUB {
        return true;
    }
    !intra_live_observation(text)
}

#[pyfunction]
pub fn intra_broadcast(host: &str) -> bool {
    let h = norm_host(host);
    !h.is_empty() && (h.ends_with(".0") || h.ends_with(".255"))
}

#[pyfunction]
pub fn intra_hosts_file_cmd(command: &str) -> bool {
    HOSTS_CMD.is_match(command)
}

#[pyfunction]
pub fn intra_should_absorb_cmd(command: &str) -> bool {
    RECON.is_match(command)
}

pub fn private_hosts(text: &str, limit: i64) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let cap = limit.max(1) as usize;
    for c in IPV4.captures_iter(text) {
        let h = norm_host(c.get(1).map(|m| m.as_str()).unwrap_or(""));
        if h.is_empty() || seen.contains(&h) || h.ends_with(".0") || h.ends_with(".255") {
            continue;
        }
        if !is_dotted_v4(&h) || !ip_is_private_or_loop_or_link(&h) || is_loopback_host(&h) {
            continue;
        }
        seen.insert(h.clone());
        out.push(h);
        if out.len() >= cap {
            break;
        }
    }
    out
}

#[pyfunction]
pub fn intra_private_hosts(text: &str, limit: i64) -> Vec<String> {
    private_hosts(text, limit)
}

#[pyfunction]
pub fn intra_live_hosts(output: &str, limit: i64) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    let cap = limit.max(1) as usize;
    for line in output.split('\n') {
        if !LIVE_LINE.is_match(line) {
            continue;
        }
        for h in private_hosts(line, 4) {
            if seen.insert(h.clone()) {
                found.push(h);
            }
            if found.len() >= cap {
                return found;
            }
        }
    }
    found
}

#[pyfunction]
pub fn intra_capability_hosts(url: &str, data: &str, command: &str, output: &str) -> Vec<String> {
    if intra_hosts_file_cmd(command) {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    let mut add = |hosts: Vec<String>| {
        for h in hosts {
            if h.is_empty() || seen.contains(&h) || intra_is_canary(&h) {
                continue;
            }
            seen.insert(h.clone());
            found.push(h);
        }
    };
    let live = intra_live_observation(output);
    if !data.is_empty() {
        let dh = private_hosts(data, 4);
        if live && (1..=2).contains(&dh.len()) {
            add(dh);
        }
    }
    let url_hosts = private_hosts(url, 4);
    if live && (1..=2).contains(&url_hosts.len()) {
        add(url_hosts);
    }
    let cmd_hosts = private_hosts(command, 16);
    if live && (1..=2).contains(&cmd_hosts.len()) {
        add(cmd_hosts);
    } else if !command.is_empty() && intra_should_absorb_cmd(command) && !output.is_empty() {
        add(intra_live_hosts(output, 8));
    }
    found.truncate(8);
    found
}

#[pyfunction]
pub fn intra_clue_hosts(command: &str, output: &str) -> Vec<String> {
    if !intra_hosts_file_cmd(command) || output.is_empty() {
        return Vec::new();
    }
    private_hosts(output, 8).into_iter().filter(|h| !intra_is_canary(h)).collect()
}

fn tagset(node: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(Some(tags)) = node.get_item("tags") {
        if let Ok(s) = tags.extract::<String>() {
            out.insert(s.to_ascii_lowercase());
        } else if let Ok(list) = tags.downcast::<PyList>() {
            for t in list.iter() {
                if let Ok(s) = t.extract::<String>() {
                    out.insert(s.to_ascii_lowercase());
                }
            }
        }
    }
    out
}

fn host_from_key(key: &str) -> String {
    for p in ["info:scope-expanded:", "info:host:", "target:"] {
        if let Some(rest) = key.strip_prefix(p) {
            return norm_host(rest.split(':').next().unwrap_or(""));
        }
    }
    String::new()
}

#[pyfunction]
#[pyo3(name = "node_host")]
pub(crate) fn node_host_py(node: Option<&Bound<PyDict>>) -> String {
    node.map(node_host).unwrap_or_default()
}

fn node_host(node: &Bound<PyDict>) -> String {
    let key = node.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let h = host_from_key(&key);
    if !h.is_empty() {
        return h;
    }
    if let Ok(Some(tags)) = node.get_item("tags") {
        if let Ok(list) = tags.downcast::<PyList>() {
            for t in list.iter() {
                if let Ok(ts) = t.extract::<String>() {
                    if ts.to_ascii_lowercase().starts_with("host:") {
                        let hh = norm_host(ts.split_once(':').map(|(_, r)| r).unwrap_or(""));
                        if !hh.is_empty() {
                            return hh;
                        }
                    }
                }
            }
        }
    }
    String::new()
}

fn blob(node: &Bound<PyDict>) -> String {
    let key = node.get_item("key").ok().flatten().map(|v| v.to_string()).unwrap_or_default();
    let title = node.get_item("title").ok().flatten().map(|v| v.to_string()).unwrap_or_default();
    let detail = node.get_item("detail").ok().flatten().map(|v| v.to_string()).unwrap_or_default();
    format!("{key} {title} {detail}")
}

#[pyfunction]
pub fn intra_node_live(node: Option<&Bound<PyDict>>) -> bool {
    let Some(n) = node else { return false };
    let tags = tagset(n);
    if tags.contains("clue-only") && !tags.contains("via-live") {
        return false;
    }
    let h = node_host(n);
    if !h.is_empty() && (intra_broadcast(&h) || intra_is_canary(&h)) {
        return false;
    }
    if tags.contains("via-live") {
        return true;
    }
    let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    if key.starts_with("info:scope-expanded:") && !tags.contains("clue-only") {
        return true;
    }
    let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    ntype == "target" && ["lateral", "pivot", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t))
}

#[pyfunction]
pub fn intra_node_capability(node: Option<&Bound<PyDict>>) -> bool {
    let Some(n) = node else { return false };
    let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let tags = tagset(n);
    if tags.contains("clue-only") && !tags.contains("via-live") {
        return false;
    }
    if key.starts_with("info:scope-expanded:") {
        return true;
    }
    if tags.contains("via-live") {
        return true;
    }
    let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    if ntype == "target" && ["lateral", "pivot", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t)) {
        return true;
    }
    let via = ["scope-expanded", "via-capability", "pivot", "ssrf", "shell_reachable", "port_forward", "socks_tunnel", "via-live"];
    key.starts_with("info:host:") && (via.iter().any(|t| tags.contains(*t)) || tags.contains("lateral") || tags.contains("internal"))
}

#[pyfunction]
pub fn intra_junk_hop(host: &str) -> bool {
    intra_broadcast(host) || intra_is_canary(host)
}

fn hosts_from_node(n: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let h = node_host(n);
    if !h.is_empty() && ip_is_private_or_loop_or_link(&h) && !is_loopback_host(&h) && !intra_broadcast(&h) {
        out.insert(h);
    }
    let tags = n.get_item("tags").ok().flatten().map(|v| v.to_string()).unwrap_or_default();
    let blob = format!("{} {tags}", blob(n));
    for h in private_hosts(&blob, 16) {
        out.insert(h);
    }
    if let Ok(Some(tags)) = n.get_item("tags") {
        if let Ok(list) = tags.downcast::<PyList>() {
            for t in list.iter() {
                if let Ok(ts) = t.extract::<String>() {
                    if ts.to_ascii_lowercase().starts_with("host:") {
                        let hh = norm_host(ts.split_once(':').map(|(_, r)| r).unwrap_or(""));
                        if !hh.is_empty() && ip_is_private_or_loop_or_link(&hh) && !is_loopback_host(&hh) && !intra_broadcast(&hh) {
                            out.insert(hh);
                        }
                    }
                }
            }
        }
    }
    out
}

fn nodes<'py>(graph: &'py Bound<'py, PyDict>) -> Vec<Bound<'py, PyDict>> {
    let mut out = Vec::new();
    if let Ok(Some(ns)) = graph.get_item("nodes") {
        if let Ok(list) = ns.downcast::<PyList>() {
            for n in list.iter() {
                if let Ok(d) = n.downcast::<PyDict>() {
                    out.push(d.clone());
                }
            }
        }
    }
    out
}

pub(crate) fn foothold_hosts(graph: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut entry = BTreeSet::new();
    for n in nodes(graph) {
        let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        if is_entry(&n) {
            let h = host_from_key(&key);
            if !h.is_empty() {
                entry.insert(h);
            }
            continue;
        }
        if ntype == "foothold" || confirmed_shell(&n) {
            out.extend(hosts_from_node(&n));
        }
    }
    out.into_iter().filter(|h| !entry.contains(h)).collect()
}

fn is_entry(n: &Bound<PyDict>) -> bool {
    let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    if ntype != "target" && !key.starts_with("target:") {
        return false;
    }
    let tags = tagset(n);
    if tags.contains("entry") {
        return true;
    }
    if ["lateral", "pivot", "internal", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t)) {
        return false;
    }
    true
}

fn confirmed_shell(n: &Bound<PyDict>) -> bool {
    let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let tags = tagset(n);
    let is_rce = n.get_item("is_rce").ok().flatten().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false);
    if ntype == "goal" && (is_rce || key.starts_with("goal:shell") || tags.contains("getshell")) {
        return true;
    }
    if ntype == "foothold" {
        return is_rce || tags.contains("getshell");
    }
    false
}

pub(crate) fn identity_service_hosts(graph: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in nodes(graph) {
        let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let kind = n.get_item("kind").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        if ntype != "service" && kind != "service" {
            continue;
        }
        let tags = n.get_item("tags").ok().flatten().map(|v| v.to_string()).unwrap_or_default();
        let blob = format!("{} {tags}", blob(&n));
        if IDENTITY.is_match(&blob) {
            out.extend(hosts_from_node(&n));
        }
    }
    out
}

pub(crate) fn cred_named_hosts(graph: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in nodes(graph) {
        let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let tags = tagset(&n);
        let cred = ntype == "credential" || ntype == "cred" || tags.contains("credential") || tags.contains("cred");
        if !cred {
            if !IDENTITY.is_match(&blob(&n)) {
                continue;
            }
            if ntype != "info" && ntype != "credential" {
                continue;
            }
        }
        out.extend(hosts_from_node(&n));
    }
    out
}

pub(crate) fn live_surface_hosts(graph: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in nodes(graph) {
        let tags = tagset(&n);
        if tags.contains("via-live") {
            out.extend(hosts_from_node(&n));
        }
    }
    out
}

#[pyfunction]
pub fn intra_hop_eligible(node: Option<&Bound<PyDict>>, graph: Option<&Bound<PyDict>>) -> bool {
    let Some(n) = node else { return false };
    let h = node_host(n);
    if !h.is_empty() && (intra_broadcast(&h) || intra_is_canary(&h)) {
        return false;
    }
    if let Some(g) = graph {
        if !h.is_empty() && foothold_hosts(g).contains(&h) {
            return false;
        }
    }
    let tags = tagset(n);
    if tags.contains("via-live") {
        return true;
    }
    let mut names: Vec<String> = tags.iter().cloned().collect();
    names.sort();
    let blob = format!("{} {}", blob(n), names.join(" "));
    if IDENTITY.is_match(&blob) {
        return true;
    }
    if let Some(g) = graph {
        if !h.is_empty() && (identity_service_hosts(g).contains(&h) || cred_named_hosts(g).contains(&h) || live_surface_hosts(g).contains(&h)) {
            return true;
        }
    }
    false
}

#[pyfunction]
pub fn intra_intent_hosts(intent: Option<&Bound<PyDict>>) -> Vec<String> {
    let Some(it) = intent else { return Vec::new() };
    let blob = format!(
        "{} {} {} {}",
        it.get_item("from_keys").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
        it.get_item("description").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
        it.get_item("strategy_key").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
        it.get_item("rationale").ok().flatten().map(|v| v.to_string()).unwrap_or_default(),
    );
    private_hosts(&blob, 8)
}

#[allow(dead_code)]
fn _loot(graph: &Bound<PyDict>) -> BTreeSet<String> {
    let _ = (LOOT.is_match(""), LOOT_CATS);
    let _ = graph;
    BTreeSet::new()
}

#[allow(dead_code)]
fn _any(v: &Bound<PyAny>) -> bool {
    v.is_truthy().unwrap_or(false)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(intra_is_canary, m)?)?;
    m.add_function(wrap_pyfunction!(intra_live_observation, m)?)?;
    m.add_function(wrap_pyfunction!(intra_oracle_only, m)?)?;
    m.add_function(wrap_pyfunction!(intra_broadcast, m)?)?;
    m.add_function(wrap_pyfunction!(intra_hosts_file_cmd, m)?)?;
    m.add_function(wrap_pyfunction!(intra_should_absorb_cmd, m)?)?;
    m.add_function(wrap_pyfunction!(intra_private_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(intra_live_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(intra_capability_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(intra_clue_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(intra_node_live, m)?)?;
    m.add_function(wrap_pyfunction!(intra_node_capability, m)?)?;
    m.add_function(wrap_pyfunction!(intra_junk_hop, m)?)?;
    m.add_function(wrap_pyfunction!(intra_hop_eligible, m)?)?;
    m.add_function(wrap_pyfunction!(intra_intent_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(foothold_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(identity_service_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(cred_named_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(live_surface_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(clue_only_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(all_service_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(unauth_loot_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(verified_hop_auth_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(node_host_py, m)?)?;
    Ok(())
}

fn as_set(py: Python<'_>, items: BTreeSet<String>) -> PyResult<Py<PySet>> {
    Ok(PySet::new(py, items)?.unbind())
}

fn field_str(d: &Bound<PyDict>, key: &str) -> String {
    d.get_item(key).ok().flatten().and_then(|v| if v.is_none() { None } else { v.extract::<String>().ok() }).unwrap_or_default()
}

#[pyfunction]
#[pyo3(name = "foothold_hosts")]
fn foothold_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    as_set(py, graph.map(foothold_hosts).unwrap_or_default())
}
#[pyfunction]
#[pyo3(name = "identity_service_hosts")]
fn identity_service_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    as_set(py, graph.map(identity_service_hosts).unwrap_or_default())
}
#[pyfunction]
#[pyo3(name = "cred_named_hosts")]
fn cred_named_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    as_set(py, graph.map(cred_named_hosts).unwrap_or_default())
}
#[pyfunction]
#[pyo3(name = "live_surface_hosts")]
fn live_surface_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    as_set(py, graph.map(live_surface_hosts).unwrap_or_default())
}
#[pyfunction]
#[pyo3(name = "clue_only_hosts")]
fn clue_only_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let Some(graph) = graph else { return as_set(py, BTreeSet::new()); };
    let live = live_surface_hosts(graph);
    let mut out = BTreeSet::new();
    for n in nodes(graph) {
        let tags = tagset(&n);
        if tags.contains("clue-only") && !tags.contains("via-live") {
            for h in hosts_from_node(&n) {
                if !live.contains(&h) {
                    out.insert(h);
                }
            }
        }
    }
    as_set(py, out)
}
#[pyfunction]
#[pyo3(name = "all_service_hosts")]
fn all_service_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let Some(graph) = graph else { return as_set(py, BTreeSet::new()); };
    let mut out = BTreeSet::new();
    for n in nodes(graph) {
        let ntype = field_str(&n, "type");
        let kind = field_str(&n, "kind");
        if ntype == "service" || kind == "service" {
            out.extend(hosts_from_node(&n));
        }
    }
    as_set(py, out)
}
#[pyfunction]
#[pyo3(name = "unauth_loot_hosts")]
fn unauth_loot_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let Some(graph) = graph else { return as_set(py, BTreeSet::new()); };
    let mut by_key = Vec::new();
    for n in nodes(graph) {
        by_key.push((field_str(&n, "key"), n));
    }
    let mut out = BTreeSet::new();
    if let Ok(Some(findings)) = graph.get_item("findings") {
        if let Ok(list) = findings.downcast::<PyList>() {
            for f in list.iter() {
                let Ok(row) = f.downcast::<PyDict>() else { continue };
                let vs = field_str(row, "verification_status").to_ascii_lowercase();
                if ["disproved", "false", "rejected", "pending"].contains(&vs.as_str()) {
                    continue;
                }
                let cat = field_str(row, "category").to_ascii_lowercase();
                let blob = format!("{} {} {cat}", field_str(row, "title"), field_str(row, "description"));
                if !LOOT_CATS.contains(&cat.as_str()) && !LOOT.is_match(&blob) {
                    continue;
                }
                if !["verified", "confirmed", ""].contains(&vs.as_str()) {
                    continue;
                }
                let nk = field_str(row, "node_key");
                if let Some((_, n)) = by_key.iter().find(|(k, _)| k == &nk) {
                    out.extend(hosts_from_node(n));
                }
                out.extend(private_hosts(&blob, 8));
            }
        }
    }
    as_set(py, out)
}
#[pyfunction]
#[pyo3(name = "verified_hop_auth_hosts", signature = (graph=None, intents=None))]
fn verified_hop_auth_hosts_py(py: Python<'_>, graph: Option<&Bound<PyDict>>, intents: Option<&Bound<PyAny>>) -> PyResult<Py<PySet>> {
    let mut rows: Vec<Bound<PyDict>> = Vec::new();
    if let Some(intents) = intents {
        if let Ok(it) = intents.try_iter() {
            for item in it.flatten() {
                if let Ok(d) = item.downcast::<PyDict>() {
                    rows.push(d.clone());
                }
            }
        }
    }
    if rows.is_empty() {
        if let Some(graph) = graph {
            if let Ok(Some(raw)) = graph.get_item("intents") {
                if let Ok(list) = raw.downcast::<PyList>() {
                    for item in list.iter() {
                        if let Ok(d) = item.downcast::<PyDict>() {
                            rows.push(d.clone());
                        }
                    }
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    for it in rows {
        let sk = field_str(&it, "strategy_key");
        if !sk.ends_with("hop_auth") && !sk.contains("::hop_auth") {
            continue;
        }
        if field_str(&it, "status") != "verified" {
            continue;
        }
        let blob = format!(
            "{} {} {} {}",
            field_str(&it, "from_keys"), field_str(&it, "description"), sk, field_str(&it, "rationale"),
        );
        out.extend(private_hosts(&blob, 8));
    }
    as_set(py, out)
}
