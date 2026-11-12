//! intranet_reach 里还没暴露成原名的函数。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::BTreeSet;

use crate::intranet::{intra_is_canary, intra_private_hosts};
use crate::net::{is_loopback_host, is_private_host, norm_host};
use crate::osnet::attacker_hosts;
use crate::scope::{scope_host_in_scope, scope_same_pivot_lan};

fn scope_to_dict(py: Python<'_>, scope: &Bound<PyAny>) -> Option<Py<PyDict>> {
    if scope.is_none() {
        return None;
    }
    if let Ok(d) = scope.downcast::<PyDict>() {
        return Some(d.clone().unbind());
    }
    let _ = py;
    scope.call_method0("to_dict").ok().and_then(|v| v.extract().ok())
}

fn nodes<'py>(graph: &Bound<'py, PyDict>) -> Vec<Bound<'py, PyDict>> {
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

fn tags(n: &Bound<PyDict>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(Some(raw)) = n.get_item("tags") {
        if let Ok(s) = raw.extract::<String>() {
            out.insert(s.to_ascii_lowercase());
        } else if let Ok(list) = raw.downcast::<PyList>() {
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

fn is_entry(n: &Bound<PyDict>) -> bool {
    let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
    if ntype != "target" && !key.starts_with("target:") {
        return false;
    }
    let tags = tags(n);
    if tags.contains("entry") {
        return true;
    }
    if ["lateral", "pivot", "internal", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t)) {
        return false;
    }
    true
}

#[pyfunction]
fn infer_pivot_mechanism(kinds: Option<&Bound<PyAny>>) -> String {
    let mut has_ssrf = false;
    let mut has_tunnel = false;
    if let Some(kinds) = kinds {
        if let Ok(it) = kinds.try_iter() {
            for item in it.flatten() {
                let s = item.extract::<String>().unwrap_or_default();
                if s == "ssrf" { has_ssrf = true; }
                if s == "tunnel" { has_tunnel = true; }
            }
        }
    }
    if has_ssrf { "ssrf_direct".into() } else if has_tunnel { "port_forward".into() } else { "shell_reachable".into() }
}

#[pyfunction]
#[pyo3(signature = (scope=None, *, primary="", own_hosts=None))]
fn entry_hosts(scope: Option<&Bound<PyAny>>, primary: &str, own_hosts: Option<&Bound<PyAny>>) -> Vec<String> {
    let mut out = BTreeSet::new();
    if !primary.is_empty() {
        out.insert(norm_host(primary.split(':').next().unwrap_or("")));
    }
    if let Some(own) = own_hosts {
        if let Ok(it) = own.try_iter() {
            for x in it.flatten() {
                let s = x.extract::<String>().unwrap_or_default();
                let h = norm_host(s.split(':').next().unwrap_or(""));
                if !h.is_empty() { out.insert(h); }
            }
        }
    }
    if let Some(scope) = scope {
        if let Some(d) = scope_to_dict(scope.py(), scope) {
            let d = d.bind(scope.py());
            if let Ok(Some(targets)) = d.get_item("targets") {
                if let Ok(list) = targets.downcast::<PyList>() {
                    for t in list.iter() {
                        let s = t.extract::<String>().unwrap_or_default();
                        let h = norm_host(s.split(':').next().unwrap_or(""));
                        if !h.is_empty() { out.insert(h); }
                    }
                }
            }
        }
    }
    out.into_iter().filter(|h| !h.is_empty()).collect()
}

#[pyfunction]
#[pyo3(signature = (host, *, primary="", own_hosts=None, scope=None))]
fn is_entry_identity(host: &str, primary: &str, own_hosts: Option<&Bound<PyAny>>, scope: Option<&Bound<PyAny>>) -> bool {
    let h = norm_host(host);
    if h.is_empty() { return false; }
    entry_hosts(scope, primary, own_hosts).iter().any(|x| x == &h)
}

#[pyfunction]
#[pyo3(signature = (host, *, primary="", own_hosts=None, scope=None, has_precondition=false, via_hosts=None))]
pub(crate) fn kali_direct_intranet_reason(
    py: Python<'_>,
    host: &str,
    primary: &str,
    own_hosts: Option<&Bound<PyAny>>,
    scope: Option<&Bound<PyAny>>,
    has_precondition: bool,
    via_hosts: Option<&Bound<PyAny>>,
) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || !is_private_host(&h) || is_loopback_host(&h) {
        return None;
    }
    if is_entry_identity(&h, primary, own_hosts, scope) {
        return None;
    }
    let via: BTreeSet<String> = via_hosts.map(|v| v.try_iter().map(|it| it.flatten().filter_map(|x| x.extract::<String>().ok()).map(|s| norm_host(&s)).collect()).unwrap_or_default()).unwrap_or_default();
    let mut in_scope = false;
    if let Some(scope) = scope {
        if let Some(owned) = scope_to_dict(py, scope) {
            let d = owned.bind(py);
            in_scope = scope_host_in_scope(&h, d, attacker_hosts(&[]));
            if !in_scope && scope_same_pivot_lan(&h, Some(d)) {
                in_scope = true;
            }
        }
    }
    let seen = via.contains(&h) || in_scope;
    if !has_precondition {
        return Some("只有内网线索，没有可达前置条件，不能对内网操作。先在已验证 SSRF、立足点 shell 或隧道上看到该主机，再经该能力访问。".into());
    }
    if !seen {
        return Some("该地址只是内网线索，尚未经已验证跳板观测到，不能从本机直连操作。".into());
    }
    Some("该主机是经跳板看见的本题内网，攻击机网卡到不了。把目标放进已验证 SSRF 参数，或在立足点 shell 上访问，或经入口上的转发端口；禁止本机直连。".into())
}

#[pyfunction]
pub(crate) fn has_verified_precondition(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> bool {
    !precondition_kinds(py, graph).is_empty()
}

#[pyfunction]
pub(crate) fn precondition_kinds(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> Vec<String> {
    let Some(graph) = graph else { return Vec::new() };
    let mut kinds = BTreeSet::new();
    let ssrf = ["ssrf_direct", "ssrf_gopher", "ssrf_dns_rebind"];
    for n in nodes(graph) {
        let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let tags = tags(&n);
        let is_rce = n.get_item("is_rce").ok().flatten().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false);
        if (ntype == "goal" && (is_rce || key.starts_with("goal:shell") || tags.contains("getshell")))
            || (ntype == "foothold" && (is_rce || tags.contains("getshell")))
        {
            kinds.insert("shell".to_string());
        }
        let blob = format!("{key} {} {}", n.get_item("title").ok().flatten().map(|v| v.to_string()).unwrap_or_default(), n.get_item("detail").ok().flatten().map(|v| v.to_string()).unwrap_or_default()).to_ascii_lowercase();
        let hay = format!("{blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
        if ["vpn", "socks", "端口转发", "隧道", "port_forward", "socks_tunnel"].iter().any(|m| hay.contains(m)) {
            kinds.insert("tunnel".to_string());
        }
        if key.starts_with("info:scope-expanded:") || (key.starts_with("target:") && (tags.contains("ssrf") || tags.contains("scope-expanded") || blob.contains("ssrf"))) {
            if ssrf.iter().any(|m| blob.contains(m)) || blob.contains("ssrf") || tags.contains("ssrf") {
                kinds.insert("ssrf".to_string());
            }
            if hay.contains("shell_reachable") || tags.contains("shell") {
                kinds.insert("shell".to_string());
            }
        }
    }
    if let Ok(Some(findings)) = graph.get_item("findings") {
        if let Ok(list) = findings.downcast::<PyList>() {
            for f in list.iter() {
                let Ok(d) = f.downcast::<PyDict>() else { continue };
                let vs = d.get_item("verification_status").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default().to_ascii_lowercase();
                if matches!(vs.as_str(), "disproved" | "false" | "rejected") { continue; }
                let cat = d.get_item("category").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default().to_ascii_lowercase();
                let blob = format!("{} {} {cat}", d.get_item("title").ok().flatten().map(|v| v.to_string()).unwrap_or_default(), d.get_item("description").ok().flatten().map(|v| v.to_string()).unwrap_or_default()).to_ascii_lowercase();
                if cat == "ssrf" || cat == "ssrf_internal" || blob.contains("ssrf") {
                    kinds.insert("ssrf".to_string());
                }
            }
        }
    }
    if py.import("atkbrain.graph.hypothesize").and_then(|m| m.getattr("live_gadget_tactics")).and_then(|f| f.call1((graph,))).map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false) {
        kinds.insert("ssrf".to_string());
    }
    kinds.into_iter().collect()
}

#[pyfunction]
#[pyo3(signature = (graph=None, scope=None))]
pub(crate) fn via_capability_hosts(py: Python<'_>, graph: Option<&Bound<PyDict>>, scope: Option<&Bound<PyAny>>) -> Vec<String> {
    let Some(graph) = graph else { return Vec::new() };
    let mut out = BTreeSet::new();
    let mut entry = BTreeSet::new();
    let via_tags = ["scope-expanded", "via-capability", "pivot", "ssrf", "shell_reachable", "port_forward", "socks_tunnel", "via-live"];
    let pivot = ["lateral", "pivot", "internal", "scope-expanded", "via-live"];
    for n in nodes(graph) {
        let key = n.get_item("key").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let ntype = n.get_item("type").ok().flatten().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let h = host_from_key(&key);
        if is_entry(&n) {
            if !h.is_empty() { entry.insert(h); }
            continue;
        }
        let tags = tags(&n);
        let via = key.starts_with("info:scope-expanded:")
            || (ntype == "target" && pivot.iter().any(|t| tags.contains(*t)))
            || via_tags.iter().any(|t| tags.contains(*t));
        if !via { continue; }
        if !h.is_empty() && crate::net::ip_is_private_or_loop_or_link(&h) && !is_loopback_host(&h) && !intra_is_canary(&h) {
            out.insert(h);
        }
    }
    for h in entry { out.remove(&h); }
    if let Some(scope) = scope {
        if let Some(owned) = scope_to_dict(py, scope) {
            let d = owned.bind(py);
            if let Ok(Some(ips)) = d.get_item("ips") {
                if let Ok(list) = ips.downcast::<PyList>() {
                    for raw in list.iter() {
                        let h = norm_host(&raw.extract::<String>().unwrap_or_default());
                        if h.is_empty() || !crate::net::ip_is_private_or_loop_or_link(&h) || is_loopback_host(&h) || intra_is_canary(&h) {
                            continue;
                        }
                        if out.contains(&h) || scope_same_pivot_lan(&h, Some(&d)) {
                            out.insert(h);
                        }
                    }
                }
            }
        }
    }
    out.into_iter().collect()
}

fn scope_owned(py: Python<'_>, scope: &Bound<PyAny>) -> Option<Py<PyDict>> {
    scope_to_dict(py, scope)
}

#[pyfunction]
#[pyo3(signature = (host, scope=None, *, primary=""))]
pub(crate) fn unauthorized_public_host(py: Python<'_>, host: &str, scope: Option<&Bound<PyAny>>, primary: &str) -> Option<String> {
    let owned = scope.and_then(|s| scope_to_dict(py, s));
    match owned {
        Some(d) => {
            let b = d.bind(py);
            crate::scope::scope_unauthorized_public(host, Some(&b), primary, attacker_hosts(&[]))
        }
        None => crate::scope::scope_unauthorized_public(host, None, primary, attacker_hosts(&[])),
    }
}

#[pyfunction]
#[pyo3(signature = (host, scope=None, *, primary="", peers=None, own_hosts=None))]
pub(crate) fn unauthorized_private_host(
    py: Python<'_>,
    host: &str,
    scope: Option<&Bound<PyAny>>,
    primary: &str,
    peers: Option<&Bound<PyAny>>,
    own_hosts: Option<&Bound<PyAny>>,
) -> Option<String> {
    let owned = scope.and_then(|s| scope_to_dict(py, s));
    let peers = peers.and_then(|p| p.downcast::<PyList>().ok().map(|l| l.clone()));
    let own = own_hosts.and_then(|p| p.downcast::<PyList>().ok().map(|l| l.clone()));
    match owned {
        Some(d) => {
            let b = d.bind(py);
            crate::scope::scope_unauthorized_private(host, Some(&b), primary, peers.as_ref(), own.as_ref(), attacker_hosts(&[]))
        }
        None => crate::scope::scope_unauthorized_private(host, None, primary, peers.as_ref(), own.as_ref(), attacker_hosts(&[])),
    }
}

#[pyfunction]
fn same_pivot_lan(py: Python<'_>, host: &str, scope: Option<&Bound<PyAny>>) -> bool {
    let Some(scope) = scope else { return false };
    let Some(d) = scope_to_dict(py, scope) else { return false };
    let b = d.bind(py);
    scope_same_pivot_lan(host, Some(&b))
}

#[pyfunction]
#[pyo3(signature = (token, scope, extra_self=None))]
pub(crate) fn scan_network_forbidden_reason(py: Python<'_>, token: &str, scope: &Bound<PyAny>, extra_self: Option<&Bound<PyAny>>) -> Option<String> {
    let Some(d) = scope_to_dict(py, scope) else { return None };
    let d = d.bind(py);
    let mut extra = Vec::new();
    if let Some(raw) = extra_self {
        if let Ok(it) = raw.try_iter() {
            for x in it.flatten() {
                if let Ok(s) = x.extract::<String>() { extra.push(s); }
            }
        }
    }
    crate::scope::scope_scan_forbidden(token, d, attacker_hosts(&extra))
}

#[pyfunction]
#[pyo3(signature = (scope=None, primary=""))]
fn authorized_registrable_domains(py: Python<'_>, scope: Option<&Bound<PyAny>>, primary: &str) -> Vec<String> {
    let owned = scope.and_then(|s| scope_to_dict(py, s));
    match owned {
        Some(d) => crate::scope::scope_authorized_domains(Some(&d.bind(py)), primary),
        None => crate::scope::scope_authorized_domains(None, primary),
    }
}

#[pyfunction]
#[pyo3(signature = (host, port=None, *, self_hosts=None, self_ports=None))]
pub(crate) fn is_platform_endpoint(host: &str, port: Option<i64>, self_hosts: Option<&Bound<PyAny>>, self_ports: Option<&Bound<PyAny>>) -> bool {
    let base: Vec<String> = self_hosts.map(|v| v.try_iter().map(|it| it.flatten().filter_map(|x| x.extract::<String>().ok()).collect()).unwrap_or_else(|_| crate::osnet::local_self_hosts())).unwrap_or_else(|| crate::osnet::local_self_hosts());
    let ports: Vec<i64> = self_ports.map(|v| v.try_iter().map(|it| it.flatten().filter_map(|x| x.extract::<i64>().ok()).collect()).unwrap_or_default()).unwrap_or_default();
    let idents = attacker_hosts(&base);
    crate::scope::scope_platform_endpoint(host, port, idents, base, ports)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(infer_pivot_mechanism, m)?)?;
    m.add_function(wrap_pyfunction!(entry_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(is_entry_identity, m)?)?;
    m.add_function(wrap_pyfunction!(kali_direct_intranet_reason, m)?)?;
    m.add_function(wrap_pyfunction!(has_verified_precondition, m)?)?;
    m.add_function(wrap_pyfunction!(precondition_kinds, m)?)?;
    m.add_function(wrap_pyfunction!(via_capability_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(unauthorized_public_host, m)?)?;
    m.add_function(wrap_pyfunction!(unauthorized_private_host, m)?)?;
    m.add_function(wrap_pyfunction!(same_pivot_lan, m)?)?;
    m.add_function(wrap_pyfunction!(scan_network_forbidden_reason, m)?)?;
    m.add_function(wrap_pyfunction!(authorized_registrable_domains, m)?)?;
    m.add_function(wrap_pyfunction!(is_platform_endpoint, m)?)?;
    m.add("SSRF_NEIGHBOR_RULE", "只有从目标响应里看见、或经 SSRF 拿到登录页/横幅/业务正文的具体内网主机才扩 Scope。链路本地与云元数据、文档网段、以及超时/无业务正文的错误码差分只证明 SSRF 原语，不要当成新邻机、不要 hop_auth。")?;
    Ok(())
}
