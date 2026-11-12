//! 命令放行。真正拉起进程仍在 runner.py。

use pyo3::prelude::*;
use pyo3::types::{PyAny, PyList, PySet};
use regex::Regex;
use std::sync::LazyLock;

use crate::guard::{guard_ctf_mega, guard_destructive, guard_extract_host_ports, guard_extract_hosts};
use crate::net::{canonical_host, is_loopback_host};
use crate::objective::objective_allows_flag;
use crate::osnet::attacker_hosts;
use crate::scope::{scope_lan_forbidden, scope_loopback_forbidden, scope_peer_endpoint, scope_private_hint, scope_public_hint, scope_sensitive_attack};
use crate::scope_obj::{is_attacker_identity_py, on_local_docker_bridge_py, Scope};

static EXEC_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|[\s;&|`(])(?:\./|sh\s|bash\s|python[23]?\s|perl\s|ruby\s|php\s|node\s|source\s|\.\s)").unwrap()
});
static PROXY_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:proxychains4?|\bsshpass\b|(?:-x|--proxy|--socks5(?:-hostname)?)\b|ProxyCommand=|\bnc\s+-x\b|socks5h?://127\.|TCP-LISTEN:|\s-(?:D|L|R)\s)").unwrap()
});
static CIDR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b").unwrap());
const PROXY_PORTS: &[i64] = &[1080, 1081, 1082, 9050, 9051, 4145, 10800, 8083];

static LOCAL_DESTRUCTIVE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        Regex::new(r"\brm\s+-rf\s+/(?:\s|$)").unwrap(),
        Regex::new(r"\brm\s+-rf\s+~(?:/|\s|$)").unwrap(),
        Regex::new(r":\(\)\s*\{\s*:\|:&\s*\};:").unwrap(),
        Regex::new(r"(?i)\bmkfs\.").unwrap(),
        Regex::new(r"(?i)\bdd\s+if=.*of=/dev/(sd|nvme|vd)").unwrap(),
        Regex::new(r"(?i)>\s*/dev/(sd|nvme|vd)").unwrap(),
        Regex::new(r"(?i)\bshutdown\b|\breboot\b|\bpoweroff\b").unwrap(),
    ]
});

#[pyclass]
pub struct GuardDecision {
    #[pyo3(get)]
    pub allow: bool,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub category: String,
    #[pyo3(get)]
    pub hosts: Py<PyList>,
}

#[pyclass]
pub struct Guard {
    scope: Py<Scope>,
    #[pyo3(get, set)]
    pub quarantine_dir: String,
    #[pyo3(get, set)]
    pub objective: Option<String>,
    #[pyo3(get, set)]
    pub primary_port: Option<i64>,
    #[pyo3(get, set)]
    pub workspace_dir: String,
    #[pyo3(get, set)]
    pub has_intranet_precondition: bool,
    peer_hosts: Py<PyList>,
    peer_addrs: Py<PyList>,
    own_addrs: Py<PyList>,
    self_hosts: Py<PyList>,
    self_ports: Py<PyList>,
    allowed_secrets: Py<PyAny>,
    via_capability_hosts: Py<PyList>,
}

#[pymethods]
impl Guard {
    #[new]
    #[pyo3(signature = (scope, quarantine_dir="", *, objective=None))]
    fn new(py: Python<'_>, scope: Py<Scope>, quarantine_dir: &str, objective: Option<String>) -> PyResult<Self> {
        let ports = PyList::empty(py);
        if let Ok(cfg) = py.import("atkbrain.config") {
            if let Ok(settings) = cfg.getattr("settings") {
                if let Ok(p) = settings.getattr("port") {
                    let _ = ports.append(p);
                }
                if let Ok(p) = settings.getattr("frontend_port") {
                    let _ = ports.append(p);
                }
            }
        }
        let hosts = PyList::new(py, crate::osnet::local_self_hosts())?;
        Ok(Guard {
            scope,
            quarantine_dir: quarantine_dir.trim_end_matches('/').to_string(),
            objective,
            primary_port: None,
            workspace_dir: String::new(),
            has_intranet_precondition: false,
            peer_hosts: PyList::empty(py).unbind(),
            peer_addrs: PyList::empty(py).unbind(),
            own_addrs: PyList::empty(py).unbind(),
            self_hosts: hosts.unbind(),
            self_ports: ports.unbind(),
            allowed_secrets: PySet::empty(py)?.into_any().unbind(),
            via_capability_hosts: PyList::empty(py).unbind(),
        })
    }

    #[getter]
    fn scope<'py>(&self, py: Python<'py>) -> Py<Scope> {
        self.scope.clone_ref(py)
    }
    #[getter]
    fn peer_hosts<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.peer_hosts.bind(py).clone() }
    #[setter]
    fn set_peer_hosts(&mut self, value: Py<PyList>) { self.peer_hosts = value; }
    #[getter]
    fn peer_addrs<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.peer_addrs.bind(py).clone() }
    #[setter]
    fn set_peer_addrs(&mut self, value: Py<PyList>) { self.peer_addrs = value; }
    #[getter]
    fn own_addrs<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.own_addrs.bind(py).clone() }
    #[setter]
    fn set_own_addrs(&mut self, value: Py<PyList>) { self.own_addrs = value; }
    #[getter]
    fn self_hosts<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.self_hosts.bind(py).clone() }
    #[setter]
    fn set_self_hosts(&mut self, value: Py<PyList>) { self.self_hosts = value; }
    #[getter]
    fn self_ports<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.self_ports.bind(py).clone() }
    #[getter]
    fn allowed_secrets<'py>(&self, py: Python<'py>) -> Bound<'py, PyAny> { self.allowed_secrets.bind(py).clone() }
    #[setter]
    fn set_allowed_secrets(&mut self, value: Py<PyAny>) { self.allowed_secrets = value; }
    #[getter]
    fn via_capability_hosts<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.via_capability_hosts.bind(py).clone() }
    #[setter]
    fn set_via_capability_hosts(&mut self, value: Py<PyList>) { self.via_capability_hosts = value; }

    fn check_command(&self, py: Python<'_>, command: &str) -> PyResult<Py<GuardDecision>> {
        let cmd = command.trim();
        let deny = |allow: bool, reason: String, category: &str, hosts: Vec<String>| -> PyResult<Py<GuardDecision>> {
            Ok(Py::new(py, GuardDecision {
                allow,
                reason,
                category: category.into(),
                hosts: PyList::new(py, hosts)?.unbind(),
            })?)
        };
        for pat in LOCAL_DESTRUCTIVE.iter() {
            if pat.is_match(cmd) {
                return deny(false, format!("拦截破坏性命令：匹配 {}", pat.as_str()), "destructive", vec![]);
            }
        }
        for host in crate::scope::scope_public_hosts(vec![cmd.to_string()]) {
            if let Some(why) = scope_sensitive_attack(&host) {
                return deny(false, format!("拦截：{why}"), "policy", vec![host]);
            }
        }
        if let Some(why) = guard_destructive(Some(cmd), self.objective.as_deref()) {
            let hint = if why.contains("SQL") || why.to_ascii_lowercase().contains("sqlmap") || why.contains("DUMPFILE") || why.contains("OUTFILE") {
                "SQLi 只用 SELECT/布尔/报错证明。"
            } else {
                "只证明、不落地。"
            };
            return deny(false, format!("拦截破坏性操作：{why}。{hint}"), "destructive", vec![]);
        }
        if let Some(why) = crate::guard::guard_mega_wordlist(Some(cmd)) {
            return deny(false, format!("拦截：{why}"), "policy", vec![]);
        }
        if objective_allows_flag(self.objective.as_deref()) {
            if let Some(why) = guard_ctf_mega(Some(cmd)) {
                return deny(false, format!("拦截：{why}"), "policy", vec![]);
            }
        } else if let Ok(pool_mod) = py.import("atkbrain.proxy.pool") {
            let must = pool_mod.getattr("pool")
                .and_then(|pool| pool.call_method1("must_proxy", (self.objective.as_deref(),)))
                .and_then(|v| v.extract::<bool>())
                .unwrap_or(false);
            if must {
                if let Ok(why) = py.import("atkbrain.proxy.enforce")
                    .and_then(|enf| enf.getattr("proxy_bypass_reason"))
                    .and_then(|f| f.call1((cmd,)))
                    .and_then(|v| v.extract::<Option<String>>())
                {
                    if let Some(why) = why.filter(|s| !s.is_empty()) {
                        return deny(false, format!("拦截：{why}"), "proxy", vec![]);
                    }
                }
            }
        }
        if !self.quarantine_dir.is_empty() && cmd.contains(&self.quarantine_dir) && (EXEC_PREFIX.is_match(cmd) || cmd.contains("chmod")) {
            return deny(false, "拒绝执行隔离区中的文件，仅允许静态分析。".into(), "honeypot", vec![]);
        }
        let pairs = guard_extract_host_ports(cmd);
        let scope = self.scope.bind(py);
        let primary = scope.borrow().targets(py).get_item(0).ok().and_then(|v| v.extract::<String>().ok()).unwrap_or_default();
        let primary_host = primary.split(':').next().unwrap_or("").to_string();
        let self_hosts = self.self_hosts.bind(py);
        let self_ports = self.self_ports.bind(py);
        let own_addrs = self.own_addrs.bind(py);
        let peer_addrs = self.peer_addrs.bind(py);
        let peer_hosts = self.peer_hosts.bind(py);
        let mut own_hosts = Vec::new();
        for item in own_addrs.iter() {
            if let Ok(s) = item.extract::<String>() {
                let h = s.split(':').next().unwrap_or("").trim().to_string();
                if !h.is_empty() {
                    own_hosts.push(h);
                }
            }
        }
        let mut authorized = own_hosts.clone();
        for item in scope.borrow().targets(py).iter() {
            if let Ok(s) = item.extract::<String>() {
                let h = s.split(':').next().unwrap_or("").trim().to_string();
                if !h.is_empty() { authorized.push(h); }
            }
        }
        for item in scope.borrow().ips(py).iter() {
            if let Ok(s) = item.extract::<String>() {
                let h = s.split(':').next().unwrap_or("").trim().to_string();
                if !h.is_empty() { authorized.push(h); }
            }
        }
        let authorized_list = PyList::new(py, authorized)?;
        let own_list = PyList::new(py, own_hosts.clone())?;
        let mut docker_allow = own_hosts.clone();
        if !primary_host.is_empty() {
            docker_allow.push(primary_host.clone());
        }
        let docker_allow = PyList::new(py, docker_allow)?;
        let mut self_host_vec = Vec::new();
        for item in self_hosts.iter() {
            if let Ok(s) = item.extract::<String>() { self_host_vec.push(s); }
        }
        for (host, port) in &pairs {
            let ch = canonical_host(host);
            if crate::reach::is_platform_endpoint(&ch, *port, Some(&self_hosts), Some(&self_ports)) {
                let label = match port { Some(p) => format!("{ch}:{p}"), None => ch.clone() };
                return deny(false, format!("拦截：不要把本机控制台/物理网卡（{label}）当作作业目标。"), "self_protection", vec![ch]);
            }
            if let Some(why) = scope_loopback_forbidden(&ch, Some(&authorized_list)) {
                if !loopback_proxy(cmd, &ch, *port) {
                    return deny(false, format!("拦截：{why}。SSRF 载荷请放进 -d/--data，不要让 本机直连 127.0.0.0/8。本地 SOCKS/ssh -D 转发端口除外。"), "self_protection", vec![ch]);
                }
            }
            if is_attacker_identity_py(&ch, Some(self_hosts.as_any())) {
                return deny(false, format!("拦截：{ch} 是本机网卡或物机网关，禁止直连物理机。"), "self_protection", vec![ch]);
            }
            if let Some(why) = scope_lan_forbidden(&ch, attacker_hosts(&self_host_vec)) {
                return deny(false, format!("拦截：{why}。本机网卡和物机网关是守卫，不是目标。"), "self_protection", vec![ch]);
            }
            if let Some(why) = on_local_docker_bridge_py(&ch, Some(docker_allow.as_any())) {
                return deny(false, format!("拦截：{why}。经已有 SSRF/shell 中转；sshpass 只打题目入口上的监听端口。"), "self_protection", vec![ch]);
            }
            if let Some(why) = scope_peer_endpoint(&ch, *port, &primary_host, self.primary_port, Some(&peer_addrs), Some(&peer_hosts), Some(&own_addrs)) {
                return deny(false, format!("拦截越界私网：{why}。只打当前入口；邻题 IP/端口不是横向。"), "out_of_scope", vec![ch]);
            }
            if let Some(why) = crate::reach::kali_direct_intranet_reason(
                py, &ch, &primary_host, Some(own_list.as_any()), Some(scope.as_any()),
                self.has_intranet_precondition, Some(self.via_capability_hosts.bind(py).as_any()),
            ) {
                return deny(false, format!("拦截：{why}"), "out_of_scope", vec![ch]);
            }
            if let Ok(gate) = py.import("atkbrain.engine.hop_auth_gate") {
                let kw = pyo3::types::PyDict::new(py);
                kw.set_item("host", &ch)?;
                kw.set_item("port", *port)?;
                kw.set_item("workspace_dir", &self.workspace_dir)?;
                kw.set_item("allowed_secrets", self.allowed_secrets.bind(py))?;
                if let Ok(why) = gate.getattr("ssh_auth_block_reason").and_then(|f| f.call((cmd,), Some(&kw))).and_then(|v| v.extract::<Option<String>>()) {
                    if let Some(why) = why.filter(|s| !s.is_empty()) {
                        return deny(false, format!("拦截：{why}"), "policy", vec![ch]);
                    }
                }
            }
            if let Some(why) = crate::reach::unauthorized_private_host(py, &ch, Some(scope.as_any()), &primary_host, Some(peer_hosts.as_any()), Some(own_list.as_any())) {
                return deny(false, format!("拦截越界私网：{}", scope_private_hint(&why)), "out_of_scope", vec![ch]);
            }
            if let Some(why) = crate::reach::unauthorized_public_host(py, &ch, Some(scope.as_any()), &primary_host) {
                return deny(false, format!("拦截越界公网：{}", scope_public_hint(&why)), "out_of_scope", vec![ch]);
            }
        }
        let mut seen = Vec::new();
        for net in CIDR.find_iter(cmd) {
            let key = net.as_str().to_string();
            if seen.contains(&key) { continue; }
            seen.push(key.clone());
            if let Some(why) = crate::reach::scan_network_forbidden_reason(py, &key, scope.as_any(), Some(self_hosts.as_any())) {
                let cat = if why.contains("命中攻击机本机网卡或物机网关") || why.contains("物机网关") { "self_protection" } else { "scope" };
                return deny(false, why, cat, vec![key]);
            }
        }
        let data_dir = crate::guard::console_data_dir(py);
        if let Some(why) = atkbrain_core::guard_rules::custom_block_reason(&data_dir, cmd) {
            if !why.is_empty() {
                return deny(false, why, "custom", vec![]);
            }
        }
        let hosts = guard_extract_hosts(cmd);
        deny(true, "ok".into(), "ok", hosts)
    }

    #[staticmethod]
    fn looks_like_honeypot(banner: &str) -> (bool, String) {
        let b = banner.to_ascii_lowercase();
        for (kw, why) in [
            ("kippo", "Kippo SSH 蜜罐特征"),
            ("cowrie", "Cowrie SSH 蜜罐特征"),
            ("dionaea", "Dionaea 蜜罐特征"),
            ("t-pot", "T-Pot 蜜罐平台特征"),
            ("honeyd", "Honeyd 蜜罐特征"),
            ("glastopf", "Glastopf Web 蜜罐特征"),
            ("conpot", "Conpot ICS 蜜罐特征"),
        ] {
            if b.contains(kw) {
                return (true, why.into());
            }
        }
        (false, String::new())
    }
}

fn loopback_proxy(command: &str, host: &str, port: Option<i64>) -> bool {
    if !is_loopback_host(host) {
        return false;
    }
    if port.is_some_and(|p| PROXY_PORTS.contains(&p)) {
        return true;
    }
    PROXY_HINT.is_match(command)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Guard>()?;
    m.add_class::<GuardDecision>()?;
    Ok(())
}
