//! 授权范围里的主机判断。网卡与网桥仍由 Python 采集后传入。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::Bound;
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::net::{
    canonical_host, coerce_ip, ip_is_private_or_loop_or_link, is_dotted_v4, is_loopback_host,
    is_private_host, norm_host, summarize_v4, NetV4,
};

const INFRA: &[&str] = &[
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com", "pypi.org", "files.pythonhosted.org",
    "gitlab.com", "registry.npmjs.org",
];
const MULTI: &[&str] = &[
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.au", "net.au", "org.au", "co.nz",
    "com.tw", "com.hk", "co.kr",
];
const ECHO: &[&str] = &[
    "icanhazip.com", "ipv4.icanhazip.com", "ipv6.icanhazip.com",
    "api.ipify.org", "ifconfig.me", "ifconfig.co", "ip.sb", "ipinfo.io",
];
const DOCS: &[&str] = &[
    "nvd.nist.gov", "cve.org", "www.cve.org", "cvedetails.com",
    "exploit-db.com", "www.exploit-db.com", "attack.mitre.org",
];
const OOB_EXACT: &[&str] = &[
    "dnslog.cn", "ceye.io", "interact.sh", "oastify.com", "webhook.site", "requestbin.net",
];
const OOB_SUF: &[&str] = &[
    ".dnslog.cn", ".dnslog.io", ".ceye.io", ".interact.sh", ".oastify.com",
    ".burpcollaborator.net", ".webhook.site", ".requestbin.net",
    ".ngrok.io", ".ngrok-free.app", ".ngrok.app", ".loca.lt",
    ".iyhc.eu.org", ".lfcx.eu.org", ".zaza.eu.org",
];
const FILE_TLD: &[&str] = &[
    "txt", "xml", "js", "mjs", "cjs", "ts", "tsx", "jsx", "json", "map",
    "html", "htm", "css", "scss", "png", "jpg", "jpeg", "gif", "svg", "webp",
    "ico", "woff", "woff2", "ttf", "eot", "pdf", "zip", "gz", "tgz", "md",
    "yml", "yaml", "toml", "lock", "log", "php", "asp", "aspx", "jsp",
];
const GTLD: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "app", "dev", "cloud",
    "info", "biz", "xyz", "top", "site", "online", "store", "tech", "pro",
    "vip", "work", "live", "team", "group", "network", "systems", "host",
    "studio", "blog", "page", "shop", "news", "media", "link", "space",
    "io", "ai", "co",
];
const PROT_TLD: &[&str] = &["gov", "edu", "mil", "int"];
const PROT_SLD: &[&str] = &["gov", "edu", "mil", "ac", "gob", "gouv", "govt"];

static HOST_IN_TEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:https?://)?(",
        r"(?:\d{1,3}\.){3}\d{1,3}",
        r"|",
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?",
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+",
        r")(?::\d{1,5})?"
    )).unwrap()
});
static CIDR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$").unwrap());
static RANGE_LAST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$").unwrap());
static RANGE_FULL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$").unwrap());

struct ScopeIn {
    targets: Vec<String>,
    ips: Vec<String>,
    cidrs: Vec<String>,
    allow_subdomains: bool,
}

fn str_list(v: Option<Bound<PyAny>>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    if v.is_none() {
        return Vec::new();
    }
    if let Ok(list) = v.downcast::<PyList>() {
        return list.iter().filter_map(|x| x.extract::<String>().ok()).collect();
    }
    Vec::new()
}

fn scope_from(d: &Bound<PyDict>) -> ScopeIn {
    ScopeIn {
        targets: str_list(d.get_item("targets").ok().flatten()),
        ips: str_list(d.get_item("ips").ok().flatten()),
        cidrs: str_list(d.get_item("cidrs").ok().flatten()),
        allow_subdomains: d.get_item("allow_subdomains").ok().flatten().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false),
    }
}

fn strs(list: Option<&Bound<PyList>>) -> Vec<String> {
    list.map(|l| l.iter().filter_map(|x| x.extract::<String>().ok()).collect()).unwrap_or_default()
}

pub fn is_attacker(host: &str, attackers: &[String]) -> bool {
    let h = norm_host(host);
    if h.is_empty() || is_loopback_host(&h) || !is_dotted_v4(&h) {
        let key = if h.is_empty() { String::new() } else { canonical_host(&h) };
        if !key.is_empty() && is_dotted_v4(&key) && !is_loopback_host(&key) {
            return attackers.iter().any(|a| a == &key);
        }
        return false;
    }
    attackers.iter().any(|a| a == &h || a == &canonical_host(&h))
}

fn identity(scope: &ScopeIn) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for t in scope.targets.iter().chain(scope.ips.iter()) {
        let h = norm_host(t);
        if !h.is_empty() {
            out.insert(h);
        }
    }
    out
}

fn ip_in_cidrs(host: &str, scope: &ScopeIn) -> bool {
    let Ok(addr) = host.parse::<std::net::IpAddr>() else { return false };
    for raw in &scope.cidrs {
        if let Ok(net) = raw.parse::<ipnet::IpNet>() {
            if net.contains(&addr) {
                return true;
            }
        }
    }
    false
}

pub fn host_in_scope(host: &str, scope: &ScopeIn, attackers: &[String]) -> bool {
    let h = norm_host(host);
    if h.is_empty() {
        return false;
    }
    if is_attacker(&h, attackers) {
        return false;
    }
    if INFRA.contains(&h.as_str()) {
        return true;
    }
    if identity(scope).contains(&h) {
        return true;
    }
    if ip_in_cidrs(&h, scope) {
        return true;
    }
    if scope.allow_subdomains {
        for t in &scope.targets {
            let apex = norm_host(t);
            if !apex.is_empty() && (h == apex || h.ends_with(&format!(".{apex}"))) {
                return true;
            }
        }
    }
    false
}

pub fn registrable(host: &str) -> String {
    let mut h = norm_host(host);
    if h.starts_with('[') && h.ends_with(']') && h.len() >= 2 {
        h = h[1..h.len() - 1].to_string();
    }
    if let Some(rest) = h.strip_prefix("www.") {
        if rest.contains('.') {
            h = rest.to_string();
        }
    }
    if h.is_empty() {
        return String::new();
    }
    if is_dotted_v4(&h) {
        return h;
    }
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return h;
    }
    let last2 = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if MULTI.contains(&last2.as_str()) && parts.len() >= 3 {
        return format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1]);
    }
    last2
}

fn oob_or_infra(host: &str) -> bool {
    let h = norm_host(host);
    if h.is_empty() {
        return false;
    }
    if INFRA.contains(&h.as_str()) || ECHO.contains(&h.as_str()) || DOCS.contains(&h.as_str()) || OOB_EXACT.contains(&h.as_str()) {
        return true;
    }
    let all: Vec<&str> = INFRA.iter().chain(ECHO.iter()).chain(DOCS.iter()).copied().collect();
    for t in all {
        if is_dotted_v4(t) {
            continue;
        }
        let apex = registrable(t);
        if !apex.is_empty() && registrable(&h) == apex {
            return true;
        }
        if h == t || h.ends_with(&format!(".{t}")) {
            return true;
        }
    }
    for suf in OOB_SUF {
        if h.ends_with(suf) || h == &suf[1..] {
            return true;
        }
    }
    h.contains(".oast.") || h.starts_with("oast.")
}

fn plausible(host: &str) -> bool {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) || !h.contains('.') {
        return false;
    }
    let tld = h.rsplit('.').next().unwrap_or("");
    if !tld.chars().all(|c| c.is_ascii_alphabetic()) || FILE_TLD.contains(&tld) || tld.len() < 2 {
        return false;
    }
    if tld.len() != 2 && !GTLD.contains(&tld) {
        return false;
    }
    let labels: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if labels.len() < 2 || labels.iter().any(|l| l.chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    true
}

fn strip_port(host: &str) -> String {
    let mut h = norm_host(host);
    h = h.split('/').next().unwrap_or("").to_string();
    if h.matches(':').count() == 1 {
        if let Some((name, port)) = h.split_once(':') {
            if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
                h = name.to_string();
            }
        }
    }
    h
}

pub fn sensitive_domain(host: &str) -> Option<String> {
    let h = strip_port(host);
    if h.is_empty() || is_dotted_v4(&h) || h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    let protected = PROT_TLD.contains(&tld) || (tld.len() == 2 && (PROT_SLD.contains(&sld) || sld == "go"));
    if !protected {
        return None;
    }
    Some(format!(
        "禁止攻击政府、教育、军队或学术网域名：{h}。这类后缀（.gov/.edu/.mil/.int，以及 .gov.cn/.edu.cn/.ac.uk/.go.jp 等）不能作为项目目标，也不能连接。登记进作业范围也不能例外。"
    ))
}

fn parse_scan(token: &str) -> Option<String> {
    let mut t = token.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
    if t.starts_with('-') && t.contains('=') {
        t = t.split_once('=').map(|(_, r)| r.trim().trim_matches(|c| c == '\'' || c == '"').to_string()).unwrap_or(t);
    }
    if let Some(c) = CIDR_RE.captures(&t) {
        let cidr = format!("{}/{}", c.get(1).unwrap().as_str(), c.get(2).unwrap().as_str());
        if let Some(net) = NetV4::parse(&cidr) {
            if net.num_addresses() > 1 {
                return Some(net.to_string_cidr());
            }
        }
        return None;
    }
    if let Some(c) = RANGE_LAST.captures(&t) {
        let prefix = c.get(1).unwrap().as_str();
        let a: u32 = c.get(2).unwrap().as_str().parse().ok()?;
        let b: u32 = c.get(3).unwrap().as_str().parse().ok()?;
        let (lo, hi) = (a.min(b), a.max(b));
        if lo == hi || lo > 255 || hi > 255 {
            return None;
        }
        let start: u32 = format!("{prefix}{lo}").parse::<std::net::Ipv4Addr>().ok().map(u32::from)?;
        let end: u32 = format!("{prefix}{hi}").parse::<std::net::Ipv4Addr>().ok().map(u32::from)?;
        let nets = summarize_v4(start, end);
        if nets.len() == 1 {
            return Some(nets[0].to_string_cidr());
        }
        return Some(format!("{prefix}0/24"));
    }
    if let Some(c) = RANGE_FULL.captures(&t) {
        let mut start = u32::from(c.get(1)?.as_str().parse::<std::net::Ipv4Addr>().ok()?);
        let mut end = u32::from(c.get(2)?.as_str().parse::<std::net::Ipv4Addr>().ok()?);
        if end < start {
            std::mem::swap(&mut start, &mut end);
        }
        if start == end {
            return None;
        }
        let nets = summarize_v4(start, end);
        if nets.is_empty() {
            return None;
        }
        if nets.len() == 1 {
            return Some(nets[0].to_string_cidr());
        }
        let mut cover = NetV4::parse(&nets[0].to_string_cidr())?;
        for n in nets.iter().skip(1) {
            let mut piece = NetV4::parse(&n.to_string_cidr())?;
            while !piece.subnet_of(&cover) {
                cover = cover.supernet()?;
            }
        }
        return Some(cover.to_string_cidr());
    }
    None
}

fn hits_attacker(cidr: &str, attackers: &[String]) -> bool {
    let Some(net) = NetV4::parse(cidr) else { return false };
    attackers.iter().any(|h| h.parse::<std::net::Ipv4Addr>().ok().map(|ip| net.contains(ip)).unwrap_or(false))
}

fn explicitly_authorized(cidr: &str, scope: &ScopeIn) -> bool {
    let Some(net) = NetV4::parse(cidr) else { return false };
    if net.num_addresses() <= 1 {
        return false;
    }
    for c in &scope.cidrs {
        if let Some(parent) = NetV4::parse(c) {
            if net.subnet_of(&parent) || net.to_string_cidr() == parent.to_string_cidr() {
                return true;
            }
        }
    }
    false
}

fn entry_slash24(scope: &ScopeIn) -> Vec<NetV4> {
    let mut out = Vec::new();
    for t in &scope.targets {
        let h = norm_host(t);
        if !is_dotted_v4(&h) {
            continue;
        }
        if let Ok(ip) = h.parse::<std::net::Ipv4Addr>() {
            if let Some(net) = NetV4::parse(&format!("{ip}/24")) {
                out.push(net);
            }
        }
    }
    out
}

fn network_is_pivot(cidr: &str, scope: &ScopeIn) -> bool {
    let Some(net) = NetV4::parse(cidr) else { return false };
    if net.num_addresses() <= 1 || net.prefix() < 16 {
        return false;
    }
    let addr = net.network();
    if !crate::net::ipv4_is_private(addr) && !addr.is_private() {
        // 网段只要不是私网就不算 pivot lan。用网络地址的私网属性不够，改看是否完全落在 RFC1918。
    }
    if !net_is_private(&net) {
        return false;
    }
    for en in entry_slash24(scope) {
        if net.overlaps(&en) {
            return false;
        }
    }
    let entry: BTreeSet<String> = scope.targets.iter().map(|t| norm_host(t)).collect();
    for raw in &scope.ips {
        let h = norm_host(raw);
        if entry.contains(&h) {
            continue;
        }
        if let Ok(addr) = h.parse::<std::net::Ipv4Addr>() {
            if crate::net::ipv4_is_private(addr) && net.contains(addr) {
                return true;
            }
        }
    }
    false
}

fn net_is_private(net: &NetV4) -> bool {
    // Python IPv4Network.is_private 要求网络与广播都在私网且无例外。这里用网络地址与最后一个地址。
    let start = u32::from(net.network());
    let end = start + (net.num_addresses() as u32).saturating_sub(1);
    crate::net::ipv4_is_private(std::net::Ipv4Addr::from(start))
        && crate::net::ipv4_is_private(std::net::Ipv4Addr::from(end))
}

#[pyfunction]
pub fn scope_norm(host: &str) -> String { norm_host(host) }
#[pyfunction]
pub fn scope_is_private_ip(host: &str) -> bool { ip_is_private_or_loop_or_link(host) }
#[pyfunction]
pub fn scope_is_loopback(host: &str) -> bool { is_loopback_host(host) }
#[pyfunction]
pub fn scope_is_private(host: &str) -> bool { is_private_host(host) }
#[pyfunction]
pub fn scope_is_single_label(host: &str) -> bool {
    let h = norm_host(host);
    !h.contains('.') && !is_dotted_v4(&h) && h != "" && h != "::1"
}
#[pyfunction]
pub fn scope_is_internal_tld(host: &str) -> bool {
    let h = norm_host(host);
    [".internal", ".local", ".localdomain", ".lan", ".intra", ".corp", ".svc"].iter().any(|s| h.ends_with(s))
}
#[pyfunction]
pub fn scope_registrable(host: &str) -> String { registrable(host) }
#[pyfunction]
pub fn scope_canonical(host: &str) -> String { canonical_host(host) }
#[pyfunction]
pub fn scope_coerce(host: &str) -> Option<String> { coerce_ip(host) }
#[pyfunction]
pub fn scope_www(host: &str) -> Vec<String> {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) {
        return if h.is_empty() { Vec::new() } else { vec![h] };
    }
    let mut out = vec![h.clone()];
    if let Some(rest) = h.strip_prefix("www.") {
        if rest.contains('.') { out.push(rest.to_string()); }
    } else if h.contains('.') {
        out.push(format!("www.{h}"));
    }
    out
}
#[pyfunction]
pub fn scope_oob(host: &str) -> bool { oob_or_infra(host) }
#[pyfunction]
pub fn scope_plausible(host: &str) -> bool { plausible(host) }
#[pyfunction]
pub fn scope_public_hosts(texts: Vec<String>) -> Vec<String> {
    let blob = texts.join(" ");
    let mut out = Vec::new();
    for c in HOST_IN_TEXT.captures_iter(&blob) {
        let raw = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let h = norm_host(raw.split(':').next().unwrap_or(""));
        if h.is_empty() || is_dotted_v4(&h) || out.contains(&h) {
            continue;
        }
        if plausible(&h) {
            out.push(h);
        }
    }
    out
}
#[pyfunction]
pub fn scope_sensitive_domain(host: &str) -> Option<String> { sensitive_domain(host) }
#[pyfunction]
pub fn scope_sensitive_attack(host: &str) -> Option<String> {
    let h = strip_port(host);
    if DOCS.contains(&h.as_str()) {
        return None;
    }
    sensitive_domain(&h)
}
#[pyfunction]
pub fn scope_forbidden_target(host: &str, attackers: Vec<String>) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() {
        return Some("目标不能为空".into());
    }
    if is_loopback_host(&h) || h == "localhost" || h == "0.0.0.0" || h == "host.docker.internal" {
        return Some(format!("禁止以回环/本机别名作为项目目标：{h}"));
    }
    if is_attacker(&h, &attackers) {
        return Some(format!("禁止以本机/物机（攻击机网卡或默认网关）作为项目目标：{h}"));
    }
    sensitive_domain(&h)
}
#[pyfunction]
pub fn scope_host_in_scope(host: &str, scope: &Bound<PyDict>, attackers: Vec<String>) -> bool {
    host_in_scope(host, &scope_from(scope), &attackers)
}
#[pyfunction]
pub fn scope_is_attacker(host: &str, attackers: Vec<String>) -> bool { is_attacker(host, &attackers) }

#[pyfunction]
pub fn scope_unauthorized_public(host: &str, scope: Option<&Bound<PyDict>>, primary: &str, attackers: Vec<String>) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) {
        return None;
    }
    if oob_or_infra(&h) {
        return None;
    }
    let sc = scope.map(scope_from);
    if let Some(sc) = &sc {
        if host_in_scope(&h, sc, &attackers) {
            return None;
        }
    }
    let mut names: Vec<String> = sc.as_ref().map(|s| {
        let mut v: Vec<String> = identity(s).into_iter().collect();
        v.sort();
        v
    }).unwrap_or_default();
    names.truncate(8);
    let shown = if names.is_empty() {
        let p = norm_host(primary.split(':').next().unwrap_or(""));
        if p.is_empty() { "当前作业对象".into() } else { p }
    } else {
        names.join("、")
    };
    Some(format!("{h} 不在本项目已授权主机内（{shown}）"))
}

#[pyfunction]
pub fn scope_unauthorized_private(
    host: &str,
    scope: Option<&Bound<PyDict>>,
    primary: &str,
    peers: Option<&Bound<PyList>>,
    own_hosts: Option<&Bound<PyList>>,
    attackers: Vec<String>,
) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || !ip_is_private_or_loop_or_link(&h) {
        return None;
    }
    let ph = norm_host(primary.split(':').next().unwrap_or(""));
    if !ph.is_empty() && h == ph {
        return None;
    }
    let own: BTreeSet<String> = strs(own_hosts).into_iter().map(|x| norm_host(x.split(':').next().unwrap_or(""))).filter(|s| !s.is_empty()).collect();
    if own.contains(&h) {
        return None;
    }
    let peers: BTreeSet<String> = strs(peers).into_iter().map(|p| norm_host(p.split(':').next().unwrap_or(""))).filter(|s| !s.is_empty()).collect();
    if peers.contains(&h) {
        return Some(format!("{h} 是其它题目入口，不是本机横向"));
    }
    if let Some(sc) = scope.map(scope_from) {
        if host_in_scope(&h, &sc, &attackers) {
            return None;
        }
    }
    Some(format!("{h} 不在当前入口范围内（无已验证横向）"))
}

#[pyfunction]
pub fn scope_private_hint(why: &str) -> String {
    let mut head = why.trim().to_string();
    if !head.is_empty() && !head.ends_with('。') {
        head.push('。');
    }
    format!("{head}不要无跳板 Kali 直连。本题立足点、SSRF、备份或 SQL 里出现的 RFC1918 是本题内网，不是邻题入口。先 report_pivot_capability 扩进 Scope，再经已有 shell、已验证 SSRF/代理参数，或立足点隧道 + 本机 ssh/sshpass 打。攻击机 docker 网桥不是题目内网。")
}
#[pyfunction]
pub fn scope_public_hint(why: &str) -> String {
    let mut head = why.trim().to_string();
    if !head.is_empty() && !head.ends_with('。') {
        head.push('。');
    }
    format!("{head}只打作业对象填写主机的注册域；页面/JS/iframe 里出现的其它注册域不能当第一跳，可作 SSRF 载荷参数。OOB/dnslog 与 CVE 文档域名除外。")
}
#[pyfunction]
pub fn scope_authorized_domains(scope: Option<&Bound<PyDict>>, primary: &str) -> Vec<String> {
    let mut names = Vec::new();
    if !primary.is_empty() {
        names.push(primary.split(':').next().unwrap_or("").to_string());
    }
    if let Some(sc) = scope.map(scope_from) {
        for t in sc.targets {
            names.push(t.split(':').next().unwrap_or("").to_string());
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for t in names {
        let h = norm_host(&t);
        if h.is_empty() || is_dotted_v4(&h) {
            continue;
        }
        let apex = registrable(&h);
        if !apex.is_empty() && seen.insert(apex.clone()) {
            out.push(apex);
        }
    }
    out
}
#[pyfunction]
pub fn scope_parse_scan(token: &str) -> Option<String> { parse_scan(token) }
#[pyfunction]
pub fn scope_scan_forbidden(token: &str, scope: &Bound<PyDict>, attackers: Vec<String>) -> Option<String> {
    let net = parse_scan(token)?;
    let sc = scope_from(scope);
    if hits_attacker(&net, &attackers) {
        return Some(format!("拦截：扫描范围 {net} 命中攻击机本机网卡或物机网关。禁止打到自己的物理机/Kali。"));
    }
    if explicitly_authorized(&net, &sc) || network_is_pivot(&net, &sc) {
        return None;
    }
    Some(format!("拦截：禁止从攻击机扫未显式授权的网段 {net}。单个目标 IP 不授权其入口 /24 邻居；已扩容的目标内网/容器网可从跳板枚举，命中后 report_pivot_capability 逐台入库。"))
}
#[pyfunction]
pub fn scope_loopback_forbidden(host: &str, authorized: Option<&Bound<PyList>>) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() {
        return None;
    }
    let ch = canonical_host(&h);
    if !(is_loopback_host(&h) || is_loopback_host(&ch)) {
        return None;
    }
    for raw in strs(authorized) {
        let a = norm_host(&raw);
        if a.is_empty() { continue; }
        let ca = canonical_host(&a);
        if is_loopback_host(&a) || is_loopback_host(&ca) || ca == ch || a == h {
            return None;
        }
    }
    Some(format!("{ch} 是回环地址，禁止直连本机"))
}
#[pyfunction]
pub fn scope_lan_forbidden(host: &str, attackers: Vec<String>) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() {
        return None;
    }
    if is_attacker(&h, &attackers) {
        let key = canonical_host(&h);
        return Some(format!("{key} 是本机网卡或物机网关，禁止直连物理机"));
    }
    None
}
#[pyfunction]
pub fn scope_same_pivot_lan(host: &str, scope: Option<&Bound<PyDict>>) -> bool {
    let Some(sc) = scope.map(scope_from) else { return false };
    let h = norm_host(host);
    if h.is_empty() || !ip_is_private_or_loop_or_link(&h) {
        return false;
    }
    let Ok(addr) = h.parse::<std::net::Ipv4Addr>() else { return false };
    if !crate::net::ipv4_is_private(addr) {
        return false;
    }
    let entry: BTreeSet<String> = sc.targets.iter().map(|t| norm_host(t)).collect();
    if entry.contains(&h) {
        return false;
    }
    for en in entry_slash24(&sc) {
        if en.contains(addr) {
            return false;
        }
    }
    for raw in &sc.ips {
        let ph = norm_host(raw);
        if ph.is_empty() || entry.contains(&ph) {
            continue;
        }
        let Ok(paddr) = ph.parse::<std::net::Ipv4Addr>() else { continue };
        if !crate::net::ipv4_is_private(paddr) {
            continue;
        }
        if let Some(net) = NetV4::parse(&format!("{paddr}/24")) {
            if net.contains(addr) {
                return true;
            }
        }
    }
    false
}
#[pyfunction]
pub fn scope_platform_endpoint(host: &str, port: Option<i64>, identity: Vec<String>, self_hosts: Vec<String>, ports: Vec<i64>) -> bool {
    let h = canonical_host(host);
    if h.is_empty() {
        return false;
    }
    let mut extra: BTreeSet<String> = self_hosts.into_iter().map(|x| norm_host(&x)).filter(|s| !s.is_empty()).collect();
    let canon: Vec<String> = extra.iter().map(|x| canonical_host(x)).collect();
    extra.extend(canon);
    if is_attacker(&h, &identity) && !is_loopback_host(&h) {
        return true;
    }
    if extra.contains(&h) && !is_loopback_host(&h) {
        return true;
    }
    let Some(port) = port else { return false };
    if !ports.contains(&port) {
        return false;
    }
    is_loopback_host(&h) || extra.contains(&h)
}
#[pyfunction]
pub fn scope_peer_endpoint(
    host: &str,
    port: Option<i64>,
    primary: &str,
    primary_port: Option<i64>,
    peer_addrs: Option<&Bound<PyList>>,
    peers: Option<&Bound<PyList>>,
    own_addrs: Option<&Bound<PyList>>,
) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || !ip_is_private_or_loop_or_link(&h) {
        return None;
    }
    let ph = norm_host(primary.split(':').next().unwrap_or(""));
    let addrs: BTreeSet<String> = strs(peer_addrs).into_iter().map(|a| a.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    let own: BTreeSet<String> = strs(own_addrs).into_iter().map(|a| a.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    let own_hosts: BTreeSet<String> = own.iter().map(|a| norm_host(a.split(':').next().unwrap_or(""))).collect();
    if let Some(p) = port {
        let key = format!("{h}:{p}");
        if own.contains(&key) || (own_hosts.contains(&h) && own.iter().any(|a| a == &key || (a.ends_with(&format!(":{p}")) && norm_host(a.rsplit_once(':').map(|(x, _)| x).unwrap_or("")) == h))) {
            return None;
        }
        if let Some(pp) = primary_port {
            if !ph.is_empty() && h == ph && p == pp {
                return None;
            }
        }
        if addrs.contains(&key) {
            return Some(format!("{h}:{p} 是其它题目入口"));
        }
        if !ph.is_empty() && h == ph {
            for a in &addrs {
                if let Some((ah, ap)) = a.rsplit_once(':') {
                    if norm_host(ah) == h && ap.parse::<i64>().ok() == Some(p) {
                        return Some(format!("{h}:{p} 是其它题目入口"));
                    }
                }
            }
        }
    }
    if own_hosts.contains(&h) {
        return None;
    }
    let mut peer_hosts: BTreeSet<String> = strs(peers).into_iter().map(|x| norm_host(x.split(':').next().unwrap_or(""))).filter(|s| !s.is_empty()).collect();
    peer_hosts.extend(addrs.iter().map(|a| norm_host(a.split(':').next().unwrap_or(""))));
    if !ph.is_empty() && h == ph {
        return None;
    }
    if peer_hosts.contains(&h) {
        return Some(format!("{h} 是其它题目入口"));
    }
    None
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scope_norm, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_private_ip, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_loopback, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_private, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_single_label, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_internal_tld, m)?)?;
    m.add_function(wrap_pyfunction!(scope_registrable, m)?)?;
    m.add_function(wrap_pyfunction!(scope_canonical, m)?)?;
    m.add_function(wrap_pyfunction!(scope_coerce, m)?)?;
    m.add_function(wrap_pyfunction!(scope_www, m)?)?;
    m.add_function(wrap_pyfunction!(scope_oob, m)?)?;
    m.add_function(wrap_pyfunction!(scope_plausible, m)?)?;
    m.add_function(wrap_pyfunction!(scope_public_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(scope_sensitive_domain, m)?)?;
    m.add_function(wrap_pyfunction!(scope_sensitive_attack, m)?)?;
    m.add_function(wrap_pyfunction!(scope_forbidden_target, m)?)?;
    m.add_function(wrap_pyfunction!(scope_host_in_scope, m)?)?;
    m.add_function(wrap_pyfunction!(scope_is_attacker, m)?)?;
    m.add_function(wrap_pyfunction!(scope_unauthorized_public, m)?)?;
    m.add_function(wrap_pyfunction!(scope_unauthorized_private, m)?)?;
    m.add_function(wrap_pyfunction!(scope_private_hint, m)?)?;
    m.add_function(wrap_pyfunction!(scope_public_hint, m)?)?;
    m.add_function(wrap_pyfunction!(scope_authorized_domains, m)?)?;
    m.add_function(wrap_pyfunction!(scope_parse_scan, m)?)?;
    m.add_function(wrap_pyfunction!(scope_scan_forbidden, m)?)?;
    m.add_function(wrap_pyfunction!(scope_loopback_forbidden, m)?)?;
    m.add_function(wrap_pyfunction!(scope_lan_forbidden, m)?)?;
    m.add_function(wrap_pyfunction!(scope_same_pivot_lan, m)?)?;
    m.add_function(wrap_pyfunction!(scope_platform_endpoint, m)?)?;
    m.add_function(wrap_pyfunction!(scope_peer_endpoint, m)?)?;
    Ok(())
}
