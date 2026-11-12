//! 本机网卡、默认网关、docker 网桥。读失败则空，和 Python 一样。

use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::net::{is_loopback_host, norm_host, NetV4};

static CACHE: Mutex<(f64, Vec<String>)> = Mutex::new((0.0, Vec::new()));

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn ip_addr_lines() -> String {
    Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

pub fn iface_rows() -> Vec<(String, String, u32)> {
    let mut out = Vec::new();
    for line in ip_addr_lines().lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }
        let iface = cols[1].trim_end_matches(':');
        if iface == "lo" || iface.starts_with("lo:") {
            continue;
        }
        let inet = cols.iter().position(|c| *c == "inet").and_then(|i| cols.get(i + 1));
        let Some(cidr) = inet else { continue };
        let Some((addr, pref)) = cidr.split_once('/') else { continue };
        let Ok(prefix) = pref.parse::<u32>() else { continue };
        if is_loopback_host(addr) {
            continue;
        }
        out.push((iface.to_string(), addr.to_string(), prefix));
    }
    out
}

pub fn local_self_hosts() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(name) = std::process::Command::new("hostname").output() {
        let host = String::from_utf8_lossy(&name.stdout).trim().to_string();
        if let Ok(addrs) = (host.as_str(), 0).to_socket_addrs() {
            for addr in addrs {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let ip = v4.ip().to_string();
                    if !is_loopback_host(&ip) {
                        out.push(norm_host(&ip));
                    }
                }
            }
        }
    }
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                let ip = addr.ip().to_string();
                if !is_loopback_host(&ip) {
                    out.push(norm_host(&ip));
                }
            }
        }
    }
    for (_iface, addr, _p) in iface_rows() {
        out.push(norm_host(&addr));
    }
    out.sort();
    out.dedup();
    out
}

pub fn gateways() -> Vec<String> {
    let mut gws = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
        for line in text.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            if parts[1] != "00000000" || parts[2] == "00000000" {
                continue;
            }
            if let Ok(raw) = hex::decode(parts[2]) {
                if raw.len() == 4 && !raw[3].to_string().starts_with("127") {
                    let ip = format!("{}.{}.{}.{}", raw[3], raw[2], raw[1], raw[0]);
                    if !ip.starts_with("127.") {
                        gws.push(ip);
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("ip").args(["-4", "route", "show", "default"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for token in text.split_whitespace() {
            if let Some(ip) = token.strip_prefix("") {
                let _ = ip;
            }
        }
        for part in text.split("via ") {
            let ip = part.split_whitespace().next().unwrap_or("");
            if ip.parse::<Ipv4Addr>().is_ok() && !ip.starts_with("127.") {
                gws.push(ip.to_string());
            }
        }
    }
    gws.sort();
    gws.dedup();
    gws
}

pub fn attacker_hosts(extra: &[String]) -> Vec<String> {
    let now = now();
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if now - guard.0 > 30.0 || guard.1.is_empty() {
        let mut hosts = local_self_hosts();
        hosts.extend(gateways());
        hosts.sort();
        hosts.dedup();
        *guard = (now, hosts);
    }
    let mut out = guard.1.clone();
    for x in extra {
        let h = norm_host(x);
        if !h.is_empty() && !out.contains(&h) {
            out.push(h);
        }
    }
    out.retain(|h| !h.is_empty());
    out
}

pub fn docker_bridges() -> Vec<(String, NetV4)> {
    let mut out = Vec::new();
    for (iface, addr, prefix) in iface_rows() {
        if iface != "docker0" && !iface.starts_with("br-") {
            continue;
        }
        if let Some(net) = NetV4::parse(&format!("{addr}/{prefix}")) {
            out.push((iface, net));
        }
    }
    out
}

pub fn on_docker_bridge(host: &str, allow: &[String]) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() {
        return None;
    }
    let allowed: Vec<String> = allow.iter().map(|x| norm_host(x.split(':').next().unwrap_or(""))).collect();
    if allowed.iter().any(|a| a == &h) {
        return None;
    }
    let Ok(ip) = h.parse::<Ipv4Addr>() else { return None };
    for (iface, net) in docker_bridges() {
        if net.contains(ip) {
            return Some(format!(
                "{h} 落在攻击机 docker 网桥 {iface}（{}）上，Kali 直连会打到本机容器，不是题内网",
                net.to_string_cidr()
            ));
        }
    }
    None
}

pub fn local_networks() -> Vec<String> {
    let mut out = Vec::new();
    for (_iface, addr, prefix) in iface_rows() {
        if !(16..=30).contains(&prefix) {
            continue;
        }
        if let Some(net) = NetV4::parse(&format!("{addr}/{prefix}")) {
            let s = net.to_string_cidr();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}
