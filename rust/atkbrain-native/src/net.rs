//! 与 CPython 3.12 ipaddress 对齐的主机归一化。只做判断，不读网卡。

use std::net::{Ipv4Addr, Ipv6Addr};

const PRIV4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.0.170/31",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "240.0.0.0/4",
    "255.255.255.255/32",
];
const PRIV4_EX: &[&str] = &["192.0.0.9/32", "192.0.0.10/32"];

pub fn norm_host(host: &str) -> String {
    let mut h = host.trim().to_ascii_lowercase();
    while h.ends_with('.') {
        h.pop();
    }
    if let Some(rest) = h.strip_prefix("::ffff:") {
        if is_dotted_v4(rest) {
            return rest.to_string();
        }
    }
    h
}

pub fn is_dotted_v4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.chars().all(|c| c.is_ascii_digit())
            && p.parse::<u16>().ok().filter(|n| *n <= 255).is_some()
    })
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
    let (addr, pref) = cidr.split_once('/')?;
    let ip: Ipv4Addr = addr.parse().ok()?;
    let prefix: u32 = pref.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let ip = u32::from(ip);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((ip & mask, mask))
}

pub fn ipv4_is_private(ip: Ipv4Addr) -> bool {
    let n = u32::from(ip);
    let in_priv = PRIV4.iter().any(|c| {
        let (net, mask) = parse_cidr_v4(c).unwrap();
        n & mask == net
    });
    if !in_priv {
        return false;
    }
    !PRIV4_EX.iter().any(|c| {
        let (net, mask) = parse_cidr_v4(c).unwrap();
        n & mask == net
    })
}

pub fn ipv6_is_private(ip: Ipv6Addr) -> bool {
    // 测试与守卫只依赖常见 ULA / 链路本地 / 回环 / 未指定 / IPv4 映射。
    ip.is_loopback()
        || ip.is_unspecified()
        || is_ipv6_link_local(ip)
        || is_ula(ip)
        || ip.to_ipv4_mapped().is_some()
}

fn is_ula(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

pub fn parse_ip(host: &str) -> Option<std::net::IpAddr> {
    let h = norm_host(host);
    let h = h
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(h.as_str())
        .to_string();
    h.parse().ok()
}

pub fn ip_is_private_or_loop_or_link(host: &str) -> bool {
    match parse_ip(host) {
        Some(std::net::IpAddr::V4(ip)) => {
            ipv4_is_private(ip) || ip.is_loopback() || ip.is_link_local()
        }
        Some(std::net::IpAddr::V6(ip)) => {
            ipv6_is_private(ip) || ip.is_loopback() || is_ipv6_link_local(ip)
        }
        None => false,
    }
}

pub fn is_loopback_host(host: &str) -> bool {
    let h = norm_host(host);
    if h == "localhost" || h == "::1" || h.starts_with("127.") {
        return true;
    }
    match parse_ip(&h) {
        Some(std::net::IpAddr::V4(ip)) => ip.is_loopback(),
        Some(std::net::IpAddr::V6(ip)) => ip.is_loopback(),
        None => false,
    }
}

pub fn is_private_host(host: &str) -> bool {
    match parse_ip(&norm_host(host)) {
        Some(std::net::IpAddr::V4(ip)) => ipv4_is_private(ip) || ip.is_link_local(),
        Some(std::net::IpAddr::V6(ip)) => ipv6_is_private(ip) || is_ipv6_link_local(ip),
        None => false,
    }
}

fn octet(part: &str) -> Option<u64> {
    let p = part.trim().to_ascii_lowercase();
    if p.is_empty() {
        return None;
    }
    if let Some(hex) = p.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if p.len() > 1 && p.starts_with('0') && p.chars().all(|c| matches!(c, '0'..='7')) {
        return u64::from_str_radix(&p, 8).ok();
    }
    if p.chars().all(|c| c.is_ascii_digit()) {
        return p.parse().ok();
    }
    None
}

fn inet_aton_parts(nums: &[u64]) -> Option<u32> {
    let v = match nums.len() {
        4 => {
            if nums.iter().any(|x| *x > 255) {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        }
        3 => {
            if nums[0] > 255 || nums[1] > 255 || nums[2] > 0xFFFF {
                return None;
            }
            (nums[0] << 24) | (nums[1] << 16) | nums[2]
        }
        2 => {
            if nums[0] > 255 || nums[1] > 0xFFFFFF {
                return None;
            }
            (nums[0] << 24) | nums[1]
        }
        _ => return None,
    };
    u32::try_from(v).ok()
}

/// 收成标准 IPv4/IPv6 文本。无法识别则 None。
pub fn coerce_ip(host: &str) -> Option<String> {
    let mut h = host.trim().to_ascii_lowercase();
    while h.ends_with('.') {
        h.pop();
    }
    if let Some(inner) = h.strip_prefix('[') {
        if let Some(inner) = inner.strip_suffix(']') {
            h = inner.to_string();
        }
    }
    if let Some(rest) = h.strip_prefix("::ffff:") {
        if is_dotted_v4(rest) {
            h = rest.to_string();
        }
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(|v4| v4.to_string())
                .or(Some(v6.to_string())),
            std::net::IpAddr::V4(v4) => Some(v4.to_string()),
        };
    }
    if let Some(hex) = h.strip_prefix("0x") {
        if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(n) = u64::from_str_radix(hex, 16) {
                if n <= u32::MAX as u64 {
                    return Some(Ipv4Addr::from(n as u32).to_string());
                }
            }
            return None;
        }
    }
    if h.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() {
        if let Ok(n) = h.parse::<u64>() {
            if (65536..=u32::MAX as u64).contains(&n) {
                return Some(Ipv4Addr::from(n as u32).to_string());
            }
        }
        return None;
    }
    if h.contains('.') {
        let parts: Vec<&str> = h.split('.').collect();
        if (2..=4).contains(&parts.len()) {
            let mut nums = Vec::new();
            for p in parts {
                let v = octet(p)?;
                nums.push(v);
            }
            if let Some(n) = inet_aton_parts(&nums) {
                return Some(Ipv4Addr::from(n).to_string());
            }
        }
    }
    None
}

pub fn canonical_host(host: &str) -> String {
    coerce_ip(host).unwrap_or_else(|| norm_host(host))
}

pub fn ipv4_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Ok(net) = cidr.parse::<ipnet_lite::NetV4>() else {
        return false;
    };
    net.contains(ip)
}

/// 不引入 ipnet：自己解析 strict=False 的 IPv4 网段。
mod ipnet_lite {
    use std::net::Ipv4Addr;
    pub struct NetV4 {
        net: u32,
        mask: u32,
        prefix: u32,
    }
    impl NetV4 {
        pub fn contains(&self, ip: Ipv4Addr) -> bool {
            u32::from(ip) & self.mask == self.net
        }
        pub fn prefix(&self) -> u32 {
            self.prefix
        }
        pub fn num_addresses(&self) -> u64 {
            1u64 << (32 - self.prefix)
        }
        pub fn network(&self) -> Ipv4Addr {
            Ipv4Addr::from(self.net)
        }
        pub fn subnet_of(&self, parent: &NetV4) -> bool {
            self.prefix >= parent.prefix && (self.net & parent.mask) == parent.net
        }
        pub fn overlaps(&self, other: &NetV4) -> bool {
            let m = self.mask & other.mask;
            self.net & m == other.net & m
        }
        pub fn supernet(&self) -> Option<NetV4> {
            if self.prefix == 0 {
                return None;
            }
            NetV4::parse(&format!("{}/{}", self.network(), self.prefix - 1))
        }
    }
    impl std::str::FromStr for NetV4 {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            Self::parse(s).ok_or(())
        }
    }
    impl NetV4 {
        pub fn parse(raw: &str) -> Option<Self> {
            let (addr, pref) = raw.split_once('/')?;
            let ip: Ipv4Addr = addr.parse().ok()?;
            let prefix: u32 = pref.parse().ok()?;
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let net = u32::from(ip) & mask;
            Some(NetV4 { net, mask, prefix })
        }
        pub fn to_string_cidr(&self) -> String {
            format!("{}/{}", self.network(), self.prefix)
        }
    }
    pub use NetV4 as Net;
}

pub use ipnet_lite::NetV4;

pub fn count_righthand_zero_bits(number: u32, bits: u32) -> u32 {
    if number == 0 {
        return bits;
    }
    bits.min(number.trailing_zeros())
}

pub fn summarize_v4(first: u32, last: u32) -> Vec<NetV4> {
    let mut out = Vec::new();
    let mut cur = first;
    let ip_bits = 32u32;
    while cur <= last {
        let span = (last - cur) as u64 + 1;
        let nbits = count_righthand_zero_bits(cur, ip_bits).min((span.bit_length() as u32).saturating_sub(1));
        let prefix = ip_bits - nbits;
        let addr = Ipv4Addr::from(cur);
        if let Some(net) = NetV4::parse(&format!("{addr}/{prefix}")) {
            out.push(net);
        }
        let step = 1u64 << nbits;
        let next = cur as u64 + step;
        if next > u32::MAX as u64 {
            break;
        }
        cur = next as u32;
        if nbits == 0 && cur == first {
            break;
        }
    }
    out
}

trait BitLength {
    fn bit_length(self) -> u32;
}
impl BitLength for u64 {
    fn bit_length(self) -> u32 {
        if self == 0 { 0 } else { 64 - self.leading_zeros() }
    }
}
