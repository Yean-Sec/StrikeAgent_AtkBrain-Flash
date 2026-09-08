"""项目作业对象：创建时填写的 host/IP。"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

INFRA_ALLOWLIST = {
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
    "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com", "pypi.org", "files.pythonhosted.org",
    "gitlab.com", "registry.npmjs.org",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTNAME_IN_TEXT_RE = re.compile(
    r"(?:https?://)?("
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+"
    r")(?::\d{1,5})?",
)


def _norm_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("::ffff:") and _IP_RE.match(h[7:]):
        return h[7:]
    return h


def is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(_norm_host(host))
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except Exception:
        return False


def unauthorized_peer_endpoint(
    host: str,
    port: int | None,
    *,
    primary: str = "",
    primary_port: int | None = None,
    peer_addrs: set[str] | None = None,
    peers: set[str] | None = None,
    own_addrs: set[str] | None = None,
) -> str | None:
    """邻题入口：不同 IP，或同一 IP 上其它 unique_code 的端口。本题自己的入口一律放行。"""
    h = _norm_host(host)
    if not h or not is_private_ip(h):
        return None
    ph = _norm_host(str(primary or "").split(":")[0])
    addrs = {str(a).strip().lower() for a in (peer_addrs or ()) if a}
    own = {str(a).strip().lower() for a in (own_addrs or ()) if a}
    own_hosts = {_norm_host(a.split(":")[0]) for a in own}
    if port is not None:
        try:
            p = int(port)
        except (TypeError, ValueError):
            p = None
        else:
            key = f"{h}:{p}"
            if key in own or (h in own_hosts and any(
                a == key or (a.endswith(f":{p}") and _norm_host(a.rsplit(":", 1)[0]) == h)
                for a in own
            )):
                return None
            if primary_port is not None:
                try:
                    if ph and h == ph and p == int(primary_port):
                        return None
                except (TypeError, ValueError):
                    pass
            if key in addrs:
                return f"{h}:{p} 是其它题目入口"
            if ph and h == ph:
                for a in addrs:
                    if ":" not in a:
                        continue
                    ah, _, ap = a.rpartition(":")
                    if _norm_host(ah) != h:
                        continue
                    try:
                        if int(ap) == p:
                            return f"{h}:{p} 是其它题目入口"
                    except (TypeError, ValueError):
                        continue
    if h in own_hosts:
        return None
    peer_hosts = {_norm_host(str(x).split(":")[0]) for x in (peers or ()) if x}
    peer_hosts |= {_norm_host(a.split(":")[0]) for a in addrs}
    if ph and h == ph:
        return None
    if h in peer_hosts:
        return f"{h} 是其它题目入口"
    return None


def unauthorized_private_host(
    host: str,
    scope: "Scope | None",
    *,
    primary: str = "",
    peers: set[str] | None = None,
    own_hosts: set[str] | None = None,
) -> str | None:
    """当前入口以外的私网 IP：没有写进 Scope（已验证横向才会hydrate）就视为越界。

    评测里邻题常在同一网段；公网域名（CVE 文档/pypi）不拦。
    本题自己的全部入口主机（多 container_addr）一律放行。
    """
    h = _norm_host(host)
    if not h or not is_private_ip(h):
        return None
    if primary and h == _norm_host(str(primary).split(":")[0]):
        return None
    own = {_norm_host(str(x).split(":")[0]) for x in (own_hosts or ()) if x}
    if h in own:
        return None
    # 邻题入口优先于 Scope：同网段误入 ips 也不能当横向。
    peer_set = {_norm_host(p.split(":")[0]) for p in (peers or ()) if p}
    if h in peer_set:
        return f"{h} 是其它题目入口，不是本机横向"
    if scope is not None:
        try:
            if scope.host_in_scope(h):
                return None
        except Exception:
            pass
    return f"{h} 不在当前入口范围内（无已验证横向）"


def www_aliases(host: str) -> set[str]:
    h = _norm_host(host)
    if not h or _IP_RE.match(h):
        return {h} if h else set()
    out = {h}
    if h.startswith("www.") and "." in h[4:]:
        out.add(h[4:])
    elif "." in h:
        out.add("www." + h)
    return out


def is_loopback(host: str) -> bool:
    h = _norm_host(host)
    if h in ("localhost", "::1"):
        return True
    if h.startswith("127."):
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_private(host: str) -> bool:
    h = _norm_host(host)
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_link_local)


def is_single_label(host: str) -> bool:
    h = _norm_host(host)
    return "." not in h and not _IP_RE.match(h) and h not in ("", "::1")


def is_internal_tld(host: str) -> bool:
    h = _norm_host(host)
    return h.endswith((".internal", ".local", ".localdomain", ".lan", ".intra", ".corp", ".svc"))


_IFACE_INET_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b")
# 过宽前缀（VPN /8）会把 CTF 的 10.0.0.0/8 入口吞进「物理机内网」；只把常见局域网前缀当 LAN。
_LAN_PREFIX_MIN = 16
_LAN_PREFIX_MAX = 30
_IPV4_MAX = 0xFFFFFFFF
# 小于等于端口号的十进制不当成 IPv4，避免把 nmap --top-ports 100 当成 0.0.0.100。
_IPV4_INT_MIN = 65536


def _ipv4_octet(part: str) -> int | None:
    p = (part or "").strip().lower()
    if not p:
        return None
    try:
        if p.startswith("0x"):
            n = int(p, 16)
        elif len(p) > 1 and p.startswith("0") and set(p) <= set("01234567"):
            n = int(p, 8)
        elif p.isdigit():
            n = int(p, 10)
        else:
            return None
    except ValueError:
        return None
    return n


def _inet_aton_parts(nums: list[int]) -> int:
    """BSD inet_aton：127.1 → 127.0.0.1，127.0.1 → 127.0.0.1。"""
    if len(nums) == 4:
        if not all(0 <= x <= 255 for x in nums):
            raise ValueError("octet")
        a, b, c, d = nums
        return (a << 24) | (b << 16) | (c << 8) | d
    if len(nums) == 3:
        a, b, c = nums
        if a > 255 or b > 255 or c > 0xFFFF:
            raise ValueError("short")
        return (a << 24) | (b << 16) | c
    if len(nums) == 2:
        a, b = nums
        if a > 255 or b > 0xFFFFFF:
            raise ValueError("short")
        return (a << 24) | b
    raise ValueError("parts")


def coerce_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """把直连目标里的十进制/十六进制/八进制/短写 IPv4 以及映射 IPv6 收成标准地址。

    只用于守卫判定真实连接，不改作业对象字符串本身。
    """
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.startswith("::ffff:") and _IP_RE.match(h[7:]):
        h = h[7:]
    try:
        ip = ipaddress.ip_address(h)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        pass
    if re.fullmatch(r"0x[0-9a-f]+", h):
        try:
            n = int(h, 16)
            if 0 <= n <= _IPV4_MAX:
                return ipaddress.IPv4Address(n)
        except Exception:
            return None
        return None
    if h.isdigit():
        try:
            n = int(h, 10)
            if _IPV4_INT_MIN <= n <= _IPV4_MAX:
                return ipaddress.IPv4Address(n)
        except Exception:
            return None
        return None
    if "." in h:
        parts = h.split(".")
        if 2 <= len(parts) <= 4:
            nums: list[int] = []
            for p in parts:
                v = _ipv4_octet(p)
                if v is None:
                    return None
                nums.append(v)
            try:
                return ipaddress.IPv4Address(_inet_aton_parts(nums))
            except Exception:
                return None
    return None


def canonical_host(host: str) -> str:
    ip = coerce_ip(host)
    if ip is not None:
        return str(ip)
    return _norm_host(host)


def is_attacker_identity(host: str) -> bool:
    """本机网卡或回环：不能当立足点。不含整段物理局域网（题目可能和 Kali 同网段）。"""
    h = _norm_host(host)
    if not h:
        return False
    key = canonical_host(h)
    if is_loopback(h) or is_loopback(key):
        return True
    selves = local_self_hosts()
    return h in selves or key in selves


def _iface_ipv4() -> list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]]:
    """本机非回环 IPv4 及网卡前缀。读失败则空列表。"""
    rows: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Network]] = []
    try:
        import subprocess
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"],
            text=True, timeout=2, stderr=subprocess.DEVNULL,
        )
    except Exception:
        return rows
    for line in (out or "").splitlines():
        cols = line.split()
        if len(cols) < 4:
            continue
        iface = cols[1].rstrip(":")
        if iface == "lo" or iface.startswith("lo:"):
            continue
        m = _IFACE_INET_RE.search(line)
        if not m:
            continue
        try:
            ip = ipaddress.IPv4Address(m.group(1))
            prefix = int(m.group(2))
            net = ipaddress.IPv4Network(f"{m.group(1)}/{prefix}", strict=False)
        except Exception:
            continue
        if ip.is_loopback:
            continue
        rows.append((ip, net))
    return rows


def local_self_hosts() -> set[str]:
    """本机网卡 IPv4（不含回环），用于保护物理机。"""
    out: set[str] = set()
    try:
        import socket
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not is_loopback(ip):
                out.add(_norm_host(ip))
    except Exception:
        pass
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not is_loopback(ip):
                out.add(_norm_host(ip))
        finally:
            s.close()
    except Exception:
        pass
    for ip, _net in _iface_ipv4():
        out.add(_norm_host(str(ip)))
    return out


def local_self_networks() -> list[ipaddress.IPv4Network]:
    """物理机局域网前缀（/16–/30）。过宽前缀不收录，以免吞掉题目网段。"""
    nets: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for _ip, net in _iface_ipv4():
        if net.prefixlen < _LAN_PREFIX_MIN or net.prefixlen > _LAN_PREFIX_MAX:
            continue
        key = str(net)
        if key not in seen:
            seen.add(key)
            nets.append(net)
    return nets


def _ipv4_in_authorized(ip: ipaddress.IPv4Address, authorized: set[str] | None) -> bool:
    for raw in authorized or ():
        other = coerce_ip(raw)
        if isinstance(other, ipaddress.IPv4Address) and other == ip:
            return True
        if _norm_host(raw) == str(ip):
            return True
    return False


def attacker_loopback_forbidden(
    host: str,
    *,
    authorized: set[str] | None = None,
) -> str | None:
    """Kali 直连回环会打到本机，不是题目入口。入口本身就是回环时放行。"""
    h = _norm_host(host)
    if not h:
        return None
    ch = canonical_host(h)
    if not (is_loopback(h) or is_loopback(ch)):
        return None
    for raw in authorized or ():
        a = _norm_host(raw)
        if not a:
            continue
        ca = canonical_host(a)
        if is_loopback(a) or is_loopback(ca) or ca == ch or a == h:
            return None
    return f"{ch} 是回环地址，禁止直连本机"


def attacker_lan_forbidden(
    host: str,
    *,
    self_hosts: set[str] | None = None,
    self_networks: list[ipaddress.IPv4Network] | None = None,
    authorized: set[str] | None = None,
) -> str | None:
    """Kali 直连物理机网卡或办公网段：禁止。题目入口若就在该网段，只拦网卡本身。"""
    h = _norm_host(host)
    if not h:
        return None
    selves = {_norm_host(x) for x in (self_hosts if self_hosts is not None else local_self_hosts())}
    key = canonical_host(h)
    if key in selves or h in selves:
        ip_self = coerce_ip(key)
        if isinstance(ip_self, ipaddress.IPv4Address) and _ipv4_in_authorized(ip_self, authorized):
            return None
        return f"{key} 是本机网卡，禁止直连物理机"
    ip = coerce_ip(h)
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    if _ipv4_in_authorized(ip, authorized):
        return None
    nets = list(self_networks if self_networks is not None else local_self_networks())
    hit = [n for n in nets if ip in n]
    if not hit:
        return None
    auth_ips: list[ipaddress.IPv4Address] = []
    for raw in authorized or ():
        other = coerce_ip(raw)
        if isinstance(other, ipaddress.IPv4Address):
            auth_ips.append(other)
    if any(any(a in n for a in auth_ips) for n in hit):
        return None
    return f"{ip} 落在本机网段 {hit[0]}，禁止直连物理机内网"


def attacker_lan_scan_forbidden(
    net: ipaddress.IPv4Network,
    *,
    self_hosts: set[str] | None = None,
    self_networks: list[ipaddress.IPv4Network] | None = None,
    authorized: set[str] | None = None,
) -> str | None:
    """nmap/masscan 扫到物理机网段：禁止。即使题目和 Kali 同网段，也不许扫整段。"""
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    if net.prefixlen == 32:
        return attacker_lan_forbidden(
            str(net.network_address),
            self_hosts=self_hosts,
            self_networks=self_networks,
            authorized=authorized,
        )
    selves = {_norm_host(x) for x in (self_hosts if self_hosts is not None else local_self_hosts())}
    for raw in selves:
        ip = coerce_ip(raw)
        if isinstance(ip, ipaddress.IPv4Address) and ip in net:
            return f"禁止扫描覆盖本机网卡的网段 {net}"
    nets = list(self_networks if self_networks is not None else local_self_networks())
    for sn in nets:
        if net.overlaps(sn):
            return f"禁止扫描本机网段 {sn}"
    return None


def is_platform_endpoint(
    host: str,
    port: int | None = None,
    *,
    self_hosts: set[str] | None = None,
    self_ports: set[int] | None = None,
) -> bool:
    """勿打本机控制台端口，也勿把物理机网卡 IP 当作业目标。"""
    h = canonical_host(host)
    if not h:
        return False
    extra = {_norm_host(x) for x in (self_hosts if self_hosts is not None else local_self_hosts())}
    extra |= {canonical_host(x) for x in extra}
    # 物理机网卡：任意端口均视为平台自保护
    if h in extra and not is_loopback(h):
        return True
    ports = self_ports or set()
    if port is None or int(port) not in ports:
        return False
    if is_loopback(h) or h in extra:
        return True
    return False


def scan_network_forbidden_reason(token: str, scope: "Scope", extra_self: set[str] | None = None) -> str | None:
    raw = (token or "").strip()
    if "/" not in raw:
        return None
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except Exception:
        return None
    if not isinstance(net, ipaddress.IPv4Network):
        return None
    auth: set[str] = set()
    if scope is not None:
        auth |= {_norm_host(str(t).split(":")[0]) for t in (scope.targets or []) if t}
        auth |= {_norm_host(str(i)) for i in (scope.ips or []) if i}
    return attacker_lan_scan_forbidden(net, self_hosts=extra_self, authorized=auth)


def forbidden_project_target_reason(host: str) -> str | None:
    h = _norm_host(host)
    if not h:
        return "目标不能为空"
    return None


@dataclass
class Scope:
    targets: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    ports: list[int] | None = None
    allow_subdomains: bool = False
    mode: str = "strict"

    def identity_hosts(self) -> set[str]:
        out: set[str] = set()
        for t in self.targets:
            out |= www_aliases(t)
        for ip in self.ips:
            out.add(_norm_host(ip))
        return {h for h in out if h}

    def host_in_scope(
        self,
        host: str,
        *,
        objective: str | None = None,
        allow_internal: bool = False,
    ) -> bool:
        h = _norm_host(host)
        if not h:
            return False
        if h in INFRA_ALLOWLIST:
            return True
        if self._explicit_member(h):
            return True
        if self.allow_subdomains:
            for t in self.targets:
                apex = _norm_host(t)
                if apex and (h == apex or h.endswith("." + apex)):
                    return True
        return False

    def _explicit_member(self, host: str) -> bool:
        return _norm_host(host) in self.identity_hosts()

    def host_header_authorized(self, host: str) -> bool:
        return self.host_in_scope(host)

    def to_dict(self) -> dict:
        return {
            "targets": list(self.targets),
            "ips": list(self.ips),
            "cidrs": list(self.cidrs),
            "ports": self.ports,
            "allow_subdomains": self.allow_subdomains,
            "mode": self.mode,
        }

    @classmethod
    def from_dict(cls, d: dict | None) -> "Scope":
        d = d or {}
        return cls(
            targets=list(d.get("targets") or []),
            ips=list(d.get("ips") or []),
            cidrs=list(d.get("cidrs") or []),
            ports=d.get("ports"),
            allow_subdomains=bool(d.get("allow_subdomains")),
            mode=str(d.get("mode") or "strict"),
        )
