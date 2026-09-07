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


def is_attacker_identity(host: str) -> bool:
    return False


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
    return out


def is_platform_endpoint(
    host: str,
    port: int | None = None,
    *,
    self_hosts: set[str] | None = None,
    self_ports: set[int] | None = None,
) -> bool:
    """勿打本机控制台端口，也勿把物理机网卡 IP 当作业目标。"""
    h = _norm_host(host)
    if not h:
        return False
    extra = {_norm_host(x) for x in (self_hosts if self_hosts is not None else local_self_hosts())}
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
    return None


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
