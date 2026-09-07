"""智能体运行上下文：项目状态、作业对象、HTTP 与命令通道。"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..exec.guard import Guard
from ..exec.runner import CmdResult, run_shell
from ..scope import Scope, is_platform_endpoint, local_self_hosts, unauthorized_peer_endpoint, unauthorized_private_host


@dataclass
class AgentContext:
    project_id: str
    workspace_dir: str
    loot_dir: str
    scope: Scope
    guard: Guard
    run_id: str | None = None
    objective: str = "getshell"
    project: dict | None = None
    flags_needed: int = 1
    flags_correct: int = 0
    flags_captured: list = field(default_factory=list)
    benchmark: dict | None = None
    achievements_at_start: list = field(default_factory=list)
    goal_reached: bool = False
    shell_evidence: str = ""
    shell_access: str = ""
    active_host: str = ""
    postex_phase: str = ""
    lateral_emitted: bool = False
    abort_run: object | None = None
    peer_hosts: set = field(default_factory=set)
    peer_addrs: set = field(default_factory=set)
    own_addrs: set = field(default_factory=set)
    primary_port: int | None = None
    entry_kind: str = "http"
    entry_surface: list = field(default_factory=list)
    last_local_progress_mono: float = 0.0
    turn_activity_mono: float = 0.0
    cmd_inflight: int = 0
    _cookies: dict = field(default_factory=dict)
    _httpx_cli: object = None
    _ssrf_gw_hosts: set = field(default_factory=set)
    _ssrf_gw_ts: float = 0.0
    bound_must_intents: frozenset = field(default_factory=frozenset)

    def host_of(self, url: str) -> str:
        try:
            netloc = urlparse(url).netloc
            return netloc.split("@")[-1].split(":")[0]
        except Exception:
            return ""

    def _http_blocked(self, url: str) -> str | None:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == "https" else 80
        if is_platform_endpoint(
            host, port,
            self_hosts=local_self_hosts(),
            self_ports={int(settings.port), int(settings.frontend_port)},
        ):
            return f"不要把本机控制台/物理网卡（{host}:{port}）当作作业目标。"
        primary = ""
        try:
            primary = str((self.project or {}).get("target") or "").split(":")[0]
        except Exception:
            primary = ""
        if not primary:
            primary = str((self.scope.targets or [""])[0] or "").split(":")[0]
        why = unauthorized_peer_endpoint(
            host, port,
            primary=primary,
            primary_port=getattr(self, "primary_port", None),
            peer_addrs=getattr(self, "peer_addrs", None),
            peers=getattr(self, "peer_hosts", None),
            own_addrs=getattr(self, "own_addrs", None),
        )
        if why:
            return f"越界：{why}。只打当前入口；邻题 IP/端口不是横向。"
        why = unauthorized_private_host(
            host, self.scope, primary=primary, peers=getattr(self, "peer_hosts", None),
            own_hosts={
                str(a).split(":")[0] for a in (getattr(self, "own_addrs", None) or set()) if a
            },
        )
        if why:
            return f"越界：{why}。只打当前入口；邻题 IP 不是横向。"
        return None

    async def _host_is_ssrf_gateway(self, host: str) -> bool:
        h = (host or "").strip().lower().split(":")[0]
        if not h:
            return False
        import time
        now = time.monotonic()
        if self._ssrf_gw_ts and (now - self._ssrf_gw_ts) < 20.0:
            return h in self._ssrf_gw_hosts
        try:
            from ..graph import store as gstore
            from ..scope_pivot import ssrf_gateway_hosts
            g = await gstore.get_graph(self.project_id)
            self._ssrf_gw_hosts = ssrf_gateway_hosts(g)
        except Exception:
            self._ssrf_gw_hosts = set()
        self._ssrf_gw_ts = now
        return h in self._ssrf_gw_hosts

    def mark_activity(self) -> None:
        import time as _t
        self.turn_activity_mono = _t.monotonic()

    async def run_command(self, command: str, timeout: int | None = None) -> CmdResult:
        self.cmd_inflight = int(getattr(self, "cmd_inflight", 0) or 0) + 1
        self.mark_activity()
        try:
            return await run_shell(
                command, cwd=self.workspace_dir, guard=self.guard, timeout=timeout,
            )
        finally:
            self.cmd_inflight = max(0, int(getattr(self, "cmd_inflight", 0) or 0) - 1)
            self.mark_activity()

    def _client(self) -> httpx.AsyncClient:
        if self._httpx_cli is None:
            self._httpx_cli = httpx.AsyncClient(
                follow_redirects=True,
                timeout=30.0,
                verify=False,
            )
        return self._httpx_cli  # type: ignore[return-value]

    async def http(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        data: str | None = None,
        **_kw,
    ) -> dict:
        blocked = self._http_blocked(url)
        if blocked:
            return {"blocked": True, "error": blocked, "status": 0}
        host = self.host_of(url)
        if host and await self._host_is_ssrf_gateway(host):
            return {
                "error": (
                    f"⛔ {host} 是经 SSRF 跳板扩入 Scope 的内网主机，攻击机网卡到不了"
                    f"（直连超时是预期，不是入口挂了）。请把 `{url}` 作为已验证 SSRF 入口的参数"
                    f"（保持 HTTP/HTTPS）转发，不要 http_request 直连该 IP。"
                ),
                "blocked": True,
                "ssrf_gateway": True,
                "status": 0,
            }
        hdrs = dict(headers or {})
        if self._cookies:
            cookie = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            if cookie:
                hdrs.setdefault("Cookie", cookie)
        try:
            resp = await self._client().request(method.upper(), url, headers=hdrs, content=data)
        except Exception as e:
            return {"error": str(e), "status": 0, "engine": "httpx"}
        for k, v in resp.cookies.items():
            self._cookies[str(k)] = str(v)
        body = ""
        try:
            body = resp.text
        except Exception:
            body = ""
        if len(body) > 24000:
            body = body[:24000] + "\n...[truncated]..."
        return {
            "status": resp.status_code,
            "headers": dict(list(resp.headers.items())[:40]),
            "body": body,
            "final_url": str(resp.url),
            "engine": "httpx",
        }
