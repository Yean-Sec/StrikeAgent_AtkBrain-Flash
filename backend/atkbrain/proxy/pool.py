"""红队/SRC 出口代理：pyfreeproxy 白名单源 + 自建池，后台探活。"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config import settings
from ..objective import FLAG, normalize_objective

IP_ECHO_URLS = (
    "https://ipv4.icanhazip.com",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "http://ip.sb",
)
# 经代理探活先走 HTTP 回显：免费 HTTP 代理多数没有 HTTPS CONNECT，只用 icanhazip 会把能用的判死。
PROXY_ECHO_URLS = (
    "http://ip.sb",
    "http://ifconfig.me/ip",
    "https://ipv4.icanhazip.com",
)
MAX_LIVE = 120
CHECK_TIMEOUT = 4.0
SOURCE_CAP = 240
PROBE_CAP = 1000
LOOP_PAUSE_SEC = 8.0
FIRST_WAVE = 12

# 不跑 DrissionPage / 下 Chrome 的源。Proxifly 走 all/data.json，避免按国抓 80 份。
SAFE_SOURCES = (
    "TheSpeedXProxiedSession",
    "OpenProxyListProxiedSession",
)

FALLBACK_LISTS = (
    ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
    ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
    ("http", "https://api.openproxylist.xyz/http.txt"),
    ("socks5", "https://api.openproxylist.xyz/socks5.txt"),
)
PROXIFLY_ALL = "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.json"
SOURCE_TIMEOUT_SEC = 18.0
_SCRAPE_EX = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pxscrape")
# README 里要 DrissionPage/Chrome 的源不跑；其余按 pyfreeproxy 注册表动态全开。
SKIP_SOURCES = frozenset({"IP3366ProxiedSession"})

_LINE_URL = re.compile(
    r"^(https?|socks4|socks5)://[^\s]+$",
    re.I,
)
_LINE_HOSTPORT = re.compile(
    r"^(?:\S+@)?((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+):(\d{2,5})$",
    re.I,
)


_BAD_HOSTS = {"0.0.0.0", "127.0.0.1", "localhost", "::1"}
_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def proxy_allowed_for_objective(obj: str | None) -> bool:
    """CTF 永不走代理；红队与 SRC 可以。"""
    return normalize_objective(obj) != FLAG


def parse_proxy_line(line: str) -> str | None:
    raw = (line or "").strip()
    if not raw or raw.startswith("#"):
        return None
    url = raw if _LINE_URL.match(raw) else None
    if url is None:
        m = _LINE_HOSTPORT.match(raw)
        if m:
            url = f"http://{raw}"
    if not url:
        return None
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if not host or host in _BAD_HOSTS:
        return None
    return url


def _settings_path() -> Path:
    return Path(settings.data_dir) / "proxy-settings.json"


@dataclass
class LiveProxy:
    url: str
    exit_ip: str = ""
    proto: str = "http"
    checked_at: float = 0.0
    https_ok: bool = False


@dataclass
class ProxyPool:
    enabled: bool = True
    custom_text: str = ""
    live: list[LiveProxy] = field(default_factory=list)
    fetching: bool = False
    exit_ip: str | None = None
    error: str | None = None
    _task: asyncio.Task | None = field(default=None, repr=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _direct_ip: str | None = field(default=None, repr=False)

    def snapshot(self) -> dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "live": len(self.live),
            "fetching": bool(self.enabled and self.fetching),
            "exit_ip": self.exit_ip,
            "error": self.error,
            "custom_count": len(self._custom_urls()),
            "custom_text": self.custom_text,
        }

    def load(self) -> None:
        p = _settings_path()
        if not p.is_file():
            return
        try:
            data = json.loads(p.read_text(encoding="utf-8") or "{}")
        except Exception:
            return
        if not isinstance(data, dict):
            return
        self.enabled = bool(data.get("enabled"))
        self.custom_text = str(data.get("custom_text") or "")

    def save(self) -> None:
        p = _settings_path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(
                    {"enabled": bool(self.enabled), "custom_text": self.custom_text},
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    def _custom_urls(self) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for line in (self.custom_text or "").splitlines():
            u = parse_proxy_line(line)
            if u and u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def pick(self) -> str | None:
        if not self.enabled or not self.live:
            return None
        https_ok = [i for i in self.live if i.https_ok]
        if https_ok:
            return random.choice(https_ok).url
        httpish = [i for i in self.live if (i.proto or "").startswith("http")]
        return random.choice(httpish or self.live).url

    def must_proxy(self, obj: str | None) -> bool:
        """红队/SRC 且开关开：必须走代理，禁止回落直连。"""
        return bool(self.enabled and proxy_allowed_for_objective(obj))

    def should_proxy(self, obj: str | None) -> bool:
        return bool(self.must_proxy(obj) and self.live)

    def proxy_env(self, url: str | None = None) -> dict[str, str] | None:
        px = url or self.pick()
        if not px:
            return None
        # curl 认 socks5h（远端解析 DNS）；httpx 走 http_request 仍用原 URL
        cmd_px = px
        if px.lower().startswith("socks5://"):
            cmd_px = "socks5h://" + px.split("://", 1)[1]
        return {
            "http_proxy": cmd_px, "https_proxy": cmd_px,
            "HTTP_PROXY": cmd_px, "HTTPS_PROXY": cmd_px,
            "ALL_PROXY": cmd_px, "all_proxy": cmd_px,
            "no_proxy": "127.0.0.1,localhost,::1",
            "NO_PROXY": "127.0.0.1,localhost,::1",
        }

    async def wait_pick(self, timeout: float = 8.0) -> str | None:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            px = self.pick()
            if px:
                return px
            if time.monotonic() >= deadline:
                return None
            self.ensure_loop()
            await asyncio.sleep(0.4)

    async def set_enabled(self, on: bool) -> dict[str, Any]:
        self.enabled = bool(on)
        self.fetching = bool(on)
        if not self.enabled:
            self.fetching = False
        self.save()
        self.ensure_loop()
        return self.snapshot()

    async def set_custom_text(self, text: str) -> dict[str, Any]:
        self.custom_text = str(text or "")
        self.save()
        if self.enabled:
            await self._probe_urls(self._custom_urls(), keep_existing=True)
        return self.snapshot()

    def ensure_loop(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._task is None or self._task.done():
            self._task = loop.create_task(self._run_loop())

    async def _run_loop(self) -> None:
        print("[proxy] 出口代理池后台循环已启动", flush=True)
        while True:
            try:
                if not self.enabled:
                    self.fetching = False
                    await asyncio.sleep(LOOP_PAUSE_SEC)
                    continue
                self.fetching = True
                await self._refresh_once()
            except asyncio.CancelledError:
                self.fetching = False
                raise
            except Exception as e:
                self.error = str(e)[:240]
                print(f"[proxy] 刷新失败: {self.error}", flush=True)
            await asyncio.sleep(LOOP_PAUSE_SEC)

    async def _refresh_once(self) -> None:
        self._direct_ip = await _probe_exit(None)
        custom = self._custom_urls()
        if custom:
            await self._probe_urls(custom, keep_existing=True, stop_at=MAX_LIVE)

        pending = {
            asyncio.create_task(_fetch_one_list(proto, url), name=f"pxlist-{proto}")
            for proto, url in FALLBACK_LISTS
        }
        deadline = time.monotonic() + 22.0
        while pending and time.monotonic() < deadline:
            done, pending = await asyncio.wait(
                pending,
                timeout=max(0.05, deadline - time.monotonic()),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                break
            for fut in done:
                urls = _task_urls(fut)
                if not urls:
                    continue
                stop = FIRST_WAVE if len(self.live) < FIRST_WAVE else MAX_LIVE
                await self._probe_urls(urls, keep_existing=True, stop_at=stop)
        for fut in pending:
            fut.cancel()

        if len(self.live) < MAX_LIVE:
            extra: list[str] = []
            try:
                extra = await asyncio.wait_for(_fetch_proxifly_json(), timeout=12.0)
            except Exception:
                extra = []
            if extra:
                await self._probe_urls(extra, keep_existing=True, stop_at=MAX_LIVE)

        if len(self.live) < MAX_LIVE:
            await self._ingest_freeproxy()

        await self._recheck_live()
        if not self.live:
            self.error = "公开源暂无存活节点。免费列表多数已死，可在设置页粘贴自建代理。"
            print("[proxy] 本轮 0 存活", flush=True)
        else:
            print(f"[proxy] 本轮存活 {len(self.live)} 出口 {self.exit_ip}", flush=True)

    async def _ingest_freeproxy(self) -> None:
        """CharlesPikachu/freeproxy README 里的源（除 Chrome）先收齐再混着探。"""
        sources = _all_safe_sources()
        if not sources:
            return
        print(f"[proxy] 拉取 freeproxy 源 {len(sources)} 个", flush=True)
        loop = asyncio.get_running_loop()
        ex = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pxsrc")
        bag: list[str] = []
        seen: set[str] = set()
        try:
            pending = {loop.run_in_executor(ex, _one_freeproxy_source, src) for src in sources}
            deadline = time.monotonic() + 32.0
            while pending and time.monotonic() < deadline:
                done, pending = await asyncio.wait(
                    pending,
                    timeout=max(0.05, deadline - time.monotonic()),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    break
                for fut in done:
                    for u in _task_urls(fut):
                        if u and u not in seen:
                            seen.add(u)
                            bag.append(u)
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        print(f"[proxy] freeproxy 候选 {len(bag)} 条，开始探活", flush=True)
        if bag:
            await self._probe_urls(bag, keep_existing=True, stop_at=MAX_LIVE)

    async def _recheck_live(self) -> None:
        now = time.time()
        stale = [i for i in self.live if now - i.checked_at > 90]
        if not stale:
            return
        sem = asyncio.Semaphore(16)

        async def one(item: LiveProxy) -> LiveProxy | None:
            async with sem:
                fresh = await _probe_proxy(item.url, direct=self._direct_ip)
            return fresh

        kept_stale = {
            x.url: x for x in await asyncio.gather(*(one(i) for i in stale)) if x
        }
        stale_urls = {s.url for s in stale}
        async with self._lock:
            nxt: list[LiveProxy] = []
            for item in self.live:
                if item.url in stale_urls:
                    fresh = kept_stale.get(item.url)
                    if fresh:
                        nxt.append(fresh)
                else:
                    nxt.append(item)
            self.live = nxt[:MAX_LIVE]
            if self.live:
                self.exit_ip = self.live[0].exit_ip
                self.error = None

    async def _probe_urls(
        self, urls: list[str], *, keep_existing: bool, stop_at: int | None = None,
    ) -> None:
        if not urls:
            return
        have = {i.url for i in self.live}
        httpish: list[str] = []
        socks: list[str] = []
        for u in urls:
            if not u or u in have:
                continue
            if (urlparse(u).scheme or "http").lower().startswith("http"):
                httpish.append(u)
            else:
                socks.append(u)
        random.shuffle(httpish)
        random.shuffle(socks)
        target = stop_at or MAX_LIVE
        todo = (httpish + socks)[:PROBE_CAP]
        if not todo:
            return
        sem = asyncio.Semaphore(40)
        hits = 0
        tried = 0

        async def one(url: str) -> LiveProxy | None:
            nonlocal tried
            if len(self.live) >= target:
                return None
            async with sem:
                if len(self.live) >= target:
                    return None
                tried += 1
                item = await _probe_proxy(url, direct=self._direct_ip)
            return item

        batch = 40
        for i in range(0, len(todo), batch):
            if len(self.live) >= target:
                break
            chunk = todo[i:i + batch]
            tasks = [asyncio.create_task(one(u)) for u in chunk]
            for fut in asyncio.as_completed(tasks):
                try:
                    item = await fut
                except Exception:
                    item = None
                if not item:
                    continue
                hits += 1
                async with self._lock:
                    seen = {j.url for j in self.live}
                    if item.url not in seen:
                        self.live.append(item)
                    self.live = self.live[:MAX_LIVE]
                    if self.live:
                        self.exit_ip = self.live[0].exit_ip
                        self.error = None
                if len(self.live) >= target:
                    break
            if len(self.live) >= target:
                for t in tasks:
                    if not t.done():
                        t.cancel()
        print(f"[proxy] 探活 {tried}/{len(todo)} 命中 {hits} 池内 {len(self.live)}", flush=True)

    async def verify(self) -> dict[str, Any]:
        direct = await _probe_exit(None)

        async def try_one(url: str | None) -> tuple[str | None, str | None]:
            if not url:
                return None, None
            ip = await _probe_exit(url, direct=direct)
            if ip and (not direct or ip != direct):
                return url, ip
            return url, None

        used: str | None = None
        via: str | None = None
        seen: set[str] = set()
        http_first = [i for i in list(self.live) if (i.proto or "").startswith("http")]
        other = [i for i in list(self.live) if i not in http_first]
        for item in http_first + other:
            if item.url in seen:
                continue
            seen.add(item.url)
            used, via = await try_one(item.url)
            if via:
                break
        if not via:
            try:
                scraped = list(self._custom_urls()) + await asyncio.wait_for(
                    _fetch_fallback_lists(), timeout=16.0,
                )
            except Exception:
                scraped = list(self._custom_urls())
            random.shuffle(scraped)
            deadline = time.monotonic() + 35
            for i in range(0, min(len(scraped), 48), 16):
                if time.monotonic() > deadline:
                    break
                await self._probe_urls(scraped[i:i + 16], keep_existing=True, stop_at=FIRST_WAVE)
                for item in list(self.live):
                    if item.url in seen:
                        continue
                    seen.add(item.url)
                    used, via = await try_one(item.url)
                    if via:
                        break
                if via:
                    break
        ok = bool(direct and via and direct != via)
        if via:
            self.exit_ip = via
        return {
            "direct_ip": direct,
            "proxy_ip": via,
            "proxy": used,
            "ok": ok,
            "live": len(self.live),
            "message": (
                "出口已换成代理池 IP"
                if ok
                else ("没有可用代理" if not via else "经代理出口与直连相同")
            ),
        }


def _run_scrape(fn, *args):
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(_SCRAPE_EX, fn, *args)


def _task_urls(fut: asyncio.Future) -> list[str]:
    try:
        val = fut.result()
    except Exception:
        return []
    return [u for u in (val or []) if u]


def _direct_transport(*, async_client: bool) -> Any:
    if async_client:
        return httpx.AsyncHTTPTransport(local_address="0.0.0.0", retries=0)
    return httpx.HTTPTransport(local_address="0.0.0.0", retries=0)


def _row_to_url(row: Any) -> str | None:
    u = ""
    try:
        u = str(getattr(row, "proxy", None) or "").strip()
    except Exception:
        u = ""
    if isinstance(row, dict):
        u = u or str(row.get("proxy") or "").strip()
        if not u:
            proto = str(row.get("protocol") or row.get("proto") or "http").lower()
            ip = str(row.get("ip") or "")
            port = str(row.get("port") or "")
            if ip and port:
                u = f"{proto}://{ip}:{port}"
    return parse_proxy_line(u) if u else None


def _all_safe_sources() -> list[str]:
    try:
        from freeproxy.modules.proxies import ProxiedSessionBuilder
        names = [
            n for n in ProxiedSessionBuilder.REGISTERED_MODULES
            if n not in SKIP_SOURCES
        ]
        if names:
            return names
    except Exception:
        pass
    return list(SAFE_SOURCES)


def _install_scrape_patches() -> None:
    try:
        from freeproxy.modules.utils import IPLocater
        IPLocater.locate = staticmethod(lambda _ip: "")
    except Exception:
        pass


def _one_freeproxy_source(src: str) -> list[str]:
    _install_scrape_patches()
    from freeproxy.modules import BuildProxiedSession
    sess = BuildProxiedSession({
        "max_pages": 1,
        "type": src,
        "disable_print": True,
        "filter_rule": {},
        "trust_env": False,
    })
    orig = sess.request

    def _req(method, url, **kw):
        kw.setdefault("timeout", 8)
        return orig(method, url, **kw)

    sess.request = _req  # type: ignore[method-assign]
    try:
        rows = sess.refreshproxies() or []
    except Exception as e:
        print(f"[proxy] {src} 失败: {e}"[:200], flush=True)
        return []
    found: list[str] = []
    for row in rows:
        parsed = _row_to_url(row)
        if parsed:
            found.append(parsed)
        if len(found) >= SOURCE_CAP:
            break
    print(f"[proxy] {src} -> {len(found)} 条", flush=True)
    return found


def _scrape_freeproxy() -> list[str]:
    _install_scrape_patches()
    sources = _all_safe_sources()
    found: list[str] = []
    ex = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pxsrc")
    try:
        futs = [ex.submit(_one_freeproxy_source, src) for src in sources]
        done, _pending = wait(futs, timeout=SOURCE_TIMEOUT_SEC)
        for fut in done:
            try:
                found.extend(fut.result() or [])
            except Exception:
                continue
    except Exception:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return found


def _parse_list_text(proto: str, text: str) -> list[str]:
    out: list[str] = []
    for line in (text or "").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        parsed = parse_proxy_line(raw if "://" in raw else f"{proto}://{raw}")
        if parsed:
            out.append(parsed)
        if len(out) >= SOURCE_CAP:
            break
    return out


async def _fetch_one_list(proto: str, url: str) -> list[str]:
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
            trust_env=False,
            transport=_direct_transport(async_client=True),
            headers={"User-Agent": "StrikeAgent-AtkBrain-Flash/proxy-check"},
        ) as cli:
            r = await asyncio.wait_for(cli.get(url), timeout=12.0)
            if r.status_code != 200:
                return []
            return _parse_list_text(proto, r.text or "")
    except Exception:
        return []


async def _fetch_fallback_lists() -> list[str]:
    chunks = await asyncio.gather(
        *(_fetch_one_list(proto, url) for proto, url in FALLBACK_LISTS),
        return_exceptions=True,
    )
    out: list[str] = []
    seen: set[str] = set()
    for chunk in chunks:
        if not isinstance(chunk, list):
            continue
        for u in chunk:
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


async def _fetch_proxifly_json() -> list[str]:
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
            trust_env=False,
            transport=_direct_transport(async_client=True),
            headers={"User-Agent": "StrikeAgent-AtkBrain-Flash/proxy-check"},
        ) as cli:
            r = await asyncio.wait_for(cli.get(PROXIFLY_ALL), timeout=12.0)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []
    rows = data if isinstance(data, list) else []
    out: list[str] = []
    for item in rows:
        parsed = _row_to_url(item)
        if parsed:
            out.append(parsed)
        if len(out) >= SOURCE_CAP * 2:
            break
    return out


async def _probe_exit(proxy_url: str | None, *, direct: str | None = None) -> str | None:
    item = await _probe_proxy(proxy_url, direct=direct) if proxy_url else await _probe_proxy(None, direct=None)
    return item.exit_ip if item else None


async def _probe_proxy(proxy_url: str | None, *, direct: str | None) -> LiveProxy | None:
    async def _echo(cli: httpx.AsyncClient, url: str) -> str | None:
        r = await cli.get(url)
        raw = (r.text or "").strip()
        text = raw.splitlines()[0].strip() if raw else ""
        m = _IPV4_RE.fullmatch(text) or _IPV4_RE.search(text)
        if not m:
            return None
        ip = m.group(1)
        if not _ok_exit_ip(ip, direct if proxy_url else None):
            return None
        return ip

    async def _run() -> LiveProxy | None:
        kw: dict[str, Any] = {
            "timeout": httpx.Timeout(CHECK_TIMEOUT, connect=2.0, pool=2.0),
            "follow_redirects": True,
            "verify": False,
            "trust_env": False,
            "headers": {"User-Agent": "StrikeAgent-AtkBrain-Flash/proxy-check"},
        }
        if proxy_url:
            kw["proxy"] = proxy_url
        else:
            kw["transport"] = _direct_transport(async_client=True)
        echoes = IP_ECHO_URLS if not proxy_url else PROXY_ECHO_URLS
        exit_ip: str | None = None
        https_ok = False
        async with httpx.AsyncClient(**kw) as cli:
            for url in echoes:
                try:
                    ip = await _echo(cli, url)
                except Exception:
                    ip = None
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://"):
                    https_ok = True
                break
            if exit_ip and proxy_url and not https_ok:
                try:
                    hip = await asyncio.wait_for(_echo(cli, "https://ipv4.icanhazip.com"), timeout=2.0)
                    if hip:
                        exit_ip = hip
                        https_ok = True
                except Exception:
                    pass
        if not exit_ip:
            return None
        proto = (urlparse(proxy_url).scheme or "http").lower() if proxy_url else "direct"
        return LiveProxy(
            url=proxy_url or "",
            exit_ip=exit_ip,
            proto=proto,
            checked_at=time.time(),
            https_ok=https_ok,
        )

    try:
        return await asyncio.wait_for(_run(), timeout=CHECK_TIMEOUT + 2.5)
    except Exception:
        return None


def _ok_exit_ip(ip: str, direct: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    if addr.version != 4:
        return False
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return False
    if direct and ip == direct:
        return False
    return True


pool = ProxyPool()
pool.load()
