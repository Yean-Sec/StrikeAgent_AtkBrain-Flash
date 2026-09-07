"""入口活探针：用短连接指纹分流 HTTP vs 非 HTTP 交互，不写死端口、不扫题面关键词。"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qsl, urlparse

_HTTP_HEAD_RE = re.compile(
    br"^(?:HTTP/\d(?:\.\d)?\s+\d{3}|[A-Z]{3,10}\s+\S+\s+HTTP/\d)",
    re.I,
)
_HTML_RE = re.compile(br"<(?:html|head|body|title|!doctype)\b", re.I)
_FILTER_RE = re.compile(
    br"(access\s+denied|request\s+blocked|forbidden|not\s+acceptable|"
    br"method\s+not\s+allowed|intercept|blocked\s+by)",
    re.I,
)
_FILTER_TEXT_RE = re.compile(
    r"(拦截|禁止访问|访问被拒绝|访问被阻止)",
)
_MENU_RE = re.compile(
    br"(?:^\s*[\[(]?\d[\])]\s+\S|^\s*\d+[.:)]\s+\S|>\s*$|:\s*$)",
    re.M,
)
_JWT_RE = re.compile(
    br"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*",
)
_GRAPHQL_RE = re.compile(
    br"(?:__schema\b|/graphql\b|application/graphql|\bgraphql\b)",
    re.I,
)
_SOAP_RE = re.compile(
    br"(?:soap:envelope|\bwsdl\b|xmlns:soap|text/xml[^\r\n]*soap)",
    re.I,
)
_XML_RE = re.compile(
    br"(?:application/xml|text/xml|<\?xml\b|<Envelope\b)",
    re.I,
)
_MULTIPART_RE = re.compile(
    br"(?:multipart/form-data|enctype=[\"']multipart|type=[\"']file[\"']|input[^\>]+type=[\"']file)",
    re.I,
)
_TEMPLATE_RE = re.compile(
    br"(?:jinja2\.exceptions|TemplateError|Twig_Error|UndefinedError|"
    br"freemarker|mako\.exceptions|django\.template|TemplateSyntaxError)",
    re.I,
)
_JSON_API_RE = re.compile(
    br"(?:application/json|openapi|swagger|/api/v\d)",
    re.I,
)
_BEARER_RE = re.compile(br"authorization:\s*bearer\s+eyJ", re.I)
_OBJECT_STORE_RE = re.compile(
    br"(?:ListAllMyBuckets(?:Result)?|ListBucketResult|NoSuchBucket|NoSuchKey|"
    br"InvalidBucketName|x-amz-request-id|x-amz-id-2|\bS3rver\b|\bMinIO\b|"
    br"xmlns=[\"']http://s3\.amazonaws\.com/doc/|AmazonS3)",
    re.I,
)
_PHP_SERIAL_RE = re.compile(
    br'(?:^|[^A-Za-z0-9_])(?:'
    br'O:\d+:"[A-Za-z_\\\\][A-Za-z0-9_\\\\]{0,80}":\d+:\{'
    br'|C:\d+:"[A-Za-z_\\\\][A-Za-z0-9_\\\\]{0,80}":\d+:\{'
    br'|a:\d+:\{'
    br')',
)
_EXPR_EVAL_RE = re.compile(
    br"(?:SyntaxError|Parse(?:Error|Exception)|Unexpected(?:\s+token|\s+EOF)|"
    br"invalid\s+(?:syntax|encoding|expression)|unknown\s+encoding|"
    br"Unicode(?:Encode|Decode)Error|eval\(\)|cannot\s+decode|"
    br"malformed\s+(?:encoding|expression)|unexpected\s+(?:character|end)|"
    br"ExpressionError|EncodeError|DecodeError)",
    re.I,
)
_HTML_SINK_RE = re.compile(
    br"<(?:html|head|body|div|span|p|script|textarea|pre|title)\b",
    re.I,
)
_WRITE_LOCK_HEADERS = frozenset({
    "etag", "if-match", "if-none-match", "lock-token", "x-content-lock",
})

HTTP_SURFACES = (
    "graphql", "soap", "jwt", "multipart", "object_store", "xml",
    "template_error", "json_api", "html_sink", "php_serial", "expr_eval",
    "race_window",
)
# 首页没打出表面时补探的契约入口。只走协议惯例路径，不写题号。
_CONTRACT_FAMILIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("graphql", ("/graphql", "/graphql/")),
    ("soap", ("/wsdl", "/?wsdl")),
    ("json_api", ("/openapi.json", "/swagger.json")),
)
_HTTP_BODY_LIMIT = 4096
_PRINTABLE_RATIO = 0.75


def contract_paths_for(tags: list[str] | None) -> list[str]:
    """已打上的表面不再重复探。"""
    have = {str(t).strip().lower() for t in (tags or []) if t}
    out: list[str] = []
    seen: set[str] = set()
    for name, paths in _CONTRACT_FAMILIES:
        if name in have:
            continue
        for p in paths:
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _http_status(raw: bytes | None) -> int | None:
    m = re.match(br"HTTP/\d(?:\.\d)?\s+(\d{3})", (raw or b"").lstrip(), re.I)
    if not m:
        return None
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return None


def contract_response_usable(raw: bytes | None) -> bool:
    """404 / 3xx 经常把路径名回显进错误页，不能当表面证据。"""
    st = _http_status(raw)
    if st is None:
        return bool(raw)
    if st == 404 or 300 <= st < 400:
        return False
    return True


def merge_surface_tags(*groups: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for t in group or []:
            name = str(t).strip().lower()
            if not name or name not in HTTP_SURFACES or name in seen:
                continue
            seen.add(name)
            out.append(name)
    if "object_store" in seen and "xml" in seen:
        out = [x for x in out if x != "xml"]
    return out


def _header_names(headers: dict | None) -> set[str]:
    if not isinstance(headers, dict):
        return set()
    return {str(k).strip().lower() for k in headers if k}


def _request_values(url: str | None, form: str | None) -> list[str]:
    vals: list[str] = []
    seen: set[str] = set()

    def _add(v: str) -> None:
        s = (v or "").strip()
        if len(s) < 3 or s.lower() in seen:
            return
        if s.lower() in {"true", "false", "null", "http", "https", "html", "utf-8"}:
            return
        seen.add(s.lower())
        vals.append(s)

    if url:
        parsed = urlparse(str(url))
        for _k, v in parse_qsl(parsed.query, keep_blank_values=False):
            _add(v)
    if form and "=" in str(form):
        for _k, v in parse_qsl(str(form), keep_blank_values=False):
            _add(v)
    return vals


def _html_reflects(raw: bytes, values: list[str]) -> bool:
    if not values or not _HTML_SINK_RE.search(raw[:4096]):
        return False
    try:
        text = raw[:4096].decode("utf-8", "ignore")
    except Exception:
        return False
    return any(v in text for v in values)


def classify_http_surface(
    data: bytes | None,
    *,
    headers: dict | None = None,
    url: str | None = None,
    method: str | None = None,
    status: int | None = None,
    form: str | None = None,
) -> list[str]:
    """从活体 HTTP 字节/头打表面标签。不看题名、不写 payload。"""
    raw = data or b""
    hdr_blob = b""
    if headers:
        parts = []
        for k, v in headers.items():
            parts.append(f"{k}: {v}")
        hdr_blob = "\n".join(parts).encode("utf-8", "ignore")
    blob = hdr_blob + b"\n" + raw[:4096]
    out: list[str] = []

    def _add(tag: str) -> None:
        if tag not in out:
            out.append(tag)

    if _GRAPHQL_RE.search(blob):
        _add("graphql")
    if _SOAP_RE.search(blob):
        _add("soap")
    if _JWT_RE.search(blob) or _BEARER_RE.search(blob):
        _add("jwt")
    if _MULTIPART_RE.search(blob):
        _add("multipart")
    if _OBJECT_STORE_RE.search(blob):
        _add("object_store")
    if _XML_RE.search(blob) and "object_store" not in out:
        _add("xml")
    if _TEMPLATE_RE.search(blob):
        _add("template_error")
    if _JSON_API_RE.search(blob) and "graphql" not in out:
        _add("json_api")
    if _PHP_SERIAL_RE.search(blob):
        _add("php_serial")
    if _EXPR_EVAL_RE.search(blob):
        _add("expr_eval")
    if _html_reflects(raw[:4096], _request_values(url, form)):
        _add("html_sink")
    meth = str(method or "").strip().upper()
    st = status if status is not None else _http_status(raw)
    try:
        st_i = int(st) if st is not None else None
    except (TypeError, ValueError):
        st_i = None
    if (
        meth in {"PUT", "PATCH"}
        and st_i is not None
        and 200 <= st_i < 300
        and not (_header_names(headers) & _WRITE_LOCK_HEADERS)
    ):
        _add("race_window")
    return out


def surfaces_from_http_result(res: dict | None) -> list[str]:
    """从 http_request 结果打表面标签。正文或头任一命中即可。"""
    if not isinstance(res, dict):
        return []
    body = res.get("body")
    if body is None:
        desk = res.get("desktop") if isinstance(res.get("desktop"), dict) else {}
        body = desk.get("body") if isinstance(desk, dict) else None
    if isinstance(body, str):
        raw = body.encode("utf-8", "ignore")
    elif isinstance(body, (bytes, bytearray)):
        raw = bytes(body)
    else:
        raw = b""
    headers = res.get("headers")
    if not isinstance(headers, dict):
        desk = res.get("desktop") if isinstance(res.get("desktop"), dict) else {}
        headers = desk.get("headers") if isinstance(desk, dict) else None
    if not isinstance(headers, dict):
        headers = None
    url = res.get("url") or res.get("final_url")
    if not isinstance(url, str):
        url = None
    method = res.get("method")
    if not isinstance(method, str):
        method = None
    status = res.get("status")
    if status is None:
        desk = res.get("desktop") if isinstance(res.get("desktop"), dict) else {}
        status = desk.get("status") if isinstance(desk, dict) else None
    form = res.get("data")
    if not isinstance(form, str):
        form = None
    return classify_http_surface(
        raw[:4096], headers=headers, url=url, method=method, status=status, form=form,
    )


def _split_hostport(addr: str) -> tuple[str, int | None]:
    a = (addr or "").strip()
    if "://" in a:
        a = a.split("://", 1)[1]
    a = a.split("/")[0]
    if a.count(":") == 1:
        h, p = a.split(":")
        if p.isdigit():
            return h.lower(), int(p)
    return a.lower(), None


def _looks_filtered(raw: bytes) -> bool:
    if _FILTER_RE.search(raw):
        return True
    try:
        text = raw.decode("utf-8", "ignore")
    except Exception:
        text = ""
    return bool(text and _FILTER_TEXT_RE.search(text))


def classify_banner(data: bytes | None, *, http_status: int | None = None) -> str:
    """把一次短读分成 http / filter / interactive / unknown。不看端口号。"""
    raw = data or b""
    if http_status is not None and 100 <= int(http_status) <= 599:
        if int(http_status) in (403, 406, 501) or (
            int(http_status) == 400 and _looks_filtered(raw)
        ):
            return "filter"
        if int(http_status) == 403:
            return "filter"
        return "http"
    if not raw:
        return "unknown"
    head = raw.lstrip()[:24]
    if _HTTP_HEAD_RE.match(head) or _HTML_RE.search(raw[:800]):
        m = re.match(br"HTTP/\d(?:\.\d)?\s+(\d{3})", raw.lstrip(), re.I)
        if m:
            try:
                st = int(m.group(1))
            except (TypeError, ValueError):
                st = 0
            if st == 403 or (st in (400, 406, 501) and _looks_filtered(raw)):
                return "filter"
        if _looks_filtered(raw) and not _HTML_RE.search(raw[:400]):
            return "filter"
        return "http"
    sample = raw[:400]
    nul = sample.count(b"\x00")
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = (printable / len(sample)) if sample else 0.0
    if nul > 2 or ratio < _PRINTABLE_RATIO:
        return "interactive"
    if _MENU_RE.search(sample) or ratio >= _PRINTABLE_RATIO:
        return "interactive"
    return "unknown"


def kind_from_fingerprints(fps: dict[str, str] | None) -> str:
    kinds = [str(v or "").strip().lower() for v in (fps or {}).values() if v]
    if any(k == "interactive" for k in kinds):
        if any(k in ("http", "filter") for k in kinds):
            return "mixed"
        return "interactive"
    if any(k == "filter" for k in kinds):
        return "filter"
    if any(k == "http" for k in kinds):
        return "http"
    return "unknown"


def pick_focus_addr(addrs: list[str], fps: dict[str, str] | None) -> str:
    """同题多入口时先打非 HTTP 交互口；全是 HTTP 则保持原顺序。"""
    ordered = [str(a).strip() for a in addrs or [] if str(a).strip()]
    if not ordered:
        return ""
    fp = {str(k).strip().lower(): str(v or "").strip().lower() for k, v in (fps or {}).items()}
    for want in ("interactive", "filter", "http", "unknown"):
        for a in ordered:
            if fp.get(a.lower()) == want:
                return a
    return ordered[0]


async def _read_limited(reader, n: int, timeout: float) -> bytes:
    """在 timeout 内最多读 n 字节；HTTP 有 Content-Length 且已收齐则提前停。"""
    want = max(0, int(n or 0))
    if want <= 0 or reader is None:
        return b""
    buf = bytearray()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.05, float(timeout or 0))
    while len(buf) < want:
        remain = deadline - loop.time()
        if remain <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(2048, want - len(buf))), remain,
            )
        except (asyncio.TimeoutError, Exception):
            break
        if not chunk:
            break
        buf.extend(chunk)
        if not buf.startswith(b"HTTP/"):
            continue
        if b"\r\n\r\n" not in buf:
            continue
        head, _, body = bytes(buf).partition(b"\r\n\r\n")
        m = re.search(br"content-length:\s*(\d+)", head, re.I)
        if m:
            try:
                need = int(m.group(1))
            except (TypeError, ValueError):
                need = 0
            if need >= 0 and len(body) >= min(need, want - len(head) - 4):
                break
    return bytes(buf)


async def peek_http_path(
    host: str, port: int, path: str = "/", *, timeout: float = 0.8, limit: int = 2048,
) -> bytes:
    """对单一路径发 HTTP/1.0 GET，读一小段就关。"""
    h = (host or "").strip()
    if not h or not port:
        return b""
    raw_path = str(path or "/").strip() or "/"
    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path
    req = f"GET {raw_path} HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n".encode()
    reader = None
    writer = None
    try:
        conn = asyncio.open_connection(h, int(port))
        reader, writer = await asyncio.wait_for(conn, timeout)
        writer.write(req)
        await writer.drain()
        return await _read_limited(reader, int(limit or 2048), max(0.2, float(timeout or 0)))
    except Exception:
        return b""
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def peek_tcp(host: str, port: int, *, timeout: float = 2.0) -> bytes:
    """短连：先等 banner，没有再发一行 HTTP GET，读到约 4KB 就关。"""
    h = (host or "").strip()
    if not h or not port:
        return b""
    reader = None
    writer = None
    try:
        conn = asyncio.open_connection(h, int(port))
        reader, writer = await asyncio.wait_for(conn, timeout)
        try:
            chunk = await _read_limited(reader, 256, 0.4)
        except Exception:
            chunk = b""
        head = (chunk or b"").lstrip()[:24]
        looks_http = bool(_HTTP_HEAD_RE.match(head) or _HTML_RE.search((chunk or b"")[:200]))
        if chunk and not looks_http:
            return chunk
        if not chunk:
            writer.write(b"GET / HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n")
            await writer.drain()
        rest_timeout = max(0.6, float(timeout or 0) - 0.5)
        rest = await _read_limited(
            reader, _HTTP_BODY_LIMIT - len(chunk or b""), rest_timeout,
        )
        return ((chunk or b"") + (rest or b""))[:_HTTP_BODY_LIMIT]
    except Exception:
        return b""
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


async def probe_http_contracts(
    host: str, port: int, *, tags: list[str] | None = None, timeout: float = 0.8,
) -> list[str]:
    """首页没打出 GraphQL/SOAP/OpenAPI 时，并探惯例契约路径。"""
    paths = contract_paths_for(tags)
    if not paths:
        return []
    got = await asyncio.gather(
        *[peek_http_path(host, port, p, timeout=timeout) for p in paths],
        return_exceptions=True,
    )
    extra: list[str] = []
    for raw in got:
        if isinstance(raw, bytes) and contract_response_usable(raw):
            extra.extend(classify_http_surface(raw))
    return merge_surface_tags(extra)


async def fingerprint_addrs(addrs: list[str], *, timeout: float = 2.0) -> dict[str, str]:
    fps, _surfaces = await fingerprint_entry(addrs, timeout=timeout)
    return fps


async def fingerprint_entry(
    addrs: list[str], *, timeout: float = 2.0,
) -> tuple[dict[str, str], dict[str, list[str]]]:
    """同时返回入口形态（http/interactive/…）与 HTTP 表面标签。"""
    fps: dict[str, str] = {}
    surfaces: dict[str, list[str]] = {}
    for raw in addrs or []:
        addr = str(raw or "").strip()
        if not addr:
            continue
        host, port = _split_hostport(addr)
        if not host:
            continue
        data = await peek_tcp(host, int(port or 80), timeout=timeout)
        fps[addr] = classify_banner(data)
        tags = classify_http_surface(data)
        if fps[addr] in ("http", "filter"):
            extra = await probe_http_contracts(
                host, int(port or 80), tags=tags, timeout=min(0.8, timeout),
            )
            tags = merge_surface_tags(tags, extra)
        if tags:
            surfaces[addr] = tags
    return fps, surfaces


def fingerprints_from_project(project: dict | None) -> dict[str, str]:
    cfg = (project or {}).get("config") or {}
    raw = ((cfg.get("benchmark") or {}).get("entry_fp") or cfg.get("entry_fp") or {})
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if k}


def surfaces_from_project(project: dict | None, *, per_addr: bool = False):
    """读 config.benchmark.entry_surface。默认扁平去重列表；per_addr 时返回 addr→tags。"""
    cfg = (project or {}).get("config") or {}
    raw = (cfg.get("benchmark") or {}).get("entry_surface") or cfg.get("entry_surface") or {}
    per: dict[str, list[str]] = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            tags: list[str] = []
            if isinstance(v, (list, tuple, set)):
                tags = [str(x).strip() for x in v if str(x).strip()]
            elif v:
                tags = [str(v).strip()]
            if tags:
                per[str(k)] = tags
    elif isinstance(raw, (list, tuple)):
        flat = [str(x).strip() for x in raw if str(x).strip()]
        if flat:
            per["*"] = flat
    if per_addr:
        return per
    out: list[str] = []
    seen: set[str] = set()
    for tags in per.values():
        for t in tags:
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def apply_fingerprints(project: dict | None, fps: dict[str, str]) -> dict:
    """写回 config.benchmark.entry_fp；返回更新后的 project 浅拷贝。"""
    proj = dict(project or {})
    cfg = dict(proj.get("config") or {})
    bm = dict(cfg.get("benchmark") or {})
    bm["entry_fp"] = dict(fps or {})
    cfg["benchmark"] = bm
    proj["config"] = cfg
    return proj


def project_entry_addrs(project: dict | None) -> list[str]:
    """本题全部入口 host:port（container_addr + target/ports），保序去重。"""
    seen: set[str] = set()
    out: list[str] = []

    def _add(host: str, port: int | None) -> None:
        h = (host or "").strip().lower().split("/")[0]
        if not h:
            return
        if port and 1 <= int(port) <= 65535:
            key = f"{h}:{int(port)}"
        else:
            key = h
        if key in seen:
            return
        seen.add(key)
        out.append(key)

    cfg = (project or {}).get("config") or {}
    for a in ((cfg.get("benchmark") or {}).get("container_addr") or []):
        h, p = _split_hostport(str(a or ""))
        _add(h, p)
    tgt = str((project or {}).get("target") or "").strip()
    th, tp = _split_hostport(tgt) if tgt else ("", None)
    ports: list[int] = []
    raw_ports = (project or {}).get("ports") or []
    for p in raw_ports:
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= n <= 65535 and n not in ports:
            ports.append(n)
    if th:
        if tp:
            _add(th, tp)
        for n in ports:
            _add(th, n)
        if not tp and not ports:
            _add(th, None)
    return out


def project_entry_hosts(project: dict | None) -> set[str]:
    hosts: set[str] = set()
    for a in project_entry_addrs(project):
        hosts.add(a.split(":")[0].lower())
    return hosts


def subtract_own_entries(peer_addrs: set[str], own_addrs: set[str] | list[str]) -> set[str]:
    """邻题入口里去掉本题自己的 host:port。"""
    own = {str(a).strip().lower() for a in (own_addrs or ()) if a}
    out: set[str] = set()
    for a in peer_addrs or ():
        key = str(a).strip().lower()
        if not key or key in own:
            continue
        out.add(key)
    return out


def subtract_own_hosts(peer_hosts: set[str], own_hosts: set[str]) -> set[str]:
    own = {str(h).strip().lower().split(":")[0] for h in (own_hosts or ()) if h}
    out: set[str] = set()
    for h in peer_hosts or ():
        key = str(h).strip().lower().split(":")[0]
        if not key or key in own:
            continue
        out.add(key)
    return out
