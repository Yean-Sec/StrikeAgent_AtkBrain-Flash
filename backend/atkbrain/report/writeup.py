"""漏洞详报：从真实 PoC/证据生成复现步骤，可选 AI 写成因与危害（禁止编造）。"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from ..config import settings
from ..graph.model import display_finding_severity

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}")
_URL_RE = re.compile(r"https?://[^\s'\"\\]+", re.I)
_HEADER_RE = re.compile(r"""(?:^|\s)-H\s+(['"])(.+?)\1""", re.S)
_METHOD_RE = re.compile(r"(?:^|\s)-X\s+([A-Z]+)")
_DATA_RE = re.compile(
    r"""(?:^|\s)(?:--data-raw|--data-binary|--data|-d|--data-urlencode)\s+(['"])([\s\S]*?)\1"""
)

WRITEUP_SYSTEM = """你是给安全工程师看的授权渗透测试报告撰写人。读者要能只靠本报告理解成因、危害，并在授权环境中逐步复现。

硬约束
- 不得编造事实包里没有的 URL、路径、参数名、payload、CVE、响应原文、文件路径或状态码。
- 没有的信息写「未采集」，不要用 SQLMap/典型 payload 填空。
- 原理必须扣到本条入口、参数和服务端处理，禁止只写「存在注入」。
- 危害分「证据已证实」和「未证实的潜在后续」，不要把潜在写成已打穿。
- 复现步骤必须是操作级：用哪个工具、点哪、填哪一栏、点 Send 后看什么。只能解释如何使用事实包里的 curl/python/证据。

每个漏洞输出一个 JSON 对象（不要数组包裹以外的解释）：
{
  "id": "与事实包 id 一致",
  "mechanism": "漏洞原理（400～800 字：缺陷类型、数据如何流入、为何校验失败）",
  "root_cause": "成因与说明（800～1500 字，分现象、入口、可控点、服务端缺陷、与证据的对应）",
  "impact_detail": "危害分析（600～1200 字：已证实影响、权限主体、机密性/完整性/可用性、未证实的后续）",
  "affected_scope": "影响资产、Host、路径、参数、会话条件",
  "expected_result": "复现成功时响应/输出必须出现的、证据里已有的特征",
  "remediation": "针对本入口的修复（参数化、鉴权、落地校验等，落到本条路径）",
  "reproduction_notes": ["8～15 条 Burp/curl 操作提示，不新增 payload"]
}
"""


def real_poc_text(text: str | None) -> str:
    """去掉「禁止合成」占位，只保留可执行的 curl/python 原文。"""
    raw = (text or "").strip()
    if not raw:
        return ""
    markers = (
        "无人工复现", "禁止使用合成", "禁止自动合成利用",
        "missing real poc", "missing real poc_python",
        'raise SystemExit("missing real poc',
    )
    if any(m in raw for m in markers):
        return ""
    return raw


def parse_curl_command(text: str | None) -> dict[str, Any] | None:
    """从真实 curl 抽出 method/url/headers/body。解析失败返回 None，不猜测。"""
    raw = real_poc_text(text)
    if not raw or "curl" not in raw.lower():
        return None
    compact = " ".join(
        ln.rstrip("\\").strip()
        for ln in raw.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    )
    if "curl" not in compact.lower():
        return None
    url = ""
    m = _URL_RE.search(compact)
    if m:
        url = m.group(0).rstrip("\\),;")
    method_m = _METHOD_RE.search(compact)
    method = (method_m.group(1) if method_m else "GET").upper()
    headers: list[str] = []
    for hm in _HEADER_RE.finditer(compact):
        headers.append(hm.group(2).strip())
    body = ""
    dm = _DATA_RE.search(compact)
    if dm:
        body = dm.group(2)
        if method == "GET":
            method = "POST"
    if not url and not body and not headers:
        return None
    path = ""
    host = ""
    query_params: list[tuple[str, str]] = []
    if url:
        try:
            p = urlparse(url)
            host = p.netloc
            path = p.path or "/"
            if p.query:
                path = f"{path}?{p.query}"
                query_params = parse_qsl(p.query, keep_blank_values=True)
        except Exception:
            path = url
    if body and method != "GET" and not query_params:
        if any("application/x-www-form-urlencoded" in h.lower() for h in headers) or "=" in body:
            try:
                query_params = parse_qsl(body, keep_blank_values=True)
            except Exception:
                query_params = []
    parsed = {
        "method": method,
        "url": url,
        "host": host,
        "path": unquote(path) if path else "",
        "headers": headers,
        "body": body,
        "query_params": query_params,
        "raw": compact[:4000],
    }
    parsed["raw_http"] = _raw_http(parsed)
    return parsed


def _raw_http(parsed: dict) -> str:
    host = parsed.get("host") or ""
    path = parsed.get("path") or "/"
    if not path.startswith("/"):
        path = "/" + path
    method = parsed.get("method") or "GET"
    lines = [f"{method} {path} HTTP/1.1"]
    if host:
        lines.append(f"Host: {host}")
    seen_cl = False
    for h in parsed.get("headers") or []:
        lines.append(h)
        if h.lower().startswith("content-length:"):
            seen_cl = True
    body = parsed.get("body") or ""
    if body:
        if not seen_cl:
            lines.append(f"Content-Length: {len(body.encode('utf-8', errors='replace'))}")
        lines.append("")
        lines.append(body)
    else:
        lines.append("")
        lines.append("")
    return "\n".join(lines)


def _norm_blob(text: str | None) -> str:
    return re.sub(r"\s+", "", str(text or ""))


def _covered_by(fragment: str | None, *blobs: str | None) -> bool:
    """fragment 已被其它段落完整包含时不再复述。"""
    frag = _norm_blob(fragment)
    if len(frag) < 32:
        return False
    return any(frag in _norm_blob(b) for b in blobs if b)


def _strip_embedded_mechanism(root: str, mechanism: str) -> str:
    """漏洞说明里不要再嵌一整段「漏洞原理」。"""
    if not (root or "").strip():
        return root
    parts = re.split(r"(?=【)", root)
    mech_n = _norm_blob(mechanism)
    kept: list[str] = []
    for p in parts:
        if not p.strip():
            continue
        if p.startswith("【漏洞原理】"):
            continue
        if mech_n and len(mech_n) > 48 and mech_n in _norm_blob(p) and not p.startswith("【现象】"):
            continue
        kept.append(p)
    return "".join(kept).strip() or root


def _node_detail(finding: dict) -> str:
    node = finding.get("related_node") or {}
    detail = node.get("detail") if isinstance(node, dict) else None
    if isinstance(detail, str) and detail.strip():
        return detail.strip()
    return ""


def _edge_lines(finding: dict) -> list[str]:
    out: list[str] = []
    for e in finding.get("related_edges") or []:
        if not isinstance(e, dict):
            continue
        frm = e.get("from") or e.get("src") or ""
        to = e.get("to") or e.get("dst") or ""
        rel = e.get("relation") or ""
        why = e.get("rationale") or ""
        bit = f"`{frm}` --{rel}--> `{to}`"
        if why:
            bit += f"：{why}"
        out.append(bit)
    return out


def _evidence_excerpt(finding: dict, n: int = 800) -> str:
    ev = (finding.get("evidence") or "").strip()
    if not ev:
        return ""
    one = re.sub(r"[ \t]+", " ", ev)
    return one if len(one) <= n else one[:n] + "…"


def _parsed_of(finding: dict, poc: dict | None = None) -> dict | None:
    curl = real_poc_text(finding.get("poc_curl") or (poc or {}).get("curl"))
    return parse_curl_command(curl)


def expected_signals(finding: dict) -> list[str]:
    """从证据/证明里抽出复现成功时应出现的特征，不编造。"""
    blob = "\n".join(
        str(finding.get(k) or "")
        for k in ("evidence", "proof_detail", "proof_canary", "description")
    )
    out: list[str] = []
    patterns = [
        (r"You have an error in your SQL syntax[^\n]{0,80}", "数据库语法错误回显"),
        (r"SQLException[^\n]{0,80}", "JDBC/SQL 异常"),
        (r"uid=\d+\([^)]+\)", "id/whoami 类命令回显"),
        (r"www-data", "进程用户 www-data"),
        (r"nt authority[^\n]{0,40}", "Windows 系统账户回显"),
        (r"root:[^:\n]*:0:0:", "/etc/passwd 特征行"),
        (r"HTTP/\d(?:\.\d)?\s+(\d{3})", None),
        (r"(?:status|Status-Code)[:= ]+(\d{3})", None),
    ]
    for pat, label in patterns:
        m = re.search(pat, blob, re.I)
        if not m:
            continue
        if label is None:
            out.append(f"HTTP 状态 {m.group(1)}")
        else:
            out.append(f"{label}：`{m.group(0).strip()}`")
    canary = (finding.get("proof_canary") or "").strip()
    if canary:
        out.append(f"Canary `{canary}`")
    url = (finding.get("proof_url") or "").strip()
    if url:
        out.append(f"证明 URL 可访问：{url}")
    # 去重保序
    seen: set[str] = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def param_analysis(parsed: dict | None) -> str:
    if not parsed:
        return "未从 PoC 解析出查询/表单参数；复现时整段使用「PoC」原文，不要自行增参。"
    pairs = parsed.get("query_params") or []
    if not pairs:
        if parsed.get("body"):
            return (
                "PoC 含请求体但未能稳定拆成键值。请把「原始 HTTP」或 curl `-d` 原文原样粘贴，"
                "不要改字段名。"
            )
        return "该请求无 QueryString / 表单字段；注入点若存在，应在路径或 Header 中（以 PoC 为准）。"
    lines = ["PoC 中出现的参数（名称与取值均来自已采集请求，未改写）："]
    for k, v in pairs:
        hint = "（取值含引号/注释/特殊字符，优先作为注入点复核）" if re.search(
            r"['\"#;<>]|--|/\*|\*/|\$\(|`|\\|%27|%22", v
        ) else "（普通取值，多半是业务或会话字段，复现时保持不变）"
        disp = v if len(v) <= 200 else v[:200] + "…"
        lines.append(f"- `{k}` = `{disp}` {hint}")
    return "\n".join(lines)


def deterministic_mechanism(finding: dict, parsed: dict | None = None) -> str:
    cat = (finding.get("category") or "").lower() or "未分类"
    title = finding.get("title") or ""
    parsed = parsed or _parsed_of(finding)
    url = (parsed or {}).get("url") or ""
    method = (parsed or {}).get("method") or ""
    pairs = (parsed or {}).get("query_params") or []
    inj = [k for k, v in pairs if re.search(r"['\"#;<>]|--|/\*|%27|%22|\$\(", v)]
    inj_txt = "、".join(f"`{k}`" for k in inj) if inj else "PoC 中的可控输入"
    loc = url or (finding.get("node_key") or "未采集 URL")
    by_cat = {
        "sqli": (
            f"类别为 SQL 注入。应用把调用方可控数据拼进 SQL，而不是使用绑定参数。"
            f"本条入口为 `{method} {loc}`，优先复核参数 {inj_txt}。"
            "当特殊字符进入语句后，引号闭合或注释会改变查询结构；"
            "证据里的语法错误/异常堆栈是语句被破坏的直接表现，不是「页面刚好 500」。"
        ),
        "db_access": (
            f"类别为数据库访问。入口 `{method} {loc}` 上的可控输入最终进入数据层。"
            "危害以证据中实际读到或改到的对象为准，不假设未出现的 UNION/写库。"
        ),
        "rce": (
            f"类别为远程代码/命令执行。入口 `{method} {loc}` 上的输入进入了操作系统命令、模板或反序列化触发面。"
            "证据中的 uid/whoami/canary 是进程已执行攻击者数据的证明。"
        ),
        "command_injection": (
            f"类别为命令注入。用户输入与系统命令拼接。入口 `{method} {loc}`，参数 {inj_txt}。"
            "元字符（如 `;`、`|`、`$()`）若未被剥离，就会在 Web 进程权限下跑额外命令。"
        ),
        "deserialization": (
            f"类别为不安全反序列化。入口 `{method} {loc}` 接受的数据被还原为对象并触发危险 gadget。"
            "只陈述证据里已出现的执行/报错，不补充未出现的 gadget 链名称。"
        ),
        "file_read": (
            f"类别为任意文件读取。入口 `{method} {loc}` 的路径/文件参数未做规范化和根目录约束。"
            "证据中的系统文件特征行证明读取越过了应用目录。"
        ),
        "lfi": (
            f"类别为本地文件包含/读取。入口 `{method} {loc}`，参数 {inj_txt} 指向服务端本地文件。"
        ),
        "arbitrary_file_read": (
            f"类别为任意文件读取。入口 `{method} {loc}`。成功判定以证据中的文件内容特征为准。"
        ),
        "path_traversal": (
            f"类别为路径穿越。`../` 或等价编码使参数 {inj_txt} 跳出预定目录。入口 `{method} {loc}`。"
        ),
        "file_upload": (
            f"类别为文件上传。入口 `{method} {loc}` 对扩展名、内容或落地目录校验不足。"
            "是否已变成 Webshell 以 canary/证明 URL 为准，未出现则只写上传成功。"
        ),
        "file_write": (
            f"类别为任意文件写入。入口 `{method} {loc}`。写入位置与内容以 proof/canary 为准。"
        ),
        "auth_bypass": (
            f"类别为认证绕过。入口 `{method} {loc}` 上服务端未校验会话/令牌/口令，或校验可被跳过。"
        ),
        "unauth": (
            f"类别为未授权访问。本应鉴权的接口 `{method} {loc}` 在无有效凭证时仍返回敏感数据或接受操作。"
        ),
        "idor": (
            f"类别为越权/IDOR。对象标识可被调用方改写。入口 `{method} {loc}`，参数 {inj_txt}。"
            "成功以证据中「访问了非当前主体对象」为准。"
        ),
        "admin_access": (
            f"类别为管理功能暴露或越权进入后台。入口 `{method} {loc}`。"
        ),
        "ssrf": (
            f"类别为服务端请求伪造。入口 `{method} {loc}` 让服务器向调用方指定的 URL 发请求。"
            "内网打到哪以证据为准，不假设未出现的云元数据。"
        ),
        "xss": (
            f"类别为跨站脚本。入口 `{method} {loc}` 的输出未编码，参数 {inj_txt} 被反射或存储后执行。"
        ),
        "info_disclosure": (
            f"类别为信息泄露。入口 `{method} {loc}` 暴露了版本、路径、调试或配置。"
            "本身未必能直接打穿，但会降低后续利用成本。"
        ),
    }
    core = by_cat.get(cat) or (
        f"类别标记为 `{cat}`。标题：{title or '未命名'}。入口 `{method} {loc}`。"
        "原理以本条证据为准，不套用其它类别的利用模型。"
    )
    return core + "\n\n原理分析禁止引入 PoC/证据未出现的第二个参数、隐藏接口或 CVE 编号。"


def deterministic_root_cause(finding: dict) -> str:
    parsed = _parsed_of(finding)
    cat = (finding.get("category") or "").strip() or "未分类"
    title = finding.get("title") or "（无标题）"
    desc = (finding.get("description") or "").strip()
    loc = (finding.get("node_key") or "").strip()
    nd = _node_detail(finding)
    parts: list[str] = []

    parts.append(f"【现象】{title}。严重度 `{finding.get('severity') or 'info'}`，类别 `{cat}`。")
    if desc and not _covered_by(desc, title):
        parts.append("【测试人员描述】\n" + desc)
    elif not desc:
        parts.append("【测试人员描述】未采集独立 description 字段。")

    if parsed and parsed.get("url"):
        parts.append(
            f"【入口】`{parsed.get('method')} {parsed.get('url')}`。\n"
            f"Host `{parsed.get('host') or '未解析'}`，路径 `{parsed.get('path') or '/'}`。\n"
            "所有复现必须使用该 URL 与方法；替换 Host 仅当测试环境与取证环境域名不同。"
        )
        parts.append("【可控参数】\n" + param_analysis(parsed))
    else:
        parts.append(
            "【入口】未采集可解析的 poc_curl。"
            + (f" 攻击图节点 `{loc}`。" if loc else "")
            + " 复现时只能依据证据里出现的方法和路径，禁止补全未出现的路由。"
        )

    if nd and not _covered_by(nd, desc):
        parts.append("【关联节点记录】\n" + nd)

    sigs = expected_signals(finding)
    if sigs:
        parts.append(
            "【与证据的对应】下列特征出现在本条证据/证明中，是「原理成立」的观察，不是猜测：\n"
            + "\n".join(f"- {s}" for s in sigs)
        )
    else:
        parts.append("【与证据的对应】证据中没有抽出可引用的报错/回显特征；复核时不要把单纯超时当成漏洞成立。")
    return "\n\n".join(parts)


def deterministic_impact(finding: dict) -> str:
    cat = (finding.get("category") or "").lower()
    ev = (finding.get("evidence") or "").strip()
    proof = (finding.get("proof_detail") or "").strip()
    blob = f"{ev}\n{proof}"
    blob_l = blob.lower()
    sev = display_finding_severity(finding)
    bits: list[str] = []

    bits.append(
        f"【评级】报告严重度为 `{sev}`，类别 `{cat or '未分类'}`。"
        "以下「已证实」只引用本条证据；未在证据中出现的读库、写文件、横向移动一律标为潜在。"
    )

    proved: list[str] = []
    potential: list[str] = []
    uid_m = re.search(r"uid=\d+\([^)]+\)", blob)
    if uid_m or "www-data" in blob_l or "nt authority" in blob_l:
        who = uid_m.group(0) if uid_m else ("www-data" if "www-data" in blob_l else "Windows 系统账户")
        proved.append(
            f"命令执行已证实：证据含 `{who}`，说明漏洞通道能在 Web/服务进程的操作系统权限下跑命令。"
            "当前权限边界就是该进程用户，能否提权未在本条证明。"
        )
    if re.search(r"root:[^:\n]*:0:0:|/etc/passwd", blob):
        proved.append("本地文件读取已证实：证据含 passwd 特征行，说明可读系统账号文件，后续可读配置与密钥的风险成立。")
    if re.search(r"SQL syntax|SQLException|mysql_|syntax error", blob, re.I):
        proved.append(
            "SQL 语句可被攻击者数据改写已证实（语法错误/驱动异常）。"
            "这证明注入点存在；是否已 UNION 出库、是否可写库，本条证据未写明则不算已证实。"
        )
    if finding.get("proof_canary") or finding.get("proof_url"):
        proved.append(
            "写入/回显通道已用 canary 或证明 URL 钉死，说明影响不是一次性误报。"
            + (f" Canary `{finding.get('proof_canary')}`。" if finding.get("proof_canary") else "")
            + (f" URL {finding.get('proof_url')}。" if finding.get("proof_url") else "")
        )
    if cat in ("auth_bypass", "unauth", "idor", "admin_access") and ev:
        proved.append("鉴权/对象级授权在本条入口上可被绕过或未执行；具体对象以证据里的接口和返回为准。")
    if cat in ("info_disclosure", "info") and ev:
        proved.append("信息泄露已采集到响应内容；单独通常不构成接管，但会暴露版本、路径或配置，降低攻击成本。")

    if cat in ("sqli", "db_access"):
        potential.append("潜在：在注入被证实后，可能读取业务表、拖取账号哈希；未做出网或堆叠写入则不要写成已发生。")
    if cat in ("rce", "command_injection", "deserialization", "file_upload", "file_write"):
        potential.append("潜在：在当前进程权限下可能读环境变量、连内网、写 Web 目录；未做横向则不写「已控制内网」。")
    if cat in ("ssrf",):
        potential.append("潜在：可探测内网 HTTP 服务或云元数据；证据未出现内网回显则只保留「具备发请求能力」。")

    bits.append("【已证实】\n" + ("\n".join(f"- {x}" for x in proved) if proved else "- 除类别与描述外，没有可引用的执行/读文件/报错证据。不要把严重度当成已打穿。"))
    bits.append("【机密性 / 完整性 / 可用性】")
    bits.append(
        "- 机密性：若证据含文件内容、SQL 报错中的表/列、未授权响应体，则机密性已受损；否则为潜在。\n"
        "- 完整性：仅当证据表明写入文件、改数据或执行了改变状态的命令时成立。\n"
        "- 可用性：本报告默认不做破坏性验证；证据未出现拒绝服务则可用性未测。"
    )
    if potential:
        bits.append("【未证实的后续（不得当作已发生）】\n" + "\n".join(f"- {x}" for x in potential))
    excerpt = _evidence_excerpt(finding, 900)
    if excerpt:
        bits.append("【证据摘要】原文见「完整证据」。摘要：\n" + excerpt)
    return "\n\n".join(bits)


def deterministic_scope(finding: dict) -> str:
    node = finding.get("related_node") or {}
    title = ""
    ntype = ""
    if isinstance(node, dict):
        title = str(node.get("title") or "")
        ntype = str(node.get("type") or "")
    loc = finding.get("node_key") or ""
    parsed = _parsed_of(finding)
    lines = []
    if loc:
        lines.append(f"攻击图节点：`{loc}`" + (f"（{ntype} {title}）" if title else ""))
    if parsed and parsed.get("url"):
        lines.append(f"HTTP 入口：`{parsed['method']} {parsed['url']}`")
        if parsed.get("host"):
            lines.append(f"主机：`{parsed['host']}`")
        if parsed.get("path"):
            lines.append(f"路径与查询：`{parsed['path']}`")
        for k, v in (parsed.get("query_params") or [])[:16]:
            disp = v if len(v) <= 120 else v[:120] + "…"
            lines.append(f"参数 `{k}` = `{disp}`")
        for h in parsed.get("headers") or []:
            if h.lower().startswith("cookie:"):
                lines.append("会话：请求带 Cookie（复现时用当前有效会话替换，不要改其它 Header 名）")
                break
    for el in _edge_lines(finding)[:12]:
        lines.append("关系：" + el)
    if finding.get("prerequisites"):
        lines.append("前置：" + str(finding.get("prerequisites")))
    if not lines:
        return "未采集明确资产归属；请按标题与证据中的 Host/URL 定位。"
    return "\n".join(f"- {x}" for x in lines)


def _benign_value(value: str) -> str | None:
    """从 PoC 取值推导对照用良性值：去掉引号/注释标记，不发明新 payload。"""
    v = value
    for token in ("'", '"', "%27", "%22", "--", "#", ";", "`"):
        v = v.replace(token, "")
    v = re.sub(r"/\*.*?\*/", "", v)
    v = v.strip()
    if not v or v == value:
        return None
    return v


def manual_reproduction_steps(finding: dict, poc: dict | None = None) -> list[str]:
    """编号手动复现步骤。只用真实 PoC/证据，不合成假利用。"""
    poc = poc or {}
    steps: list[str] = []
    n = 1
    loc = (finding.get("node_key") or "").strip()
    cat = (finding.get("category") or "").lower()
    curl = real_poc_text(finding.get("poc_curl") or poc.get("curl"))
    py = real_poc_text(finding.get("poc_python") or poc.get("python"))
    evidence = (finding.get("evidence") or "").strip()
    proof_url = (finding.get("proof_url") or "").strip()
    canary = (finding.get("proof_canary") or "").strip()
    parsed = parse_curl_command(curl) or _parsed_of(finding, poc)
    sigs = expected_signals(finding)

    def add(text: str) -> None:
        nonlocal n
        steps.append(f"{n}. {text}")
        n += 1

    add(
        "确认你有书面授权，且目标就是本报告中的 Host/资产。"
        + (f" 关联节点 `{loc}`。" if loc else "")
        + " 禁止把 payload 打到非授权域名或生产只读禁令范围之外。"
    )
    add(
        "准备工具：Burp Suite（Proxy + Repeater）或任何可编辑原始 HTTP 的客户端，以及系统自带 curl。"
        " 浏览器只用于需要 Cookie 登录的场景。"
    )
    if parsed and parsed.get("host"):
        add(
            f"先探测入口是否可达（不要带 payload）："
            f"`curl -skI --max-time 15 'http://{parsed['host']}/'` 或对 PoC URL 去掉查询串后发 HEAD/GET。"
            " 连接失败、TLS 名字不匹配时先修环境，不要开始复现。"
        )

    rce_like = cat in (
        "rce", "command_injection", "deserialization", "file_write", "file_upload",
    ) or loc.startswith(("goal:shell", "foothold:shell"))
    if rce_like and (canary or proof_url):
        add(
            "本条含命令执行/写文件证明。"
            f" 若走漏洞通道落盘短 txt，内容必须使用 canary `{canary or '<已采集 canary>'}`，"
            "文件名与路径只能用证据/proof 里出现过的，禁止换目录碰运气。"
        )
        if proof_url:
            add(f"浏览器或 curl 访问证明 URL `{proof_url}`，响应体必须含同一 canary，否则不算复现成功。")

    if parsed:
        raw_http = parsed.get("raw_http") or ""
        add(
            f"打开 Burp Repeater，目标 Host `{parsed.get('host') or '见 PoC'}`，"
            f"方法 `{parsed['method']}`，完整 URL `{parsed.get('url') or parsed.get('path')}`。"
        )
        add(
            "把下面「原始 HTTP 请求」整段粘贴进 Repeater（或 Intruder 的 Raw）。"
            " 不要改路径、不要增加 Query 参数、不要改参数名。"
            + ("\n```http\n" + raw_http + "\n```" if raw_http else "")
        )
        pairs = parsed.get("query_params") or []
        if pairs:
            lines = ["核对每一个参数（来自 PoC，不是猜测）："]
            for k, v in pairs:
                disp = v if len(v) <= 180 else v[:180] + "…"
                lines.append(f"  - `{k}` = `{disp}`")
            add("\n".join(lines))
        if parsed.get("headers"):
            hdr = "；".join(parsed["headers"][:12])
            add(
                f"请求头必须包含：{hdr}。"
                " 若 Cookie/CSRF 过期，只替换这两类会话值，Header 名称保持不变。"
            )
        if parsed.get("body"):
            body = parsed["body"]
            if len(body) > 1200:
                body = body[:1200] + "…"
            add("请求体使用 PoC 原文（不要改字段名）：\n```\n" + body + "\n```")
        add(
            "点击 Send。在 Response 面板同时看 Status、Body、Length。"
            " 成功判定只认「完整证据」里出现过的特征，不要把网关 502/WAF 拦截页当漏洞。"
        )
        if sigs:
            add("复现成功时，响应或命令输出应出现：\n" + "\n".join(f"  - {s}" for s in sigs))
        add(
            "终端等价复现：把报告「PoC / curl」整段复制到已授权机器执行。"
            " 仅当 Host/Cookie 与取证时不同才替换这两项。"
        )
        benign_bits = []
        for k, v in pairs:
            b = _benign_value(v)
            if b is not None:
                benign_bits.append(f"`{k}` 从 `{v}` 改为 `{b}`（去掉 PoC 里的特殊字符，不新增任何 payload）")
        if benign_bits:
            add(
                "基线对照：复制同一请求，仅做下列修改后重放，确认差异来自本参数而不是站点普遍报错：\n"
                + "\n".join(f"  - {x}" for x in benign_bits)
            )
        else:
            add(
                "基线对照：再发一次去掉攻击取值、改用该参数在业务里的普通数字/字母值的请求"
                "（不得引入 PoC 未出现的第二个注入向量）。对比两次 Response Body。"
            )
    elif curl:
        add("Burp 未能解析出结构化字段。将报告中的 curl PoC 原样在终端执行，只替换 Host/Cookie。")
    elif py:
        add(
            "将报告中的 python PoC 存为 `poc.py`，在授权环境执行 `python3 poc.py`。"
            " 不要改脚本里的路径与参数名；会话类值可按环境替换。"
        )
    elif evidence:
        add(
            "本条未提供独立 poc_curl。打开「完整证据」，"
            "按其中出现的方法、URL、参数和响应特征手工构造等价请求；证据里没有的字段不要编。"
        )
    else:
        add("未采集可复现 PoC 与证据。请结合漏洞说明与关联节点复核，禁止用类别典型 payload 盲打。")

    if evidence and not (parsed and sigs):
        add(
            "将响应或命令输出与「完整证据」逐字对照。"
            " 成功标准是证据中已记录的特征（状态码、回显、文件内容、canary）。"
        )
    add(
        "失败排查：① DNS/TCP/TLS 失败 → 环境问题，不是漏洞消失；"
        "② 200 但无证据特征 → 会话失效、WAF 或已修复，不要换未出现的 payload 硬打；"
        "③ 与证据完全一致 → 记录时间、账号、完整请求/响应，供修复后回归。"
    )
    add("把 Repeater 的 Request/Response 或 curl `-D -` 输出归档，和本报告证据放在一起。")
    notes = finding.get("reproduction_notes") or []
    if isinstance(notes, list):
        for note in notes:
            s = str(note or "").strip()
            if s:
                add(s)
    return steps


def apply_deterministic_writeup(finding: dict, *, poc: dict | None = None) -> dict:
    """就地补齐成因/危害/范围/步骤。已有 AI 字段则保留。"""
    out = dict(finding)
    parsed = _parsed_of(out, poc)
    if parsed:
        out["http_raw"] = parsed.get("raw_http") or out.get("http_raw")
        out["param_analysis"] = out.get("param_analysis") or param_analysis(parsed)
    else:
        out.setdefault("http_raw", "")
        out.setdefault("param_analysis", param_analysis(None))
    if not (out.get("mechanism") or "").strip():
        out["mechanism"] = deterministic_mechanism(out, parsed)
    if not (out.get("root_cause") or "").strip():
        out["root_cause"] = deterministic_root_cause(out)
    else:
        out["root_cause"] = _strip_embedded_mechanism(
            str(out.get("root_cause") or ""), str(out.get("mechanism") or ""),
        )
    nd = _node_detail(out)
    if _covered_by(nd, out.get("description"), out.get("root_cause"), out.get("mechanism")):
        out["node_detail_unique"] = ""
    else:
        out["node_detail_unique"] = nd
    from ..graph.model import secondary_review_narrative
    out["secondary_review"] = secondary_review_narrative(out)
    if not (out.get("impact_detail") or "").strip():
        out["impact_detail"] = deterministic_impact(out)
    if not (out.get("affected_scope") or "").strip():
        out["affected_scope"] = deterministic_scope(out)
    out["expected_signals"] = expected_signals(out)
    if not (out.get("expected_result") or "").strip() and out["expected_signals"]:
        out["expected_result"] = "；".join(out["expected_signals"])
    out["manual_steps"] = manual_reproduction_steps(out, poc)
    return out


def finding_from_vuln_node(node: dict, *, related_edges: list | None = None) -> dict:
    """图上有 vuln 节点但无 finding 行时，合成可导出条目。"""
    detail = node.get("detail")
    if not isinstance(detail, str):
        detail = ""
    tags = node.get("tags") or []
    cat = "vuln"
    if isinstance(tags, list):
        for t in tags:
            ts = str(t or "")
            if ts and not ts.startswith("host:"):
                cat = ts
                break
    sev = str(node.get("severity") or "info")
    out = {
        "id": f"node:{node.get('key') or ''}",
        "project_id": node.get("project_id"),
        "node_key": node.get("key"),
        "severity": sev,
        "category": cat,
        "title": node.get("title") or node.get("key") or "vuln",
        "description": detail or None,
        "evidence": None,
        "poc_curl": None,
        "poc_python": None,
        "cvss": None,
        "created_at": node.get("created_at"),
        "critical": bool(node.get("is_rce")) or sev == "critical",
        "verification_status": "pending",
        "verified_at": None,
        "proof_type": None,
        "proof_canary": None,
        "proof_url": None,
        "proof_detail": None,
        "related_node": {
            "key": node.get("key"),
            "type": node.get("type"),
            "title": node.get("title"),
            "detail": detail or None,
            "severity": node.get("severity"),
            "risk_score": node.get("risk_score"),
            "tags": tags if isinstance(tags, list) else [],
        },
        "related_edges": related_edges or [],
        "from_node_only": True,
    }
    return apply_deterministic_writeup(out)


def _facts_for_ai(finding: dict) -> dict:
    parsed = parse_curl_command(finding.get("poc_curl"))
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "node_key": finding.get("node_key"),
        "description": finding.get("description") or "",
        "evidence": (finding.get("evidence") or "")[:8000],
        "poc_curl": real_poc_text(finding.get("poc_curl"))[:4000],
        "poc_python": real_poc_text(finding.get("poc_python"))[:4000],
        "proof_type": finding.get("proof_type"),
        "proof_canary": finding.get("proof_canary"),
        "proof_url": finding.get("proof_url"),
        "proof_detail": (finding.get("proof_detail") or "")[:4000],
        "cvss": finding.get("cvss"),
        "related_node": finding.get("related_node"),
        "related_edges": finding.get("related_edges") or [],
        "parsed_curl": parsed,
        "http_raw": (parsed or {}).get("raw_http") or finding.get("http_raw") or "",
        "param_analysis": finding.get("param_analysis") or "",
        "expected_signals": finding.get("expected_signals") or expected_signals(finding),
        "deterministic_mechanism": finding.get("mechanism") or "",
        "deterministic_root_cause": finding.get("root_cause") or "",
        "deterministic_impact": finding.get("impact_detail") or "",
    }


def parse_writeups_payload(text: str) -> list[dict]:
    raw = (text or "").strip()
    if not raw:
        return []
    blob = raw
    m = _JSON_FENCE_RE.search(raw)
    if m:
        blob = m.group(1)
    else:
        m2 = _JSON_OBJ_RE.search(raw)
        if m2:
            blob = m2.group(0)
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return []
    items = data.get("writeups") if isinstance(data, dict) else data
    if isinstance(data, dict) and not items and data.get("id"):
        items = [data]
    if not isinstance(items, list):
        return []
    out = []
    for it in items:
        if isinstance(it, dict) and it.get("id"):
            out.append(it)
        elif isinstance(it, dict) and (it.get("root_cause") or it.get("mechanism")):
            out.append(it)
    return out


def merge_ai_writeup(finding: dict, spec: dict) -> dict:
    out = dict(finding)
    for key in ("mechanism", "root_cause", "impact_detail", "affected_scope",
                "expected_result", "remediation"):
        val = str(spec.get(key) or "").strip()
        if val:
            out[key] = val
    notes = spec.get("reproduction_notes") or spec.get("reproduction_steps") or []
    if isinstance(notes, list):
        clean = [str(x).strip() for x in notes if str(x).strip()]
        if clean:
            out["reproduction_notes"] = clean[:15]
    return apply_deterministic_writeup(out)


async def _ai_one_writeup(finding: dict) -> dict | None:
    import asyncio

    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, TextBlock, query

    from ..agents.session import _get_spawn_sem

    facts = _facts_for_ai(finding)
    prompt = (
        "请为下面这一条漏洞写给安全工程师看的中文详报。"
        "只使用事实包，写满 mechanism / root_cause / impact_detail / reproduction_notes。\n\n"
        + json.dumps(facts, ensure_ascii=False, indent=2)[:80000]
    )
    model = (getattr(settings, "report_model", None) or "").strip() or (
        (getattr(settings, "supervisor_model", None) or "").strip() or settings.claude_model
    )
    wait = float(getattr(settings, "report_timeout_sec", 90) or 90)
    opts = ClaudeAgentOptions(
        tools=[],
        allowed_tools=[],
        disallowed_tools=["Bash", "WebFetch", "Read", "Write", "Edit", "Grep", "Glob", "WebSearch", "TodoWrite", "Task"],
        system_prompt=WRITEUP_SYSTEM,
        model=model,
        fallback_model=settings.claude_fallback_model,
        max_turns=1,
        permission_mode="dontAsk",
        setting_sources=[],
        skills=[],
        plugins=[],
        cwd=str(settings.data_dir),
        max_buffer_size=8 * 1024 * 1024,
    )
    texts: list[str] = []

    async def _run() -> None:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for b in getattr(msg, "content", []) or []:
                    if isinstance(b, TextBlock) and (b.text or "").strip():
                        texts.append(b.text)

    sem = _get_spawn_sem()
    async with sem:
        await asyncio.wait_for(_run(), timeout=max(30.0, wait))
    specs = parse_writeups_payload("\n".join(texts))
    if not specs:
        return None
    fid = str(finding.get("id") or "")
    for s in specs:
        if str(s.get("id") or "") in ("", fid):
            if not s.get("id"):
                s = {**s, "id": fid}
            return s
    return specs[0]


async def ai_enrich_writeups(findings: list[dict]) -> list[dict]:
    """逐条请模型写详报。单条失败不影响其余，回退确定性结果。"""
    if not findings:
        return findings
    if not bool(getattr(settings, "report_ai", True)):
        return findings
    out: list[dict] = []
    for f in findings:
        try:
            spec = await _ai_one_writeup(f)
        except Exception:
            spec = None
        out.append(merge_ai_writeup(f, spec) if spec else f)
    return out
