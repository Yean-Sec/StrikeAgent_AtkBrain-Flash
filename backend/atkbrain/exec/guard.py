"""执行纪律：破坏性命令拦截、勿打本机控制台与物理网卡。"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

from ..config import settings
from ..objective import objective_allows_flag
from ..scope import Scope, is_loopback, is_platform_endpoint, local_self_hosts, unauthorized_peer_endpoint, unauthorized_private_host

# 一个 token 若以 scheme:// 开头 → 只取其“权威主机”(authority)，忽略 path/query/fragment。
# 这样 body/参数里的域名不会被误判，且 SSRF/开放重定向 payload(在 query 里的 URL)天然放行——
# 我们真正连接的只是 authority 那台主机。
_SCHEME_AUTH_RE = re.compile(
    r"""^["']?(?:https?|ftp|ftps|ssh|sftp|smb|cifs|rdp|mysql|redis|mongodb|
        postgres(?:ql)?|gopher|dict|ldaps?|telnet|vnc|memcached?|rtsp|ws|wss)://
        ([^/\\\s?#'"]+)""",
    re.I | re.X,
)
# 裸 IPv4(:port) —— 必须整 token 匹配（作为 nmap/redis-cli 等的位置参数目标）
_IP_TOKEN_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?$")
# 回环别名（无 TLD，DOMAIN_TOKEN_RE 匹配不到）
_LOOPBACK_NAME_RE = re.compile(r"^(localhost|ip6-localhost)(?::(\d{1,5}))?$", re.I)
# 裸域名(:port) —— 必须整 token 匹配，避免把 body/字符串里的域名当主机
_DOMAIN_TOKEN_RE = re.compile(
    r"^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d+)?$", re.I
)
# 解释器代码体里的回环/本机 URL（仅用于平台自我保护，不把普通 payload URL 当连接目标）
_LOOPBACK_IN_CODE_RE = re.compile(
    r"(?:https?://)?(127(?:\.\d{1,3}){1,3}|localhost|::1|0\.0\.0\.0)(?::(\d{1,5}))?",
    re.I,
)

# 这些选项的“值”是发送给目标的数据/头部/表单/Cookie，而非我们要连接的主机；扫描主机时必须排除，
# 否则 POST body/Header/Cookie/参数里出现的域名(邮箱、SSRF 内网 URL、云元数据 IP、XSS/SQLi payload…)
# 会被误当“越界主机”而拦下合法攻击。注意 -u/--user 不在此列：ffuf/sqlmap/nikto 的 -u 是 URL 目标，
# 需要参与边界校验（curl 的 -u user:pass 不含主机，天然不会误报）。
_SKIP_VALUE_FLAGS = {
    "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
    "--form-string", "-F", "--form", "-H", "--header", "-b", "--cookie", "--cookie-jar",
    "-A", "--user-agent", "-e", "--referer", "--json", "--url-query",
    "--mail-from", "--mail-rcpt", "--aws-sigv4", "--oauth2-bearer",
}
# 这些选项的“值”本身是一条子命令(如 sh -c '...')，需递归解析出其中真正的连接目标作为兜底。
_SUBCMD_FLAGS = {"-c", "--command"}
# shell 与解释器区分：shell 的 -c 值是子命令(递归)；解释器的代码体是数据(跳过，避免把 Header/payload
# 里的 URL 误当连接目标)。
_SHELL_PROGS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
_INTERP_PROGS = {"python", "python2", "python3", "ruby", "node", "nodejs", "perl", "php", "php7", "php8"}
_INTERP_CODE_FLAGS = {"-c", "-e", "-r", "--eval", "--command"}
# 命令前缀里的“包装器”：定位真正程序名时应跳过它们（及 timeout 的时长参数、VAR=val 赋值）。
_WRAPPERS = {"env", "sudo", "nohup", "stdbuf", "nice", "setsid", "time"}


def _leading_prog(tokens: list[str]) -> str:
    """定位命令真正的程序名（basename），跳过 env/sudo/timeout 等包装器与 VAR=val 赋值。"""
    i = 0
    while i < len(tokens):
        t = tokens[i]
        b = t.rsplit("/", 1)[-1]
        if not t.startswith("-") and "=" in t:      # VAR=val 环境赋值
            i += 1; continue
        if b in _WRAPPERS:
            i += 1; continue
        if b == "timeout":                          # timeout <dur> <cmd...>
            i += 2; continue
        return b
    return ""

# 真实公共 TLD 白名单（用于把裸域名与文件名/payload 区分开，避免误报）
_REAL_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev",
    "cloud", "cn", "uk", "de", "jp", "ru", "fr", "us", "eu", "in", "br", "au", "ca",
    "info", "biz", "xyz", "top", "site", "online", "store", "tech", "me", "tv", "cc",
    "pro", "vip", "work", "live", "team", "group", "network", "systems", "host",
    "kr", "hk", "tw", "sg", "nl", "it", "es", "se", "no", "fi", "pl", "cz", "ch",
}

# 明显是文件/payload 的扩展名（这些 token 一律不当主机）
_FILE_EXTS = {
    "py", "sh", "txt", "json", "md", "js", "ts", "log", "conf", "cfg", "ini",
    "xml", "yaml", "yml", "html", "htm", "php", "jsp", "asp", "aspx", "jspx",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "jar", "war", "class",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "csv", "sql", "db", "bak", "old",
    "so", "dll", "exe", "bin", "dat", "pem", "key", "crt", "cer", "pcap",
    "css", "map", "woff", "woff2", "ttf", "mp4", "mp3", "avi", "iso", "img",
}

# 显式代表"执行"的前缀
_EXEC_PREFIX_RE = re.compile(
    r"(?:^|[\s;&|`(])(?:\./|sh\s|bash\s|python[23]?\s|perl\s|ruby\s|php\s|node\s|source\s|\.\s)",
    re.I,
)

# 破坏性命令黑名单（针对本机/宿主，防误伤自身）
_DESTRUCTIVE = [
    re.compile(r"\brm\s+-rf\s+/(?:\s|$)"),
    re.compile(r"\brm\s+-rf\s+~(?:/|\s|$)"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),   # fork bomb
    re.compile(r"\bmkfs\.", re.I),
    re.compile(r"\bdd\s+if=.*of=/dev/(sd|nvme|vd)", re.I),
    re.compile(r">\s*/dev/(sd|nvme|vd)", re.I),
    re.compile(r"\bshutdown\b|\breboot\b|\bpoweroff\b", re.I),
]

# 对作业目标的破坏性操作：只读证明，禁止真删/破坏性 SQL
_TARGET_DESTRUCTIVE = [
    (re.compile(r"\bdrop\s+(?:table|database|schema|index)\b", re.I), "DROP TABLE/DATABASE 等破坏性 SQL"),
    (re.compile(r"\btruncate\s+(?:table\s+)?[`\"'\w]", re.I), "TRUNCATE 破坏性 SQL"),
    (re.compile(r"\bdelete\s+from\s+", re.I), "DELETE FROM 破坏性 SQL"),
    (re.compile(r"\balter\s+table\s+\S+\s+drop\b", re.I), "ALTER TABLE DROP 破坏性 SQL"),
    (re.compile(r"\binsert\s+into\s+", re.I), "INSERT INTO 会往业务库写垃圾数据"),
    (re.compile(r"\breplace\s+into\s+", re.I), "REPLACE INTO 会改写业务数据"),
    (re.compile(r"\bupdate\s+\S+\s+set\s+", re.I), "UPDATE SET 会改业务数据"),
    (re.compile(r"\bload\s+data\s+(?:local\s+)?infile\b", re.I), "LOAD DATA INFILE 会写库"),
    (re.compile(r"\binto\s+(?:dumpfile|outfile)\b", re.I), "INTO OUTFILE/DUMPFILE 会在目标落盘"),
    (re.compile(r"sqlmap[^\n]*--file-write\b", re.I), "sqlmap --file-write 会在目标写文件"),
    (re.compile(r"sqlmap[^\n]*--sql-query=['\"][^'\"]*\b(?:insert|update|replace)\b", re.I), "sqlmap 写库语句"),
    (re.compile(r"sqlmap[^\n]*--os-shell\b", re.I), "sqlmap --os-shell 对业务环境过重"),
    (re.compile(r"sqlmap[^\n]*--os-cmd[^\n]*\b(?:rm\s+-|del\s+/|rd\s+/s)", re.I), "sqlmap --os-cmd 含删除"),
    (re.compile(
        r"[?&](?:action|op|do|operate|method|cmd|act)=(?:delete|remove|unlink|destroy|drop)\b",
        re.I,
    ), "请求会触发删除动作"),
]

# CTF 必有解：拦截超级大字典撞库/撞哈希。红队不走这条。
_CTF_MEGA_DICT_RE = re.compile(
    r"rockyou|"
    r"crackstation|"
    r"10[-_]?million[-_]?password|"
    r"hashed[-_]?password|"
    r"darkc0de|"
    r"\bhashcat\b|"
    r"\bjohn(?:the(?:ripper)?)?\b.{0,120}--wordlist|"
    r"seclists/.*/Passwords/.{0,80}(?:large|huge|million|rockyou)",
    re.I,
)


def ctf_mega_dict_reason(text: str | None) -> str | None:
    """CTF 禁止千万级词表撞口令/哈希。命中则返回原因。"""
    blob = text or ""
    if not blob.strip():
        return None
    if _CTF_MEGA_DICT_RE.search(blob):
        return (
            "CTF 必有解，禁止超级大字典撞库/撞哈希。"
            "题面账号或个位数默认口令即可；失败则回到已验证通道抽数据。"
        )
    return None


def target_destructive_reason(text: str | None) -> str | None:
    """业务环境禁止的破坏性 payload/命令。命中则返回原因。"""
    blob = text or ""
    if not blob.strip():
        return None
    for pat, why in _TARGET_DESTRUCTIVE:
        if pat.search(blob):
            return why
    return None


@dataclass
class GuardDecision:
    allow: bool
    reason: str = ""
    category: str = ""          # scope | honeypot | destructive | ok
    hosts: list[str] | None = None


def _authority_host(token: str) -> str | None:
    """从 scheme:// 开头的 token 中取权威主机（去掉 user:pass@ 与 :port）。"""
    m = _SCHEME_AUTH_RE.match(token)
    if not m:
        return None
    auth = m.group(1).split("@")[-1]           # 去掉 user:pass@
    if auth.startswith("["):                    # IPv6 字面量 [::1]:port
        return auth.split("]")[0].lstrip("[").lower() or None
    # 只取“合法主机字符”前缀：截断 shell 变量/元字符（如 http://10.0.0.1$f、http://host`cmd`）——
    # fuzz 循环里常把变量直接拼在主机后，若把 10.0.0.1$f) 整体当主机会误判越界。
    mh = re.match(r"[A-Za-z0-9._\-]+", auth)
    if mh:
        auth = mh.group(0)
    return auth.split(":")[0].lower() or None   # 去掉 :port


def _hosts_from_tokens(tokens: list[str], depth: int = 0) -> set[str]:
    hosts: set[str] = set()
    skip_next = False
    recurse_next = False
    # 判定当前命令的“程序”：shell 的 -c 值是子命令(需递归找连接目标)；解释器(python/ruby/node…)的
    # -c/-e/-r 值是脚本体(其中的 URL 多为 Header/payload 等数据，抽出来会误杀)，一律跳过不抽主机。
    prog = _leading_prog(tokens)
    is_interp = prog in _INTERP_PROGS
    code_flags = _INTERP_CODE_FLAGS if is_interp else _SUBCMD_FLAGS
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if recurse_next:
            recurse_next = False
            if depth < 2:
                hosts |= _hosts_from_tokens(_safe_split(tok), depth + 1)
            continue

        # --flag=value 内联形式
        if tok.startswith("-") and "=" in tok:
            flag, val = tok.split("=", 1)
            if flag in _SKIP_VALUE_FLAGS:
                continue
            if is_interp and flag in code_flags:
                continue  # 解释器脚本体：整体跳过，不抽其中的数据 URL
            if (not is_interp) and flag in _SUBCMD_FLAGS:
                if depth < 2:
                    hosts |= _hosts_from_tokens(_safe_split(val), depth + 1)
                continue
            tok = val  # 其余带值选项：按普通 token 继续判定其值是否为主机
        elif tok in _SKIP_VALUE_FLAGS:
            skip_next = True
            continue
        elif is_interp and tok in code_flags:
            skip_next = True   # 解释器代码体：跳过其值
            continue
        elif (not is_interp) and tok in _SUBCMD_FLAGS:
            recurse_next = True
            continue

        # 1) URL token → 只取 authority（忽略 path/query，放行 SSRF/redirect payload）
        h = _authority_host(tok)
        if h:
            hosts.add(h)
            continue
        # 2) 裸 IPv4(:port)
        m = _IP_TOKEN_RE.match(tok)
        if m:
            hosts.add(m.group(1).lower())
            continue
        # 2.5) localhost 别名
        m = _LOOPBACK_NAME_RE.match(tok)
        if m:
            hosts.add(m.group(1).lower())
            continue
        # 3) 裸域名(:port)：整 token 匹配 + 真实 TLD + 非文件扩展名
        m = _DOMAIN_TOKEN_RE.match(tok)
        if m:
            h = m.group(1).lower()
            tld = h.rsplit(".", 1)[-1]
            if tld in _REAL_TLDS and tld not in _FILE_EXTS:
                hosts.add(h)
            continue
    return hosts


def _safe_split(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except Exception:
        return command.split()


_CONNECT_PROGS = {
    "curl", "wget", "http", "https", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
    "nmap", "ncat", "masscan", "ffuf", "feroxbuster", "gobuster", "sqlmap", "nikto",
    "redis-cli", "mysql", "psql", "mongo", "ftp", "lftp", "smbclient", "rpcclient",
}


def _direct_connect_hosts(tokens: list[str]) -> set[str]:
    """curl/wget/nmap/ssh 等真正发起连接的主机；python 编码参数里的 URL 不算。"""
    hosts: set[str] = set()
    i = 0
    n = len(tokens)
    while i < n:
        b = tokens[i].rsplit("/", 1)[-1].lower()
        if b in _CONNECT_PROGS:
            j = i + 1
            while j < n and tokens[j] not in (";", "&&", "||", "|"):
                t = tokens[j]
                if t in ("-u", "--url", "--host") and j + 1 < n:
                    cand = tokens[j + 1]
                    h = _authority_host(cand)
                    if h:
                        hosts.add(h)
                    m = _IP_TOKEN_RE.match(cand)
                    if m:
                        hosts.add(m.group(1).lower())
                    j += 2
                    continue
                if t.startswith("-") and "=" in t:
                    flag, val = t.split("=", 1)
                    if flag in ("-u", "--url", "--host"):
                        h = _authority_host(val)
                        if h:
                            hosts.add(h)
                    j += 1
                    continue
                if t.startswith("-"):
                    j += 1
                    continue
                h = _authority_host(t)
                if h:
                    hosts.add(h)
                m = _IP_TOKEN_RE.match(t)
                if m:
                    hosts.add(m.group(1).lower())
                j += 1
            i = j
            continue
        i += 1
    return hosts


def extract_hosts(command: str) -> list[str]:
    """抽取命令中真正代表“网络连接目标”的主机，避免把 payload/数据里的域名误判为主机。

    规则（对每个 shell token 判定，而非整条字符串扫描）：
    - 跳过 -d/-H/--cookie/--json/--form 等“数据/头部”选项的值——这些是发给目标的内容，不是连接目标。
    - URL token 仅取 scheme:// 后的 authority，忽略其 path/query——因此 SSRF/开放重定向等把 URL
      放进目标 URL 查询串或请求体里的 payload 会被正确放行（我们连接的仍是授权目标本身）。
    - 裸 IPv4 / 裸域名需整 token 匹配（域名还需真实 TLD 且非文件扩展名），作为 nmap/redis-cli 等位置目标。
    - 递归解析 `sh -c '...'` 一类子命令值，作为直连越界主机的兜底拦截。
    """
    return sorted(_hosts_from_tokens(_safe_split(command)))


_TRAIL_PORT_RE = re.compile(r":(\d{1,5})$")


def _port_of(s: str) -> int | None:
    m = _TRAIL_PORT_RE.search(s or "")
    return int(m.group(1)) if m else None


def _token_hostport(tok: str) -> tuple[str | None, int | None]:
    """从单个 token 取 (host, port)。仅用于平台自我保护端口判定，复用 extract_hosts 的主机白/黑逻辑。"""
    m = _SCHEME_AUTH_RE.match(tok)
    if m:
        auth = m.group(1).split("@")[-1]
        if auth.startswith("["):
            host = auth.split("]")[0].lstrip("[").lower()
            rest = auth.split("]")[-1]
            return (host or None), _port_of(rest)
        mh = re.match(r"[A-Za-z0-9._\-]+(?::\d+)?", auth)
        core = mh.group(0) if mh else auth
        return (core.split(":")[0].lower() or None), _port_of(core)
    m = _IP_TOKEN_RE.match(tok)
    if m:
        return m.group(1).lower(), _port_of(tok)
    m = _LOOPBACK_NAME_RE.match(tok)
    if m:
        return m.group(1).lower(), int(m.group(2)) if m.group(2) else None
    m = _DOMAIN_TOKEN_RE.match(tok)
    if m:
        h = m.group(1).lower()
        tld = h.rsplit(".", 1)[-1]
        if tld in _REAL_TLDS and tld not in _FILE_EXTS:
            return h, _port_of(tok)
    return None, None


def _loopback_ports_from_code(code: str) -> list[tuple[str, int | None]]:
    """从解释器 -c 代码体中仅抽取回环/本机 URL（防 python -c 绕过平台闸）。"""
    out: list[tuple[str, int | None]] = []
    for m in _LOOPBACK_IN_CODE_RE.finditer(code or ""):
        h = (m.group(1) or "").lower()
        p = int(m.group(2)) if m.group(2) else None
        if h:
            out.append((h, p))
    return out


def extract_host_ports(command: str) -> list[tuple[str, int | None]]:
    """抽取 (host, port) 对，仅保留通过 extract_hosts 校验的合法连接主机（端口尽力解析）。

    额外：host 与端口分 token（`nc 127.0.0.1 8000`）；解释器 -c 代码体中的回环 URL。
    """
    tokens = _safe_split(command)
    valid = set(_hosts_from_tokens(tokens))
    # 回环别名也视作合法（即使未进 valid）
    for tok in tokens:
        m = _LOOPBACK_NAME_RE.match(tok)
        if m:
            valid.add(m.group(1).lower())
        m = _IP_TOKEN_RE.match(tok)
        if m and is_loopback(m.group(1)):
            valid.add(m.group(1).lower())
    pairs: list[tuple[str, int | None]] = []
    for i, tok in enumerate(tokens):
        h, p = _token_hostport(tok)
        if h and h in valid:
            # host 后紧跟纯数字端口（nc/nmap 常见写法）
            if p is None and i + 1 < len(tokens) and tokens[i + 1].isdigit():
                try:
                    p = int(tokens[i + 1])
                except ValueError:
                    p = None
            pairs.append((h, p))
    # 解释器代码体：仅扫回环，避免把普通 payload URL 当连接目标
    prog = _leading_prog(tokens)
    if prog in _INTERP_PROGS:
        for i, tok in enumerate(tokens):
            if tok in _INTERP_CODE_FLAGS and i + 1 < len(tokens):
                pairs.extend(_loopback_ports_from_code(tokens[i + 1]))
            elif tok.startswith("-") and "=" in tok:
                flag, val = tok.split("=", 1)
                if flag in _INTERP_CODE_FLAGS:
                    pairs.extend(_loopback_ports_from_code(val))
    # 去重（同 host 不同 port 都保留）
    return list(dict.fromkeys(pairs))


class Guard:
    def __init__(
        self, scope: Scope, quarantine_dir: str = "", *,
        objective: str | None = None,
    ) -> None:
        self.scope = scope
        self.quarantine_dir = (quarantine_dir or "").rstrip("/")
        self.objective = objective
        self.self_ports = {int(settings.port), int(settings.frontend_port)}
        self.self_hosts: set[str] = local_self_hosts()
        self.peer_hosts: set[str] = set()
        self.peer_addrs: set[str] = set()
        self.own_addrs: set[str] = set()
        self.primary_port: int | None = None

    def check_command(self, command: str) -> GuardDecision:
        cmd = command.strip()

        for pat in _DESTRUCTIVE:
            if pat.search(cmd):
                return GuardDecision(False, f"拦截破坏性命令：匹配 {pat.pattern}", "destructive")

        why = target_destructive_reason(cmd)
        if why:
            return GuardDecision(
                False,
                f"拦截破坏性操作：{why}。SQLi 只用 SELECT/布尔/报错证明。",
                "destructive",
            )

        if objective_allows_flag(self.objective):
            why = ctf_mega_dict_reason(cmd)
            if why:
                return GuardDecision(False, f"拦截：{why}", "policy")

        for host, port in extract_host_ports(cmd):
            if is_platform_endpoint(host, port, self_hosts=self.self_hosts, self_ports=self.self_ports):
                label = f"{host}:{port}" if port is not None else host
                return GuardDecision(
                    False,
                    f"拦截：不要把本机控制台/物理网卡（{label}）当作作业目标。",
                    "self_protection", hosts=[host],
                )

        if self.quarantine_dir and self.quarantine_dir in cmd:
            if _EXEC_PREFIX_RE.search(cmd) or "chmod" in cmd:
                return GuardDecision(
                    False,
                    "拒绝执行隔离区中的文件，仅允许静态分析。",
                    "honeypot",
                )

        hosts = extract_hosts(cmd)
        primary = ""
        try:
            primary = str((self.scope.targets or [""])[0] or "").split(":")[0]
        except Exception:
            primary = ""
        pairs = list(extract_host_ports(cmd))
        tokens = _safe_split(cmd)
        direct = _direct_connect_hosts(tokens)
        extra_ports: list[int] = []
        for i, tok in enumerate(tokens):
            if tok in ("-p", "--port") and i + 1 < len(tokens):
                raw = tokens[i + 1].split(",")[0].split("-")[0]
                if raw.isdigit():
                    extra_ports.append(int(raw))
        if extra_ports:
            have = {h for h, _ in pairs}
            for h in hosts:
                if h not in have:
                    pairs.append((h, extra_ports[0]))
            pairs = [(h, p if p is not None else (extra_ports[0] if extra_ports else None)) for h, p in pairs]
        for host, port in pairs:
            why = unauthorized_peer_endpoint(
                host, port,
                primary=primary,
                primary_port=getattr(self, "primary_port", None),
                peer_addrs=getattr(self, "peer_addrs", None),
                peers=getattr(self, "peer_hosts", None),
                own_addrs=getattr(self, "own_addrs", None),
            )
            if why:
                return GuardDecision(
                    False,
                    f"拦截越界私网：{why}。只打当前入口；邻题 IP/端口不是横向。",
                    "out_of_scope", hosts=[host],
                )
        for host in hosts:
            why = unauthorized_private_host(
                host, self.scope, primary=primary,
                peers=getattr(self, "peer_hosts", None),
                own_hosts={
                    str(a).split(":")[0] for a in (getattr(self, "own_addrs", None) or set()) if a
                },
            )
            if why:
                if host not in direct:
                    continue
                return GuardDecision(
                    False,
                    f"拦截越界私网：{why}。只打当前入口；邻题 IP 不是横向。",
                    "out_of_scope", hosts=[host],
                )
        return GuardDecision(True, "ok", "ok", hosts=hosts)

    @staticmethod
    def looks_like_honeypot(banner: str) -> tuple[bool, str]:
        """基于响应/横幅的蜜罐启发式识别。返回(是否蜜罐, 理由)。"""
        b = (banner or "").lower()
        signals = [
            ("kippo", "Kippo SSH 蜜罐特征"),
            ("cowrie", "Cowrie SSH 蜜罐特征"),
            ("dionaea", "Dionaea 蜜罐特征"),
            ("t-pot", "T-Pot 蜜罐平台特征"),
            ("honeyd", "Honeyd 蜜罐特征"),
            ("glastopf", "Glastopf Web 蜜罐特征"),
            ("conpot", "Conpot ICS 蜜罐特征"),
        ]
        for kw, why in signals:
            if kw in b:
                return True, why
        # 异常：过多端口同时开放且横幅雷同 → 交由上层结合端口数量判断
        return False, ""
