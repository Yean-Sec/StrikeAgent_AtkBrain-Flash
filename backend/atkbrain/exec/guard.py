"""执行纪律：破坏性命令拦截、勿打本机控制台与物理网卡。"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass

from ..config import settings
from ..objective import objective_allows_flag
from ..scope import (
    Scope,
    attacker_lan_forbidden,
    attacker_loopback_forbidden,
    canonical_host,
    coerce_ip,
    is_attacker_identity,
    is_loopback,
    is_platform_endpoint,
    local_self_hosts,
    parse_scan_network,
    scan_network_forbidden_reason,
    public_hosts_in_text,
    sensitive_attack_reason,
    unauthorized_peer_endpoint,
    unauthorized_private_host,
    unauthorized_public_host,
    on_local_docker_bridge,
    private_out_of_scope_hint,
    public_out_of_scope_hint,
)

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
    "-x", "--proxy", "--socks5", "--socks5-hostname", "--proxy1.0",
    "-o", "-D", "-L", "-R",
}
# 这些选项的“值”本身是一条子命令(如 sh -c '...')，需递归解析出其中真正的连接目标作为兜底。
_SUBCMD_FLAGS = {"-c", "--command"}
# shell 与解释器区分：shell 的 -c 值是子命令(递归)；解释器的代码体是数据(跳过，避免把 Header/payload
# 里的 URL 误当连接目标)。
_SHELL_PROGS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "busybox"}
_INTERP_PROGS = {"python", "python2", "python3", "ruby", "node", "nodejs", "perl", "php", "php7", "php8"}
_INTERP_CODE_FLAGS = {"-c", "-e", "-r", "--eval", "--command"}
# 命令前缀里的“包装器”：定位真正程序名时应跳过它们（及 timeout 的时长参数、VAR=val 赋值）。
_WRAPPERS = {"env", "sudo", "nohup", "stdbuf", "nice", "setsid", "time", "proxychains", "proxychains4", "sshpass"}

# 本地 SOCKS/端口转发：回环是代理入口，不是作业目标。
_LOCAL_PROXY_PORTS = {1080, 1081, 1082, 9050, 9051, 4145, 10800, 8083}


def _local_proxy_ports() -> set[int]:
    return set(_LOCAL_PROXY_PORTS)


_LOCAL_PROXY_HINT_RE = re.compile(
    r"(?:proxychains4?|\bsshpass\b|"
    r"(?:-x|--proxy|--socks5(?:-hostname)?)\b|"
    r"ProxyCommand=|"
    r"\bnc\s+-x\b|"
    r"socks5h?://127\.|"
    r"TCP-LISTEN:|"
    r"\s-(?:D|L|R)\s)",
    re.I,
)


def _loopback_is_local_proxy(command: str, host: str, port: int | None) -> bool:
    """127.0.0.1:1080 / ssh -D / proxychains 是跳板隧道，不是打本机控制台。"""
    if not is_loopback(host):
        return False
    if port is not None and int(port) in _local_proxy_ports():
        return True
    return bool(_LOCAL_PROXY_HINT_RE.search(command or ""))


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
    "studio", "blog", "page", "shop", "news", "media", "link", "space",
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
    (re.compile(r"\bFLUSH(?:ALL|DB)\b", re.I), "FLUSHALL/FLUSHDB 会清空业务缓存"),
    (re.compile(r"\bdropDatabase\b", re.I), "dropDatabase 会删库"),
]

# 红队/SRC：证明漏洞，禁止把写操作落到真实用户、资金、库存。CTF 不套（题解常要改管理员）。
_RESET_PATH_RE = re.compile(
    r"(?:/|\b)(?:reset[-_]?pass(?:word)?|forgot[-_]?pass(?:word)?|change[-_]?pass(?:word)?|"
    r"changepwd|password[-_]?reset|passwd[-_]?reset|update[-_]?pass(?:word)?|"
    r"set[-_]?pass(?:word)?)\b",
    re.I,
)
_NEW_PASS_FIELD_RE = re.compile(
    r"\b(?:new[_-]?pass(?:word)?|password[_-]?confirm(?:ation)?|confirm[_-]?password|"
    r"re[_-]?password)\s*=",
    re.I,
)
_ADMIN_OR_VICTIM_RE = re.compile(
    r"(?:user(?:name|_name)?|account|email|login)\s*=\s*['\"]?(?:admin|root|administrator)\b|"
    r"[?&](?:uid|user_id|userId|account_id)=(?:1|admin|root)\b|"
    r"\b(?:admin|root|administrator)@[a-z0-9.-]+",
    re.I,
)
_BIND_PATH_RE = re.compile(
    r"(?:/|\b)(?:bind[-_]?(?:mobile|phone|email)|change[-_]?(?:email|mobile|phone)|"
    r"unbind[-_]?(?:mobile|phone|email)?)\b",
    re.I,
)
_LOGIN_PATH_RE = re.compile(r"(?:/|\b)login(?:\b|/|\.php|\.do|\.action|\?)", re.I)
_WRITE_HTTP_RE = re.compile(
    r"(?:^|[\s;&|])(?:PUT|POST|PATCH|DELETE)\b|"
    r"\s-(?:X|-request)\s+(?:PUT|POST|PATCH|DELETE)\b|"
    r"\s(?:-d|--data(?:-raw|-binary|-ascii|-urlencode)?|--json|-F|--form)\s",
    re.I,
)
_PAY_PATH_RE = re.compile(
    r"(?:/|\b)(?:pay(?:ment|pal)?|refund|transfer|checkout|alipay|wxpay|"
    r"wechat[-_]?pay|unionpay|create[-_]?order|place[-_]?order)\b",
    re.I,
)
_MONEY_FIELD_RE = re.compile(
    r"\b(?:amount|price|money|total|pay[_-]?amount|fee|cash|coupon|points|integral)\s*=",
    re.I,
)
_NOTIFY_PATH_RE = re.compile(
    r"(?:/|\b)(?:sms|send[-_]?code|verify[-_]?code|vcode|otp|"
    r"send[-_]?(?:sms|email|voice|mail)|captcha[-_]?sms)\b",
    re.I,
)
_LOOP_RE = re.compile(
    r"\b(?:for|while)\b.{0,120}(?:sms|send[-_]?code|verify|curl|http)|"
    r"\bseq\s+\d+\s+\d+\s*\||"
    r"\bxargs\s+-P\b|"
    r"\{1?\.\.(?:[2-9]\d|\d{3,})\}",
    re.I,
)
_DOS_RE = re.compile(
    r"(?:^|[;&|\s])(?:ab|hey|wrk|siege|bombardier|slowloris|hping3?)\s+-"
    r"|\bxargs\s+-P\s*(?:[4-9]|\d{2,})\b"
    r"|\bparallel\b.{0,80}\bcurl\b",
    re.I,
)
_OTHER_MUTATE_RE = re.compile(
    r"(?:/|\b)(?:cancel[-_]?order|close[-_]?account|destroy[-_]?user|"
    r"delete[-_]?user|unregister|deactivate[-_]?account)\b",
    re.I,
)
_BIZ_RM_RE = re.compile(
    r"\brm\s+-rf\s+(?:/var/www|/usr/share/nginx|/opt/|/home/www)",
    re.I,
)
# 红队/SRC：口令喷洒会锁线上账号，也超出「证明漏洞」的授权。
_SPRAY_TOOL_RE = re.compile(
    r"(?:^|[\s;&|`(])(?:/usr/(?:s?bin)/)?(?:hydra|medusa|ncrack|patator)\b",
    re.I,
)
# 红队/SRC：不在目标上留账号、计划任务或开机项。
_PERSIST_RE = re.compile(
    r"(?:^|[\s;&|`(])(?:crontab|useradd|adduser|schtasks)\b"
    r"|\bauthorized_keys\b"
    r"|\bnet\s+user\b"
    r"|\bsystemctl\s+(?:enable|start)\b"
    r"|/etc/rc\.local\b",
    re.I,
)

# 超过 10 万行的词表：CTF 与红队一律拦截（目录/口令/子域/host/哈希）。
_MEGA_WORDLIST_RE = re.compile(
    r"rockyou|"
    r"directory-list-2\.3-medium|"
    r"directory-list-2\.3-large|"
    r"crackstation|"
    r"10[-_]?million[-_]?password|"
    r"hashed[-_]?password|"
    r"darkc0de|"
    r"raft[-_]?large|"
    r"seclists/.*/Passwords/.{0,80}(?:large|huge|million|rockyou)",
    re.I,
)

# CTF 额外：禁止 hashcat / john --wordlist 去撞哈希（即使用未超 10 万的表）。
_CTF_MEGA_DICT_RE = re.compile(
    r"\bhashcat\b|"
    r"\bjohn(?:the(?:ripper)?)?\b.{0,120}--wordlist",
    re.I,
)


def mega_wordlist_reason(text: str | None) -> str | None:
    """CTF 与红队禁止超过 10 万行的词表。命中则返回原因。"""
    blob = text or ""
    if not blob.strip():
        return None
    if _MEGA_WORDLIST_RE.search(blob):
        return (
            "禁止超级大字典：词表不得超过 10 万行（目录/子域/host 碰撞/口令/哈希一律）。"
            "不要用 rockyou 或 dirbuster medium（220560）；目录最大中档 87664。"
        )
    return None


def ctf_mega_dict_reason(text: str | None) -> str | None:
    """CTF 禁止千万级词表与 hashcat/john 撞哈希。命中则返回原因。"""
    why = mega_wordlist_reason(text)
    if why:
        return (
            "CTF 必有解，禁止超级大字典撞库/撞哈希。"
            "题面账号或个位数默认口令即可；送达认证接口后失败不要升字典。"
        )
    blob = text or ""
    if not blob.strip():
        return None
    if _CTF_MEGA_DICT_RE.search(blob):
        return (
            "CTF 必有解，禁止超级大字典撞库/撞哈希。"
            "题面账号或个位数默认口令即可；送达认证接口后失败不要升字典。"
        )
    return None


def _is_auth_login(blob: str) -> bool:
    if _RESET_PATH_RE.search(blob) or _BIND_PATH_RE.search(blob):
        return False
    return bool(_LOGIN_PATH_RE.search(blob))


def _looks_like_write_http(blob: str) -> bool:
    return bool(_WRITE_HTTP_RE.search(blob))


def _business_mutation_reason(blob: str) -> str | None:
    """红队/SRC：身份落地、资金提交、通知轰炸、高并发写、他人资料删改。"""
    if _SPRAY_TOOL_RE.search(blob):
        return "禁止口令喷洒（hydra/medusa/ncrack/patator）；会锁线上账号，也超出授权证明"
    if _PERSIST_RE.search(blob):
        return "禁止在目标上留账号、计划任务或开机项；只做当次可复现的证明"
    if _DOS_RE.search(blob):
        return "高并发写/压测工具会把业务打挂；最多对自己的测试对象做 2 路对照"
    if _BIZ_RM_RE.search(blob):
        return "禁止删除业务站点目录"
    if _OTHER_MUTATE_RE.search(blob) and _looks_like_write_http(blob):
        return "禁止对线上订单/账号做取消、销户、销毁"
    if not _is_auth_login(blob):
        if _RESET_PATH_RE.search(blob) and (
            _NEW_PASS_FIELD_RE.search(blob) or _ADMIN_OR_VICTIM_RE.search(blob)
        ):
            return "禁止覆盖已有管理员/他人口令；只证明 token/IDOR，不提交落地"
        if _BIND_PATH_RE.search(blob) and (
            _ADMIN_OR_VICTIM_RE.search(blob) or re.search(r"[?&](?:uid|user_id|userId)=", blob)
        ):
            return "禁止给他人账号换绑手机/邮箱"
    if _PAY_PATH_RE.search(blob) and _MONEY_FIELD_RE.search(blob) and _looks_like_write_http(blob):
        return "禁止提交支付/退款/转账落地；看回包差分即可"
    if _NOTIFY_PATH_RE.search(blob) and _LOOP_RE.search(blob):
        return "禁止短信/邮件验证码循环轰炸"
    return None


def target_destructive_reason(text: str | None, *, objective: str | None = None) -> str | None:
    """业务环境禁止的破坏性 payload/命令。命中则返回原因。

    SQL 写三赛道都拦。改密/资金/轰炸/高并发写仅红队与 SRC。
    """
    blob = text or ""
    if not blob.strip():
        return None
    for pat, why in _TARGET_DESTRUCTIVE:
        if pat.search(blob):
            return why
    if not objective_allows_flag(objective):
        why = _business_mutation_reason(blob)
        if why:
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
        raw = tok
        if "@" in raw and "://" not in raw.split("@", 1)[0]:
            raw = raw.rsplit("@", 1)[-1]
        # 2) 裸 IPv4(:port) 或 user@IPv4
        m = _IP_TOKEN_RE.match(raw)
        if m:
            hosts.add(m.group(1).lower())
            continue
        # 2.5) localhost 别名
        m = _LOOPBACK_NAME_RE.match(raw)
        if m:
            hosts.add(m.group(1).lower())
            continue
        # 3) 裸域名(:port)：整 token 匹配 + 真实 TLD + 非文件扩展名
        m = _DOMAIN_TOKEN_RE.match(raw)
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
    "nmap", "masscan", "ffuf", "feroxbuster", "gobuster", "sqlmap", "nikto",
    "redis-cli", "mysql", "psql", "mongo", "ftp", "lftp", "smbclient", "rpcclient",
    "hydra", "nuclei", "whatweb", "wafw00f", "nxc", "crackmapexec", "smbmap",
}
_CONNECT_URL_FLAGS = {"-u", "--url", "--host"}
_CMD_BREAK = {";", "&&", "||", "|"}
_CIDR_TOKEN_RE = re.compile(r"^((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$")
_ALT_HOSTPORT_RE = re.compile(
    r"^(0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}(?::(\d{1,5}))?$",
    re.I,
)


def _connect_token_hostport(tok: str) -> tuple[str | None, int | None]:
    """直连参数上的主机（含十进制/短写 IPv4），不含 -d 载荷。"""
    h, p = _token_hostport(tok)
    if h:
        return h, p
    raw = tok.strip().strip("'\"")
    m = _CIDR_TOKEN_RE.match(raw)
    if m:
        return None, None
    m = _ALT_HOSTPORT_RE.match(raw)
    if m and coerce_ip(raw.split(":")[0]):
        return raw.split(":")[0].lower(), int(m.group(2)) if m.group(2) else _port_of(raw)
    return None, None


def _add_direct_token(
    tok: str,
    hosts: set[str],
    pairs: list[tuple[str, int | None]],
    cidrs: list[ipaddress.IPv4Network],
) -> None:
    raw = (tok or "").strip().strip("'\"")
    if not raw:
        return
    net = parse_scan_network(raw)
    if net is not None:
        cidrs.append(net)
        return
    h, p = _connect_token_hostport(raw)
    if h:
        hosts.add(h)
        pairs.append((h, p))


def _direct_connect_targets(
    tokens: list[str],
    depth: int = 0,
) -> tuple[set[str], list[tuple[str, int | None]], list[ipaddress.IPv4Network]]:
    """curl/nmap 等真正发起的连接目标；for 列表 / -d 载荷里的 URL 不算。"""
    hosts: set[str] = set()
    pairs: list[tuple[str, int | None]] = []
    cidrs: list[ipaddress.IPv4Network] = []
    if depth > 3:
        return hosts, pairs, cidrs
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if "://" in tok:
            i += 1
            continue
        b = tok.rsplit("/", 1)[-1].lower()
        if not tok.startswith("-") and "=" in tok:
            i += 1
            continue
        if b in _WRAPPERS:
            i += 1
            continue
        if b == "timeout":
            i += 2
            continue
        if b in _SHELL_PROGS:
            j = i + 1
            while j < n and tokens[j] not in _CMD_BREAK:
                t = tokens[j]
                if t.startswith("-") and "=" in t:
                    flag, val = t.split("=", 1)
                    if flag in _SUBCMD_FLAGS:
                        h2, p2, c2 = _direct_connect_targets(_safe_split(val), depth + 1)
                        hosts |= h2
                        pairs.extend(p2)
                        cidrs.extend(c2)
                    j += 1
                    continue
                if t in _SUBCMD_FLAGS and j + 1 < n:
                    h2, p2, c2 = _direct_connect_targets(_safe_split(tokens[j + 1]), depth + 1)
                    hosts |= h2
                    pairs.extend(p2)
                    cidrs.extend(c2)
                    j += 2
                    continue
                j += 1
            i = j
            continue
        if b in _CONNECT_PROGS:
            j = i + 1
            skip_next = False
            while j < n and tokens[j] not in _CMD_BREAK:
                t = tokens[j]
                if skip_next:
                    skip_next = False
                    j += 1
                    continue
                if t.startswith("-") and "=" in t:
                    flag, val = t.split("=", 1)
                    if flag in _SKIP_VALUE_FLAGS:
                        j += 1
                        continue
                    if flag in _CONNECT_URL_FLAGS:
                        _add_direct_token(val, hosts, pairs, cidrs)
                    j += 1
                    continue
                if t in _SKIP_VALUE_FLAGS:
                    skip_next = True
                    j += 1
                    continue
                if t in _CONNECT_URL_FLAGS and j + 1 < n:
                    _add_direct_token(tokens[j + 1], hosts, pairs, cidrs)
                    j += 2
                    continue
                if t.startswith("-"):
                    j += 1
                    continue
                _add_direct_token(t, hosts, pairs, cidrs)
                j += 1
            i = j
            continue
        i += 1
    return hosts, pairs, cidrs


def _direct_connect_hosts(tokens: list[str]) -> set[str]:
    hosts, _pairs, _cidrs = _direct_connect_targets(tokens)
    return hosts


def _interp_loopback_pairs(tokens: list[str]) -> list[tuple[str, int | None]]:
    prog = _leading_prog(tokens)
    if prog not in _INTERP_PROGS:
        return []
    pairs: list[tuple[str, int | None]] = []
    for i, tok in enumerate(tokens):
        if tok in _INTERP_CODE_FLAGS and i + 1 < len(tokens):
            pairs.extend(_loopback_ports_from_code(tokens[i + 1]))
        elif tok.startswith("-") and "=" in tok:
            flag, val = tok.split("=", 1)
            if flag in _INTERP_CODE_FLAGS:
                pairs.extend(_loopback_ports_from_code(val))
    return list(dict.fromkeys(pairs))


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
    raw = (tok or "").strip().strip("'\"")
    if "@" in raw and "://" not in raw.split("@", 1)[0]:
        # ssh user@host[:port] / sshpass 目标
        raw = raw.rsplit("@", 1)[-1]
        tok = raw
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
        self.workspace_dir: str = ""
        self.has_intranet_precondition: bool = False
        self.via_capability_hosts: set[str] = set()
        self.allowed_secrets: set[str] = set()

    def _authorized_hosts(self) -> set[str]:
        out: set[str] = set()
        for t in self.scope.targets or []:
            h = str(t or "").split(":")[0].strip()
            if h:
                out.add(h)
        for ip in self.scope.ips or []:
            h = str(ip or "").split(":")[0].strip()
            if h:
                out.add(h)
        for a in getattr(self, "own_addrs", None) or ():
            h = str(a or "").split(":")[0].strip()
            if h:
                out.add(h)
        return out

    def check_command(self, command: str) -> GuardDecision:
        cmd = command.strip()

        for pat in _DESTRUCTIVE:
            if pat.search(cmd):
                return GuardDecision(False, f"拦截破坏性命令：匹配 {pat.pattern}", "destructive")

        for h in public_hosts_in_text(cmd):
            why = sensitive_attack_reason(h)
            if why:
                return GuardDecision(False, f"拦截：{why}", "policy", hosts=[h])

        why = target_destructive_reason(cmd, objective=self.objective)
        if why:
            hint = (
                "SQLi 只用 SELECT/布尔/报错证明。"
                if "SQL" in why or "sqlmap" in why.lower() or "DUMPFILE" in why or "OUTFILE" in why
                else "只证明、不落地。"
            )
            return GuardDecision(
                False,
                f"拦截破坏性操作：{why}。{hint}",
                "destructive",
            )

        why = mega_wordlist_reason(cmd)
        if why:
            return GuardDecision(False, f"拦截：{why}", "policy")

        if objective_allows_flag(self.objective):
            why = ctf_mega_dict_reason(cmd)
            if why:
                return GuardDecision(False, f"拦截：{why}", "policy")
        else:
            try:
                from ..proxy.pool import pool as _proxy_pool
                must_px = _proxy_pool.must_proxy(self.objective)
            except Exception:
                must_px = False
            if must_px:
                from ..proxy.enforce import proxy_bypass_reason
                why = proxy_bypass_reason(cmd)
                if why:
                    return GuardDecision(False, f"拦截：{why}", "proxy")

        if self.quarantine_dir and self.quarantine_dir in cmd:
            if _EXEC_PREFIX_RE.search(cmd) or "chmod" in cmd:
                return GuardDecision(
                    False,
                    "拒绝执行隔离区中的文件，仅允许静态分析。",
                    "honeypot",
                )

        tokens = _safe_split(cmd)
        direct_hosts, direct_pairs, direct_cidrs = _direct_connect_targets(tokens)
        extra_ports: list[int] = []
        for i, tok in enumerate(tokens):
            if tok in ("-p", "--port") and i + 1 < len(tokens):
                raw = tokens[i + 1].split(",")[0].split("-")[0]
                if raw.isdigit():
                    extra_ports.append(int(raw))
        pairs: list[tuple[str, int | None]] = list(direct_pairs)
        have = {h for h, _ in pairs}
        for h in direct_hosts:
            if h not in have:
                pairs.append((h, extra_ports[0] if extra_ports else None))
                have.add(h)
        if extra_ports:
            pairs = [
                (h, p if p is not None else extra_ports[0])
                for h, p in pairs
            ]

        primary = ""
        try:
            primary = str((self.scope.targets or [""])[0] or "").split(":")[0]
        except Exception:
            primary = ""
        authorized = self._authorized_hosts()
        own_hosts = {
            str(a).split(":")[0] for a in (getattr(self, "own_addrs", None) or set()) if a
        }
        self_hosts = self.self_hosts

        for host, port in pairs:
            ch = canonical_host(host)
            if is_platform_endpoint(
                ch, port, self_hosts=self_hosts, self_ports=self.self_ports,
            ):
                label = f"{ch}:{port}" if port is not None else ch
                return GuardDecision(
                    False,
                    f"拦截：不要把本机控制台/物理网卡（{label}）当作作业目标。",
                    "self_protection", hosts=[ch],
                )
            why = attacker_loopback_forbidden(ch, authorized=authorized)
            if why and not _loopback_is_local_proxy(cmd, ch, port):
                return GuardDecision(
                    False,
                    f"拦截：{why}。SSRF 载荷请放进 -d/--data，不要让 Kali 直连 127.0.0.0/8。"
                    "本地 SOCKS/ssh -D 转发端口除外。",
                    "self_protection", hosts=[ch],
                )
            if is_attacker_identity(ch, extra=self_hosts):
                return GuardDecision(
                    False,
                    f"拦截：{ch} 是本机网卡或物机网关，禁止直连物理机。",
                    "self_protection", hosts=[ch],
                )
            why = attacker_lan_forbidden(ch, self_hosts=self_hosts)
            if why:
                return GuardDecision(
                    False,
                    f"拦截：{why}。本机网卡和物机网关是守卫，不是目标。",
                    "self_protection", hosts=[ch],
                )
            why = on_local_docker_bridge(ch, allow=own_hosts | {primary})
            if why:
                return GuardDecision(
                    False,
                    f"拦截：{why}。经已有 SSRF/shell 中转；sshpass 只打题目入口上的监听端口。",
                    "self_protection", hosts=[ch],
                )
            why = unauthorized_peer_endpoint(
                ch, port,
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
                    "out_of_scope", hosts=[ch],
                )
            try:
                from ..engine.hop_auth_gate import apply_kali_direct_reason, ssh_auth_block_reason
                via_why = apply_kali_direct_reason(ch, self)
                if via_why:
                    return GuardDecision(False, f"拦截：{via_why}", "out_of_scope", hosts=[ch])
                ssh_why = ssh_auth_block_reason(
                    cmd, host=ch, port=port,
                    workspace_dir=str(getattr(self, "workspace_dir", "") or ""),
                    allowed_secrets=set(getattr(self, "allowed_secrets", None) or ()),
                )
                if ssh_why:
                    return GuardDecision(False, f"拦截：{ssh_why}", "policy", hosts=[ch])
            except Exception:
                pass
            why = unauthorized_private_host(
                ch, self.scope, primary=primary,
                peers=getattr(self, "peer_hosts", None),
                own_hosts=own_hosts,
            )
            if why:
                return GuardDecision(
                    False,
                    f"拦截越界私网：{private_out_of_scope_hint(why)}",
                    "out_of_scope", hosts=[ch],
                )
            why = unauthorized_public_host(ch, self.scope, primary=primary)
            if why:
                return GuardDecision(
                    False,
                    f"拦截越界公网：{public_out_of_scope_hint(why)}",
                    "out_of_scope", hosts=[ch],
                )

        seen_nets: set[str] = set()
        for net in direct_cidrs:
            key = str(net)
            if key in seen_nets:
                continue
            seen_nets.add(key)
            why = scan_network_forbidden_reason(str(net), self.scope, extra_self=self_hosts)
            if why:
                cat = (
                    "self_protection"
                    if ("命中攻击机本机网卡或物机网关" in why or "物机网关" in why)
                    else "scope"
                )
                return GuardDecision(
                    False,
                    f"{why}",
                    cat, hosts=[str(net)],
                )

        for host, port in _interp_loopback_pairs(tokens):
            ch = canonical_host(host)
            if is_platform_endpoint(
                ch, port, self_hosts=self_hosts, self_ports=self.self_ports,
            ):
                label = f"{ch}:{port}" if port is not None else ch
                return GuardDecision(
                    False,
                    f"拦截：不要把本机控制台/物理网卡（{label}）当作作业目标。",
                    "self_protection", hosts=[ch],
                )

        return GuardDecision(True, "ok", "ok", hosts=sorted(direct_hosts))

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
