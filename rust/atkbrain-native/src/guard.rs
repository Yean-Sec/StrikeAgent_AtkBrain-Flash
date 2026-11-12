//! 命令里的主机提取和破坏性写入拒绝。真正执行仍在 Python。

use pyo3::exceptions::{PyLookupError, PyPermissionError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::net::{coerce_ip, is_loopback_host};
use crate::objective::objective_allows_flag;
use crate::scope::scope_parse_scan;

static MEGA: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)rockyou|directory-list-2\.3-medium|directory-list-2\.3-large|crackstation|10[-_]?million[-_]?password|hashed[-_]?password|darkc0de|raft[-_]?large|seclists/.*/Passwords/.{0,80}(?:large|huge|million|rockyou)"#).unwrap()
});
static CTF_DICT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\bhashcat\b|\bjohn(?:the(?:ripper)?)?\b.{0,120}--wordlist"#).unwrap());

fn destructive() -> Vec<(Regex, &'static str)> {
    vec![
        (Regex::new(r#"(?i)\bdrop\s+(?:table|database|schema|index)\b"#).unwrap(), "DROP TABLE/DATABASE 等破坏性 SQL"),
        (Regex::new(r#"(?i)\btruncate\s+(?:table\s+)?[`\"'\w]"#).unwrap(), "TRUNCATE 破坏性 SQL"),
        (Regex::new(r#"(?i)\bdelete\s+from\s+"#).unwrap(), "DELETE FROM 破坏性 SQL"),
        (Regex::new(r#"(?i)\balter\s+table\s+\S+\s+drop\b"#).unwrap(), "ALTER TABLE DROP 破坏性 SQL"),
        (Regex::new(r#"(?i)\binsert\s+into\s+"#).unwrap(), "INSERT INTO 会往业务库写垃圾数据"),
        (Regex::new(r#"(?i)\breplace\s+into\s+"#).unwrap(), "REPLACE INTO 会改写业务数据"),
        (Regex::new(r#"(?i)\bupdate\s+\S+\s+set\s+"#).unwrap(), "UPDATE SET 会改业务数据"),
        (Regex::new(r#"(?i)\bload\s+data\s+(?:local\s+)?infile\b"#).unwrap(), "LOAD DATA INFILE 会写库"),
        (Regex::new(r#"(?i)\binto\s+(?:dumpfile|outfile)\b"#).unwrap(), "INTO OUTFILE/DUMPFILE 会在目标落盘"),
        (Regex::new(r#"(?i)sqlmap[^\n]*--file-write\b"#).unwrap(), "sqlmap --file-write 会在目标写文件"),
        (Regex::new(r#"(?i)sqlmap[^\n]*--sql-query=['\"][^'\"]*\b(?:insert|update|replace)\b"#).unwrap(), "sqlmap 写库语句"),
        (Regex::new(r#"(?i)sqlmap[^\n]*--os-shell\b"#).unwrap(), "sqlmap --os-shell 对业务环境过重"),
        (Regex::new(r#"(?i)sqlmap[^\n]*--os-cmd[^\n]*\b(?:rm\s+-|del\s+/|rd\s+/s)"#).unwrap(), "sqlmap --os-cmd 含删除"),
        (Regex::new(r#"(?i)[?&](?:action|op|do|operate|method|cmd|act)=(?:delete|remove|unlink|destroy|drop)\b"#).unwrap(), "请求会触发删除动作"),
        (Regex::new(r#"\bFLUSH(?:ALL|DB)\b"#).unwrap(), "FLUSHALL/FLUSHDB 会清空业务缓存"),
        (Regex::new(r#"\bdropDatabase\b"#).unwrap(), "dropDatabase 会删库"),
    ]
}

static SPRAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:^|[\s;&|`(])(?:/usr/(?:s?bin)/)?(?:hydra|medusa|ncrack|patator)\b"#).unwrap());
static PERSIST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:^|[\s;&|`(])(?:crontab|useradd|adduser|schtasks)\b|\bauthorized_keys\b|\bnet\s+user\b|\bsystemctl\s+(?:enable|start)\b|/etc/rc\.local\b"#).unwrap());
static DOS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:^|[;&|\s])(?:ab|hey|wrk|siege|bombardier|slowloris|hping3?)\s+-|\bxargs\s+-P\s*(?:[4-9]|\d{2,})\b|\bparallel\b.{0,80}\bcurl\b"#).unwrap());
static BIZ_RM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\brm\s+-rf\s+(?:/var/www|/usr/share/nginx|/opt/|/home/www)"#).unwrap());
static OTHER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)(?:cancel[-_]?order|close[-_]?account|destroy[-_]?user|delete[-_]?user|unregister|deactivate[-_]?account)\b"#).unwrap());
static RESET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)(?:reset[-_]?pass(?:word)?|forgot[-_]?pass(?:word)?|change[-_]?pass(?:word)?|changepwd|password[-_]?reset|passwd[-_]?reset|update[-_]?pass(?:word)?|set[-_]?pass(?:word)?)\b"#).unwrap());
static NEWPASS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:new[_-]?pass(?:word)?|password[_-]?confirm(?:ation)?|confirm[_-]?password|re[_-]?password)\s*="#).unwrap());
static ADMIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r###"(?i)(?:user(?:name|_name)?|account|email|login)\s*=\s*['\"]?(?:admin|root|administrator)\b|[?&](?:uid|user_id|userId|account_id)=(?:1|admin|root)\b|\b(?:admin|root|administrator)@[a-z0-9.-]+"###).unwrap());
static BIND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)(?:bind[-_]?(?:mobile|phone|email)|change[-_]?(?:email|mobile|phone)|unbind[-_]?(?:mobile|phone|email)?)\b"#).unwrap());
static LOGIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)login(?:\b|/|\.php|\.do|\.action|\?)"#).unwrap());
static WRITE_HTTP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:^|[\s;&|])(?:PUT|POST|PATCH|DELETE)\b|\s-(?:X|-request)\s+(?:PUT|POST|PATCH|DELETE)\b|\s(?:-d|--data(?:-raw|-binary|-ascii|-urlencode)?|--json|-F|--form)\s"#).unwrap());
static PAY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)(?:pay(?:ment|pal)?|refund|transfer|checkout|alipay|wxpay|wechat[-_]?pay|unionpay|create[-_]?order|place[-_]?order)\b"#).unwrap());
static MONEY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:amount|price|money|total|pay[_-]?amount|fee|cash|coupon|points|integral)\s*="#).unwrap());
static NOTIFY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:/|\b)(?:sms|send[-_]?code|verify[-_]?code|vcode|otp|send[-_]?(?:sms|email|voice|mail)|captcha[-_]?sms)\b"#).unwrap());
static LOOP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(?:for|while)\b.{0,120}(?:sms|send[-_]?code|verify|curl|http)|\bseq\s+\d+\s+\d+\s*\||\bxargs\s+-P\b|\{1?\.\.(?:[2-9]\d|\d{3,})\}"#).unwrap());
static SCHEME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^["']?(?:https?|ftp|ftps|ssh|sftp|smb|cifs|rdp|mysql|redis|mongodb|postgres(?:ql)?|gopher|dict|ldaps?|telnet|vnc|memcached?|rtsp|ws|wss)://([^/\\\s?#'"]+)"#).unwrap());
static IP_TOK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?$"#).unwrap());
static LOOP_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^(localhost|ip6-localhost)(?::(\d{1,5}))?$"#).unwrap());
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?::\d+)?$"#).unwrap());
static LOOP_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:https?://)?(127(?:\.\d{1,3}){1,3}|localhost|::1|0\.0\.0\.0)(?::(\d{1,5}))?"#).unwrap());
static HOSTCHARS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[A-Za-z0-9._\-]+"#).unwrap());
static HOSTPORT_CORE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[A-Za-z0-9._\-]+(?::\d+)?"#).unwrap());
static TRAIL_PORT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#":(\d{1,5})$"#).unwrap());
static ALT_HOST: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)^(0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){0,3}(?::(\d{1,5}))?$"#).unwrap());

const REAL_TLDS: &[&str] = &[
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "ai", "app", "dev",
    "cloud", "cn", "uk", "de", "jp", "ru", "fr", "us", "eu", "in", "br", "au", "ca",
    "info", "biz", "xyz", "top", "site", "online", "store", "tech", "me", "tv", "cc",
    "pro", "vip", "work", "live", "team", "group", "network", "systems", "host",
    "kr", "hk", "tw", "sg", "nl", "it", "es", "se", "no", "fi", "pl", "cz", "ch",
    "studio", "blog", "page", "shop", "news", "media", "link", "space",
];
const FILE_EXTS: &[&str] = &[
    "py", "sh", "txt", "json", "md", "js", "ts", "log", "conf", "cfg", "ini",
    "xml", "yaml", "yml", "html", "htm", "php", "jsp", "asp", "aspx", "jspx",
    "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "jar", "war", "class",
    "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp", "pdf", "doc",
    "docx", "xls", "xlsx", "ppt", "pptx", "csv", "sql", "db", "bak", "old",
    "so", "dll", "exe", "bin", "dat", "pem", "key", "crt", "cer", "pcap",
    "css", "map", "woff", "woff2", "ttf", "mp4", "mp3", "avi", "iso", "img",
];
fn skip_flags() -> &'static [&'static str] {
    &[
        "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode",
        "--form-string", "-F", "--form", "-H", "--header", "-b", "--cookie", "--cookie-jar",
        "-A", "--user-agent", "-e", "--referer", "--json", "--url-query",
        "--mail-from", "--mail-rcpt", "--aws-sigv4", "--oauth2-bearer",
        "-x", "--proxy", "--socks5", "--socks5-hostname", "--proxy1.0",
        "-o", "-D", "-L", "-R",
    ]
}
fn subcmd() -> &'static [&'static str] { &["-c", "--command"] }
fn interp() -> &'static [&'static str] { &["python", "python2", "python3", "ruby", "node", "nodejs", "perl", "php", "php7", "php8"] }
fn code_flags() -> &'static [&'static str] { &["-c", "-e", "-r", "--eval", "--command"] }
fn wrappers() -> &'static [&'static str] { &["env", "sudo", "nohup", "stdbuf", "nice", "setsid", "time", "proxychains", "proxychains4", "sshpass"] }

fn has(list: &[&str], s: &str) -> bool { list.iter().any(|x| *x == s) }

fn mega_reason(text: &str) -> Option<&'static str> {
    if text.trim().is_empty() {
        return None;
    }
    if MEGA.is_match(text) {
        return Some("禁止超级大字典：词表不得超过 10 万行（目录/子域/host 碰撞/口令/哈希一律）。不要用 rockyou 或 dirbuster medium（220560）；目录最大中档 87664。");
    }
    None
}

fn business(blob: &str) -> Option<&'static str> {
    if SPRAY.is_match(blob) {
        return Some("禁止口令喷洒（hydra/medusa/ncrack/patator）；会锁线上账号，也超出授权证明");
    }
    if PERSIST.is_match(blob) {
        return Some("禁止在目标上留账号、计划任务或开机项；只做当次可复现的证明");
    }
    if DOS.is_match(blob) {
        return Some("高并发写/压测工具会把业务打挂；最多对自己的测试对象做 2 路对照");
    }
    if BIZ_RM.is_match(blob) {
        return Some("禁止删除业务站点目录");
    }
    if OTHER.is_match(blob) && WRITE_HTTP.is_match(blob) {
        return Some("禁止对线上订单/账号做取消、销户、销毁");
    }
    let login = !(RESET.is_match(blob) || BIND.is_match(blob)) && LOGIN.is_match(blob);
    if !login {
        if RESET.is_match(blob) && (NEWPASS.is_match(blob) || ADMIN.is_match(blob)) {
            return Some("禁止覆盖已有管理员/他人口令；只证明 token/IDOR，不提交落地");
        }
        if BIND.is_match(blob) && (ADMIN.is_match(blob) || Regex::new(r#"[?&](?:uid|user_id|userId)="#).unwrap().is_match(blob)) {
            return Some("禁止给他人账号换绑手机/邮箱");
        }
    }
    if PAY.is_match(blob) && MONEY.is_match(blob) && WRITE_HTTP.is_match(blob) {
        return Some("禁止提交支付/退款/转账落地；看回包差分即可");
    }
    if NOTIFY.is_match(blob) && LOOP.is_match(blob) {
        return Some("禁止短信/邮件验证码循环轰炸");
    }
    None
}

#[pyfunction]
pub fn guard_mega_wordlist(text: Option<&str>) -> Option<String> {
    mega_reason(text.unwrap_or("")).map(|s| s.to_string())
}

#[pyfunction]
pub fn guard_ctf_mega(text: Option<&str>) -> Option<String> {
    let text = text.unwrap_or("");
    if mega_reason(text).is_some() || CTF_DICT.is_match(text) && !text.trim().is_empty() {
        if text.trim().is_empty() {
            return None;
        }
        if mega_reason(text).is_some() || CTF_DICT.is_match(text) {
            return Some("CTF 必有解，禁止超级大字典撞库/撞哈希。题面账号或个位数默认口令即可；送达认证接口后失败不要升字典。".into());
        }
    }
    None
}

#[pyfunction]
pub fn guard_destructive(text: Option<&str>, objective: Option<&str>) -> Option<String> {
    let blob = text.unwrap_or("");
    if blob.trim().is_empty() {
        return None;
    }
    for (pat, why) in destructive() {
        if pat.is_match(blob) {
            return Some(why.to_string());
        }
    }
    if !objective_allows_flag(objective) {
        return business(blob).map(|s| s.to_string());
    }
    None
}

fn safe_split(command: &str) -> Vec<String> {
    shlex::split(command).unwrap_or_else(|| command.split_whitespace().map(|s| s.to_string()).collect())
}

fn leading_prog(tokens: &[String]) -> String {
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        let b = t.rsplit('/').next().unwrap_or(t);
        if !t.starts_with('-') && t.contains('=') {
            i += 1;
            continue;
        }
        if has(wrappers(), b) {
            i += 1;
            continue;
        }
        if b == "timeout" {
            i += 2;
            continue;
        }
        return b.to_string();
    }
    String::new()
}

fn authority(token: &str) -> Option<String> {
    let c = SCHEME.captures(token)?;
    let mut auth = c.get(1)?.as_str().rsplit('@').next().unwrap_or("").to_string();
    if auth.starts_with('[') {
        let host = auth.split(']').next().unwrap_or("").trim_start_matches('[').to_ascii_lowercase();
        return if host.is_empty() { None } else { Some(host) };
    }
    if let Some(m) = HOSTCHARS.find(&auth) {
        auth = m.as_str().to_string();
    }
    let host = auth.split(':').next().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

fn hosts_from(tokens: &[String], depth: usize) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let mut skip_next = false;
    let mut recurse_next = false;
    let prog = leading_prog(tokens);
    let is_interp = has(interp(), &prog);
    for tok in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if recurse_next {
            recurse_next = false;
            if depth < 2 {
                hosts.extend(hosts_from(&safe_split(tok), depth + 1));
            }
            continue;
        }
        let mut tok = tok.clone();
        if tok.starts_with('-') && tok.contains('=') {
            let (flag, val) = tok.split_once('=').unwrap();
            if has(skip_flags(), flag) {
                continue;
            }
            if is_interp && has(code_flags(), flag) {
                continue;
            }
            if !is_interp && has(subcmd(), flag) {
                if depth < 2 {
                    hosts.extend(hosts_from(&safe_split(val), depth + 1));
                }
                continue;
            }
            tok = val.to_string();
        } else if has(skip_flags(), &tok) {
            skip_next = true;
            continue;
        } else if is_interp && has(code_flags(), &tok) {
            skip_next = true;
            continue;
        } else if !is_interp && has(subcmd(), &tok) {
            recurse_next = true;
            continue;
        }
        if let Some(h) = authority(&tok) {
            hosts.insert(h);
            continue;
        }
        let mut raw = tok.clone();
        if raw.contains('@') && !raw.split('@').next().unwrap_or("").contains("://") {
            raw = raw.rsplit('@').next().unwrap_or("").to_string();
        }
        if let Some(c) = IP_TOK.captures(&raw) {
            hosts.insert(c.get(1).unwrap().as_str().to_ascii_lowercase());
            continue;
        }
        if let Some(c) = LOOP_NAME.captures(&raw) {
            hosts.insert(c.get(1).unwrap().as_str().to_ascii_lowercase());
            continue;
        }
        if let Some(c) = DOMAIN.captures(&raw) {
            let h = c.get(1).unwrap().as_str().to_ascii_lowercase();
            let tld = h.rsplit('.').next().unwrap_or("");
            if has(REAL_TLDS, tld) && !has(FILE_EXTS, tld) {
                hosts.insert(h);
            }
        }
    }
    hosts
}

fn port_of(s: &str) -> Option<i64> {
    TRAIL_PORT.captures(s).and_then(|c| c.get(1).unwrap().as_str().parse().ok())
}

fn token_hostport(tok: &str) -> (Option<String>, Option<i64>) {
    let mut raw = tok.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
    let mut tok_owned = tok.to_string();
    if raw.contains('@') && !raw.split('@').next().unwrap_or("").contains("://") {
        raw = raw.rsplit('@').next().unwrap_or("").to_string();
        tok_owned = raw.clone();
    }
    if let Some(c) = SCHEME.captures(&tok_owned) {
        let auth = c.get(1).unwrap().as_str().rsplit('@').next().unwrap_or("");
        if auth.starts_with('[') {
            let host = auth.split(']').next().unwrap_or("").trim_start_matches('[').to_ascii_lowercase();
            let rest = auth.split(']').last().unwrap_or("");
            return (if host.is_empty() { None } else { Some(host) }, port_of(rest));
        }
        let core = HOSTPORT_CORE.find(auth).map(|m| m.as_str()).unwrap_or(auth);
        let host = core.split(':').next().unwrap_or("").to_ascii_lowercase();
        return (if host.is_empty() { None } else { Some(host) }, port_of(core));
    }
    if let Some(c) = IP_TOK.captures(&tok_owned) {
        return (Some(c.get(1).unwrap().as_str().to_ascii_lowercase()), port_of(&tok_owned));
    }
    if let Some(c) = LOOP_NAME.captures(&tok_owned) {
        let p = c.get(2).and_then(|m| m.as_str().parse().ok());
        return (Some(c.get(1).unwrap().as_str().to_ascii_lowercase()), p);
    }
    if let Some(c) = DOMAIN.captures(&tok_owned) {
        let h = c.get(1).unwrap().as_str().to_ascii_lowercase();
        let tld = h.rsplit('.').next().unwrap_or("");
        if has(REAL_TLDS, tld) && !has(FILE_EXTS, tld) {
            return (Some(h), port_of(&tok_owned));
        }
    }
    (None, None)
}

fn loopback_from_code(code: &str) -> Vec<(String, Option<i64>)> {
    let mut out = Vec::new();
    for c in LOOP_CODE.captures_iter(code) {
        let h = c.get(1).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default();
        let p = c.get(2).and_then(|m| m.as_str().parse().ok());
        if !h.is_empty() {
            out.push((h, p));
        }
    }
    out
}

#[pyfunction]
pub fn guard_extract_hosts(command: &str) -> Vec<String> {
    let mut hosts: Vec<String> = hosts_from(&safe_split(command), 0).into_iter().collect();
    hosts.sort();
    hosts
}

#[pyfunction]
pub fn guard_extract_host_ports(command: &str) -> Vec<(String, Option<i64>)> {
    let tokens = safe_split(command);
    let mut valid = hosts_from(&tokens, 0);
    for tok in &tokens {
        if let Some(c) = LOOP_NAME.captures(tok) {
            valid.insert(c.get(1).unwrap().as_str().to_ascii_lowercase());
        }
        if let Some(c) = IP_TOK.captures(tok) {
            let ip = c.get(1).unwrap().as_str();
            if is_loopback_host(ip) {
                valid.insert(ip.to_ascii_lowercase());
            }
        }
    }
    let mut pairs = Vec::new();
    for (i, tok) in tokens.iter().enumerate() {
        let (h, mut p) = token_hostport(tok);
        if let Some(h) = h {
            if valid.contains(&h) {
                if p.is_none() && i + 1 < tokens.len() && tokens[i + 1].chars().all(|c| c.is_ascii_digit()) {
                    p = tokens[i + 1].parse().ok();
                }
                pairs.push((h, p));
            }
        }
    }
    let prog = leading_prog(&tokens);
    if has(interp(), &prog) {
        for (i, tok) in tokens.iter().enumerate() {
            if has(code_flags(), tok) && i + 1 < tokens.len() {
                pairs.extend(loopback_from_code(&tokens[i + 1]));
            } else if tok.starts_with('-') && tok.contains('=') {
                let (flag, val) = tok.split_once('=').unwrap();
                if has(code_flags(), flag) {
                    pairs.extend(loopback_from_code(val));
                }
            }
        }
    }
    let mut seen = BTreeSet::new();
    pairs.retain(|(h, p)| seen.insert((h.clone(), *p)));
    let _ = (ALT_HOST.is_match(""), coerce_ip, scope_parse_scan);
    pairs
}

#[pyfunction]
pub fn builtin_guard_rules(py: Python<'_>) -> PyResult<Py<PyList>> {
    let specs: &[(&str, &str, &str, &str)] = &[
        ("builtin-rm-root", "删除根目录", "destructive", r"\brm\s+-rf\s+/(?:\s|$)"),
        ("builtin-rm-home", "删除家目录", "destructive", r"\brm\s+-rf\s+~(?:/|\s|$)"),
        ("builtin-fork-bomb", "fork 炸弹", "destructive", r":\(\)\s*\{\s*:\|:&\s*\};:"),
        ("builtin-mkfs", "格式化磁盘", "destructive", r"(?i)\bmkfs\."),
        ("builtin-dd-disk", "dd 写磁盘", "destructive", r"(?i)\bdd\s+if=.*of=/dev/(sd|nvme|vd)"),
        ("builtin-redirect-disk", "重定向写磁盘", "destructive", r"(?i)>\s*/dev/(sd|nvme|vd)"),
        ("builtin-power", "关机或重启", "destructive", r"(?i)\bshutdown\b|\breboot\b|\bpoweroff\b"),
        ("builtin-sql-drop", "破坏性 SQL", "destructive", r"(?i)\bdrop\s+(?:table|database|schema|index)\b"),
        ("builtin-sql-write", "写入业务库", "destructive", r"(?i)\b(?:insert\s+into|update\s+\S+\s+set|replace\s+into|truncate\s+)\b"),
        ("builtin-sensitive-host", "政府教育军队学术域名", "scope", r"(?i)(?:^|\.)(?:gov|edu|mil|int)$|(?:^|\.)(?:gov|edu|ac|mil|go)\.[a-z]{2}$"),
        ("builtin-out-of-scope", "授权范围外的主机", "scope", "仅允许作业范围、已授权跳板和回环代理端口"),
        ("builtin-mega-wordlist", "超大词表", "wordlist", r"(?i)rockyou|directory-list-2\.3-medium|directory-list-2\.3-large|crackstation|10[-_]?million[-_]?password|hashed[-_]?password|darkc0de|raft[-_]?large"),
        ("builtin-quarantine-exec", "隔离区执行", "quarantine", r"(?i)(?:^|[\s;&|`(])(?:\./|sh\s|bash\s|python[23]?\s|perl\s|ruby\s|php\s|node\s|source\s|\.\s)"),
    ];
    let list = PyList::empty(py);
    for (id, name, category, pattern) in specs {
        let row = PyDict::new(py);
        row.set_item("id", *id)?;
        row.set_item("name", *name)?;
        row.set_item("category", *category)?;
        row.set_item("pattern", *pattern)?;
        row.set_item("builtin", true)?;
        list.append(row)?;
    }
    Ok(list.unbind())
}

pub(crate) fn console_data_dir(py: Python<'_>) -> std::path::PathBuf {
    if let Ok(cfg) = py.import("atkbrain.config") {
        if let Ok(settings) = cfg.getattr("settings") {
            if let Ok(value) = settings.getattr("data_dir") {
                if let Ok(text) = value.str() {
                    let path = std::path::PathBuf::from(text.to_string_lossy().as_ref());
                    if !path.as_os_str().is_empty() {
                        return path;
                    }
                }
            }
        }
    }
    atkbrain_core::config::repo_root().join("backend").join("data")
}

fn rule_dict<'py>(py: Python<'py>, rule: &atkbrain_core::guard_rules::GuardRule) -> PyResult<Bound<'py, PyDict>> {
    let row = PyDict::new(py);
    row.set_item("id", &rule.id)?;
    row.set_item("name", &rule.name)?;
    row.set_item("pattern", &rule.pattern)?;
    row.set_item("reason", &rule.reason)?;
    row.set_item("enabled", rule.enabled)?;
    row.set_item("category", &rule.category)?;
    row.set_item("builtin", rule.builtin)?;
    Ok(row)
}

fn guard_err(message: String) -> PyErr {
    if message.contains("不能修改") || message.contains("不能删除") {
        PyPermissionError::new_err(message)
    } else if message.contains("不存在") {
        PyLookupError::new_err(message)
    } else {
        PyValueError::new_err(message)
    }
}

#[pyfunction]
fn guard_list_custom(py: Python<'_>) -> PyResult<Vec<Py<PyDict>>> {
    let dir = console_data_dir(py);
    atkbrain_core::guard_rules::list_custom(&dir)
        .iter()
        .map(|rule| rule_dict(py, rule).map(|row| row.unbind()))
        .collect()
}

#[pyfunction]
#[pyo3(signature = (name, pattern, reason="", enabled=true))]
fn guard_create_rule(py: Python<'_>, name: &str, pattern: &str, reason: &str, enabled: bool) -> PyResult<Py<PyDict>> {
    let dir = console_data_dir(py);
    match atkbrain_core::guard_rules::create_rule(&dir, name, pattern, reason, enabled) {
        Ok(rule) => Ok(rule_dict(py, &rule)?.unbind()),
        Err(err) => Err(guard_err(err)),
    }
}

#[pyfunction]
fn guard_set_enabled(py: Python<'_>, rule_id: &str, enabled: bool) -> PyResult<Py<PyDict>> {
    let dir = console_data_dir(py);
    match atkbrain_core::guard_rules::set_enabled(&dir, rule_id, enabled) {
        Ok(rule) => Ok(rule_dict(py, &rule)?.unbind()),
        Err(err) => Err(guard_err(err)),
    }
}

#[pyfunction]
fn guard_delete_rule(py: Python<'_>, rule_id: &str) -> PyResult<()> {
    let dir = console_data_dir(py);
    atkbrain_core::guard_rules::delete_rule(&dir, rule_id).map_err(guard_err)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(guard_mega_wordlist, m)?)?;
    m.add_function(wrap_pyfunction!(guard_ctf_mega, m)?)?;
    m.add_function(wrap_pyfunction!(guard_destructive, m)?)?;
    m.add_function(wrap_pyfunction!(guard_extract_hosts, m)?)?;
    m.add_function(wrap_pyfunction!(guard_extract_host_ports, m)?)?;
    m.add_function(wrap_pyfunction!(builtin_guard_rules, m)?)?;
    m.add_function(wrap_pyfunction!(guard_list_custom, m)?)?;
    m.add_function(wrap_pyfunction!(guard_create_rule, m)?)?;
    m.add_function(wrap_pyfunction!(guard_set_enabled, m)?)?;
    m.add_function(wrap_pyfunction!(guard_delete_rule, m)?)?;
    Ok(())
}
