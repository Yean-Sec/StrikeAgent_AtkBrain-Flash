//! 攻击图假设。话术沿用原来的中文，不新写步骤。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet};
use regex::Regex;
use sha1::{Digest, Sha1};

const SSRF_NOTE: &str = "只有从目标响应里看见、或经 SSRF 拿到登录页/横幅的具体内网主机才 report_pivot_capability（ssrf_*）扩进 Scope。链路本地与云元数据、文档网段、以及超时/无业务正文的错误码差分只证明 SSRF 原语，不要当成新邻机、不要 hop_auth。";
const SECRET_HINT: &str = "浅层路径 404 不能否证带叶子的深层路径，也不等于无挂载点。无密钥基线先找 401/403（路存在），再把同一密钥值用查询参数、请求头、Cookie、body 回挂。没见过 401/403 就不能写无挂载点。字段名不等于查询参数名或头名。";

static GADGET_BLOB: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bssrf\b|open\s*proxy|gopher://|file://|跳板|导入面|upload").unwrap());
static TRANSPORT_DEAD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)connection refused|no route to host|code=000|http_code=000|network is unreachable|name or service not known").unwrap());
static NEGATIVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)无挂载|无\s*HTTP\s*挂载|挂载点.{0,6}无|无任何挂载|差分.{0,12}闭环|全闭环|面.{0,8}穷尽|穷尽.{0,8}(?:路由|HTTP|功能)|终审|no[-_ ]?(?:http[-_ ]?)?mount|exhausted|仅有?\s*\d+\s*条?(?:路由|路径)|其余.{0,8}404|全部.?404|分析方法.{0,12}穷尽|全部.{0,16}穷尽|无法通过现有方法|纯诱饵|判定为诱饵|确为诱饵|(?:^|[^不])是诱饵|\bdecoy\b|\btheater\b|全负|口令空间.{0,12}(?:穷尽|全负)|登录门.{0,16}全部失败|突破尝试全部失败|爆破失败|brute[-_ ]?fail|强随机|不可爆破").unwrap());
static CHANNEL_NEG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)通道否证|否证.{0,12}(?:SSRF|通道|网关|跳板)|判定为存根|同体.{0,12}400|硬\s*400|存根级|恒定\s*4\d\d|统一\s*4\d\d").unwrap());
static AUTO_FROM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)auto from (?:https?://|http_request)").unwrap());
static BINARY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)逆向|可执行文件|固件|字节码|bytecode|\bELF\b|octet-stream|自定义\s*(?:VM|执行)|自研\s*(?:VM|执行)|stripped\s+binary|analy[sz]e.{0,24}(?:executable|binary)|(?:executable|binary).{0,16}analy").unwrap());
static NON_ASSET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)枚举进行中|进行中[,，。]|\binflight\b|无业务逻辑|零业务|模板\s*UI|表单结构|字段.{0,40}username\s*/\s*password|csrf.?token.?头|非POST未带").unwrap());
static PROCESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:变体|包装|绕过族).{0,12}(?:失败|否证)|探测失败|仍被(?:拦|阻止|拒绝)|过程笔记").unwrap());
static INFO_LEAK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:泄露|泄漏|注释).{0,16}(?:password|passwd|token|口令|账号|credential)|(?:password|passwd|口令)\s*[=:]\s*\S|\b(?:default[-_ ]creds?|test:test|有效账号|默认口令)\b").unwrap());
static INFO_CRED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(password|passwd|token|secret|credential|账号|口令)\b").unwrap());
static FORM_CRED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)表单|字段|username\s*/\s*password|POST\s+/login").unwrap());
static SECRET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)\b(admin[_-]?token|api[_-]?key|access[_-]?token|secret[_-]?key|bearer|auth[_-]?token|internal[_-]?token)\b|["']?(?:token|secret|api_key|apikey)["']?\s*[:=]"#).unwrap());
static LOGIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:\b(?:password|passwd|username|default-cred|default.creds)\b|口令|账密|用户名)").unwrap());
static USER_SLASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[\w.@+-]+/.+").unwrap());
static LOCAL_GATE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)访问码|access[_\s-]?code|argv\s*\[|license[_\s-]?key").unwrap());
static LOCAL_BIN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bELF\b|stripped|validator|bytecode|自定义\s*VM|自研\s*(?:VM|执行)|\./[A-Za-z0-9_.-]+").unwrap());
static AUTHZ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(401|403)\b|unauthorized|www-authenticate").unwrap());
static CRASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)availability|error_handling|misconfig|\bdos\b|\bcrash\b|崩溃|可用性|渲染层|视图层|模板异常|确定性\s*500").unwrap());
static EXPLOIT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)sqli|sql.?inject|sql注入|db_access|\brce\b|command.inject|\bssrf\b|\blfi\b|file_read|file_write|file_upload|ssti|deserial|unauth|auth_bypass|\bidor\b|xxe").unwrap());
static UNIFORM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)恒定\s*\d{3}|恒\s*\d{3}|无条件\s*\d{3}|持续\s*\d{3}|统一(?:错误|模板|状态)|无差异|无\s*set-cookie|没有\s*set-cookie|无\s*cookie|uniform\s+(?:error|status)|\balways\s+\d{3}\b|no\s+set-cookie").unwrap());
static CHANNEL_DIFF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)时间差|长度差|布尔差|耗时差|延时差|timing\s+diff|length\s+diff|boolean\s+diff|差分.{0,12}(?:耗时|长度|rtt|delay)").unwrap());
static UNIFORM_5: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)恒定\s*5\d\d|恒\s*5\d\d|无条件\s*5\d\d|持续\s*5\d\d|always\s+5\d\d|统一(?:错误|模板).{0,12}5\d\d").unwrap());
static FALSE_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|(?:该|此)面(?:已死|关闭)|面已关|通道级否证|确定性\s*500|死面|输入无关|无条件崩溃").unwrap());
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bjwt\b|\bjws\b|\bjwe\b|\bhs256\b|\brs256\b|\bes256\b|json\s*web\s*token|signed\s+(?:token|cookie)|hmac-sha").unwrap());
static AUTH_SVC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b(?:sshd?|rdp|smb|ftp|redis|mysql|mariadb|postgres(?:ql)?|mongo(?:db)?|telnet|vnc)\b").unwrap());
static DSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)jdbc:|redis://|mysql://|mongodb://|postgres(?:ql)?://|\.rds\.|\.internal(?:[.:/\s]|$)|(?:^|[^a-z])db_host\s*[:=]").unwrap());
static INFO_DANGER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)(?:(?:^|[\s"'=])/admin\b|\bswagger\b|\bendpoint\b|\bapi/[A-Za-z]|\bdebug\s*(?:port|panel|interface|endpoint))"#).unwrap());
static FILE_DELIVERY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\bdownload\b|\battachment\b|\breadfile\b|\bsendfile\b|\bsend_file\b|filepath|file_path|fileid|file_id|localfile|local_file|\bfilename\b|\blfi\b|任意文件|文件下载|附件下载|路径穿越|path.?traversal|[?&](?:file|filename|filepath|path|doc|document|attachment)=|/(?:file|files|download|attach|attachment|export)(?:\.[a-z0-9]+)?").unwrap());
static WILD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)通配映射|未知.{0,16}action.{0,24}首页|首页.{0,16}\d{4,6}\s*B").unwrap());
static LINKED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"前端引用|端点全集|端点清单|仅\s*\d+\s*个|目录枚举收益低|映射面很窄|继续目录枚举").unwrap());
static STATIC_TRAV: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"文件面封死|读文件面全否证|静态目录穿越|WEB-INF.{0,12}否证").unwrap());
static FILE_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)(?:fileName|localfile|local_file|filepath|file_path|filename)|文件参数|上传接口|下载参数|本地文件|(?:[?&](?:file|filename|filepath|upload|download|doc|document|attach(?:ment)?|image|img|template|include|folder|dir)=)|\b(?:filename|upload|download|attachment|template|include)\s*参数").unwrap());
static NOT_FILE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)否证|封死|无上传|不能推断|没有上传|不存在上传|不可达|filename\s*位置|字段名|Content-Type|multipart|假阳性|任何以|载荷矩阵|形式接收|还没有|尚未").unwrap());
static HTTP_PAGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)https?://|text/html|\b(?:jsp|php|aspx|asp)\b").unwrap());
static ACTION_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/([A-Za-z][A-Za-z0-9_]*)((?:![A-Za-z][A-Za-z0-9_]*)*)\.action\b").unwrap());
static FAKE_ACTION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/([A-Za-z][A-Za-z0-9_]*)(?:![A-Za-z][A-Za-z0-9_]*)*\.action[^\n]{0,32}不是真实").unwrap());
static ENUM_PLAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)content_enum|目录爆破|目录枚举").unwrap());
static OBJ_SIDE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)方法矩阵|method[\s_-]*matrix|方法枚举|verb\s*enum").unwrap());
static SURFACE_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:https?://[^\s/]+)?(/[A-Za-z][A-Za-z0-9._-]{0,63})").unwrap());
static SURFACE_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)[a-z]{3,}|登录|口令|认证|表单|资产|报销|后台").unwrap());

const GADGET_TAGS: &[&str] = &["ssrf", "ssrf_internal", "ssrf_as_gateway", "proxy", "import", "upload", "open_proxy", "ssrf-echo", "ssrf_echo"];
const EXPLOIT_TAGS: &[&str] = &["sqli", "sql-injection", "sql注入", "db_access", "rce", "command_injection", "ssrf", "ssrf_internal", "lfi", "file_read", "file_write", "file_upload", "ssti", "deserialization", "unauth", "auth_bypass", "idor", "xxe"];
const CRASH_TAGS: &[&str] = &["availability", "crash", "dos", "error_handling", "misconfig", "template"];
const SURFACES: &[(&str, &str, &str, &str)] = &[
    ("graphql", "graphql_contract", "对 {title} 先读 GraphQL 契约，再按字段做授权差分", "GraphQL 入口的下一步是契约与授权差分"),
    ("soap", "soap_contract", "对 {title} 先拉 WSDL/SOAP 契约再调操作", "SOAP 入口的下一步是契约操作"),
    ("jwt", "token_inspect", "对 {title} 的会话令牌本地解码 header/claims，按通用缺陷族验证", "令牌面先看结构再验证"),
    ("multipart", "upload_bypass", "对 {title} 把内容类型与扩展名当服务端校验假设，只传无害短 canary", "上传面用短 canary 验证解析链"),
    ("object_store", "object_write", "对 {title} 先列桶/键，再在可写或已登录面做对象级读写与键级授权差分", "对象存储面的下一步是键级读写差分"),
    ("xml", "xml_parse", "对 {title} 先确认 XML 解析器如何处理外部实体与扩展，短 canary", "XML 面先确认解析行为再验证"),
    ("template_error", "ssti", "对 {title} 的模板报错回显先做无害 canary 确认注入面", "模板报错说明渲染面还活着，先 canary"),
    ("json_api", "api_contract", "对 {title} 先读 JSON API 契约/字段，再做未授权与对象级授权差分。前端/JS 键不是后端必填名：4xx 正文若点名其它字段，立刻换那个名，不要对已否证键做编码变体。", "JSON API 的下一步是契约与授权差分；客户端字段名过时则按错误正文换键"),
    ("html_sink", "html_sink", "对 {title} 用短 canary 确认查询/表单参数是否原样进 HTML/DOM", "反射 HTML 汇的下一步是短 canary"),
    ("php_serial", "restricted_deserialize", "对 {title} 按受限反序列化族短验证入口里的序列化形态", "序列化字节本身就是入口标签"),
    ("expr_eval", "expr_eval", "对 {title} 用无害 canary 确认表达式/编码求值面", "求值报错回显输入说明求值面还活着，先 canary"),
    ("race_window", "race_window", "对 {title} 只证明写接口缺锁；最多对自己的测试对象做 2 路对照，禁止打爆真实库存/优惠券/名额", "无锁写成功是并发窗口的证据，不要对生产对象加压"),
];

#[pyclass]
#[derive(Clone)]
struct Hypothesis {
    #[pyo3(get)]
    from_keys: Vec<String>,
    #[pyo3(get)]
    description: String,
    #[pyo3(get)]
    rationale: String,
    #[pyo3(get)]
    est_success: f64,
    #[pyo3(get)]
    strategy_key: String,
    #[pyo3(get)]
    evidence_fingerprint: String,
    #[pyo3(get)]
    priority: f64,
    #[pyo3(get)]
    status: String,
    #[pyo3(get)]
    depends_on: Vec<String>,
}

struct Nv {
    key: String,
    ntype: String,
    title: String,
    severity: String,
    is_rce: bool,
    tags: BTreeSet<String>,
    blob: String,
    raw_blob: String,
}

fn text_of(v: &Bound<PyAny>) -> String {
    if v.is_none() { return String::new(); }
    v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn item_str(d: &Bound<PyDict>, key: &str) -> String {
    d.get_item(key).ok().flatten().map(|v| text_of(&v)).unwrap_or_default()
}

fn tags_from(value: &Bound<PyAny>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if value.is_none() { return out; }
    if let Ok(s) = value.extract::<String>() {
        if let Ok(parsed) = serde_json::from_str::<Vec<String>>(&s) {
            for t in parsed { out.insert(t.to_ascii_lowercase()); }
            return out;
        }
        out.insert(s.to_ascii_lowercase());
        return out;
    }
    if let Ok(it) = value.try_iter() {
        for v in it.flatten() {
            out.insert(text_of(&v).to_ascii_lowercase());
        }
    }
    out
}

fn node_of(node: &Bound<PyAny>) -> Nv {
    let d = node.downcast::<PyDict>().ok();
    let get = |k: &str| d.as_ref().map(|d| item_str(d, k)).unwrap_or_else(|| node.getattr(k).ok().map(|v| text_of(&v)).unwrap_or_default());
    let key = get("key");
    let title = get("title");
    let detail_v = d.as_ref().and_then(|d| d.get_item("detail").ok().flatten());
    let detail = if let Some(v) = detail_v {
        if let Ok(dict) = v.downcast::<PyDict>() {
            dict.values().iter().map(|v| text_of(&v)).collect::<Vec<_>>().join(" ")
        } else { text_of(&v) }
    } else { String::new() };
    let tags = d.as_ref().and_then(|d| d.get_item("tags").ok().flatten()).map(|v| tags_from(&v)).unwrap_or_default();
    let tag_join = tags.iter().cloned().collect::<Vec<_>>().join(" ");
    let blob = format!("{key} {title} {detail} {tag_join}").to_ascii_lowercase();
    let raw_blob = format!("{title} {detail} {key}");
    let is_rce = d.as_ref().and_then(|d| d.get_item("is_rce").ok().flatten()).map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false);
    Nv { key, ntype: get("type").to_ascii_lowercase(), title, severity: { let s = get("severity"); if s.is_empty() { "info".into() } else { s } }, is_rce, tags, blob, raw_blob }
}

fn has(tags: &BTreeSet<String>, name: &str) -> bool { tags.contains(name) }
fn any_in(blob: &str, tags: &BTreeSet<String>, needles: &[&str]) -> bool {
    needles.iter().any(|n| blob.contains(&n.to_ascii_lowercase()) || tags.contains(*n))
}

fn sev_n(s: &str) -> f64 {
    match s { "low" => 1.0, "medium" => 2.0, "high" => 3.0, "critical" => 4.0, _ => 0.0 }
}
fn priority(base: f64, severity: &str, boost: f64) -> f64 {
    let v = (base + sev_n(severity) * 0.04 + boost).clamp(0.05, 0.99);
    (v * 1000.0).round() / 1000.0
}
fn canon(source: &str) -> String {
    let mut s = source.trim().to_ascii_lowercase();
    for p in ["vuln:", "danger:", "svc:", "service:", "cred:", "credential:", "info:", "foothold:", "goal:", "file:", "dir:", "web:", "host:"] {
        if let Some(rest) = s.strip_prefix(p) { s = rest.to_string(); break; }
    }
    let mut toks: Vec<String> = Regex::new(r"[^a-z0-9]+").unwrap().split(&s).filter(|t| !t.is_empty()).map(|t| t.to_string()).collect();
    if toks.is_empty() { return s; }
    toks.sort();
    toks.join("-")
}
fn strategy_key_of(source: &str, tactic: &str) -> String {
    let sk = format!("{}::{tactic}", canon(source)).trim().to_ascii_lowercase();
    if sk.len() > 120 {
        let mut h = Sha1::new();
        h.update(sk.as_bytes());
        format!("{:x}", h.finalize())[..20].to_string()
    } else { sk }
}
fn fingerprint(node: &Nv, extra: &str) -> String {
    let raw = format!("{}|{}|{}|{}|{extra}", node.key, node.ntype, node.title, node.severity);
    let mut h = Sha1::new();
    h.update(raw.as_bytes());
    format!("{:x}", h.finalize())[..16].to_string()
}

fn hyp(py: Python<'_>, node: &Nv, tactic: &str, description: String, rationale: &str, est: f64, severity: &str, boost: f64, extra: &str) -> PyResult<Py<Hypothesis>> {
    Py::new(py, Hypothesis {
        from_keys: vec![node.key.clone()],
        description,
        rationale: rationale.into(),
        est_success: est,
        strategy_key: strategy_key_of(&node.key, tactic),
        evidence_fingerprint: fingerprint(node, if extra.is_empty() { tactic } else { extra }),
        priority: priority(est, severity, boost),
        status: "open".into(),
        depends_on: Vec::new(),
    })
}

fn channel_neg(blob: &str, title: &str) -> bool { CHANNEL_NEG.is_match(&format!("{title} {blob}")) }
fn negative(blob: &str, title: &str) -> bool {
    if channel_neg(blob, title) { return false; }
    NEGATIVE.is_match(&format!("{title} {blob}"))
}
fn gadget(blob: &str, tags: &BTreeSet<String>, title: &str) -> bool {
    if tags.iter().any(|t| GADGET_TAGS.contains(&t.as_str())) { return true; }
    let hay = format!("{title} {blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    if AUTO_FROM.is_match(&hay) { return false; }
    GADGET_BLOB.is_match(&hay)
}
fn looks_binary(blob: &str, title: &str, brief: &str) -> bool { BINARY.is_match(&format!("{title} {blob} {brief}")) }
fn local_gate(blob: &str, title: &str) -> bool {
    let s = format!("{title} {blob}");
    LOCAL_GATE.is_match(&s) && LOCAL_BIN.is_match(&s)
}
fn looks_secret(blob: &str, tags: &BTreeSet<String>) -> bool {
    tags.iter().any(|t| ["token", "api-key", "api_key", "secret", "config-leak", "config_leak"].contains(&t.as_str())) || SECRET.is_match(blob)
}
fn login_cred(blob: &str, title: &str) -> bool {
    if local_gate(blob, title) { return false; }
    LOGIN.is_match(blob) || LOGIN.is_match(title) || USER_SLASH.is_match(title.trim())
}
fn is_http_svc(blob: &str, tags: &BTreeSet<String>) -> bool {
    let hay = format!("{blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    ["http", "https", "apache", "nginx", "php", "tomcat", "weblogic", "spring", "iis", "gunicorn", "uwsgi", "flask", "django", "fastapi", "web 应用", "web应用"].iter().any(|x| hay.contains(x))
}
fn is_token(blob: &str, tags: &BTreeSet<String>, title: &str) -> bool {
    tags.iter().any(|t| ["jwt", "jws", "jwe", "hs256", "signed_token"].contains(&t.as_str())) || TOKEN.is_match(blob) || TOKEN.is_match(title)
}
fn is_rce(node: &Nv) -> bool { node.is_rce || any_in(&node.blob, &node.tags, &["rce", "command", "shell", "desp"]) }
fn is_ssrf(node: &Nv) -> bool { node.blob.contains("ssrf") || node.tags.contains("ssrf") }
fn info_oracle(blob: &str, title: &str) -> bool {
    let text = format!("{title} {blob}");
    if CHANNEL_DIFF.is_match(&text) || channel_neg(blob, title) { return false; }
    UNIFORM_5.is_match(&text) || FALSE_CLOSE.is_match(&text)
}
fn process_note(blob: &str, title: &str, key: &str) -> bool {
    key.contains(":exec:") || key.contains(":knife:") || PROCESS.is_match(&format!("{title} {blob}"))
}
fn non_asset(blob: &str, title: &str) -> bool { NON_ASSET.is_match(&format!("{title} {blob}")) }
fn leaked_login(blob: &str, title: &str) -> bool {
    if negative(blob, title) || non_asset(blob, title) || process_note(blob, title, "") || channel_neg(blob, title) { return false; }
    let text = format!("{title} {blob}");
    INFO_LEAK.is_match(&text) || (INFO_CRED.is_match(&text) && !FORM_CRED.is_match(&text))
}
fn file_delivery(blob: &str, title: &str, key: &str) -> bool { FILE_DELIVERY.is_match(&format!("{key} {title} {blob}")) }
fn crash_only(node: &Nv) -> bool {
    if node.tags.iter().any(|t| EXPLOIT_TAGS.contains(&t.as_str())) || EXPLOIT.is_match(&node.blob) { return false; }
    node.tags.iter().any(|t| CRASH_TAGS.contains(&t.as_str())) || CRASH.is_match(&node.blob)
}
fn filter_hit(node: &Nv) -> bool { any_in(&node.blob, &node.tags, &["403", "waf", "拦截", "blocked", "forbidden", "filter"]) }
fn skips_filter(node: &Nv, ssrf: bool) -> bool { ssrf || gadget(&node.blob, &node.tags, &node.title) }

fn dict_nodes<'py>(graph: Option<&Bound<'py, PyDict>>) -> Vec<Bound<'py, PyDict>> {
    let Some(graph) = graph else { return Vec::new() };
    let Ok(Some(ns)) = graph.get_item("nodes") else { return Vec::new() };
    let Ok(list) = ns.downcast::<PyList>() else { return Vec::new() };
    list.iter().filter_map(|n| n.downcast::<PyDict>().ok().map(|d| d.clone())).collect()
}

fn cred_suffix(_py: Python<'_>, brief: &str) -> String {
    let cands = atkbrain_core::creds::credential_candidates_from_brief(brief, 10);
    atkbrain_core::creds::format_cred_hint(&cands)
}

fn surfaces_of(py: Python<'_>, blob: &str, tags: &BTreeSet<String>) -> Vec<String> {
    let hay = format!("{blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    let mut out = Vec::new();
    for (name, _, _, _) in SURFACES {
        if tags.contains(*name) || hay.contains(name) { out.push((*name).to_string()); }
    }
    if let Ok(fp) = py.import("atkbrain.entry_fingerprint") {
        if let Ok(extra) = fp.getattr("classify_http_surface").and_then(|f| f.call1((blob.as_bytes(),))) {
            if let Ok(merged) = fp.getattr("merge_surface_tags").and_then(|f| f.call1((out.clone(), extra))) {
                if let Ok(list) = merged.extract::<Vec<String>>() { return list; }
            }
        }
    }
    if out.iter().any(|x| x == "object_store") { out.retain(|x| x != "xml"); }
    out
}

fn surface_prefer(names: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for name in names {
        if let Some((_, tac, _, _)) = SURFACES.iter().find(|(n, _, _, _)| *n == name.to_ascii_lowercase()) {
            out.insert((*tac).to_string());
        }
    }
    out
}

fn push_surfaces(py: Python<'_>, out: &mut Vec<Py<Hypothesis>>, node: &Nv, sev: &str) -> PyResult<()> {
    let names = surfaces_of(py, &node.blob, &node.tags);
    let want: BTreeSet<_> = names.into_iter().collect();
    for (name, tactic, desc, why) in SURFACES {
        if !want.contains(*name) { continue; }
        out.push(hyp(py, node, tactic, desc.replace("{title}", &node.title), why, 0.68, sev, 0.1, "")?);
    }
    Ok(())
}

fn src_vendor(py: Python<'_>, node: &Nv, sev: &str) -> PyResult<Vec<Py<Hypothesis>>> {
    let mut out = Vec::new();
    let Ok(m) = py.import("atkbrain.engine.src_surface") else {
        out.push(hyp(py, node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问（当前无注入/文件等分型）", node.title), "SRC HTTP 活体至少留一格打洞，优先越权", 0.66, sev, 0.0, "")?);
        return Ok(out);
    };
    let fake = PyDict::new(py);
    let one = PyDict::new(py);
    one.set_item("key", &node.key)?;
    one.set_item("type", "service")?;
    one.set_item("title", &node.title)?;
    one.set_item("detail", &node.blob)?;
    one.set_item("tags", PyList::new(py, node.tags.iter().cloned())?)?;
    fake.set_item("nodes", PyList::new(py, [one])?)?;
    let advice = m.getattr("suggest_src_types")?.call1((fake,))?;
    let suggested = advice.getattr("suggested")?;
    let mut seen = BTreeSet::new();
    if let Ok(it) = suggested.try_iter() {
        for p in it.flatten() {
            let tactic = p.getattr("tactic").ok().map(|v| text_of(&v)).unwrap_or_default();
            if tactic.is_empty() || !seen.insert(tactic.clone()) { continue; }
            let label = p.getattr("label").ok().map(|v| text_of(&v)).unwrap_or_default();
            let why = p.getattr("why").ok().map(|v| text_of(&v)).unwrap_or_default();
            out.push(hyp(py, node, &tactic, format!("围绕 {} 按入口形态测{label}：{why}；没有对应面不要硬打其它厂商类型", node.title), &format!("SRC 按面选类型，不是每轮全开；本节点命中 {label}"), 0.7, sev, 0.1, "")?);
        }
    }
    if out.is_empty() {
        out.push(hyp(py, node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问（当前无注入/文件等分型）", node.title), "SRC HTTP 活体至少留一格打洞，优先越权", 0.66, sev, 0.0, "")?);
    }
    Ok(out)
}

fn impact(py: Python<'_>, node: &Nv, cat: &str, sev: &str, obj: &str) -> PyResult<Option<Py<Hypothesis>>> {
    if obj == "flag" { return Ok(None); }
    let (ladder, extra) = if obj == "src" {
        ("把已确认漏洞打到高危影响（大量数据/命令执行/改价），不要停在存在性 PoC", "已验证 SSRF 必须 report_pivot_capability 扩网；不要 socks/shell 横向、不要为拿 shell 放弃未测类型；继续挖厂商清单下一类。")
    } else {
        let ladder = match cat {
            "sqli" => "证库名/用户 → 只读 SELECT 一条敏感样本；禁止 DROP/DELETE/INSERT/UPDATE/拖全表",
            "ssrf" | "ssrf_internal" => "能打内网 → 具体主机才扩 Scope；经 SSRF 打从目标响应看见的内网口；禁止 本机直连",
            "rce" | "command_injection" => "已能执行 → 短 txt canary 取回即删，切下一类，不横向",
            "lfi" | "file_read" | "arbitrary_file_read" => "任意读 → 凭证或少量敏感文件样本",
            _ => "把已确认漏洞推进到命令执行（getshell），不要停在存在性 PoC；尚未 GETSHELL 则对其它活体面继续测→证",
        };
        (ladder, "提权/横向只在已有立足点之后，不要为换路丢掉这条已验证洞。")
    };
    Ok(Some(hyp(py, node, "impact_escalate", format!("提升已验证洞「{}」的危害：{ladder}。影响实质性变大就独立 report_finding，不要只改标题重报同一事实。厂商清单/攻击面穷尽时优先走这一步。{extra}", node.title), "已证明的洞停在存在性不够；危害上调常打出新的独立高危", 0.77, if sev.is_empty() { "high" } else { sev }, 0.14, cat)?))
}

fn channel_oracle(py: Python<'_>, node: &Nv, sev: &str, crash: bool, include_input: bool) -> PyResult<Vec<Py<Hypothesis>>> {
    let mut desc = format!("对 {} 换观测通道：状态码/正文/Cookie/跳转无差异时，对同一输入的两次提交比对耗时差/长度差/响应头差/其它路由副作用；同一状态码再采样不算换通道，不要关闭输入面", node.title);
    if crash { desc.push_str("；不要把恒定错误页写成已验证利用"); }
    let mut out = vec![hyp(py, node, "channel_oracle", desc, "一类 oracle 失败不等于后端没处理参数", 0.78, sev, 0.14, "")?];
    if include_input {
        out.push(hyp(py, node, "input_abuse", format!("验证 {} 的可控输入是否仍被后端处理，不要关闭输入面", node.title), "恒定错误页只否证了这一类观测", 0.7, sev, 0.08, "")?);
    }
    Ok(out)
}

fn real_file(graph: Option<&Bound<PyDict>>) -> bool {
    for n in dict_nodes(graph) {
        let view = node_of(n.as_any());
        if FILE_PARAM.is_match(&view.raw_blob) && !NOT_FILE.is_match(&view.raw_blob) { return true; }
    }
    false
}

#[pyfunction]
#[pyo3(signature = (graph=None, *, http=false))]
pub(crate) fn action_surface_incomplete(graph: Option<&Bound<PyDict>>, http: bool) -> bool {
    if real_file(graph) { return false; }
    if http { return true; }
    for n in dict_nodes(graph) {
        let view = node_of(n.as_any());
        if WILD.is_match(&view.raw_blob) || LINKED.is_match(&view.raw_blob) || STATIC_TRAV.is_match(&view.raw_blob) || HTTP_PAGE.is_match(&view.raw_blob) {
            return true;
        }
    }
    false
}

fn action_forms(text: &str) -> Vec<(String, Vec<String>)> {
    ACTION_PATH.captures_iter(text).map(|c| {
        let methods = c.get(2).map(|m| m.as_str().split('!').filter(|p| !p.is_empty()).map(|p| p.to_string()).collect()).unwrap_or_default();
        (c.get(1).unwrap().as_str().to_string(), methods)
    }).collect()
}

#[pyfunction]
pub(crate) fn request_form_gaps(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PyList>> {
    let nodes = dict_nodes(graph);
    let mut fake = BTreeSet::new();
    let mut blobs = Vec::new();
    for n in &nodes {
        let blob = format!("{} {} {}", item_str(n, "key"), item_str(n, "title"), item_str(n, "detail"));
        for c in FAKE_ACTION.captures_iter(&blob) {
            if let Some(s) = c.get(1) { fake.insert(s.as_str().to_string()); }
        }
        blobs.push(blob);
    }
    let mut seen: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
    let mut order = Vec::new();
    for blob in &blobs {
        for (stem, methods) in action_forms(blob) {
            if fake.contains(&stem) { continue; }
            if !seen.contains_key(&stem) { order.push(stem.clone()); }
            seen.entry(stem).or_default().insert(methods);
        }
    }
    let mut extras: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (stem, forms) in &seen {
        let names: BTreeSet<String> = forms.iter().flatten().cloned().collect();
        if !names.is_empty() { extras.insert(stem.clone(), names); }
    }
    let all: BTreeSet<String> = extras.values().flatten().cloned().collect();
    let out = PyList::empty(py);
    for stem in &order {
        let own = extras.get(stem).cloned().unwrap_or_default();
        let missing: Vec<String> = all.difference(&own).cloned().collect();
        if missing.is_empty() { continue; }
        if !seen.get(stem).map(|s| s.iter().any(|m| m.is_empty())).unwrap_or(false) { continue; }
        let siblings: Vec<String> = order.iter().filter(|n| *n != stem && extras.contains_key(*n)).cloned().collect();
        if siblings.is_empty() { continue; }
        let d = PyDict::new(py);
        d.set_item("stem", stem)?;
        d.set_item("siblings", PyList::new(py, siblings)?)?;
        d.set_item("forms", PyList::new(py, missing)?)?;
        out.append(d)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
#[pyo3(signature = (blob, title="", key=""))]
fn looks_like_file_delivery(blob: &str, title: &str, key: &str) -> bool { file_delivery(blob, title, key) }

#[pyfunction]
#[pyo3(signature = (blob, title="", brief=""))]
fn looks_like_served_binary(blob: &str, title: &str, brief: &str) -> bool { looks_binary(blob, title, brief) }

#[pyfunction]
#[pyo3(signature = (graph=None, brief=""))]
fn graph_looks_like_served_binary(graph: Option<&Bound<PyDict>>, brief: &str) -> bool {
    if looks_binary("", "", brief) { return true; }
    dict_nodes(graph).iter().any(|n| { let v = node_of(n.as_any()); looks_binary(&v.blob, &v.title, brief) })
}

#[pyfunction]
#[pyo3(name = "_node_looks_like_gadget", signature = (blob, tags=None, title=""))]
fn node_looks_like_gadget(blob: &str, tags: Option<&Bound<PyAny>>, title: &str) -> bool {
    gadget(blob, &tags.map(tags_from).unwrap_or_default(), title)
}

#[pyfunction]
fn node_is_non_exploit_crash(node: Option<&Bound<PyAny>>) -> bool {
    node.map(|n| crash_only(&node_of(n))).unwrap_or(false)
}

#[pyfunction]
fn live_gadget_tactics(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let mut out = BTreeSet::new();
    let Some(graph) = graph else { return Ok(PySet::empty(py)?.unbind()); };
    for n in dict_nodes(Some(graph)) {
        let v = node_of(n.as_any());
        if !["service", "danger", "vuln"].contains(&v.ntype.as_str()) { continue; }
        if !gadget(&v.blob, &v.tags, &v.title) { continue; }
        let hay = format!("{} {}", v.title, v.blob);
        if TRANSPORT_DEAD.is_match(&hay) && !hay.to_ascii_lowercase().contains("ssrf") { continue; }
        out.insert("ssrf_as_gateway".to_string());
        if v.tags.contains("upload") || hay.to_ascii_lowercase().contains("upload") { out.insert("upload_bypass".to_string()); }
    }
    if let Ok(Some(fs)) = graph.get_item("findings") {
        if let Ok(list) = fs.downcast::<PyList>() {
            for f in list.iter() {
                let Ok(d) = f.downcast::<PyDict>() else { continue };
                let vs = item_str(d, "verification_status").to_ascii_lowercase();
                if ["disproved", "false", "rejected"].contains(&vs.as_str()) { continue; }
                let cat = item_str(d, "category").to_ascii_lowercase();
                let blob = format!("{} {} {cat}", item_str(d, "title"), item_str(d, "description"));
                if cat == "ssrf" || cat == "ssrf_internal" || GADGET_BLOB.is_match(&blob) { out.insert("ssrf_as_gateway".into()); }
                if blob.to_ascii_lowercase().contains("upload") { out.insert("upload_bypass".into()); }
            }
        }
    }
    Ok(PySet::new(py, out)?.unbind())
}

#[pyfunction]
fn weaponize_prefer_tactics(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let mut out = BTreeSet::new();
    if graph.is_some() {
        let live = live_gadget_tactics(py, graph)?;
        for x in live.bind(py).iter() { if let Ok(s) = x.extract::<String>() { out.insert(s); } }
    }
    let map = |cat: &str| -> &[&str] {
        match cat {
            "ssrf" | "ssrf_internal" => &["ssrf_as_gateway", "ssrf_local_svc"],
            "lfi" | "file_read" | "arbitrary_file_read" => &["file_read_chain", "read_to_creds", "finding_read_loot"],
            "sqli" | "sql-injection" | "db_access" => &["finding_sqli_chain", "weaponize"],
            "rce" | "command_injection" => &["finding_rce_close", "weaponize"],
            _ => &[],
        }
    };
    if let Some(graph) = graph {
        if let Ok(Some(fs)) = graph.get_item("findings") {
            if let Ok(list) = fs.downcast::<PyList>() {
                for f in list.iter() {
                    let Ok(d) = f.downcast::<PyDict>() else { continue };
                    let vs = item_str(d, "verification_status").to_ascii_lowercase();
                    if !vs.is_empty() && vs != "verified" && vs != "accepted" { continue; }
                    let sev = item_str(d, "severity").to_ascii_lowercase();
                    if vs != "verified" && sev != "high" && sev != "critical" { continue; }
                    for t in map(&item_str(d, "category").to_ascii_lowercase()) { out.insert((*t).into()); }
                }
            }
        }
        for n in dict_nodes(Some(graph)) {
            let v = node_of(n.as_any());
            if v.ntype != "vuln" { continue; }
            if !v.tags.contains("verified") && v.severity != "high" && v.severity != "critical" { continue; }
            let hay = format!("{} {} {}", v.title, v.blob, v.tags.iter().cloned().collect::<Vec<_>>().join(" "));
            for cat in ["ssrf", "ssrf_internal", "lfi", "file_read", "arbitrary_file_read", "sqli", "sql-injection", "db_access", "rce", "command_injection"] {
                if hay.contains(cat) || v.tags.contains(cat) {
                    for t in map(cat) { out.insert((*t).into()); }
                }
            }
        }
    }
    Ok(PySet::new(py, out)?.unbind())
}

#[pyfunction]
fn enum_sidetrack_when_weaponizable(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PySet>> {
    let prefs = weaponize_prefer_tactics(py, graph)?;
    let items: Vec<String> = if prefs.bind(py).len() > 0 { vec!["content_enum".into(), "fingerprint".into()] } else { Vec::new() };
    Ok(PySet::new(py, items)?.unbind())
}

#[pyfunction]
fn graph_has_unmounted_secret(graph: Option<&Bound<PyDict>>) -> bool {
    let mut has_secret = false;
    let mut saw = false;
    for n in dict_nodes(graph) {
        let v = node_of(n.as_any());
        if v.ntype == "credential" && looks_secret(&v.blob, &v.tags) && !local_gate(&v.blob, &v.title) { has_secret = true; }
        if negative(&v.blob, &v.title) { continue; }
        if AUTHZ.is_match(&v.title) || AUTHZ.is_match(&v.blob) { saw = true; }
    }
    has_secret && !saw
}

#[pyfunction]
fn needs_channel_oracle(graph: Option<&Bound<PyDict>>) -> bool {
    let nodes: Vec<Nv> = dict_nodes(graph).iter().map(|n| node_of(n.as_any())).collect();
    let mut settled = BTreeSet::new();
    for n in &nodes {
        if !["danger", "vuln", "info"].contains(&n.ntype.as_str()) { continue; }
        if CHANNEL_DIFF.is_match(&n.blob) || CHANNEL_DIFF.is_match(&n.title) {
            for t in surface_tokens(n) { settled.insert(t); }
        }
    }
    for n in &nodes {
        let uniform = if n.ntype == "danger" || n.ntype == "vuln" {
            !(CHANNEL_DIFF.is_match(&n.blob) || CHANNEL_DIFF.is_match(&n.title)) && (UNIFORM.is_match(&n.blob) || UNIFORM.is_match(&n.title) || FALSE_CLOSE.is_match(&format!("{} {}", n.title, n.blob)))
        } else if n.ntype == "info" { info_oracle(&n.blob, &n.title) } else { false };
        if !uniform { continue; }
        let toks = surface_tokens(n);
        if !toks.is_empty() && !settled.is_empty() && toks.iter().any(|t| settled.contains(t)) { continue; }
        return true;
    }
    false
}

fn surface_tokens(n: &Nv) -> BTreeSet<String> {
    let text = format!("{} {}", n.key, n.title);
    let mut paths = Vec::new();
    for c in SURFACE_PATH.captures_iter(&text) {
        let p = c.get(1).unwrap().as_str().to_ascii_lowercase().trim_end_matches('/').to_string();
        if !p.is_empty() && !["/http", "/https", "/tcp", "/udp"].contains(&p.as_str()) { paths.push(p); }
    }
    if !paths.is_empty() { return paths.into_iter().collect(); }
    let rest = n.key.split_once(':').map(|(_, r)| r).unwrap_or(&n.key);
    let mut out = BTreeSet::new();
    let stop = ["danger", "info", "vuln", "http", "https", "www", "html", "always", "error", "page", "uniform", "status", "cookie", "crash", "closed", "none", "null", "diff", "query", "param", "post", "get", "svc", "service", "target", "goal", "host", "tcp", "udp", "port", "flask", "gunicorn", "werkzeug", "the", "and", "for", "from", "with", "ams"];
    for c in SURFACE_WORD.find_iter(&format!("{rest} {}", n.title)) {
        let s = c.as_str().to_ascii_lowercase();
        if !s.is_empty() && !stop.contains(&s.as_str()) { out.insert(s); }
    }
    out
}

#[pyfunction]
fn surfaces_from_graph_nodes(py: Python<'_>, graph: Option<&Bound<PyDict>>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for n in dict_nodes(graph) {
        let v = node_of(n.as_any());
        for name in surfaces_of(py, &format!("{} {}", item_str(&n, "detail"), v.title), &v.tags) {
            if seen.insert(name.clone()) { out.push(name); }
        }
    }
    out
}

#[pyfunction]
fn surface_prefer_tactics(py: Python<'_>, surfaces: Option<&Bound<PyAny>>) -> PyResult<Py<PySet>> {
    let names = surfaces.map(tags_from).unwrap_or_default();
    Ok(PySet::new(py, surface_prefer(&names.into_iter().collect::<Vec<_>>()))?.unbind())
}

#[pyfunction]
#[pyo3(signature = (surfaces=None, *, has_verified=false))]
fn surface_defer_tactics(py: Python<'_>, surfaces: Option<&Bound<PyAny>>, has_verified: bool) -> PyResult<Py<PySet>> {
    let names: Vec<String> = surfaces.map(tags_from).unwrap_or_default().into_iter().collect();
    let mut out = BTreeSet::new();
    if !surface_prefer(&names).is_empty() { out.insert("content_enum".to_string()); }
    if names.iter().any(|n| n == "object_store") && has_verified {
        out.extend(["content_enum".into(), "filter_bypass".into(), "channel_oracle".into()]);
    }
    Ok(PySet::new(py, out)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (surfaces=None, *, resolved_tactics=None))]
fn live_surface_needs_cycle(surfaces: Option<&Bound<PyAny>>, resolved_tactics: Option<&Bound<PyAny>>) -> bool {
    let names: Vec<String> = surfaces.map(tags_from).unwrap_or_default().into_iter().collect();
    let want = surface_prefer(&names);
    if want.is_empty() { return false; }
    let done = resolved_tactics.map(tags_from).unwrap_or_default();
    !want.iter().any(|t| done.contains(t))
}

#[pyfunction]
#[pyo3(signature = (plan_text, *, surfaces=None))]
fn plan_blocks_live_surface(plan_text: &str, surfaces: Option<&Bound<PyAny>>) -> bool {
    let names: Vec<String> = surfaces.map(tags_from).unwrap_or_default().into_iter().collect();
    if !surface_prefer(&names).is_empty() && ENUM_PLAN.is_match(plan_text) { return true; }
    names.iter().any(|n| n == "object_store") && OBJ_SIDE.is_match(plan_text)
}

#[pyfunction]
fn strategy_key(source_key: &str, tactic: &str) -> String { strategy_key_of(source_key, tactic) }

#[pyfunction]
#[pyo3(signature = (node, brief=""))]
fn stale_tactics_for_node(node: &Bound<PyAny>, brief: &str) -> Vec<String> {
    let v = node_of(node);
    let mut stale = vec!["split_tier".to_string()];
    if v.ntype == "vuln" && is_ssrf(&v) && !is_rce(&v) { stale.push("weaponize".into()); }
    if v.ntype == "vuln" && local_gate(&v.blob, &v.title) { stale.extend(["weaponize".into(), "finding_rce_close".into(), "flag_or_privesc".into()]); }
    if v.ntype == "credential" && looks_secret(&v.blob, &v.tags) && !login_cred(&v.blob, &v.title) { stale.extend(["auth_reuse".into(), "priv_enum".into()]); }
    if v.ntype == "credential" && local_gate(&v.blob, &v.title) { stale.extend(["auth_reuse".into(), "priv_enum".into(), "secret_mount".into()]); }
    if v.ntype == "info" && (negative(&v.blob, &v.title) || non_asset(&v.blob, &v.title) || process_note(&v.blob, &v.title, &v.key)) {
        stale.extend(["info_to_cred".into(), "info_to_danger".into(), "secret_mount".into()]);
    }
    if v.ntype == "service" && (!is_http_svc(&v.blob, &v.tags) || looks_binary(&v.blob, &v.title, brief)) {
        stale.extend(["content_enum".into(), "web_inject".into(), "auth_surface".into()]);
    }
    stale
}

fn data_plane(py: Python<'_>, node: &Nv, sev: &str) -> PyResult<Py<Hypothesis>> {
    hyp(py, node, "data_plane_via_app", format!("把 {} 里的库/缓存 DSN 当成「经应用碰数据面」：经已验证 SSRF/gopher 或跳板隧道碰 db_host，禁止无跳板 本机直连内网库，不要把 RDS IP 建成新子项目。", node.title), "红队数据面经应用/跳板隧道，不是无跳板 本机直连", 0.74, if sev.is_empty() { "high" } else { sev }, 0.14, "")
}

#[pyfunction]
#[pyo3(signature = (node, allows_flag=true, objective=None, brief="", graph=None))]
fn hypotheses_for_node(py: Python<'_>, node: &Bound<PyAny>, allows_flag: bool, objective: Option<&str>, brief: &str, graph: Option<&Bound<PyDict>>) -> PyResult<Vec<Py<Hypothesis>>> {
    let obj = match objective {
        Some(s) => crate::objective::objective_normalize(Some(s)),
        None => if allows_flag { "flag".into() } else { "redteam".into() },
    };
    let raw = node;
    let mut node = node_of(raw);
    if node.title.is_empty() { node.title = node.key.clone(); }
    if node.severity.is_empty() { node.severity = "info".into(); }
    let sev = node.severity.clone();
    let cred = cred_suffix(py, &format!("{brief}\n{}\n{}", node.title, node.blob));
    let binary = looks_binary(&node.blob, &node.title, brief);
    let mut out = Vec::new();
    let loot = if allows_flag { "配置/源码/flag" } else { "配置/源码/凭证/敏感数据" };
    if node.ntype == "service" {
        let http = is_http_svc(&node.blob, &node.tags);
        out.push(hyp(py, &node, "fingerprint", format!("确认 {} 的产品/版本指纹与已知漏洞面", node.title), "服务发现后先定性技术栈，才能选对利用族", if http { 0.48 } else { 0.7 }, &sev, 0.0, "")?);
        if binary {
            out.push(hyp(py, &node, "reverse_binary", format!("下载 {} 下发的可执行文件/固件/字节码，file/strings/objdump/radare2 静态分析，再用已装的 z3/pwntools 符号求解；不要扫目录、不要当网站打", node.title), "题面要求分析可执行文件时，下一事件是本地逆向而不是 Web 枚举", 0.8, &sev, 0.16, "")?);
            out.push(hyp(py, &node, "protocol_model", format!("对 {} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录", node.title), "可执行文件入口常伴随自定义协议，会话建模与静态分析并行", 0.72, &sev, 0.12, "")?);
        } else if http {
            out.push(hyp(py, &node, "auth_surface", format!("枚举 {} 的登录/鉴权/管理入口并测默认口令与弱鉴权{cred}；先读表单 action；经代理转发时把方法与请求体送到内层认证处理接口，外壳 POST 或仍回登录页不算口令否证", node.title), "多数 Web 服务的高价值面在认证边界", 0.58, &sev, 0.0, "")?);
            out.push(hyp(py, &node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问", node.title), "访问控制缺陷常比复杂 exploit 更快出成果", 0.68, &sev, 0.08, "")?);
            out.push(hyp(py, &node, "content_enum", format!("对 {} 做目录与脚本文件枚举（先看入口已知路径与源码；禁止超 10 万行词表）", node.title), "未链接脚本常无目录命中；无扩展名扫描不能当内容枚举完成", 0.52, &sev, 0.0, "")?);
            if gadget(&node.blob, &node.tags, &node.title) {
                out.push(hyp(py, &node, "ssrf_as_gateway", format!("把 {} 当跳板：内网/回环走该 gadget，不要从攻击机直连那些地址。{SSRF_NOTE}GET 与 POST 是两种能力；登录等写请求必须确认内层收到方法与 body", node.title), "跳板类服务的下一事件是当传输层，不是直连内网", 0.8, &sev, 0.16, "")?);
            }
            let chain = node.tags.iter().any(|t| ["json-rpc", "jsonrpc", "ethereum", "geth"].contains(&t.as_str())) || ["json-rpc", "jsonrpc", "ethereum", "geth", "anvil", "hardhat", "nethermind", "besu", "ganache", "erigon"].iter().any(|x| node.blob.contains(x));
            if chain {
                out.push(hyp(py, &node, "chain_rpc", format!("对 {} 做 JSON-RPC 指纹与未授权方法探测，不要当网站做目录枚举", node.title), "JSON-RPC 的入口是方法表，不是目录与 SQLi", 0.72, &sev, 0.1, "")?);
            } else if obj == "src" {
                out.extend(src_vendor(py, &node, &sev)?);
            } else {
                out.push(hyp(py, &node, "web_inject", format!("围绕 {} 探测注入类漏洞（SQLi/SSTI/命令注入/反序列化）", node.title), "Web 服务常见通往 RCE/读文件的入口族", 0.72, &sev, 0.12, "")?);
            }
            if filter_hit(&node) && !skips_filter(&node, is_ssrf(&node)) {
                out.push(hyp(py, &node, "filter_bypass", format!("对 {} 的拦截/过滤页换方法与通道探测，不要结案去枚举目录", node.title), "过滤器页说明请求已达应用边界，目录枚举不是下一事件", 0.66, &sev, 0.08, "")?);
            }
            push_surfaces(py, &mut out, &node, &sev)?;
        } else {
            out.push(hyp(py, &node, "protocol_model", format!("对 {} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录", node.title), "非 HTTP 交互口的下一步是会话建模，不是 Web 枚举", 0.72, &sev, 0.12, "")?);
            if node.tags.iter().any(|t| ["ssh", "sshd", "rdp", "smb", "ftp", "redis", "mysql", "mariadb", "postgres", "postgresql", "mongo", "mongodb", "telnet", "vnc"].contains(&t.as_str())) || AUTH_SVC.is_match(&format!("{} {}", node.blob, node.tags.iter().cloned().collect::<Vec<_>>().join(" "))) {
                out.push(hyp(py, &node, "svc_auth_bruteforce", format!("对 {} 做有节制的默认/弱口令与未授权探测（个位数，禁止全量词表）{cred}", node.title), "非 HTTP 服务常因默认配置失守", 0.5, &sev, 0.0, "")?);
            }
        }
    } else if node.ntype == "danger" {
        out.push(hyp(py, &node, "input_abuse", format!("验证危险点 {} 的可控输入与参数污染", node.title), "危险点需确认输入面后才能升级为 vuln", 0.66, &sev, 0.05, "")?);
        out.push(hyp(py, &node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问", node.title), "访问控制缺陷常比复杂 exploit 更快出成果", 0.6, &sev, 0.0, "")?);
        if gadget(&node.blob, &node.tags, &node.title) {
            out.push(hyp(py, &node, "ssrf_as_gateway", format!("把危险点 {} 当跳板继续打，一种 4xx 不关闭整族，禁止攻击机直连内网", node.title), "跳板类危险点的下一事件是当传输层", 0.78, &sev, 0.14, "")?);
        }
        if UNIFORM.is_match(&node.blob) || UNIFORM.is_match(&node.title) { out.extend(channel_oracle(py, &node, &sev, false, false)?); }
        if any_in(&node.blob, &node.tags, &["upload", "multipart", "附件", "file-upload", "file_upload"]) {
            out.push(hyp(py, &node, "upload_bypass", format!("对 {} 做上传/解析链绕过并尝试 webshell/文件写", node.title), "上传面是经典 getshell 路径", 0.64, &sev, 0.08, "")?);
        }
        if filter_hit(&node) && !skips_filter(&node, is_ssrf(&node)) {
            out.push(hyp(py, &node, "filter_bypass", format!("对 {} 换通道绕过拦截/过滤，不要结案去枚举目录", node.title), "拦截页是否定了这一通道，不是攻击面关闭", 0.7, &sev, 0.1, "")?);
        }
        push_surfaces(py, &mut out, &node, &sev)?;
        if any_in(&node.blob, &node.tags, &["deserial", "pickle", "unserialize", "ysoserial", "gadget", "marshal"]) {
            out.push(hyp(py, &node, "restricted_deserialize", format!("对 {} 做受限反序列化：在允许的构造器/类型里搜 gadget，不要把白名单当成攻击面已关闭", node.title), "白名单反序列化的下一事件是 gadget 搜索，不是停手", 0.7, &sev, 0.1, "")?);
        }
        if file_delivery(&node.blob, &node.title, &node.key) && !AUTHZ.is_match(&format!("{} {}", node.title, node.blob)) {
            let loot_r = if allows_flag { "文件读可直接转凭证或 flag" } else { "文件读可直接转凭证或大量数据泄露" };
            out.push(hyp(py, &node, "file_read_chain", format!("利用 {} 尝试任意文件读并定位{loot}", node.title), loot_r, 0.68, &sev, 0.1, "")?);
        }
        let stem = action_forms(&format!("{} {}", node.key, node.title)).into_iter().find(|(_, m)| m.is_empty()).map(|(s, _)| s).unwrap_or_default();
        if !stem.is_empty() {
            let gaps = request_form_gaps(py, graph)?;
            for gap in gaps.bind(py).iter() {
                let Ok(d) = gap.downcast::<PyDict>() else { continue };
                if item_str(&d, "stem") != stem { continue; }
                let sibs = d.get_item("siblings").ok().flatten().and_then(|v| v.extract::<Vec<String>>().ok()).unwrap_or_default();
                let forms = d.get_item("forms").ok().flatten().and_then(|v| v.extract::<Vec<String>>().ok()).unwrap_or_default();
                let sibs = sibs.into_iter().take(2).collect::<Vec<_>>().join("、");
                let forms = forms.join("、");
                out.push(hyp(py, &node, "transfer_form", format!("{stem} 已确认存在，调用形式比 {sibs} 少。把 {sibs} 上已经改变响应的形式 {forms} 套到 {stem}。方法名只用本站已经出现过的，不要新造路径。堆栈里的方法名和重写路径返回 404，不能算这个入口已经测完。"), "同站已经改变响应的调用形式可以套到调用更少的入口", 0.7, &sev, 0.1, "")?);
                break;
            }
        }
    } else if node.ntype == "vuln" {
        let ssrf = is_ssrf(&node);
        let rce = is_rce(&node);
        let sqli = any_in(&node.blob, &node.tags, &["sqli", "sql-injection", "sql注入"]);
        let token = is_token(&node.blob, &node.tags, &node.title);
        let crash = crash_only(&node);
        if crash { out.extend(channel_oracle(py, &node, &sev, true, true)?); }
        else if !(ssrf && !rce) {
            if token {
                out.push(hyp(py, &node, "weaponize", format!("把 {} 的签名令牌当服务端校验对象继续打：少数算法或弱密钥变体失败不关闭整类；不要只改前端角色字段，也不要把令牌面写成已关闭", node.title), "持有令牌后下一事件是打校验类，不是关闭伪造面或只改 UI 角色", 0.76, &sev, 0.12, "")?);
            } else if local_gate(&node.blob, &node.title) {
                out.push(hyp(py, &node, "reverse_binary", format!("把 {} 当本地开门钥匙：校验通过后按本题已出现的运算取循环末态或真实出口，不要当成 Web RCE 去读文件/提权", node.title), "本地二进制访问码的下一事件是反演/取末态，不是 HTTP 武器化", 0.8, &sev, 0.16, "")?);
            } else if sqli {
                out.push(hyp(py, &node, "weaponize", format!("把 {} 先打成应用控制流/回显（状态码/Cookie/跳转），再 dump 库/密钥；确认注入后不要再校准耗时，也不要在同一面上改打无关的身份伪造", node.title), "登录/鉴权查询上错误页只说明失败分支崩了，查询可能已执行完", 0.76, &sev, 0.12, "")?);
            } else {
                out.push(hyp(py, &node, "weaponize", format!("把已确认漏洞 {} 推进到稳定利用（读文件/执行/提权）", node.title), "vuln 节点的下一事件是能力升级而非重复探测", 0.72, &sev, 0.1, "")?);
            }
        }
        if !crash {
            let why = if allows_flag { "可复现证据便于后续 flag/shell 收口" } else { "可复现证据便于后续 shell/数据收口" };
            out.push(hyp(py, &node, "evidence_poc", format!("为 {} 固化最小 PoC 并串联到目标攻击链", node.title), why, 0.65, &sev, 0.0, "")?);
            let cat = if ssrf { "ssrf" } else if sqli { "sqli" } else if rce { "rce" } else { "vuln" };
            if let Some(esc) = impact(py, &node, cat, &sev, &obj)? { out.push(esc); }
        }
        if rce && !local_gate(&node.blob, &node.title) {
            if obj == "src" {
                out.push(hyp(py, &node, "src_next_type", format!("「{}」已经是命令执行：report_shell 收工，其它未报漏洞照样 report_finding", node.title), "命令执行后 report_shell 收工", 0.8, "critical", 0.12, "")?);
            } else {
                let desc = if allows_flag { format!("基于 {} 的执行能力搜 flag / 提权 / 横向", node.title) } else { format!("基于 {} 落地命令执行并 report_shell，其它未报漏洞继续报", node.title) };
                out.push(hyp(py, &node, "flag_or_privesc", desc, "已有 RCE 时应优先收口而不是继续盲扫", 0.8, "critical", 0.15, "")?);
            }
        }
        if any_in(&node.blob, &node.tags, &["file_read", "lfi", "path", "read", "穿越", "include"]) {
            out.push(hyp(py, &node, "read_to_creds", format!("用 {} 读取配置/密钥/会话并尝试登录复用", node.title), "文件读→凭证→更高权限是高胜率链路", 0.75, &sev, 0.12, "")?);
        }
        if ssrf {
            out.push(hyp(py, &node, "ssrf_as_gateway", format!("把 {} 当传输层：对回环/容器网的 HTTP 经该 SSRF 转发，禁止从攻击机直连那些 IP。{SSRF_NOTE}登录等写请求必须确认内层收到方法与 body，不要把外壳 POST 当已送达", node.title), "SSRF 入 Scope 不给攻击机路由；直连超时不是入口挂了", 0.8, &sev, 0.16, "")?);
            out.push(hyp(py, &node, "ssrf_local_svc", format!("用 {} 打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从本机直连", node.title), "unix socket / bind 127.0.0.1 的库只能从目标侧发起", 0.74, &sev, 0.12, "")?);
            out.push(hyp(py, &node, "secret_mount", format!("若 {} 已读到配置/token：在被访问的那台服务上做有/无密钥路由差分（查询参数、请求头、Cookie、body；401/403=路存在）。JSON 字段名不等于参数名或头名，短名 token/key/auth 都要试。{SECRET_HINT}", node.title), "泄露密钥是开门钥匙；GET-only SSRF 仍可用查询参数或头携带", 0.83, &sev, 0.18, "")?);
        }
    } else if node.ntype == "credential" {
        if local_gate(&node.blob, &node.title) { return Ok(out); }
        if looks_secret(&node.blob, &node.tags) && !login_cred(&node.blob, &node.title) {
            out.push(hyp(py, &node, "secret_mount", format!("把 {} 当开门钥匙：在同一服务上做有/无该密钥的路由差分，盯 401/403 而不是只看 200。字段名不等于查询参数/头名；查询参数、请求头、Cookie、body 都要试。{SECRET_HINT}", node.title), "机器令牌的第一事件是鉴权差分挂载，不是当战利品结束", 0.84, &sev, 0.18, "")?);
        } else {
            out.push(hyp(py, &node, "auth_reuse", format!("用凭证 {} 登录签发它的那一跳/同一应用，不要当其它 hop 的万能钥匙", node.title), "凭证复用的范围是签发该凭证的应用，不是内网任意协议", 0.78, &sev, 0.12, "")?);
            let why = if allows_flag { "认证后的功能面常直接通向 flag 或 RCE" } else { "认证后的功能面常直接通向 RCE 或敏感数据/后台" };
            out.push(hyp(py, &node, "priv_enum", format!("登录后枚举 {} 可达的管理功能/敏感数据/上传与命令入口", node.title), why, 0.7, &sev, 0.08, "")?);
        }
        if obj == "redteam" && DSN.is_match(&node.blob) { out.push(data_plane(py, &node, &sev)?); }
    } else if (node.ntype == "target" && node.tags.iter().any(|t| ["lateral", "pivot", "scope-expanded"].contains(&t.as_str()))) || (node.ntype == "info" && (node.key.starts_with("info:host:") || node.key.starts_with("info:scope-expanded:"))) {
        let same = node.tags.iter().any(|t| t == "same-machine" || t == "vhost") || node.title.contains("同一容器");
        let dict = raw.downcast::<PyDict>().ok();
        let host = crate::intranet::node_host_py(dict);
        if !host.is_empty() && crate::intranet::intra_is_canary(&host) { return Ok(out); }
        if !same {
            out.push(hyp(py, &node, "fingerprint", format!("经已有 SSRF/shell 跳板摸清 {} 的开放端口、HTTP 标题与服务类型，立刻 add_node service/info 挂到该目标下；禁止 本机直连该 IP。", node.title), "新内网目标先定性活体并落图，才能打登录/未授权；直连超时是预期", 0.72, "high", 0.12, "")?);
            if crate::intranet::intra_node_live(dict) {
                out.push(hyp(py, &node, "access_control", format!("对 {} 已暴露的面做未授权可达差分，与过门并行；不要把身份验证写成使用这些面的前置条件。", node.title), "要身份与不要身份是并行假设", 0.74, "high", 0.13, "")?);
            }
            if crate::intranet::intra_hop_eligible(dict, graph) {
                out.push(hyp(py, &node, "hop_auth", format!("过 {} 自己的身份边界；上一跳泄露只是候选。经跳板 HTTP 时先确认认证接口收到请求体再判口令；外壳 POST、站点根路径、仍回登录页 HTML 不算失败。同一身份面在认证接口已送达后没有新秘密、只重复失败，这一跳的过门假设做完。", node.title), "新 hop 是新身份域；过门只是假设之一", 0.74, "high", 0.13, "")?);
            }
        }
    } else if node.ntype == "foothold" {
        if obj == "src" {
            out.push(hyp(py, &node, "src_next_type", format!("立足点 {} 已经是命令执行：report_shell 收工，其它未报漏洞照样 report_finding", node.title), "命令执行后 report_shell 收工", 0.72, &sev, 0.1, "")?);
        } else {
            out.push(hyp(py, &node, "stabilize", format!("巩固立足点 {}：持久化通道、环境枚举、敏感文件", node.title), "立足后先稳住再扩权", 0.7, &sev, 0.1, "")?);
            out.push(hyp(py, &node, "privesc_lateral", format!("从 {} 做本地提权与授权范围内横向/跳板", node.title), "foothold 的下一事件是提权或横向", 0.68, &sev, 0.1, "")?);
            if allows_flag {
                out.push(hyp(py, &node, "flag_hunt", format!("在 {} 权限下定位并 report_flag", node.title), "flag 赛道下立足点应立即转夺旗；未满分继续，满分由平台收工", 0.74, &sev, 0.12, "")?);
            } else {
                out.push(hyp(py, &node, "flag_hunt", format!("在 {} 权限下确认 getshell（report_shell）并收工", node.title), "红队立足后 report_shell 即收工，不夺旗", 0.74, &sev, 0.12, "")?);
            }
        }
    } else if node.ntype == "info" {
        if process_note(&node.blob, &node.title, &node.key) { return Ok(out); }
        if channel_neg(&node.blob, &node.title) {
            if gadget(&node.blob, &node.tags, &node.title) {
                out.push(hyp(py, &node, "ssrf_as_gateway", format!("把 {} 当还活着的跳板：恒定 4xx / 一种观测失败不关闭整族；按错误正文换键，禁止攻击机直连内网面。过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。", node.title), "同体 4xx 或否证笔记否定的是一种契约，不是跳板已死", 0.78, "high", 0.14, "")?);
            }
            return Ok(out);
        }
        if info_oracle(&node.blob, &node.title) { out.extend(channel_oracle(py, &node, &sev, false, true)?); return Ok(out); }
        let joined = format!("{} {}", node.title, node.blob);
        if WILD.is_match(&joined) || LINKED.is_match(&joined) || STATIC_TRAV.is_match(&joined) {
            out.push(hyp(py, &node, "content_enum", format!("把 {} 当阴性对照，不要当成入口已经列完。先打开入口 HTML 里的同站内容页，把图片、文件、下载地址建成节点；和首页相同的只当阴性对照。第一个 500 或登录页不能代替这些内容页。页面和 JS 里的接口不是服务端全集。再用中档词表列同应用路径，和首页同状态、同长度的丢掉；301/302/403/500 或长度不同的逐个建成节点。带文件名、路径、上传的入口单独记。静态目录穿不过只否定这次穿越。", node.title), "内容页、前端名单和已知目录否证都不关闭未出现在页面上的入口", 0.74, &sev, 0.12, "")?);
            if LINKED.is_match(&joined) || STATIC_TRAV.is_match(&joined) { return Ok(out); }
        }
        if negative(&node.blob, &node.title) || non_asset(&node.blob, &node.title) { return Ok(out); }
        if file_delivery(&node.blob, &node.title, &node.key) && !looks_binary(&node.blob, &node.title, brief) && !AUTHZ.is_match(&joined) {
            out.push(hyp(py, &node, "file_read_chain", format!("对 {} 的文件/下载参数做路径与对象差分，尝试任意文件读并定位{loot}", node.title), "下载/附件/文件路径参数是文件读面，不要停在状态码或回头打登录表单", 0.72, &sev, 0.12, "")?);
        }
        if looks_secret(&node.blob, &node.tags) {
            out.push(hyp(py, &node, "secret_mount", format!("把信息点 {} 里的密钥当开门钥匙：同一服务有/无密钥路由差分，401/403=路存在。{SECRET_HINT}", node.title), "配置泄露的 token 不是终点", 0.8, "high", 0.16, "")?);
        } else if leaked_login(&node.blob, &node.title) {
            out.push(hyp(py, &node, "info_to_cred", format!("把信息点 {} 验证为可用凭证并尝试登录", node.title), "明文口令/密钥应立刻升级为 credential 利用", 0.7, "medium", 0.08, "")?);
        }
        if INFO_DANGER.is_match(&node.blob) || INFO_DANGER.is_match(&node.title) {
            out.push(hyp(py, &node, "info_to_danger", format!("把 {} 对应接口升级为危险点并做未授权/注入探测", node.title), "接口信息需落到可验证攻击面", 0.55, &sev, 0.0, "")?);
        }
        if obj == "redteam" && DSN.is_match(&node.blob) { out.push(data_plane(py, &node, &sev)?); }
    }
    Ok(out)
}

fn finding_field(finding: &Bound<PyAny>, key: &str) -> String {
    if let Ok(d) = finding.downcast::<PyDict>() { return item_str(&d, key); }
    finding.getattr(key).ok().map(|v| text_of(&v)).unwrap_or_default()
}

#[pyfunction]
#[pyo3(signature = (finding, node, allows_flag=true, objective=None))]
fn hypotheses_for_finding(py: Python<'_>, finding: &Bound<PyAny>, node: &Bound<PyAny>, allows_flag: bool, objective: Option<&str>) -> PyResult<Vec<Py<Hypothesis>>> {
    let obj = match objective {
        Some(s) => crate::objective::objective_normalize(Some(s)),
        None => if allows_flag { "flag".into() } else { "redteam".into() },
    };
    let mut view = node_of(node);
    let cat = finding_field(finding, "category").to_ascii_lowercase();
    let cat = if cat.is_empty() { "info".into() } else { cat };
    let title = { let t = finding_field(finding, "title"); if t.is_empty() { view.key.clone() } else { t } };
    let sev = { let s = finding_field(finding, "severity"); if s.is_empty() { view.severity.clone() } else { s } };
    if view.key.is_empty() { view.key = finding_field(finding, "node_key"); }
    if view.key.is_empty() { view.key = "finding".into(); }
    view.title = title.clone();
    let fblob = format!("{title} {} {} {cat} {}", finding_field(finding, "description"), finding_field(finding, "evidence"), view.blob).to_ascii_lowercase();
    let mut out = Vec::new();
    if local_gate(&fblob, &title) {
        out.push(hyp(py, &view, "reverse_binary", format!("把发现「{title}」当本地开门钥匙：校验通过后取循环末态或真实出口，不要推进到读文件/提权"), "本地访问码不是 Web RCE finding", 0.8, &sev, 0.16, &cat)?);
        return Ok(out);
    }
    if ["file_read", "lfi", "arbitrary_file_read"].contains(&cat.as_str()) {
        let loot = if allows_flag { "配置/源码/flag" } else { "配置/源码/凭证/大量敏感数据" };
        out.push(hyp(py, &view, "finding_read_loot", format!("利用文件读发现「{title}」提取{loot}"), "文件读 finding 应直接转战利品收集", 0.8, &sev, 0.15, &cat)?);
    } else if cat == "sqli" || cat == "db_access" {
        out.push(hyp(py, &view, "finding_sqli_chain", format!("把 SQLi「{title}」先打成应用控制流/回显（状态码/Cookie/跳转/页面差分），再按需 dump 库表/应用密钥/用户。时间/布尔差已证明查询在跑：先换回显/联合/报错等更快证明类，不要再校准 oracle，也不要把同一耗时通道按位问到底。不要只用单一错误页否证。库侧文件读原语常被配置挡住，只有更快类和 dump 都走不通才试。"), "时间差只证明查询在跑；回显/联合/报错往往比按位抽取更快收口。统一错误页不能否证结果集已变", 0.78, &sev, 0.14, &cat)?);
    } else if ["rce", "command_injection", "deserialization", "ssti", "file_upload", "file_write"].contains(&cat.as_str()) {
        let (desc, why) = if allows_flag { ("落地 shell/webshell 并夺旗或提权", "执行类 finding 优先收口") } else { ("落地命令执行并 report_shell，同时把其它未报漏洞继续报出来", "agent 测试要把已证实危害做到 getshell") };
        out.push(hyp(py, &view, "finding_rce_close", format!("基于「{title}」{desc}"), why, 0.82, "critical", 0.18, &cat)?);
    } else if cat == "ssrf" || cat == "ssrf_internal" {
        out.push(hyp(py, &view, "ssrf_as_gateway", format!("把 SSRF「{title}」当跳板：内网/回环 HTTP 走 gadget，不要从攻击机直连那些 IP。{SSRF_NOTE}登录等写请求必须确认内层收到方法与 body"), "SSRF 扩容只授权打目标，不授予攻击机路由", 0.82, &sev, 0.16, &cat)?);
        out.push(hyp(py, &view, "ssrf_local_svc", format!("用「{title}」打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从本机直连"), "本机只监听服务必须从 SSRF 所在进程发起", 0.76, &sev, 0.12, &cat)?);
        out.push(hyp(py, &view, "secret_mount", format!("若 SSRF「{title}」已读到 token/配置：在被访问服务上做有/无密钥路由差分（查询参数、请求头、Cookie、body；401/403=路存在）。{SECRET_HINT}"), "泄露密钥是钥匙；GET-only 通道仍可用查询参数或头", 0.84, &sev, 0.18, &cat)?);
    } else {
        out.push(hyp(py, &view, "finding_followup", format!("围绕发现「{title}」设计下一条可验证利用链"), "通用 finding 至少派生一次跟进事件", 0.5, &sev, 0.0, &cat)?);
    }
    if !crate::verify::verify_non_exploit(Some(&cat)) {
        if let Some(esc) = impact(py, &view, &cat, &sev, &obj)? { out.push(esc); }
    }
    Ok(out)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Hypothesis>()?;
    let tactics = PySet::new(m.py(), SURFACES.iter().map(|(_, t, _, _)| *t).collect::<Vec<_>>())?;
    m.add("LIVE_SURFACE_TACTICS", tactics)?;
    m.add_function(wrap_pyfunction!(action_surface_incomplete, m)?)?;
    m.add_function(wrap_pyfunction!(request_form_gaps, m)?)?;
    m.add_function(wrap_pyfunction!(looks_like_file_delivery, m)?)?;
    m.add_function(wrap_pyfunction!(looks_like_served_binary, m)?)?;
    m.add_function(wrap_pyfunction!(graph_looks_like_served_binary, m)?)?;
    m.add_function(wrap_pyfunction!(node_looks_like_gadget, m)?)?;
    m.add_function(wrap_pyfunction!(node_is_non_exploit_crash, m)?)?;
    m.add_function(wrap_pyfunction!(live_gadget_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(weaponize_prefer_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(enum_sidetrack_when_weaponizable, m)?)?;
    m.add_function(wrap_pyfunction!(graph_has_unmounted_secret, m)?)?;
    m.add_function(wrap_pyfunction!(needs_channel_oracle, m)?)?;
    m.add_function(wrap_pyfunction!(surfaces_from_graph_nodes, m)?)?;
    m.add_function(wrap_pyfunction!(surface_prefer_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(surface_defer_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(live_surface_needs_cycle, m)?)?;
    m.add_function(wrap_pyfunction!(plan_blocks_live_surface, m)?)?;
    m.add_function(wrap_pyfunction!(strategy_key, m)?)?;
    m.add_function(wrap_pyfunction!(stale_tactics_for_node, m)?)?;
    m.add_function(wrap_pyfunction!(hypotheses_for_node, m)?)?;
    m.add_function(wrap_pyfunction!(hypotheses_for_finding, m)?)?;
    Ok(())
}
