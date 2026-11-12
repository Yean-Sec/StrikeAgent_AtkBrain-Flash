//! 攻击图仓储。行为对齐 `backend/atkbrain/graph` 的 store、model、rating_rubric。
//! 图算法用邻接表，不再调用 networkx 或 Python。

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::db::{new_id, now, Db};
use rusqlite::types::ToSql;
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

pub const RATING_RUBRIC: &str = "\
红队评级只准用四级（对号入座，取已证明影响的最高符合项；禁止跳级，禁止压级）。\
info 仅二次复验失败时收口，不是第四级。

严重 critical（须 evidence 已证明，不能只凭类别或口子存在）
1. 已直接获取服务器权限：任意命令执行、上传 webshell、任意代码执行。
2. 已直接导致大量个人敏感信息泄露。
3. 已证明支付类逻辑可修改金额并影响盈利。

高危 high
1. 直接获取服务器权限的漏洞。包括但不限于任意命令执行、上传 webshell、任意代码执行。已打成执行则评严重。
2. 直接导致严重的信息泄漏漏洞。包括但不限于大量个人敏感信息泄露。已批量读出则评严重。
3. 支付类型逻辑漏洞。包括但不限于影响盈利的修改金额逻辑漏洞。已证实可改价则评严重。
4. 能直接盗取用户身份信息的影响严重的漏洞。可获取大量敏感信息或者执行命令的 SQL 漏洞。
5. 直接导致严重影响的逻辑漏洞。可重置管理员的密码，且导致大量敏感信息泄露。

中危 medium
1. 能直接盗取用户身份信息的漏洞。包括但不限于一般的 SQL 注入（需证明可获取数据库名/用户名）。
2. 直接导致相对严重影响的逻辑漏洞。包括无法导致大量敏感信息泄露的管理员用户密码重置或普通用户密码重置。
3. 需交互才能获取用户身份信息的漏洞。包括但不限于存储型 XSS。
4. 任意文件操作漏洞。包括但不限于任意文件读、写、删除、下载。
5. 越权访问。包括但不限于绕过认证访问后台，绕过限制修改用户资料、执行用户操作。
6. 比较严重的信息泄漏漏洞。包含敏感信息文件泄露（如 DB 连接密码）。
7. 弱口令。但不包括前台弱口令（前台弱口令不报）。

低危 low
1. 普通逻辑漏洞。包括但不限于 redis 未授权、heapdump 敏感信息泄露、短信轰炸等。
2. 需交互才能获取用户身份信息并且有一定利用难度的漏洞。

本表只决定级别，不是收洞白名单。表里没写到的可利用问题仍必须 report_finding（反射 XSS、SSRF、XXE、CORS 带凭证、竞态等）：按已证明影响就近落到中危或低危，禁止因为对不上条目就丢掉或标 info 了事。
未授权只打到「角色不存在 / 参数不完整 / 空 data」不能评高危或严重，仍按实际证明报中危或低危。
";

pub const RATING_RUBRIC_BRIEF: &str = "\
评级用四级：严重 / 高危 / 中危 / 低危。\
已打成命令执行、批量个人敏感信息、可改金额 → 严重；\
可直接导致这些后果但尚未打成 → 高危；\
一般 SQLi（库名/用户名）、存储 XSS、任意文件、越权进后台、DB 密码文件、后台弱口令 → 中危；\
redis 未授权 / heapdump / 短信轰炸 / 高交互身份类 → 低危。\
禁止把中危抬成高危，禁止把已打成的严重压成高危。\
四级表不是白名单：对不上条目的洞也要报，就近中危或低危，不要丢掉。";

const SEV_RANK: &[(&str, i64)] = &[("info", 0), ("low", 1), ("medium", 2), ("high", 3), ("critical", 4)];
const SEV_BASE: &[(&str, f64)] = &[("info", 5.0), ("low", 20.0), ("medium", 45.0), ("high", 72.0), ("critical", 92.0)];
const SEV_FLOOR: &[(&str, &str)] = &[
    ("rce", "critical"), ("command_injection", "critical"), ("deserialization", "critical"),
    ("file_write", "high"), ("file_upload", "high"), ("arbitrary_file_read", "high"),
    ("file_read", "high"), ("lfi", "high"), ("sqli", "high"), ("db_access", "high"),
    ("auth_bypass", "high"), ("admin_access", "high"), ("privilege_escalation", "high"),
    ("unauth", "high"), ("authz", "high"), ("idor", "medium"), ("ssrf", "medium"),
    ("xss", "medium"), ("info", "info"), ("business_logic", "high"), ("account_takeover", "high"),
    ("source_leak", "high"), ("backup_leak", "high"), ("hardcoded_secret", "high"),
    ("key_leak", "high"), ("mass_pii", "high"), ("cloud_credential", "high"),
    ("sensitive_data_exposure", "high"), ("credential_dump", "high"), ("secrets_leak", "high"),
];
const CRITICAL_CATEGORIES: &[&str] = &[
    "rce", "command_injection", "deserialization", "file_write", "file_upload",
    "arbitrary_file_read", "file_read", "lfi", "sqli", "db_access",
    "auth_bypass", "authz", "unauth", "idor", "admin_access", "privilege_escalation", "ssrf_internal",
];
const RCE_CATS: &[&str] = &["rce", "command_injection", "deserialization", "ssti", "code_execution"];
const NON_EXPLOIT: &[&str] = &["availability", "dos", "crash", "error_handling", "misconfig"];
const DATA_ACCESS_CATEGORIES: &[&str] = &["db_access", "db_dump", "dump", "data_leak", "mass_data_leak", "mass_disclosure"];
const KEY_LEAK_CATEGORIES: &[&str] = &[
    "source_leak", "backup_leak", "hardcoded_secret", "cloud_credential", "mass_pii",
    "sensitive_data_exposure", "credential_dump", "secrets_leak", "key_leak",
];
const MASS_LEAK_TAGS: &[&str] = &[
    "data_leak", "backup_leak", "source_leak", "mass_disclosure", "dump", "db_dump",
    "key_leak", "hardcoded_secret", "mass_pii",
];
const TAG_LIVE: &str = "via-live";
const TAG_CLUE: &str = "clue-only";
const GRAPH_TTL: std::time::Duration = std::time::Duration::from_secs(2);
const INTENT_TTL: std::time::Duration = std::time::Duration::from_secs(20);
const ATTACH_ROOT: &[(&str, i64)] = &[
    ("service", 0), ("danger", 1), ("vuln", 2), ("credential", 3),
    ("foothold", 4), ("goal", 5), ("info", 6), ("honeypot", 7),
];
const CHAIN_CHILD: &[&str] = &["vuln", "danger"];
const CHAIN_PARENT: &[&str] = &["service", "info"];
const LOCAL_CLOSEOUT: &[&str] = &["flag_hunt", "finding_rce_close", "read_to_creds", "finding_sqli_chain", "flag_or_privesc"];
const ADVISOR_DEFER: &[&str] = &["ai-supervisor defer family=", "advisor-bind deny family="];
const ORACLE_REOPEN: &[&str] = &["channel_oracle", "input_abuse"];
const CHAIN_CLOSE: &[&str] = &[
    "ssrf_as_gateway", "secret_mount", "reverse_binary", "protocol_model", "weaponize",
    "finding_rce_close", "finding_sqli_chain", "access_control", "file_read_chain",
    "svc_auth_bruteforce", "hop_auth", "flag_hunt", "flag_or_privesc", "finding_read_loot",
    "read_to_creds", "channel_oracle", "input_abuse", "restricted_deserialize", "filter_bypass",
];
const SSRF_VULN: &[&str] = &["ssrf", "ssrf_internal"];
const RCE_VULN: &[&str] = &["rce", "command_injection", "deserialization", "ssti", "file_upload", "code_exec"];
const CLOSE_FINDING: &[&str] = &[
    "rce", "command_injection", "deserialization", "ssti", "file_read", "lfi", "file_write", "file_upload", "sqli",
];
const SSRF_MECH: &[&str] = &["ssrf_direct", "ssrf_gopher", "ssrf_dns_rebind"];
#[allow(dead_code)]
const HOP_AUTH_FALSE: &str = "未证明认证处理接口收到方法与请求体（或 SSH 尚未出 banner）之前，不能否证 hop_auth。";
const HOP_AUTH_NUDGE: &str = "经已验证跳板看到活着的邻机后，本轮主线是 hop_auth：用图上或简报已有字面量账密/token（含授权测试身份），经该跳板把认证请求体送到邻机处理接口。无请求体的空 POST 不能否证。禁止本机直连，禁止喷字典，禁止再把扫段空号扩进 Scope。";
const SSRF_NOTE: &str = "只有从目标响应里看见、或经 SSRF 拿到登录页/横幅的具体内网主机才 report_pivot_capability（ssrf_*）扩进 Scope。链路本地与云元数据、文档网段、以及超时/无业务正文的错误码差分只证明 SSRF 原语，不要当成新邻机、不要 hop_auth。";
const SECRET_HINT: &str = "浅层路径 404 不能否证带叶子的深层路径，也不等于无挂载点。无密钥基线先找 401/403（路存在），再把同一密钥值用查询参数、请求头、Cookie、body 回挂。没见过 401/403 就不能写无挂载点。字段名不等于查询参数名或头名。";

fn info_ty() -> String { "info".into() }
fn open_st() -> String { "open".into() }
fn med_ty() -> String { "medium".into() }
fn half() -> f64 { 0.5 }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeIn {
    pub key: String,
    #[serde(rename = "type", default = "info_ty")]
    pub node_type: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub detail: Option<Value>,
    #[serde(default = "info_ty")]
    pub severity: String,
    #[serde(default)]
    pub is_rce: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "open_st")]
    pub status: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EdgeIn {
    #[serde(alias = "from")]
    pub src: String,
    #[serde(alias = "to")]
    pub dst: String,
    #[serde(default = "leads")]
    pub relation: String,
    #[serde(default = "half")]
    pub weight: f64,
    #[serde(default)]
    pub rationale: Option<String>,
}
fn leads() -> String { "LEADS_TO".into() }

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FindingIn {
    #[serde(default)]
    pub node_key: Option<String>,
    #[serde(default = "med_ty")]
    pub severity: String,
    #[serde(default = "info_ty")]
    pub category: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub poc_curl: Option<String>,
    #[serde(default)]
    pub poc_python: Option<String>,
    #[serde(default)]
    pub cvss: Option<f64>,
    #[serde(default)]
    pub proof_type: Option<String>,
    #[serde(default)]
    pub proof_canary: Option<String>,
    #[serde(default)]
    pub proof_url: Option<String>,
    #[serde(default)]
    pub proof_detail: Option<String>,
    #[serde(default)]
    pub verification_status: Option<String>,
    #[serde(default)]
    pub finding_id: Option<String>,
    #[serde(default)]
    pub secondary_verified: bool,
    #[serde(default)]
    pub redteam_rating: Option<String>,
    #[serde(default)]
    pub redteam_rating_rationale: Option<String>,
    #[serde(default)]
    pub report_summary: Option<String>,
    #[serde(default)]
    pub report_impact: Option<String>,
    #[serde(default)]
    pub report_rating: Option<String>,
    #[serde(default)]
    pub report_repro: Option<String>,
    #[serde(default)]
    pub report_fix: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IntentIn {
    #[serde(default, alias = "from")]
    pub from_keys: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default = "half")]
    pub est_success: f64,
    #[serde(default)]
    pub strategy_key: Option<String>,
    #[serde(default)]
    pub evidence_fingerprint: Option<String>,
    #[serde(default)]
    pub priority: Option<f64>,
    #[serde(default = "open_st")]
    pub status: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

#[derive(Clone, Debug)]
struct VerifyResult {
    status: String,
    reason: String,
    proof_type: Option<String>,
    proof_canary: Option<String>,
    proof_url: Option<String>,
    proof_detail: Option<String>,
}

struct Mem {
    graph_cache: HashMap<String, (Instant, Value)>,
    intent_at: HashMap<String, Instant>,
    brief: HashMap<String, String>,
    obj_meta: HashMap<String, (bool, String)>,
    attaching: HashSet<String>,
    pivoting: HashSet<String>,
    folding: HashSet<String>,
    rce_sig: HashMap<String, String>,
}

fn mem() -> &'static Mutex<Mem> {
    static M: OnceLock<Mutex<Mem>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(Mem {
        graph_cache: HashMap::new(),
        intent_at: HashMap::new(),
        brief: HashMap::new(),
        obj_meta: HashMap::new(),
        attaching: HashSet::new(),
        pivoting: HashSet::new(),
        folding: HashSet::new(),
        rce_sig: HashMap::new(),
    }))
}

fn lock() -> std::sync::MutexGuard<'static, Mem> {
    mem().lock().unwrap_or_else(|e| e.into_inner())
}

pub fn invalidate_graph_cache(project_id: Option<&str>) {
    let mut g = lock();
    if let Some(id) = project_id {
        g.graph_cache.remove(id);
        g.brief.remove(id);
        g.obj_meta.remove(id);
    } else {
        g.graph_cache.clear();
        g.brief.clear();
        g.obj_meta.clear();
    }
}

fn enter(set: &str, id: &str) -> bool {
    let mut g = lock();
    let bag = match set {
        "attach" => &mut g.attaching,
        "pivot" => &mut g.pivoting,
        _ => &mut g.folding,
    };
    if bag.contains(id) {
        return false;
    }
    bag.insert(id.to_string());
    true
}

fn leave(set: &str, id: &str) {
    let mut g = lock();
    let bag = match set {
        "attach" => &mut g.attaching,
        "pivot" => &mut g.pivoting,
        _ => &mut g.folding,
    };
    bag.remove(id);
}

macro_rules! rex {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static regex::Regex {
            static R: OnceLock<regex::Regex> = OnceLock::new();
            R.get_or_init(|| regex::Regex::new($pat).unwrap())
        }
    };
}

rex!(re_cand, r"(?i)[（(]\s*候选\s*RCE\s*[)）]|候选\s*RCE");
rex!(re_spaces, r"\s{2,}");
rex!(re_cve, r"(?i)cve-\d{4}-\d{4,}");
rex!(re_endpoint, r#"(?i)https?://([^/\s'"?#]+)([^\s'"?#]*)"#);
rex!(re_bare, r"(?i)(?:^|[^A-Za-z0-9_./-])(/[a-z0-9_./~-]{2,160})");
rex!(re_ajax, r"(?i)fusion_form_submit_ajax|fusion_form_update_view|action=fusion_form_[a-z0-9_]+");
rex!(re_exec, r"(?i)\bwhoami\b|uid=\d+|www-data|phpinfo\s*\(|\bshell_exec\b|command executed|命令执行成功|canary_ok");
rex!(re_no_exec, r"(?i)未打成执行|未证明\s*rce|尚未证明|未获得代码执行|rce\s*未证明|upload_failed|未打通|没有解释器|未复现|版本命中|不给\s*rce|不标\s*rce|不能评.{0,8}rce|未打成.{0,6}执行");
rex!(re_write, r"(?i)upload|file_write|file write|写入|上传|fusion-forms");
rex!(re_unproven, r"(?i)(版本对应|版本匹配|疑似|可能存在|参数可疑|n-?day)");
rex!(re_host_at, r"@((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9](?:[\w.-]{0,62}[A-Za-z0-9])?)$");
rex!(re_ipv4, r"(?:^|[^\d.])((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(?:$|[^\d.])");
rex!(re_dash_octets, r"(?:^|[^\d-])(\d{1,3}(?:-\d{1,3}){3})(?:$|[^\d])");
rex!(re_impact, r"(?i)uid=\d+\(|www-data|nt authority|root:[^:\n]*:0:0:|领取成功|兑换成功|发放成功|下单成功|支付成功|订单已");
rex!(re_error_only, r"(?i)角色不存在|参数不完整|活动未配置|没有获奖记录|游戏未配置|Error parsing ObjectId|the \$sort key specification");
rex!(re_empty_data, r#""data"\s*:\s*(\{\s*\}|\[\s*\])"#);
rex!(re_data_span, r#"(?s)"data"\s*:\s*(\{.*?\}|\[.*?\])"#);
rex!(re_path_key, r"(?i)/api/[A-Za-z0-9_./-]+");
rex!(re_transport, r"(?i)(timed?\s*out|timeout|connection refused|unreachable|no route to host|name or service not known|empty reply)");
rex!(re_forbid_peer, r"(不要打|不要碰|别去打|禁止打|勿打|禁打|不要去|禁止当本题|不是本题|禁区|越界)");
rex!(re_hop_intent, r"(?i)(?:^|::)hop_auth$");
rex!(re_delivered, r"(?i)认证(?:处理)?接口.{0,24}(?:收到|送达).{0,24}(?:请求体|body)|表单\s*action.{0,16}(?:收到|送达)|banner.{0,16}(?:已通|已出|SSH-)|字面量.{0,24}Permission denied|请求体.{0,16}已(?:收到|送达)");
rex!(re_wrapper, r"(?i)外壳|根路径|无请求体|没有(?:请求)?体|登录页|未登录|timeout|超时|短转发|通道(?:死|不通)|只收公钥|publickey");
rex!(re_ipv4_loose, r"\b((?:\d{1,3}\.){3}\d{1,3})\b");
rex!(re_nip, r"(?i)(?:^|\.)(?:nip\.io|sslip\.io)$");
rex!(re_identity, r"(?i)登录|login|ssh(?:-|\b)|/22\b|\b22/tcp|password|pass(?:wd|word)|认证|口令");

fn loads(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::String(s) if s.is_empty() => Value::Null,
        Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
        other => other.clone(),
    }
}

fn dumps(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
}

fn dumps_tags(tags: &[String]) -> String {
    Value::Array(tags.iter().cloned().map(Value::String).collect::<Vec<_>>()).to_string()
}

fn row_str(row: &Map<String, Value>, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(true)) => "1".into(),
        Some(Value::Bool(false)) => "0".into(),
        _ => String::new(),
    }
}

fn row_opt(row: &Map<String, Value>, key: &str) -> Option<String> {
    match row.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => Some(other.to_string()),
    }
}

fn row_f64(row: &Map<String, Value>, key: &str) -> f64 {
    match row.get(key) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn row_i64(row: &Map<String, Value>, key: &str) -> i64 {
    match row.get(key) {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(n.as_f64().unwrap_or(0.0) as i64),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        Some(Value::Bool(b)) => i64::from(*b),
        _ => 0,
    }
}

fn row_bool(row: &Map<String, Value>, key: &str) -> bool {
    match row.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0 || n.as_f64().unwrap_or(0.0) != 0.0,
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "true" | "True"),
        _ => false,
    }
}

fn row_tags(row: &Map<String, Value>, key: &str) -> Vec<String> {
    let raw = row.get(key).cloned().unwrap_or(Value::Null);
    match loads(&raw) {
        Value::Array(items) => items.into_iter().map(|v| match v {
            Value::String(s) => s,
            other => other.to_string(),
        }).collect(),
        Value::String(s) if !s.is_empty() => vec![s],
        _ => Vec::new(),
    }
}

fn json_obj(map: Map<String, Value>) -> Value { Value::Object(map) }

fn emit(db: &Db, project_id: &str, kind: &str, payload: Value, run_id: Option<&str>) {
    let blob = payload.to_string();
    let run = run_id.map(|s| s.to_string());
    let ts = now();
    let _ = db.execute(
        "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES (?1,?2,?3,?4,?5)",
        &[&project_id as &dyn ToSql, &run, &ts, &kind, &blob],
    );
}

fn clip_owned(s: &str, n: usize) -> String {
    if s.chars().count() <= n { return s.to_string(); }
    let head: String = s.chars().take(n).collect();
    format!("{head}…")
}

fn opt_clip(v: Option<String>, n: usize) -> Option<String> {
    v.map(|s| if s.is_empty() { s } else { clip_owned(&s, n) })
}

pub fn normalize_objective(obj: Option<&str>) -> &'static str {
    let o = obj.unwrap_or("").trim().to_ascii_lowercase();
    if o == "flag" || o == "ctf" { "flag" } else { "agent" }
}

pub fn objective_allows_flag(obj: Option<&str>) -> bool { normalize_objective(obj) == "flag" }
pub fn objective_is_src(obj: Option<&str>) -> bool { normalize_objective(obj) == "agent" }

pub fn hard_stop_exempt(obj: Option<&str>, flags_correct: i64, verified_high: i64, verified_critical: i64, untested_types: Option<i64>) -> bool {
    if normalize_objective(obj) == "flag" { return flags_correct > 0; }
    if let Some(n) = untested_types { if n > 0 { return false; } }
    verified_high + verified_critical > 0
}

fn sev_rank(s: &str) -> i64 { SEV_RANK.iter().find(|(k, _)| *k == s).map(|(_, n)| *n).unwrap_or(0) }

pub fn normalize_severity(category: Option<&str>, severity: Option<&str>) -> String {
    let mut sev = severity.unwrap_or("").to_string();
    if SEV_RANK.iter().all(|(k, _)| *k != sev) { sev = "info".into(); }
    if let Some(cat) = category {
        if let Some((_, floor)) = SEV_FLOOR.iter().find(|(k, _)| *k == cat.to_ascii_lowercase()) {
            if sev_rank(floor) > sev_rank(&sev) { sev = (*floor).into(); }
        }
    }
    sev
}

fn rating_alias(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "严重" => "critical", "高危" => "high", "中危" => "medium", "低危" => "low", "信息" => "info",
        "crit" | "c" => "critical", "h" => "high", "m" => "medium", "l" => "low",
        _ => return None,
    })
}

pub fn normalize_redteam_rating(raw: Option<&str>) -> Option<String> {
    let s = raw.unwrap_or("").trim();
    if s.is_empty() { return None; }
    let mapped = rating_alias(s).or_else(|| rating_alias(&s.to_ascii_lowercase()));
    let s = mapped.unwrap_or(s).to_ascii_lowercase();
    if ["critical", "high", "medium", "low", "info"].contains(&s.as_str()) { Some(s) } else { None }
}

pub fn display_finding_severity(row: &Map<String, Value>) -> String {
    if let Some(rt) = normalize_redteam_rating(Some(&row_str(row, "redteam_rating"))) { return rt; }
    let sev = row_str(row, "severity").trim().to_ascii_lowercase();
    let sev = if sev.is_empty() { "info".into() } else { sev };
    if SEV_RANK.iter().any(|(k, _)| *k == sev) { sev } else { "info".into() }
}

pub fn compute_risk_score(severity: &str, node_type: &str, is_rce: bool, category: Option<&str>) -> f64 {
    let sev = normalize_severity(category, Some(severity));
    let mut score = SEV_BASE.iter().find(|(k, _)| *k == sev).map(|(_, n)| *n).unwrap_or(5.0);
    if is_rce || node_type == "foothold" || node_type == "goal" { score = score.max(90.0) + 6.0; }
    if node_type == "vuln" || node_type == "danger" { score += 4.0; }
    if category.map(|c| CRITICAL_CATEGORIES.contains(&c.to_ascii_lowercase().as_str())).unwrap_or(false) { score += 4.0; }
    if node_type == "honeypot" { score = score.min(15.0); }
    let capped = score.min(100.0);
    (capped * 10.0).round() / 10.0
}

pub fn is_critical(severity: &str, category: Option<&str>) -> bool {
    let sev = normalize_severity(category, Some(severity));
    sev_rank(&sev) >= sev_rank("high") || category.map(|c| CRITICAL_CATEGORIES.contains(&c.to_ascii_lowercase().as_str())).unwrap_or(false)
}

pub fn scrub_candidate_rce_label(text: &str) -> String {
    if !text.contains('候') { return text.to_string(); }
    let s = re_cand().replace_all(text, "");
    let s = re_spaces().replace_all(&s, " ");
    s.trim_matches(|c: char| c == ' ' || c == '\t' || c == '-' || c == '—' || c == '·' || c == '/' || c == '|').to_string()
}

fn scrub_keep(title: &str) -> String {
    let s = scrub_candidate_rce_label(title);
    if s.is_empty() { title.to_string() } else { s }
}

fn blob_join(parts: &[String]) -> String { parts.join(" ") }

fn execution_proven(parts: &[String]) -> bool {
    let blob = blob_join(parts);
    if re_no_exec().is_match(&blob) && !re_exec().is_match(&blob) { return false; }
    re_exec().is_match(&blob)
}

fn claims_rce(parts: &[String], category: &str) -> bool {
    let cat = category.trim().to_ascii_lowercase();
    if RCE_CATS.contains(&cat.as_str()) { return true; }
    let blob = blob_join(parts).to_ascii_lowercase();
    blob.contains("rce") || blob.contains("命令执行") || blob.contains("getshell")
}

pub fn coerce_unproven_rce_claim(category: &str, severity: &str, rating: Option<&str>, title: &str, description: &str, evidence: &str, poc_curl: &str, poc_python: &str) -> (String, String, Option<String>) {
    let mut cat = { let c = category.trim().to_ascii_lowercase(); if c.is_empty() { "info".into() } else { c } };
    let parts = vec![title.into(), description.into(), evidence.into(), poc_curl.into(), poc_python.into(), cat.clone()];
    let proven = execution_proven(&parts);
    let rce_claim = claims_rce(&parts, &cat);
    if rce_claim && !proven {
        cat = if re_write().is_match(&blob_join(&parts)) { "file_write".into() } else { "vuln".into() };
    }
    let mut sev = normalize_severity(Some(&cat), Some(severity));
    let mut out_rating = normalize_redteam_rating(rating);
    if rce_claim && !proven {
        if sev_rank(&sev) > sev_rank("medium") { sev = "medium".into(); }
        if matches!(out_rating.as_deref(), Some("high") | Some("critical")) { out_rating = Some("medium".into()); }
    }
    (cat, sev, out_rating)
}

fn norm_endpoint(parts: &[String]) -> String {
    let blob = blob_join(parts);
    if let Some(c) = re_endpoint().captures(&blob) {
        let host = c.get(1).map(|m| m.as_str().to_ascii_lowercase().trim_end_matches('.').to_string()).unwrap_or_default();
        let mut path = c.get(2).map(|m| m.as_str()).unwrap_or("/").trim_end_matches('/').to_string();
        if path.is_empty() { path = "/".into(); }
        if path == "/" { return String::new(); }
        return format!("{host}{}", path.to_ascii_lowercase());
    }
    if let Some(c) = re_bare().captures(&blob) {
        let mut path = c.get(1).map(|m| m.as_str()).unwrap_or("/").trim_end_matches('/').to_string();
        if path.is_empty() { path = "/".into(); }
        if path == "/" { return String::new(); }
        return path.to_ascii_lowercase();
    }
    String::new()
}

pub fn finding_dedup_keys(parts: &[String], category: &str, endpoint_parts: Option<&[String]>) -> BTreeSet<String> {
    let blob = blob_join(parts).to_ascii_lowercase();
    let mut keys = BTreeSet::new();
    for m in re_cve().find_iter(&blob) { keys.insert(format!("cve:{}", m.as_str().to_ascii_lowercase())); }
    for m in re_ajax().find_iter(&blob) {
        let cleaned: String = m.as_str().to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        keys.insert(format!("ep:{cleaned}"));
    }
    if blob.contains("fusion-forms") || blob.contains("fusion_form") { keys.insert("ep:fusion_form_upload".into()); }
    let path = norm_endpoint(endpoint_parts.unwrap_or(parts));
    let cat: String = category.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    if !path.is_empty() && !cat.is_empty() { keys.insert(format!("pc:{path}|{cat}")); }
    keys
}

pub fn finding_dedup_keys_from_row(row: &Map<String, Value>) -> BTreeSet<String> {
    let endpoint = vec![row_str(row, "proof_url"), row_str(row, "node_key"), row_str(row, "poc_curl"), row_str(row, "description"), row_str(row, "evidence")];
    let mut parts = vec![row_str(row, "title"), row_str(row, "category")];
    parts.extend(endpoint.clone());
    parts.push(row_str(row, "poc_python"));
    finding_dedup_keys(&parts, &row_str(row, "category"), Some(&endpoint))
}

fn secondary_flag(row: &Map<String, Value>) -> bool {
    match row.get("secondary_verified") {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        Some(Value::String(s)) => !matches!(s.as_str(), "" | "0" | "false" | "False"),
        _ => false,
    }
}

fn canonical_key(row: &Map<String, Value>) -> (i64, f64, String) {
    let sec = if secondary_flag(row) { 1 } else { 0 };
    (-sec, row_f64(row, "created_at"), row_str(row, "id"))
}

pub fn collapse_duplicate_findings(rows: &[Map<String, Value>]) -> Vec<Map<String, Value>> {
    let n = rows.len();
    if n <= 1 { return rows.to_vec(); }
    let keys: Vec<BTreeSet<String>> = rows.iter().map(finding_dedup_keys_from_row).collect();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i { parent[i] = parent[parent[i]]; i = parent[i]; }
        i
    }
    for i in 0..n {
        if keys[i].is_empty() { continue; }
        for j in (i + 1)..n {
            if !keys[j].is_empty() && keys[i].intersection(&keys[j]).next().is_some() {
                let ra = find(&mut parent, i);
                let rb = find(&mut parent, j);
                if ra != rb { parent[rb] = ra; }
            }
        }
    }
    let mut order = Vec::new();
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    for i in 0..n {
        let r = find(&mut parent, i);
        if let Some(pos) = order.iter().position(|x| *x == r) { clusters[pos].push(i); }
        else { order.push(r); clusters.push(vec![i]); }
    }
    clusters.into_iter().map(|members| {
        let mut best = members[0];
        let mut best_key = canonical_key(&rows[best]);
        for idx in members.into_iter().skip(1) {
            let key = canonical_key(&rows[idx]);
            if key < best_key { best = idx; best_key = key; }
        }
        rows[best].clone()
    }).collect()
}

fn finding_family(category: &str) -> String {
    match category.trim().to_ascii_lowercase().as_str() {
        "lfi" | "arbitrary_file_read" | "path_traversal" => "file_read".into(),
        "command_injection" | "file_write" | "file_upload" => "rce".into(),
        other => other.to_string(),
    }
}

fn finding_path_key(title: &str, category: &str) -> String {
    re_path_key().find(&format!("{title} {category}")).map(|m| m.as_str().to_ascii_lowercase()).unwrap_or_default()
}

pub fn sort_findings_by_severity(rows: Vec<Map<String, Value>>) -> Vec<Map<String, Value>> {
    let mut items: Vec<(i64, f64, usize, Map<String, Value>)> = rows.into_iter().enumerate().map(|(i, row)| {
        let sev = display_finding_severity(&row);
        (-sev_rank(&sev), -row_f64(&row, "created_at"), i, row)
    }).collect();
    items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)).then(a.2.cmp(&b.2)));
    items.into_iter().map(|x| x.3).collect()
}

pub fn listed_finding_rows(rows: &[Map<String, Value>]) -> Vec<Map<String, Value>> {
    let mut verified_keys = HashSet::new();
    let mut verified_fam = HashSet::new();
    for row in rows {
        let vs = row_str(row, "verification_status").trim().to_ascii_lowercase();
        if vs.is_empty() || vs == "verified" {
            let key = finding_path_key(&row_str(row, "title"), &row_str(row, "category"));
            if !key.is_empty() { verified_keys.insert(key); }
            let fam = finding_family(&row_str(row, "category"));
            if !fam.is_empty() { verified_fam.insert(fam); }
        }
    }
    let mut kept = Vec::new();
    for row in rows {
        let vs_owned = row_str(row, "verification_status").trim().to_ascii_lowercase();
        let vs = if vs_owned.is_empty() { "verified" } else { vs_owned.as_str() };
        if vs == "rejected" { continue; }
        if vs == "pending" {
            let title = row_str(row, "title");
            let cat = row_str(row, "category");
            let key = finding_path_key(&title, &cat);
            if !key.is_empty() && verified_keys.contains(&key) { continue; }
            if key.is_empty() && verified_fam.contains(&finding_family(&cat)) { continue; }
        }
        kept.push(row.clone());
    }
    sort_findings_by_severity(kept)
}

pub fn finding_row_visible(row: &Map<String, Value>) -> bool {
    row_str(row, "verification_status").trim().to_ascii_lowercase() != "rejected"
}

pub fn is_visible_finding(row: &Map<String, Value>) -> bool {
    let status = row_opt(row, "verification_status").unwrap_or_default();
    let status = status.trim();
    status.is_empty() || ["verified", "flaky", "pending", "excluded"].contains(&status.to_ascii_lowercase().as_str())
}

fn verify_non_exploit(category: &str) -> bool { NON_EXPLOIT.contains(&category.trim().to_ascii_lowercase().as_str()) }

fn verify_has_proof(parts: &[&str]) -> bool { parts.iter().any(|v| !v.trim().is_empty()) }

fn verify_finding(f: &FindingIn) -> VerifyResult {
    let category = f.category.clone();
    let non = verify_non_exploit(&category);
    let proof = verify_has_proof(&[
        f.evidence.as_deref().unwrap_or(""), f.poc_curl.as_deref().unwrap_or(""), f.poc_python.as_deref().unwrap_or(""),
        f.proof_detail.as_deref().unwrap_or(""), f.proof_canary.as_deref().unwrap_or(""), f.proof_url.as_deref().unwrap_or(""),
    ]);
    let (status, reason) = if non { ("pending", "availability_not_exploit") } else if !proof { ("pending", "no_proof") } else { ("verified", "accepted") };
    VerifyResult {
        status: status.into(), reason: reason.into(),
        proof_type: f.proof_type.clone().filter(|s| !s.is_empty()),
        proof_canary: f.proof_canary.clone().filter(|s| !s.is_empty()),
        proof_url: f.proof_url.clone().filter(|s| !s.is_empty()),
        proof_detail: f.proof_detail.clone().filter(|s| !s.is_empty()),
    }
}

fn contains_any(text: &str, marks: &[&str]) -> bool { marks.iter().any(|m| text.contains(m)) }
fn rating_left_alone(rationale: &str) -> bool {
    contains_any(rationale, &["保持原状", "未再动手", "未改二次验证", "不要改二次验证", "只做 NVD", "只做红队评级", "本轮未再", "未做二次验证"])
}
fn secondary_claim_failed(rationale: &str) -> bool {
    contains_any(rationale, &["未复现", "未能复现", "无法复现", "没有复现", "打不出", "未观察到", "未能证明", "没有证明", "未看到同样", "假阳性"])
}
fn recheck_skipped(rationale: &str) -> bool { contains_any(rationale, &["本条意图已经写回", "不再改打别的类型", "这次会话不再"]) }
fn is_real_secondary_failure(rationale: &str) -> bool {
    if rating_left_alone(rationale) || recheck_skipped(rationale) { return false; }
    if rationale.contains("二次验证失败") || secondary_claim_failed(rationale) { return true; }
    rationale.contains("没看到") || rationale.contains("没有看到") || rationale.contains("没有独立证明")
}
fn merge_verification_status(prev_status: &str, prev_secondary: bool, incoming_status: Option<&str>, incoming_secondary: bool, rationale: &str) -> (String, bool) {
    let prev = { let p = prev_status.trim().to_ascii_lowercase(); if p.is_empty() { "pending".into() } else { p } };
    if prev == "excluded" { return ("excluded".into(), false); }
    let incoming = incoming_status.unwrap_or("").trim().to_ascii_lowercase();
    if incoming == "excluded" && is_real_secondary_failure(rationale) && !incoming_secondary { return ("excluded".into(), false); }
    if incoming_secondary && !rating_left_alone(rationale) { return ("verified".into(), true); }
    if prev == "verified" { return ("verified".into(), prev_secondary); }
    let status = if prev.is_empty() || prev == "pending" { "pending".into() } else { prev };
    (status, prev_secondary)
}
fn accept_secondary(mut vr: VerifyResult, secondary: bool) -> VerifyResult {
    if secondary && vr.status != "verified" { vr.status = "verified".into(); vr.reason = "secondary_review".into(); }
    vr
}

fn src_impact_proven(f: &FindingIn) -> bool {
    let evidence = f.evidence.clone().unwrap_or_default();
    let proof_detail = f.proof_detail.clone().unwrap_or_default();
    let proof_canary = f.proof_canary.clone().unwrap_or_default();
    let proof_url = f.proof_url.clone().unwrap_or_default();
    let proof_type = f.proof_type.clone().unwrap_or_default().trim().to_ascii_lowercase();
    let blob = [evidence, proof_detail.clone(), proof_canary.clone(), proof_url.clone()].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join("\n");
    let blob_ok = !blob.trim().is_empty();
    if !blob_ok && !(matches!(proof_type.as_str(), "impact_extract" | "write_txt") && (!proof_canary.is_empty() || !proof_url.is_empty() || !proof_detail.is_empty())) {
        return false;
    }
    if re_impact().is_match(&blob) { return true; }
    if re_error_only().is_match(&blob) { return false; }
    if matches!(proof_type.as_str(), "impact_extract" | "write_txt") && (!proof_canary.is_empty() || !proof_url.is_empty() || !proof_detail.is_empty()) { return true; }
    if blob.trim().is_empty() { return false; }
    let mut payload = false;
    for c in re_data_span().captures_iter(&blob) {
        let raw = c.get(1).map(|m| m.as_str()).unwrap_or("");
        let compact: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
        if compact == "{}" || compact == "[]" || compact == "null" { continue; }
        if compact.len() >= 8 { payload = true; }
    }
    payload && !re_empty_data().is_match(&blob)
}

pub fn finding_review_need(secondary_verified: bool, rating: Option<&str>, verification_status: &str, want_secondary: bool, want_rating: bool) -> Option<String> {
    let has_rating = normalize_redteam_rating(rating).is_some();
    if verification_status.to_ascii_lowercase() == "excluded" {
        if want_rating && !has_rating { return Some("rating".into()); }
        return None;
    }
    let need_sec = want_secondary && !secondary_verified;
    let need_rate = want_rating && !has_rating;
    if need_sec && need_rate { return Some("both".into()); }
    if need_sec { return Some("secondary".into()); }
    if need_rate { return Some("rating".into()); }
    None
}

fn review_flags() -> (bool, bool) { (true, true) }

fn report_from(f: &FindingIn) -> [Option<String>; 5] {
    fn clean(v: &Option<String>) -> Option<String> {
        let s = v.as_deref().unwrap_or("").trim();
        if s.is_empty() { None } else if s.chars().count() <= 8000 { Some(s.to_string()) } else {
            Some(format!("{}…", s.chars().take(8000).collect::<String>().trim_end()))
        }
    }
    [clean(&f.report_summary), clean(&f.report_impact), clean(&f.report_rating), clean(&f.report_repro), clean(&f.report_fix)]
}

pub fn project_track(kind: Option<&str>, config: &Value) -> String {
    let cfg = config.as_object();
    let explicit = cfg.and_then(|m| m.get("track").or_else(|| m.get("objective"))).and_then(Value::as_str).unwrap_or("").trim().to_ascii_lowercase();
    let kind = kind.unwrap_or("single");
    if kind == "benchmark" && explicit.is_empty() { return "ctf".into(); }
    if normalize_objective(if explicit.is_empty() { cfg.and_then(|m| m.get("objective")).and_then(Value::as_str) } else { Some(explicit.as_str()) }) == "flag" {
        "ctf".into()
    } else { "agent".into() }
}

fn node_is_landed_shell(ntype: &str, key: &str, tags: &[String], is_rce: bool) -> bool {
    if ntype != "foothold" && ntype != "goal" { return false; }
    let tags: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    is_rce || tags.iter().any(|t| t == "getshell") || key.starts_with("goal:shell") || key.starts_with("foothold:shell")
}

fn infer_prefix(key: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("target:", "target"), ("svc:", "service"), ("service:", "service"), ("danger:", "danger"),
        ("vuln:", "vuln"), ("cred:", "credential"), ("credential:", "credential"),
        ("foothold:", "foothold"), ("honeypot:", "honeypot"), ("goal:", "goal"),
    ];
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() { return None; }
    PREFIXES.iter().find(|(p, _)| k.starts_with(p)).map(|(_, t)| *t)
}

pub fn infer_node_type_from_key(key: &str) -> Option<String> { infer_prefix(key).map(|s| s.to_string()) }

pub fn humanize_node_key(key: &str) -> String {
    let raw = key.trim();
    if raw.is_empty() || infer_prefix(raw).is_none() { return raw.to_string(); }
    let rest = raw.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    if rest.is_empty() { raw.to_string() } else { rest.to_string() }
}

fn type_rank(name: &str) -> i64 {
    match name {
        "service" => 1, "danger" | "honeypot" => 2, "credential" => 3, "vuln" => 4,
        "foothold" => 5, "target" => 6, "goal" => 7, _ => 0,
    }
}

fn achieved_shell(key: &str, tags: &[String]) -> bool {
    let tags: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    key.trim().starts_with("goal:shell") || tags.iter().any(|t| t == "getshell")
}
fn achieved_flag(key: &str, tags: &[String]) -> bool {
    let tags: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    key.starts_with("goal:flag") || tags.iter().any(|t| t == "flag" || t == "getflag")
}
fn coerce_goal(key: &str, ntype: &str, tags: &[String]) -> String {
    if ntype != "goal" { return ntype.to_string(); }
    if achieved_shell(key, tags) || achieved_flag(key, tags) { "goal".into() } else { "danger".into() }
}

pub fn coerce_declared_node_type(key: &str, ntype: &str, tags: &[String]) -> String {
    let declared_in = if ntype.is_empty() { "info" } else { ntype };
    let declared = coerce_goal(key, declared_in, tags);
    let Some(inferred) = infer_prefix(key) else { return if declared.is_empty() { "info".into() } else { declared }; };
    if inferred == "goal" { return coerce_goal(key, "goal", tags); }
    let lower: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    if inferred == "vuln" && lower.iter().any(|t| t == "placeholder") {
        if type_rank(if declared.is_empty() { "info" } else { declared.as_str() }) <= type_rank("vuln") { return "danger".into(); }
        return if declared.is_empty() { "danger".into() } else { declared };
    }
    let declared_rank = type_rank(if declared.is_empty() { "info" } else { declared.as_str() });
    if declared_rank < type_rank(inferred) { inferred.into() } else if declared.is_empty() { inferred.into() } else { declared }
}

pub fn placeholder_node_spec(key: &str) -> (String, String, String, Vec<String>) {
    let inferred = infer_prefix(key).unwrap_or("info");
    let title = humanize_node_key(key);
    let (ntype, sev) = if inferred == "vuln" {
        ("danger".to_string(), "medium".to_string())
    } else {
        let ntype = coerce_declared_node_type(key, inferred, &[]);
        let sev = if ntype == "foothold" || ntype == "goal" { "critical" } else if ntype == "danger" { "medium" } else { "info" };
        (ntype, sev.to_string())
    };
    (ntype, title, sev, vec!["placeholder".into()])
}

pub fn is_merged_duplicate_title(title: &str) -> bool { title.contains("重复节点") || title.contains("已并入") }

fn detail_empty(detail: &Value) -> bool {
    match loads(detail) {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

pub fn is_placeholder_node(key: &str, title: &str, detail: &Value, tags: &[String]) -> bool {
    let lower: Vec<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    if lower.iter().any(|t| t == "placeholder") { return true; }
    let human = humanize_node_key(key);
    detail_empty(detail) && (title == key || title == human)
}

fn norm_host(host: &str) -> String {
    let mut h = host.trim().to_ascii_lowercase();
    while h.ends_with('.') { h.pop(); }
    if let Some(rest) = h.strip_prefix("::ffff:") { if is_dotted_v4(rest) { return rest.to_string(); } }
    h
}

fn is_dotted_v4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u16>().ok().filter(|n| *n <= 255).is_some())
}

fn parse_ip(host: &str) -> Option<std::net::IpAddr> {
    let h = norm_host(host);
    let h = h.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(h.as_str());
    h.parse().ok()
}

fn cidr_has(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((addr, pref)) = cidr.split_once('/') else { return false };
    let Ok(net) = addr.parse::<Ipv4Addr>() else { return false };
    let Ok(prefix) = pref.parse::<u32>() else { return false };
    if prefix > 32 { return false; }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn ipv4_private_like(ip: Ipv4Addr) -> bool {
    const PRIV: &[&str] = &[
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.0.170/31", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
    ];
    let n = u32::from(ip);
    let inn = PRIV.iter().any(|c| {
        let (addr, pref) = c.split_once('/').unwrap();
        let net = u32::from(addr.parse::<Ipv4Addr>().unwrap());
        let prefix: u32 = pref.parse().unwrap();
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        n & mask == net & mask
    });
    if !inn { return false; }
    !cidr_has(ip, "192.0.0.9/32") && !cidr_has(ip, "192.0.0.10/32")
}

fn ip_private_or_loop_or_link(host: &str) -> bool {
    match parse_ip(host) {
        Some(std::net::IpAddr::V4(ip)) => ipv4_private_like(ip) || ip.is_loopback() || ip.is_link_local(),
        Some(std::net::IpAddr::V6(ip)) => ip.is_loopback() || ((ip.segments()[0] & 0xffc0) == 0xfe80) || ((ip.segments()[0] & 0xfe00) == 0xfc00),
        None => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let h = norm_host(host);
    h == "localhost" || h == "::1" || h.starts_with("127.") || parse_ip(&h).map(|ip| match ip { std::net::IpAddr::V4(v) => v.is_loopback(), std::net::IpAddr::V6(v) => v.is_loopback() }).unwrap_or(false)
}

fn in_doc(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"].iter().any(|c| cidr_has(v4, c)),
        std::net::IpAddr::V6(v6) => v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8,
    }
}

pub fn intra_is_canary(host: &str) -> bool {
    let h = norm_host(host);
    if h.is_empty() { return false; }
    if is_loopback_host(&h) || h == "localhost" || h == "0.0.0.0" || h == "host.docker.internal" { return true; }
    if ["metadata.google.internal", "metadata", "instance-data"].contains(&h.as_str()) { return true; }
    if h.contains("metadata") && (h.ends_with(".internal") || h.contains("google")) { return true; }
    if let Some(ip) = parse_ip(&h) {
        let link = match ip {
            std::net::IpAddr::V4(v4) => v4.is_link_local() || v4.is_multicast() || v4.is_unspecified(),
            std::net::IpAddr::V6(v6) => ((v6.segments()[0] & 0xffc0) == 0xfe80) || v6.is_multicast() || v6.is_unspecified(),
        };
        if link || ip.to_string() == "100.100.100.200" || in_doc(ip) { return true; }
    }
    if re_nip().is_match(&h) {
        let dotted = h.replace('-', ".");
        for c in re_ipv4_loose().captures_iter(&dotted) {
            let inner = c.get(1).map(|m| m.as_str()).unwrap_or("");
            if !inner.is_empty() && inner != h && intra_is_canary(inner) { return true; }
        }
    }
    false
}

fn intra_broadcast(host: &str) -> bool {
    let h = norm_host(host);
    !h.is_empty() && (h.ends_with(".0") || h.ends_with(".255"))
}

pub fn junk_hop_auth_host(host: &str) -> bool { intra_broadcast(host) || intra_is_canary(host) }

#[derive(Clone, Debug, Default)]
pub struct Scope {
    pub targets: Vec<String>,
    pub ips: Vec<String>,
    pub cidrs: Vec<String>,
    pub allow_subdomains: bool,
}

impl Scope {
    pub fn identity_hosts(&self) -> BTreeSet<String> {
        self.targets.iter().chain(self.ips.iter()).map(|t| norm_host(t)).filter(|h| !h.is_empty()).collect()
    }
    pub fn host_in_scope(&self, host: &str) -> bool { host_in_scope(host, self) }
}

fn host_in_scope(host: &str, scope: &Scope) -> bool {
    let h = norm_host(host);
    if h.is_empty() { return false; }
    const INFRA: &[&str] = &["localhost", "127.0.0.1", "::1", "0.0.0.0", "github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "codeload.github.com", "pypi.org", "files.pythonhosted.org", "gitlab.com", "registry.npmjs.org"];
    if INFRA.contains(&h.as_str()) { return true; }
    if scope.identity_hosts().contains(&h) { return true; }
    if let Ok(addr) = h.parse::<std::net::IpAddr>() {
        if scope.cidrs.iter().any(|c| match addr { std::net::IpAddr::V4(v4) => cidr_has(v4, c), _ => false }) { return true; }
    }
    if scope.allow_subdomains {
        for t in &scope.targets {
            let apex = norm_host(t);
            if !apex.is_empty() && (h == apex || h.ends_with(&format!(".{apex}"))) { return true; }
        }
    }
    false
}

pub fn unauthorized_public_host(host: &str, scope: &Scope) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) { return None; }
    if host_in_scope(&h, scope) { return None; }
    let mut names: Vec<String> = scope.identity_hosts().into_iter().collect();
    names.sort();
    names.truncate(8);
    let shown = if names.is_empty() { "当前作业对象".into() } else { names.join("、") };
    Some(format!("{h} 不在本项目已授权主机内（{shown}）"))
}

fn host_from_tags(tags: &[String]) -> String {
    for t in tags {
        if let Some(rest) = t.strip_prefix("host:") {
            let h = rest.trim().to_ascii_lowercase().trim_end_matches('.').to_string();
            if !h.is_empty() { return h; }
        }
    }
    String::new()
}

pub fn host_from_target_key(key: &str) -> String {
    if key.starts_with("target:") {
        return key.split_once(':').map(|(_, r)| r).unwrap_or("").split(':').next().unwrap_or("").trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    }
    String::new()
}

pub fn host_from_asset_key(key: &str) -> String {
    let host = host_from_target_key(key);
    if !host.is_empty() { return host; }
    if key.starts_with("info:host:") || key.starts_with("info:scope-expanded:") {
        return key.split(':').nth(2).unwrap_or("").split(':').next().unwrap_or("").trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    }
    String::new()
}

pub fn host_of_node(key: &str, tags: &[String]) -> String {
    let h = host_from_tags(tags);
    if !h.is_empty() { return h; }
    if let Some(c) = re_host_at().captures(key) { return c.get(1).map(|m| m.as_str().to_ascii_lowercase().trim_end_matches('.').to_string()).unwrap_or_default(); }
    let h = host_from_asset_key(key);
    if !h.is_empty() { return h; }
    if let Some(c) = re_ipv4().captures(key) { return c.get(1).map(|m| m.as_str().to_ascii_lowercase().trim_end_matches('.').to_string()).unwrap_or_default(); }
    String::new()
}

pub fn is_rfc1918(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_string();
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 { return false; }
    let nums: Vec<i64> = match parts.iter().map(|p| p.parse::<i64>()).collect::<Result<Vec<_>, _>>() { Ok(v) => v, Err(_) => return false };
    if nums.iter().any(|n| *n < 0 || *n > 255) { return false; }
    let (a, b) = (nums[0], nums[1]);
    a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
}

fn same_slash24(a: &str, b: &str) -> bool {
    let a = a.trim().to_ascii_lowercase();
    let b = b.trim().to_ascii_lowercase();
    let pa: Vec<&str> = a.split('.').collect();
    let pb: Vec<&str> = b.split('.').collect();
    pa.len() == 4 && pb.len() == 4 && pa[..3] == pb[..3]
}

fn vuln_pivot_tags(tags: &[String]) -> bool {
    let set: HashSet<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    ["ssrf", "via-live", "getshell", "shell", "rce", "vuln-pivot"].iter().any(|t| set.contains(*t))
}

pub fn should_promote_intranet_host(host: &str, tags: &[String], primary: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.').to_string();
    if host.is_empty() { return false; }
    if !primary.is_empty() && host == primary { return false; }
    let set: HashSet<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    if set.contains("entry") { return false; }
    if set.contains("vhost") || set.contains("same-machine") { return false; }
    if set.contains("clue-only") && !set.contains("via-live") { return false; }
    vuln_pivot_tags(tags)
}

fn target_key_allowed(key: &str, tags: &[String], primary: &str, pivot_dst: &HashSet<String>) -> bool {
    if !key.starts_with("target:") { return false; }
    let host = key.split_once(':').map(|(_, r)| r).unwrap_or("").split('/').next().unwrap_or("").trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    if host.is_empty() { return false; }
    if !primary.is_empty() && host == primary && key == format!("target:{primary}") { return true; }
    if !primary.is_empty() && host == primary { return false; }
    if pivot_dst.contains(key) { return true; }
    vuln_pivot_tags(tags)
}

fn derive_category(node_type: &str, tags: &[String], is_rce: bool) -> String {
    let set: HashSet<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    let known = ["rce", "command_injection", "deserialization", "sqli", "file_upload", "file_write", "file_read", "lfi", "ssrf", "auth_bypass", "unauth", "idor", "admin_access", "privilege_escalation", "xxe", "ssti", "xss"];
    for k in known {
        if set.contains(k) || set.iter().any(|t| t.contains(k)) { return k.into(); }
    }
    if is_rce || node_type == "foothold" || node_type == "goal" { "rce".into() } else { "vuln".into() }
}

fn canon_host_fragment(host: &str) -> String {
    let host = host.trim().to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_string();
    let parts: Vec<&str> = host.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() == 4 { let mut p = parts; p.sort(); p.join("-") } else { String::new() }
}

fn mentions_host(text: &str, host: &str, allow_octet: bool) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or("").trim_end_matches('.').to_string();
    if text.is_empty() || host.is_empty() { return false; }
    let mut parts = vec![
        format!(r"(?<![\d.]){}(?![\d.])", regex::escape(&host)),
        format!(r"(?<![\d-]){}(?![\d])", regex::escape(&host.replace('.', "-"))),
    ];
    let frag = canon_host_fragment(&host);
    if !frag.is_empty() { parts.push(format!(r"(?<![\d-]){}(?![\d])", regex::escape(&frag))); }
    if allow_octet {
        if let Some(last) = host.rsplit('.').next() { if last.chars().all(|c| c.is_ascii_digit()) { parts.push(format!(r"(?<![\d.])\.{last}(?!\d)")); } }
    }
    regex::Regex::new(&parts.join("|")).map(|r| r.is_match(text)).unwrap_or(false)
}

fn private_hosts_in_text(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in re_ipv4().captures_iter(text) {
        let h = m.get(1).map(|x| x.as_str()).unwrap_or("").to_ascii_lowercase().trim_end_matches('.').to_string();
        if is_rfc1918(&h) { out.insert(h); }
    }
    out
}

fn absent_canon_fragments(text: &str, live: &HashSet<String>) -> bool {
    for m in re_dash_octets().captures_iter(text) {
        let frag = m.get(1).map(|x| x.as_str()).unwrap_or("");
        let nums: Vec<&str> = frag.split('-').collect();
        if nums.iter().any(|n| n.parse::<i64>().map(|v| v > 255).unwrap_or(true)) { continue; }
        if live.contains(frag) { continue; }
        let end = m.get(1).map(|x| x.end()).unwrap_or(0);
        let start = m.get(1).map(|x| x.start()).unwrap_or(0);
        let after: String = text[end..text.len().min(end + 16)].trim_start_matches(['-', ':']).to_string();
        let before = text[start.saturating_sub(16)..start].to_ascii_lowercase();
        if after.to_ascii_lowercase().starts_with("target") || before.contains("target") { return true; }
    }
    false
}

fn private_hosts(text: &str, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for c in re_ipv4_loose().captures_iter(text) {
        let h = norm_host(c.get(1).map(|m| m.as_str()).unwrap_or(""));
        if h.is_empty() || seen.contains(&h) || h.ends_with(".0") || h.ends_with(".255") { continue; }
        if !is_dotted_v4(&h) || !ip_private_or_loop_or_link(&h) || is_loopback_host(&h) { continue; }
        seen.insert(h.clone());
        out.push(h);
        if out.len() >= limit.max(1) { break; }
    }
    out
}

pub fn intent_private_hosts(item: &Value) -> Vec<String> {
    let blob = ["from_keys", "description", "strategy_key", "rationale"].iter().map(|k| item.get(*k).map(|v| v.to_string()).unwrap_or_default()).collect::<Vec<_>>().join(" ");
    private_hosts(&blob, 8)
}

fn value_host(node: &Value) -> String {
    let key = node.get("key").and_then(Value::as_str).unwrap_or("");
    let tags = json_tags(node.get("tags"));
    let h = host_from_asset_key(key);
    if !h.is_empty() { return h; }
    host_from_tags(&tags)
}

fn json_tags(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().unwrap_or("").to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => match serde_json::from_str::<Vec<String>>(s) { Ok(v) => v, Err(_) => vec![s.clone()] },
        _ => Vec::new(),
    }
}

fn graph_nodes(graph: &Value) -> Vec<Value> {
    graph.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn node_tagset(node: &Value) -> BTreeSet<String> {
    json_tags(node.get("tags")).into_iter().map(|t| t.to_ascii_lowercase()).collect()
}

fn hosts_from_json_node(node: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let h = value_host(node);
    if !h.is_empty() && ip_private_or_loop_or_link(&h) && !is_loopback_host(&h) && !intra_broadcast(&h) { out.insert(h); }
    let blob = format!("{} {}", node_blob(node), json_tags(node.get("tags")).join(" "));
    for h in private_hosts(&blob, 16) { out.insert(h); }
    for t in json_tags(node.get("tags")) {
        if let Some(rest) = t.to_ascii_lowercase().strip_prefix("host:") {
            let hh = norm_host(rest);
            if !hh.is_empty() && ip_private_or_loop_or_link(&hh) && !is_loopback_host(&hh) && !intra_broadcast(&hh) { out.insert(hh); }
        }
    }
    out
}

fn node_blob(node: &Value) -> String {
    format!("{} {} {}", node.get("key").and_then(Value::as_str).unwrap_or(""), node.get("title").and_then(Value::as_str).unwrap_or(""), detail_text(node.get("detail").unwrap_or(&Value::Null)))
}

fn detail_text(v: &Value) -> String {
    match loads(v) {
        Value::Object(m) => m.values().map(|x| match x { Value::String(s) => s.clone(), o => o.to_string() }).collect::<Vec<_>>().join(" "),
        Value::String(s) => s,
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn ssrf_gateway_hosts(graph: &Value) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let absorb = |hosts: &mut BTreeSet<String>, raw: &str| {
        let h = raw.trim().to_ascii_lowercase();
        let h = h.split('/').next().unwrap_or("").split(':').next().unwrap_or("").to_string();
        if !h.is_empty() && h != "localhost" && h != "127.0.0.1" { hosts.insert(h); }
    };
    for n in graph_nodes(graph) {
        let key = n.get("key").and_then(Value::as_str).unwrap_or("");
        let detail = detail_text(n.get("detail").unwrap_or(&Value::Null)).to_ascii_lowercase();
        let title = n.get("title").and_then(Value::as_str).unwrap_or("");
        let blob = format!("{key} {title} {detail}").to_ascii_lowercase();
        let tagset = node_tagset(&n);
        let keep = if key.starts_with("info:scope-expanded:") { true }
            else if key.starts_with("target:") && (tagset.contains("ssrf") || tagset.contains("pivot") || tagset.contains("scope-expanded") || blob.contains("ssrf") || SSRF_MECH.iter().any(|m| blob.contains(m))) { true }
            else { false };
        if !keep { continue; }
        let via = SSRF_MECH.iter().any(|m| blob.contains(m)) || blob.contains("ssrf") || tagset.iter().any(|t| t.starts_with("ssrf"));
        if !via { continue; }
        if key.starts_with("target:") { absorb(&mut hosts, key.split_once(':').map(|(_, r)| r).unwrap_or("")); }
        else { absorb(&mut hosts, key.split(':').nth(2).unwrap_or("")); }
        for t in &tagset { if let Some(rest) = t.strip_prefix("host:") { absorb(&mut hosts, rest); } }
    }
    for e in graph.get("edges").and_then(Value::as_array).cloned().unwrap_or_default() {
        let rel = e.get("relation").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase();
        let rat = e.get("rationale").or_else(|| e.get("detail")).map(|v| v.to_string()).unwrap_or_default().to_ascii_lowercase();
        if rel == "PIVOTS_TO" { if !SSRF_MECH.iter().any(|m| rat.contains(m)) && !rat.contains("ssrf") { continue; } }
        else if rel == "LEADS_TO" { if !rat.contains("pivot_capability") && !rat.contains("ssrf") { continue; } }
        else { continue; }
        let dst = e.get("to").or_else(|| e.get("dst")).and_then(Value::as_str).unwrap_or("");
        if dst.starts_with("target:") { absorb(&mut hosts, dst.split_once(':').map(|(_, r)| r).unwrap_or("")); }
        else if dst.starts_with("info:host:") || dst.starts_with("info:scope-expanded:") { absorb(&mut hosts, dst.split(':').nth(2).unwrap_or("")); }
    }
    hosts
}

fn is_entry_json(n: &Value) -> bool {
    let key = n.get("key").and_then(Value::as_str).unwrap_or("");
    let ntype = n.get("type").and_then(Value::as_str).unwrap_or("");
    if ntype != "target" && !key.starts_with("target:") { return false; }
    let tags = node_tagset(n);
    if tags.contains("entry") { return true; }
    if ["lateral", "pivot", "internal", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t)) { return false; }
    true
}

pub fn via_capability_hosts(graph: &Value, scope: Option<&Scope>) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut entry = BTreeSet::new();
    let via_tags = ["scope-expanded", "via-capability", "pivot", "ssrf", "shell_reachable", "port_forward", "socks_tunnel", "via-live"];
    let pivot = ["lateral", "pivot", "internal", "scope-expanded", "via-live"];
    for n in graph_nodes(graph) {
        let key = n.get("key").and_then(Value::as_str).unwrap_or("").to_string();
        let ntype = n.get("type").and_then(Value::as_str).unwrap_or("");
        let h = host_from_asset_key(&key);
        if is_entry_json(&n) { if !h.is_empty() { entry.insert(h); } continue; }
        let tags = node_tagset(&n);
        let via = key.starts_with("info:scope-expanded:") || (ntype == "target" && pivot.iter().any(|t| tags.contains(*t))) || via_tags.iter().any(|t| tags.contains(*t));
        if !via { continue; }
        if !h.is_empty() && ip_private_or_loop_or_link(&h) && !is_loopback_host(&h) && !intra_is_canary(&h) { out.insert(h); }
    }
    for h in entry { out.remove(&h); }
    if let Some(scope) = scope {
        for raw in &scope.ips {
            let h = norm_host(raw);
            if h.is_empty() || !ip_private_or_loop_or_link(&h) || is_loopback_host(&h) || intra_is_canary(&h) { continue; }
            if out.contains(&h) { out.insert(h); }
        }
    }
    out.into_iter().collect()
}

fn node_live(node: &Value) -> bool {
    let tags = node_tagset(node);
    if tags.contains("clue-only") && !tags.contains("via-live") { return false; }
    let h = value_host(node);
    if !h.is_empty() && (intra_broadcast(&h) || intra_is_canary(&h)) { return false; }
    if tags.contains("via-live") { return true; }
    let key = node.get("key").and_then(Value::as_str).unwrap_or("");
    if key.starts_with("info:scope-expanded:") && !tags.contains("clue-only") { return true; }
    let ntype = node.get("type").and_then(Value::as_str).unwrap_or("");
    ntype == "target" && ["lateral", "pivot", "scope-expanded", "via-live"].iter().any(|t| tags.contains(*t))
}

fn foothold_hosts(graph: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut entry = BTreeSet::new();
    for n in graph_nodes(graph) {
        let key = n.get("key").and_then(Value::as_str).unwrap_or("");
        let ntype = n.get("type").and_then(Value::as_str).unwrap_or("");
        if is_entry_json(&n) { let h = host_from_asset_key(key); if !h.is_empty() { entry.insert(h); } continue; }
        let tags = node_tagset(&n);
        let is_rce = n.get("is_rce").and_then(Value::as_bool).unwrap_or(false) || row_like_bool(n.get("is_rce"));
        let shell = (ntype == "goal" && (is_rce || key.starts_with("goal:shell") || tags.contains("getshell"))) || (ntype == "foothold" && (is_rce || tags.contains("getshell") || ntype == "foothold"));
        if ntype == "foothold" || shell { out.extend(hosts_from_json_node(&n)); }
    }
    out.into_iter().filter(|h| !entry.contains(h)).collect()
}

fn row_like_bool(v: Option<&Value>) -> bool {
    match v { Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0, Some(Value::Bool(b)) => *b, _ => false }
}

fn hop_eligible(node: &Value, graph: Option<&Value>) -> bool {
    let h = value_host(node);
    if !h.is_empty() && (intra_broadcast(&h) || intra_is_canary(&h)) { return false; }
    if let Some(g) = graph { if !h.is_empty() && foothold_hosts(g).contains(&h) { return false; } }
    let tags = node_tagset(node);
    if tags.contains("via-live") { return true; }
    let blob = format!("{} {}", node_blob(node), tags.iter().cloned().collect::<Vec<_>>().join(" "));
    if re_identity().is_match(&blob) { return true; }
    if let Some(g) = graph {
        if !h.is_empty() && live_surface_hosts(g).contains(&h) { return true; }
    }
    false
}

fn live_surface_hosts(graph: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for n in graph_nodes(graph) { if node_tagset(&n).contains("via-live") { out.extend(hosts_from_json_node(&n)); } }
    out
}

struct Nv {
    key: String,
    ntype: String,
    title: String,
    severity: String,
    is_rce: bool,
    tags: BTreeSet<String>,
    blob: String,
    #[allow(dead_code)]
    raw_blob: String,
}

pub struct Hyp {
    pub from_keys: Vec<String>,
    pub description: String,
    pub rationale: String,
    pub est_success: f64,
    pub strategy_key: String,
    pub evidence_fingerprint: String,
    pub priority: f64,
    pub depends_on: Vec<String>,
}

fn node_of(node: &Value) -> Nv {
    let key = node.get("key").and_then(Value::as_str).unwrap_or("").to_string();
    let title = node.get("title").and_then(Value::as_str).unwrap_or("").to_string();
    let detail = detail_text(node.get("detail").unwrap_or(&Value::Null));
    let tags: BTreeSet<String> = json_tags(node.get("tags")).into_iter().map(|t| t.to_ascii_lowercase()).collect();
    let tag_join = tags.iter().cloned().collect::<Vec<_>>().join(" ");
    let blob = format!("{key} {title} {detail} {tag_join}").to_ascii_lowercase();
    let raw_blob = format!("{title} {detail} {key}");
    let is_rce = row_like_bool(node.get("is_rce")) || node.get("is_rce").and_then(Value::as_bool).unwrap_or(false);
    let severity = node.get("severity").and_then(Value::as_str).unwrap_or("info").to_string();
    Nv { key, ntype: node.get("type").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase(), title, severity, is_rce, tags, blob, raw_blob }
}

fn canon_source(source: &str) -> String {
    let mut s = source.trim().to_ascii_lowercase();
    for p in ["vuln:", "danger:", "svc:", "service:", "cred:", "credential:", "info:", "foothold:", "goal:", "file:", "dir:", "web:", "host:"] {
        if let Some(rest) = s.strip_prefix(p) { s = rest.to_string(); break; }
    }
    let mut toks: Vec<String> = regex::Regex::new(r"[^a-z0-9]+").unwrap().split(&s).filter(|t| !t.is_empty()).map(|t| t.to_string()).collect();
    if toks.is_empty() { return s; }
    toks.sort();
    toks.join("-")
}

pub fn strategy_key(source_key: &str, tactic: &str) -> String {
    let sk = format!("{}::{tactic}", canon_source(source_key)).trim().to_ascii_lowercase();
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

fn sev_n(s: &str) -> f64 { match s { "low" => 1.0, "medium" => 2.0, "high" => 3.0, "critical" => 4.0, _ => 0.0 } }
fn priority_of(base: f64, severity: &str, boost: f64) -> f64 { ((base + sev_n(severity) * 0.04 + boost).clamp(0.05, 0.99) * 1000.0).round() / 1000.0 }

fn hyp(node: &Nv, tactic: &str, description: String, rationale: &str, est: f64, severity: &str, boost: f64, extra: &str) -> Hyp {
    Hyp {
        from_keys: vec![node.key.clone()],
        description,
        rationale: rationale.into(),
        est_success: est,
        strategy_key: strategy_key(&node.key, tactic),
        evidence_fingerprint: fingerprint(node, if extra.is_empty() { tactic } else { extra }),
        priority: priority_of(est, severity, boost),
        depends_on: Vec::new(),
    }
}

rex!(re_gadget, r"(?i)\bssrf\b|open\s*proxy|gopher://|file://|跳板|导入面|upload");
rex!(re_auto_from, r"(?i)auto from (?:https?://|http_request)");
rex!(re_negative, r"(?i)无挂载|无\s*HTTP\s*挂载|挂载点.{0,6}无|无任何挂载|差分.{0,12}闭环|全闭环|面.{0,8}穷尽|穷尽.{0,8}(?:路由|HTTP|功能)|终审|no[-_ ]?(?:http[-_ ]?)?mount|exhausted|仅有?\s*\d+\s*条?(?:路由|路径)|其余.{0,8}404|全部.?404|分析方法.{0,12}穷尽|全部.{0,16}穷尽|无法通过现有方法|纯诱饵|判定为诱饵|确为诱饵|(?:^|[^不])是诱饵|\bdecoy\b|\btheater\b|全负|口令空间.{0,12}(?:穷尽|全负)|登录门.{0,16}全部失败|突破尝试全部失败|爆破失败|brute[-_ ]?fail|强随机|不可爆破");
rex!(re_channel_neg, r"(?i)通道否证|否证.{0,12}(?:SSRF|通道|网关|跳板)|判定为存根|同体.{0,12}400|硬\s*400|存根级|恒定\s*4\d\d|统一\s*4\d\d");
rex!(re_binary, r"(?i)逆向|可执行文件|固件|字节码|bytecode|\bELF\b|octet-stream|自定义\s*(?:VM|执行)|自研\s*(?:VM|执行)|stripped\s+binary|analy[sz]e.{0,24}(?:executable|binary)|(?:executable|binary).{0,16}analy");
rex!(re_local_gate, r"(?i)访问码|access[_\s-]?code|argv\s*\[|license[_\s-]?key");
rex!(re_local_bin, r"(?i)\bELF\b|stripped|validator|bytecode|自定义\s*VM|自研\s*(?:VM|执行)|\./[A-Za-z0-9_.-]+");
rex!(re_secret, r#"(?i)\b(admin[_-]?token|api[_-]?key|access[_-]?token|secret[_-]?key|bearer|auth[_-]?token|internal[_-]?token)\b|["']?(?:token|secret|api_key|apikey)["']?\s*[:=]"#);
rex!(re_login, r"(?i)(?:\b(?:password|passwd|username|default-cred|default.creds)\b|口令|账密|用户名)");
rex!(re_user_slash, r"^[\w.@+-]+/.+");
rex!(re_token, r"(?i)\bjwt\b|\bjws\b|\bjwe\b|\bhs256\b|\brs256\b|\bes256\b|json\s*web\s*token|signed\s+(?:token|cookie)|hmac-sha");
rex!(re_auth_svc, r"(?i)\b(?:sshd?|rdp|smb|ftp|redis|mysql|mariadb|postgres(?:ql)?|mongo(?:db)?|telnet|vnc)\b");
rex!(re_dsn, r"(?i)jdbc:|redis://|mysql://|mongodb://|postgres(?:ql)?://|\.rds\.|\.internal(?:[.:/\s]|$)|(?:^|[^a-z])db_host\s*[:=]");
rex!(re_uniform, r"(?i)恒定\s*\d{3}|恒\s*\d{3}|无条件\s*\d{3}|持续\s*\d{3}|统一(?:错误|模板|状态)|无差异|无\s*set-cookie|没有\s*set-cookie|无\s*cookie|uniform\s+(?:error|status)|\balways\s+\d{3}\b|no\s+set-cookie");
rex!(re_uniform5, r"(?i)恒定\s*5\d\d|恒\s*5\d\d|无条件\s*5\d\d|持续\s*5\d\d|always\s+5\d\d|统一(?:错误|模板).{0,12}5\d\d");
rex!(re_false_close, r"(?i)(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|(?:该|此)面(?:已死|关闭)|面已关|通道级否证|确定性\s*500|死面|输入无关|无条件崩溃");
rex!(re_channel_diff, r"(?i)时间差|长度差|布尔差|耗时差|延时差|timing\s+diff|length\s+diff|boolean\s+diff|差分.{0,12}(?:耗时|长度|rtt|delay)");
rex!(re_file_delivery, r"(?i)\bdownload\b|\battachment\b|\breadfile\b|\bsendfile\b|\bsend_file\b|filepath|file_path|fileid|file_id|localfile|local_file|\bfilename\b|\blfi\b|任意文件|文件下载|附件下载|路径穿越|path.?traversal|[?&](?:file|filename|filepath|path|doc|document|attachment)=|/(?:file|files|download|attach|attachment|export)(?:\.[a-z0-9]+)?");
rex!(re_authz, r"(?i)\b(401|403)\b|unauthorized|www-authenticate");
rex!(re_crash, r"(?i)availability|error_handling|misconfig|\bdos\b|\bcrash\b|崩溃|可用性|渲染层|视图层|模板异常|确定性\s*500");
rex!(re_exploit, r"(?i)sqli|sql.?inject|sql注入|db_access|\brce\b|command.inject|\bssrf\b|\blfi\b|file_read|file_write|file_upload|ssti|deserial|unauth|auth_bypass|\bidor\b|xxe");
rex!(re_process, r"(?i)(?:变体|包装|绕过族).{0,12}(?:失败|否证)|探测失败|仍被(?:拦|阻止|拒绝)|过程笔记");
rex!(re_non_asset, r"(?i)枚举进行中|进行中[,，。]|\binflight\b|无业务逻辑|零业务|模板\s*UI|表单结构|字段.{0,40}username\s*/\s*password|csrf.?token.?头|非POST未带");
rex!(re_info_leak, r"(?i)(?:泄露|泄漏|注释).{0,16}(?:password|passwd|token|口令|账号|credential)|(?:password|passwd|口令)\s*[=:]\s*\S|\b(?:default[-_ ]creds?|test:test|有效账号|默认口令)\b");
rex!(re_info_cred, r"(?i)\b(password|passwd|token|secret|credential|账号|口令)\b");
rex!(re_form_cred, r"(?i)表单|字段|username\s*/\s*password|POST\s+/login");
rex!(re_info_danger, r#"(?i)(?:(?:^|[\s"'=])/admin\b|\bswagger\b|\bendpoint\b|\bapi/[A-Za-z]|\bdebug\s*(?:port|panel|interface|endpoint))"#);
rex!(re_wild, r"(?i)通配映射|未知.{0,16}action.{0,24}首页|首页.{0,16}\d{4,6}\s*B");
rex!(re_linked, "前端引用|端点全集|端点清单|仅\\s*\\d+\\s*个|目录枚举收益低|映射面很窄|继续目录枚举");
rex!(re_static_trav, "文件面封死|读文件面全否证|静态目录穿越|WEB-INF.{0,12}否证");
rex!(re_action, r"/([A-Za-z][A-Za-z0-9_]*)((?:![A-Za-z][A-Za-z0-9_]*)*)\.action\b");
rex!(re_fake_action, r"/([A-Za-z][A-Za-z0-9_]*)(?:![A-Za-z][A-Za-z0-9_]*)*\.action[^\n]{0,32}不是真实");

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
const GADGET_TAGS: &[&str] = &["ssrf", "ssrf_internal", "ssrf_as_gateway", "proxy", "import", "upload", "open_proxy", "ssrf-echo", "ssrf_echo"];
const EXPLOIT_TAGS: &[&str] = &["sqli", "sql-injection", "sql注入", "db_access", "rce", "command_injection", "ssrf", "ssrf_internal", "lfi", "file_read", "file_write", "file_upload", "ssti", "deserialization", "unauth", "auth_bypass", "idor", "xxe"];
const CRASH_TAGS: &[&str] = &["availability", "crash", "dos", "error_handling", "misconfig", "template"];

fn any_in(blob: &str, tags: &BTreeSet<String>, needles: &[&str]) -> bool {
    needles.iter().any(|n| blob.contains(&n.to_ascii_lowercase()) || tags.contains(*n))
}
fn channel_neg(blob: &str, title: &str) -> bool { re_channel_neg().is_match(&format!("{title} {blob}")) }
fn negative(blob: &str, title: &str) -> bool { !channel_neg(blob, title) && re_negative().is_match(&format!("{title} {blob}")) }
fn gadget(blob: &str, tags: &BTreeSet<String>, title: &str) -> bool {
    if tags.iter().any(|t| GADGET_TAGS.contains(&t.as_str())) { return true; }
    let hay = format!("{title} {blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    if re_auto_from().is_match(&hay) { return false; }
    re_gadget().is_match(&hay)
}
fn looks_binary(blob: &str, title: &str, brief: &str) -> bool { re_binary().is_match(&format!("{title} {blob} {brief}")) }
fn local_gate(blob: &str, title: &str) -> bool { let s = format!("{title} {blob}"); re_local_gate().is_match(&s) && re_local_bin().is_match(&s) }
fn looks_secret(blob: &str, tags: &BTreeSet<String>) -> bool {
    tags.iter().any(|t| ["token", "api-key", "api_key", "secret", "config-leak", "config_leak"].contains(&t.as_str())) || re_secret().is_match(blob)
}
fn login_cred(blob: &str, title: &str) -> bool {
    if local_gate(blob, title) { return false; }
    re_login().is_match(blob) || re_login().is_match(title) || re_user_slash().is_match(title.trim())
}
fn is_http_svc(blob: &str, tags: &BTreeSet<String>) -> bool {
    let hay = format!("{blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    ["http", "https", "apache", "nginx", "php", "tomcat", "weblogic", "spring", "iis", "gunicorn", "uwsgi", "flask", "django", "fastapi", "web 应用", "web应用"].iter().any(|x| hay.contains(x))
}
fn is_token(blob: &str, tags: &BTreeSet<String>, title: &str) -> bool {
    tags.iter().any(|t| ["jwt", "jws", "jwe", "hs256", "signed_token"].contains(&t.as_str())) || re_token().is_match(blob) || re_token().is_match(title)
}
fn nv_rce(node: &Nv) -> bool { node.is_rce || any_in(&node.blob, &node.tags, &["rce", "command", "shell", "desp"]) }
fn nv_ssrf(node: &Nv) -> bool { node.blob.contains("ssrf") || node.tags.contains("ssrf") }
fn info_oracle(blob: &str, title: &str) -> bool {
    let text = format!("{title} {blob}");
    if re_channel_diff().is_match(&text) || channel_neg(blob, title) { return false; }
    re_uniform5().is_match(&text) || re_false_close().is_match(&text)
}
fn process_note(blob: &str, title: &str, key: &str) -> bool { key.contains(":exec:") || key.contains(":knife:") || re_process().is_match(&format!("{title} {blob}")) }
fn non_asset(blob: &str, title: &str) -> bool { re_non_asset().is_match(&format!("{title} {blob}")) }
fn leaked_login(blob: &str, title: &str) -> bool {
    if negative(blob, title) || non_asset(blob, title) || process_note(blob, title, "") || channel_neg(blob, title) { return false; }
    let text = format!("{title} {blob}");
    re_info_leak().is_match(&text) || (re_info_cred().is_match(&text) && !re_form_cred().is_match(&text))
}
fn file_delivery(blob: &str, title: &str, key: &str) -> bool { re_file_delivery().is_match(&format!("{key} {title} {blob}")) }
fn crash_only(node: &Nv) -> bool {
    if node.tags.iter().any(|t| EXPLOIT_TAGS.contains(&t.as_str())) || re_exploit().is_match(&node.blob) { return false; }
    node.tags.iter().any(|t| CRASH_TAGS.contains(&t.as_str())) || re_crash().is_match(&node.blob)
}
fn filter_hit(node: &Nv) -> bool { any_in(&node.blob, &node.tags, &["403", "waf", "拦截", "blocked", "forbidden", "filter"]) }
fn skips_filter(node: &Nv, ssrf: bool) -> bool { ssrf || gadget(&node.blob, &node.tags, &node.title) }

fn surfaces_of(blob: &str, tags: &BTreeSet<String>) -> Vec<String> {
    let hay = format!("{blob} {}", tags.iter().cloned().collect::<Vec<_>>().join(" "));
    let mut out = Vec::new();
    for (name, _, _, _) in SURFACES { if tags.contains(*name) || hay.contains(name) { out.push((*name).to_string()); } }
    if out.iter().any(|x| x == "object_store") { out.retain(|x| x != "xml"); }
    out
}

fn push_surfaces(out: &mut Vec<Hyp>, node: &Nv, sev: &str) {
    let want: BTreeSet<String> = surfaces_of(&node.blob, &node.tags).into_iter().collect();
    for (name, tactic, desc, why) in SURFACES {
        if !want.contains(*name) { continue; }
        out.push(hyp(node, tactic, desc.replace("{title}", &node.title), why, 0.68, sev, 0.1, ""));
    }
}

fn channel_oracle(node: &Nv, sev: &str, crash: bool, include_input: bool) -> Vec<Hyp> {
    let mut desc = format!("对 {} 换观测通道：状态码/正文/Cookie/跳转无差异时，对同一输入的两次提交比对耗时差/长度差/响应头差/其它路由副作用；同一状态码再采样不算换通道，不要关闭输入面", node.title);
    if crash { desc.push_str("；不要把恒定错误页写成已验证利用"); }
    let mut out = vec![hyp(node, "channel_oracle", desc, "一类 oracle 失败不等于后端没处理参数", 0.78, sev, 0.14, "")];
    if include_input { out.push(hyp(node, "input_abuse", format!("验证 {} 的可控输入是否仍被后端处理，不要关闭输入面", node.title), "恒定错误页只否证了这一类观测", 0.7, sev, 0.08, "")); }
    out
}

fn impact_hyp(node: &Nv, cat: &str, sev: &str, obj: &str) -> Option<Hyp> {
    if obj == "flag" { return None; }
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
    Some(hyp(node, "impact_escalate", format!("提升已验证洞「{}」的危害：{ladder}。影响实质性变大就独立 report_finding，不要只改标题重报同一事实。厂商清单/攻击面穷尽时优先走这一步。{extra}", node.title), "已证明的洞停在存在性不够；危害上调常打出新的独立高危", 0.77, if sev.is_empty() { "high" } else { sev }, 0.14, cat))
}

fn action_forms(text: &str) -> Vec<(String, Vec<String>)> {
    re_action().captures_iter(text).map(|c| {
        let methods = c.get(2).map(|m| m.as_str().split('!').filter(|p| !p.is_empty()).map(|p| p.to_string()).collect()).unwrap_or_default();
        (c.get(1).unwrap().as_str().to_string(), methods)
    }).collect()
}

fn request_form_gaps(graph: Option<&Value>) -> Vec<(String, Vec<String>, Vec<String>)> {
    let nodes = graph.map(graph_nodes).unwrap_or_default();
    let mut fake = BTreeSet::new();
    let mut blobs = Vec::new();
    for n in &nodes {
        let blob = format!("{} {} {}", n.get("key").and_then(Value::as_str).unwrap_or(""), n.get("title").and_then(Value::as_str).unwrap_or(""), detail_text(n.get("detail").unwrap_or(&Value::Null)));
        for c in re_fake_action().captures_iter(&blob) { if let Some(s) = c.get(1) { fake.insert(s.as_str().to_string()); } }
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
    let mut out = Vec::new();
    for stem in &order {
        let own = extras.get(stem).cloned().unwrap_or_default();
        let missing: Vec<String> = all.difference(&own).cloned().collect();
        if missing.is_empty() { continue; }
        if !seen.get(stem).map(|s| s.iter().any(|m| m.is_empty())).unwrap_or(false) { continue; }
        let siblings: Vec<String> = order.iter().filter(|n| *n != stem && extras.contains_key(*n)).cloned().collect();
        if siblings.is_empty() { continue; }
        out.push((stem.clone(), siblings, missing));
    }
    out
}

pub fn stale_tactics_for_node(node: &Value, brief: &str) -> Vec<String> {
    let v = node_of(node);
    let mut stale = vec!["split_tier".to_string()];
    if v.ntype == "vuln" && nv_ssrf(&v) && !nv_rce(&v) { stale.push("weaponize".into()); }
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

pub fn hypotheses_for_node(node: &Value, allows_flag: bool, objective: Option<&str>, brief: &str, graph: Option<&Value>) -> Vec<Hyp> {
    let obj = match objective {
        Some(s) => normalize_objective(Some(s)).to_string(),
        None => if allows_flag { "flag".into() } else { "redteam".into() },
    };
    let mut node = node_of(node);
    if node.title.is_empty() { node.title = node.key.clone(); }
    if node.severity.is_empty() { node.severity = "info".into(); }
    let sev = node.severity.clone();
    let binary = looks_binary(&node.blob, &node.title, brief);
    let mut out = Vec::new();
    let loot = if allows_flag { "配置/源码/flag" } else { "配置/源码/凭证/敏感数据" };
    if node.ntype == "service" {
        let http = is_http_svc(&node.blob, &node.tags);
        out.push(hyp(&node, "fingerprint", format!("确认 {} 的产品/版本指纹与已知漏洞面", node.title), "服务发现后先定性技术栈，才能选对利用族", if http { 0.48 } else { 0.7 }, &sev, 0.0, ""));
        if binary {
            out.push(hyp(&node, "reverse_binary", format!("下载 {} 下发的可执行文件/固件/字节码，file/strings/objdump/radare2 静态分析，再用已装的 z3/pwntools 符号求解；不要扫目录、不要当网站打", node.title), "题面要求分析可执行文件时，下一事件是本地逆向而不是 Web 枚举", 0.8, &sev, 0.16, ""));
            out.push(hyp(&node, "protocol_model", format!("对 {} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录", node.title), "可执行文件入口常伴随自定义协议，会话建模与静态分析并行", 0.72, &sev, 0.12, ""));
        } else if http {
            out.push(hyp(&node, "auth_surface", format!("枚举 {} 的登录/鉴权/管理入口并测默认口令与弱鉴权；先读表单 action；经代理转发时把方法与请求体送到内层认证处理接口，外壳 POST 或仍回登录页不算口令否证", node.title), "多数 Web 服务的高价值面在认证边界", 0.58, &sev, 0.0, ""));
            out.push(hyp(&node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问", node.title), "访问控制缺陷常比复杂 exploit 更快出成果", 0.68, &sev, 0.08, ""));
            out.push(hyp(&node, "content_enum", format!("对 {} 做目录与脚本文件枚举（先看入口已知路径与源码；禁止超 10 万行词表）", node.title), "未链接脚本常无目录命中；无扩展名扫描不能当内容枚举完成", 0.52, &sev, 0.0, ""));
            if gadget(&node.blob, &node.tags, &node.title) {
                out.push(hyp(&node, "ssrf_as_gateway", format!("把 {} 当跳板：内网/回环走该 gadget，不要从攻击机直连那些地址。{SSRF_NOTE}GET 与 POST 是两种能力；登录等写请求必须确认内层收到方法与 body", node.title), "跳板类服务的下一事件是当传输层，不是直连内网", 0.8, &sev, 0.16, ""));
            }
            let chain = node.tags.iter().any(|t| ["json-rpc", "jsonrpc", "ethereum", "geth"].contains(&t.as_str())) || ["json-rpc", "jsonrpc", "ethereum", "geth", "anvil", "hardhat", "nethermind", "besu", "ganache", "erigon"].iter().any(|x| node.blob.contains(x));
            if chain {
                out.push(hyp(&node, "chain_rpc", format!("对 {} 做 JSON-RPC 指纹与未授权方法探测，不要当网站做目录枚举", node.title), "JSON-RPC 的入口是方法表，不是目录与 SQLi", 0.72, &sev, 0.1, ""));
            } else if obj == "src" {
                out.push(hyp(&node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问（当前无注入/文件等分型）", node.title), "SRC HTTP 活体至少留一格打洞，优先越权", 0.66, &sev, 0.0, ""));
            } else {
                out.push(hyp(&node, "web_inject", format!("围绕 {} 探测注入类漏洞（SQLi/SSTI/命令注入/反序列化）", node.title), "Web 服务常见通往 RCE/读文件的入口族", 0.72, &sev, 0.12, ""));
            }
            if filter_hit(&node) && !skips_filter(&node, nv_ssrf(&node)) {
                out.push(hyp(&node, "filter_bypass", format!("对 {} 的拦截/过滤页换方法与通道探测，不要结案去枚举目录", node.title), "过滤器页说明请求已达应用边界，目录枚举不是下一事件", 0.66, &sev, 0.08, ""));
            }
            push_surfaces(&mut out, &node, &sev);
        } else {
            out.push(hyp(&node, "protocol_model", format!("对 {} 做协议转储与本地建模：记下输入输出，用已装求解库重建变换，再自适应查询；不要当网站扫目录", node.title), "非 HTTP 交互口的下一步是会话建模，不是 Web 枚举", 0.72, &sev, 0.12, ""));
            if node.tags.iter().any(|t| ["ssh", "sshd", "rdp", "smb", "ftp", "redis", "mysql", "mariadb", "postgres", "postgresql", "mongo", "mongodb", "telnet", "vnc"].contains(&t.as_str())) || re_auth_svc().is_match(&format!("{} {}", node.blob, node.tags.iter().cloned().collect::<Vec<_>>().join(" "))) {
                out.push(hyp(&node, "svc_auth_bruteforce", format!("对 {} 做有节制的默认/弱口令与未授权探测（个位数，禁止全量词表）", node.title), "非 HTTP 服务常因默认配置失守", 0.5, &sev, 0.0, ""));
            }
        }
    } else if node.ntype == "danger" {
        out.push(hyp(&node, "input_abuse", format!("验证危险点 {} 的可控输入与参数污染", node.title), "危险点需确认输入面后才能升级为 vuln", 0.66, &sev, 0.05, ""));
        out.push(hyp(&node, "access_control", format!("测试 {} 的鉴权/越权/未授权访问", node.title), "访问控制缺陷常比复杂 exploit 更快出成果", 0.6, &sev, 0.0, ""));
        if gadget(&node.blob, &node.tags, &node.title) {
            out.push(hyp(&node, "ssrf_as_gateway", format!("把危险点 {} 当跳板继续打，一种 4xx 不关闭整族，禁止攻击机直连内网", node.title), "跳板类危险点的下一事件是当传输层", 0.78, &sev, 0.14, ""));
        }
        if re_uniform().is_match(&node.blob) || re_uniform().is_match(&node.title) { out.extend(channel_oracle(&node, &sev, false, false)); }
        if any_in(&node.blob, &node.tags, &["upload", "multipart", "附件", "file-upload", "file_upload"]) {
            out.push(hyp(&node, "upload_bypass", format!("对 {} 做上传/解析链绕过并尝试 webshell/文件写", node.title), "上传面是经典 getshell 路径", 0.64, &sev, 0.08, ""));
        }
        if filter_hit(&node) && !skips_filter(&node, nv_ssrf(&node)) {
            out.push(hyp(&node, "filter_bypass", format!("对 {} 换通道绕过拦截/过滤，不要结案去枚举目录", node.title), "拦截页是否定了这一通道，不是攻击面关闭", 0.7, &sev, 0.1, ""));
        }
        push_surfaces(&mut out, &node, &sev);
        if any_in(&node.blob, &node.tags, &["deserial", "pickle", "unserialize", "ysoserial", "gadget", "marshal"]) {
            out.push(hyp(&node, "restricted_deserialize", format!("对 {} 做受限反序列化：在允许的构造器/类型里搜 gadget，不要把白名单当成攻击面已关闭", node.title), "白名单反序列化的下一事件是 gadget 搜索，不是停手", 0.7, &sev, 0.1, ""));
        }
        if file_delivery(&node.blob, &node.title, &node.key) && !re_authz().is_match(&format!("{} {}", node.title, node.blob)) {
            let loot_r = if allows_flag { "文件读可直接转凭证或 flag" } else { "文件读可直接转凭证或大量数据泄露" };
            out.push(hyp(&node, "file_read_chain", format!("利用 {} 尝试任意文件读并定位{loot}", node.title), loot_r, 0.68, &sev, 0.1, ""));
        }
        let stem = action_forms(&format!("{} {}", node.key, node.title)).into_iter().find(|(_, m)| m.is_empty()).map(|(s, _)| s).unwrap_or_default();
        if !stem.is_empty() {
            for (gstem, sibs, forms) in request_form_gaps(graph) {
                if gstem != stem { continue; }
                let sibs = sibs.into_iter().take(2).collect::<Vec<_>>().join("、");
                let forms = forms.join("、");
                out.push(hyp(&node, "transfer_form", format!("{stem} 已确认存在，调用形式比 {sibs} 少。把 {sibs} 上已经改变响应的形式 {forms} 套到 {stem}。方法名只用本站已经出现过的，不要新造路径。堆栈里的方法名和重写路径返回 404，不能算这个入口已经测完。"), "同站已经改变响应的调用形式可以套到调用更少的入口", 0.7, &sev, 0.1, ""));
                break;
            }
        }
    } else if node.ntype == "vuln" {
        let ssrf = nv_ssrf(&node);
        let rce = nv_rce(&node);
        let sqli = any_in(&node.blob, &node.tags, &["sqli", "sql-injection", "sql注入"]);
        let token = is_token(&node.blob, &node.tags, &node.title);
        let crash = crash_only(&node);
        if crash { out.extend(channel_oracle(&node, &sev, true, true)); }
        else if !(ssrf && !rce) {
            if token {
                out.push(hyp(&node, "weaponize", format!("把 {} 的签名令牌当服务端校验对象继续打：少数算法或弱密钥变体失败不关闭整类；不要只改前端角色字段，也不要把令牌面写成已关闭", node.title), "持有令牌后下一事件是打校验类，不是关闭伪造面或只改 UI 角色", 0.76, &sev, 0.12, ""));
            } else if local_gate(&node.blob, &node.title) {
                out.push(hyp(&node, "reverse_binary", format!("把 {} 当本地开门钥匙：校验通过后按本题已出现的运算取循环末态或真实出口，不要当成 Web RCE 去读文件/提权", node.title), "本地二进制访问码的下一事件是反演/取末态，不是 HTTP 武器化", 0.8, &sev, 0.16, ""));
            } else if sqli {
                out.push(hyp(&node, "weaponize", format!("把 {} 先打成应用控制流/回显（状态码/Cookie/跳转），再 dump 库/密钥；确认注入后不要再校准耗时，也不要在同一面上改打无关的身份伪造", node.title), "登录/鉴权查询上错误页只说明失败分支崩了，查询可能已执行完", 0.76, &sev, 0.12, ""));
            } else {
                out.push(hyp(&node, "weaponize", format!("把已确认漏洞 {} 推进到稳定利用（读文件/执行/提权）", node.title), "vuln 节点的下一事件是能力升级而非重复探测", 0.72, &sev, 0.1, ""));
            }
        }
        if !crash {
            let why = if allows_flag { "可复现证据便于后续 flag/shell 收口" } else { "可复现证据便于后续 shell/数据收口" };
            out.push(hyp(&node, "evidence_poc", format!("为 {} 固化最小 PoC 并串联到目标攻击链", node.title), why, 0.65, &sev, 0.0, ""));
            let cat = if ssrf { "ssrf" } else if sqli { "sqli" } else if rce { "rce" } else { "vuln" };
            if let Some(esc) = impact_hyp(&node, cat, &sev, &obj) { out.push(esc); }
        }
        if rce && !local_gate(&node.blob, &node.title) {
            if obj == "src" {
                out.push(hyp(&node, "src_next_type", format!("「{}」已经是命令执行：report_shell 收工，其它未报漏洞照样 report_finding", node.title), "命令执行后 report_shell 收工", 0.8, "critical", 0.12, ""));
            } else {
                let desc = if allows_flag { format!("基于 {} 的执行能力搜 flag / 提权 / 横向", node.title) } else { format!("基于 {} 落地命令执行并 report_shell，其它未报漏洞继续报", node.title) };
                out.push(hyp(&node, "flag_or_privesc", desc, "已有 RCE 时应优先收口而不是继续盲扫", 0.8, "critical", 0.15, ""));
            }
        }
        if any_in(&node.blob, &node.tags, &["file_read", "lfi", "path", "read", "穿越", "include"]) {
            out.push(hyp(&node, "read_to_creds", format!("用 {} 读取配置/密钥/会话并尝试登录复用", node.title), "文件读→凭证→更高权限是高胜率链路", 0.75, &sev, 0.12, ""));
        }
        if ssrf {
            out.push(hyp(&node, "ssrf_as_gateway", format!("把 {} 当传输层：对回环/容器网的 HTTP 经该 SSRF 转发，禁止从攻击机直连那些 IP。{SSRF_NOTE}登录等写请求必须确认内层收到方法与 body，不要把外壳 POST 当已送达", node.title), "SSRF 入 Scope 不给攻击机路由；直连超时不是入口挂了", 0.8, &sev, 0.16, ""));
            out.push(hyp(&node, "ssrf_local_svc", format!("用 {} 打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从本机直连", node.title), "unix socket / bind 127.0.0.1 的库只能从目标侧发起", 0.74, &sev, 0.12, ""));
            out.push(hyp(&node, "secret_mount", format!("若 {} 已读到配置/token：在被访问的那台服务上做有/无密钥路由差分（查询参数、请求头、Cookie、body；401/403=路存在）。JSON 字段名不等于参数名或头名，短名 token/key/auth 都要试。{SECRET_HINT}", node.title), "泄露密钥是开门钥匙；GET-only SSRF 仍可用查询参数或头携带", 0.83, &sev, 0.18, ""));
        }
    } else if node.ntype == "credential" {
        if local_gate(&node.blob, &node.title) { return out; }
        if looks_secret(&node.blob, &node.tags) && !login_cred(&node.blob, &node.title) {
            out.push(hyp(&node, "secret_mount", format!("把 {} 当开门钥匙：在同一服务上做有/无该密钥的路由差分，盯 401/403 而不是只看 200。字段名不等于查询参数/头名；查询参数、请求头、Cookie、body 都要试。{SECRET_HINT}", node.title), "机器令牌的第一事件是鉴权差分挂载，不是当战利品结束", 0.84, &sev, 0.18, ""));
        } else {
            out.push(hyp(&node, "auth_reuse", format!("用凭证 {} 登录签发它的那一跳/同一应用，不要当其它 hop 的万能钥匙", node.title), "凭证复用的范围是签发该凭证的应用，不是内网任意协议", 0.78, &sev, 0.12, ""));
            let why = if allows_flag { "认证后的功能面常直接通向 flag 或 RCE" } else { "认证后的功能面常直接通向 RCE 或敏感数据/后台" };
            out.push(hyp(&node, "priv_enum", format!("登录后枚举 {} 可达的管理功能/敏感数据/上传与命令入口", node.title), why, 0.7, &sev, 0.08, ""));
        }
        if obj == "redteam" && re_dsn().is_match(&node.blob) {
            out.push(hyp(&node, "data_plane_via_app", format!("把 {} 里的库/缓存 DSN 当成「经应用碰数据面」：经已验证 SSRF/gopher 或跳板隧道碰 db_host，禁止无跳板 本机直连内网库，不要把 RDS IP 建成新子项目。", node.title), "红队数据面经应用/跳板隧道，不是无跳板 本机直连", 0.74, if sev.is_empty() { "high" } else { sev.as_str() }, 0.14, ""));
        }
    } else if (node.ntype == "target" && node.tags.iter().any(|t| ["lateral", "pivot", "scope-expanded"].contains(&t.as_str()))) || (node.ntype == "info" && (node.key.starts_with("info:host:") || node.key.starts_with("info:scope-expanded:"))) {
        let same = node.tags.iter().any(|t| t == "same-machine" || t == "vhost") || node.title.contains("同一容器");
        let host = value_host(&json!({"key": node.key, "tags": node.tags.iter().cloned().collect::<Vec<_>>()}));
        if !host.is_empty() && intra_is_canary(&host) { return out; }
        if !same {
            out.push(hyp(&node, "fingerprint", format!("经已有 SSRF/shell 跳板摸清 {} 的开放端口、HTTP 标题与服务类型，立刻 add_node service/info 挂到该目标下；禁止 本机直连该 IP。", node.title), "新内网目标先定性活体并落图，才能打登录/未授权；直连超时是预期", 0.72, "high", 0.12, ""));
            let live_node = json!({"key": node.key, "type": node.ntype, "title": node.title, "tags": node.tags.iter().cloned().collect::<Vec<_>>()});
            if node_live(&live_node) {
                out.push(hyp(&node, "access_control", format!("对 {} 已暴露的面做未授权可达差分，与过门并行；不要把身份验证写成使用这些面的前置条件。", node.title), "要身份与不要身份是并行假设", 0.74, "high", 0.13, ""));
            }
            if hop_eligible(&live_node, graph) {
                out.push(hyp(&node, "hop_auth", format!("过 {} 自己的身份边界；上一跳泄露只是候选。经跳板 HTTP 时先确认认证接口收到请求体再判口令；外壳 POST、站点根路径、仍回登录页 HTML 不算失败。同一身份面在认证接口已送达后没有新秘密、只重复失败，这一跳的过门假设做完。", node.title), "新 hop 是新身份域；过门只是假设之一", 0.74, "high", 0.13, ""));
            }
        }
    } else if node.ntype == "foothold" {
        if obj == "src" {
            out.push(hyp(&node, "src_next_type", format!("立足点 {} 已经是命令执行：report_shell 收工，其它未报漏洞照样 report_finding", node.title), "命令执行后 report_shell 收工", 0.72, &sev, 0.1, ""));
        } else {
            out.push(hyp(&node, "stabilize", format!("巩固立足点 {}：持久化通道、环境枚举、敏感文件", node.title), "立足后先稳住再扩权", 0.7, &sev, 0.1, ""));
            out.push(hyp(&node, "privesc_lateral", format!("从 {} 做本地提权与授权范围内横向/跳板", node.title), "foothold 的下一事件是提权或横向", 0.68, &sev, 0.1, ""));
            if allows_flag {
                out.push(hyp(&node, "flag_hunt", format!("在 {} 权限下定位并 report_flag", node.title), "flag 赛道下立足点应立即转夺旗；未满分继续，满分由平台收工", 0.74, &sev, 0.12, ""));
            } else {
                out.push(hyp(&node, "flag_hunt", format!("在 {} 权限下确认 getshell（report_shell）并收工", node.title), "红队立足后 report_shell 即收工，不夺旗", 0.74, &sev, 0.12, ""));
            }
        }
    } else if node.ntype == "info" {
        if process_note(&node.blob, &node.title, &node.key) { return out; }
        if channel_neg(&node.blob, &node.title) {
            if gadget(&node.blob, &node.tags, &node.title) {
                out.push(hyp(&node, "ssrf_as_gateway", format!("把 {} 当还活着的跳板：恒定 4xx / 一种观测失败不关闭整族；按错误正文换键，禁止攻击机直连内网面。过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。", node.title), "同体 4xx 或否证笔记否定的是一种契约，不是跳板已死", 0.78, "high", 0.14, ""));
            }
            return out;
        }
        if info_oracle(&node.blob, &node.title) { out.extend(channel_oracle(&node, &sev, false, true)); return out; }
        let joined = format!("{} {}", node.title, node.blob);
        if re_wild().is_match(&joined) || re_linked().is_match(&joined) || re_static_trav().is_match(&joined) {
            out.push(hyp(&node, "content_enum", format!("把 {} 当阴性对照，不要当成入口已经列完。先打开入口 HTML 里的同站内容页，把图片、文件、下载地址建成节点；和首页相同的只当阴性对照。第一个 500 或登录页不能代替这些内容页。页面和 JS 里的接口不是服务端全集。再用中档词表列同应用路径，和首页同状态、同长度的丢掉；301/302/403/500 或长度不同的逐个建成节点。带文件名、路径、上传的入口单独记。静态目录穿不过只否定这次穿越。", node.title), "内容页、前端名单和已知目录否证都不关闭未出现在页面上的入口", 0.74, &sev, 0.12, ""));
            if re_linked().is_match(&joined) || re_static_trav().is_match(&joined) { return out; }
        }
        if negative(&node.blob, &node.title) || non_asset(&node.blob, &node.title) { return out; }
        if file_delivery(&node.blob, &node.title, &node.key) && !looks_binary(&node.blob, &node.title, brief) && !re_authz().is_match(&joined) {
            out.push(hyp(&node, "file_read_chain", format!("对 {} 的文件/下载参数做路径与对象差分，尝试任意文件读并定位{loot}", node.title), "下载/附件/文件路径参数是文件读面，不要停在状态码或回头打登录表单", 0.72, &sev, 0.12, ""));
        }
        if looks_secret(&node.blob, &node.tags) {
            out.push(hyp(&node, "secret_mount", format!("把信息点 {} 里的密钥当开门钥匙：同一服务有/无密钥路由差分，401/403=路存在。{SECRET_HINT}", node.title), "配置泄露的 token 不是终点", 0.8, "high", 0.16, ""));
        } else if leaked_login(&node.blob, &node.title) {
            out.push(hyp(&node, "info_to_cred", format!("把信息点 {} 验证为可用凭证并尝试登录", node.title), "明文口令/密钥应立刻升级为 credential 利用", 0.7, "medium", 0.08, ""));
        }
        if re_info_danger().is_match(&node.blob) || re_info_danger().is_match(&node.title) {
            out.push(hyp(&node, "info_to_danger", format!("把 {} 对应接口升级为危险点并做未授权/注入探测", node.title), "接口信息需落到可验证攻击面", 0.55, &sev, 0.0, ""));
        }
        if obj == "redteam" && re_dsn().is_match(&node.blob) {
            out.push(hyp(&node, "data_plane_via_app", format!("把 {} 里的库/缓存 DSN 当成「经应用碰数据面」：经已验证 SSRF/gopher 或跳板隧道碰 db_host，禁止无跳板 本机直连内网库，不要把 RDS IP 建成新子项目。", node.title), "红队数据面经应用/跳板隧道，不是无跳板 本机直连", 0.74, if sev.is_empty() { "high" } else { sev.as_str() }, 0.14, ""));
        }
    }
    out
}

fn field_of(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

pub fn hypotheses_for_finding(finding: &Value, node: &Value, allows_flag: bool, objective: Option<&str>) -> Vec<Hyp> {
    let obj = match objective {
        Some(s) => normalize_objective(Some(s)).to_string(),
        None => if allows_flag { "flag".into() } else { "redteam".into() },
    };
    let mut view = node_of(node);
    let mut cat = field_of(finding, "category").to_ascii_lowercase();
    if cat.is_empty() { cat = "info".into(); }
    let title = { let t = field_of(finding, "title"); if t.is_empty() { view.key.clone() } else { t } };
    let sev = { let s = field_of(finding, "severity"); if s.is_empty() { view.severity.clone() } else { s } };
    if view.key.is_empty() { view.key = field_of(finding, "node_key"); }
    if view.key.is_empty() { view.key = "finding".into(); }
    view.title = title.clone();
    let fblob = format!("{title} {} {} {cat} {}", field_of(finding, "description"), field_of(finding, "evidence"), view.blob).to_ascii_lowercase();
    let mut out = Vec::new();
    if local_gate(&fblob, &title) {
        out.push(hyp(&view, "reverse_binary", format!("把发现「{title}」当本地开门钥匙：校验通过后取循环末态或真实出口，不要推进到读文件/提权"), "本地访问码不是 Web RCE finding", 0.8, &sev, 0.16, &cat));
        return out;
    }
    if ["file_read", "lfi", "arbitrary_file_read"].contains(&cat.as_str()) {
        let loot = if allows_flag { "配置/源码/flag" } else { "配置/源码/凭证/大量敏感数据" };
        out.push(hyp(&view, "finding_read_loot", format!("利用文件读发现「{title}」提取{loot}"), "文件读 finding 应直接转战利品收集", 0.8, &sev, 0.15, &cat));
    } else if cat == "sqli" || cat == "db_access" {
        out.push(hyp(&view, "finding_sqli_chain", format!("把 SQLi「{title}」先打成应用控制流/回显（状态码/Cookie/跳转/页面差分），再按需 dump 库表/应用密钥/用户。时间/布尔差已证明查询在跑：先换回显/联合/报错等更快证明类，不要再校准 oracle，也不要把同一耗时通道按位问到底。不要只用单一错误页否证。库侧文件读原语常被配置挡住，只有更快类和 dump 都走不通才试。"), "时间差只证明查询在跑；回显/联合/报错往往比按位抽取更快收口。统一错误页不能否证结果集已变", 0.78, &sev, 0.14, &cat));
    } else if ["rce", "command_injection", "deserialization", "ssti", "file_upload", "file_write"].contains(&cat.as_str()) {
        let (desc, why) = if allows_flag { ("落地 shell/webshell 并夺旗或提权", "执行类 finding 优先收口") } else { ("落地命令执行并 report_shell，同时把其它未报漏洞继续报出来", "agent 测试要把已证实危害做到 getshell") };
        out.push(hyp(&view, "finding_rce_close", format!("基于「{title}」{desc}"), why, 0.82, "critical", 0.18, &cat));
    } else if cat == "ssrf" || cat == "ssrf_internal" {
        out.push(hyp(&view, "ssrf_as_gateway", format!("把 SSRF「{title}」当跳板：内网/回环 HTTP 走 gadget，不要从攻击机直连那些 IP。{SSRF_NOTE}登录等写请求必须确认内层收到方法与 body"), "SSRF 扩容只授权打目标，不授予攻击机路由", 0.82, &sev, 0.16, &cat));
        out.push(hyp(&view, "ssrf_local_svc", format!("用「{title}」打目标本机只绑回环的 HTTP 服务；配置里 localhost 不能从本机直连"), "本机只监听服务必须从 SSRF 所在进程发起", 0.76, &sev, 0.12, &cat));
        out.push(hyp(&view, "secret_mount", format!("若 SSRF「{title}」已读到 token/配置：在被访问服务上做有/无密钥路由差分（查询参数、请求头、Cookie、body；401/403=路存在）。{SECRET_HINT}"), "泄露密钥是钥匙；GET-only 通道仍可用查询参数或头", 0.84, &sev, 0.18, &cat));
    } else {
        out.push(hyp(&view, "finding_followup", format!("围绕发现「{title}」设计下一条可验证利用链"), "通用 finding 至少派生一次跟进事件", 0.5, &sev, 0.0, &cat));
    }
    if !verify_non_exploit(&cat) { if let Some(esc) = impact_hyp(&view, &cat, &sev, &obj) { out.push(esc); } }
    out
}

fn hyp_to_intent(h: Hyp) -> IntentIn {
    IntentIn {
        from_keys: h.from_keys, description: h.description, rationale: Some(h.rationale), est_success: h.est_success,
        strategy_key: Some(h.strategy_key), evidence_fingerprint: Some(h.evidence_fingerprint), priority: Some(h.priority),
        status: "open".into(), depends_on: h.depends_on,
    }
}

// ---- CVSS v3.1（定点小数，进位与 NVD Roundup 一致） ----

#[derive(Clone, Copy)]
struct Dec(i128);
const SCALE: i128 = 1_000_000_000_000;

fn dec_parse(raw: &str) -> Dec {
    let neg = raw.trim().starts_with('-');
    let s = raw.trim().trim_start_matches(['-', '+']);
    let (a, b) = s.split_once('.').unwrap_or((s, ""));
    let mut frac = b.to_string();
    while frac.len() < 12 { frac.push('0'); }
    if frac.len() > 12 { frac.truncate(12); }
    let whole: i128 = if a.is_empty() { 0 } else { a.parse().unwrap_or(0) };
    let fr: i128 = frac.parse().unwrap_or(0);
    let v = whole.saturating_mul(SCALE).saturating_add(fr);
    Dec(if neg { -v } else { v })
}
fn dmul(a: Dec, b: Dec) -> Dec { Dec(a.0.saturating_mul(b.0) / SCALE) }
fn dadd(a: Dec, b: Dec) -> Dec { Dec(a.0 + b.0) }
fn dsub(a: Dec, b: Dec) -> Dec { Dec(a.0 - b.0) }
fn dmin(a: Dec, b: Dec) -> Dec { if a.0 < b.0 { a } else { b } }
fn dpow(base: Dec, exp: u32) -> Dec { let mut acc = Dec(SCALE); for _ in 0..exp { acc = dmul(acc, base); } acc }
fn div_half_up(n: i128, d: i128) -> i128 { if n >= 0 { (n + d / 2) / d } else { (n - d / 2) / d } }

pub fn roundup(raw: &str) -> String {
    let v = dec_parse(raw);
    let int_input = div_half_up(v.0, 10_000_000);
    let out = if int_input % 10000 == 0 { Dec(int_input * 10_000_000) } else { Dec((int_input / 10000 + 1) * (SCALE / 10)) };
    let tenths = div_half_up(out.0, SCALE / 10);
    format!("{}.{}", tenths.div_euclid(10), tenths.rem_euclid(10).abs())
}

fn roundup_dec(v: Dec) -> Dec {
    let int_input = div_half_up(v.0, 10_000_000);
    if int_input % 10000 == 0 { Dec(int_input * 10_000_000) } else { Dec((int_input / 10000 + 1) * (SCALE / 10)) }
}

fn dec_one(v: Dec) -> (String, f64) {
    let tenths = div_half_up(v.0, SCALE / 10);
    let text = format!("{}.{}", tenths.div_euclid(10), tenths.rem_euclid(10).abs());
    let score = text.parse::<f64>().unwrap_or(0.0);
    (text, score)
}

pub fn qualitative_score(raw: &str) -> &'static str {
    let v = dec_parse(raw);
    if v.0 <= 0 { "info" }
    else if v.0 <= dec_parse("3.9").0 { "low" }
    else if v.0 <= dec_parse("6.9").0 { "medium" }
    else if v.0 <= dec_parse("8.9").0 { "high" }
    else { "critical" }
}

fn band_zh(rating: &str) -> &'static str {
    match rating { "info" => "无", "low" => "低危", "medium" => "中危", "high" => "高危", "critical" => "严重", _ => "无" }
}

fn code_ok(key: &str, code: &str) -> bool {
    match key {
        "AV" => ["N", "A", "L", "P"].contains(&code),
        "AC" => ["L", "H"].contains(&code),
        "PR" => ["N", "L", "H"].contains(&code),
        "UI" => ["N", "R"].contains(&code),
        "S" => ["U", "C"].contains(&code),
        "C" | "I" | "A" => ["H", "L", "N"].contains(&code),
        _ => false,
    }
}

fn word_code(raw: &str) -> Option<&'static str> {
    let up = raw.trim().to_ascii_uppercase();
    Some(match up.as_str() {
        "NETWORK" | "网络" => "N", "ADJACENT" | "相邻" => "A", "LOCAL" | "本地" => "L", "PHYSICAL" | "物理" => "P",
        "LOW" | "低" => "L", "HIGH" | "高" => "H", "NONE" | "无" => "N", "REQUIRED" | "需要" => "R",
        "UNCHANGED" | "不变" => "U", "CHANGED" | "改变" => "C",
        _ => return match raw.trim() {
            "网络" => Some("N"), "相邻" => Some("A"), "本地" => Some("L"), "物理" => Some("P"),
            "低" => Some("L"), "高" => Some("H"), "无" => Some("N"), "需要" => Some("R"),
            "不变" => Some("U"), "改变" => Some("C"), _ => None,
        },
    })
}

fn code_of(raw: &str, key: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() { return None; }
    let up = s.to_ascii_uppercase();
    if code_ok(key, &up) { return Some(up); }
    let word = word_code(s)?;
    if code_ok(key, word) { Some(word.to_string()) } else { None }
}

pub fn normalize_metrics(raw: &BTreeMap<String, String>) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for key in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"] {
        out.insert(key.to_string(), code_of(raw.get(key).map(|s| s.as_str()).unwrap_or(""), key)?);
    }
    Some(out)
}

#[derive(Clone, Debug)]
pub struct CvssScore { pub vector: String, pub score: f64, pub rating: String, pub band_zh: String }

pub fn base_score(metrics: &BTreeMap<String, String>) -> CvssScore {
    let miss = || CvssScore { vector: String::new(), score: 0.0, rating: "info".into(), band_zh: "无".into() };
    let Some(av) = metrics.get("AV").and_then(|c| match c.as_str() { "N" => Some(dec_parse("0.85")), "A" => Some(dec_parse("0.62")), "L" => Some(dec_parse("0.55")), "P" => Some(dec_parse("0.20")), _ => None }) else { return miss(); };
    let Some(ac) = metrics.get("AC").and_then(|c| match c.as_str() { "L" => Some(dec_parse("0.77")), "H" => Some(dec_parse("0.44")), _ => None }) else { return miss(); };
    let Some(ui) = metrics.get("UI").and_then(|c| match c.as_str() { "N" => Some(dec_parse("0.85")), "R" => Some(dec_parse("0.62")), _ => None }) else { return miss(); };
    let scope_changed = metrics.get("S").map(|s| s == "C").unwrap_or(false);
    let Some(pr) = metrics.get("PR").and_then(|c| match c.as_str() {
        "N" => Some(dec_parse("0.85")),
        "L" if scope_changed => Some(dec_parse("0.68")),
        "L" => Some(dec_parse("0.62")),
        "H" if scope_changed => Some(dec_parse("0.50")),
        "H" => Some(dec_parse("0.27")),
        _ => None,
    }) else { return miss(); };
    let cia = |c: &str| match c { "H" => Some(dec_parse("0.56")), "L" => Some(dec_parse("0.22")), "N" => Some(Dec(0)), _ => None };
    let (Some(c), Some(i), Some(a)) = (metrics.get("C").and_then(|s| cia(s)), metrics.get("I").and_then(|s| cia(s)), metrics.get("A").and_then(|s| cia(s))) else { return miss(); };
    let one = Dec(SCALE);
    let iss = dsub(one, dmul(dmul(dsub(one, c), dsub(one, i)), dsub(one, a)));
    let impact = if scope_changed {
        dsub(dmul(dec_parse("7.52"), dsub(iss, dec_parse("0.029"))), dmul(dec_parse("3.25"), dpow(dsub(iss, dec_parse("0.02")), 15)))
    } else { dmul(dec_parse("6.42"), iss) };
    let exploit = dmul(dmul(dmul(dmul(dec_parse("8.22"), av), ac), pr), ui);
    let score = if impact.0 <= 0 { Dec(0) } else if scope_changed { roundup_dec(dmin(dmul(dec_parse("1.08"), dadd(impact, exploit)), dec_parse("10"))) } else { roundup_dec(dmin(dadd(impact, exploit), dec_parse("10"))) };
    let (text, score_f) = dec_one(score);
    let rating = qualitative_score(&text);
    let vector = format!("CVSS:3.1/{}", ["AV", "AC", "PR", "UI", "S", "C", "I", "A"].iter().map(|k| format!("{k}:{}", metrics.get(*k).map(|s| s.as_str()).unwrap_or(""))).collect::<Vec<_>>().join("/"));
    CvssScore { vector, score: score_f, rating: rating.into(), band_zh: band_zh(rating).into() }
}

pub fn parse_vector(text: &str) -> Option<BTreeMap<String, String>> {
    let mut raw = BTreeMap::new();
    for part in text.trim().split('/') {
        if part.is_empty() || part.to_ascii_uppercase().starts_with("CVSS:") { continue; }
        if let Some((k, v)) = part.split_once(':') { raw.insert(k.trim().to_ascii_uppercase(), v.trim().to_string()); }
    }
    if !["AV", "AC", "PR", "UI", "S", "C", "I", "A"].iter().all(|k| raw.get(*k).map(|s| !s.is_empty()).unwrap_or(false)) { return None; }
    normalize_metrics(&raw)
}

pub fn nvd_reject_reason(metrics: &BTreeMap<String, String>) -> Option<String> {
    if metrics.get("C").map(|s| s.as_str()) == Some("N") && metrics.get("I").map(|s| s.as_str()) == Some("N") && metrics.get("A").map(|s| s.as_str()) == Some("N") {
        Some("NVD 不对三项影响都是 None 的向量打分。这条如果确实没有机密性、完整性或可用性影响，不要当作漏洞评级。".into())
    } else { None }
}

pub fn metrics_from_args(args: &Map<String, Value>) -> (Option<BTreeMap<String, String>>, bool) {
    let get = |k: &str| match args.get(k) { Some(Value::String(s)) => s.clone(), Some(Value::Null) | None => String::new(), Some(o) => o.to_string() };
    let fields = ["cvss_av", "cvss_ac", "cvss_pr", "cvss_ui", "cvss_s", "cvss_c", "cvss_i", "cvss_a"];
    let keys = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
    let vals: Vec<String> = fields.iter().map(|k| get(k)).collect();
    let touched = vals.iter().any(|v| !v.trim().is_empty()) || !get("cvss_vector").trim().is_empty();
    let rating = !get("redteam_rating").trim().is_empty();
    if !touched && !rating { return (None, false); }
    if vals.iter().all(|v| !v.trim().is_empty()) {
        let mut raw = BTreeMap::new();
        for (k, v) in keys.iter().zip(vals.iter()) { raw.insert((*k).to_string(), v.clone()); }
        return (normalize_metrics(&raw), true);
    }
    if let Some(parsed) = parse_vector(&get("cvss_vector")) { return (Some(parsed), true); }
    (None, true)
}

fn q1(db: &Db, sql: &str, params: &[&dyn ToSql]) -> Result<Option<Map<String, Value>>, String> { db.query_one(sql, params) }
fn qn(db: &Db, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Map<String, Value>>, String> { db.query(sql, params) }

fn project_row(db: &Db, project_id: &str) -> Result<Option<Map<String, Value>>, String> {
    q1(db, "SELECT * FROM projects WHERE id=?1", &[&project_id])
}

fn project_config(db: &Db, project_id: &str) -> Result<Value, String> {
    let row = project_row(db, project_id)?;
    Ok(row.as_ref().map(|r| loads(&r.get("config").cloned().unwrap_or(Value::Null))).unwrap_or(Value::Null))
}

fn project_entry_host(db: &Db, project_id: &str) -> Result<String, String> {
    let row = project_row(db, project_id)?;
    Ok(row.as_ref().map(|r| row_str(r, "target")).unwrap_or_default().split(':').next().unwrap_or("").trim().to_ascii_lowercase().trim_end_matches('.').to_string())
}

fn project_objective_meta(db: &Db, project_id: &str) -> Result<(bool, String), String> {
    if let Some(hit) = lock().obj_meta.get(project_id).cloned() { return Ok(hit); }
    let cfg = project_config(db, project_id).unwrap_or(Value::Null);
    let raw = cfg.get("objective").and_then(Value::as_str).unwrap_or("");
    let obj = normalize_objective(Some(raw)).to_string();
    let allows = obj == "flag";
    lock().obj_meta.insert(project_id.to_string(), (allows, obj.clone()));
    Ok((allows, obj))
}

fn project_brief(db: &Db, project_id: &str) -> Result<String, String> {
    if let Some(hit) = lock().brief.get(project_id).cloned() { return Ok(hit); }
    let cfg = project_config(db, project_id).unwrap_or(Value::Null);
    let text = ["description", "hint", "tip"].iter().filter_map(|k| cfg.get(*k).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())).collect::<Vec<_>>().join("\n");
    lock().brief.insert(project_id.to_string(), text.clone());
    Ok(text)
}

fn split_hostport(raw: &str) -> (String, Option<i64>) {
    let raw = raw.trim();
    if let Some((h, p)) = raw.rsplit_once(':') {
        if let Ok(n) = p.parse::<i64>() { if (1..=65535).contains(&n) && !h.is_empty() && h.chars().filter(|c| *c == ':').count() == 0 { return (norm_host(h), Some(n)); } }
    }
    (norm_host(raw), None)
}

fn project_entry_hosts_from(row: &Map<String, Value>) -> BTreeSet<String> {
    let mut hosts = BTreeSet::new();
    let cfg = loads(&row.get("config").cloned().unwrap_or(Value::Null));
    if let Some(addrs) = cfg.get("benchmark").and_then(|b| b.get("container_addr")).and_then(Value::as_array) {
        for a in addrs { let (h, _) = split_hostport(a.as_str().unwrap_or("")); if !h.is_empty() { hosts.insert(h); } }
    }
    let (th, _) = split_hostport(&row_str(row, "target"));
    if !th.is_empty() { hosts.insert(th); }
    hosts
}

fn peer_enabled(db: &Db, row: &Map<String, Value>) -> Result<bool, String> {
    let own = loads(&row.get("config").cloned().unwrap_or(Value::Null));
    let mut cfgs = vec![own];
    let pid = row_str(row, "parent_id");
    if !pid.is_empty() {
        if let Some(parent) = project_row(db, &pid)? { cfgs.push(loads(&parent.get("config").cloned().unwrap_or(Value::Null))); }
    }
    for c in cfgs {
        if !c.is_object() { continue; }
        let obj = c.get("objective").or_else(|| c.get("track")).and_then(Value::as_str);
        if objective_allows_flag(obj) { return Ok(true); }
        if c.get("benchmark").and_then(|b| b.get("unique_code")).map(|v| !v.is_null() && v.as_str() != Some("")).unwrap_or(false) { return Ok(true); }
    }
    Ok(false)
}

fn peer_challenge_entry_hosts(db: &Db, project_id: &str) -> Result<BTreeSet<String>, String> {
    let Some(row) = project_row(db, project_id)? else { return Ok(BTreeSet::new()); };
    let parent = row_str(&row, "parent_id");
    if parent.is_empty() || !peer_enabled(db, &row)? { return Ok(BTreeSet::new()); }
    let own = project_entry_hosts_from(&row);
    let sibs = qn(db, "SELECT id, target, config, status FROM projects WHERE parent_id=?1", &[&parent])?;
    let mut out = BTreeSet::new();
    for s in &sibs {
        if row_str(s, "id") == project_id { continue; }
        let st = row_str(s, "status").trim().to_ascii_lowercase();
        if st == "completed" || st == "failed" { continue; }
        let t = norm_host(row_str(s, "target").split(':').next().unwrap_or(""));
        if is_dotted_v4(&t) { out.insert(t); }
        let cfg = loads(&s.get("config").cloned().unwrap_or(Value::Null));
        if let Some(addrs) = cfg.get("benchmark").and_then(|b| b.get("container_addr")).and_then(Value::as_array) {
            for a in addrs {
                let h = norm_host(a.as_str().unwrap_or("").split(':').next().unwrap_or(""));
                if is_dotted_v4(&h) { out.insert(h); }
            }
        }
    }
    out.retain(|h| !own.contains(h));
    Ok(out)
}

fn peer_challenge_entry_addrs(db: &Db, project_id: &str) -> Result<Vec<String>, String> {
    let Some(row) = project_row(db, project_id)? else { return Ok(Vec::new()); };
    let parent = row_str(&row, "parent_id");
    if parent.is_empty() || !peer_enabled(db, &row)? { return Ok(Vec::new()); }
    let own_hosts = project_entry_hosts_from(&row);
    let sibs = qn(db, "SELECT id, target, ports, config, status FROM projects WHERE parent_id=?1", &[&parent])?;
    let mut out = BTreeSet::new();
    for s in &sibs {
        if row_str(s, "id") == project_id { continue; }
        let st = row_str(s, "status").trim().to_ascii_lowercase();
        if st == "completed" || st == "failed" { continue; }
        let host = norm_host(row_str(s, "target").split(':').next().unwrap_or(""));
        let ports = loads(&s.get("ports").cloned().unwrap_or(Value::Null));
        let mut port_nums = Vec::new();
        if let Some(arr) = ports.as_array() {
            for p in arr { if let Some(n) = p.as_i64().or_else(|| p.as_str().and_then(|s| s.parse().ok())) { if (1..=65535).contains(&n) { port_nums.push(n); } } }
        }
        if is_dotted_v4(&host) { for n in &port_nums { out.insert(format!("{host}:{n}")); } }
    }
    out.retain(|a| !own_hosts.contains(a.split(':').next().unwrap_or("")));
    Ok(out.into_iter().collect())
}

fn is_peer_entry_host(db: &Db, project_id: &str, host: &str) -> Result<bool, String> {
    let host = norm_host(host.split(':').next().unwrap_or(""));
    if host.is_empty() { return Ok(false); }
    Ok(peer_challenge_entry_hosts(db, project_id)?.contains(&host))
}

fn all_mentions_forbidden(blob: &str, needle: &str) -> bool {
    if needle.is_empty() || !blob.contains(needle) { return false; }
    let mut idx = 0;
    let mut found = false;
    while let Some(rel) = blob[idx..].find(needle) {
        found = true;
        let i = idx + rel;
        let start = i.saturating_sub(24);
        let end = (i + needle.len() + 16).min(blob.len());
        if !re_forbid_peer().is_match(&blob[start..end]) { return false; }
        idx = i + needle.len().max(1);
        if idx >= blob.len() { break; }
    }
    found
}

fn plan_cites_peer_entry(text: &str, peers: &[String]) -> bool {
    let blob = text.to_ascii_lowercase();
    if blob.is_empty() { return false; }
    for a in peers {
        let s = a.trim().to_ascii_lowercase();
        if s.is_empty() { continue; }
        if blob.contains(&s) && !all_mentions_forbidden(&blob, &s) { return true; }
        let Some((host, port)) = s.rsplit_once(':') else { continue; };
        let _ = host;
        let Ok(pn) = port.parse::<i64>() else { continue; };
        if pn < 1024 { continue; }
        for tok in [format!("svc:{port}"), format!("port:{port}"), format!("{port}-http"), format!("{port}/http"), format!(":{port}/"), format!(":{port} "), format!("{port}-")] {
            if blob.contains(tok.trim()) && !all_mentions_forbidden(&blob, tok.trim()) { return true; }
        }
        let unders = format!("{port}_");
        if blob.contains(&unders) && !all_mentions_forbidden(&blob, &unders) { return true; }
    }
    false
}

fn is_hop_auth_intent(item: &Map<String, Value>) -> bool {
    let sk = row_str(item, "strategy_key");
    let tac = if sk.contains("::") { sk.rsplit("::").next().unwrap_or("").to_string() } else { sk.clone() };
    tac == "hop_auth" || re_hop_intent().is_match(&sk)
}

fn false_hop_disprove(summary: &str, fingerprint: &str) -> bool {
    let blob = format!("{summary} {fingerprint}");
    let delivered = re_delivered().is_match(&blob);
    let wrapper = re_wrapper().is_match(&blob);
    !(delivered && !wrapper)
}

fn serialize_node(row: &Map<String, Value>) -> Value {
    let title = row_str(row, "title");
    let scrubbed = scrub_candidate_rce_label(&title);
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "key": row_str(row, "key"),
        "type": row_str(row, "type"),
        "title": if scrubbed.is_empty() { title } else { scrubbed },
        "detail": loads(&row.get("detail").cloned().unwrap_or(Value::Null)),
        "severity": row_str(row, "severity"),
        "is_rce": row_bool(row, "is_rce"),
        "risk_score": row.get("risk_score").cloned().unwrap_or(Value::from(0)),
        "tags": Value::Array(row_tags(row, "tags").into_iter().map(Value::String).collect()),
        "status": row_str(row, "status"),
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
        "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null),
    })
}

fn serialize_edge(row: &Map<String, Value>) -> Value {
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "from": row_str(row, "src"),
        "to": row_str(row, "dst"),
        "relation": row_str(row, "relation"),
        "weight": row.get("weight").cloned().unwrap_or(Value::from(0.5)),
        "rationale": row.get("rationale").cloned().unwrap_or(Value::Null),
        "on_rce_path": row_bool(row, "on_rce_path"),
    })
}

pub fn serialize_finding(row: &Map<String, Value>) -> Value {
    let title = row_opt(row, "title").unwrap_or_default();
    let scrubbed = scrub_candidate_rce_label(&title);
    let title = if scrubbed.is_empty() { title } else { scrubbed };
    let disp = display_finding_severity(row);
    let verification = {
        let s = row_opt(row, "verification_status").unwrap_or_default();
        if s.is_empty() { Value::from("verified") } else { Value::from(s) }
    };
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "node_key": row.get("node_key").cloned().unwrap_or(Value::Null),
        "severity": disp,
        "category": row_str(row, "category"),
        "title": title,
        "description": opt_clip(row_opt(row, "description"), 800),
        "evidence": opt_clip(row_opt(row, "evidence"), 600),
        "poc_curl": opt_clip(row_opt(row, "poc_curl"), 800),
        "poc_python": opt_clip(row_opt(row, "poc_python"), 800),
        "cvss": row.get("cvss").cloned().unwrap_or(Value::Null),
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
        "critical": disp == "critical",
        "verification_status": verification,
        "verified_at": row.get("verified_at").cloned().unwrap_or(Value::Null),
        "proof_type": row.get("proof_type").cloned().unwrap_or(Value::Null),
        "proof_canary": row.get("proof_canary").cloned().unwrap_or(Value::Null),
        "proof_url": opt_clip(row_opt(row, "proof_url"), 400),
        "proof_detail": opt_clip(row_opt(row, "proof_detail"), 800),
        "secondary_verified": row_bool(row, "secondary_verified"),
        "redteam_rating": row.get("redteam_rating").cloned().unwrap_or(Value::Null),
        "redteam_rating_rationale": opt_clip(row_opt(row, "redteam_rating_rationale"), 800),
        "report_summary": opt_clip(row_opt(row, "report_summary"), 1500),
        "report_impact": opt_clip(row_opt(row, "report_impact"), 1500),
        "report_rating": opt_clip(row_opt(row, "report_rating"), 1500),
        "report_repro": opt_clip(row_opt(row, "report_repro"), 1500),
        "report_fix": opt_clip(row_opt(row, "report_fix"), 1500),
        "disposition": row.get("disposition").cloned().unwrap_or(Value::Null),
        "retest_conclusion": row.get("retest_conclusion").cloned().unwrap_or(Value::Null),
    })
}

fn serialize_intent(row: &Map<String, Value>) -> Value {
    let priority = row.get("priority").cloned().filter(|v| !v.is_null()).unwrap_or_else(|| row.get("est_success").cloned().unwrap_or(Value::from(0.5)));
    let depends = {
        let v = loads(&row.get("depends_on").cloned().unwrap_or(Value::Null));
        if v.is_null() { Value::Array(vec![]) } else { v }
    };
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "from": loads(&row.get("from_keys").cloned().unwrap_or(Value::Null)),
        "description": row_str(row, "description"),
        "rationale": row.get("rationale").cloned().unwrap_or(Value::Null),
        "est_success": row.get("est_success").cloned().unwrap_or(Value::from(0.5)),
        "status": row_str(row, "status"),
        "strategy_key": row.get("strategy_key").cloned().unwrap_or(Value::Null),
        "evidence_fingerprint": row.get("evidence_fingerprint").cloned().unwrap_or(Value::Null),
        "priority": priority,
        "attempt_count": row_i64(row, "attempt_count"),
        "failure_fingerprint": row.get("failure_fingerprint").cloned().unwrap_or(Value::Null),
        "result_summary": row.get("result_summary").cloned().unwrap_or(Value::Null),
        "active_run_id": row.get("active_run_id").cloned().unwrap_or(Value::Null),
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
        "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null),
        "paused": row_i64(row, "paused"),
        "pending_steer": row.get("pending_steer").cloned().unwrap_or(Value::Null),
        "depends_on": depends,
    })
}

fn node_in_from_row(row: &Map<String, Value>, node_type: &str, title: &str, severity: &str, tags: Vec<String>) -> NodeIn {
    let status = { let s = row_str(row, "status"); if s.is_empty() { "open".into() } else { s } };
    NodeIn {
        key: row_str(row, "key"), node_type: node_type.into(), title: title.into(),
        detail: row.get("detail").cloned().filter(|v| !v.is_null()).map(|v| loads(&v)),
        severity: severity.into(), is_rce: row_bool(row, "is_rce"), tags, status,
    }
}

pub fn coerce_intranet_target_node(db: &Db, project_id: &str, mut node: NodeIn) -> Result<NodeIn, String> {
    let host = { let h = host_from_asset_key(&node.key); if h.is_empty() { host_of_node(&node.key, &node.tags) } else { h } };
    if host.is_empty() { return Ok(node); }
    let tags_l: HashSet<String> = node.tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    if tags_l.contains("vhost") || tags_l.contains("same-machine") { return Ok(node); }
    let primary = project_entry_host(db, project_id)?;
    if !primary.is_empty() && host == primary { return Ok(node); }
    if is_peer_entry_host(db, project_id, &host)? { return Ok(node); }
    let declared = node.node_type == "target" || node.key.starts_with("target:");
    let old_info = node.key.starts_with("info:host:") || node.key.starts_with("info:scope-expanded:");
    if !(declared || old_info) { return Ok(node); }
    if !should_promote_intranet_host(&host, &node.tags, &primary) { return Ok(node); }
    for t in [format!("internal"), format!("pivot"), format!("host:{host}")] {
        if !node.tags.iter().any(|x| x == &t) { node.tags.push(t); }
    }
    let mut title = if node.title.is_empty() { format!("内网目标 {host}") } else { node.title.clone() };
    if title.starts_with("内网主机 ") || title.starts_with("内网资产 ") { title = format!("内网目标 {host}"); }
    node.node_type = "target".into();
    node.key = format!("target:{host}");
    node.title = title;
    Ok(node)
}

fn rewire_node_key(db: &Db, project_id: &str, old_key: &str, new_key: &str) -> Result<i64, String> {
    if old_key.is_empty() || new_key.is_empty() || old_key == new_key { return Ok(0); }
    let edges = qn(db, "SELECT id, src, dst, relation FROM edges WHERE project_id=?1 AND (src=?2 OR dst=?3)", &[&project_id, &old_key, &old_key])?;
    let mut moved = 0i64;
    for e in edges {
        let id = row_str(&e, "id");
        let nsrc = if row_str(&e, "src") == old_key { new_key.to_string() } else { row_str(&e, "src") };
        let ndst = if row_str(&e, "dst") == old_key { new_key.to_string() } else { row_str(&e, "dst") };
        if nsrc == ndst {
            db.execute("DELETE FROM edges WHERE id=?1", &[&id])?;
            moved += 1;
            continue;
        }
        let rel = row_str(&e, "relation");
        let dup = q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &nsrc, &ndst, &rel])?;
        if dup.is_some() { db.execute("DELETE FROM edges WHERE id=?1", &[&id])?; }
        else { db.execute("UPDATE edges SET src=?1, dst=?2 WHERE id=?3", &[&nsrc, &ndst, &id])?; }
        moved += 1;
    }
    db.execute("UPDATE findings SET node_key=?1 WHERE project_id=?2 AND node_key=?3", &[&new_key, &project_id, &old_key])?;
    db.execute("DELETE FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &old_key])?;
    Ok(moved)
}

fn autofinding_from_node(db: &Db, project_id: &str, row: &Map<String, Value>, run_id: Option<&str>) -> Result<bool, String> {
    let ntype = row_str(row, "type");
    if ntype == "foothold" || ntype == "goal" || ntype != "vuln" { return Ok(false); }
    let tags = row_tags(row, "tags");
    let detail = row.get("detail").cloned().unwrap_or(Value::Null);
    if is_placeholder_node(&row_str(row, "key"), &row_str(row, "title"), &detail, &tags) { return Ok(false); }
    if is_merged_duplicate_title(&row_str(row, "title")) { return Ok(false); }
    if !(row_bool(row, "is_rce") || sev_rank(&row_str(row, "severity")) >= sev_rank("high")) { return Ok(false); }
    let key = row_str(row, "key");
    if q1(db, "SELECT 1 FROM findings WHERE project_id=?1 AND node_key=?2", &[&project_id, &key])?.is_some() { return Ok(false); }
    let category = derive_category(&ntype, &tags, row_bool(row, "is_rce"));
    let detail_s = detail.as_str().map(|s| s.to_string());
    add_finding(db, project_id, FindingIn {
        node_key: Some(key), severity: if row_bool(row, "is_rce") { "critical".into() } else { row_str(row, "severity") },
        category, title: row_str(row, "title"), description: detail_s.clone(), evidence: detail_s,
        ..FindingIn::blank()
    }, run_id)?;
    Ok(true)
}

fn promote_prefix_stub(db: &Db, project_id: &str, row: &Map<String, Value>, run_id: Option<&str>) -> Result<(), String> {
    let key = row_str(row, "key");
    let old_type = { let t = row_str(row, "type"); if t.is_empty() { "info".into() } else { t } };
    let mut tags = row_tags(row, "tags");
    let detail = row.get("detail").cloned().unwrap_or(Value::Null);
    let stub = is_placeholder_node(&key, &row_str(row, "title"), &detail, &tags);
    let inferred = infer_node_type_from_key(&key).unwrap_or_default();
    let mut new_type = coerce_declared_node_type(&key, &old_type, &tags);
    if stub && inferred == "vuln" { new_type = "danger".into(); }
    let mut title = row_str(row, "title");
    if title == key { title = humanize_node_key(&key); }
    let (_nt, spec_title, spec_sev, extra) = placeholder_node_spec(&key);
    if stub && !tags.iter().any(|t| t.eq_ignore_ascii_case("placeholder")) { tags.extend(extra); }
    if !stub { tags.retain(|t| !t.eq_ignore_ascii_case("placeholder")); }
    let mut sev_out = { let s = row_str(row, "severity"); if s.is_empty() { spec_sev.clone() } else { s } };
    if stub {
        if sev_rank(&sev_out) > sev_rank(&spec_sev) { sev_out = spec_sev; }
    } else if new_type == "vuln" && sev_rank(&sev_out) < sev_rank("high") { sev_out = "high".into(); }
    let old_tags = row_tags(row, "tags");
    let title_out = if title.is_empty() { spec_title } else { title.clone() };
    if new_type == old_type && title_out == row_str(row, "title") && sev_out == row_str(row, "severity") && tags.iter().map(|s| s.as_str()).collect::<Vec<_>>() == old_tags.iter().map(|s| s.as_str()).collect::<Vec<_>>() {
        return Ok(());
    }
    let mut node = node_in_from_row(row, &new_type, &title_out, &sev_out, tags);
    node.key = key;
    upsert_node(db, project_id, node, run_id)?;
    Ok(())
}

pub fn upsert_node(db: &Db, project_id: &str, mut node: NodeIn, run_id: Option<&str>) -> Result<Map<String, Value>, String> {
    let orig_key = node.key.clone();
    node.title = scrub_keep(&node.title);
    if node.node_type.is_empty() { node.node_type = "info".into(); }
    if node.severity.is_empty() { node.severity = "info".into(); }
    if node.status.is_empty() { node.status = "open".into(); }
    node = coerce_intranet_target_node(db, project_id, node)?;
    if node.node_type == "target" && !target_key_allowed(&node.key, &node.tags, &project_entry_host(db, project_id)?, &HashSet::new()) {
        let fallback = if node.tags.iter().any(|t| t.to_ascii_lowercase().contains("candidate")) { "danger" } else { "info" };
        node.node_type = fallback.into();
    }
    let coerced = coerce_declared_node_type(&node.key, &node.node_type, &node.tags);
    if coerced != node.node_type { node.node_type = coerced; }
    let score = compute_risk_score(&node.severity, &node.node_type, node.is_rce, None);
    let existing = q1(db, "SELECT id FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &node.key])?;
    let ts = now();
    let detail = dumps(&node.detail.clone().unwrap_or(Value::Null));
    let tags = dumps_tags(&node.tags);
    let is_rce = i64::from(node.is_rce);
    let created;
    let nid = if let Some(ex) = existing {
        created = false;
        db.execute(
            "UPDATE nodes SET type=?1, title=?2, detail=?3, severity=?4, is_rce=?5, risk_score=?6, tags=?7, status=?8, updated_at=?9 WHERE project_id=?10 AND key=?11",
            &[&node.node_type as &dyn ToSql, &node.title, &detail, &node.severity, &is_rce, &score, &tags, &node.status, &ts, &project_id, &node.key],
        )?;
        row_str(&ex, "id")
    } else {
        created = true;
        let nid = new_id("n_");
        db.execute(
            "INSERT INTO nodes(id, project_id, key, type, title, detail, severity, is_rce, risk_score, tags, status, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            &[&nid as &dyn ToSql, &project_id, &node.key, &node.node_type, &node.title, &detail, &node.severity, &is_rce, &score, &tags, &node.status, &ts, &ts],
        )?;
        nid
    };
    let row = q1(db, "SELECT * FROM nodes WHERE id=?1", &[&nid])?.ok_or_else(|| "node missing".to_string())?;
    emit(db, project_id, "node", serialize_node(&row), run_id);
    if !orig_key.is_empty() && orig_key != node.key {
        if q1(db, "SELECT id FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &orig_key])?.is_some() {
            rewire_node_key(db, project_id, &orig_key, &node.key)?;
        }
    }
    if let Err(e) = autofinding_from_node(db, project_id, &row, run_id) {
        let msg = clip_owned(&format!("漏洞节点未进入复核：{} {e}", node.key), 200);
        emit(db, project_id, "log", json!({"level": "warn", "message": msg}), run_id);
    }
    let tags_l: HashSet<String> = node.tags.iter().map(|t| t.to_ascii_lowercase()).collect();
    let pivot_target = node.node_type == "target" && !tags_l.contains("entry") && ["lateral", "pivot", "internal", "scope-expanded", "via-live"].iter().any(|t| tags_l.contains(*t));
    if node.node_type != "honeypot" && (node.node_type != "target" || pivot_target) {
        derive_intents_for_node(db, project_id, &row, run_id)?;
    }
    if created && node.node_type != "target" && !host_of_node(&node.key, &node.tags).is_empty() {
        ensure_lateral_pivots(db, project_id, run_id)?;
    }
    if created && node.node_type != "target" {
        ensure_target_attachments(db, project_id, run_id)?;
    }
    invalidate_graph_cache(Some(project_id));
    Ok(row)
}

pub fn promote_orphan_vuln_nodes(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let rows = qn(db, "SELECT * FROM nodes WHERE project_id=?1 AND type='vuln'", &[&project_id])?;
    let mut made = 0i64;
    for row in rows {
        if autofinding_from_node(db, project_id, &row, run_id).unwrap_or(false) { made += 1; }
    }
    Ok(made)
}

pub fn ensure_node(db: &Db, project_id: &str, key: &str, run_id: Option<&str>) -> Result<(), String> {
    if let Some(exists) = q1(db, "SELECT * FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &key])? {
        promote_prefix_stub(db, project_id, &exists, run_id)?;
        return Ok(());
    }
    let (ntype, title, sev, tags) = placeholder_node_spec(key);
    upsert_node(db, project_id, NodeIn { key: key.into(), node_type: ntype, title, detail: None, severity: sev, is_rce: false, tags, status: "open".into() }, run_id)?;
    Ok(())
}

pub fn fill_source_node(db: &Db, project_id: &str, key: &str, title: Option<&str>, detail: Option<&str>, severity: Option<&str>, ntype: Option<&str>, run_id: Option<&str>) -> Result<(), String> {
    if project_id.is_empty() || key.is_empty() { return Ok(()); }
    let row = q1(db, "SELECT * FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &key])?;
    let inferred = infer_node_type_from_key(key).unwrap_or_else(|| ntype.unwrap_or("info").to_string());
    let current = row.as_ref().map(|r| row_str(r, "type")).unwrap_or(inferred);
    let want = coerce_declared_node_type(key, ntype.unwrap_or(&current), &[]);
    let mut tags = row.as_ref().map(|r| row_tags(r, "tags")).unwrap_or_default();
    let stub = row.is_none() || is_placeholder_node(key, &row.as_ref().map(|r| row_str(r, "title")).unwrap_or_default(), &row.as_ref().and_then(|r| r.get("detail")).cloned().unwrap_or(Value::Null), &tags);
    tags.retain(|t| !t.eq_ignore_ascii_case("placeholder"));
    let old_title = row.as_ref().map(|r| row_str(r, "title")).unwrap_or_default();
    let new_title = title.unwrap_or("").trim().to_string();
    let new_title = if !new_title.is_empty() { new_title } else if !old_title.is_empty() && old_title != key { old_title } else { humanize_node_key(key) };
    let old_detail = row.as_ref().and_then(|r| r.get("detail")).cloned();
    let incoming = detail.map(str::trim).filter(|s| !s.is_empty()).map(|s| Value::String(s.to_string()));
    let new_detail = if stub || old_detail.as_ref().map(detail_empty).unwrap_or(true) { incoming.or(old_detail) } else { old_detail };
    let old_sev = row.as_ref().map(|r| { let s = row_str(r, "severity"); if s.is_empty() { "info".into() } else { s } }).unwrap_or_else(|| "info".into());
    let mut new_sev = severity.unwrap_or(&old_sev).to_string();
    if want == "vuln" && sev_rank(&new_sev) < sev_rank("high") { new_sev = "high".into(); }
    let (spec_type, spec_title, spec_sev, _) = placeholder_node_spec(key);
    let is_rce = row.as_ref().map(|r| row_bool(r, "is_rce")).unwrap_or(false);
    let node = NodeIn {
        key: key.into(),
        node_type: if row.is_none() { if want.is_empty() { spec_type } else { want.clone() } } else { want },
        title: if new_title.is_empty() { spec_title } else { new_title },
        detail: new_detail.filter(|v| !matches!(v, Value::Null)),
        severity: if new_sev.is_empty() { spec_sev } else { new_sev },
        is_rce, tags, status: "open".into(),
    };
    upsert_node(db, project_id, node, run_id)?;
    Ok(())
}

pub fn demote_false_targets(db: &Db, project_id: &str) -> Result<i64, String> {
    let primary = project_entry_host(db, project_id)?;
    let rows = qn(db, "SELECT key, type, tags, title FROM nodes WHERE project_id=?1 AND type='target'", &[&project_id])?;
    if rows.is_empty() { return Ok(0); }
    let pivots = qn(db, "SELECT dst FROM edges WHERE project_id=?1 AND relation='PIVOTS_TO'", &[&project_id])?;
    let pivot_dst: HashSet<String> = pivots.iter().map(|r| row_str(r, "dst")).collect();
    let mut changed = 0i64;
    for row in rows {
        let key = row_str(&row, "key");
        let tags = row_tags(&row, "tags");
        if target_key_allowed(&key, &tags, &primary, &pivot_dst) { continue; }
        let tags_l: HashSet<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        let new_type = if tags_l.iter().any(|t| t.contains("candidate") || ["sqli", "xss", "lfi", "rce", "upload"].contains(&t.as_str())) { "danger" } else { "info" };
        let ts = now();
        db.execute("UPDATE nodes SET type=?1, updated_at=?2 WHERE project_id=?3 AND key=?4", &[&new_type as &dyn ToSql, &ts, &project_id, &key])?;
        changed += 1;
    }
    if changed > 0 { invalidate_graph_cache(Some(project_id)); }
    Ok(changed)
}

pub fn repair_prefix_type_stubs(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let rows = qn(db, "SELECT * FROM nodes WHERE project_id=?1", &[&project_id])?;
    let mut n = 0i64;
    for row in rows {
        let old = { let t = row_str(&row, "type"); if t.is_empty() { "info".into() } else { t } };
        let tags = row_tags(&row, "tags");
        let detail = row.get("detail").cloned().unwrap_or(Value::Null);
        let stub = is_placeholder_node(&row_str(&row, "key"), &row_str(&row, "title"), &detail, &tags);
        let inferred = infer_node_type_from_key(&row_str(&row, "key")).unwrap_or_default();
        let new = if stub && inferred == "vuln" { "danger".into() } else { coerce_declared_node_type(&row_str(&row, "key"), &old, &tags) };
        let sev = row_str(&row, "severity");
        let mut needs = new != old;
        if stub && inferred == "vuln" && sev_rank(&sev) > sev_rank("medium") { needs = true; }
        if !needs { continue; }
        promote_prefix_stub(db, project_id, &row, run_id)?;
        n += 1;
    }
    Ok(n)
}

impl FindingIn {
    pub fn blank() -> Self {
        Self {
            node_key: None, severity: "medium".into(), category: "info".into(), title: String::new(),
            description: None, evidence: None, poc_curl: None, poc_python: None, cvss: None,
            proof_type: None, proof_canary: None, proof_url: None, proof_detail: None,
            verification_status: None, finding_id: None, secondary_verified: false,
            redteam_rating: None, redteam_rating_rationale: None,
            report_summary: None, report_impact: None, report_rating: None, report_repro: None, report_fix: None,
        }
    }
}

fn prefer_chain_parent(root_key: &str, root_type: &str, root_tags: &[String], _primary: &str, reachable: &HashSet<String>, by_key: &HashMap<String, Map<String, Value>>) -> Option<(String, &'static str)> {
    if !CHAIN_CHILD.contains(&root_type) { return None; }
    let host = host_of_node(root_key, root_tags);
    let mut ranked: Vec<(usize, f64, String)> = Vec::new();
    for k in reachable {
        let Some(n) = by_key.get(k) else { continue };
        let ntype = row_str(n, "type");
        if !CHAIN_PARENT.contains(&ntype.as_str()) { continue; }
        if ntype == root_type && k == root_key { continue; }
        let ph = host_of_node(k, &row_tags(n, "tags"));
        if !host.is_empty() && !ph.is_empty() && ph != host { continue; }
        if !host.is_empty() && ph.is_empty() && ntype != "service" { continue; }
        let pri = CHAIN_PARENT.iter().position(|t| *t == ntype).unwrap_or(9);
        ranked.push((pri, row_f64(n, "created_at"), k.clone()));
    }
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)).then(a.2.cmp(&b.2)));
    ranked.into_iter().next().map(|(_, _, k)| (k, "LEADS_TO"))
}

fn undirected_reach(nodes: &[Map<String, Value>], edges: &[Map<String, Value>], seeds: &[String]) -> (HashMap<String, HashSet<String>>, HashSet<String>) {
    let mut adj: HashMap<String, HashSet<String>> = nodes.iter().map(|n| (row_str(n, "key"), HashSet::new())).collect();
    for e in edges {
        let (s, d) = (row_str(e, "src"), row_str(e, "dst"));
        if adj.contains_key(&s) && adj.contains_key(&d) {
            adj.get_mut(&s).unwrap().insert(d.clone());
            adj.get_mut(&d).unwrap().insert(s);
        }
    }
    let mut reachable = HashSet::new();
    let mut stack = seeds.to_vec();
    for k in &stack { reachable.insert(k.clone()); }
    let mut i = 0;
    while i < stack.len() {
        let cur = stack[i].clone();
        if let Some(nbs) = adj.get(&cur) {
            for nb in nbs {
                if reachable.insert(nb.clone()) { stack.push(nb.clone()); }
            }
        }
        i += 1;
    }
    (adj, reachable)
}

fn heal_target_vuln_shortcuts(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let nodes = qn(db, "SELECT key, type, created_at, tags FROM nodes WHERE project_id=?1", &[&project_id])?;
    let by_key: HashMap<String, Map<String, Value>> = nodes.iter().map(|n| (row_str(n, "key"), n.clone())).collect();
    let targets: Vec<String> = nodes.iter().filter(|n| row_str(n, "type") == "target").map(|n| row_str(n, "key")).collect();
    if targets.is_empty() { return Ok(0); }
    let edges = qn(db, "SELECT id, src, dst, relation FROM edges WHERE project_id=?1", &[&project_id])?;
    let (adj, mut reachable) = undirected_reach(&nodes, &edges, &targets);
    let _ = adj;
    let mut healed = 0i64;
    for e in &edges {
        if row_str(e, "relation") != "CONTAINS" || !targets.iter().any(|t| t == &row_str(e, "src")) { continue; }
        let Some(dst) = by_key.get(&row_str(e, "dst")) else { continue };
        if !CHAIN_CHILD.contains(&row_str(dst, "type").as_str()) { continue; }
        let mut reach2 = reachable.clone();
        reach2.remove(&row_str(dst, "key"));
        let Some((pkey, rel)) = prefer_chain_parent(&row_str(dst, "key"), &row_str(dst, "type"), &row_tags(dst, "tags"), &row_str(e, "src"), &reach2, &by_key) else { continue };
        if pkey == row_str(e, "dst") { continue; }
        let dst_key = row_str(e, "dst");
        if q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &pkey, &dst_key, &rel])?.is_none() {
            let eid = new_id("e_");
            let rationale = format!("系统改挂：漏洞/危险点经 {pkey} 进入攻击链，不再由 target 直连");
            let weight = 0.7f64;
            let ts = now();
            db.execute("INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", &[&eid as &dyn ToSql, &project_id, &pkey, &dst_key, &rel, &weight, &rationale, &ts])?;
            if let Some(row) = q1(db, "SELECT * FROM edges WHERE id=?1", &[&eid])? { emit(db, project_id, "edge", serialize_edge(&row), run_id); }
        }
        let eid_old = row_str(e, "id");
        db.execute("DELETE FROM edges WHERE id=?1", &[&eid_old])?;
        emit(db, project_id, "log", json!({"level": "info", "message": format!("关系图改挂：去掉 {} → {} 直连，改为经 {pkey}", row_str(e, "src"), dst_key)}), run_id);
        healed += 1;
        reachable.insert(dst_key);
    }
    Ok(healed)
}

fn entry_primary_target_key(db: &Db, project_id: &str, targets: &[Map<String, Value>]) -> Result<String, String> {
    let row = project_row(db, project_id)?;
    let host = row.as_ref().map(|r| row_str(r, "target")).unwrap_or_default().split(':').next().unwrap_or("").trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    let keys: Vec<String> = targets.iter().map(|t| row_str(t, "key")).collect();
    if !host.is_empty() {
        let want = format!("target:{host}");
        if keys.iter().any(|k| k == &want) { return Ok(want); }
        for t in targets {
            let blob = format!("{} {}", row_str(t, "key"), row_str(t, "title")).to_ascii_lowercase();
            if blob.contains(&host) { return Ok(row_str(t, "key")); }
        }
    }
    let mut sorted = targets.to_vec();
    sorted.sort_by(|a, b| row_f64(a, "created_at").partial_cmp(&row_f64(b, "created_at")).unwrap_or(Ordering::Equal));
    Ok(sorted.first().map(|t| row_str(t, "key")).unwrap_or_default())
}

fn rehang_auto_edges(db: &Db, project_id: &str, primary: &str, run_id: Option<&str>) -> Result<i64, String> {
    let addrs = peer_challenge_entry_addrs(db, project_id).unwrap_or_default();
    let mut hosts = peer_challenge_entry_hosts(db, project_id).unwrap_or_default();
    for a in &addrs { hosts.insert(norm_host(a.split(':').next().unwrap_or(""))); }
    let primary_host = host_from_target_key(primary);
    hosts.remove(&primary_host);
    if let Some(row) = project_row(db, project_id)? { for h in project_entry_hosts_from(&row) { hosts.remove(&h); } }
    if hosts.is_empty() { return Ok(0); }
    let nodes = qn(db, "SELECT key, type, title, tags, detail FROM nodes WHERE project_id=?1", &[&project_id])?;
    let by_key: HashMap<String, Map<String, Value>> = nodes.iter().map(|n| (row_str(n, "key"), n.clone())).collect();
    let edges = qn(db, "SELECT id, src, dst, relation, rationale FROM edges WHERE project_id=?1 AND relation='CONTAINS'", &[&project_id])?;
    let mut moved = 0i64;
    let addr_list: Vec<String> = addrs;
    for e in edges {
        let src_host = host_from_target_key(&row_str(&e, "src"));
        if src_host.is_empty() || !hosts.contains(&src_host) { continue; }
        let Some(dst) = by_key.get(&row_str(&e, "dst")) else { continue };
        let blob = format!("{} {} {} {}", row_str(dst, "key"), row_str(dst, "title"), row_tags(dst, "tags").join(" "), detail_text(dst.get("detail").unwrap_or(&Value::Null)).chars().take(200).collect::<String>());
        if plan_cites_peer_entry(&blob, &addr_list) || blob.to_ascii_lowercase().contains(&src_host) { continue; }
        let dst_key = row_str(&e, "dst");
        let exists = q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &primary, &dst_key, &"CONTAINS"])?;
        db.execute("DELETE FROM edges WHERE id=?1", &[&row_str(&e, "id")])?;
        if exists.is_none() && primary != dst_key {
            let eid = new_id("e_");
            let weight = 0.55f64;
            let rationale = "系统改挂：游离发现从邻题入口改挂回本题入口";
            let ts = now();
            db.execute("INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", &[&eid as &dyn ToSql, &project_id, &primary, &dst_key, &"CONTAINS", &weight, &rationale, &ts])?;
            if let Some(row) = q1(db, "SELECT * FROM edges WHERE id=?1", &[&eid])? { emit(db, project_id, "edge", serialize_edge(&row), run_id); }
        }
        moved += 1;
    }
    Ok(moved)
}

pub fn ensure_target_attachments(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    if !enter("attach", project_id) { return Ok(0); }
    let result = (|| {
        let nodes = qn(db, "SELECT key, type, created_at, tags FROM nodes WHERE project_id=?1", &[&project_id])?;
        if nodes.len() < 2 { return Ok(0); }
        let targets: Vec<Map<String, Value>> = nodes.iter().filter(|n| row_str(n, "type") == "target").cloned().collect();
        if targets.is_empty() { return Ok(0); }
        let primary = entry_primary_target_key(db, project_id, &targets)?;
        let mut added = rehang_auto_edges(db, project_id, &primary, run_id)?;
        let edges = qn(db, "SELECT src, dst FROM edges WHERE project_id=?1", &[&project_id])?;
        let (mut adj, mut reachable) = undirected_reach(&nodes, &edges, &targets.iter().map(|t| row_str(t, "key")).collect::<Vec<_>>());
        let mut orphan: HashSet<String> = nodes.iter().map(|n| row_str(n, "key")).filter(|k| !reachable.contains(k)).collect();
        let by_key: HashMap<String, Map<String, Value>> = nodes.iter().map(|n| (row_str(n, "key"), n.clone())).collect();
        let mut visited = HashSet::new();
        for seed in orphan.clone() {
            if !visited.insert(seed.clone()) { continue; }
            let mut comp = Vec::new();
            let mut queue = vec![seed];
            while let Some(cur) = queue.pop() {
                comp.push(cur.clone());
                if let Some(nbs) = adj.get(&cur) {
                    for nb in nbs.clone() {
                        if orphan.contains(&nb) && visited.insert(nb.clone()) { queue.push(nb); }
                    }
                }
            }
            let root = comp.iter().min_by(|a, b| {
                let pa = ATTACH_ROOT.iter().find(|(t, _)| *t == row_str(&by_key[*a], "type")).map(|(_, p)| *p).unwrap_or(9);
                let pb = ATTACH_ROOT.iter().find(|(t, _)| *t == row_str(&by_key[*b], "type")).map(|(_, p)| *p).unwrap_or(9);
                pa.cmp(&pb).then(row_f64(&by_key[*a], "created_at").partial_cmp(&row_f64(&by_key[*b], "created_at")).unwrap_or(Ordering::Equal)).then(a.cmp(b))
            }).cloned().unwrap_or_default();
            if root == primary { continue; }
            let root_node = &by_key[&root];
            if row_str(root_node, "type") == "target" { continue; }
            let (src, relation, weight, rationale) = if let Some((pkey, rel)) = prefer_chain_parent(&root, &row_str(root_node, "type"), &row_tags(root_node, "tags"), &primary, &reachable, &by_key) {
                let rationale = format!("系统自动补边：经 {pkey} 挂入攻击链");
                (pkey, rel.to_string(), 0.7, rationale)
            } else {
                let host = host_of_node(&root, &row_tags(root_node, "tags"));
                let same = if host.is_empty() { String::new() } else { format!("target:{host}") };
                if !same.is_empty() && by_key.contains_key(&same) && same != primary {
                    (same.clone(), "CONTAINS".into(), 0.8, format!("系统自动补边：挂到内网目标 {host}"))
                } else {
                    (primary.clone(), "CONTAINS".into(), 0.55, "系统自动补边：将游离发现挂回目标起点".into())
                }
            };
            if q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &src, &root, &relation])?.is_some() {
                reachable.insert(root.clone());
                orphan.remove(&root);
                continue;
            }
            let eid = new_id("e_");
            let ts = now();
            db.execute("INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", &[&eid as &dyn ToSql, &project_id, &src, &root, &relation, &weight, &rationale, &ts])?;
            if let Some(row) = q1(db, "SELECT * FROM edges WHERE id=?1", &[&eid])? { emit(db, project_id, "edge", serialize_edge(&row), run_id); }
            adj.entry(src.clone()).or_default().insert(root.clone());
            adj.entry(root.clone()).or_default().insert(src);
            reachable.insert(root.clone());
            orphan.remove(&root);
            added += 1;
        }
        added += heal_target_vuln_shortcuts(db, project_id, run_id)?;
        if added > 0 { recompute_rce_path(db, project_id, run_id, true)?; }
        added += ensure_lateral_pivots(db, project_id, run_id)?;
        Ok(added)
    })();
    leave("attach", project_id);
    result
}

fn merge_node_tags(db: &Db, project_id: &str, key: &str, extra: &[String]) -> Result<(), String> {
    if key.is_empty() || extra.is_empty() { return Ok(()); }
    let Some(row) = q1(db, "SELECT tags FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &key])? else { return Ok(()); };
    let mut tags = row_tags(&row, "tags");
    let mut changed = false;
    for t in extra {
        let s = t.trim();
        if !s.is_empty() && !tags.iter().any(|x| x == s) { tags.push(s.to_string()); changed = true; }
    }
    if tags.iter().any(|t| t == TAG_LIVE) && tags.iter().any(|t| t == TAG_CLUE) {
        tags.retain(|t| t != TAG_CLUE);
        changed = true;
    }
    if changed {
        let blob = dumps_tags(&tags);
        let ts = now();
        db.execute("UPDATE nodes SET tags=?1, updated_at=?2 WHERE project_id=?3 AND key=?4", &[&blob as &dyn ToSql, &ts, &project_id, &key])?;
    }
    Ok(())
}

fn drop_entry_contains(db: &Db, project_id: &str, primary: &str, dst_key: &str) -> Result<(), String> {
    if primary.is_empty() || dst_key.is_empty() { return Ok(()); }
    let src = format!("target:{primary}");
    db.execute("DELETE FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation='CONTAINS'", &[&project_id, &src, &dst_key])?;
    Ok(())
}

pub fn ensure_host_target(db: &Db, project_id: &str, host: &str, title: &str, run_id: Option<&str>, live: Option<bool>, extra_tags: &[String]) -> Result<String, String> {
    let host = host.trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    if host.is_empty() { return Ok(String::new()); }
    let primary = project_entry_host(db, project_id)?;
    if !primary.is_empty() && host == primary {
        let tkey = format!("target:{host}");
        if q1(db, "SELECT id FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &tkey])?.is_none() {
            upsert_node(db, project_id, NodeIn { key: tkey.clone(), node_type: "target".into(), title: if title.is_empty() { format!("目标 {host}") } else { title.into() }, detail: Some(Value::String(format!("入口 {host}"))), severity: "info".into(), is_rce: false, tags: vec!["entry".into(), format!("host:{host}")], status: "open".into() }, run_id)?;
        }
        return Ok(tkey);
    }
    if is_peer_entry_host(db, project_id, &host)? { return Ok(String::new()); }
    let mut want = extra_tags.to_vec();
    let clue_only = live == Some(false);
    if live == Some(true) { want.extend([TAG_LIVE.into(), "scope-expanded".into(), "pivot".into(), "internal".into(), format!("host:{host}")]); }
    else if clue_only { want.extend([TAG_CLUE.into(), "internal".into(), format!("host:{host}")]); }
    else { want.extend(["internal".into(), format!("host:{host}")]); }
    let mut seen = Vec::new();
    for t in want { let s = t.trim().to_string(); if !s.is_empty() && !seen.contains(&s) { seen.push(s); } }
    if live == Some(true) { seen.retain(|t| t != TAG_CLUE); }
    if clue_only || !vuln_pivot_tags(&seen) {
        let ikey = format!("info:host:{host}");
        if q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &ikey])?.is_some() {
            merge_node_tags(db, project_id, &ikey, &seen)?;
        } else {
            upsert_node(db, project_id, NodeIn { key: ikey.clone(), node_type: "info".into(), title: if title.is_empty() { format!("内网线索 {host}") } else { title.into() }, detail: Some(Value::String(format!("本题内网线索 {host}"))), severity: "info".into(), is_rce: false, tags: seen, status: "open".into() }, run_id)?;
        }
        return Ok(ikey);
    }
    let tkey = format!("target:{host}");
    for cand in [tkey.clone(), format!("info:host:{host}"), format!("info:scope-expanded:{host}")] {
        if q1(db, "SELECT key, type FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &cand])?.is_none() { continue; }
        if cand != tkey && q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &tkey])?.is_none() {
            upsert_node(db, project_id, NodeIn { key: tkey.clone(), node_type: "target".into(), title: if title.is_empty() { format!("内网目标 {host}") } else { title.into() }, detail: Some(Value::String(format!("经跳板发现的内网目标 {host}"))), severity: "info".into(), is_rce: false, tags: seen.clone(), status: "open".into() }, run_id)?;
            rewire_node_key(db, project_id, &cand, &tkey)?;
        } else if cand != tkey { rewire_node_key(db, project_id, &cand, &tkey)?; }
        merge_node_tags(db, project_id, &tkey, &seen)?;
        let ts = now();
        db.execute("UPDATE nodes SET type='target', updated_at=?1 WHERE project_id=?2 AND key=?3", &[&ts as &dyn ToSql, &project_id, &tkey])?;
        if !primary.is_empty() { drop_entry_contains(db, project_id, &primary, &tkey)?; }
        return Ok(tkey);
    }
    upsert_node(db, project_id, NodeIn { key: tkey.clone(), node_type: "target".into(), title: if title.is_empty() { format!("内网目标 {host}") } else { title.into() }, detail: Some(Value::String(format!("经跳板发现的内网目标 {host}"))), severity: "info".into(), is_rce: false, tags: seen, status: "open".into() }, run_id)?;
    if !primary.is_empty() { drop_entry_contains(db, project_id, &primary, &tkey)?; }
    Ok(tkey)
}

fn is_entry_target_row(row: &Map<String, Value>) -> bool {
    let tags = row_tags(row, "tags");
    if tags.iter().any(|t| ["lateral", "pivot", "vhost", "same-machine", "internal", "scope-expanded"].contains(&t.as_str())) { return false; }
    tags.iter().any(|t| t == "entry") || tags.is_empty()
}

pub fn entry_adopt_retire_hosts(new_host: &str, extra_hosts: &[String], keep_hosts: &[String], peer_hosts: &[String]) -> (String, Vec<String>) {
    let new_h = norm_host(new_host.split(':').next().unwrap_or(""));
    let peers: BTreeSet<String> = peer_hosts.iter().map(|h| norm_host(h.split(':').next().unwrap_or(""))).filter(|h| !h.is_empty()).collect();
    if !new_h.is_empty() && peers.contains(&new_h) { return ("refuse".into(), Vec::new()); }
    let keep: BTreeSet<String> = keep_hosts.iter().map(|h| norm_host(h.split(':').next().unwrap_or(""))).filter(|h| !h.is_empty()).collect();
    let mut retire = Vec::new();
    for raw in extra_hosts {
        let h = norm_host(raw.split(':').next().unwrap_or(""));
        if h.is_empty() || h == new_h || keep.contains(&h) || peers.contains(&h) { continue; }
        retire.push(h);
    }
    ("ok".into(), retire)
}

pub fn adopt_entry_host(db: &Db, project_id: &str, host: &str, scope_detail: Option<&Value>, run_id: Option<&str>, keep_hosts: &[String]) -> Result<Value, String> {
    let host = norm_host(host.split(':').next().unwrap_or(""));
    if host.is_empty() { return Ok(json!({"entry": "", "retired": [], "deferred": 0})); }
    let peers = peer_challenge_entry_hosts(db, project_id).unwrap_or_default();
    let rows = qn(db, "SELECT key, tags FROM nodes WHERE project_id=?1 AND type='target'", &[&project_id])?;
    let new_key = format!("target:{host}");
    let mut extra_hosts = Vec::new();
    let mut extra_rows = Vec::new();
    for n in &rows {
        if row_str(n, "key") == new_key { continue; }
        if !is_entry_target_row(n) { continue; }
        extra_rows.push(n.clone());
        let other = host_from_target_key(&row_str(n, "key"));
        if !other.is_empty() { extra_hosts.push(other); }
    }
    let peer_vec: Vec<String> = peers.iter().cloned().collect();
    let (decision, retire_hosts) = entry_adopt_retire_hosts(&host, &extra_hosts, keep_hosts, &peer_vec);
    if decision == "refuse" {
        emit(db, project_id, "log", json!({"level": "warn", "message": format!("入口换址拒绝：{host} 是邻题入口，保留本题原入口节点。")}), run_id);
        return Ok(json!({"entry": "", "retired": [], "deferred": 0, "refused": "peer"}));
    }
    let retire_set: HashSet<String> = retire_hosts.into_iter().collect();
    if q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &new_key])?.is_none() {
        let detail = scope_detail.cloned().unwrap_or_else(|| Value::String(format!("入口 {host}")));
        upsert_node(db, project_id, NodeIn { key: new_key.clone(), node_type: "target".into(), title: format!("目标 {host}"), detail: Some(detail), severity: "info".into(), is_rce: false, tags: vec!["entry".into()], status: "open".into() }, run_id)?;
    }
    let mut retired = Vec::new();
    for n in extra_rows {
        let other = host_from_target_key(&row_str(&n, "key"));
        if !other.is_empty() && !retire_set.contains(&other) { continue; }
        if other.is_empty() { continue; }
        rewire_node_key(db, project_id, &row_str(&n, "key"), &new_key)?;
        retired.push(row_str(&n, "key"));
    }
    if !retired.is_empty() {
        emit(db, project_id, "log", json!({"level": "info", "message": format!("入口换址：{} 并入 {new_key}（同一容器，不是新主机）", retired.join(", "))}), run_id);
        recompute_rce_path(db, project_id, run_id, true)?;
    }
    let old_hosts: Vec<String> = retired.iter().filter_map(|k| { let h = host_from_target_key(k); if h.is_empty() { None } else { Some(h) } }).collect();
    let deferred = defer_intents_for_absent_entry_hosts(db, project_id, &host, &old_hosts, run_id)?;
    Ok(json!({"entry": new_key, "retired": retired, "deferred": deferred}))
}

fn live_graph_hosts(db: &Db, project_id: &str) -> Result<BTreeSet<String>, String> {
    let rows = qn(db, "SELECT key, type, tags FROM nodes WHERE project_id=?1 AND (type IN ('target','foothold','goal') OR key LIKE 'info:host:%' OR key LIKE 'info:scope-expanded:%')", &[&project_id])?;
    let mut live = BTreeSet::new();
    for r in rows {
        let h = { let h = host_of_node(&row_str(&r, "key"), &row_tags(&r, "tags")); if h.is_empty() { host_from_asset_key(&row_str(&r, "key")) } else { h } };
        if !h.is_empty() { live.insert(h); }
    }
    Ok(live)
}

pub fn defer_intents_for_absent_entry_hosts(db: &Db, project_id: &str, current_host: &str, extra_hosts: &[String], run_id: Option<&str>) -> Result<i64, String> {
    let current_host = norm_host(current_host.split(':').next().unwrap_or(""));
    if current_host.is_empty() { return Ok(0); }
    let mut extra: BTreeSet<String> = extra_hosts.iter().map(|h| norm_host(h.split(':').next().unwrap_or(""))).filter(|h| !h.is_empty() && h != &current_host).collect();
    let mut live = live_graph_hosts(db, project_id)?;
    live.insert(current_host.clone());
    for r in qn(db, "SELECT key, tags FROM nodes WHERE project_id=?1", &[&project_id])? {
        let h = host_of_node(&row_str(&r, "key"), &row_tags(&r, "tags"));
        if !h.is_empty() && !live.contains(&h) && same_slash24(&h, &current_host) { extra.insert(h); }
    }
    let live_frags: HashSet<String> = live.iter().filter_map(|h| { let f = canon_host_fragment(h); if f.is_empty() { None } else { Some(f) } }).collect();
    let rows = qn(db, "SELECT id, strategy_key, description, rationale, from_keys FROM intents WHERE project_id=?1 AND status IN ('open','active')", &[&project_id])?;
    let mut n = 0i64;
    let reason = format!("入口换址：旧地址不是新主机，当前入口 {current_host}");
    for r in rows {
        let blob = ["strategy_key", "description", "rationale", "from_keys"].iter().map(|k| row_str(&r, k)).collect::<Vec<_>>().join(" ");
        let mut hit = extra.iter().any(|h| mentions_host(&blob, h, true));
        if !hit {
            for ip in private_hosts_in_text(&blob) {
                if ip == current_host || live.contains(&ip) { continue; }
                if extra.contains(&ip) || same_slash24(&ip, &current_host) { hit = true; break; }
            }
        }
        if !hit && absent_canon_fragments(&blob, &live_frags) { hit = true; }
        if !hit { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "deferred", Some(&reason), Some(&reason), run_id)?;
        n += 1;
    }
    if n > 0 { emit(db, project_id, "log", json!({"level": "info", "message": format!("入口换址：已搁置 {n} 条仍指向旧地址的 Intent（当前入口 {current_host}）")}), run_id); }
    Ok(n)
}

fn intranet_hop_hosts(db: &Db, project_id: &str) -> Result<BTreeSet<String>, String> {
    let entry = project_entry_host(db, project_id)?;
    let live = live_graph_hosts(db, project_id)?;
    let mut hops = BTreeSet::new();
    for h in live {
        if h.is_empty() || h == entry || !is_rfc1918(&h) { continue; }
        if is_peer_entry_host(db, project_id, &h)? { continue; }
        hops.insert(h);
    }
    Ok(hops)
}

pub fn reopen_live_hop_auth(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let hops = intranet_hop_hosts(db, project_id)?;
    if hops.is_empty() { return Ok(0); }
    let rows = qn(db, "SELECT id, strategy_key, description, rationale, from_keys FROM intents WHERE project_id=?1 AND status='deferred' AND (IFNULL(strategy_key,'') LIKE '%hop_auth%' OR IFNULL(strategy_key,'') LIKE '%access_control%')", &[&project_id])?;
    let mut n = 0i64;
    let reason = "内网主机仍在图上：恢复过门与未授权对偶";
    for r in rows {
        let blob = ["strategy_key", "description", "rationale", "from_keys"].iter().map(|k| row_str(&r, k)).collect::<Vec<_>>().join(" ");
        if !hops.iter().any(|h| mentions_host(&blob, h, false)) { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "open", Some(reason), None, run_id)?;
        n += 1;
    }
    Ok(n)
}

pub fn reopen_advisor_deferred_tactics(db: &Db, project_id: &str, tactics: &[String], run_id: Option<&str>) -> Result<i64, String> {
    let want: HashSet<String> = tactics.iter().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
    if want.is_empty() { return Ok(0); }
    let rows = qn(db, "SELECT id, strategy_key, result_summary, failure_fingerprint FROM intents WHERE project_id=?1 AND status='deferred'", &[&project_id])?;
    let mut n = 0i64;
    let reason = "已验证资产尚未立足：恢复顾问误搁置的利用下一跳";
    for r in rows {
        let sk = row_str(&r, "strategy_key");
        let tac = if sk.contains("::") { sk.rsplit("::").next().unwrap_or("").to_string() } else { sk };
        if !want.contains(&tac) { continue; }
        let blob = format!("{} {}", row_str(&r, "result_summary"), row_str(&r, "failure_fingerprint"));
        if !ADVISOR_DEFER.iter().any(|m| blob.contains(m)) { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "open", Some(reason), None, run_id)?;
        n += 1;
    }
    Ok(n)
}

pub fn reopen_false_closed_oracle(db: &Db, project_id: &str, needs_oracle: bool, run_id: Option<&str>) -> Result<i64, String> {
    if !needs_oracle { return Ok(0); }
    let rows = qn(db, "SELECT id, strategy_key FROM intents WHERE project_id=?1 AND status='disproved'", &[&project_id])?;
    let mut n = 0i64;
    let reason = "单通道否证不能关闭输入面：复开换观测通道";
    for r in rows {
        let sk = row_str(&r, "strategy_key");
        let tac = if sk.contains("::") { sk.rsplit("::").next().unwrap_or("").to_string() } else { sk };
        if !ORACLE_REOPEN.contains(&tac.as_str()) { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "open", Some(reason), None, run_id)?;
        n += 1;
    }
    Ok(n)
}

pub fn reopen_false_disproved_hop_auth(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let rows = qn(db, "SELECT id, strategy_key, result_summary, failure_fingerprint FROM intents WHERE project_id=?1 AND status='disproved'", &[&project_id])?;
    let mut n = 0i64;
    let reason = "假否证不能关闭过门：复开 hop_auth";
    for r in &rows {
        if !is_hop_auth_intent(r) { continue; }
        if !false_hop_disprove(&row_str(r, "result_summary"), &row_str(r, "failure_fingerprint")) { continue; }
        set_intent_status(db, project_id, &row_str(r, "id"), "open", Some(reason), None, run_id)?;
        n += 1;
    }
    Ok(n)
}

pub fn defer_local_closeout_for_remaining_flags(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let hops = intranet_hop_hosts(db, project_id)?;
    if hops.is_empty() { return Ok(0); }
    let cfg = project_config(db, project_id)?;
    let needed = cfg.get("flag_count").and_then(Value::as_i64).unwrap_or(0);
    if needed <= 1 { return Ok(0); }
    let got_row = q1(db, "SELECT COUNT(*) AS n FROM flags WHERE project_id=?1 AND correct=1", &[&project_id])?;
    let got = got_row.as_ref().map(|r| row_i64(r, "n")).unwrap_or(0);
    if got <= 0 || got >= needed { return Ok(0); }
    let entry = project_entry_host(db, project_id)?;
    let rows = qn(db, "SELECT id, strategy_key, description, rationale, from_keys, status FROM intents WHERE project_id=?1 AND status IN ('open','active')", &[&project_id])?;
    let mut n = 0i64;
    let reason = "本机 flag 已交、剩余在邻机：搁置本机收口，改打邻机身份面（过门与未授权并行）";
    for r in rows {
        let sk = row_str(&r, "strategy_key");
        let tac = if sk.contains("::") { sk.rsplit("::").next().unwrap_or("").to_string() } else { sk };
        if !LOCAL_CLOSEOUT.contains(&tac.as_str()) { continue; }
        let blob = ["strategy_key", "description", "rationale", "from_keys"].iter().map(|k| row_str(&r, k)).collect::<Vec<_>>().join(" ");
        if hops.iter().any(|h| mentions_host(&blob, h, false)) { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "deferred", Some(reason), Some(reason), run_id)?;
        n += 1;
    }
    if n > 0 {
        emit(db, project_id, "log", json!({"level": "info", "message": format!("剩余 flag：已搁置 {n} 条本机收口 Intent，优先邻机 hop_auth（入口 {entry} 已交过的不要再挖）")}), run_id);
    }
    Ok(n)
}

fn hop_switch(hops: &[Value], preferred: &str) -> (String, Vec<String>) {
    let mut active = Vec::new();
    for h in hops {
        let id = h.get("id").and_then(Value::as_str).unwrap_or("");
        let st = h.get("status").and_then(Value::as_str).unwrap_or("");
        if st == "active" && !id.is_empty() { active.push(id.to_string()); }
    }
    if preferred.is_empty() { (String::new(), Vec::new()) }
    else if active.iter().any(|i| i == preferred) { (String::new(), active.into_iter().filter(|i| i != preferred).collect()) }
    else { (preferred.to_string(), active) }
}

fn preferred_hop_id(hops: &[Value], graph: &Value) -> String {
    let live = live_surface_hosts(graph);
    let mut best = (i64::MIN, String::new());
    for hop in hops {
        let id = hop.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        let st = hop.get("status").and_then(Value::as_str).unwrap_or("open");
        let sk = hop.get("strategy_key").and_then(Value::as_str).unwrap_or("");
        let tac = if sk.contains("::") { sk.rsplit("::").next().unwrap_or("") } else { sk };
        if id.is_empty() || tac != "hop_auth" || st == "deferred" || st == "disproved" { continue; }
        let hosts = intent_private_hosts(hop);
        let mut score: i64 = if hosts.is_empty() { -20 } else { 0 };
        for h in &hosts {
            if intra_broadcast(h) { score -= 100; continue; }
            if live.contains(h) { score += 100; }
            if foothold_hosts(graph).contains(h) { score -= 80; }
        }
        let rank = score * 10;
        if rank > best.0 { best = (rank, id); }
    }
    best.1
}

pub fn defer_ineligible_hop_auth(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    let hops = qn(db, "SELECT * FROM intents WHERE project_id=?1 AND strategy_key LIKE '%::hop_auth' AND status IN ('open','active')", &[&project_id])?;
    if hops.is_empty() { return Ok(0); }
    let _graph = get_graph(db, project_id, false)?;
    let mut n = 0i64;
    let reason = "空号/广播/SSRF 探测地址不是身份门：搁置 hop_auth";
    for r in hops {
        let it = serialize_intent(&r);
        let hosts = intent_private_hosts(&it);
        if hosts.is_empty() { continue; }
        if !hosts.iter().all(|h| junk_hop_auth_host(h)) { continue; }
        set_intent_status(db, project_id, &row_str(&r, "id"), "deferred", Some(reason), Some(reason), run_id)?;
        n += 1;
    }
    Ok(n)
}

pub fn nudge_hop_auth_frontier(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<String, String> {
    let _ = defer_ineligible_hop_auth(db, project_id, run_id);
    let hops = qn(db, "SELECT * FROM intents WHERE project_id=?1 AND strategy_key LIKE '%::hop_auth' AND status IN ('open','active')", &[&project_id])?;
    if hops.is_empty() { return Ok(String::new()); }
    let serialized: Vec<Value> = hops.iter().map(serialize_intent).collect();
    let graph = get_graph(db, project_id, false)?;
    let iid = preferred_hop_id(&serialized, &graph);
    if iid.is_empty() { return Ok(String::new()); }
    let (claim, reopen) = hop_switch(&serialized, &iid);
    for old in &reopen { set_intent_status(db, project_id, old, "open", Some("过门认领换到活身份面"), None, run_id)?; }
    if !claim.is_empty() {
        let claimed = claim_intents(db, project_id, &[claim], run_id)?;
        if let Some(first) = claimed.first() {
            let sk = first.get("strategy_key").and_then(Value::as_str).unwrap_or("");
            let sk: String = sk.chars().rev().take(48).collect::<String>().chars().rev().collect();
            let message = if reopen.is_empty() { format!("中途把 hop_auth 推上前沿: {sk}") } else { format!("过门认领换到活身份面: {sk}") };
            emit(db, project_id, "log", json!({"level": "info", "message": message}), run_id);
        }
    } else if !reopen.is_empty() {
        emit(db, project_id, "log", json!({"level": "info", "message": "过门认领换到活身份面"}), run_id);
    }
    Ok(HOP_AUTH_NUDGE.into())
}

fn insert_edge_once(db: &Db, project_id: &str, src: &str, dst: &str, relation: &str, weight: f64, rationale: &str, run_id: Option<&str>) -> Result<bool, String> {
    if src.is_empty() || dst.is_empty() || src == dst { return Ok(false); }
    if q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &src, &dst, &relation])?.is_some() { return Ok(false); }
    for k in [src, dst] {
        if q1(db, "SELECT 1 FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &k])?.is_none() { return Ok(false); }
    }
    let eid = new_id("e_");
    let ts = now();
    db.execute("INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", &[&eid as &dyn ToSql, &project_id, &src, &dst, &relation, &weight, &rationale, &ts])?;
    if let Some(row) = q1(db, "SELECT * FROM edges WHERE id=?1", &[&eid])? { emit(db, project_id, "edge", serialize_edge(&row), run_id); }
    Ok(true)
}

pub fn promote_intranet_hosts(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    if project_id.is_empty() || !enter("fold", project_id) { return Ok(0); }
    let result = (|| {
        let primary = project_entry_host(db, project_id)?;
        let rows = qn(db, "SELECT key, type, tags, title FROM nodes WHERE project_id=?1 AND (key LIKE 'info:host:%' OR key LIKE 'info:scope-expanded:%')", &[&project_id])?;
        let mut promoted = 0i64;
        for r in rows {
            let key = row_str(&r, "key");
            let host = host_from_asset_key(&key);
            let mut tags = row_tags(&r, "tags");
            if host.is_empty() || !should_promote_intranet_host(&host, &tags, &primary) { continue; }
            if is_peer_entry_host(db, project_id, &host)? { continue; }
            let tkey = format!("target:{host}");
            for t in [format!("internal"), "pivot".into(), format!("host:{host}")] { if !tags.iter().any(|x| x == &t) { tags.push(t); } }
            if q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &tkey])?.is_none() {
                upsert_node(db, project_id, NodeIn { key: tkey.clone(), node_type: "target".into(), title: { let t = row_str(&r, "title"); if t.is_empty() { format!("内网目标 {host}") } else { t } }, detail: Some(Value::String(format!("经跳板发现的内网目标 {host}"))), severity: "info".into(), is_rce: false, tags: tags.clone(), status: "open".into() }, run_id)?;
            } else {
                let blob = dumps_tags(&tags);
                let ts = now();
                db.execute("UPDATE nodes SET type='target', tags=?1, updated_at=?2 WHERE project_id=?3 AND key=?4", &[&blob as &dyn ToSql, &ts, &project_id, &tkey])?;
            }
            if key != tkey { rewire_node_key(db, project_id, &key, &tkey)?; }
            if !primary.is_empty() { drop_entry_contains(db, project_id, &primary, &tkey)?; drop_entry_contains(db, project_id, &primary, &key)?; }
            promoted += 1;
        }
        Ok(promoted)
    })();
    leave("fold", project_id);
    result
}

pub fn fold_intranet_targets(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    promote_intranet_hosts(db, project_id, run_id)
}

fn best_control<'a>(ns: &'a [Map<String, Value>]) -> &'a Map<String, Value> {
    ns.iter().min_by(|a, b| {
        let ka = (i64::from(!row_bool(a, "is_rce")), i64::from(row_str(a, "type") != "foothold"), i64::from(!row_str(a, "key").contains("shell")), row_f64(a, "created_at"), row_str(a, "key"));
        let kb = (i64::from(!row_bool(b, "is_rce")), i64::from(row_str(b, "type") != "foothold"), i64::from(!row_str(b, "key").contains("shell")), row_f64(b, "created_at"), row_str(b, "key"));
        ka.0.cmp(&kb.0).then(ka.1.cmp(&kb.1)).then(ka.2.cmp(&kb.2)).then(ka.3.partial_cmp(&kb.3).unwrap_or(Ordering::Equal)).then(ka.4.cmp(&kb.4))
    }).unwrap()
}

pub fn ensure_lateral_pivots(db: &Db, project_id: &str, run_id: Option<&str>) -> Result<i64, String> {
    if !enter("pivot", project_id) { return Ok(0); }
    let result = (|| {
        let mut added = promote_intranet_hosts(db, project_id, run_id)?;
        let rows = qn(db, "SELECT key, type, tags, is_rce, created_at, title FROM nodes WHERE project_id=?1 AND (type='foothold' OR (type='goal' AND key LIKE 'goal:shell%')) ORDER BY created_at", &[&project_id])?;
        let mut contain_host = HashMap::new();
        for e in qn(db, "SELECT src, dst FROM edges WHERE project_id=?1 AND relation='CONTAINS'", &[&project_id])? {
            let parent = host_from_asset_key(&row_str(&e, "src"));
            if !parent.is_empty() && !row_str(&e, "dst").is_empty() { contain_host.entry(row_str(&e, "dst")).or_insert(parent); }
        }
        let mut by_host: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
        let mut control = Vec::new();
        for mut rec in rows {
            let mut tags = row_tags(&rec, "tags");
            let mut host = host_of_node(&row_str(&rec, "key"), &tags);
            if host.is_empty() {
                host = contain_host.get(&row_str(&rec, "key")).cloned().unwrap_or_default();
                if !host.is_empty() {
                    let tag = format!("host:{host}");
                    if !tags.iter().any(|t| t == &tag) {
                        tags.push(tag);
                        let blob = dumps_tags(&tags);
                        rec.insert("tags".into(), Value::String(blob.clone()));
                        db.execute("UPDATE nodes SET tags=?1 WHERE project_id=?2 AND key=?3", &[&blob as &dyn ToSql, &project_id, &row_str(&rec, "key")])?;
                    }
                }
            }
            rec.insert("_host".into(), Value::String(host.clone()));
            control.push(rec.clone());
            if !host.is_empty() { by_host.entry(host).or_default().push(rec); }
        }
        let targets = qn(db, "SELECT key, created_at FROM nodes WHERE project_id=?1 AND type='target' ORDER BY created_at", &[&project_id])?;
        let mut primary_host = project_entry_host(db, project_id)?;
        let mut primary_target = if primary_host.is_empty() { targets.first().map(|t| row_str(t, "key")).unwrap_or_default() } else { format!("target:{primary_host}") };
        if !primary_target.is_empty() && !targets.iter().any(|t| row_str(t, "key") == primary_target) {
            primary_target = targets.first().map(|t| row_str(t, "key")).unwrap_or(primary_target);
            primary_host = { let h = host_from_target_key(&primary_target); if h.is_empty() { primary_host } else { h } };
        }
        if primary_host.is_empty() {
            for t in &targets {
                let h = host_from_target_key(&row_str(t, "key"));
                if !h.is_empty() { primary_host = h; primary_target = row_str(t, "key"); break; }
            }
        }
        if primary_host.is_empty() {
            if let Some((h, _)) = by_host.iter().find(|(_, ns)| ns.iter().any(|n| !row_str(n, "key").contains('@'))) { primary_host = h.clone(); }
        }
        if primary_host.is_empty() && !by_host.is_empty() {
            primary_host = by_host.keys().min_by(|a, b| {
                let ma = by_host[*a].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
                let mb = by_host[*b].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
                ma.partial_cmp(&mb).unwrap_or(Ordering::Equal)
            }).cloned().unwrap_or_default();
        }
        let all_edges = qn(db, "SELECT * FROM edges WHERE project_id=?1 ORDER BY created_at", &[&project_id])?;
        let controls: HashMap<String, Map<String, Value>> = control.iter().map(|n| (row_str(n, "key"), n.clone())).collect();
        let mut control_hosts = HashMap::new();
        for n in &control {
            let host = { let h = row_str(n, "_host"); if h.is_empty() { host_of_node(&row_str(n, "key"), &row_tags(n, "tags")) } else { h } };
            control_hosts.insert(row_str(n, "key"), host);
        }
        let mut asset_hosts: HashMap<String, String> = targets.iter().map(|t| (row_str(t, "key"), host_from_asset_key(&row_str(t, "key")))).collect();
        for n in qn(db, "SELECT key FROM nodes WHERE project_id=?1 AND (key LIKE 'info:host:%' OR key LIKE 'info:scope-expanded:%')", &[&project_id])? {
            let h = host_from_asset_key(&row_str(&n, "key"));
            if !h.is_empty() { asset_hosts.insert(row_str(&n, "key"), h); }
        }
        let verified_hosts: HashSet<String> = control_hosts.iter().filter(|(k, h)| !h.is_empty() && controls.get(*k).map(|n| row_bool(n, "is_rce")).unwrap_or(false)).map(|(_, h)| h.clone()).collect();
        for e in &all_edges {
            if row_str(e, "relation") != "PIVOTS_TO" { continue; }
            let dst_host = asset_hosts.get(&row_str(e, "dst")).cloned().filter(|s| !s.is_empty()).or_else(|| control_hosts.get(&row_str(e, "dst")).cloned()).unwrap_or_else(|| host_from_asset_key(&row_str(e, "dst")));
            let src_key = row_str(e, "src");
            let dst_key = row_str(e, "dst");
            if src_key.starts_with("vuln:") && dst_key.starts_with("target:") && !dst_host.is_empty() && dst_host != primary_host { continue; }
            let dup = q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation='LEADS_TO'", &[&project_id, &src_key, &dst_key])?;
            if dup.is_some() { db.execute("DELETE FROM edges WHERE id=?1", &[&row_str(e, "id")])?; }
            else {
                let rationale = format!("{} [横向主边改为漏洞→新目标]", { let r = row_str(e, "rationale"); if r.is_empty() { "发现链路".into() } else { r } });
                db.execute("UPDATE edges SET relation='LEADS_TO', rationale=?1 WHERE id=?2", &[&rationale, &row_str(e, "id")])?;
            }
            added += 1;
        }
        if by_host.len() < 2 {
            if added > 0 { recompute_rce_path(db, project_id, run_id, true)?; }
            return Ok(added);
        }
        let rce_hosts: Vec<String> = by_host.iter().filter(|(_, ns)| ns.iter().any(|n| row_bool(n, "is_rce"))).map(|(h, _)| h.clone()).collect();
        let (pivot_src, pivot_src_host) = if by_host.get(&primary_host).map(|ns| ns.iter().any(|n| row_bool(n, "is_rce"))).unwrap_or(false) {
            (row_str(best_control(&by_host[&primary_host]), "key"), primary_host.clone())
        } else if !rce_hosts.is_empty() {
            let host = rce_hosts.iter().min_by(|a, b| {
                let pa = i64::from(a.as_str() != primary_host);
                let pb = i64::from(b.as_str() != primary_host);
                let ma = by_host[*a].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
                let mb = by_host[*b].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
                pa.cmp(&pb).then(ma.partial_cmp(&mb).unwrap_or(Ordering::Equal))
            }).cloned().unwrap_or_default();
            (row_str(best_control(&by_host[&host]), "key"), host)
        } else { (String::new(), String::new()) };
        if pivot_src.is_empty() { return Ok(added); }
        let existing = qn(db, "SELECT id, src, dst FROM edges WHERE project_id=?1 AND relation='PIVOTS_TO'", &[&project_id])?;
        let mut pivoted = HashSet::new();
        for e in existing {
            let h = { let h = host_from_asset_key(&row_str(&e, "dst")); if h.is_empty() { control_hosts.get(&row_str(&e, "dst")).cloned().unwrap_or_default() } else { h } };
            if !h.is_empty() { pivoted.insert(h); }
        }
        let mut other: Vec<String> = by_host.keys().filter(|h| h.as_str() != pivot_src_host).cloned().collect();
        other.sort_by(|a, b| {
            let ma = by_host[a].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
            let mb = by_host[b].iter().map(|n| row_f64(n, "created_at")).fold(f64::MAX, f64::min);
            ma.partial_cmp(&mb).unwrap_or(Ordering::Equal)
        });
        for host in other {
            let shell_key = row_str(best_control(&by_host[&host]), "key");
            let asset_key = ensure_host_target(db, project_id, &host, &format!("内网目标 {host}"), run_id, Some(true), &[])?;
            if !pivoted.contains(&host) && verified_hosts.contains(&host) {
                let vuln = find_pivot_vuln(db, project_id, &pivot_src_host, "shell_reachable")?;
                if !vuln.is_empty() && !asset_key.is_empty() && vuln != asset_key && insert_edge_once(db, project_id, &vuln, &asset_key, "PIVOTS_TO", 0.95, &format!("pivot_capability shell_reachable: {vuln} → {host}"), run_id)? {
                    added += 1;
                    pivoted.insert(host.clone());
                }
            }
            if !asset_key.is_empty() && asset_key != primary_target && asset_key != shell_key && insert_edge_once(db, project_id, &asset_key, &shell_key, "CONTAINS", 0.85, &format!("内网目标 {host} 上的立足点"), run_id)? {
                added += 1;
            }
        }
        if added > 0 { recompute_rce_path(db, project_id, run_id, true)?; }
        Ok(added)
    })();
    leave("pivot", project_id);
    result
}

pub fn find_pivot_source(db: &Db, project_id: &str, primary_host: &str) -> Result<String, String> {
    let ph = primary_host.trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    let rows = qn(db, "SELECT key, tags, is_rce, created_at FROM nodes WHERE project_id=?1 AND type IN ('foothold','goal') ORDER BY created_at", &[&project_id])?;
    let mut primary_nodes = Vec::new();
    for r in rows {
        let host = host_of_node(&row_str(&r, "key"), &row_tags(&r, "tags"));
        if !ph.is_empty() && !host.is_empty() && host != ph { continue; }
        if !ph.is_empty() && host == ph { primary_nodes.push(r); }
        else if host.is_empty() && !row_str(&r, "key").contains('@') { primary_nodes.push(r); }
    }
    if !primary_nodes.is_empty() {
        primary_nodes.sort_by(|a, b| {
            (i64::from(!row_bool(a, "is_rce")), i64::from(!row_str(a, "key").contains("shell")), row_f64(a, "created_at"))
                .partial_cmp(&(i64::from(!row_bool(b, "is_rce")), i64::from(!row_str(b, "key").contains("shell")), row_f64(b, "created_at")))
                .unwrap_or(Ordering::Equal)
        });
        return Ok(row_str(&primary_nodes[0], "key"));
    }
    Ok(q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND type='target' ORDER BY created_at LIMIT 1", &[&project_id])?.map(|t| row_str(&t, "key")).unwrap_or_default())
}

fn vuln_matches_host(key: &str, tags: &[String], host: &str) -> bool {
    if host.is_empty() { return true; }
    if host_of_node(key, tags) == host { return true; }
    format!("{key} {}", tags.join(" ")).contains(host)
}

pub fn find_pivot_vuln(db: &Db, project_id: &str, from_host: &str, mechanism: &str) -> Result<String, String> {
    let ph = from_host.trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    let mech = mechanism.trim().to_ascii_lowercase();
    let want_ssrf = mech.starts_with("ssrf");
    let want_rce = mech == "shell_reachable" || mech == "port_forward" || mech == "socks_tunnel" || (!mech.is_empty() && !want_ssrf);
    let nodes = qn(db, "SELECT key, tags, created_at FROM nodes WHERE project_id=?1 AND type='vuln' ORDER BY created_at DESC", &[&project_id])?;
    let findings = qn(db, "SELECT node_key, category, verification_status, created_at FROM findings WHERE project_id=?1 ORDER BY created_at DESC", &[&project_id])?;
    let mut finding_cat = HashMap::new();
    for f in findings {
        let nk = row_str(&f, "node_key");
        if nk.is_empty() { continue; }
        let vs = row_str(&f, "verification_status").to_ascii_lowercase();
        let vs = if vs.is_empty() { "verified".into() } else { vs };
        if ["rejected", "disproved", "false"].contains(&vs.as_str()) { continue; }
        finding_cat.insert(nk, row_str(&f, "category").to_ascii_lowercase());
    }
    let mut ranked: Vec<(i64, String, i64)> = Vec::new();
    for r in &nodes {
        let key = row_str(r, "key");
        let tags = row_tags(r, "tags");
        let tagset: HashSet<String> = tags.iter().map(|t| t.to_ascii_lowercase()).collect();
        let blob = format!("{key} {}", tagset.iter().cloned().collect::<Vec<_>>().join(" "));
        let cat = finding_cat.get(&key).cloned().unwrap_or_default();
        let is_ssrf = SSRF_VULN.contains(&cat.as_str()) || blob.contains("ssrf");
        let is_rce = RCE_VULN.contains(&cat.as_str()) || ["rce", "command_injection", "getshell"].iter().any(|x| blob.contains(x));
        if want_ssrf && !is_ssrf { continue; }
        if want_rce && !want_ssrf && !is_rce && !vuln_matches_host(&key, &tags, &ph) { continue; }
        let mut host_score = if vuln_matches_host(&key, &tags, &ph) { 0 } else { 1 };
        if !ph.is_empty() && host_score == 1 && want_ssrf { host_score = 1; }
        let kind_score = if (want_ssrf && is_ssrf) || (want_rce && is_rce) { 0 } else { 2 };
        ranked.push((host_score + kind_score, key, row_f64(r, "created_at") as i64));
    }
    if ranked.is_empty() && want_ssrf {
        for r in &nodes {
            let tags = row_tags(r, "tags");
            let blob = format!("{} {}", row_str(r, "key"), tags.iter().map(|t| t.to_ascii_lowercase()).collect::<Vec<_>>().join(" "));
            if blob.contains("ssrf") || SSRF_VULN.contains(&finding_cat.get(&row_str(r, "key")).cloned().unwrap_or_default().as_str()) {
                ranked.push((3, row_str(r, "key"), row_f64(r, "created_at") as i64));
            }
        }
    }
    if ranked.is_empty() && !want_ssrf {
        for r in &nodes {
            if !ph.is_empty() && !vuln_matches_host(&row_str(r, "key"), &row_tags(r, "tags"), &ph) { continue; }
            ranked.push((9, row_str(r, "key"), row_f64(r, "created_at") as i64));
        }
    }
    if ranked.is_empty() { return Ok(String::new()); }
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then(b.2.cmp(&a.2)).then(a.1.cmp(&b.1)));
    Ok(ranked[0].1.clone())
}

pub fn has_verified_internal_vantage(db: &Db, project_id: &str) -> Result<bool, String> {
    if project_id.is_empty() { return Ok(false); }
    Ok(q1(db, "SELECT 1 FROM findings WHERE project_id=?1 AND verification_status='verified' AND (lower(IFNULL(category,'')) IN ('rce','command_injection','deserialization','ssti','ssrf') OR IFNULL(node_key,'') LIKE 'goal:shell%' OR IFNULL(node_key,'') LIKE 'foothold:shell%') LIMIT 1", &[&project_id])?.is_some())
}

pub fn is_verified_lateral_pivot(db: &Db, project_id: &str, src: &str, dst: &str) -> Result<bool, String> {
    let rows = qn(db, "SELECT key, type, tags, is_rce FROM nodes WHERE project_id=?1", &[&project_id])?;
    let by_key: HashMap<String, Map<String, Value>> = rows.iter().map(|r| (row_str(r, "key"), r.clone())).collect();
    let (Some(source), Some(dest)) = (by_key.get(src), by_key.get(dst)) else { return Ok(false); };
    if !row_bool(source, "is_rce") { return Ok(false); }
    let src_host = host_of_node(&row_str(source, "key"), &row_tags(source, "tags"));
    let dst_host = { let h = host_of_node(&row_str(dest, "key"), &row_tags(dest, "tags")); if h.is_empty() { host_from_asset_key(&row_str(dest, "key")) } else { h } };
    if src_host.is_empty() || dst_host.is_empty() || src_host == dst_host { return Ok(false); }
    if !["target", "info", "foothold", "goal"].contains(&row_str(dest, "type").as_str()) { return Ok(false); }
    Ok(rows.iter().any(|r| row_bool(r, "is_rce") && ["foothold", "goal"].contains(&row_str(r, "type").as_str()) && host_of_node(&row_str(r, "key"), &row_tags(r, "tags")) == dst_host))
}

pub fn find_host_source(db: &Db, project_id: &str, host: &str) -> Result<String, String> {
    let host = host.trim().to_ascii_lowercase().trim_end_matches('.').to_string();
    if host.is_empty() { return Ok(String::new()); }
    let rows = qn(db, "SELECT key, type, tags, is_rce, created_at FROM nodes WHERE project_id=?1 AND (type != 'goal' OR key LIKE 'goal:shell%') ORDER BY created_at", &[&project_id])?;
    let mut candidates = Vec::new();
    for r in rows { if host_of_node(&row_str(&r, "key"), &row_tags(&r, "tags")) == host { candidates.push(r); } }
    if !candidates.is_empty() {
        candidates.sort_by(|a, b| {
            let ka = (i64::from(!(row_str(a, "type") == "foothold" && row_bool(a, "is_rce"))), i64::from(row_str(a, "type") != "foothold"), i64::from(!row_str(a, "key").contains("shell")), row_f64(a, "created_at"));
            let kb = (i64::from(!(row_str(b, "type") == "foothold" && row_bool(b, "is_rce"))), i64::from(row_str(b, "type") != "foothold"), i64::from(!row_str(b, "key").contains("shell")), row_f64(b, "created_at"));
            ka.partial_cmp(&kb).unwrap_or(Ordering::Equal)
        });
        return Ok(row_str(&candidates[0], "key"));
    }
    for cand in [format!("target:{host}"), format!("info:host:{host}"), format!("info:scope-expanded:{host}")] {
        if q1(db, "SELECT key FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &cand])?.is_some() { return Ok(cand); }
    }
    Ok(String::new())
}

pub fn add_edge(db: &Db, project_id: &str, edge: &EdgeIn, run_id: Option<&str>) -> Result<Map<String, Value>, String> {
    ensure_node(db, project_id, &edge.src, run_id)?;
    ensure_node(db, project_id, &edge.dst, run_id)?;
    let weight = edge.weight.clamp(0.01, 1.0);
    let rationale = edge.rationale.clone();
    let existing = q1(db, "SELECT id FROM edges WHERE project_id=?1 AND src=?2 AND dst=?3 AND relation=?4", &[&project_id, &edge.src, &edge.dst, &edge.relation])?;
    let eid = if let Some(ex) = existing {
        db.execute("UPDATE edges SET weight=?1, rationale=?2 WHERE id=?3", &[&weight as &dyn ToSql, &rationale, &row_str(&ex, "id")])?;
        row_str(&ex, "id")
    } else {
        let eid = new_id("e_");
        let ts = now();
        db.execute("INSERT INTO edges(id, project_id, src, dst, relation, weight, rationale, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", &[&eid as &dyn ToSql, &project_id, &edge.src, &edge.dst, &edge.relation, &weight, &rationale, &ts])?;
        eid
    };
    let row = q1(db, "SELECT * FROM edges WHERE id=?1", &[&eid])?.ok_or_else(|| "edge missing".to_string())?;
    emit(db, project_id, "edge", serialize_edge(&row), run_id);
    ensure_target_attachments(db, project_id, run_id)?;
    recompute_rce_path(db, project_id, run_id, true)?;
    invalidate_graph_cache(Some(project_id));
    Ok(row)
}

fn unproven_hint(f: &FindingIn) -> bool {
    if !f.poc_curl.as_deref().unwrap_or("").trim().is_empty() || !f.poc_python.as_deref().unwrap_or("").trim().is_empty() || !f.proof_canary.as_deref().unwrap_or("").trim().is_empty() { return false; }
    let blob = format!("{} {} {}", f.title, f.description.as_deref().unwrap_or(""), f.evidence.as_deref().unwrap_or(""));
    re_unproven().is_match(&blob)
}

fn find_duplicate_finding(db: &Db, project_id: &str, finding: &FindingIn) -> Result<Option<Map<String, Value>>, String> {
    let endpoint = vec![finding.title.clone(), finding.category.clone(), finding.node_key.clone().unwrap_or_default(), finding.description.clone().unwrap_or_default(), finding.evidence.clone().unwrap_or_default(), finding.poc_curl.clone().unwrap_or_default(), finding.poc_python.clone().unwrap_or_default()];
    let keys = finding_dedup_keys(&endpoint, &finding.category, Some(&endpoint[2..]));
    if keys.is_empty() { return Ok(None); }
    for row in qn(db, "SELECT * FROM findings WHERE project_id=?1 ORDER BY created_at", &[&project_id])? {
        if finding_dedup_keys_from_row(&row).intersection(&keys).next().is_some() { return Ok(Some(row)); }
    }
    Ok(None)
}

pub fn add_finding(db: &Db, project_id: &str, mut finding: FindingIn, run_id: Option<&str>) -> Result<Value, String> {
    finding.title = scrub_keep(&finding.title);
    let incoming_rating = normalize_redteam_rating(finding.redteam_rating.as_deref());
    let cvss_locked = finding.cvss.is_some() && incoming_rating.is_some();
    let (cat, sev, capped) = coerce_unproven_rce_claim(&finding.category, &finding.severity, finding.redteam_rating.as_deref(), &finding.title, finding.description.as_deref().unwrap_or(""), finding.evidence.as_deref().unwrap_or(""), finding.poc_curl.as_deref().unwrap_or(""), finding.poc_python.as_deref().unwrap_or(""));
    finding.category = cat.clone();
    finding.severity = sev.clone();
    let mut rating = if cvss_locked { incoming_rating } else { capped };
    if let Some(r) = &rating { finding.redteam_rating = Some(r.clone()); }
    let mut vr = verify_finding(&finding);
    if let Ok(cfg) = project_config(db, project_id) {
        let obj = normalize_objective(cfg.get("objective").or_else(|| cfg.get("track")).and_then(Value::as_str));
        if objective_is_src(Some(obj)) && !src_impact_proven(&finding) {
            vr.status = "pending".into();
            vr.reason = "src_impact_not_proven".into();
        }
    }
    if unproven_hint(&finding) && vr.status != "excluded" {
        vr.status = "pending".into();
        vr.reason = "unproven_hint".into();
    }
    if vr.status == "pending" {
        if finding.severity == "high" || finding.severity == "critical" { finding.severity = "medium".into(); }
        if matches!(rating.as_deref(), Some("high") | Some("critical")) { rating = Some("medium".into()); finding.redteam_rating = Some("medium".into()); }
        if finding.cvss.map(|n| n >= 7.0).unwrap_or(false) { finding.cvss = None; }
    }
    let sev = finding.severity.clone();
    rating = normalize_redteam_rating(finding.redteam_rating.as_deref()).or(rating);
    let rating_why = finding.redteam_rating_rationale.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let mut secondary = i64::from(finding.secondary_verified);
    let mut wants_exclude = finding.verification_status.as_deref().unwrap_or("").eq_ignore_ascii_case("excluded");
    if secondary == 1 && secondary_claim_failed(rating_why.as_deref().unwrap_or("")) { wants_exclude = true; secondary = 0; }
    let page = report_from(&finding);
    let mut existing = None;
    if let Some(fid) = finding.finding_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        existing = q1(db, "SELECT * FROM findings WHERE project_id=?1 AND id=?2", &[&project_id, &fid])?;
    }
    if existing.is_none() { if let Some(nk) = finding.node_key.as_deref().filter(|s| !s.is_empty()) { existing = q1(db, "SELECT * FROM findings WHERE project_id=?1 AND node_key=?2 ORDER BY created_at DESC LIMIT 1", &[&project_id, &nk])?; } }
    if existing.is_none() && !finding.title.trim().is_empty() { existing = q1(db, "SELECT * FROM findings WHERE project_id=?1 AND title=?2 ORDER BY created_at DESC LIMIT 1", &[&project_id, &finding.title])?; }
    if existing.is_none() { existing = find_duplicate_finding(db, project_id, &finding)?; }
    let merged = existing.is_some();
    let fid;
    if let Some(ex) = existing {
        fid = row_str(&ex, "id");
        let prev_sec = row_i64(&ex, "secondary_verified") != 0;
        let prev_st = row_str(&ex, "verification_status");
        let prev_vat = ex.get("verified_at").and_then(Value::as_f64);
        let ts = now();
        let real_fail = wants_exclude && is_real_secondary_failure(rating_why.as_deref().unwrap_or(""));
        let incoming_status = if real_fail { Some("excluded") } else if wants_exclude { finding.verification_status.as_deref() } else { None };
        let (new_st, keep_sec) = merge_verification_status(&prev_st, prev_sec, incoming_status, secondary == 1 && !real_fail, rating_why.as_deref().unwrap_or(""));
        let (verified_at, stored_detail, secondary_out) = if new_st == "excluded" {
            (prev_vat, vr.proof_detail.clone(), 0)
        } else if new_st == "verified" && keep_sec {
            vr = accept_secondary(vr, true);
            let vat = if prev_st != "verified" { Some(ts) } else { prev_vat };
            (vat, vr.proof_detail.clone(), 1)
        } else {
            (prev_vat, vr.proof_detail.clone(), i64::from(keep_sec))
        };
        db.execute(
            "UPDATE findings SET evidence=COALESCE(?1, evidence), poc_curl=COALESCE(?2, poc_curl), poc_python=COALESCE(?3, poc_python), proof_type=COALESCE(?4, proof_type), proof_canary=COALESCE(?5, proof_canary), proof_url=COALESCE(?6, proof_url), proof_detail=COALESCE(?7, proof_detail), verification_status=?8, verified_at=COALESCE(?9, verified_at), secondary_verified=?10, redteam_rating=COALESCE(?11, redteam_rating), redteam_rating_rationale=COALESCE(?12, redteam_rating_rationale), cvss=COALESCE(?13, cvss), report_summary=COALESCE(?14, report_summary), report_impact=COALESCE(?15, report_impact), report_rating=COALESCE(?16, report_rating), report_repro=COALESCE(?17, report_repro), report_fix=COALESCE(?18, report_fix), category=?19, severity=?20 WHERE id=?21",
            &[&finding.evidence as &dyn ToSql, &finding.poc_curl, &finding.poc_python, &vr.proof_type, &vr.proof_canary, &vr.proof_url, &stored_detail, &new_st, &verified_at, &secondary_out, &rating, &rating_why, &finding.cvss, &page[0], &page[1], &page[2], &page[3], &page[4], &finding.category, &sev, &fid],
        )?;
    } else {
        if wants_exclude {
            secondary = 0;
            vr.status = "excluded".into();
            vr.reason = "secondary_not_proven".into();
        } else { vr = accept_secondary(vr, secondary == 1); }
        let ts = now();
        let verified_at = if vr.status == "verified" { Some(ts) } else { None };
        fid = new_id("f_");
        db.execute(
            "INSERT INTO findings(id, project_id, node_key, severity, category, title, description, evidence, poc_curl, poc_python, cvss, created_at, verification_status, verified_at, proof_type, proof_canary, proof_url, proof_detail, secondary_verified, redteam_rating, redteam_rating_rationale, report_summary, report_impact, report_rating, report_repro, report_fix) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26)",
            &[&fid as &dyn ToSql, &project_id, &finding.node_key, &sev, &finding.category, &finding.title, &finding.description, &finding.evidence, &finding.poc_curl, &finding.poc_python, &finding.cvss, &ts, &vr.status, &verified_at, &vr.proof_type, &vr.proof_canary, &vr.proof_url, &vr.proof_detail, &secondary, &rating, &rating_why, &page[0], &page[1], &page[2], &page[3], &page[4]],
        )?;
    }
    let row = q1(db, "SELECT * FROM findings WHERE id=?1", &[&fid])?.ok_or_else(|| "finding missing".to_string())?;
    let mut data = serialize_finding(&row);
    if let Some(obj) = data.as_object_mut() {
        obj.insert("critical".into(), Value::from(is_critical(&sev, Some(&finding.category))));
        obj.insert("verify_reason".into(), Value::from(vr.reason.clone()));
        obj.insert("merged".into(), Value::from(merged));
    }
    emit(db, project_id, "finding", data.clone(), run_id);
    if finding.node_key.as_deref().map(|s| !s.is_empty()).unwrap_or(false) && !merged {
        if let Some(nk) = &finding.node_key {
            if let Some(nrow) = q1(db, "SELECT * FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, nk])? {
                let score = compute_risk_score(&sev, &row_str(&nrow, "type"), row_bool(&nrow, "is_rce"), Some(&finding.category));
                let ts = now();
                db.execute("UPDATE nodes SET severity=?1, risk_score=?2, updated_at=?3 WHERE id=?4", &[&sev as &dyn ToSql, &score, &ts, &row_str(&nrow, "id")])?;
                derive_intents_for_finding(db, project_id, &finding, &nrow, run_id)?;
            }
        }
    }
    invalidate_graph_cache(Some(project_id));
    let proof = finding.proof_url.clone().filter(|s| !s.trim().is_empty()).or_else(|| vr.proof_url.clone().filter(|s| !s.trim().is_empty()));
    let _ = crate::assets::attach_finding_assets(db, project_id, &fid, proof.as_deref(), finding.evidence.as_deref());
    Ok(data)
}

pub fn findings_pending_review(db: &Db, project_id: &str, want_secondary: Option<bool>, want_rating: Option<bool>) -> Result<Vec<Value>, String> {
    let (def_sec, def_rate) = review_flags();
    let do_sec = want_secondary.unwrap_or(def_sec);
    let do_rate = want_rating.unwrap_or(def_rate);
    if !do_sec && !do_rate { return Ok(Vec::new()); }
    let rows = qn(db, "SELECT * FROM findings WHERE project_id=?1 ORDER BY created_at DESC", &[&project_id])?;
    let obj = project_config(db, project_id).ok().and_then(|cfg| cfg.get("objective").or_else(|| cfg.get("track")).and_then(Value::as_str).map(|s| s.to_string()));
    let _ = obj;
    let mut sec_done = BTreeSet::new();
    let mut rate_done = BTreeSet::new();
    let mut pending = Vec::new();
    for row in rows {
        if !finding_row_visible(&row) || !is_visible_finding(&row) { continue; }
        let data = serialize_finding(&row);
        let keys = finding_dedup_keys_from_row(&row);
        if data.get("secondary_verified").and_then(Value::as_bool).unwrap_or(false) { sec_done.extend(keys.iter().cloned()); }
        if normalize_redteam_rating(data.get("redteam_rating").and_then(Value::as_str)).is_some() { rate_done.extend(keys.iter().cloned()); }
        pending.push((data, keys));
    }
    let mut out = Vec::new();
    for (mut data, keys) in pending {
        let covered_sec = data.get("secondary_verified").and_then(Value::as_bool).unwrap_or(false) || (!keys.is_empty() && keys.intersection(&sec_done).next().is_some());
        let covered_rate = normalize_redteam_rating(data.get("redteam_rating").and_then(Value::as_str)).is_some() || (!keys.is_empty() && keys.intersection(&rate_done).next().is_some());
        let status = data.get("verification_status").and_then(Value::as_str).unwrap_or("");
        let mode = finding_review_need(covered_sec, if covered_rate { Some("info") } else { None }, status, do_sec, do_rate);
        let Some(mode) = mode else { continue; };
        if let Some(obj) = data.as_object_mut() { obj.insert("_review_mode".into(), Value::from(mode)); }
        out.push(data);
    }
    Ok(out)
}

pub fn findings_pending_secondary(db: &Db, project_id: &str) -> Result<Vec<Value>, String> {
    findings_pending_review(db, project_id, None, None)
}

pub fn add_intent(db: &Db, project_id: &str, intent: &IntentIn, run_id: Option<&str>) -> Result<Value, String> {
    let ts = now();
    let priority = intent.priority.unwrap_or(intent.est_success);
    let status = if intent.status.is_empty() { "open".to_string() } else { intent.status.clone() };
    let sk = intent.strategy_key.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let ev = intent.evidence_fingerprint.clone();
    if let Some(sk) = &sk {
        if let Some(existing) = q1(db, "SELECT * FROM intents WHERE project_id=?1 AND strategy_key=?2", &[&project_id, sk])? {
            let same = row_str(&existing, "evidence_fingerprint") == ev.clone().unwrap_or_default();
            let st = row_str(&existing, "status");
            if ["verified", "disproved"].contains(&st.as_str()) && same { return Ok(serialize_intent(&existing)); }
            if ["open", "active", "deferred"].contains(&st.as_str()) && same {
                db.execute("UPDATE intents SET description=?1, rationale=?2, est_success=?3, priority=?4, evidence_fingerprint=?5, updated_at=?6 WHERE id=?7", &[&intent.description as &dyn ToSql, &intent.rationale, &intent.est_success, &priority, &ev, &ts, &row_str(&existing, "id")])?;
                let row = q1(db, "SELECT * FROM intents WHERE id=?1", &[&row_str(&existing, "id")])?.unwrap_or(existing);
                invalidate_graph_cache(Some(project_id));
                return Ok(serialize_intent(&row));
            }
            db.execute("UPDATE intents SET description=?1, rationale=?2, est_success=?3, priority=?4, evidence_fingerprint=?5, status='open', failure_fingerprint=NULL, result_summary=NULL, updated_at=?6 WHERE id=?7", &[&intent.description as &dyn ToSql, &intent.rationale, &intent.est_success, &priority, &ev, &ts, &row_str(&existing, "id")])?;
            let row = q1(db, "SELECT * FROM intents WHERE id=?1", &[&row_str(&existing, "id")])?.unwrap_or(existing);
            let data = serialize_intent(&row);
            emit(db, project_id, "intent", data.clone(), run_id);
            invalidate_graph_cache(Some(project_id));
            return Ok(data);
        }
    }
    let iid = new_id("i_");
    let from_keys = dumps_tags(&intent.from_keys);
    let attempts = 0i64;
    let none: Option<String> = None;
    db.execute(
        "INSERT INTO intents(id, project_id, from_keys, description, rationale, est_success, status, strategy_key, evidence_fingerprint, priority, attempt_count, failure_fingerprint, result_summary, active_run_id, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
        &[&iid as &dyn ToSql, &project_id, &from_keys, &intent.description, &intent.rationale, &intent.est_success, &status, &sk, &ev, &priority, &attempts, &none, &none, &none, &ts, &ts],
    )?;
    let deps: Vec<String> = intent.depends_on.iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if !deps.is_empty() {
        let blob = dumps_tags(&deps);
        db.execute("UPDATE intents SET depends_on=?1 WHERE id=?2", &[&blob, &iid])?;
    }
    let row = q1(db, "SELECT * FROM intents WHERE id=?1", &[&iid])?.ok_or_else(|| "intent missing".to_string())?;
    let data = serialize_intent(&row);
    emit(db, project_id, "intent", data.clone(), run_id);
    invalidate_graph_cache(Some(project_id));
    Ok(data)
}

pub fn derive_intents_for_node(db: &Db, project_id: &str, node_row: &Map<String, Value>, run_id: Option<&str>) -> Result<Vec<Value>, String> {
    let (allows, obj) = project_objective_meta(db, project_id)?;
    let brief = project_brief(db, project_id).unwrap_or_default();
    let siblings = qn(db, "SELECT * FROM nodes WHERE project_id=?1", &[&project_id]).unwrap_or_default();
    let graph = json!({"nodes": siblings.iter().map(serialize_node).collect::<Vec<_>>()});
    let node = json_obj(node_row.clone());
    let mut created = Vec::new();
    for hyp in hypotheses_for_node(&node, allows, Some(&obj), &brief, Some(&graph)) {
        created.push(add_intent(db, project_id, &hyp_to_intent(hyp), run_id)?);
    }
    Ok(created)
}

pub fn derive_intents_for_finding(db: &Db, project_id: &str, finding: &FindingIn, node_row: &Map<String, Value>, run_id: Option<&str>) -> Result<Vec<Value>, String> {
    let (allows, obj) = project_objective_meta(db, project_id)?;
    let finding_v = json!({
        "node_key": finding.node_key, "severity": finding.severity, "category": finding.category,
        "title": finding.title, "description": finding.description, "evidence": finding.evidence,
    });
    let mut created = Vec::new();
    for hyp in hypotheses_for_finding(&finding_v, &json_obj(node_row.clone()), allows, Some(&obj)) {
        created.push(add_intent(db, project_id, &hyp_to_intent(hyp), run_id)?);
    }
    Ok(created)
}

fn defer_intent_tactic(db: &Db, project_id: &str, source_key: &str, tactic: &str, reason: &str, run_id: Option<&str>) -> Result<bool, String> {
    let sk = strategy_key(source_key, tactic);
    let Some(row) = q1(db, "SELECT id, status FROM intents WHERE project_id=?1 AND strategy_key=?2", &[&project_id, &sk])? else { return Ok(false); };
    if !["open", "active"].contains(&row_str(&row, "status").as_str()) { return Ok(false); }
    set_intent_status(db, project_id, &row_str(&row, "id"), "deferred", Some(reason), Some(reason), run_id)?;
    Ok(true)
}

fn open_strategy_keys(db: &Db, project_id: &str) -> Result<HashSet<String>, String> {
    let rows = qn(db, "SELECT strategy_key FROM intents WHERE project_id=?1 AND status IN ('open','active')", &[&project_id])?;
    Ok(rows.into_iter().map(|r| row_str(&r, "strategy_key")).filter(|s| !s.is_empty()).collect())
}

pub fn refresh_derived_intents(db: &Db, project_id: &str, run_id: Option<&str>, force: bool) -> Result<Value, String> {
    if !force {
        if let Some(at) = lock().intent_at.get(project_id).copied() {
            if at.elapsed() < INTENT_TTL { return Ok(json!({"opened": 0, "stale_deferred": 0, "skipped": true})); }
        }
    }
    lock().intent_at.insert(project_id.to_string(), Instant::now());
    let nodes = qn(db, "SELECT * FROM nodes WHERE project_id=?1", &[&project_id])?;
    let before = open_strategy_keys(db, project_id)?;
    let mut stale_deferred = 0i64;
    let reason = "规则刷新：该 tactic 不再适用于此节点（SSRF≠weaponize；机器令牌≠登录复用）";
    let serialized: Vec<Value> = nodes.iter().map(serialize_node).collect();
    let brief = project_brief(db, project_id).unwrap_or_default();
    let mut node_by = HashMap::new();
    for (raw, ser) in nodes.iter().zip(serialized.iter()) {
        derive_intents_for_node(db, project_id, raw, run_id)?;
        for tac in stale_tactics_for_node(ser, &brief) {
            if defer_intent_tactic(db, project_id, ser.get("key").and_then(Value::as_str).unwrap_or(""), &tac, reason, run_id)? { stale_deferred += 1; }
        }
        node_by.insert(ser.get("key").and_then(Value::as_str).unwrap_or("").to_string(), ser.clone());
    }
    for f in qn(db, "SELECT * FROM findings WHERE project_id=?1", &[&project_id])? {
        let key = row_str(&f, "node_key");
        let nrow = if let Some(n) = node_by.get(&key) {
            let mut m = Map::new();
            if let Some(obj) = n.as_object() { m = obj.clone(); }
            m
        } else {
            let mut m = Map::new();
            m.insert("key".into(), Value::from(key.clone()));
            m.insert("type".into(), Value::from("info"));
            m.insert("title".into(), Value::from(if row_str(&f, "title").is_empty() { key.clone() } else { row_str(&f, "title") }));
            m
        };
        let finding = FindingIn { node_key: if key.is_empty() { None } else { Some(key) }, severity: { let s = row_str(&f, "severity"); if s.is_empty() { "medium".into() } else { s } }, category: { let s = row_str(&f, "category"); if s.is_empty() { "info".into() } else { s } }, title: { let s = row_str(&f, "title"); if s.is_empty() { "finding".into() } else { s } }, description: row_opt(&f, "description"), evidence: row_opt(&f, "evidence"), ..FindingIn::blank() };
        let _ = derive_intents_for_finding(db, project_id, &finding, &nrow, run_id);
    }
    stale_deferred += defer_ineligible_hop_auth(db, project_id, run_id).unwrap_or(0);
    let after = open_strategy_keys(db, project_id)?;
    let opened = after.difference(&before).count() as i64;
    Ok(json!({"opened": opened.max(0), "stale_deferred": stale_deferred}))
}

fn intent_deps_ready(db: &Db, project_id: &str, item: &Value) -> Result<bool, String> {
    let deps = item.get("depends_on").cloned().unwrap_or(Value::Null);
    let deps = loads(&deps);
    let Some(list) = deps.as_array() else { return Ok(true); };
    if list.is_empty() { return Ok(true); }
    for iid in list {
        let id = iid.as_str().unwrap_or("").to_string();
        let Some(row) = q1(db, "SELECT status, from_keys FROM intents WHERE id=?1 AND project_id=?2", &[&id, &project_id])? else { return Ok(false); };
        if row_str(&row, "status") == "verified" { continue; }
        let keys = loads(&row.get("from_keys").cloned().unwrap_or(Value::Null));
        let Some(keys) = keys.as_array() else { return Ok(false); };
        if keys.is_empty() { return Ok(false); }
        let mut found = false;
        for key in keys {
            let k = key.as_str().unwrap_or("");
            if q1(db, "SELECT id FROM nodes WHERE project_id=?1 AND key=?2", &[&project_id, &k])?.is_some() { found = true; break; }
        }
        if !found { return Ok(false); }
    }
    Ok(true)
}

pub fn list_open_intents(db: &Db, project_id: &str, limit: i64) -> Result<Vec<Value>, String> {
    let cap = (limit * 4).max(limit);
    let rows = qn(db, "SELECT * FROM intents WHERE project_id=?1 AND status IN ('open','deferred','active') AND IFNULL(paused,0)=0 ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'open' THEN 1 ELSE 2 END, COALESCE(priority, est_success) DESC, created_at ASC LIMIT ?2", &[&project_id as &dyn ToSql, &cap])?;
    let mut out = Vec::new();
    for row in rows {
        let item = serialize_intent(&row);
        if !intent_deps_ready(db, project_id, &item)? { continue; }
        out.push(item);
        if out.len() as i64 >= limit { break; }
    }
    Ok(out)
}

pub fn list_disproved_intents(db: &Db, project_id: &str, limit: i64) -> Result<Vec<Value>, String> {
    let rows = qn(db, "SELECT * FROM intents WHERE project_id=?1 AND status='disproved' ORDER BY updated_at DESC LIMIT ?2", &[&project_id as &dyn ToSql, &limit])?;
    Ok(rows.iter().map(serialize_intent).collect())
}

fn tactic_of(it: &Value) -> String {
    let sk = it.get("strategy_key").and_then(Value::as_str).unwrap_or("");
    if sk.contains("::") { sk.rsplit("::").next().unwrap_or("").to_string() } else { sk.to_string() }
}

pub fn list_frontier_intents(db: &Db, project_id: &str, limit: i64, exclude: &HashSet<String>, prefer: &HashSet<String>) -> Result<Vec<Value>, String> {
    let mut candidates = list_open_intents(db, project_id, 50)?;
    candidates.retain(|it| it.get("status").and_then(Value::as_str) != Some("deferred"));
    if !exclude.is_empty() {
        candidates.retain(|it| {
            let sk = it.get("strategy_key").and_then(Value::as_str).unwrap_or("");
            !exclude.contains(sk) && !exclude.contains(&tactic_of(it))
        });
    }
    if !prefer.is_empty() {
        let mut head: Vec<Value> = candidates.iter().filter(|it| prefer.contains(&tactic_of(it))).cloned().collect();
        let tail: Vec<Value> = candidates.iter().filter(|it| !prefer.contains(&tactic_of(it))).cloned().collect();
        let mut rank: HashMap<&str, i64> = CHAIN_CLOSE.iter().enumerate().map(|(i, n)| (*n, i as i64)).collect();
        if prefer.contains("reverse_binary") { rank.insert("reverse_binary", -3); rank.insert("protocol_model", -2); }
        head.sort_by_key(|it| rank.get(tactic_of(it).as_str()).copied().unwrap_or(50));
        candidates = head;
        candidates.extend(tail);
    }
    let mut picked = Vec::new();
    let mut used_sources = HashSet::new();
    let mut used_tactics = HashSet::new();
    for it in candidates {
        let sk = it.get("strategy_key").and_then(Value::as_str).unwrap_or("").to_string();
        let tactic = tactic_of(&it);
        if exclude.contains(&sk) || exclude.contains(&tactic) { continue; }
        let sources: HashSet<String> = it.get("from").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(|s| s.to_string()).collect()).unwrap_or_default();
        if !sources.is_disjoint(&used_sources) && !picked.is_empty() && used_tactics.contains(&tactic) { continue; }
        if used_tactics.contains(&tactic) && !picked.is_empty() { continue; }
        used_sources.extend(sources);
        if !tactic.is_empty() { used_tactics.insert(tactic); }
        picked.push(it);
        if picked.len() as i64 >= limit { break; }
    }
    Ok(picked)
}

pub fn frontier_stats(db: &Db, project_id: &str) -> Result<Value, String> {
    let rows = qn(db, "SELECT status, strategy_key, attempt_count FROM intents WHERE project_id=?1", &[&project_id])?;
    let mut by_status: BTreeMap<String, i64> = BTreeMap::new();
    let mut strategies = HashSet::new();
    for r in &rows {
        let st = { let s = row_str(r, "status"); if s.is_empty() { "open".into() } else { s } };
        *by_status.entry(st).or_insert(0) += 1;
        let sk = row_str(r, "strategy_key");
        if !sk.is_empty() { strategies.insert(sk); }
    }
    let open_n = ["open", "active", "deferred"].iter().map(|s| by_status.get(*s).copied().unwrap_or(0)).sum::<i64>();
    Ok(json!({"open": open_n, "by_status": by_status, "strategies": strategies.len(), "disproved": by_status.get("disproved").copied().unwrap_or(0), "verified": by_status.get("verified").copied().unwrap_or(0)}))
}

pub fn set_intent_status(db: &Db, project_id: &str, intent_id: &str, status: &str, result_summary: Option<&str>, failure_fingerprint: Option<&str>, run_id: Option<&str>) -> Result<Option<Value>, String> {
    let Some(row) = q1(db, "SELECT * FROM intents WHERE id=?1 AND project_id=?2", &[&intent_id, &project_id])? else { return Ok(None); };
    let ts = now();
    let mut attempts = row_i64(&row, "attempt_count");
    if status == "active" { attempts += 1; }
    let summary = result_summary.map(|s| s.to_string());
    let fail = failure_fingerprint.map(|s| s.to_string());
    let run = run_id.map(|s| s.to_string());
    db.execute("UPDATE intents SET status=?1, result_summary=COALESCE(?2, result_summary), failure_fingerprint=COALESCE(?3, failure_fingerprint), attempt_count=?4, active_run_id=?5, updated_at=?6 WHERE id=?7 AND project_id=?8", &[&status as &dyn ToSql, &summary, &fail, &attempts, &run, &ts, &intent_id, &project_id])?;
    let out = q1(db, "SELECT * FROM intents WHERE id=?1", &[&intent_id])?;
    if let Some(out) = &out { emit(db, project_id, "intent", serialize_intent(out), run_id); }
    Ok(out.map(|r| serialize_intent(&r)))
}

pub fn claim_intents(db: &Db, project_id: &str, intent_ids: &[String], run_id: Option<&str>) -> Result<Vec<Value>, String> {
    let mut claimed = Vec::new();
    for iid in intent_ids { if let Some(row) = set_intent_status(db, project_id, iid, "active", None, None, run_id)? { claimed.push(row); } }
    Ok(claimed)
}

pub fn get_intent(db: &Db, project_id: &str, intent_id: &str) -> Result<Option<Value>, String> {
    let iid = intent_id.trim();
    if iid.is_empty() { return Ok(None); }
    Ok(q1(db, "SELECT * FROM intents WHERE id=?1 AND project_id=?2", &[&iid, &project_id])?.map(|r| serialize_intent(&r)))
}

pub fn resolve_intent(db: &Db, project_id: &str, intent_id: &str, verified: bool, summary: Option<&str>, failure_fingerprint: Option<&str>, run_id: Option<&str>) -> Result<Option<Value>, String> {
    let status = if verified { "verified" } else { "disproved" };
    let fail = if verified { None } else { failure_fingerprint.or(summary) };
    set_intent_status(db, project_id, intent_id, status, summary, fail, run_id)
}

pub fn defer_strategy_family(db: &Db, project_id: &str, tactic_substr: &str, reason: &str, run_id: Option<&str>) -> Result<i64, String> {
    let like = format!("%::{tactic_substr}%");
    let rows = qn(db, "SELECT id, strategy_key FROM intents WHERE project_id=?1 AND status IN ('open','active') AND strategy_key LIKE ?2", &[&project_id, &like])?;
    let mut n = 0i64;
    for r in rows { set_intent_status(db, project_id, &row_str(&r, "id"), "deferred", Some(reason), Some(reason), run_id)?; n += 1; }
    Ok(n)
}

pub fn quality_progress_delta(prev: &[i64], curr: &[i64], graph: &Value) -> String {
    if prev.len() < 4 || curr.len() < 4 || prev.iter().take(4).any(|x| *x < 0) { return "none".into(); }
    if curr[3] > prev[3] { return "flag".into(); }
    if curr[2] > prev[2] { return "finding".into(); }
    let edges = graph.get("edges").and_then(Value::as_array).cloned().unwrap_or_default();
    if edges.iter().any(|e| ["EXPLOITS", "ESCALATES_TO", "PIVOTS_TO"].contains(&e.get("relation").and_then(Value::as_str).unwrap_or(""))) && curr[1] > prev[1] { return "capability_edge".into(); }
    let nodes = graph.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default();
    let valuable = nodes.iter().filter(|n| ["vuln", "credential", "foothold", "goal"].contains(&n.get("type").and_then(Value::as_str).unwrap_or(""))).count();
    if curr[0] > prev[0] && valuable > 0 { return "valuable_node".into(); }
    if curr[0] > prev[0] {
        if nodes.iter().any(|n| n.get("type").and_then(Value::as_str) == Some("info")) { return "info_node".into(); }
        return "weak_graph".into();
    }
    if curr[1] > prev[1] { return "weak_graph".into(); }
    "none".into()
}

struct Dig {
    nodes: HashSet<String>,
    out: HashMap<String, Vec<(String, f64, f64)>>,
}

fn path_likelihood(g: &Dig, path: &[String]) -> f64 {
    if path.len() <= 1 { return if path.is_empty() { 0.0 } else { 1.0 }; }
    let mut lik = 1.0;
    for w in path.windows(2) {
        let weight = g.out.get(&w[0]).and_then(|es| es.iter().find(|e| e.0 == w[1])).map(|e| e.2).unwrap_or(0.01);
        lik *= weight;
    }
    lik
}

fn simple_paths(g: &Dig, start: &str, goal: &str, cutoff: usize) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut path = vec![start.to_string()];
    fn walk(g: &Dig, goal: &str, cutoff: usize, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        if out.len() >= 4000 { return; }
        if path.last().map(String::as_str) == Some(goal) && path.len() > 1 { out.push(path.clone()); return; }
        if path.len() - 1 >= cutoff { return; }
        let Some(nbs) = g.out.get(path.last().unwrap()).cloned() else { return; };
        for (nb, _, _) in nbs {
            if path.iter().any(|p| p == &nb) { continue; }
            path.push(nb);
            walk(g, goal, cutoff, path, out);
            path.pop();
        }
    }
    walk(g, goal, cutoff, &mut path, &mut out);
    out
}

fn dijkstra(g: &Dig, start: &str, goal: &str) -> Option<(f64, Vec<String>)> {
    if !g.nodes.contains(start) || !g.nodes.contains(goal) { return None; }
    let mut dist: HashMap<String, f64> = HashMap::new();
    let mut prev: HashMap<String, String> = HashMap::new();
    let mut seen = HashSet::new();
    dist.insert(start.to_string(), 0.0);
    loop {
        let mut best: Option<(String, f64)> = None;
        for (n, d) in &dist {
            if seen.contains(n) { continue; }
            if best.as_ref().map(|(_, bd)| *d < *bd).unwrap_or(true) { best = Some((n.clone(), *d)); }
        }
        let Some((u, du)) = best else { break };
        if u == goal {
            let mut path = vec![u.clone()];
            let mut cur = u.clone();
            while let Some(p) = prev.get(&cur) { path.push(p.clone()); cur = p.clone(); }
            path.reverse();
            return Some((du, path));
        }
        seen.insert(u.clone());
        if let Some(nbs) = g.out.get(&u) {
            for (v, cost, _) in nbs {
                if seen.contains(v) { continue; }
                let nd = du + *cost;
                if dist.get(v).map(|d| nd < *d).unwrap_or(true) { dist.insert(v.clone(), nd); prev.insert(v.clone(), u.clone()); }
            }
        }
    }
    None
}

fn tagset_row(n: &Map<String, Value>) -> HashSet<String> { row_tags(n, "tags").into_iter().map(|t| t.to_ascii_lowercase()).collect() }

fn closeable_verified(n: &Map<String, Value>, findings: &HashMap<String, Vec<Map<String, Value>>>) -> bool {
    let key = row_str(n, "key");
    let tags = tagset_row(n);
    if tags.contains("verified") && tags.iter().any(|t| CLOSE_FINDING.contains(&t.as_str())) { return true; }
    for f in findings.get(&key).into_iter().flatten() {
        let vs = { let s = row_str(f, "verification_status").to_ascii_lowercase(); if s.is_empty() { "verified".into() } else { s } };
        if vs != "verified" { continue; }
        let cat = row_str(f, "category").to_ascii_lowercase();
        if CLOSE_FINDING.contains(&cat.as_str()) || row_str(f, "severity").eq_ignore_ascii_case("critical") || row_bool(f, "critical") { return true; }
    }
    false
}

fn rce_sink_ok(n: &Map<String, Value>, findings: &HashMap<String, Vec<Map<String, Value>>>) -> bool {
    let t = row_str(n, "type");
    let key = row_str(n, "key");
    let tags = tagset_row(n);
    if t == "info" { return false; }
    if t == "goal" && key.starts_with("goal:shell") { return true; }
    if t == "foothold" && (row_bool(n, "is_rce") || tags.contains("getshell")) { return true; }
    if (t == "vuln" || t == "danger") && closeable_verified(n, findings) { return true; }
    if t == "vuln" && row_bool(n, "is_rce") { return true; }
    false
}

fn transport_stuck(n: &Map<String, Value>) -> bool {
    re_transport().is_match(&format!("{} {} {}", row_str(n, "title"), detail_text(n.get("detail").unwrap_or(&Value::Null)), row_str(n, "key")))
}

fn sink_prio(key: &str, node_by: &HashMap<String, Map<String, Value>>, findings: &HashMap<String, Vec<Map<String, Value>>>) -> i64 {
    let Some(n) = node_by.get(key) else { return 0; };
    let t = row_str(n, "type");
    let tags = tagset_row(n);
    if t == "goal" && key.starts_with("goal:shell") { return 4; }
    if t == "foothold" && (row_bool(n, "is_rce") || tags.contains("getshell")) { return 3; }
    if (t == "vuln" || t == "danger") && closeable_verified(n, findings) { return 3; }
    if row_bool(n, "is_rce") && t == "vuln" { return 2; }
    if t == "foothold" { return 1; }
    0
}

fn pick_attack_chain(g: &Dig, sources: &[String], sinks: &[String], node_by: &HashMap<String, Map<String, Value>>, findings: &HashMap<String, Vec<Map<String, Value>>>) -> Vec<String> {
    for prio in [4, 3, 2, 1, 0] {
        let group: Vec<&String> = sinks.iter().filter(|t| sink_prio(t, node_by, findings) == prio).collect();
        if group.is_empty() { continue; }
        let mut best_path = Vec::new();
        let mut best_key = (-1i64, -1.0f64);
        for s in sources {
            for t in &group {
                if s == *t {
                    if (0, 1.0) > best_key { best_key = (0, 1.0); best_path = vec![s.clone()]; }
                    continue;
                }
                if !g.nodes.contains(s) || !g.nodes.contains(*t) { continue; }
                for path in simple_paths(g, s, t, 16) {
                    let key = ((path.len() as i64) - 1, path_likelihood(g, &path));
                    if key > best_key { best_key = key; best_path = path; }
                }
            }
        }
        if !best_path.is_empty() { return best_path; }
    }
    let mut best_path = Vec::new();
    let mut best_cost = f64::INFINITY;
    for s in sources {
        for t in sinks {
            if s == t { return vec![s.clone()]; }
            if let Some((cost, path)) = dijkstra(g, s, t) { if cost < best_cost { best_cost = cost; best_path = path; } }
        }
    }
    best_path
}

pub fn recompute_rce_path(db: &Db, project_id: &str, run_id: Option<&str>, emit_event: bool) -> Result<Value, String> {
    let nodes = qn(db, "SELECT * FROM nodes WHERE project_id=?1", &[&project_id])?;
    let edges = qn(db, "SELECT * FROM edges WHERE project_id=?1", &[&project_id])?;
    if nodes.is_empty() { return Ok(json!({"path": [], "likelihood": 0.0})); }
    let node_by: HashMap<String, Map<String, Value>> = nodes.iter().map(|n| (row_str(n, "key"), n.clone())).collect();
    let mut g = Dig { nodes: node_by.keys().cloned().collect(), out: HashMap::new() };
    for e in &edges {
        let (src, dst) = (row_str(e, "src"), row_str(e, "dst"));
        if !node_by.contains_key(&src) || !node_by.contains_key(&dst) { continue; }
        if row_str(e, "relation") == "PIVOTS_TO" { continue; }
        let src_n = &node_by[&src];
        let dst_n = &node_by[&dst];
        if row_str(src_n, "type") == "target" && (row_str(dst_n, "type") == "goal" || dst.starts_with("goal:") || dst.starts_with("flag:")) { continue; }
        let w = row_f64(e, "weight").clamp(0.01, 1.0);
        let slot = g.out.entry(src).or_default();
        if let Some(existing) = slot.iter_mut().find(|x| x.0 == dst) { *existing = (dst, -w.ln(), w); }
        else { slot.push((dst, -w.ln(), w)); }
    }
    let mut sources: Vec<String> = nodes.iter().filter(|n| row_str(n, "type") == "target").map(|n| row_str(n, "key")).collect();
    if sources.is_empty() {
        sources = g.nodes.iter().filter(|k| !g.out.values().any(|es| es.iter().any(|e| &e.0 == *k))).cloned().collect();
        if sources.is_empty() { sources.push(row_str(&nodes[0], "key")); }
    }
    let mut findings_by: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    for f in qn(db, "SELECT * FROM findings WHERE project_id=?1", &[&project_id])? {
        let nk = row_str(&f, "node_key");
        if !nk.is_empty() { findings_by.entry(nk).or_default().push(f); }
    }
    let mut sinks: Vec<String> = nodes.iter().filter(|n| rce_sink_ok(n, &findings_by)).map(|n| row_str(n, "key")).collect();
    let mut frontier_mode = false;
    if sinks.is_empty() {
        frontier_mode = true;
        let mut ranked: Vec<&Map<String, Value>> = nodes.iter().filter(|n| ["danger", "vuln"].contains(&row_str(n, "type").as_str()) && !transport_stuck(n)).collect();
        ranked.sort_by(|a, b| row_f64(b, "risk_score").partial_cmp(&row_f64(a, "risk_score")).unwrap_or(Ordering::Equal));
        if ranked.is_empty() {
            ranked = nodes.iter().filter(|n| ["danger", "vuln"].contains(&row_str(n, "type").as_str())).collect();
            ranked.sort_by(|a, b| row_f64(b, "risk_score").partial_cmp(&row_f64(a, "risk_score")).unwrap_or(Ordering::Equal));
        }
        if let Some(first) = ranked.first() { sinks.push(row_str(first, "key")); }
    }
    let mut paths = Vec::new();
    let mut seen_paths = HashSet::new();
    if !sinks.is_empty() {
        for source in &sources {
            let path = pick_attack_chain(&g, std::slice::from_ref(source), &sinks, &node_by, &findings_by);
            let sig = path.join("\u{1}");
            if path.len() >= 2 && seen_paths.insert(sig) { paths.push(path); }
        }
    }
    if paths.is_empty() && !sinks.is_empty() {
        let fallback = pick_attack_chain(&g, &sources, &sinks, &node_by, &findings_by);
        if !fallback.is_empty() { paths.push(fallback); }
    }
    let best_path = paths.iter().max_by(|a, b| a.len().cmp(&b.len()).then(path_likelihood(&g, a).partial_cmp(&path_likelihood(&g, b)).unwrap_or(Ordering::Equal))).cloned().unwrap_or_default();
    let likelihood = if best_path.is_empty() { 0.0 } else { (path_likelihood(&g, &best_path) * 10000.0).round() / 10000.0 };
    let pairs: HashSet<(String, String)> = paths.iter().flat_map(|p| p.windows(2).map(|w| (w[0].clone(), w[1].clone()))).collect();
    for e in &edges {
        let on = i64::from(pairs.contains(&(row_str(e, "src"), row_str(e, "dst"))));
        if row_i64(e, "on_rce_path") != on { db.execute("UPDATE edges SET on_rce_path=?1 WHERE id=?2", &[&on as &dyn ToSql, &row_str(e, "id")])?; }
    }
    let result = json!({"path": best_path, "paths": paths, "likelihood": likelihood, "frontier_mode": frontier_mode});
    let sig = result.to_string();
    if emit_event && lock().rce_sig.get(project_id) != Some(&sig) {
        lock().rce_sig.insert(project_id.to_string(), sig);
        emit(db, project_id, "rce_path", result.clone(), run_id);
    }
    Ok(result)
}

fn rce_path_from_marks(db: &Db, project_id: &str) -> Result<Value, String> {
    let edges = qn(db, "SELECT src, dst, weight FROM edges WHERE project_id=?1 AND on_rce_path=1", &[&project_id])?;
    if edges.is_empty() { return Ok(json!({"path": [], "paths": [], "likelihood": 0.0, "frontier_mode": false})); }
    let mut succ: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    let mut indeg: HashMap<String, i64> = HashMap::new();
    for e in &edges {
        succ.entry(row_str(e, "src")).or_default().push((row_str(e, "dst"), row_f64(e, "weight")));
        *indeg.entry(row_str(e, "dst")).or_insert(0) += 1;
        indeg.entry(row_str(e, "src")).or_insert(0);
    }
    let starts: Vec<String> = indeg.iter().filter(|(_, d)| **d == 0).map(|(k, _)| k.clone()).collect();
    let starts = if starts.is_empty() { vec![row_str(&edges[0], "src")] } else { starts };
    let mut paths = Vec::new();
    let mut likes = Vec::new();
    for s in starts {
        let mut path = vec![s.clone()];
        let mut like = 1.0;
        let mut cur = s.clone();
        let mut seen = HashSet::from([s]);
        while let Some(nbs) = succ.get(&cur) {
            if nbs.is_empty() { break; }
            let (nxt, w) = nbs[0].clone();
            if !seen.insert(nxt.clone()) { break; }
            path.push(nxt.clone());
            like *= w.clamp(0.01, 1.0);
            cur = nxt;
        }
        if path.len() >= 2 { paths.push(path); likes.push(like); }
    }
    let best_idx = (0..paths.len()).max_by(|i, j| paths[*i].len().cmp(&paths[*j].len()).then(likes[*i].partial_cmp(&likes[*j]).unwrap_or(Ordering::Equal)));
    let best = best_idx.map(|i| paths[i].clone()).unwrap_or_default();
    let best_like = best_idx.map(|i| likes[i]).unwrap_or(0.0);
    Ok(json!({"path": best, "paths": paths, "likelihood": if best.len() > 1 { (best_like * 10000.0).round() / 10000.0 } else { 0.0 }, "frontier_mode": false}))
}

pub fn clear_graph(db: &Db, project_id: &str) -> Result<Value, String> {
    for tbl in ["nodes", "edges", "findings", "intents"] {
        db.execute(&format!("DELETE FROM {tbl} WHERE project_id=?1"), &[&project_id])?;
    }
    invalidate_graph_cache(Some(project_id));
    Ok(json!({"cleared": ["nodes", "edges", "findings", "intents"]}))
}

pub fn lateral_state(nodes: &[Value], edges: &[Value]) -> Value {
    let pivot = edges.iter().filter(|e| e.get("relation").and_then(Value::as_str) == Some("PIVOTS_TO")).count();
    let mut hosts = BTreeSet::new();
    for n in nodes {
        let key = n.get("key").and_then(Value::as_str).unwrap_or("");
        let ntype = n.get("type").and_then(Value::as_str).unwrap_or("");
        if ntype == "foothold" || (ntype == "goal" && key.starts_with("goal:shell")) {
            let tags = json_tags(n.get("tags"));
            let h = host_of_node(key, &tags);
            if !h.is_empty() { hosts.insert(h); }
        }
    }
    json!({"lateral_active": pivot > 0 || hosts.len() >= 2, "pivot_edges": pivot, "hosts_footed": hosts.len()})
}

fn placeholders(n: usize) -> String { (1..=n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(",") }

pub fn get_stats_batch(db: &Db, project_ids: &[String]) -> Result<Map<String, Value>, String> {
    let empty = json!({"nodes": 0, "services": 0, "edges": 0, "findings": 0, "high": 0, "medium": 0, "low": 0, "critical": 0, "has_shell": false, "lateral_active": false, "pivot_edges": 0, "hosts_footed": 0, "mass_data_leak": false});
    let ids: Vec<String> = project_ids.iter().filter(|s| !s.is_empty()).cloned().collect();
    if ids.is_empty() { return Ok(Map::new()); }
    let mut out: Map<String, Value> = Map::new();
    let mut hosts_by: HashMap<String, BTreeSet<String>> = HashMap::new();
    for id in &ids { out.insert(id.clone(), empty.clone()); hosts_by.insert(id.clone(), BTreeSet::new()); }
    let marks = placeholders(ids.len());
    let params: Vec<&dyn ToSql> = ids.iter().map(|s| s as &dyn ToSql).collect();
    for n in qn(db, &format!("SELECT project_id, key, type, is_rce, tags FROM nodes WHERE project_id IN ({marks})"), &params)? {
        let pid = row_str(&n, "project_id");
        let Some(slot) = out.get_mut(&pid).and_then(Value::as_object_mut) else { continue; };
        let nodes_n = slot.get("nodes").and_then(Value::as_i64).unwrap_or(0) + 1;
        slot.insert("nodes".into(), Value::from(nodes_n));
        if row_str(&n, "type") == "service" {
            let c = slot.get("services").and_then(Value::as_i64).unwrap_or(0) + 1;
            slot.insert("services".into(), Value::from(c));
        }
        let tags = row_tags(&n, "tags");
        if node_is_landed_shell(&row_str(&n, "type"), &row_str(&n, "key"), &tags, row_bool(&n, "is_rce")) { slot.insert("has_shell".into(), Value::from(true)); }
        if row_str(&n, "type") == "foothold" || (row_str(&n, "type") == "goal" && row_str(&n, "key").starts_with("goal:shell")) {
            let h = host_of_node(&row_str(&n, "key"), &tags);
            if !h.is_empty() { hosts_by.entry(pid.clone()).or_default().insert(h); }
        }
        if tags.iter().any(|t| MASS_LEAK_TAGS.contains(&t.to_ascii_lowercase().as_str())) { slot.insert("mass_data_leak".into(), Value::from(true)); }
    }
    for e in qn(db, &format!("SELECT project_id, COUNT(*) AS c FROM edges WHERE project_id IN ({marks}) GROUP BY project_id"), &params)? {
        if let Some(slot) = out.get_mut(&row_str(&e, "project_id")).and_then(Value::as_object_mut) { slot.insert("edges".into(), Value::from(row_i64(&e, "c"))); }
    }
    for e in qn(db, &format!("SELECT project_id, COUNT(*) AS c FROM edges WHERE project_id IN ({marks}) AND relation='PIVOTS_TO' GROUP BY project_id"), &params)? {
        if let Some(slot) = out.get_mut(&row_str(&e, "project_id")).and_then(Value::as_object_mut) { slot.insert("pivot_edges".into(), Value::from(row_i64(&e, "c"))); }
    }
    let frows = qn(db, &format!("SELECT project_id, severity, category, title, description, evidence, verification_status, node_key, redteam_rating, proof_type, proof_canary, proof_url, proof_detail, created_at, id FROM findings WHERE project_id IN ({marks})"), &params)?;
    let prows = qn(db, &format!("SELECT id, config FROM projects WHERE id IN ({marks})"), &params)?;
    let mut obj_by = HashMap::new();
    for p in prows {
        let cfg = loads(&p.get("config").cloned().unwrap_or(Value::Null));
        obj_by.insert(row_str(&p, "id"), normalize_objective(cfg.get("objective").or_else(|| cfg.get("track")).and_then(Value::as_str)).to_string());
    }
    let _ = obj_by;
    let mut f_by: HashMap<String, Vec<Map<String, Value>>> = HashMap::new();
    let leak: HashSet<&str> = DATA_ACCESS_CATEGORIES.iter().chain(KEY_LEAK_CATEGORIES.iter()).copied().collect();
    for f in frows {
        if !finding_row_visible(&f) { continue; }
        let pid = row_str(&f, "project_id");
        if leak.contains(row_str(&f, "category").to_ascii_lowercase().as_str()) {
            if let Some(slot) = out.get_mut(&pid).and_then(Value::as_object_mut) { slot.insert("mass_data_leak".into(), Value::from(true)); }
        }
        f_by.entry(pid).or_default().push(f);
    }
    for (pid, rows) in f_by {
        let listed = listed_finding_rows(&collapse_duplicate_findings(&rows));
        if let Some(slot) = out.get_mut(&pid).and_then(Value::as_object_mut) {
            slot.insert("findings".into(), Value::from(listed.len() as i64));
            slot.insert("critical".into(), Value::from(listed.iter().filter(|r| display_finding_severity(r) == "critical").count() as i64));
            slot.insert("high".into(), Value::from(listed.iter().filter(|r| display_finding_severity(r) == "high").count() as i64));
        }
    }
    for pid in &ids {
        let hosts = hosts_by.get(pid).map(|s| s.len()).unwrap_or(0);
        if let Some(slot) = out.get_mut(pid).and_then(Value::as_object_mut) {
            let piv = slot.get("pivot_edges").and_then(Value::as_i64).unwrap_or(0);
            slot.insert("hosts_footed".into(), Value::from(hosts as i64));
            slot.insert("lateral_active".into(), Value::from(piv > 0 || hosts >= 2));
        }
    }
    Ok(out)
}

pub fn get_stats(db: &Db, project_id: &str) -> Result<Value, String> {
    let batch = get_stats_batch(db, &[project_id.to_string()])?;
    Ok(batch.get(project_id).cloned().unwrap_or_else(|| json!({"nodes": 0, "services": 0, "edges": 0, "findings": 0, "high": 0, "medium": 0, "low": 0, "critical": 0, "has_shell": false, "lateral_active": false, "pivot_edges": 0, "hosts_footed": 0, "mass_data_leak": false})))
}

pub fn get_graph(db: &Db, project_id: &str, heal: bool) -> Result<Value, String> {
    if !heal {
        let g = lock();
        if let Some((at, val)) = g.graph_cache.get(project_id) {
            if at.elapsed() < GRAPH_TTL { return Ok(val.clone()); }
        }
    }
    let _ = repair_prefix_type_stubs(db, project_id, None);
    let _ = demote_false_targets(db, project_id);
    let path = if heal {
        ensure_target_attachments(db, project_id, None)?;
        recompute_rce_path(db, project_id, None, false)?
    } else {
        let _ = ensure_lateral_pivots(db, project_id, None);
        if let Some(row) = project_row(db, project_id)? {
            let host = row_str(&row, "target").split(':').next().unwrap_or("").to_string();
            let keep: Vec<String> = project_entry_hosts_from(&row).into_iter().collect();
            if !host.is_empty() { let _ = adopt_entry_host(db, project_id, &host, None, None, &keep); }
        }
        let _ = reopen_live_hop_auth(db, project_id, None);
        let _ = defer_local_closeout_for_remaining_flags(db, project_id, None);
        rce_path_from_marks(db, project_id)?
    };
    let nodes = qn(db, "SELECT * FROM nodes WHERE project_id=?1 ORDER BY created_at", &[&project_id])?;
    let findings_all = qn(db, "SELECT * FROM findings WHERE project_id=?1 ORDER BY created_at DESC", &[&project_id])?;
    let visible: Vec<Map<String, Value>> = findings_all.into_iter().filter(|f| finding_row_visible(f) && is_visible_finding(f)).collect();
    let mut finding_node_keys = BTreeSet::new();
    for row in &visible {
        let key = row_str(row, "node_key");
        if !key.is_empty() {
            finding_node_keys.insert(key);
        }
    }
    let findings = sort_findings_by_severity(collapse_duplicate_findings(&visible));
    let listed = listed_finding_rows(&findings);
    let edges = qn(db, "SELECT * FROM edges WHERE project_id=?1 ORDER BY created_at", &[&project_id])?;
    let intents = list_open_intents(db, project_id, 30)?;
    let disproved = list_disproved_intents(db, project_id, 12)?;
    let fstats = frontier_stats(db, project_id)?;
    let verified_shell = nodes.iter().any(|n| node_is_landed_shell(&row_str(n, "type"), &row_str(n, "key"), &row_tags(n, "tags"), row_bool(n, "is_rce")));
    let node_vals: Vec<Value> = nodes.iter().map(|n| json_obj(n.clone())).collect();
    let edge_vals: Vec<Value> = edges.iter().map(|e| json_obj(e.clone())).collect();
    let lat = lateral_state(&node_vals, &edge_vals);
    let mut stats = json!({
        "nodes": nodes.len(),
        "services": nodes.iter().filter(|n| row_str(n, "type") == "service").count(),
        "edges": edges.len(),
        "findings": findings.len(),
        "high": listed.iter().filter(|f| row_str(f, "severity").eq_ignore_ascii_case("high")).count(),
        "medium": findings.iter().filter(|f| row_str(f, "severity").eq_ignore_ascii_case("medium")).count(),
        "low": findings.iter().filter(|f| { let s = row_str(f, "severity").to_ascii_lowercase(); s == "low" || s == "info" }).count(),
        "critical": listed.iter().filter(|f| row_str(f, "severity").eq_ignore_ascii_case("critical")).count(),
        "has_shell": verified_shell,
        "frontier_open": fstats.get("open").cloned().unwrap_or(Value::from(0)),
        "frontier_strategies": fstats.get("strategies").cloned().unwrap_or(Value::from(0)),
    });
    if let (Some(stats_obj), Some(lat_obj)) = (stats.as_object_mut(), lat.as_object()) {
        for (k, v) in lat_obj { stats_obj.insert(k.clone(), v.clone()); }
    }
    let out = json!({
        "nodes": nodes.iter().map(serialize_node).collect::<Vec<_>>(),
        "edges": edges.iter().map(serialize_edge).collect::<Vec<_>>(),
        "findings": findings.iter().map(serialize_finding).collect::<Vec<_>>(),
        "finding_node_keys": finding_node_keys.into_iter().collect::<Vec<_>>(),
        "intents": intents,
        "disproved": disproved,
        "frontier": fstats,
        "rce_path": path,
        "stats": stats,
    });
    if heal { invalidate_graph_cache(Some(project_id)); }
    else { lock().graph_cache.insert(project_id.to_string(), (Instant::now(), out.clone())); }
    Ok(out)
}

pub fn list_library_findings(db: &Db, q: &str, project: &str, category: &str, severity: &str, track: &str, page: i64, page_size: i64) -> Result<Value, String> {
    let qn_s = q.trim().to_ascii_lowercase();
    let pn = project.trim().to_ascii_lowercase();
    let cat = category.trim().to_ascii_lowercase();
    let sev = severity.trim().to_ascii_lowercase();
    let mut tn = track.trim().to_ascii_lowercase();
    if !["redteam", "ctf", "src", "agent"].contains(&tn.as_str()) { tn.clear(); }
    let page = page.max(1);
    let page_size = page_size.clamp(1, 100);
    let cat_rows = qn(db, "SELECT DISTINCT category FROM findings WHERE IFNULL(verification_status, 'verified') != 'rejected' AND category IS NOT NULL AND TRIM(category) != '' ORDER BY category", &[])?;
    let categories: Vec<String> = cat_rows.iter().map(|r| row_str(r, "category")).filter(|s| !s.is_empty()).collect();
    let mut sql = String::from("SELECT f.*, p.name AS project_name, p.target AS project_target, p.kind AS project_kind, p.config AS project_config, p.parent_id AS project_parent_id, parent.name AS parent_name, parent.kind AS parent_kind FROM findings f JOIN projects p ON p.id = f.project_id LEFT JOIN projects parent ON parent.id = p.parent_id WHERE IFNULL(f.verification_status, 'verified') != 'rejected'");
    let mut owned: Vec<String> = Vec::new();
    if !qn_s.is_empty() { sql.push_str(" AND (LOWER(IFNULL(f.title,'')) LIKE ?1 OR LOWER(f.id) LIKE ?2)"); owned.push(format!("%{qn_s}%")); owned.push(format!("%{qn_s}%")); }
    if !pn.is_empty() {
        let base = owned.len();
        sql.push_str(&format!(" AND (LOWER(IFNULL(p.name,'')) LIKE ?{} OR LOWER(IFNULL(p.target,'')) LIKE ?{} OR LOWER(IFNULL(parent.name,'')) LIKE ?{} OR LOWER(IFNULL(parent.target,'')) LIKE ?{})", base + 1, base + 2, base + 3, base + 4));
        for _ in 0..4 { owned.push(format!("%{pn}%")); }
    }
    if !cat.is_empty() { sql.push_str(&format!(" AND LOWER(IFNULL(f.category,'')) = ?{}", owned.len() + 1)); owned.push(cat.clone()); }
    sql.push_str(" ORDER BY f.created_at DESC");
    let params: Vec<&dyn ToSql> = owned.iter().map(|s| s as &dyn ToSql).collect();
    let rows = db.query(&sql, &params)?;
    let mut matched = Vec::new();
    let mut track_counts = json!({"all": 0, "agent": 0, "redteam": 0, "ctf": 0, "src": 0});
    for row in rows {
        if !is_visible_finding(&row) { continue; }
        let disp = display_finding_severity(&row);
        if !sev.is_empty() && disp != sev { continue; }
        let cfg = loads(&row.get("project_config").cloned().unwrap_or(Value::Null));
        let ptr = project_track(Some(&row_str(&row, "project_kind")), &cfg);
        let mut item = serialize_finding(&row);
        if let Some(obj) = item.as_object_mut() {
            obj.insert("project_id".into(), Value::from(row_str(&row, "project_id")));
            obj.insert("project_name".into(), Value::from(row_str(&row, "project_name")));
            obj.insert("project_target".into(), Value::from(row_str(&row, "project_target")));
            obj.insert("project_kind".into(), Value::from(row_str(&row, "project_kind")));
            obj.insert("project_track".into(), Value::from(ptr.clone()));
            obj.insert("parent_id".into(), Value::from(row_str(&row, "project_parent_id")));
            obj.insert("parent_name".into(), Value::from(row_str(&row, "parent_name")));
            obj.insert("parent_kind".into(), Value::from(row_str(&row, "parent_kind")));
            obj.insert("severity".into(), Value::from(disp));
            obj.insert("review_secondary".into(), Value::Null);
            obj.insert("review_rating".into(), Value::Null);
            obj.insert("reviewing_secondary".into(), Value::from(false));
            obj.insert("reviewing_rating".into(), Value::from(false));
        }
        if let Some(obj) = track_counts.as_object_mut() {
            let all = obj.get("all").and_then(Value::as_i64).unwrap_or(0) + 1;
            obj.insert("all".into(), Value::from(all));
            if ptr == "agent" || ptr == "redteam" || ptr == "src" {
                let n = obj.get("agent").and_then(Value::as_i64).unwrap_or(0) + 1;
                obj.insert("agent".into(), Value::from(n));
            } else if obj.get(&ptr).is_some() {
                let n = obj.get(&ptr).and_then(Value::as_i64).unwrap_or(0) + 1;
                obj.insert(ptr.clone(), Value::from(n));
            }
        }
        matched.push(item);
    }
    let filtered: Vec<Value> = if ["agent", "redteam", "src"].contains(&tn.as_str()) {
        matched.into_iter().filter(|x| ["agent", "redteam", "src"].contains(&x.get("project_track").and_then(Value::as_str).unwrap_or(""))).collect()
    } else { matched.into_iter().filter(|x| tn.is_empty() || x.get("project_track").and_then(Value::as_str) == Some(tn.as_str())).collect() };
    let mut counts = json!({"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0});
    for item in &filtered {
        if let Some(obj) = counts.as_object_mut() {
            let total = obj.get("total").and_then(Value::as_i64).unwrap_or(0) + 1;
            obj.insert("total".into(), Value::from(total));
            let disp = item.get("severity").and_then(Value::as_str).unwrap_or("");
            if obj.get(disp).is_some() {
                let n = obj.get(disp).and_then(Value::as_i64).unwrap_or(0) + 1;
                obj.insert(disp.to_string(), Value::from(n));
            }
        }
    }
    let mut rows_for_sort = Vec::new();
    for item in &filtered {
        let mut m = Map::new();
        if let Some(obj) = item.as_object() { m = obj.clone(); }
        rows_for_sort.push(m);
    }
    let order = sort_findings_by_severity(rows_for_sort);
    let ids: Vec<String> = order.iter().map(|r| row_str(r, "id")).collect();
    let mut ordered = Vec::new();
    for id in ids {
        if let Some(item) = filtered.iter().find(|x| x.get("id").and_then(Value::as_str) == Some(id.as_str())) { ordered.push(item.clone()); }
    }
    let total = ordered.len();
    let start = ((page - 1) * page_size).max(0) as usize;
    let items: Vec<Value> = ordered.into_iter().skip(start).take(page_size as usize).collect();
    Ok(json!({"items": items, "total": total, "page": page, "page_size": page_size, "counts": counts, "track_counts": track_counts, "categories": categories}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn roundup_spec_examples() {
        assert_eq!(roundup("4.02"), "4.1");
        assert_eq!(roundup("4.00"), "4.0");
    }

    #[test]
    fn spec_vector_is_3_8() {
        let got = base_score(&parse_vector("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N").unwrap());
        assert_eq!(got.score, 3.8);
        assert_eq!(got.rating, "low");
        assert_eq!(got.band_zh, "低危");
        assert_eq!(got.vector, "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N");
    }

    #[test]
    fn full_impact_network_is_9_8() {
        let got = base_score(&metrics(&[("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "N"), ("S", "U"), ("C", "H"), ("I", "H"), ("A", "H")]));
        assert_eq!(got.score, 9.8);
        assert_eq!(got.rating, "critical");
    }

    #[test]
    fn reflected_xss_shape_is_6_1() {
        let got = base_score(&metrics(&[("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "R"), ("S", "C"), ("C", "L"), ("I", "L"), ("A", "N")]));
        assert_eq!(got.score, 6.1);
        assert_eq!(got.rating, "medium");
    }

    #[test]
    fn nvd_does_not_score_zero_impact() {
        let m = metrics(&[("AV", "N"), ("AC", "L"), ("PR", "N"), ("UI", "N"), ("S", "C"), ("C", "N"), ("I", "N"), ("A", "N")]);
        assert_eq!(base_score(&m).score, 0.0);
        assert!(nvd_reject_reason(&m).is_some());
        let mut ok = m.clone();
        ok.insert("C".into(), "L".into());
        assert!(nvd_reject_reason(&ok).is_none());
    }

    #[test]
    fn bands() {
        assert_eq!(qualitative_score("0.0"), "info");
        assert_eq!(qualitative_score("0.1"), "low");
        assert_eq!(qualitative_score("3.9"), "low");
        assert_eq!(qualitative_score("4.0"), "medium");
        assert_eq!(qualitative_score("6.9"), "medium");
        assert_eq!(qualitative_score("7.0"), "high");
        assert_eq!(qualitative_score("8.9"), "high");
        assert_eq!(qualitative_score("9.0"), "critical");
        assert_eq!(qualitative_score("10.0"), "critical");
    }

    #[test]
    fn metrics_args() {
        let mut none = Map::new();
        none.insert("severity".into(), Value::from("high"));
        let (m, tried) = metrics_from_args(&none);
        assert!(m.is_none() && !tried);
        let mut rating = Map::new();
        rating.insert("redteam_rating".into(), Value::from("high"));
        let (m, tried) = metrics_from_args(&rating);
        assert!(m.is_none() && tried);
        let mut vecm = Map::new();
        vecm.insert("cvss_vector".into(), Value::from("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
        let (m, tried) = metrics_from_args(&vecm);
        assert!(tried);
        assert_eq!(base_score(&m.unwrap()).score, 9.8);
    }

    #[test]
    fn scope_written_host_and_cidr() {
        let scope = Scope { targets: vec!["app.example.com".into()], ips: vec!["203.0.113.10".into()], cidrs: vec![], allow_subdomains: false };
        assert!(unauthorized_public_host("app.example.com", &scope).is_none());
        assert!(unauthorized_public_host("example.com", &scope).is_some());
        assert!(unauthorized_public_host("www.app.example.com", &scope).is_some());
        assert!(!scope.identity_hosts().contains("www.app.example.com"));
        assert!(scope.host_in_scope("203.0.113.10"));
        assert!(!scope.host_in_scope("203.0.113.11"));
        let cidr = Scope { targets: vec!["app.example.com".into()], ips: vec![], cidrs: vec!["203.0.113.0/24".into()], allow_subdomains: false };
        assert!(cidr.host_in_scope("203.0.113.11"));
    }

    #[test]
    fn hard_stop_tracks() {
        assert!(!hard_stop_exempt(Some("src"), 0, 1, 0, Some(2)));
        assert!(hard_stop_exempt(Some("agent"), 0, 1, 0, Some(0)));
        assert!(!hard_stop_exempt(Some("redteam"), 0, 0, 0, Some(3)));
        assert!(!hard_stop_exempt(Some("getshell"), 0, 0, 0, Some(0)));
    }

    #[test]
    fn promote_rules_and_asset_key() {
        assert!(!should_promote_intranet_host("10.0.1.8", &["pivot".into()], "1.2.3.4"));
        assert!(!should_promote_intranet_host("10.12.0.9", &["internal".into()], "example.com"));
        assert!(should_promote_intranet_host("10.0.1.8", &["ssrf".into(), "pivot".into()], "1.2.3.4"));
        assert!(should_promote_intranet_host("10.12.0.9", &["via-live".into()], "example.com"));
        assert!(should_promote_intranet_host("10.1.1.1", &["getshell".into()], "example.com"));
        assert!(!should_promote_intranet_host("10.0.1.8", &["entry".into()], "1.2.3.4"));
        assert!(!should_promote_intranet_host("10.0.1.8", &["vhost".into()], "1.2.3.4"));
        assert!(!should_promote_intranet_host("10.0.1.8", &["same-machine".into()], "1.2.3.4"));
        assert!(!should_promote_intranet_host("10.0.1.8", &["clue-only".into()], "1.2.3.4"));
        assert!(!should_promote_intranet_host("1.2.3.4", &["pivot".into()], "1.2.3.4"));
        assert_eq!(host_from_asset_key("target:10.0.1.8"), "10.0.1.8");
        assert_eq!(host_from_asset_key("info:host:10.0.1.8"), "10.0.1.8");
        assert_eq!(host_from_asset_key("info:scope-expanded:10.0.1.8"), "10.0.1.8");
    }

    fn temp_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("atk-graph-{}.db", new_id("t")));
        let db = Db::open(&path).unwrap();
        (db, path)
    }

    fn seed_project(db: &Db, id: &str, target: &str) {
        let ts = now();
        db.execute("INSERT INTO projects(id, name, kind, target, status, created_at, updated_at, config) VALUES (?1,?2,'single',?3,'idle',?4,?4,?5)", &[&id as &dyn ToSql, &"t", &target, &ts, &"{\"objective\":\"redteam\",\"track\":\"redteam\"}"]).unwrap();
    }

    #[test]
    fn coerce_intranet_shapes() {
        let (db, path) = temp_db();
        seed_project(&db, "p_coerce", "203.0.113.10");
        let out = coerce_intranet_target_node(&db, "p_coerce", NodeIn { key: "info:scope-expanded:10.0.1.8".into(), node_type: "info".into(), title: "内网资产 10.0.1.8 加入 Scope".into(), detail: None, severity: "info".into(), is_rce: false, tags: vec!["pivot".into(), "internal".into(), "host:10.0.1.8".into(), "ssrf".into()], status: "open".into() }).unwrap();
        assert_eq!(out.node_type, "target");
        assert_eq!(out.key, "target:10.0.1.8");
        assert!(out.tags.iter().any(|t| t == "pivot"));
        let entry = coerce_intranet_target_node(&db, "p_coerce", NodeIn { key: "target:203.0.113.10".into(), node_type: "target".into(), title: "本题入口".into(), detail: None, severity: "info".into(), is_rce: false, tags: vec!["entry".into(), "host:203.0.113.10".into()], status: "open".into() }).unwrap();
        assert_eq!(entry.key, "target:203.0.113.10");
        assert!(entry.tags.iter().any(|t| t == "entry"));
        let vhost = coerce_intranet_target_node(&db, "p_coerce", NodeIn { key: "info:vhost:app.internal".into(), node_type: "info".into(), title: "同机 vhost".into(), detail: None, severity: "info".into(), is_rce: false, tags: vec!["vhost".into(), "same-machine".into(), "host:app.internal".into()], status: "open".into() }).unwrap();
        assert_eq!(vhost.node_type, "info");
        assert!(vhost.key.starts_with("info:"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn ssrf_gateway_and_via() {
        let graph = json!({"nodes": [{"key": "target:10.0.1.8", "type": "target", "title": "内网目标 10.0.1.8", "detail": "通过 ssrf_direct 触发扩容", "tags": ["pivot", "ssrf", "scope-expanded", "host:10.0.1.8"]}], "edges": [{"from": "vuln:ssrf-profile", "to": "target:10.0.1.8", "relation": "LEADS_TO", "rationale": "pivot_capability ssrf_direct: login page"}]});
        assert!(ssrf_gateway_hosts(&graph).contains("10.0.1.8"));
        let entry = json!({"nodes": [{"key": "target:hjkgaming.com", "type": "target", "title": "入口", "tags": ["entry", "host:hjkgaming.com"]}], "edges": []});
        assert!(!ssrf_gateway_hosts(&entry).contains("hjkgaming.com"));
        let via = json!({"nodes": [{"key": "target:hjkgaming.com", "type": "target", "tags": ["entry"]}, {"key": "target:10.0.1.8", "type": "target", "tags": ["pivot", "internal", "scope-expanded", "host:10.0.1.8"]}]});
        let hosts = via_capability_hosts(&via, None);
        assert!(hosts.iter().any(|h| h == "10.0.1.8"));
        assert!(!hosts.iter().any(|h| h == "hjkgaming.com"));
        let canary = json!({"nodes": [{"key": "target:169.254.169.254", "type": "target", "tags": ["pivot", "ssrf", "scope-expanded"]}]});
        let stale = Scope { targets: vec!["app.example".into()], ips: vec!["169.254.169.254".into(), "10.0.1.8".into()], cidrs: vec![], allow_subdomains: false };
        assert!(!via_capability_hosts(&canary, Some(&stale)).iter().any(|h| h == "169.254.169.254"));
        let rfc = json!({"nodes": [{"key": "target:10.0.0.1", "type": "target", "tags": ["pivot", "internal", "scope-expanded", "host:10.0.0.1"]}]});
        assert!(via_capability_hosts(&rfc, None).iter().any(|h| h == "10.0.0.1"));
    }

    #[test]
    fn pivot_target_fingerprint() {
        let node = json!({"key": "target:10.0.1.8", "type": "target", "title": "内网目标 10.0.1.8", "tags": ["pivot", "internal", "scope-expanded", "via-live", "host:10.0.1.8"], "detail": "通过 ssrf_direct 触发扩容"});
        for (obj, flag) in [("src", false), ("redteam", false), ("ctf", true), ("flag", true)] {
            let hyps = hypotheses_for_node(&node, flag, Some(obj), "", None);
            assert!(hyps.iter().any(|h| h.strategy_key.ends_with("::fingerprint")), "{obj}");
        }
        for host in ["169.254.169.254", "203.0.113.9", "198.51.100.5"] {
            let node = json!({"key": format!("target:{host}"), "type": "target", "title": format!("内网目标 {host}"), "tags": ["pivot", "ssrf", "scope-expanded", format!("host:{host}")]});
            for obj in ["src", "redteam", "ctf"] {
                let hyps = hypotheses_for_node(&node, obj == "ctf", Some(obj), "", None);
                assert!(!hyps.iter().any(|h| h.strategy_key.ends_with("::fingerprint")), "{obj} {host}");
            }
        }
        let probe = json!({"key": "target:10.0.0.1", "type": "target", "title": "内网目标 10.0.0.1", "tags": ["pivot", "internal", "scope-expanded", "host:10.0.0.1"]});
        assert!(hypotheses_for_node(&probe, false, Some("src"), "", None).iter().any(|h| h.strategy_key.ends_with("::fingerprint")));
    }

    #[test]
    fn pending_finding_cannot_stay_high() {
        let (db, path) = temp_db();
        seed_project(&db, "p_find", "app.example.com");
        let row = add_finding(&db, "p_find", FindingIn { severity: "high".into(), category: "info".into(), title: "版本对应 nginx".into(), evidence: Some("nginx 1.18 版本对应".into()), redteam_rating: Some("high".into()), cvss: Some(9.8), ..FindingIn::blank() }, None).unwrap();
        assert_eq!(row.get("verification_status").and_then(Value::as_str), Some("pending"));
        assert!(!matches!(row.get("severity").and_then(Value::as_str), Some("high") | Some("critical")));
        assert!(!matches!(row.get("redteam_rating").and_then(Value::as_str), Some("high") | Some("critical")));
        assert!(row.get("cvss").map(|v| v.is_null()).unwrap_or(true));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dependency_not_dispatched() {
        let (db, path) = temp_db();
        seed_project(&db, "p_dep", "app.example.com");
        let ts = now();
        db.execute("INSERT INTO intents(id, project_id, description, est_success, status, priority, attempt_count, created_at, from_keys) VALUES (?1,?2,?3,0.5,'open',0.5,0,?4,'[]')", &[&"i_pre" as &dyn ToSql, &"p_dep", &"先看入口", &ts]).unwrap();
        add_intent(&db, "p_dep", &IntentIn { description: "再打注入".into(), depends_on: vec!["i_pre".into()], ..IntentIn { from_keys: vec![], description: String::new(), rationale: None, est_success: 0.5, strategy_key: None, evidence_fingerprint: None, priority: None, status: "open".into(), depends_on: vec![] } }, None).unwrap();
        let open = list_open_intents(&db, "p_dep", 20).unwrap();
        let descs: Vec<String> = open.iter().map(|r| r.get("description").and_then(Value::as_str).unwrap_or("").to_string()).collect();
        assert!(descs.iter().any(|d| d == "先看入口"));
        assert!(!descs.iter().any(|d| d == "再打注入"));
        let _ = std::fs::remove_file(path);
    }
}
