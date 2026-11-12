//! 报告：HTML / PDF / Markdown，以及单条漏洞页。行为对齐 `backend/atkbrain/report`。
//! 模型没有内置运行时；未挂上钩子时按撰写失败回退，不发起网络请求。
//! 未采集到的 PoC 只保留「禁止合成」说明，不生成利用请求。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::config::Settings;
use crate::db::{new_id, now, Db};
use crate::i18n::{self, lab, msg};

pub type Obj = Map<String, Value>;

pub const THEME_REV: &str = "2026.09.02.1";
pub const PROMPT_REV: &str = "2026.09.02.1";
pub const EXPORT_ROLE: &str = "report-export";
pub const SHELL_NAME: &str = "deliverable_shell.html";
pub const PAGE_KEYS: [&str; 5] = [
    "report_summary",
    "report_impact",
    "report_rating",
    "report_repro",
    "report_fix",
];
const JSON_PAGE_KEYS: [&str; 10] = [
    "summary",
    "impact",
    "rating",
    "repro",
    "fix",
    "report_summary",
    "report_impact",
    "report_rating",
    "report_repro",
    "report_fix",
];

pub const PENDING_COPY: &str = "专职复核 Pi 完成二次验证与红队评级后撰写本段，不使用模板套话。";
pub const WRITING_COPY: &str = "专职 Pi 正在撰写漏洞页…";
pub const FAILED_COPY: &str = "漏洞页这次没有写完。可重新撰写；未写完前不套用模板。";

const RESTART_MARK: &str = "后端重启";
const BUILTIN_MODEL: &str = "deepseek-flash";

pub const PI_PAGE_SYSTEM: &str = r#"你是 StrikeAgent_AtkBrain-Flash 的漏洞页撰稿人，只服务已经二次验证过的这一条洞。

你不是猎洞工人，也不套类别模板。五个板块都必须根据事实包里「这一次打到了什么」来写，写给安全工程师看。

硬约束
- 不得编造事实包没有的 Host、URL、路径、参数、账号、flag、命令输出或状态码。
- 「危害」只写对本项目/本资产已经被证据证明的影响；没打到的后续标「尚未证明」，不要写成已打穿。
- 事实包若标明二次验证失败：五个板块仍按首次证据写完整，不要写成二次已经复现，也不要写成这类漏洞不存在。失败原因由复核理由单独展示，不要拿占位句代替正文。
- 「手动复现」写复核员实际走过的步骤（跳板、工具、命令、成功判定），不要写 Burp Repeater 十二步套话，不要把复现步骤改写成机密性/完整性/可用性三段论。
- 「修复方式」针对本条根因（例如弱口令、未授权接口、拼接 SQL），不要泛泛的「使用参数化查询」。
- 禁止把邻题 IP、本机网段、平台控制台写进正文。

只输出 JSON：
{
  "summary": "漏洞简介（120～280 字：什么入口、怎么触发、验证看到了什么）",
  "impact": "对本项目的危害（120～280 字：影响到哪台主机/哪种数据/是否已证明命令执行或数据接管）",
  "rating": "NVD CVSS 3.1（先写 CVSS:3.1 向量和基础分，再写 NVD 定性：低危/中危/高危/严重，以及八项为什么这样打）",
  "repro": "手动复现（分条，至少 4 步，含成功判定；可附真实 curl/命令，不新增 payload）",
  "fix": "修复方式（针对本条：立即缓解 + 根治，具体到账号/接口/配置）"
}
"#;

pub const WRITEUP_SYSTEM: &str = r#"你是给安全工程师看的授权渗透测试报告撰写人。只写短文，不要套话、不要 CIA 模板。

硬约束
- 不得编造事实包里没有的 URL、路径、参数名、payload、响应原文或状态码。
- 危害只写证据已经证明的影响；没打到的后续标「潜在」，不要写成已打穿。

每个漏洞输出一个 JSON 对象：
{
  "id": "与事实包 id 一致",
  "impact_detail": "危害（80～200 字：未授权能做什么、影响谁）",
  "reproduction_notes": ["最多 8 条操作提示，不新增 payload"]
}
"#;

pub const EXPORT_SYSTEM: &str = r#"你是 StrikeAgent_AtkBrain-Flash 的专职交付报告撰稿 Pi（role=report-export）。
不是猎洞工人，不是漏洞二次验证员，不是自进化蒸馏员。只把已经确认的事实写成交付报告槽位。
提示词版本 2026.09.02.1。母版已固定：封面 tag/h1/meta、执行摘要 sum-grid、8 张 KPI、条形图+验证环、path-board（pn/parrow）、资产卡片、清单表、vf 卡片（①简介/技术成因 ②利用方式 ③修复 now/root）。你只填文字，不输出完整 HTML，不写 <style>，不改版式。

只输出 JSON：
{
  "title_line": "封面主标题（机构或项目名）",
  "title_accent": "域名或目标，可空",
  "sub": "封面一两句概述，可点出入口与是否已拿权限",
  "goal_text": "若已拿权限则写「权限已获取」，否则空字符串",
  "goal_detail": "权限落地的一句话补充，可空",
  "summary_overview": "执行摘要左侧 HTML（p/ul/li/b/code/span），写清攻击链，不要产品名",
  "summary_conclusions": "执行摘要右侧 HTML，优先 <ul class=\"concl\"><li><span class=\"tag-sev crit|high|med\">等级</span><span>结论</span></li></ul>",
  "verify_note": "验证说明纯文本",
  "path_note": "攻击路径说明一句（会同时用作路径区导语与 caption）",
  "findings": {
    "vuln-01": {
      "intro": "①简介 / 技术成因（可多段，用换行分段）",
      "impact": "危害影响（会接在简介后）",
      "steps": ["②利用方式 逐步操作"],
      "prerequisites": "前置条件一句",
      "fixes_now": ["立即缓解"],
      "fixes_root": ["根治"],
      "fixes": ["若未分 now/root，可仍用此列表"],
      "verify": "修复验证一句话"
    }
  }
}

硬约束
- 只使用事实包。没有的写「未采集」。禁止编造 URL / payload / CVE。
- 每条漏洞优先改写事实包里的 report_summary / report_impact / report_rating / report_repro / report_fix（专职复核 Pi 已写的五段），不要另编一套；没有这五段才根据 evidence 写，并在 intro 标明尚未二次验证。
- 禁止出现内部引擎字段、时间线、附录、产品内部名称。
- 严重/高危必须写透简介、利用、修复。
- findings 的键用事实包里的 slot_id（vuln-01 …）。
"#;

const SHELL_FALLBACK: &str =
    include_str!("../../../backend/atkbrain/report/templates/deliverable_shell.html");

#[derive(Debug, Clone)]
pub struct ProjectReportMdGone {
    pub message: String,
}

impl std::fmt::Display for ProjectReportMdGone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProjectReportMdGone {}

#[derive(Debug)]
pub enum ReportError {
    Gone(ProjectReportMdGone),
    Message(String),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Gone(e) => e.fmt(f),
            ReportError::Message(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for ReportError {}

impl From<String> for ReportError {
    fn from(value: String) -> Self {
        ReportError::Message(value)
    }
}

#[derive(Clone, Debug)]
pub struct QueryText {
    pub system_prompt: String,
    pub user_prompt: String,
    pub cwd: String,
    pub timeout: f64,
    pub tools: bool,
    pub model: String,
    pub role: String,
    pub project_id: String,
}

pub type QueryTextFn = fn(&QueryText) -> Result<String, String>;

struct ReviewFlags {
    secondary_verify: bool,
    #[allow(dead_code)]
    redteam_rating: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn re(pat: &str) -> Regex {
    Regex::new(pat).unwrap_or_else(|e| panic!("regex {pat}: {e}"))
}

fn clip(text: &str, limit: usize) -> String {
    let s = text.trim();
    if s.is_empty() {
        return String::new();
    }
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let head: String = s.chars().take(limit).collect();
    format!("{}…", head.trim_end())
}

fn take_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if n.as_f64().is_some_and(|f| f == i as f64) {
                    return i.to_string();
                }
            }
            n.as_f64()
                .map(|f| {
                    if f.fract() == 0.0 && f.abs() < 1e15 {
                        format!("{f:.1}")
                    } else {
                        format!("{f}")
                    }
                })
                .unwrap_or_else(|| n.to_string())
        }
        other => other.to_string(),
    }
}

fn truth(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64().unwrap_or(0) != 0 || n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn g(m: &Obj, k: &str) -> Value {
    m.get(k).cloned().unwrap_or(Value::Null)
}

fn gstr(m: &Obj, k: &str) -> String {
    m.get(k).map(as_text).unwrap_or_default()
}

fn gbool(m: &Obj, k: &str) -> bool {
    m.get(k).is_some_and(truth)
}

fn gint(m: &Obj, k: &str) -> i64 {
    match m.get(k) {
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        Some(Value::Bool(b)) => {
            if *b {
                1
            } else {
                0
            }
        }
        _ => 0,
    }
}

fn gfloat(m: &Obj, k: &str) -> f64 {
    match m.get(k) {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn objects_of(v: &Value) -> Vec<Obj> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_object().cloned()).collect())
        .unwrap_or_default()
}

fn obj_list<'a>(m: &'a Obj, k: &str) -> Vec<&'a Obj> {
    m.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn put(m: &mut Obj, k: &str, v: impl serde::Serialize) {
    m.insert(
        k.to_string(),
        serde_json::to_value(v).unwrap_or(Value::Null),
    );
}

fn loads(v: &Value) -> Value {
    match v {
        Value::Null => Value::Null,
        Value::String(s) if s.is_empty() => Value::Null,
        Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
        other => other.clone(),
    }
}

fn esc(s: impl AsRef<str>, quote: bool) -> String {
    let mut out = String::new();
    for ch in s.as_ref().chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quote => out.push_str("&quot;"),
            '\'' if quote => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn canon_json(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(true) => "true".into(),
        Value::Bool(false) => "false".into(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        Value::Array(a) => {
            let parts: Vec<_> = a.iter().map(canon_json).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(m) => {
            let mut keys: Vec<_> = m.keys().cloned().collect();
            keys.sort();
            let parts: Vec<_> = keys
                .iter()
                .map(|k| {
                    let key = serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into());
                    format!("{key}: {}", canon_json(&m[k]))
                })
                .collect();
            format!("{{{}}}", parts.join(", "))
        }
    }
}

fn json_prefix(input: &str) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_str(input);
    serde::Deserialize::deserialize(&mut de).ok()
}

fn json_objects(raw: &str) -> Vec<Value> {
    let bytes = raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let mut depth = 0i32;
        let mut in_str = false;
        let mut esc_ch = false;
        let mut end = None;
        let mut j = i;
        while j < bytes.len() {
            let ch = bytes[j];
            if in_str {
                if esc_ch {
                    esc_ch = false;
                } else if ch == b'\\' {
                    esc_ch = true;
                } else if ch == b'"' {
                    in_str = false;
                }
                j += 1;
                continue;
            }
            match ch {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let Some(end) = end else { break };
        let blob = &raw[i..=end];
        let loosened = {
            static RE: LazyLock<Regex> = LazyLock::new(|| re(r",\s*([}\]])"));
            RE.replace_all(blob, "$1").into_owned()
        };
        for candidate in [blob, loosened.as_str()] {
            if let Ok(Value::Object(_)) = serde_json::from_str::<Value>(candidate) {
                if let Ok(v) = serde_json::from_str::<Value>(candidate) {
                    out.push(v);
                    break;
                }
            }
        }
        i = end + 1;
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_qsl(input: &str) -> Vec<(String, String)> {
    if input.is_empty() {
        return Vec::new();
    }
    input
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

fn quote_component(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn file_uri(path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = String::from("file://");
    for b in abs.to_string_lossy().as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(unix)]
fn generated_now() -> String {
    #[repr(C)]
    struct LibcTm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const i8,
    }
    extern "C" {
        fn time(tloc: *mut i64) -> i64;
        fn localtime_r(t: *const i64, out: *mut LibcTm) -> *mut LibcTm;
    }
    unsafe {
        let mut secs = 0i64;
        if time(&mut secs) < 0 {
            return String::new();
        }
        let mut tm = std::mem::zeroed::<LibcTm>();
        if localtime_r(&secs, &mut tm).is_null() {
            return String::new();
        }
        let _ = (
            tm.tm_wday,
            tm.tm_yday,
            tm.tm_isdst,
            tm.tm_gmtoff,
            tm.tm_zone,
        );
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

#[cfg(not(unix))]
fn generated_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

fn shell_path() -> PathBuf {
    crate::config::repo_root()
        .join("backend")
        .join("atkbrain")
        .join("report")
        .join("templates")
        .join(SHELL_NAME)
}

pub fn load_shell() -> String {
    std::fs::read_to_string(shell_path()).unwrap_or_else(|_| SHELL_FALLBACK.to_string())
}

fn review_flags(settings: &Settings) -> ReviewFlags {
    let path = settings.data_dir.join("proxy-settings.json");
    let data = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    ReviewFlags {
        secondary_verify: as_bool(data.get("finding_secondary_verify"), true),
        redteam_rating: as_bool(data.get("finding_redteam_rating"), true),
    }
}

fn secondary_on(settings: Option<&Settings>) -> bool {
    settings
        .map(|s| review_flags(s).secondary_verify)
        .unwrap_or(true)
}

fn as_bool(v: Option<&Value>, default: bool) -> bool {
    let Some(v) = v else { return default };
    match v {
        Value::Null => default,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64().unwrap_or(0) != 0 || n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            "" => default,
            _ => default,
        },
        _ => default,
    }
}

fn sev_rank(s: &str) -> i64 {
    match s {
        "info" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        "critical" => 4,
        _ => 0,
    }
}

fn severity_floor(category: &str) -> Option<&'static str> {
    Some(match category {
        "rce" | "command_injection" | "deserialization" => "critical",
        "file_write"
        | "file_upload"
        | "arbitrary_file_read"
        | "file_read"
        | "lfi"
        | "sqli"
        | "db_access"
        | "auth_bypass"
        | "admin_access"
        | "privilege_escalation"
        | "unauth"
        | "authz"
        | "business_logic"
        | "account_takeover"
        | "source_leak"
        | "backup_leak"
        | "hardcoded_secret"
        | "key_leak"
        | "mass_pii"
        | "cloud_credential"
        | "sensitive_data_exposure"
        | "credential_dump"
        | "secrets_leak" => "high",
        "idor" | "ssrf" | "xss" => "medium",
        "info" => "info",
        _ => return None,
    })
}

fn critical_category(category: &str) -> bool {
    matches!(
        category,
        "rce"
            | "command_injection"
            | "deserialization"
            | "file_write"
            | "file_upload"
            | "arbitrary_file_read"
            | "file_read"
            | "lfi"
            | "sqli"
            | "db_access"
            | "auth_bypass"
            | "authz"
            | "unauth"
            | "idor"
            | "admin_access"
            | "privilege_escalation"
            | "ssrf_internal"
    )
}

pub fn normalize_severity(category: Option<&str>, severity: Option<&str>) -> String {
    let mut sev = severity.unwrap_or("").to_string();
    if !matches!(
        sev.as_str(),
        "info" | "low" | "medium" | "high" | "critical"
    ) {
        sev = "info".into();
    }
    if let Some(cat) = category {
        if let Some(floor) = severity_floor(&cat.to_ascii_lowercase()) {
            if sev_rank(floor) > sev_rank(&sev) {
                sev = floor.to_string();
            }
        }
    }
    sev
}

fn rating_alias(raw: &str) -> Option<&'static str> {
    Some(match raw {
        "严重" => "critical",
        "高危" => "high",
        "中危" => "medium",
        "低危" => "low",
        "信息" => "info",
        "crit" | "c" => "critical",
        "h" => "high",
        "m" => "medium",
        "l" => "low",
        _ => return None,
    })
}

pub fn normalize_rating(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let mapped = rating_alias(s).or_else(|| rating_alias(&s.to_ascii_lowercase()));
    let s = mapped.unwrap_or(s).to_ascii_lowercase();
    if matches!(s.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        Some(s)
    } else {
        None
    }
}

fn rating_label(raw: Option<&str>) -> String {
    match normalize_rating(raw.unwrap_or("")).as_deref() {
        Some("critical") => "严重".into(),
        Some("high") => "高危".into(),
        Some("medium") => "中危".into(),
        Some("low") => "低危".into(),
        Some("info") => "信息".into(),
        Some(other) => other.into(),
        None => "未评级".into(),
    }
}

pub fn display_finding_severity(row: &Obj) -> String {
    if let Some(rt) = normalize_rating(&gstr(row, "redteam_rating")) {
        return rt;
    }
    let sev = gstr(row, "severity").trim().to_ascii_lowercase();
    let sev = if sev.is_empty() {
        "info".to_string()
    } else {
        sev
    };
    if matches!(
        sev.as_str(),
        "info" | "low" | "medium" | "high" | "critical"
    ) {
        sev
    } else {
        "info".into()
    }
}

pub fn is_high_severity(severity: &str, category: &str) -> bool {
    let sev = normalize_severity(Some(category), Some(severity));
    sev_rank(&sev) >= sev_rank("high") || critical_category(&category.to_ascii_lowercase())
}

pub fn normalize_objective(obj: Option<&str>) -> &'static str {
    let o = obj.unwrap_or("").trim().to_ascii_lowercase();
    if o == "flag" || o == "ctf" {
        "flag"
    } else {
        "agent"
    }
}

pub fn objective_is_src(obj: Option<&str>) -> bool {
    normalize_objective(obj) == "agent"
}

fn ctf_needed(flags_needed: Option<i64>, flag_count: Option<i64>) -> i64 {
    for v in [flags_needed, flag_count] {
        if let Some(n) = v {
            if n > 0 {
                return n;
            }
        }
    }
    1
}

pub fn ctf_full_score(
    flags_correct: i64,
    flags_needed: Option<i64>,
    flag_count: Option<i64>,
) -> bool {
    flags_correct >= ctf_needed(flags_needed, flag_count)
}

pub fn is_visible_finding(row: &Obj) -> bool {
    let status = gstr(row, "verification_status");
    let status = status.trim();
    if status.is_empty() {
        return true;
    }
    matches!(
        status.to_ascii_lowercase().as_str(),
        "verified" | "flaky" | "pending" | "excluded"
    )
}

pub fn finding_row_visible(row: &Obj) -> bool {
    let status = gstr(row, "verification_status");
    let status = status.trim();
    let status = if status.is_empty() {
        "verified"
    } else {
        status
    };
    status.to_ascii_lowercase() != "rejected"
}

fn infer_node_type(key: &str) -> Option<&'static str> {
    const PREFIXES: &[(&str, &str)] = &[
        ("target:", "target"),
        ("svc:", "service"),
        ("service:", "service"),
        ("danger:", "danger"),
        ("vuln:", "vuln"),
        ("cred:", "credential"),
        ("credential:", "credential"),
        ("foothold:", "foothold"),
        ("honeypot:", "honeypot"),
        ("goal:", "goal"),
    ];
    let k = key.trim().to_ascii_lowercase();
    if k.is_empty() {
        return None;
    }
    PREFIXES
        .iter()
        .find(|(p, _)| k.starts_with(p))
        .map(|(_, t)| *t)
}

fn humanize_node_key(key: &str) -> String {
    let raw = key.trim();
    if raw.is_empty() || infer_node_type(raw).is_none() {
        return raw.to_string();
    }
    let rest = raw.split_once(':').map(|(_, r)| r.trim()).unwrap_or("");
    if rest.is_empty() {
        raw.to_string()
    } else {
        rest.to_string()
    }
}

fn detail_empty(detail: &Value) -> bool {
    match detail {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

fn tags_of(v: &Value) -> Vec<String> {
    let parsed = if let Value::String(s) = v {
        loads(&Value::String(s.clone()))
    } else {
        v.clone()
    };
    match parsed {
        Value::Array(a) => a.iter().map(as_text).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    }
}

pub fn is_placeholder_node(key: &str, title: Option<&str>, detail: &Value, tags: &Value) -> bool {
    if tags_of(tags)
        .iter()
        .any(|t| t.eq_ignore_ascii_case("placeholder"))
    {
        return true;
    }
    let title = title.unwrap_or("");
    let human = humanize_node_key(key);
    detail_empty(detail) && (title == key || title == human)
}

pub fn node_is_landed_shell(ntype: &str, key: &str, tags: &[String], is_rce: bool) -> bool {
    if ntype != "foothold" && ntype != "goal" {
        return false;
    }
    is_rce
        || tags.iter().any(|t| t.eq_ignore_ascii_case("getshell"))
        || key.starts_with("goal:shell")
        || key.starts_with("foothold:shell")
}

fn scrub_label(text: &str) -> String {
    if !text.contains("候选") {
        return text.to_string();
    }
    static CAND: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?i)[（(]\s*候选\s*RCE\s*[)）]|候选\s*RCE"));
    static SPACES: LazyLock<Regex> = LazyLock::new(|| re(r"\s{2,}"));
    let s = CAND.replace_all(text, "");
    let s = SPACES.replace_all(&s, " ");
    s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '-' | '—' | '·' | '/' | '|'))
        .to_string()
}

pub fn redteam_rating_block(row: &Obj) -> String {
    let rating = normalize_rating(&gstr(row, "redteam_rating"));
    let why = gstr(row, "redteam_rating_rationale").trim().to_string();
    let head = if let Some(rating) = rating.as_deref() {
        if row.get("cvss").is_some_and(|v| !v.is_null()) {
            let shown = match &row["cvss"] {
                Value::Number(n) => n
                    .as_f64()
                    .map(|f| format!("{f:.1}"))
                    .unwrap_or_else(|| n.to_string()),
                other => as_text(other),
            };
            let band = if rating == "info" {
                "无".into()
            } else {
                rating_label(Some(rating))
            };
            format!("NVD CVSS 3.1 基础分：**{shown}**（{band}）")
        } else {
            format!("级别：**{}**（`{rating}`）", rating_label(Some(rating)))
        }
    } else {
        "级别：未评级".into()
    };
    if why.is_empty() {
        format!("{head}\n为什么是这个级：未写理由。")
    } else {
        format!("{head}\n为什么是这个级：{why}")
    }
}

fn sort_findings(findings: &mut [Obj]) {
    findings.sort_by(|a, b| {
        let ra = -sev_rank(&display_finding_severity(a));
        let rb = -sev_rank(&display_finding_severity(b));
        ra.cmp(&rb).then_with(|| {
            gfloat(b, "created_at")
                .partial_cmp(&gfloat(a, "created_at"))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    });
}

fn legacy_model_name(name: &str) -> bool {
    let n = name.trim().to_ascii_lowercase();
    n.is_empty() || n == "sonnet" || n == "haiku" || n == "opus" || n.starts_with("claude")
}

fn env_pi_model(settings: &Settings) -> String {
    let pi = settings.pi_model.trim();
    let claude = settings.claude_model.trim();
    if !pi.is_empty() && pi != BUILTIN_MODEL {
        return pi.to_string();
    }
    if !claude.is_empty() && claude != BUILTIN_MODEL {
        return claude.to_string();
    }
    if !pi.is_empty() {
        return pi.to_string();
    }
    if !claude.is_empty() {
        return claude.to_string();
    }
    BUILTIN_MODEL.into()
}

fn role_model(settings: &Settings, candidates: &[&str]) -> String {
    let chosen = env_pi_model(settings);
    for item in candidates {
        let raw = item.trim();
        if legacy_model_name(raw) {
            continue;
        }
        if raw == BUILTIN_MODEL && !chosen.is_empty() && chosen != BUILTIN_MODEL {
            continue;
        }
        return raw.to_string();
    }
    chosen
}

static QUERY_HOOK: LazyLock<Mutex<Option<QueryTextFn>>> = LazyLock::new(|| Mutex::new(None));

pub fn set_query_text_hook(hook: Option<QueryTextFn>) {
    *lock(&QUERY_HOOK) = hook;
}

fn query_text(req: &QueryText) -> Result<String, String> {
    match *lock(&QUERY_HOOK) {
        Some(f) => f(req),
        None => Err("pi runtime unavailable".into()),
    }
}

fn emit_event(db: &Db, project_id: &str, kind: &str, payload: &Value) {
    if project_id.is_empty() {
        return;
    }
    let body = serde_json::to_string(payload).unwrap_or_else(|_| "{}".into());
    let ts = now();
    let run_id: Option<String> = None;
    let kind = kind.to_string();
    let _ = db.execute(
        "INSERT INTO events(project_id, run_id, ts, type, payload) VALUES(?1,?2,?3,?4,?5)",
        &[&project_id, &run_id, &ts, &kind, &body],
    );
}

fn backfill_track(kind: &str, mut cfg: Obj) -> Obj {
    let track = gstr(&cfg, "track");
    let objective = gstr(&cfg, "objective");
    let explicit = {
        let raw = if !track.trim().is_empty() {
            track
        } else {
            objective.clone()
        };
        raw.trim().to_ascii_lowercase()
    };
    if kind == "benchmark" && explicit.is_empty() {
        put(&mut cfg, "track", "ctf");
        put(&mut cfg, "objective", "flag");
        return cfg;
    }
    let probe = if !explicit.is_empty() {
        explicit
    } else {
        objective
    };
    if normalize_objective(Some(probe.trim())) == "flag" {
        put(&mut cfg, "track", "ctf");
        put(&mut cfg, "objective", "flag");
        return cfg;
    }
    put(&mut cfg, "track", "agent");
    put(&mut cfg, "objective", "agent");
    cfg
}

fn project_from_row(row: &Obj) -> Obj {
    let kind = gstr(row, "kind");
    let cfg = match loads(&g(row, "config")) {
        Value::Object(m) => m,
        _ => Obj::new(),
    };
    let cfg = backfill_track(&kind, cfg);
    let ports = loads(&g(row, "ports"));
    let scope = match loads(&g(row, "scope")) {
        Value::Object(m) => Value::Object(m),
        _ => Value::Object(Obj::new()),
    };
    let mut out = Obj::new();
    put(&mut out, "id", g(row, "id"));
    put(&mut out, "name", g(row, "name"));
    put(&mut out, "kind", kind);
    put(&mut out, "target", g(row, "target"));
    out.insert("ports".into(), ports);
    out.insert("scope".into(), scope);
    out.insert("config".into(), Value::Object(cfg));
    put(&mut out, "status", g(row, "status"));
    put(&mut out, "parent_id", g(row, "parent_id"));
    put(&mut out, "created_at", g(row, "created_at"));
    put(&mut out, "updated_at", g(row, "updated_at"));
    out.insert("hard_stop".into(), Value::Null);
    put(&mut out, "category", g(row, "category"));
    put(&mut out, "archived", gint(row, "archived"));
    put(&mut out, "queued_at", g(row, "queued_at"));
    put(&mut out, "vendor_id", g(row, "vendor_id"));
    out
}

fn get_project(db: &Db, pid: &str) -> Result<Option<Obj>, String> {
    let row = db.query_one("SELECT * FROM projects WHERE id=?1", &[&pid])?;
    Ok(row.as_ref().map(project_from_row))
}

fn serialize_node(row: &Obj) -> Obj {
    let title_raw = gstr(row, "title");
    let title = {
        let scrubbed = scrub_label(&title_raw);
        if scrubbed.is_empty() {
            title_raw
        } else {
            scrubbed
        }
    };
    let mut out = Obj::new();
    put(&mut out, "id", g(row, "id"));
    put(&mut out, "key", g(row, "key"));
    put(&mut out, "type", g(row, "type"));
    put(&mut out, "title", title);
    out.insert("detail".into(), loads(&g(row, "detail")));
    put(&mut out, "severity", g(row, "severity"));
    put(&mut out, "is_rce", gbool(row, "is_rce"));
    put(&mut out, "risk_score", gfloat(row, "risk_score"));
    let tags = loads(&g(row, "tags"));
    out.insert(
        "tags".into(),
        if tags.is_array() {
            tags
        } else {
            Value::Array(Vec::new())
        },
    );
    put(&mut out, "status", g(row, "status"));
    put(&mut out, "created_at", g(row, "created_at"));
    put(&mut out, "updated_at", g(row, "updated_at"));
    put(&mut out, "project_id", g(row, "project_id"));
    out
}

fn serialize_edge(row: &Obj) -> Obj {
    let mut out = Obj::new();
    put(&mut out, "id", g(row, "id"));
    put(&mut out, "from", g(row, "src"));
    put(&mut out, "to", g(row, "dst"));
    put(&mut out, "src", g(row, "src"));
    put(&mut out, "dst", g(row, "dst"));
    put(&mut out, "relation", g(row, "relation"));
    put(&mut out, "weight", gfloat(row, "weight"));
    put(&mut out, "rationale", g(row, "rationale"));
    put(&mut out, "on_rce_path", gbool(row, "on_rce_path"));
    out
}

fn rce_path_from_marks(db: &Db, project_id: &str) -> Result<Obj, String> {
    let edges = db.query(
        "SELECT src, dst, weight FROM edges WHERE project_id=?1 AND on_rce_path=1",
        &[&project_id],
    )?;
    let mut out = Obj::new();
    if edges.is_empty() {
        put(&mut out, "path", Vec::<String>::new());
        put(&mut out, "paths", Vec::<Vec<String>>::new());
        put(&mut out, "likelihood", 0.0);
        put(&mut out, "frontier_mode", false);
        return Ok(out);
    }
    let mut succ: HashMap<String, Vec<(String, f64)>> = HashMap::new();
    let mut indeg: HashMap<String, i64> = HashMap::new();
    let mut order = Vec::new();
    for e in &edges {
        let src = gstr(e, "src");
        let dst = gstr(e, "dst");
        order.push(src.clone());
        succ.entry(src.clone()).or_default().push((dst.clone(), {
            let w = gfloat(e, "weight");
            if w == 0.0 {
                0.5
            } else {
                w
            }
        }));
        *indeg.entry(dst).or_insert(0) += 1;
        indeg.entry(src).or_insert(0);
    }
    let mut starts: Vec<String> = indeg
        .iter()
        .filter(|(_, d)| **d == 0)
        .map(|(k, _)| k.clone())
        .collect();
    if starts.is_empty() {
        starts.push(order.first().cloned().unwrap_or_default());
    }
    let mut paths = Vec::new();
    let mut likes = Vec::new();
    for s in starts {
        if s.is_empty() {
            continue;
        }
        let mut path = vec![s.clone()];
        let mut like = 1.0;
        let mut cur = s.clone();
        let mut seen = HashSet::from([s]);
        while let Some(nexts) = succ.get(&cur) {
            if nexts.is_empty() {
                break;
            }
            let (nxt, w) = nexts[0].clone();
            if !seen.insert(nxt.clone()) {
                break;
            }
            path.push(nxt.clone());
            like *= w.clamp(0.01, 1.0);
            cur = nxt;
        }
        if path.len() >= 2 {
            paths.push(path);
            likes.push(like);
        }
    }
    let best_idx = paths
        .iter()
        .enumerate()
        .max_by(|a, b| {
            a.1.len().cmp(&b.1.len()).then(
                likes[a.0]
                    .partial_cmp(&likes[b.0])
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
        })
        .map(|(i, _)| i);
    let best = best_idx.map(|i| paths[i].clone()).unwrap_or_default();
    let best_like = best_idx.map(|i| likes[i]).unwrap_or(0.0);
    put(&mut out, "path", best.clone());
    put(&mut out, "paths", paths);
    put(
        &mut out,
        "likelihood",
        if best.len() > 1 {
            (best_like * 10000.0).round() / 10000.0
        } else {
            0.0
        },
    );
    put(&mut out, "frontier_mode", false);
    Ok(out)
}

fn finding_family(category: &str) -> String {
    match category.trim().to_ascii_lowercase().as_str() {
        "lfi" | "arbitrary_file_read" | "path_traversal" => "file_read".into(),
        "command_injection" | "file_write" | "file_upload" => "rce".into(),
        other => other.to_string(),
    }
}

fn finding_path_key(title: &str, category: &str) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)/api/[A-Za-z0-9_./-]+"));
    RE.find(&format!("{title} {category}"))
        .map(|m| m.as_str().to_ascii_lowercase())
        .unwrap_or_default()
}

fn listed_finding_rows(rows: &[Obj]) -> Vec<Obj> {
    let mut verified_keys = HashSet::new();
    let mut verified_fam = HashSet::new();
    for row in rows {
        let vs = gstr(row, "verification_status").trim().to_ascii_lowercase();
        if vs.is_empty() || vs == "verified" {
            let key = finding_path_key(&gstr(row, "title"), &gstr(row, "category"));
            if !key.is_empty() {
                verified_keys.insert(key);
            }
            let fam = finding_family(&gstr(row, "category"));
            if !fam.is_empty() {
                verified_fam.insert(fam);
            }
        }
    }
    let mut kept = Vec::new();
    for row in rows {
        let vs_raw = gstr(row, "verification_status").trim().to_ascii_lowercase();
        let vs = if vs_raw.is_empty() {
            "verified"
        } else {
            vs_raw.as_str()
        };
        if vs == "rejected" {
            continue;
        }
        if vs == "pending" {
            let key = finding_path_key(&gstr(row, "title"), &gstr(row, "category"));
            if !key.is_empty() && verified_keys.contains(&key) {
                continue;
            }
            if key.is_empty() && verified_fam.contains(&finding_family(&gstr(row, "category"))) {
                continue;
            }
        }
        kept.push(row.clone());
    }
    sort_findings(&mut kept);
    kept
}

fn load_graph(db: &Db, project_id: &str) -> Result<Obj, String> {
    let node_rows = db.query(
        "SELECT * FROM nodes WHERE project_id=?1 ORDER BY created_at",
        &[&project_id],
    )?;
    let edge_rows = db.query(
        "SELECT * FROM edges WHERE project_id=?1 ORDER BY created_at",
        &[&project_id],
    )?;
    let finding_rows = db.query(
        "SELECT * FROM findings WHERE project_id=?1 ORDER BY created_at DESC",
        &[&project_id],
    )?;
    let nodes: Vec<Obj> = node_rows.iter().map(serialize_node).collect();
    let edges: Vec<Obj> = edge_rows.iter().map(serialize_edge).collect();
    let objective = get_project(db, project_id)
        .ok()
        .flatten()
        .and_then(|p| {
            p.get("config").and_then(Value::as_object).map(|cfg| {
                let o = gstr(cfg, "objective");
                let raw = if o.is_empty() { gstr(cfg, "track") } else { o };
                normalize_objective(Some(&raw)).to_string()
            })
        })
        .unwrap_or_else(|| "agent".into());
    let mut findings = Vec::new();
    for row in &finding_rows {
        let visible = if objective_is_src(Some(objective.as_str())) {
            finding_row_visible(row)
        } else {
            is_visible_finding(row)
        };
        if visible {
            findings.push(row.clone());
        }
    }
    sort_findings(&mut findings);
    let listed = listed_finding_rows(&findings);
    let services = nodes
        .iter()
        .filter(|n| gstr(n, "type") == "service")
        .count();
    let has_shell = nodes.iter().any(|n| {
        node_is_landed_shell(
            &gstr(n, "type"),
            &gstr(n, "key"),
            &tags_of(&g(n, "tags")),
            gbool(n, "is_rce"),
        )
    });
    let mut stats = Obj::new();
    put(&mut stats, "nodes", nodes.len() as i64);
    put(&mut stats, "services", services as i64);
    put(&mut stats, "edges", edges.len() as i64);
    put(&mut stats, "findings", findings.len() as i64);
    put(
        &mut stats,
        "high",
        listed
            .iter()
            .filter(|f| display_finding_severity(f) == "high")
            .count() as i64,
    );
    put(
        &mut stats,
        "medium",
        findings
            .iter()
            .filter(|f| gstr(f, "severity").to_ascii_lowercase() == "medium")
            .count() as i64,
    );
    put(
        &mut stats,
        "low",
        findings
            .iter()
            .filter(|f| {
                let s = gstr(f, "severity").to_ascii_lowercase();
                s == "low" || s == "info"
            })
            .count() as i64,
    );
    put(
        &mut stats,
        "critical",
        listed
            .iter()
            .filter(|f| display_finding_severity(f) == "critical")
            .count() as i64,
    );
    put(&mut stats, "has_shell", has_shell);
    let path = rce_path_from_marks(db, project_id)?;
    let mut graph = Obj::new();
    put(&mut graph, "nodes", nodes);
    put(&mut graph, "edges", edges);
    put(&mut graph, "findings", findings);
    graph.insert("rce_path".into(), Value::Object(path));
    graph.insert("stats".into(), Value::Object(stats));
    Ok(graph)
}

pub fn real_poc_text(text: &str) -> String {
    let raw = text.trim();
    if raw.is_empty() {
        return String::new();
    }
    const MARKERS: &[&str] = &[
        "无人工复现",
        "禁止使用合成",
        "禁止自动合成利用",
        "missing real poc",
        "missing real poc_python",
        "raise SystemExit(\"missing real poc",
    ];
    if MARKERS.iter().any(|m| raw.contains(m)) {
        String::new()
    } else {
        raw.to_string()
    }
}

/// 已采集的 curl / python 原样返回。没有采集到时只写「禁止合成」，不补请求模板。
pub fn poc_for_finding(finding: &Obj, _target: &str) -> Obj {
    let mut curl = {
        let s = gstr(finding, "poc_curl");
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    };
    let mut py = {
        let s = gstr(finding, "poc_python");
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    };
    let category = gstr(finding, "category").to_ascii_lowercase();
    let title = {
        let t = gstr(finding, "title");
        if t.is_empty() {
            "finding".into()
        } else {
            t
        }
    };
    let evidence = gstr(finding, "evidence");
    let sev = normalize_severity(Some(&category), Some(&gstr(finding, "severity")));
    let _high = is_high_severity(&sev, &category);
    if curl.is_none() {
        curl = Some(format!(
            "# 无人工复现 PoC（禁止使用合成模板）。\n# 请在 report_finding 时填写真实 poc_curl，或依据证据手工复现。\n# title: {title}\n# category: {category}\n# evidence: {}",
            take_chars(&evidence, 200)
        ));
    }
    if py.is_none() {
        py = Some(format!(
            "#!/usr/bin/env python3\n\"\"\"无人工复现 PoC：{title} ({category})\n禁止自动合成利用脚本。请使用 agent 提供的真实 poc_python。\n证据片段：{}\n\"\"\"\nraise SystemExit(\"missing real poc_python\")\n",
            take_chars(&evidence, 200)
        ));
    }
    let mut bits = Vec::new();
    if !gstr(finding, "proof_canary").is_empty() {
        bits.push(format!("# proof_canary: {}", gstr(finding, "proof_canary")));
    }
    if !gstr(finding, "proof_url").is_empty() {
        bits.push(format!("# proof_url: {}", gstr(finding, "proof_url")));
    }
    if !gstr(finding, "proof_detail").is_empty() {
        bits.push(format!(
            "# proof_detail: {}",
            take_chars(&gstr(finding, "proof_detail"), 240)
        ));
    }
    let mut curl = curl.unwrap_or_default();
    if !bits.is_empty() {
        curl = format!("{}\n{curl}", bits.join("\n"));
    }
    let mut out = Obj::new();
    put(&mut out, "curl", curl);
    put(&mut out, "python", py.unwrap_or_default());
    out
}

fn url_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r#"(?i)https?://[^\s'"\\]+"#));
    &RE
}
fn header_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r#"(?s)(?:^|\s)-H\s+(['"])(.+?)\1"#));
    &RE
}
fn method_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r"(?:^|\s)-X\s+([A-Z]+)"));
    &RE
}
fn data_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r#"(?s)(?:^|\s)(?:--data-raw|--data-binary|--data|-d|--data-urlencode)\s+(['"])([\s\S]*?)\1"#,
        )
    });
    &RE
}

struct ParsedCurl {
    method: String,
    url: String,
    host: String,
    path: String,
    headers: Vec<String>,
    body: String,
    query_params: Vec<(String, String)>,
    raw: String,
    raw_http: String,
}

fn parsed_to_obj(p: &ParsedCurl) -> Obj {
    let mut out = Obj::new();
    put(&mut out, "method", p.method.clone());
    put(&mut out, "url", p.url.clone());
    put(&mut out, "host", p.host.clone());
    put(&mut out, "path", p.path.clone());
    put(&mut out, "headers", p.headers.clone());
    put(&mut out, "body", p.body.clone());
    let pairs: Vec<Vec<String>> = p
        .query_params
        .iter()
        .map(|(k, v)| vec![k.clone(), v.clone()])
        .collect();
    put(&mut out, "query_params", pairs);
    put(&mut out, "raw", p.raw.clone());
    put(&mut out, "raw_http", p.raw_http.clone());
    out
}

fn raw_http(method: &str, host: &str, path: &str, headers: &[String], body: &str) -> String {
    let mut path = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };
    if !path.starts_with('/') {
        path = format!("/{path}");
    }
    let mut lines = vec![format!("{method} {path} HTTP/1.1")];
    if !host.is_empty() {
        lines.push(format!("Host: {host}"));
    }
    let mut seen_cl = false;
    for h in headers {
        lines.push(h.clone());
        if h.to_ascii_lowercase().starts_with("content-length:") {
            seen_cl = true;
        }
    }
    if !body.is_empty() {
        if !seen_cl {
            lines.push(format!("Content-Length: {}", body.len()));
        }
        lines.push(String::new());
        lines.push(body.to_string());
    } else {
        lines.push(String::new());
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn parse_curl_command(text: &str) -> Option<Obj> {
    let raw = real_poc_text(text);
    if raw.is_empty() || !raw.to_ascii_lowercase().contains("curl") {
        return None;
    }
    let compact = raw
        .lines()
        .filter(|ln| {
            let t = ln.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map(|ln| ln.trim_end_matches('\\').trim().to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if !compact.to_ascii_lowercase().contains("curl") {
        return None;
    }
    let url = url_re()
        .find(&compact)
        .map(|m| {
            m.as_str()
                .trim_end_matches(['\\', ')', ',', ';'])
                .to_string()
        })
        .unwrap_or_default();
    let mut method = method_re()
        .captures(&compact)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_ascii_uppercase())
        .unwrap_or_else(|| "GET".into());
    let headers: Vec<String> = header_re()
        .captures_iter(&compact)
        .filter_map(|c| c.get(2).map(|m| m.as_str().trim().to_string()))
        .collect();
    let body = data_re()
        .captures(&compact)
        .and_then(|c| c.get(2).map(|m| m.as_str().to_string()))
        .unwrap_or_default();
    if !body.is_empty() && method == "GET" {
        method = "POST".into();
    }
    if url.is_empty() && body.is_empty() && headers.is_empty() {
        return None;
    }
    let mut host = String::new();
    let mut path = String::new();
    let mut query_params = Vec::new();
    if !url.is_empty() {
        if let Some(rest) = url.split("://").nth(1) {
            let (netloc, pathq) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/"),
            };
            host = netloc.to_string();
            let (p, q) = match pathq.split_once('?') {
                Some((p, q)) => (if p.is_empty() { "/" } else { p }, q),
                None => (if pathq.is_empty() { "/" } else { pathq }, ""),
            };
            path = if q.is_empty() {
                p.to_string()
            } else {
                format!("{p}?{q}")
            };
            if !q.is_empty() {
                query_params = parse_qsl(q);
            }
            path = percent_decode(&path);
        } else {
            path = url.clone();
        }
    }
    if !body.is_empty() && method != "GET" && query_params.is_empty() {
        let form = headers.iter().any(|h| {
            h.to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
        });
        if form || body.contains('=') {
            query_params = parse_qsl(&body);
        }
    }
    let raw_cut = take_chars(&compact, 4000);
    let http = raw_http(&method, &host, &path, &headers, &body);
    Some(parsed_to_obj(&ParsedCurl {
        method,
        url,
        host,
        path,
        headers,
        body,
        query_params,
        raw: raw_cut,
        raw_http: http,
    }))
}

fn norm_blob(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn covered_by(fragment: &str, blobs: &[&str]) -> bool {
    let frag = norm_blob(fragment);
    if frag.chars().count() < 32 {
        return false;
    }
    blobs.iter().any(|b| norm_blob(b).contains(&frag))
}

fn strip_embedded_mechanism(root: &str, mechanism: &str) -> String {
    if root.trim().is_empty() {
        return root.to_string();
    }
    let mech_n = norm_blob(mechanism);
    let mut parts = Vec::new();
    let mut start = 0usize;
    for (idx, ch) in root.char_indices() {
        if ch == '【' && idx > 0 {
            parts.push(&root[start..idx]);
            start = idx;
        }
    }
    parts.push(&root[start..]);
    let mut kept = Vec::new();
    for p in parts {
        if p.trim().is_empty() {
            continue;
        }
        if p.starts_with("【漏洞原理】") {
            continue;
        }
        if !mech_n.is_empty()
            && mech_n.chars().count() > 48
            && norm_blob(p).contains(&mech_n)
            && !p.starts_with("【现象】")
        {
            continue;
        }
        kept.push(p);
    }
    let joined = kept.concat();
    let joined = joined.trim();
    if joined.is_empty() {
        root.to_string()
    } else {
        joined.to_string()
    }
}

fn node_detail(finding: &Obj) -> String {
    match finding.get("related_node").and_then(Value::as_object) {
        Some(node) => match node.get("detail") {
            Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

fn edge_lines(finding: &Obj) -> Vec<String> {
    let mut out = Vec::new();
    let Some(edges) = finding.get("related_edges").and_then(Value::as_array) else {
        return out;
    };
    for e in edges {
        let Some(e) = e.as_object() else { continue };
        let frm = {
            let a = gstr(e, "from");
            if a.is_empty() {
                gstr(e, "src")
            } else {
                a
            }
        };
        let to = {
            let a = gstr(e, "to");
            if a.is_empty() {
                gstr(e, "dst")
            } else {
                a
            }
        };
        let rel = gstr(e, "relation");
        let why = gstr(e, "rationale");
        let mut bit = format!("`{frm}` --{rel}--> `{to}`");
        if !why.is_empty() {
            bit.push('：');
            bit.push_str(&why);
        }
        out.push(bit);
    }
    out
}

fn pairs_of(parsed: &Obj) -> Vec<(String, String)> {
    parsed
        .get("query_params")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|item| {
                    let arr = item.as_array()?;
                    if arr.len() < 2 {
                        return None;
                    }
                    Some((as_text(&arr[0]), as_text(&arr[1])))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parsed_of(finding: &Obj, poc: Option<&Obj>) -> Option<Obj> {
    let curl = if let Some(poc) = poc {
        let a = gstr(finding, "poc_curl");
        if !a.trim().is_empty() {
            a
        } else {
            gstr(poc, "curl")
        }
    } else {
        gstr(finding, "poc_curl")
    };
    parse_curl_command(&curl)
}

pub fn expected_signals(finding: &Obj) -> Vec<String> {
    let blob = ["evidence", "proof_detail", "proof_canary", "description"]
        .iter()
        .map(|k| gstr(finding, k))
        .collect::<Vec<_>>()
        .join("\n");
    let patterns: &[(&str, Option<&str>)] = &[
        (
            r"You have an error in your SQL syntax[^\n]{0,80}",
            Some("数据库语法错误回显"),
        ),
        (r"SQLException[^\n]{0,80}", Some("JDBC/SQL 异常")),
        (r"uid=\d+\([^)]+\)", Some("id/whoami 类命令回显")),
        (r"www-data", Some("进程用户 www-data")),
        (r"nt authority[^\n]{0,40}", Some("Windows 系统账户回显")),
        (r"root:[^:\n]*:0:0:", Some("/etc/passwd 特征行")),
        (r"HTTP/\d(?:\.\d)?\s+(\d{3})", None),
        (r"(?:status|Status-Code)[:= ]+(\d{3})", None),
    ];
    let mut out = Vec::new();
    for (pat, label) in patterns {
        let re = Regex::new(&format!("(?i){pat}")).ok();
        let Some(re) = re else { continue };
        let Some(c) = re.captures(&blob) else {
            continue;
        };
        if let Some(label) = label {
            let hit = c.get(0).map(|m| m.as_str().trim()).unwrap_or("");
            out.push(format!("{label}：`{hit}`"));
        } else if let Some(code) = c.get(1) {
            out.push(format!("HTTP 状态 {}", code.as_str()));
        }
    }
    let canary = gstr(finding, "proof_canary").trim().to_string();
    if !canary.is_empty() {
        out.push(format!("Canary `{canary}`"));
    }
    let url = gstr(finding, "proof_url").trim().to_string();
    if !url.is_empty() {
        out.push(format!("证明 URL 可访问：{url}"));
    }
    let mut seen = HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    out
}

fn special_value(v: &str) -> bool {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| re(r##"(?i)['"#;<>]|--|/\*|\*/|\$\(|`|\\|%27|%22"##));
    RE.is_match(v)
}

pub fn param_analysis(parsed: Option<&Obj>) -> String {
    let Some(parsed) = parsed else {
        return "未从 PoC 解析出查询/表单参数；复现时整段使用「PoC」原文，不要自行增参。".into();
    };
    let pairs = pairs_of(parsed);
    if pairs.is_empty() {
        if !gstr(parsed, "body").is_empty() {
            return "PoC 含请求体但未能稳定拆成键值。请把「原始 HTTP」或 curl `-d` 原文原样粘贴，不要改字段名。".into();
        }
        return "该请求无 QueryString / 表单字段；注入点若存在，应在路径或 Header 中（以 PoC 为准）。".into();
    }
    let mut lines = vec!["PoC 中出现的参数（名称与取值均来自已采集请求，未改写）：".to_string()];
    for (k, v) in pairs {
        let hint = if special_value(&v) {
            "（取值含引号/注释/特殊字符，优先作为注入点复核）"
        } else {
            "（普通取值，多半是业务或会话字段，复现时保持不变）"
        };
        let disp = if v.chars().count() <= 200 {
            v
        } else {
            format!("{}…", take_chars(&v, 200))
        };
        lines.push(format!("- `{k}` = `{disp}` {hint}"));
    }
    lines.join("\n")
}

pub fn deterministic_mechanism(finding: &Obj, parsed: Option<&Obj>) -> String {
    let cat = {
        let c = gstr(finding, "category").to_ascii_lowercase();
        if c.is_empty() {
            "未分类".into()
        } else {
            c
        }
    };
    let title = gstr(finding, "title");
    let parsed_owned = if parsed.is_some() {
        None
    } else {
        parsed_of(finding, None)
    };
    let parsed = parsed.or(parsed_owned.as_ref());
    let url = parsed.map(|p| gstr(p, "url")).unwrap_or_default();
    let method = parsed.map(|p| gstr(p, "method")).unwrap_or_default();
    let pairs = parsed.map(pairs_of).unwrap_or_default();
    let inj: Vec<_> = pairs
        .iter()
        .filter(|(_, v)| special_value(v))
        .map(|(k, _)| format!("`{k}`"))
        .collect();
    let inj_txt = if inj.is_empty() {
        "PoC 中的可控输入".into()
    } else {
        inj.join("、")
    };
    let loc = if !url.is_empty() {
        url
    } else {
        let nk = gstr(finding, "node_key");
        if nk.is_empty() {
            "未采集 URL".into()
        } else {
            nk
        }
    };
    let core = match cat.as_str() {
        "sqli" => format!("类别为 SQL 注入。应用把调用方可控数据拼进 SQL，而不是使用绑定参数。本条入口为 `{method} {loc}`，优先复核参数 {inj_txt}。当特殊字符进入语句后，引号闭合或注释会改变查询结构；证据里的语法错误/异常堆栈是语句被破坏的直接表现，不是「页面刚好 500」。"),
        "db_access" => format!("类别为数据库访问。入口 `{method} {loc}` 上的可控输入最终进入数据层。危害以证据中实际读到或改到的对象为准，不假设未出现的 UNION/写库。"),
        "rce" => format!("类别为远程代码/命令执行。入口 `{method} {loc}` 上的输入进入了操作系统命令、模板或反序列化触发面。证据中的 uid/whoami/canary 是进程已执行攻击者数据的证明。"),
        "command_injection" => format!("类别为命令注入。用户输入与系统命令拼接。入口 `{method} {loc}`，参数 {inj_txt}。元字符（如 `;`、`|`、`$()`）若未被剥离，就会在 Web 进程权限下跑额外命令。"),
        "deserialization" => format!("类别为不安全反序列化。入口 `{method} {loc}` 接受的数据被还原为对象并触发危险 gadget。只陈述证据里已出现的执行/报错，不补充未出现的 gadget 链名称。"),
        "file_read" => format!("类别为任意文件读取。入口 `{method} {loc}` 的路径/文件参数未做规范化和根目录约束。证据中的系统文件特征行证明读取越过了应用目录。"),
        "lfi" => format!("类别为本地文件包含/读取。入口 `{method} {loc}`，参数 {inj_txt} 指向服务端本地文件。"),
        "arbitrary_file_read" => format!("类别为任意文件读取。入口 `{method} {loc}`。成功判定以证据中的文件内容特征为准。"),
        "path_traversal" => format!("类别为路径穿越。`../` 或等价编码使参数 {inj_txt} 跳出预定目录。入口 `{method} {loc}`。"),
        "file_upload" => format!("类别为文件上传。入口 `{method} {loc}` 对扩展名、内容或落地目录校验不足。是否已变成 Webshell 以 canary/证明 URL 为准，未出现则只写上传成功。"),
        "file_write" => format!("类别为任意文件写入。入口 `{method} {loc}`。写入位置与内容以 proof/canary 为准。"),
        "auth_bypass" => format!("类别为认证绕过。入口 `{method} {loc}` 上服务端未校验会话/令牌/口令，或校验可被跳过。"),
        "unauth" => format!("类别为未授权访问。本应鉴权的接口 `{method} {loc}` 在无有效凭证时仍返回敏感数据或接受操作。"),
        "idor" => format!("类别为越权/IDOR。对象标识可被调用方改写。入口 `{method} {loc}`，参数 {inj_txt}。成功以证据中「访问了非当前主体对象」为准。"),
        "admin_access" => format!("类别为管理功能暴露或越权进入后台。入口 `{method} {loc}`。"),
        "ssrf" => format!("类别为服务端请求伪造。入口 `{method} {loc}` 让服务器向调用方指定的 URL 发请求。内网打到哪以证据为准，不假设未出现的云元数据。"),
        "xss" => format!("类别为跨站脚本。入口 `{method} {loc}` 的输出未编码，参数 {inj_txt} 被反射或存储后执行。"),
        "info_disclosure" => format!("类别为信息泄露。入口 `{method} {loc}` 暴露了版本、路径、调试或配置。本身未必能直接打穿，但会降低后续利用成本。"),
        _ => format!("类别标记为 `{cat}`。标题：{}。入口 `{method} {loc}`。原理以本条证据为准，不套用其它类别的利用模型。", if title.is_empty() { "未命名" } else { title.as_str() }),
    };
    format!("{core}\n\n原理分析禁止引入 PoC/证据未出现的第二个参数、隐藏接口或 CVE 编号。")
}

pub fn deterministic_root_cause(finding: &Obj) -> String {
    let parsed = parsed_of(finding, None);
    let cat = {
        let c = gstr(finding, "category").trim().to_string();
        if c.is_empty() {
            "未分类".into()
        } else {
            c
        }
    };
    let title = {
        let t = gstr(finding, "title");
        if t.is_empty() {
            "（无标题）".into()
        } else {
            t
        }
    };
    let desc = gstr(finding, "description").trim().to_string();
    let loc = gstr(finding, "node_key").trim().to_string();
    let nd = node_detail(finding);
    let mut parts = Vec::new();
    parts.push(format!(
        "【现象】{title}。严重度 `{}`，类别 `{cat}`。",
        {
            let s = gstr(finding, "severity");
            if s.is_empty() {
                "info".into()
            } else {
                s
            }
        }
    ));
    if !desc.is_empty() && !covered_by(&desc, &[&title]) {
        parts.push(format!("【测试人员描述】\n{desc}"));
    } else if desc.is_empty() {
        parts.push("【测试人员描述】未采集独立 description 字段。".into());
    }
    if let Some(parsed) = parsed.as_ref().filter(|p| !gstr(p, "url").is_empty()) {
        parts.push(format!(
            "【入口】`{} {}`。\nHost `{}`，路径 `{}`。\n所有复现必须使用该 URL 与方法；替换 Host 仅当测试环境与取证环境域名不同。",
            gstr(parsed, "method"),
            gstr(parsed, "url"),
            {
                let h = gstr(parsed, "host");
                if h.is_empty() { "未解析".into() } else { h }
            },
            {
                let p = gstr(parsed, "path");
                if p.is_empty() { "/".into() } else { p }
            }
        ));
        parts.push(format!("【可控参数】\n{}", param_analysis(Some(parsed))));
    } else {
        let mut line = "【入口】未采集可解析的 poc_curl。".to_string();
        if !loc.is_empty() {
            line.push_str(&format!(" 攻击图节点 `{loc}`。"));
        }
        line.push_str(" 复现时只能依据证据里出现的方法和路径，禁止补全未出现的路由。");
        parts.push(line);
    }
    if !nd.is_empty() && !covered_by(&nd, &[&desc]) {
        parts.push(format!("【关联节点记录】\n{nd}"));
    }
    let sigs = expected_signals(finding);
    if sigs.is_empty() {
        parts.push("【与证据的对应】证据中没有抽出可引用的报错/回显特征；复核时不要把单纯超时当成漏洞成立。".into());
    } else {
        parts.push(format!(
            "【与证据的对应】下列特征出现在本条证据/证明中，是「原理成立」的观察，不是猜测：\n{}",
            sigs.iter()
                .map(|s| format!("- {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    parts.join("\n\n")
}

pub fn deterministic_impact(finding: &Obj) -> String {
    let cat = gstr(finding, "category").to_ascii_lowercase();
    let ev = gstr(finding, "evidence").trim().to_string();
    let proof = gstr(finding, "proof_detail").trim().to_string();
    let blob = format!("{ev}\n{proof}");
    let blob_l = blob.to_ascii_lowercase();
    let mut proved = Vec::new();
    let mut potential = Vec::new();
    static UID: LazyLock<Regex> = LazyLock::new(|| re(r"uid=\d+\([^)]+\)"));
    if let Some(m) = UID.find(&blob) {
        proved.push(format!(
            "命令执行已证实（`{}`）；能否提权未证明。",
            m.as_str()
        ));
    } else if blob_l.contains("www-data") || blob_l.contains("nt authority") {
        let who = if blob_l.contains("www-data") {
            "www-data"
        } else {
            "Windows 系统账户"
        };
        proved.push(format!("命令执行已证实（`{who}`）；能否提权未证明。"));
    }
    static PASSWD: LazyLock<Regex> = LazyLock::new(|| re(r"root:[^:\n]*:0:0:|/etc/passwd"));
    if PASSWD.is_match(&blob) {
        proved.push("本地文件读取已证实（passwd 特征行）。".into());
    }
    static SQL: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?i)SQL syntax|SQLException|mysql_|syntax error"));
    if SQL.is_match(&blob) {
        proved
            .push("SQL 可被改写已证实（语法错误/驱动异常）；是否已出库未写明则不算已打穿。".into());
    }
    if !gstr(finding, "proof_canary").is_empty() || !gstr(finding, "proof_url").is_empty() {
        let mut bit = "写入/回显通道已用 canary 或证明 URL 钉死。".to_string();
        if !gstr(finding, "proof_canary").is_empty() {
            bit.push_str(&format!(" Canary `{}`。", gstr(finding, "proof_canary")));
        }
        if !gstr(finding, "proof_url").is_empty() {
            bit.push_str(&format!(" URL {}。", gstr(finding, "proof_url")));
        }
        proved.push(bit);
    }
    if matches!(
        cat.as_str(),
        "auth_bypass" | "unauth" | "idor" | "admin_access"
    ) && !ev.is_empty()
    {
        proved.push(
            "本条入口未校验会话/对象级授权；未授权方可打到业务分支，具体对象以接口返回为准。"
                .into(),
        );
    }
    if matches!(cat.as_str(), "info_disclosure" | "info") && !ev.is_empty() {
        proved.push("已采到未授权响应内容，会暴露版本、路径或配置。".into());
    }
    if matches!(cat.as_str(), "sqli" | "db_access") {
        potential.push("潜在可读业务表；未做出库则不要写成已拖库。".into());
    }
    if matches!(
        cat.as_str(),
        "rce" | "command_injection" | "deserialization" | "file_upload" | "file_write"
    ) {
        potential.push("潜在可读环境变量或写 Web 目录；未做横向则不写已控内网。".into());
    }
    if cat == "ssrf" {
        potential.push("潜在可打内网 HTTP 或云元数据；证据无内网回显则只算能发请求。".into());
    }
    let mut bits = if proved.is_empty() {
        vec!["证据未证明读库、写文件或横向；不要把严重度当成已打穿。".to_string()]
    } else {
        proved
    };
    bits.extend(potential);
    bits.join(" ")
}

pub fn deterministic_scope(finding: &Obj) -> String {
    let node = finding.get("related_node").and_then(Value::as_object);
    let title = node.map(|n| gstr(n, "title")).unwrap_or_default();
    let ntype = node.map(|n| gstr(n, "type")).unwrap_or_default();
    let loc = gstr(finding, "node_key");
    let parsed = parsed_of(finding, None);
    let mut lines = Vec::new();
    if !loc.is_empty() {
        let extra = if title.is_empty() {
            String::new()
        } else {
            format!("（{ntype} {title}）")
        };
        lines.push(format!("攻击图节点：`{loc}`{extra}"));
    }
    if let Some(parsed) = parsed.as_ref().filter(|p| !gstr(p, "url").is_empty()) {
        lines.push(format!(
            "HTTP 入口：`{} {}`",
            gstr(parsed, "method"),
            gstr(parsed, "url")
        ));
        if !gstr(parsed, "host").is_empty() {
            lines.push(format!("主机：`{}`", gstr(parsed, "host")));
        }
        if !gstr(parsed, "path").is_empty() {
            lines.push(format!("路径与查询：`{}`", gstr(parsed, "path")));
        }
        for (k, v) in pairs_of(parsed).into_iter().take(16) {
            let disp = if v.chars().count() <= 120 {
                v
            } else {
                format!("{}…", take_chars(&v, 120))
            };
            lines.push(format!("参数 `{k}` = `{disp}`"));
        }
        if parsed
            .get("headers")
            .and_then(Value::as_array)
            .is_some_and(|hs| {
                hs.iter()
                    .any(|h| as_text(h).to_ascii_lowercase().starts_with("cookie:"))
            })
        {
            lines.push(
                "会话：请求带 Cookie（复现时用当前有效会话替换，不要改其它 Header 名）".into(),
            );
        }
    }
    for el in edge_lines(finding).into_iter().take(12) {
        lines.push(format!("关系：{el}"));
    }
    if !gstr(finding, "prerequisites").is_empty() {
        lines.push(format!("前置：{}", gstr(finding, "prerequisites")));
    }
    if lines.is_empty() {
        return "未采集明确资产归属；请按标题与证据中的 Host/URL 定位。".into();
    }
    lines
        .iter()
        .map(|x| format!("- {x}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn benign_value(value: &str) -> Option<String> {
    let mut v = value.to_string();
    for token in ["'", "\"", "%27", "%22", "--", "#", ";", "`"] {
        v = v.replace(token, "");
    }
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r"/\*.*?\*/"));
    let v = RE.replace_all(&v, "").trim().to_string();
    if v.is_empty() || v == value {
        None
    } else {
        Some(v)
    }
}

pub fn manual_reproduction_steps(finding: &Obj, poc: Option<&Obj>) -> Vec<String> {
    let poc_curl = {
        let a = gstr(finding, "poc_curl");
        if !real_poc_text(&a).is_empty() || a.trim().is_empty() {
            a
        } else {
            a
        }
    };
    let curl = real_poc_text(&{
        let own = gstr(finding, "poc_curl");
        if !own.trim().is_empty() {
            own
        } else {
            poc.map(|p| gstr(p, "curl")).unwrap_or_default()
        }
    });
    let py = real_poc_text(&{
        let own = gstr(finding, "poc_python");
        if !own.trim().is_empty() {
            own
        } else {
            poc.map(|p| gstr(p, "python")).unwrap_or_default()
        }
    });
    let _ = poc_curl;
    let evidence = gstr(finding, "evidence").trim().to_string();
    let proof_url = gstr(finding, "proof_url").trim().to_string();
    let canary = gstr(finding, "proof_canary").trim().to_string();
    let loc = gstr(finding, "node_key").trim().to_string();
    let cat = gstr(finding, "category").to_ascii_lowercase();
    let parsed = parse_curl_command(&curl).or_else(|| parsed_of(finding, poc));
    let sigs = expected_signals(finding);
    let mut steps = Vec::new();
    let mut n = 1i64;
    let mut add = |text: String| {
        steps.push(format!("{n}. {text}"));
        n += 1;
    };
    add(format!(
        "准备工具：Burp Suite（Proxy + Repeater）或可编辑原始 HTTP 的客户端，以及 curl。{}",
        if loc.is_empty() {
            String::new()
        } else {
            format!(" 关联节点 `{loc}`。")
        }
    ));
    if let Some(parsed) = parsed.as_ref().filter(|p| !gstr(p, "host").is_empty()) {
        add(format!(
            "先探测入口是否可达（不要带 payload）：`curl -skI --max-time 15 'http://{}/'` 或对 PoC URL 去掉查询串后发 HEAD/GET。 连接失败、TLS 名字不匹配时先修环境，不要开始复现。",
            gstr(parsed, "host")
        ));
    }
    let rce_like = matches!(
        cat.as_str(),
        "rce" | "command_injection" | "deserialization" | "file_write" | "file_upload"
    ) || loc.starts_with("goal:shell")
        || loc.starts_with("foothold:shell");
    if rce_like && (!canary.is_empty() || !proof_url.is_empty()) {
        let canary_show = if canary.is_empty() {
            "<已采集 canary>"
        } else {
            canary.as_str()
        };
        add(format!(
            "本条含命令执行/写文件证明。 若走漏洞通道落盘短 txt，内容必须使用 canary `{canary_show}`，文件名与路径只能用证据/proof 里出现过的，禁止换目录碰运气。"
        ));
        if !proof_url.is_empty() {
            add(format!("浏览器或 curl 访问证明 URL `{proof_url}`，响应体必须含同一 canary，否则不算复现成功。"));
        }
    }
    if let Some(parsed) = parsed.as_ref() {
        let raw_http = gstr(parsed, "raw_http");
        let host = {
            let h = gstr(parsed, "host");
            if h.is_empty() {
                "见 PoC".into()
            } else {
                h
            }
        };
        let url_or_path = {
            let u = gstr(parsed, "url");
            if u.is_empty() {
                gstr(parsed, "path")
            } else {
                u
            }
        };
        add(format!(
            "打开 Burp Repeater，目标 Host `{host}`，方法 `{}`，完整 URL `{url_or_path}`。",
            gstr(parsed, "method")
        ));
        let mut paste = "把下面「原始 HTTP 请求」整段粘贴进 Repeater（或 Intruder 的 Raw）。 不要改路径、不要增加 Query 参数、不要改参数名。".to_string();
        if !raw_http.is_empty() {
            paste.push_str(&format!("\n```http\n{raw_http}\n```"));
        }
        add(paste);
        let pairs = pairs_of(parsed);
        if !pairs.is_empty() {
            let mut lines = vec!["核对每一个参数（来自 PoC，不是猜测）：".to_string()];
            for (k, v) in &pairs {
                let disp = if v.chars().count() <= 180 {
                    v.clone()
                } else {
                    format!("{}…", take_chars(v, 180))
                };
                lines.push(format!("  - `{k}` = `{disp}`"));
            }
            add(lines.join("\n"));
        }
        let headers: Vec<String> = parsed
            .get("headers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(as_text)
                    .filter(|s| !s.is_empty())
                    .take(12)
                    .collect()
            })
            .unwrap_or_default();
        if !headers.is_empty() {
            add(format!("请求头必须包含：{}。 若 Cookie/CSRF 过期，只替换这两类会话值，Header 名称保持不变。", headers.join("；")));
        }
        let body = gstr(parsed, "body");
        if !body.is_empty() {
            let shown = if body.chars().count() > 1200 {
                format!("{}…", take_chars(&body, 1200))
            } else {
                body
            };
            add(format!(
                "请求体使用 PoC 原文（不要改字段名）：\n```\n{shown}\n```"
            ));
        }
        add("点击 Send。成功判定只认证据里已出现的特征，不要把网关 502/WAF 拦截页当漏洞。".into());
        if !sigs.is_empty() {
            add(format!(
                "复现成功时，响应或命令输出应出现：\n{}",
                sigs.iter()
                    .map(|s| format!("  - {s}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
        add("终端等价复现：把报告「PoC / curl」整段复制到已授权机器执行。 仅当 Host/Cookie 与取证时不同才替换这两项。".into());
        let mut benign_bits = Vec::new();
        for (k, v) in &pairs {
            if let Some(b) = benign_value(v) {
                benign_bits.push(format!(
                    "`{k}` 从 `{v}` 改为 `{b}`（去掉 PoC 里的特殊字符，不新增任何 payload）"
                ));
            }
        }
        if benign_bits.is_empty() {
            add("基线对照：再发一次去掉攻击取值、改用该参数在业务里的普通数字/字母值的请求（不得引入 PoC 未出现的第二个注入向量）。对比两次 Response Body。".into());
        } else {
            add(format!(
                "基线对照：复制同一请求，仅做下列修改后重放，确认差异来自本参数而不是站点普遍报错：\n{}",
                benign_bits.iter().map(|x| format!("  - {x}")).collect::<Vec<_>>().join("\n")
            ));
        }
    } else if !curl.is_empty() {
        add(
            "Burp 未能解析出结构化字段。将报告中的 curl PoC 原样在终端执行，只替换 Host/Cookie。"
                .into(),
        );
    } else if !py.is_empty() {
        add("将报告中的 python PoC 存为 `poc.py`，在授权环境执行 `python3 poc.py`。 不要改脚本里的路径与参数名；会话类值可按环境替换。".into());
    } else if !evidence.is_empty() {
        add("本条未提供独立 poc_curl。按证据里的方法、URL、参数和响应特征手工构造等价请求；证据里没有的字段不要编。".into());
    } else {
        add(
            "未采集可复现 PoC 与证据。请结合漏洞说明与关联节点复核，禁止用类别典型 payload 盲打。"
                .into(),
        );
    }
    if !evidence.is_empty() && !(parsed.is_some() && !sigs.is_empty()) {
        add("将响应或命令输出与证据逐字对照。 成功标准是证据中已记录的特征（状态码、回显、文件内容、canary）。".into());
    }
    add("失败排查：① DNS/TCP/TLS 失败 → 环境问题，不是漏洞消失；② 200 但无证据特征 → 会话失效、WAF 或已修复，不要换未出现的 payload 硬打；③ 与证据完全一致 → 记录时间、账号、完整请求/响应，供修复后回归。".into());
    add("把 Repeater 的 Request/Response 或 curl `-D -` 输出归档，和本报告证据放在一起。".into());
    if let Some(Value::Array(notes)) = finding.get("reproduction_notes") {
        for note in notes {
            let s = as_text(note).trim().to_string();
            if !s.is_empty() {
                add(s);
            }
        }
    }
    steps
}

pub fn apply_deterministic_writeup(finding: &Obj, poc: Option<&Obj>) -> Obj {
    let mut out = finding.clone();
    let parsed = parsed_of(&out, poc);
    if let Some(parsed) = parsed.as_ref() {
        let http = gstr(parsed, "raw_http");
        if !http.is_empty() {
            put(&mut out, "http_raw", http);
        } else if !out.contains_key("http_raw") {
            put(&mut out, "http_raw", "");
        }
        if gstr(&out, "param_analysis").is_empty() {
            put(&mut out, "param_analysis", param_analysis(Some(parsed)));
        }
    } else {
        if !out.contains_key("http_raw") {
            put(&mut out, "http_raw", "");
        }
        if !out.contains_key("param_analysis") {
            put(&mut out, "param_analysis", param_analysis(None));
        }
    }
    let mechanism_empty = gstr(&out, "mechanism").trim().is_empty();
    if mechanism_empty {
        let text = deterministic_mechanism(&out, parsed.as_ref());
        put(&mut out, "mechanism", text);
    }
    let root_empty = gstr(&out, "root_cause").trim().is_empty();
    if root_empty {
        let text = deterministic_root_cause(&out);
        put(&mut out, "root_cause", text);
    } else {
        let root = gstr(&out, "root_cause");
        let mech = gstr(&out, "mechanism");
        let stripped = strip_embedded_mechanism(&root, &mech);
        put(&mut out, "root_cause", stripped);
    }
    let nd = node_detail(&out);
    let description = gstr(&out, "description");
    let root_cause = gstr(&out, "root_cause");
    let mechanism = gstr(&out, "mechanism");
    if covered_by(&nd, &[&description, &root_cause, &mechanism]) {
        put(&mut out, "node_detail_unique", "");
    } else {
        put(&mut out, "node_detail_unique", nd);
    }
    let review = redteam_rating_block(&out);
    put(&mut out, "secondary_review", review);
    let impact_empty = gstr(&out, "impact_detail").trim().is_empty();
    if impact_empty {
        let text = deterministic_impact(&out);
        put(&mut out, "impact_detail", text);
    }
    let scope_empty = gstr(&out, "affected_scope").trim().is_empty();
    if scope_empty {
        let text = deterministic_scope(&out);
        put(&mut out, "affected_scope", text);
    }
    let sigs = expected_signals(&out);
    put(&mut out, "expected_signals", sigs.clone());
    let result_empty = gstr(&out, "expected_result").trim().is_empty();
    if result_empty && !sigs.is_empty() {
        put(&mut out, "expected_result", sigs.join("；"));
    }
    let steps = manual_reproduction_steps(&out, poc);
    put(&mut out, "manual_steps", steps);
    out
}

pub fn finding_from_vuln_node(node: &Obj, related_edges: Option<&[Value]>) -> Obj {
    let detail = match node.get("detail") {
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    let tags = tags_of(&g(node, "tags"));
    let mut cat = "vuln".to_string();
    for t in &tags {
        if !t.is_empty() && !t.starts_with("host:") {
            cat = t.clone();
            break;
        }
    }
    let sev = {
        let s = gstr(node, "severity");
        if s.is_empty() {
            "info".into()
        } else {
            s
        }
    };
    let key = gstr(node, "key");
    let title = {
        let t = gstr(node, "title");
        if !t.is_empty() {
            t
        } else if !key.is_empty() {
            key.clone()
        } else {
            "vuln".into()
        }
    };
    let mut related = Obj::new();
    put(&mut related, "key", g(node, "key"));
    put(&mut related, "type", g(node, "type"));
    put(&mut related, "title", g(node, "title"));
    put(
        &mut related,
        "detail",
        if detail.is_empty() {
            Value::Null
        } else {
            Value::String(detail.clone())
        },
    );
    put(&mut related, "severity", g(node, "severity"));
    put(&mut related, "risk_score", g(node, "risk_score"));
    put(&mut related, "tags", tags);
    let mut out = Obj::new();
    put(&mut out, "id", format!("node:{key}"));
    put(&mut out, "project_id", g(node, "project_id"));
    put(&mut out, "node_key", g(node, "key"));
    put(&mut out, "severity", sev.clone());
    put(&mut out, "category", cat);
    put(&mut out, "title", title);
    put(
        &mut out,
        "description",
        if detail.is_empty() {
            Value::Null
        } else {
            Value::String(detail)
        },
    );
    out.insert("evidence".into(), Value::Null);
    out.insert("poc_curl".into(), Value::Null);
    out.insert("poc_python".into(), Value::Null);
    out.insert("cvss".into(), Value::Null);
    put(&mut out, "created_at", g(node, "created_at"));
    put(
        &mut out,
        "critical",
        gbool(node, "is_rce") || sev == "critical",
    );
    put(&mut out, "verification_status", "pending");
    out.insert("verified_at".into(), Value::Null);
    out.insert("proof_type".into(), Value::Null);
    out.insert("proof_canary".into(), Value::Null);
    out.insert("proof_url".into(), Value::Null);
    out.insert("proof_detail".into(), Value::Null);
    out.insert("related_node".into(), Value::Object(related));
    put(
        &mut out,
        "related_edges",
        related_edges.unwrap_or(&[]).to_vec(),
    );
    put(&mut out, "from_node_only", true);
    apply_deterministic_writeup(&out, None)
}

fn facts_for_ai(finding: &Obj) -> Obj {
    let parsed = parse_curl_command(&gstr(finding, "poc_curl"));
    let mut out = Obj::new();
    put(&mut out, "id", g(finding, "id"));
    put(&mut out, "title", g(finding, "title"));
    put(&mut out, "severity", g(finding, "severity"));
    put(&mut out, "category", g(finding, "category"));
    put(&mut out, "node_key", g(finding, "node_key"));
    put(&mut out, "description", gstr(finding, "description"));
    put(
        &mut out,
        "evidence",
        take_chars(&gstr(finding, "evidence"), 8000),
    );
    put(
        &mut out,
        "poc_curl",
        take_chars(&real_poc_text(&gstr(finding, "poc_curl")), 4000),
    );
    put(
        &mut out,
        "poc_python",
        take_chars(&real_poc_text(&gstr(finding, "poc_python")), 4000),
    );
    put(&mut out, "proof_type", g(finding, "proof_type"));
    put(&mut out, "proof_canary", g(finding, "proof_canary"));
    put(&mut out, "proof_url", g(finding, "proof_url"));
    put(
        &mut out,
        "proof_detail",
        take_chars(&gstr(finding, "proof_detail"), 4000),
    );
    put(&mut out, "cvss", g(finding, "cvss"));
    put(&mut out, "related_node", g(finding, "related_node"));
    put(
        &mut out,
        "related_edges",
        finding
            .get("related_edges")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    );
    if let Some(parsed) = parsed {
        out.insert("parsed_curl".into(), Value::Object(parsed.clone()));
        let http = gstr(&parsed, "raw_http");
        put(
            &mut out,
            "http_raw",
            if http.is_empty() {
                gstr(finding, "http_raw")
            } else {
                http
            },
        );
    } else {
        out.insert("parsed_curl".into(), Value::Null);
        put(&mut out, "http_raw", gstr(finding, "http_raw"));
    }
    put(&mut out, "param_analysis", gstr(finding, "param_analysis"));
    let sigs = if let Some(Value::Array(a)) = finding.get("expected_signals") {
        if a.is_empty() {
            expected_signals(finding)
        } else {
            a.iter().map(as_text).collect()
        }
    } else {
        expected_signals(finding)
    };
    put(&mut out, "expected_signals", sigs);
    put(
        &mut out,
        "deterministic_mechanism",
        gstr(finding, "mechanism"),
    );
    put(
        &mut out,
        "deterministic_root_cause",
        gstr(finding, "root_cause"),
    );
    put(
        &mut out,
        "deterministic_impact",
        gstr(finding, "impact_detail"),
    );
    out
}

pub fn parse_writeups_payload(text: &str) -> Vec<Obj> {
    let raw = text.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    static FENCE: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)```(?:json)?\s*(\{.*?\})\s*```"));
    static OBJ: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)\{[\s\S]*\}"));
    let mut blob = raw.to_string();
    if let Some(c) = FENCE.captures(raw).and_then(|c| c.get(1)) {
        blob = c.as_str().to_string();
    } else if let Some(m) = OBJ.find(raw) {
        blob = m.as_str().to_string();
    }
    let data = serde_json::from_str::<Value>(&blob)
        .ok()
        .or_else(|| json_objects(raw).into_iter().next());
    let Some(data) = data else { return Vec::new() };
    let items = if let Value::Object(map) = &data {
        if let Some(w) = map.get("writeups") {
            w.clone()
        } else if map.contains_key("id") {
            Value::Array(vec![Value::Object(map.clone())])
        } else {
            Value::Null
        }
    } else {
        data.clone()
    };
    let Some(items) = items.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for it in items {
        let Some(obj) = it.as_object() else { continue };
        if !gstr(obj, "id").is_empty()
            || !gstr(obj, "root_cause").is_empty()
            || !gstr(obj, "mechanism").is_empty()
        {
            out.push(obj.clone());
        }
    }
    out
}

pub fn merge_ai_writeup(finding: &Obj, spec: &Obj) -> Obj {
    let mut out = finding.clone();
    for key in [
        "mechanism",
        "root_cause",
        "impact_detail",
        "affected_scope",
        "expected_result",
        "remediation",
    ] {
        let val = gstr(spec, key).trim().to_string();
        if !val.is_empty() {
            put(&mut out, key, val);
        }
    }
    let notes = spec
        .get("reproduction_notes")
        .or_else(|| spec.get("reproduction_steps"));
    if let Some(Value::Array(notes)) = notes {
        let clean: Vec<String> = notes
            .iter()
            .map(|x| as_text(x).trim().to_string())
            .filter(|s| !s.is_empty())
            .take(15)
            .collect();
        if !clean.is_empty() {
            put(&mut out, "reproduction_notes", clean);
        }
    }
    apply_deterministic_writeup(&out, None)
}

fn ai_one_writeup(settings: &Settings, finding: &Obj) -> Result<Option<Obj>, String> {
    let facts = facts_for_ai(finding);
    let dumped = serde_json::to_string_pretty(&facts).unwrap_or_else(|_| "{}".into());
    let prompt = format!(
        "请为下面这一条漏洞写短危害说明。只使用事实包，只填 impact_detail。\n\n{}",
        take_chars(&dumped, 80000)
    );
    let model = role_model(
        settings,
        &[&settings.report_model, &settings.supervisor_model],
    );
    let wait = settings.report_timeout_sec.max(90) as f64;
    let blob = query_text(&QueryText {
        system_prompt: WRITEUP_SYSTEM.to_string(),
        user_prompt: prompt,
        cwd: settings.data_dir.display().to_string(),
        timeout: wait.max(30.0),
        tools: false,
        model,
        role: "finding-page".into(),
        project_id: gstr(finding, "project_id"),
    })?;
    let specs = parse_writeups_payload(&blob);
    if specs.is_empty() {
        return Ok(None);
    }
    let fid = gstr(finding, "id");
    for mut s in specs.clone() {
        let sid = gstr(&s, "id");
        if sid.is_empty() || sid == fid {
            if sid.is_empty() {
                put(&mut s, "id", fid);
            }
            return Ok(Some(s));
        }
    }
    Ok(specs.into_iter().next())
}

pub fn ai_enrich_writeups(settings: &Settings, findings: Vec<Obj>) -> Vec<Obj> {
    if findings.is_empty() || !settings.report_ai {
        return findings;
    }
    findings
        .into_iter()
        .map(|f| match ai_one_writeup(settings, &f) {
            Ok(Some(spec)) => merge_ai_writeup(&f, &spec),
            _ => f,
        })
        .collect()
}

fn clean_text(text: &Value, limit: usize) -> String {
    clip(&as_text(text), limit)
}

pub fn report_from(src: &Obj) -> Obj {
    let pick = |names: &[&str]| -> String {
        for name in names {
            let s = clean_text(&g(src, name), 8000);
            if !s.is_empty() {
                return s;
            }
        }
        String::new()
    };
    let mut out = Obj::new();
    put(
        &mut out,
        "report_summary",
        pick(&["report_summary", "summary"]),
    );
    put(
        &mut out,
        "report_impact",
        pick(&["report_impact", "impact"]),
    );
    put(
        &mut out,
        "report_rating",
        pick(&["report_rating", "rating"]),
    );
    put(&mut out, "report_repro", pick(&["report_repro", "repro"]));
    put(&mut out, "report_fix", pick(&["report_fix", "fix"]));
    out
}

pub fn has_page(finding: &Obj) -> bool {
    let need = [
        "report_summary",
        "report_impact",
        "report_repro",
        "report_fix",
    ];
    if !need
        .iter()
        .all(|k| !clean_text(&g(finding, k), 8000).is_empty())
    {
        return false;
    }
    let rating = clean_text(&g(finding, "report_rating"), 8000);
    let rating = if rating.is_empty() {
        clean_text(&g(finding, "redteam_rating_rationale"), 8000)
    } else {
        rating
    };
    !rating.is_empty()
}

pub fn parse_page(text: &str) -> Obj {
    let raw = text.trim();
    if raw.is_empty() {
        return Obj::new();
    }
    let mut best: Option<Obj> = None;
    let mut best_n = 0usize;
    for (i, ch) in raw.char_indices() {
        if ch != '{' {
            continue;
        }
        let Some(Value::Object(data)) = json_prefix(&raw[i..]) else {
            continue;
        };
        let n = JSON_PAGE_KEYS
            .iter()
            .filter(|k| !clean_text(&g(&data, k), 8000).is_empty())
            .count();
        if n > best_n {
            best = Some(data);
            best_n = n;
            if n >= 4 {
                break;
            }
        }
    }
    best.map(|b| report_from(&b)).unwrap_or_default()
}

pub fn save_page(db: &Db, fid: &str, spec: &Obj) -> Result<(), String> {
    if fid.is_empty() || spec.is_empty() {
        return Ok(());
    }
    let vals: Vec<Option<String>> = PAGE_KEYS
        .iter()
        .map(|k| {
            let s = clean_text(&g(spec, k), 8000);
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .collect();
    if vals.iter().all(|v| v.is_none()) {
        return Ok(());
    }
    db.execute(
        "UPDATE findings SET report_summary=COALESCE(?1, report_summary), report_impact=COALESCE(?2, report_impact), report_rating=COALESCE(?3, report_rating), report_repro=COALESCE(?4, report_repro), report_fix=COALESCE(?5, report_fix) WHERE id=?6",
        &[&vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &fid],
    )
}

fn facts_blob(finding: &Obj, project: Option<&Obj>) -> Obj {
    let empty = Obj::new();
    let p = project.unwrap_or(&empty);
    let cfg = match p.get("config").and_then(Value::as_object) {
        Some(c) => c.clone(),
        None => Obj::new(),
    };
    let mut objective = gstr(&cfg, "objective");
    if objective.is_empty() {
        objective = gstr(&cfg, "track");
    }
    let mut out = Obj::new();
    put(&mut out, "project_name", gstr(p, "name"));
    put(&mut out, "target", gstr(p, "target"));
    put(&mut out, "objective", objective);
    put(&mut out, "id", g(finding, "id"));
    put(&mut out, "title", g(finding, "title"));
    put(&mut out, "category", g(finding, "category"));
    put(&mut out, "severity", g(finding, "severity"));
    put(&mut out, "node_key", g(finding, "node_key"));
    put(
        &mut out,
        "description",
        clean_text(&g(finding, "description"), 2000),
    );
    put(
        &mut out,
        "evidence",
        clean_text(&g(finding, "evidence"), 6000),
    );
    put(
        &mut out,
        "poc_curl",
        clean_text(&g(finding, "poc_curl"), 4000),
    );
    put(
        &mut out,
        "poc_python",
        clean_text(&g(finding, "poc_python"), 4000),
    );
    put(
        &mut out,
        "proof_detail",
        clean_text(&g(finding, "proof_detail"), 3000),
    );
    put(&mut out, "proof_url", gstr(finding, "proof_url"));
    put(&mut out, "redteam_rating", gstr(finding, "redteam_rating"));
    put(
        &mut out,
        "redteam_rating_rationale",
        clean_text(&g(finding, "redteam_rating_rationale"), 4000),
    );
    put(
        &mut out,
        "verification_status",
        gstr(finding, "verification_status"),
    );
    put(
        &mut out,
        "secondary_verified",
        gbool(finding, "secondary_verified"),
    );
    put(&mut out, "related_node", g(finding, "related_node"));
    out
}

fn page_system(project: Option<&Obj>) -> String {
    let _ = project;
    i18n::with_output_lang(Some(PI_PAGE_SYSTEM), Some(i18n::config_output_lang(())))
}

pub fn compose_page(settings: &Settings, finding: &Obj, project: Option<&Obj>) -> Obj {
    if !settings.report_ai {
        return Obj::new();
    }
    let facts = facts_blob(finding, project);
    let failed = gstr(finding, "verification_status").to_ascii_lowercase() == "excluded";
    let lead = if failed {
        "下面这条的二次验证没有复现同样危害。仍按首次事实撰写五个板块，不要写成已经二次验证通过。"
    } else {
        "下面是本项目里已经二次验证过的一条漏洞事实包。"
    };
    let dumped =
        serde_json::to_string_pretty(&Value::Object(facts)).unwrap_or_else(|_| "{}".into());
    let prompt = format!(
        "{lead}请按系统要求撰写漏洞页五个板块，只使用这些事实。\n\n{}",
        take_chars(&dumped, 80000)
    );
    let model = role_model(
        settings,
        &[&settings.report_model, &settings.supervisor_model],
    );
    let wait = (settings.report_timeout_sec as f64).max(90.0);
    let project_id = {
        let a = gstr(finding, "project_id");
        if !a.is_empty() {
            a
        } else {
            project.map(|p| gstr(p, "id")).unwrap_or_default()
        }
    };
    match query_text(&QueryText {
        system_prompt: page_system(project),
        user_prompt: prompt,
        cwd: settings.data_dir.display().to_string(),
        timeout: wait.max(20.0),
        tools: false,
        model,
        role: "finding-page".into(),
        project_id,
    }) {
        Ok(blob) => parse_page(&blob),
        Err(_) => Obj::new(),
    }
}

static PAGE_LOCKS: LazyLock<Mutex<HashMap<String, std::sync::Arc<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SCHEDULED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static FAILED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));
static PAGE_TASKS: LazyLock<Mutex<Vec<std::thread::JoinHandle<()>>>> =
    LazyLock::new(|| Mutex::new(Vec::new()));
static PAGE_RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn page_lock(fid: &str) -> std::sync::Arc<Mutex<()>> {
    let mut map = lock(&PAGE_LOCKS);
    map.entry(fid.to_string())
        .or_insert_with(|| std::sync::Arc::new(Mutex::new(())))
        .clone()
}

pub fn ensure_page(
    db: &Db,
    settings: &Settings,
    project_id: &str,
    finding: &Obj,
    project: Option<&Obj>,
) -> Obj {
    let mut out = finding.clone();
    let fid = gstr(&out, "id");
    if has_page(&out) {
        return out;
    }
    if !gbool(&out, "secondary_verified") {
        let failed = gstr(&out, "verification_status").to_ascii_lowercase() == "excluded";
        if secondary_on(Some(settings)) && !failed {
            return out;
        }
    }
    if fid.is_empty() {
        return out;
    }
    let guard = page_lock(&fid);
    let _held = lock(&guard);
    let row = db
        .query_one(
            "SELECT * FROM findings WHERE id=?1 AND project_id=?2",
            &[&fid, &project_id],
        )
        .ok()
        .flatten();
    let Some(row) = row else { return out };
    let mut merged = out.clone();
    for k in PAGE_KEYS {
        let from_row = gstr(&row, k);
        if !from_row.trim().is_empty() {
            put(&mut merged, k, from_row);
        } else if !gstr(&out, k).is_empty() {
            put(&mut merged, k, gstr(&out, k));
        }
    }
    if has_page(&merged) {
        for k in PAGE_KEYS {
            put(&mut out, k, gstr(&merged, k));
        }
        return out;
    }
    put(&mut merged, "project_id", project_id);
    let spec = compose_page(settings, &merged, project);
    if !spec.is_empty() && spec.values().any(|v| !as_text(v).trim().is_empty()) {
        let _ = save_page(db, &fid, &spec);
        for (k, v) in spec {
            out.insert(k, v);
        }
    }
    out
}

pub fn page_activity(fid: &str) -> String {
    if lock(&SCHEDULED).contains(fid) {
        "writing".into()
    } else if lock(&FAILED).contains(fid) {
        "failed".into()
    } else {
        "idle".into()
    }
}

pub fn clear_page_failure(fid: &str) {
    lock(&FAILED).remove(fid);
}

pub fn schedule_page(settings: &Settings, project_id: &str, fid: &str) {
    if project_id.is_empty() || fid.is_empty() || lock(&SCHEDULED).contains(fid) {
        return;
    }
    lock(&SCHEDULED).insert(fid.to_string());
    lock(&FAILED).remove(fid);
    let settings = settings.clone();
    let project_id = project_id.to_string();
    let fid_owned = fid.to_string();
    let spawned = std::thread::Builder::new()
        .name("atk-page".into())
        .spawn(move || {
            PAGE_RUNS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut outcome = "fail";
            let result = (|| -> Result<(), String> {
                let db = Db::open(&settings.db_path)?;
                let row = db.query_one(
                    "SELECT * FROM findings WHERE id=?1 AND project_id=?2",
                    &[&fid_owned, &project_id],
                )?;
                let Some(row) = row else {
                    outcome = "skip";
                    return Ok(());
                };
                if has_page(&row) {
                    outcome = "ok";
                    return Ok(());
                }
                let failed = gstr(&row, "verification_status").to_ascii_lowercase() == "excluded";
                if !gbool(&row, "secondary_verified") && secondary_on(Some(&settings)) && !failed {
                    outcome = "skip";
                    return Ok(());
                }
                let proj = get_project(&db, &project_id)?;
                let got = ensure_page(&db, &settings, &project_id, &row, proj.as_ref());
                if has_page(&got) {
                    outcome = "ok";
                } else {
                    eprintln!("finding page was not written pid={project_id} fid={fid_owned}");
                }
                Ok(())
            })();
            if result.is_err() {
                eprintln!("finding page write failed pid={project_id} fid={fid_owned}");
                outcome = "fail";
            }
            if outcome == "ok" {
                lock(&FAILED).remove(&fid_owned);
            } else if outcome == "fail" {
                lock(&FAILED).insert(fid_owned.clone());
            }
            lock(&SCHEDULED).remove(&fid_owned);
        });
    match spawned {
        Ok(handle) => {
            let mut tasks = lock(&PAGE_TASKS);
            let old = std::mem::take(&mut *tasks);
            for h in old {
                if h.is_finished() {
                    let _ = h.join();
                } else {
                    tasks.push(h);
                }
            }
            tasks.push(handle);
        }
        Err(_) => {
            lock(&SCHEDULED).remove(fid);
            lock(&FAILED).insert(fid.to_string());
        }
    }
}

pub fn fill_missing_pages(
    db: &Db,
    settings: &Settings,
    project_id: &str,
    project: Option<&Obj>,
) -> Result<i64, String> {
    let sql = if secondary_on(Some(settings)) {
        "SELECT * FROM findings WHERE project_id=?1 AND (secondary_verified=1 OR lower(IFNULL(verification_status,''))='excluded') AND (report_summary IS NULL OR TRIM(report_summary)='')"
    } else {
        "SELECT * FROM findings WHERE project_id=?1 AND (report_summary IS NULL OR TRIM(report_summary)='')"
    };
    let rows = db.query(sql, &[&project_id])?;
    let mut n = 0i64;
    for row in rows {
        if has_page(&row) {
            continue;
        }
        let got = ensure_page(db, settings, project_id, &row, project);
        if has_page(&got) {
            n += 1;
        }
    }
    Ok(n)
}

fn row_get<'a>(row: &'a Obj, key: &str) -> &'a Value {
    row.get(key).unwrap_or(&Value::Null)
}

const REMEDIATION: &[(&str, &str, &str, &str)] = &[
    ("rce", "攻击者可能在目标进程权限范围内执行任意命令，并进一步读取数据、横向移动或持续控制。", "攻击者可访问对应输入点，且目标路径/解释器/执行条件满足。", "移除动态命令拼接；使用参数化 API 与严格 allowlist；关闭不必要执行能力；以最小权限运行服务并修补相关组件。"),
    ("command_injection", "攻击者可借助系统命令调用突破应用逻辑边界。", "可控输入进入 shell、命令解释器或不安全的子进程调用。", "避免 shell=True 与字符串拼接；使用参数数组调用；对输入采用 allowlist；限制子进程权限与网络访问。"),
    ("sqli", "可能读取、修改或删除数据库数据，并在特定配置下扩大到服务权限。", "可控参数进入 SQL 查询且未使用参数化绑定。", "使用预编译/参数化查询；移除拼接 SQL；收紧数据库账号权限；增加统一输入验证与异常审计。"),
    ("file_upload", "攻击者可能上传可执行或敏感文件，形成代码执行或数据覆盖风险。", "上传入口可访问，且服务端仅依赖文件名、MIME 或前端校验。", "对内容做服务端验证与重编码；上传目录置于 Web 根目录外；使用随机文件名、最小权限和下载白名单。"),
    ("auth_bypass", "攻击者可能绕过认证进入受保护功能或取得高权限会话。", "攻击者可触达认证流程、令牌校验或权限分支。", "统一服务端鉴权；校验令牌签名、有效期与受众；移除前端信任逻辑；为关键操作增加二次校验和审计。"),
    ("idor", "攻击者可能读取或修改其他用户/租户的对象。", "已认证低权限用户可构造或枚举对象标识。", "每次对象访问都在服务端执行主体、租户与对象级授权；避免以可枚举 ID 作为唯一控制。"),
];

pub fn finding_guidance(finding: &Obj) -> Obj {
    let cat = gstr(finding, "category").to_ascii_lowercase();
    let (impact, prerequisites, remediation) = REMEDIATION
        .iter()
        .find(|(k, _, _, _)| *k == cat)
        .map(|(_, a, b, c)| (*a, *b, *c))
        .unwrap_or((
            "影响以已验证证据为准；应结合关联资产与权限边界进行复核。",
            "攻击前置条件见验证证据、PoC 与关联节点。",
            "修复根因、限制攻击面、补充服务端校验，并在修复后使用相同证据路径回归验证。",
        ));
    let cvss = if finding.get("cvss").is_none_or(Value::is_null) {
        "CVSS 未提供；严重度由已验证的影响与可利用性综合判定。".to_string()
    } else {
        format!(
            "CVSS {}；分值应结合部署环境、权限与影响范围复核。",
            as_text(&finding["cvss"])
        )
    };
    let mut out = Obj::new();
    put(&mut out, "impact", impact);
    put(&mut out, "prerequisites", prerequisites);
    put(&mut out, "remediation", remediation);
    put(&mut out, "cvss_explanation", cvss);
    out
}

pub fn serialize_finding_full(
    row: &Obj,
    related_node: Option<&Obj>,
    related_edges: Option<&[Value]>,
) -> Obj {
    let sev = display_finding_severity(row);
    let st = {
        let s = gstr(row, "verification_status");
        if s.is_empty() {
            "verified".into()
        } else {
            s
        }
    };
    let mut out = Obj::new();
    for key in [
        "id",
        "project_id",
        "node_key",
        "category",
        "title",
        "description",
        "evidence",
        "poc_curl",
        "poc_python",
        "cvss",
        "created_at",
    ] {
        out.insert((*key).to_string(), row_get(row, key).clone());
    }
    put(&mut out, "severity", sev.clone());
    put(&mut out, "critical", sev == "critical");
    put(&mut out, "verification_status", st);
    for key in [
        "verified_at",
        "proof_type",
        "proof_canary",
        "proof_url",
        "proof_detail",
        "redteam_rating",
        "redteam_rating_rationale",
        "report_summary",
        "report_impact",
        "report_rating",
        "report_repro",
        "report_fix",
    ] {
        out.insert(key.to_string(), row_get(row, key).clone());
    }
    put(
        &mut out,
        "secondary_verified",
        truth(row_get(row, "secondary_verified")),
    );
    if let Some(node) = related_node {
        out.insert("related_node".into(), Value::Object(node.clone()));
    } else {
        out.insert("related_node".into(), Value::Null);
    }
    put(
        &mut out,
        "related_edges",
        related_edges.unwrap_or(&[]).to_vec(),
    );
    out
}

fn verify_label(st: &str, lang: Option<&str>) -> String {
    let s = if st.is_empty() { "verified" } else { st }.to_ascii_lowercase();
    let loc = i18n::normalize_locale(lang);
    let table: &[(&str, &str, &str)] = &[
        ("verified", "已验证", "Verified"),
        ("pending", "未验证 / 待复核", "Unverified / pending"),
        ("flaky", "不稳定（曾复现）", "Flaky (previously reproduced)"),
        ("rejected", "已驳回", "Rejected"),
        ("excluded", "二次验证失败", "Secondary verification failed"),
    ];
    if let Some((_, zh, en)) = table.iter().find(|(k, _, _)| *k == s) {
        return if loc == "en" {
            (*en).to_string()
        } else {
            (*zh).to_string()
        };
    }
    let intel = lab("intel", Some(loc), &[]);
    if !intel.is_empty() {
        intel
    } else {
        s
    }
}

pub fn exclusion_reason(finding: &Obj) -> String {
    let why = gstr(finding, "redteam_rating_rationale").trim().to_string();
    if !why.is_empty() {
        why
    } else {
        gstr(finding, "proof_detail").trim().to_string()
    }
}

fn secondary_failed(finding: &Obj) -> bool {
    gstr(finding, "verification_status").to_ascii_lowercase() == "excluded"
}

fn has_verified_body(finding: &Obj) -> bool {
    [
        "description",
        "evidence",
        "proof_detail",
        "poc_curl",
        "poc_python",
        "redteam_rating_rationale",
        "report_summary",
        "report_impact",
        "report_rating",
        "report_repro",
        "report_fix",
    ]
    .iter()
    .any(|k| !gstr(finding, k).trim().is_empty())
}

fn page_state(finding: &Obj, settings: Option<&Settings>) -> String {
    let need_sec = secondary_on(settings);
    let sec = gbool(finding, "secondary_verified");
    let failed = secondary_failed(finding);
    if need_sec && !sec && !failed {
        return "pending".into();
    }
    if has_page(finding) || ((sec || failed) && has_verified_body(finding)) {
        "ready".into()
    } else {
        "writing".into()
    }
}

fn apply_verified_facts(out: &mut Obj) {
    let clean = |v: &str| v.trim().to_string();
    if clean(&gstr(out, "report_summary")).is_empty() {
        let s = clean(&gstr(out, "description"));
        let s = if s.is_empty() {
            clean(&gstr(out, "title"))
        } else {
            s
        };
        put(out, "report_summary", s);
    }
    if clean(&gstr(out, "report_impact")).is_empty() {
        let s = clean(&gstr(out, "evidence"));
        let s = if s.is_empty() {
            clean(&gstr(out, "proof_detail"))
        } else {
            s
        };
        put(out, "report_impact", s);
    }
    if clean(&gstr(out, "report_rating")).is_empty() {
        let mut rating = clean(&gstr(out, "redteam_rating_rationale"));
        if rating.is_empty() && !clean(&gstr(out, "redteam_rating")).is_empty() {
            rating = format!("NVD CVSS 3.1：{}", clean(&gstr(out, "redteam_rating")));
        }
        put(out, "report_rating", rating);
    }
    if clean(&gstr(out, "report_repro")).is_empty() {
        let parts = [
            clean(&gstr(out, "proof_detail")),
            clean(&gstr(out, "poc_curl")),
            clean(&gstr(out, "poc_python")),
        ];
        let joined = parts
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        put(out, "report_repro", joined);
    }
}

pub fn prepare_finding_report(
    finding: &Obj,
    poc: Option<&Obj>,
    progress: Option<&str>,
    settings: Option<&Settings>,
) -> Obj {
    let _ = poc;
    let mut out = finding.clone();
    let mut state = page_state(&out, settings);
    if state == "writing" && progress == Some("failed") {
        state = "failed".into();
    }
    if state == "ready" {
        apply_verified_facts(&mut out);
    }
    put(&mut out, "report_state", state.clone());
    put(&mut out, "report_pending", state != "ready");
    let failed = secondary_failed(&out);
    if failed {
        let reason = exclusion_reason(&out);
        put(&mut out, "exclusion_reason", reason);
    }
    if state != "ready" {
        let note = if state == "writing" {
            WRITING_COPY
        } else if state == "failed" {
            FAILED_COPY
        } else {
            PENDING_COPY
        };
        put(&mut out, "impact_detail", note);
        put(&mut out, "impact", note);
        put(&mut out, "secondary_review", note);
        put(&mut out, "manual_repro", note);
        put(&mut out, "manual_steps", Vec::<String>::new());
        put(&mut out, "remediation", note);
        return out;
    }
    let summary = gstr(&out, "report_summary").trim().to_string();
    let impact = gstr(&out, "report_impact").trim().to_string();
    let rating = gstr(&out, "report_rating").trim().to_string();
    let repro = gstr(&out, "report_repro").trim().to_string();
    let fix = gstr(&out, "report_fix").trim().to_string();
    if !summary.is_empty() {
        put(&mut out, "description", summary);
    }
    if !impact.is_empty() {
        put(&mut out, "impact_detail", impact.clone());
        put(&mut out, "impact", impact);
    }
    if !rating.is_empty() {
        put(&mut out, "secondary_review", rating);
    }
    if !repro.is_empty() {
        put(&mut out, "manual_repro", repro.clone());
        let steps: Vec<String> = repro
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        put(&mut out, "manual_steps", steps);
    } else {
        put(&mut out, "manual_repro", "");
        put(&mut out, "manual_steps", Vec::<String>::new());
    }
    put(&mut out, "remediation", fix);
    out
}

pub fn manual_verification_steps(finding: &Obj, poc: Option<&Obj>) -> Vec<String> {
    manual_reproduction_steps(finding, poc)
}

fn md_block(text: &str, empty: &str) -> Vec<String> {
    let t = text.trim();
    if t.is_empty() {
        vec![empty.to_string(), String::new()]
    } else {
        vec![t.to_string(), String::new()]
    }
}

pub fn render_finding_markdown(
    project: Option<&Obj>,
    finding: &Obj,
    poc: Option<&Obj>,
    heading: &str,
    lang: Option<&str>,
    progress: Option<&str>,
    settings: Option<&Settings>,
) -> String {
    let loc = i18n::normalize_locale(lang);
    let (
        cat_l,
        status_l,
        id_l,
        summary_l,
        impact_l,
        rating_l,
        repro_l,
        fix_l,
        uncat,
        why_l,
        why_empty,
        empty,
        no_poc,
        no_synth,
    ) = if loc == "en" {
        (
            "Category",
            "Verification",
            "Finding ID",
            "Summary",
            "Impact",
            "Red-team rating",
            "Manual reproduction",
            "Remediation",
            "Uncategorized",
            "Why secondary verification failed",
            "The secondary-verification failure reason was not written.",
            "_Not collected_",
            "_No executable PoC collected (no real poc_curl / poc_python)._",
            "_The system refused to synthesize an exploit script for a high/critical item._",
        )
    } else {
        (
            "类别",
            "验证状态",
            "漏洞 ID",
            "漏洞简介",
            "危害",
            "NVD CVSS 3.1",
            "手动复现",
            "修复方式",
            "未分类",
            "二次验证失败原因",
            "二次验证失败原因没有写入。",
            "_未采集_",
            "_未采集可执行 PoC（无真实 poc_curl / poc_python）。_",
            "_系统拒绝为高危项合成假利用脚本。_",
        )
    };
    let target = project.map(|p| gstr(p, "target")).unwrap_or_default();
    let poc_owned = if poc.is_none() {
        Some(poc_for_finding(finding, &target))
    } else {
        None
    };
    let poc = poc.or(poc_owned.as_ref());
    let finding = prepare_finding_report(finding, poc, progress, settings);
    let sev = display_finding_severity(&finding).to_ascii_uppercase();
    let cat = gstr(&finding, "category");
    let title = {
        let t = gstr(&finding, "title");
        if !t.is_empty() {
            t
        } else {
            let id = gstr(&finding, "id");
            if id.is_empty() {
                "finding".into()
            } else {
                id
            }
        }
    };
    let vs = {
        let s = gstr(&finding, "verification_status");
        if s.is_empty() {
            "verified".into()
        } else {
            s
        }
    };
    let h2 = if heading.is_empty() {
        "##".to_string()
    } else {
        format!("{heading}#")
    };
    let mut lines = vec![
        format!("{heading} [{sev}] {title}"),
        String::new(),
        format!(
            "- {cat_l}: `{}`",
            if cat.is_empty() { uncat } else { cat.as_str() }
        ),
        format!("- {status_l}: **{}**", verify_label(&vs, Some(loc))),
        format!("- {id_l}: `{}`", gstr(&finding, "id")),
        String::new(),
        format!("{h2} {summary_l}"),
        String::new(),
    ];
    let ready = gstr(&finding, "report_state") == "ready";
    let note = gstr(&finding, "impact_detail").trim().to_string();
    if ready {
        let body = {
            let d = gstr(&finding, "description");
            if d.trim().is_empty() {
                gstr(&finding, "title")
            } else {
                d
            }
        };
        lines.extend(md_block(&body, empty));
    } else {
        lines.extend(md_block(&note, empty));
    }
    lines.push(format!("{h2} {impact_l}"));
    lines.push(String::new());
    if ready {
        let body = {
            let d = gstr(&finding, "impact_detail");
            if d.trim().is_empty() {
                gstr(&finding, "impact")
            } else {
                d
            }
        };
        lines.extend(md_block(&body, empty));
    } else {
        lines.extend(md_block(&note, empty));
    }
    lines.push(format!("{h2} {rating_l}"));
    lines.push(String::new());
    if ready {
        let body = {
            let d = gstr(&finding, "secondary_review");
            if d.trim().is_empty() {
                redteam_rating_block(&finding)
            } else {
                d
            }
        };
        lines.extend(md_block(&body, empty));
    } else {
        lines.extend(md_block(&note, empty));
    }
    lines.push(format!("{h2} {repro_l}"));
    lines.push(String::new());
    if ready {
        let repro = gstr(&finding, "manual_repro").trim().to_string();
        if !repro.is_empty() {
            lines.extend(md_block(&repro, empty));
        } else if let Some(Value::Array(steps)) = finding.get("manual_steps") {
            if steps.is_empty() {
                lines.extend(md_block("", empty));
            } else {
                for s in steps {
                    lines.push(as_text(s));
                }
            }
        } else {
            lines.extend(md_block("", empty));
        }
        let poc_curl = poc.map(|p| gstr(p, "curl")).unwrap_or_default();
        let poc_py = poc.map(|p| gstr(p, "python")).unwrap_or_default();
        let raw_curl = {
            let a = poc_curl.trim();
            if !a.is_empty() {
                a.to_string()
            } else {
                gstr(&finding, "poc_curl").trim().to_string()
            }
        };
        let raw_py = {
            let a = poc_py.trim();
            if !a.is_empty() {
                a.to_string()
            } else {
                gstr(&finding, "poc_python").trim().to_string()
            }
        };
        let curl = real_poc_text(&raw_curl);
        let py = real_poc_text(&raw_py);
        if !curl.is_empty() {
            lines.extend([format!("```bash"), curl, "```".into(), String::new()]);
        }
        if !py.is_empty() {
            lines.extend(["```python".into(), py, "```".into(), String::new()]);
        }
        if curl_is_empty(&raw_curl) && py_is_empty(&raw_py) {
            lines.push(no_poc.into());
            lines.push(String::new());
            if !raw_curl.is_empty() || !raw_py.is_empty() {
                lines.push(no_synth.into());
            }
        }
    } else {
        lines.extend(md_block(&note, empty));
    }
    lines.push(format!("{h2} {fix_l}"));
    lines.push(String::new());
    if ready {
        let body = {
            let d = gstr(&finding, "remediation");
            if d.trim().is_empty() {
                gstr(&finding, "report_fix")
            } else {
                d
            }
        };
        lines.extend(md_block(&body, empty));
    } else {
        lines.extend(md_block(&note, empty));
    }
    if secondary_failed(&finding) {
        lines.push(format!("{h2} {why_l}"));
        lines.push(String::new());
        lines.extend(md_block(&exclusion_reason(&finding), why_empty));
    }
    lines.join("\n")
}

fn curl_is_empty(raw: &str) -> bool {
    real_poc_text(raw).is_empty()
}
fn py_is_empty(raw: &str) -> bool {
    real_poc_text(raw).is_empty()
}

pub fn is_reportable_finding(row: &Obj) -> bool {
    let st = {
        let s = gstr(row, "verification_status");
        if s.is_empty() {
            "verified".into()
        } else {
            s
        }
    };
    st.to_ascii_lowercase() != "rejected"
}

fn rl(key: &str) -> String {
    lab(key, None, &[])
}

fn rlv(key: &str, vars: &[(&str, &str)]) -> String {
    lab(key, None, vars)
}

const NODE_FILL: &[(&str, &str)] = &[
    ("target", "#141413"),
    ("info", "#8e8b82"),
    ("service", "#5db8a6"),
    ("danger", "#f08c2a"),
    ("vuln", "#c64545"),
    ("credential", "#a9583e"),
    ("foothold", "#cc785c"),
    ("honeypot", "#6c6a64"),
    ("goal", "#f23636"),
];
const NODE_LABEL: &[(&str, &str)] = &[
    ("target", "目标"),
    ("info", "信息"),
    ("service", "服务"),
    ("danger", "危险点"),
    ("vuln", "漏洞"),
    ("credential", "凭证"),
    ("foothold", "立足点"),
    ("honeypot", "蜜罐"),
    ("goal", "GETSHELL"),
];
const COL_X: &[(&str, f64)] = &[
    ("target", 90.0),
    ("info", 250.0),
    ("service", 250.0),
    ("honeypot", 250.0),
    ("danger", 430.0),
    ("credential", 430.0),
    ("vuln", 610.0),
    ("foothold", 790.0),
    ("goal", 970.0),
];
const SEV_COLOR: &[(&str, &str)] = &[
    ("critical", "#c64545"),
    ("high", "#cc785c"),
    ("medium", "#d4a017"),
    ("low", "#5db8a6"),
    ("info", "#8e8b82"),
];
const THEME_INK: &str = "#243044";
const THEME_BODY: &str = "#4a5a6e";
const THEME_MUTED: &str = "#8b97a8";
const THEME_CANVAS: &str = "#f4f7fc";
const THEME_SOFT: &str = "#f7f9fd";
const THEME_PRIMARY: &str = "#4c7dff";

fn fill_of(typ: &str) -> &str {
    NODE_FILL
        .iter()
        .find(|(k, _)| *k == typ)
        .map(|(_, v)| *v)
        .unwrap_or(THEME_MUTED)
}

fn svg_esc(s: &str) -> String {
    esc(s, true)
}

pub fn report_css() -> String {
    r#":root {
  --primary: #4c7dff; --primary-active: #3a63d8;
  --ink: #243044; --body: #4a5a6e; --muted: #8b97a8;
  --hairline: #e6edf5; --canvas: #f4f7fc;
  --surface-soft: #f7f9fd; --surface-card: #ffffff;
  --surface-dark: #eef4ff; --on-dark: #243044;
  --accent-teal: #3ecf8e; --accent-amber: #f5b942;
  --success: #22a06b; --warning: #d4a017; --error: #c64545;
  --high: #cc785c; --low: #5db8a6; --info: #8e8b82;
  --goal: #f23636;
  --font-serif: "Noto Serif CJK SC","Noto Serif SC","EB Garamond",Georgia,serif;
  --font-sans: "Noto Sans CJK SC","Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  --font-mono: ui-monospace,"Cascadia Mono","Segoe UI Mono",Consolas,monospace;
}
* { box-sizing: border-box; }
body {
  margin: 0; color: var(--ink);
  background:
    radial-gradient(900px 420px at 8% -10%, rgba(196,214,255,.55), transparent 60%),
    radial-gradient(800px 380px at 100% 0%, rgba(232,220,255,.45), transparent 55%),
    var(--canvas);
  font-family: var(--font-sans); line-height: 1.6; padding: 0;
}
.report-hero {
  background: var(--surface-dark); color: var(--on-dark);
  padding: 36px 48px 28px; border-bottom: 4px solid var(--primary);
}
.report-hero h1 {
  font-family: var(--font-serif); font-weight: 400; font-size: 34px;
  letter-spacing: -.5px; margin: 0 0 8px;
}
.report-hero .meta { color: var(--muted); font-size: 14px; }
.report-hero .meta code { color: var(--accent-amber); }
.kpi-row { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }
.kpi {
  background: #fff; border: 1px solid var(--hairline); border-radius: 999px;
  padding: 6px 14px; font-size: 13px; color: var(--ink);
}
.kpi b { color: var(--primary); font-weight: 600; }
.wrap { padding: 32px 48px 64px; max-width: 1080px; margin: 0 auto; }
h2 {
  font-family: var(--font-serif); font-weight: 400; font-size: 24px;
  border-bottom: 1px solid var(--hairline); padding-bottom: 8px; margin: 36px 0 14px;
}
h3 { font-size: 18px; margin: 22px 0 8px; }
h4 { font-size: 14px; color: var(--body); margin: 14px 0 6px; }
.figure {
  background: #fff; border: 1px solid var(--hairline); border-radius: 14px;
  padding: 16px; margin: 14px 0 22px; overflow-x: auto;
}
.figure figcaption {
  font-size: 12px; color: var(--muted); margin-top: 8px; text-align: center;
}
.charts { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 860px) { .charts { grid-template-columns: 1fr; } .wrap, .report-hero { padding-left: 20px; padding-right: 20px; } }
.card {
  background: var(--surface-card); border-radius: 12px; padding: 16px 18px; margin: 12px 0;
  border-left: 5px solid var(--primary);
}
.card.crit { border-left-color: var(--error); }
.card.high { border-left-color: var(--high); }
.badge {
  font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
  padding: 3px 10px; border-radius: 999px; color: #fff; background: var(--muted);
}
.b-critical { background: var(--error); }
.b-high { background: var(--high); color: #fff; }
.b-medium { background: var(--warning); color: #243044; }
.b-low { background: var(--low); }
.b-info { background: var(--info); }
pre {
  background: #eef3fb; color: var(--ink); border: 1px solid var(--hairline); padding: 14px;
  border-radius: 8px; overflow-x: auto; font-family: var(--font-mono); font-size: 12.5px;
  white-space: pre-wrap;
}
code { font-family: var(--font-mono); font-size: 0.92em; }
.vuln-body { white-space: pre-wrap; font-size: 14px; margin: 0 0 10px; }
ol.repro li { margin: 8px 0; white-space: pre-wrap; }
.legend { display: flex; flex-wrap: wrap; gap: 10px 16px; font-size: 12px; color: var(--muted); margin: 8px 0; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }
.foot { margin-top: 48px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--hairline); padding-top: 16px; }
.claude-body img { max-width: 100%; border-radius: 8px; }
.claude-body table { width: 100%; border-collapse: collapse; font-size: 13px; }
.claude-body th, .claude-body td { padding: 8px; border-bottom: 1px solid var(--hairline); text-align: left; }"#
        .trim()
        .to_string()
}

fn empty_svg(msg: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 120" width="100%"><rect width="640" height="120" fill="{THEME_SOFT}"/><text x="320" y="66" text-anchor="middle" fill="{THEME_MUTED}" font-size="14">{}</text></svg>"#,
        svg_esc(msg)
    )
}

fn edge_ends(e: &Obj) -> (String, String) {
    let frm = {
        let a = gstr(e, "from");
        if a.is_empty() {
            gstr(e, "src")
        } else {
            a
        }
    };
    let to = {
        let a = gstr(e, "to");
        if a.is_empty() {
            gstr(e, "dst")
        } else {
            a
        }
    };
    (frm, to)
}

fn starts_with_any(s: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| s.starts_with(p))
}

pub fn graph_svg(graph: &Obj, max_nodes: usize) -> String {
    let mut nodes = obj_list(graph, "nodes");
    let edges = obj_list(graph, "edges");
    if nodes.is_empty() {
        return empty_svg("攻击图暂无节点");
    }
    let pri = |t: &str| match t {
        "goal" => 0,
        "vuln" => 1,
        "foothold" => 2,
        "danger" => 3,
        "target" => 4,
        "credential" => 5,
        "service" => 6,
        _ => 9,
    };
    nodes.sort_by(|a, b| {
        pri(&gstr(a, "type")).cmp(&pri(&gstr(b, "type"))).then(
            gfloat(b, "risk_score")
                .partial_cmp(&gfloat(a, "risk_score"))
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    if nodes.len() > max_nodes {
        nodes.truncate(max_nodes);
    }
    let mut buckets: Vec<(String, Vec<Obj>)> = Vec::new();
    for n in nodes {
        let typ = {
            let t = gstr(&n, "type");
            if t.is_empty() {
                "info".into()
            } else {
                t
            }
        };
        let node = (*n).clone();
        if let Some((_, group)) = buckets.iter_mut().find(|(k, _)| k == &typ) {
            group.push(node);
        } else {
            buckets.push((typ, vec![node]));
        }
    }
    let mut pos: HashMap<String, (f64, f64)> = HashMap::new();
    let mut max_y = 80.0f64;
    let mut flat: Vec<Obj> = Vec::new();
    for (typ, group) in &buckets {
        let x = COL_X
            .iter()
            .find(|(k, _)| *k == typ)
            .map(|(_, v)| *v)
            .unwrap_or(520.0);
        for (i, n) in group.iter().enumerate() {
            let y = 56.0 + i as f64 * 46.0;
            pos.insert(gstr(n, "key"), (x, y));
            max_y = max_y.max(y);
            flat.push(n.clone());
        }
    }
    let w = 1080i64;
    let h = (max_y + 70.0) as i64;
    let mut parts = vec![
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%" style="background:{THEME_CANVAS};font-family:system-ui,sans-serif">"#
        ),
        format!(r#"<rect width="{w}" height="{h}" fill="{THEME_CANVAS}"/>"#),
    ];
    for e in &edges {
        let (frm, to) = edge_ends(e);
        let Some(&a) = pos.get(&frm) else { continue };
        let Some(&b) = pos.get(&to) else { continue };
        let rel = gstr(e, "relation");
        let why = gstr(e, "rationale").to_ascii_lowercase();
        let hop = rel == "LEADS_TO"
            && (why.contains("pivot_capability")
                || (frm.starts_with("vuln:")
                    && starts_with_any(&to, &["info:host:", "info:scope-expanded:", "target:"]))
                || (starts_with_any(&to, &["info:host:", "info:scope-expanded:"])
                    && starts_with_any(&frm, &["foothold:", "goal:shell"])));
        let col = if rel == "PIVOTS_TO" || hop {
            "#6d5cf0"
        } else if gbool(e, "on_rce_path") || rel == "EXPLOITS" || rel == "ESCALATES_TO" {
            THEME_PRIMARY
        } else {
            "#d5deea"
        };
        let sw = if col == "#d5deea" { 1.2 } else { 2.4 };
        parts.push(format!(
            r#"<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="{col}" stroke-width="{sw}" stroke-opacity=".85"/>"#,
            a.0, a.1, b.0, b.1
        ));
    }
    for n in &flat {
        let k = gstr(n, "key");
        let Some(&(x, y)) = pos.get(&k) else { continue };
        let typ = {
            let t = gstr(n, "type");
            if t.is_empty() {
                "info".into()
            } else {
                t
            }
        };
        let fill = fill_of(&typ);
        let mut title = {
            let t = gstr(n, "title");
            if t.is_empty() {
                k
            } else {
                t
            }
        };
        if title.chars().count() > 16 {
            title = format!("{}…", take_chars(&title, 15));
        }
        let r = 8.0 + (gfloat(n, "risk_score") / 12.0).min(10.0);
        parts.push(format!(r##"<circle cx="{x}" cy="{y}" r="{r:.1}" fill="{fill}" stroke="#fff" stroke-width="2"/>"##));
        parts.push(format!(
            r#"<text x="{x}" y="{}" text-anchor="middle" font-size="10" fill="{THEME_BODY}">{}</text>"#,
            y + r + 12.0,
            svg_esc(&title)
        ));
    }
    let mut lx = 24i64;
    for (typ, label) in [
        ("target", "目标"),
        ("service", "服务"),
        ("danger", "危险点"),
        ("vuln", "漏洞"),
        ("foothold", "立足点"),
        ("goal", "GETSHELL"),
    ] {
        parts.push(format!(
            r#"<circle cx="{lx}" cy="{}" r="5" fill="{}"/>"#,
            h - 18,
            fill_of(typ)
        ));
        parts.push(format!(
            r#"<text x="{}" y="{}" font-size="10" fill="{THEME_MUTED}">{label}</text>"#,
            lx + 10,
            h - 14
        ));
        lx += 88;
    }
    parts.push("</svg>".into());
    parts.join("")
}

pub fn severity_bar_svg(findings: &[Obj]) -> String {
    let order = ["critical", "high", "medium", "low", "info"];
    let mut counts = HashMap::new();
    for f in findings {
        *counts.entry(display_finding_severity(f)).or_insert(0i64) += 1;
    }
    let total = order
        .iter()
        .map(|s| counts.get(*s).copied().unwrap_or(0))
        .sum::<i64>()
        .max(1) as f64;
    let (w, h) = (480, 168);
    let mut parts = vec![
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%"><rect width="{w}" height="{h}" fill="#fff"/>"##
        ),
        format!(r#"<text x="16" y="22" font-size="13" fill="{THEME_INK}">漏洞严重度分布</text>"#),
    ];
    for (i, sev) in order.iter().enumerate() {
        let n = counts.get(*sev).copied().unwrap_or(0);
        let bw = (n as f64 / total) * 320.0;
        let y = 40 + i * 24;
        let col = SEV_COLOR
            .iter()
            .find(|(k, _)| k == sev)
            .map(|(_, c)| *c)
            .unwrap_or(THEME_MUTED);
        parts.push(format!(
            r#"<text x="16" y="{}" font-size="11" fill="{THEME_MUTED}">{sev}</text>"#,
            y + 12
        ));
        parts.push(format!(
            r#"<rect x="88" y="{y}" width="320" height="14" rx="7" fill="{THEME_SOFT}"/>"#
        ));
        parts.push(format!(
            r#"<rect x="88" y="{y}" width="{bw:.1}" height="14" rx="7" fill="{col}"/>"#
        ));
        parts.push(format!(
            r#"<text x="418" y="{}" font-size="11" fill="{THEME_BODY}">{n}</text>"#,
            y + 12
        ));
    }
    parts.push("</svg>".into());
    parts.join("")
}

pub fn type_bar_svg(graph: &Obj) -> String {
    let mut counts: HashMap<String, i64> = HashMap::new();
    for n in obj_list(graph, "nodes") {
        let t = {
            let s = gstr(&n, "type");
            if s.is_empty() {
                "info".into()
            } else {
                s
            }
        };
        *counts.entry(t).or_insert(0) += 1;
    }
    let types: Vec<&str> = [
        "target",
        "service",
        "danger",
        "vuln",
        "credential",
        "foothold",
        "goal",
        "info",
    ]
    .into_iter()
    .filter(|t| counts.get(*t).copied().unwrap_or(0) > 0)
    .collect();
    if types.is_empty() {
        return empty_svg("暂无节点类型统计");
    }
    let total = types
        .iter()
        .map(|t| counts.get(*t).copied().unwrap_or(0))
        .sum::<i64>()
        .max(1) as f64;
    let w = 480i64;
    let h = 36 + 24 * types.len() as i64;
    let mut parts = vec![
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%"><rect width="{w}" height="{h}" fill="#fff"/>"##
        ),
        format!(r#"<text x="16" y="22" font-size="13" fill="{THEME_INK}">攻击图节点类型</text>"#),
    ];
    for (i, typ) in types.iter().enumerate() {
        let n = counts.get(*typ).copied().unwrap_or(0);
        let bw = (n as f64 / total) * 300.0;
        let y = 40 + i * 24;
        let label = NODE_LABEL
            .iter()
            .find(|(k, _)| k == typ)
            .map(|(_, v)| *v)
            .unwrap_or(typ);
        parts.push(format!(
            r#"<text x="16" y="{}" font-size="11" fill="{THEME_MUTED}">{}</text>"#,
            y + 12,
            svg_esc(label)
        ));
        parts.push(format!(
            r#"<rect x="88" y="{y}" width="300" height="14" rx="7" fill="{THEME_SOFT}"/>"#
        ));
        parts.push(format!(
            r#"<rect x="88" y="{y}" width="{bw:.1}" height="14" rx="7" fill="{}"/>"#,
            fill_of(typ)
        ));
        parts.push(format!(
            r#"<text x="400" y="{}" font-size="11" fill="{THEME_BODY}">{n}</text>"#,
            y + 12
        ));
    }
    parts.push("</svg>".into());
    parts.join("")
}

pub fn rce_path_svg(graph: &Obj) -> String {
    let path = graph
        .get("rce_path")
        .and_then(Value::as_object)
        .and_then(|p| p.get("path"))
        .and_then(Value::as_array)
        .map(|a| a.iter().map(as_text).collect::<Vec<_>>())
        .unwrap_or_default();
    if path.len() < 2 {
        return String::new();
    }
    let by_key: HashMap<String, Obj> = obj_list(graph, "nodes")
        .into_iter()
        .map(|n| (gstr(&n, "key"), (*n).clone()))
        .collect();
    let w = (40 + path.len() as i64 * 130).max(420);
    let h = 86;
    let mut parts = vec![
        format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%"><rect width="{w}" height="{h}" fill="#fff"/>"##
        ),
        format!(r#"<text x="16" y="18" font-size="12" fill="{THEME_MUTED}">RCE 最优路径</text>"#),
    ];
    let mut arrows = Vec::new();
    for (i, k) in path.iter().enumerate() {
        let x = 24 + i as i64 * 130;
        let n = by_key.get(k);
        let typ = n.map(|n| gstr(n, "type")).unwrap_or_else(|| "info".into());
        let fill = if n.is_some() {
            fill_of(&typ)
        } else {
            THEME_PRIMARY
        };
        let mut title = n
            .map(|n| gstr(n, "title"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| k.clone());
        if title.chars().count() > 12 {
            title = format!("{}…", take_chars(&title, 11));
        }
        parts.push(format!(
            r#"<rect x="{x}" y="32" width="110" height="36" rx="8" fill="{fill}"/>"#
        ));
        parts.push(format!(
            r##"<text x="{}" y="54" text-anchor="middle" font-size="11" fill="#fff">{}</text>"##,
            x + 55,
            svg_esc(&title)
        ));
        if i + 1 < path.len() {
            arrows.push(format!(
                r#"<path d="M{} 50 L{} 50" stroke="{THEME_PRIMARY}" stroke-width="2" marker-end="url(#arr)"/>"#,
                x + 114,
                x + 126
            ));
        }
    }
    parts.extend(arrows);
    parts.insert(
        2,
        format!(
            r#"<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="{THEME_PRIMARY}"/></marker></defs>"#
        ),
    );
    parts.push("</svg>".into());
    parts.join("")
}

const WIDE_CSS: &str = r#"
@media print, all {
  @page { size: 1280px 1810px; margin: 28px 36px 40px 36px; }
  html, body {
    print-color-adjust: exact;
    -webkit-print-color-adjust: exact;
  }
  .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .kpis { grid-template-columns: repeat(4, 1fr) !important; }
  .sum-grid, .charts, .fix-grid { grid-template-columns: 1fr 1fr !important; }
  .assets { grid-template-columns: repeat(3, 1fr) !important; }
  .path-row { flex-wrap: nowrap !important; }
  details.ev > *:not(summary) { display: block !important; }
}
"#;

pub fn adapt_html_for_pdf(html: &str) -> String {
    let mut out = html.replace("<details>", "<details open>");
    out = out.replace("<details ", "<details open ");
    out = out.replace("（点击展开）", "");
    out = out.replace("（点击折叠）", "");
    if out.contains("</style>") {
        out = out.replacen("</style>", &format!("{WIDE_CSS}\n</style>"), 1);
    } else {
        out = out.replacen("</head>", &format!("<style>{WIDE_CSS}</style></head>"), 1);
    }
    out
}

fn chromium_bin() -> Option<String> {
    for name in [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
    ] {
        if let Some(p) = which(name) {
            return Some(p.display().to_string());
        }
    }
    None
}

pub fn chromium_pdf(html: &str) -> Option<Vec<u8>> {
    let binary = chromium_bin()?;
    let td = std::env::temp_dir().join(format!("atkbrain-pdf-{}", new_id("")));
    std::fs::create_dir_all(&td).ok()?;
    let src = td.join("report.html");
    let dest = td.join("report.pdf");
    let cleanup = |dir: &Path| {
        let _ = std::fs::remove_dir_all(dir);
    };
    if std::fs::write(&src, html.as_bytes()).is_err() {
        cleanup(&td);
        return None;
    }
    let cmd = [
        binary.as_str(),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--allow-file-access-from-files",
        "--no-pdf-header-footer",
    ];
    let print = format!("--print-to-pdf={}", dest.display());
    let uri = file_uri(&src);
    let mut child = match std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .arg(&print)
        .arg("--virtual-time-budget=12000")
        .arg(&uri)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => {
            cleanup(&td);
            return None;
        }
    };
    let started = Instant::now();
    let status = loop {
        if started.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            cleanup(&td);
            return None;
        }
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => {
                cleanup(&td);
                return None;
            }
        }
    };
    if !status.success() {
        cleanup(&td);
        return None;
    }
    let bytes = std::fs::read(&dest).ok().filter(|b| b.len() > 100);
    cleanup(&td);
    bytes
}

pub fn weasy_pdf(_html: &str) -> Option<Vec<u8>> {
    None
}

pub fn html_to_pdf(html: &str) -> Result<Vec<u8>, String> {
    let adapted = adapt_html_for_pdf(html);
    if let Some(pdf) = chromium_pdf(&adapted) {
        return Ok(pdf);
    }
    if let Some(pdf) = weasy_pdf(&adapted) {
        return Ok(pdf);
    }
    Err("PDF 引擎不可用：未找到 Chromium，且 WeasyPrint 失败".into())
}

pub fn render_pdf(html: &str) -> Option<Vec<u8>> {
    weasy_pdf(html)
}

fn ports_of(project: Option<&Obj>) -> Vec<Value> {
    let Some(project) = project else {
        return Vec::new();
    };
    if let Some(Value::Array(p)) = project.get("ports") {
        return p.clone();
    }
    if let Some(cfg) = project.get("config").and_then(Value::as_object) {
        if let Some(Value::Array(p)) = cfg.get("ports") {
            return p.clone();
        }
    }
    Vec::new()
}

fn detail_text(detail: &Value) -> String {
    match detail {
        Value::String(s) => s.clone(),
        Value::Object(o) => o
            .iter()
            .take(6)
            .map(|(k, v)| format!("{k}={}", as_text(v)))
            .collect::<Vec<_>>()
            .join(", "),
        Value::Null => String::new(),
        other => as_text(other),
    }
}

fn assets_of(project: Option<&Obj>, graph: &Obj) -> Vec<Obj> {
    let mut assets = Vec::new();
    let mut seen = HashSet::new();
    let target = project.map(|p| gstr(p, "target")).unwrap_or_default();
    let ports = ports_of(project);
    if !target.is_empty() {
        let key = format!("target:{target}");
        seen.insert(key.clone());
        let detail = if ports.is_empty() {
            "全端口/默认".to_string()
        } else {
            format!(
                "端口 {}",
                ports.iter().map(as_text).collect::<Vec<_>>().join(", ")
            )
        };
        let mut a = Obj::new();
        put(&mut a, "key", key);
        put(&mut a, "kind", "target");
        put(&mut a, "title", target.clone());
        put(&mut a, "detail", detail);
        assets.push(a);
    }
    for n in obj_list(graph, "nodes") {
        let ntype = gstr(&n, "type");
        if !matches!(ntype.as_str(), "target" | "service" | "endpoint" | "host") {
            continue;
        }
        let key = gstr(&n, "key");
        if key.is_empty() || seen.contains(&key) {
            continue;
        }
        if ntype == "target" && !target.is_empty() && key.contains(&target) {
            continue;
        }
        seen.insert(key.clone());
        let title = {
            let t = gstr(&n, "title");
            if t.is_empty() {
                key.clone()
            } else {
                t
            }
        };
        let detail = take_chars(&detail_text(n.get("detail").unwrap_or(&Value::Null)), 200);
        let mut a = Obj::new();
        put(&mut a, "key", key);
        put(&mut a, "kind", ntype);
        put(&mut a, "title", title);
        put(&mut a, "detail", detail);
        assets.push(a);
    }
    assets
}

fn findings_sorted(findings: Vec<Obj>) -> Vec<Obj> {
    let mut out = Vec::new();
    for mut item in findings {
        let sev = display_finding_severity(&item);
        put(&mut item, "critical", sev == "critical");
        put(&mut item, "severity", sev);
        out.push(item);
    }
    out.sort_by(|a, b| sev_rank(&gstr(b, "severity")).cmp(&sev_rank(&gstr(a, "severity"))));
    out
}

fn criticals_from(findings: &[Obj], graph: &Obj) -> Vec<Obj> {
    let criticals: Vec<Obj> = findings
        .iter()
        .filter(|f| matches!(display_finding_severity(f).as_str(), "high" | "critical"))
        .cloned()
        .collect();
    if !criticals.is_empty() {
        return criticals;
    }
    let mut nodes = obj_list(graph, "nodes");
    nodes.sort_by(|a, b| {
        gfloat(b, "risk_score")
            .partial_cmp(&gfloat(a, "risk_score"))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut out = Vec::new();
    for n in nodes {
        let sev = {
            let s = gstr(&n, "severity");
            if s.is_empty() {
                "info".into()
            } else {
                s
            }
        };
        if gbool(&n, "is_rce") || sev_rank(&sev) >= sev_rank("high") {
            let tags = n.get("tags").and_then(Value::as_array);
            let category = tags
                .and_then(|t| t.first())
                .map(as_text)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let t = gstr(&n, "type");
                    if t.is_empty() {
                        "vuln".into()
                    } else {
                        t
                    }
                });
            let title = {
                let t = gstr(&n, "title");
                if !t.is_empty() {
                    t
                } else {
                    gstr(&n, "key")
                }
            };
            let description = match n.get("detail") {
                Some(Value::String(s)) => Value::String(s.clone()),
                _ => Value::Null,
            };
            let mut item = Obj::new();
            put(
                &mut item,
                "severity",
                if gbool(&n, "is_rce") {
                    "critical".into()
                } else {
                    sev
                },
            );
            put(&mut item, "category", category);
            put(&mut item, "title", title);
            put(&mut item, "node_key", g(&n, "key"));
            item.insert("description".into(), description);
            item.insert("evidence".into(), Value::Null);
            item.insert("poc_curl".into(), Value::Null);
            item.insert("poc_python".into(), Value::Null);
            item.insert("cvss".into(), Value::Null);
            put(&mut item, "critical", true);
            out.push(item);
        }
    }
    out
}

fn vulns_by_asset(findings: &[Obj], assets: &[Obj]) -> Vec<Obj> {
    let mut buckets: HashMap<String, Vec<Obj>> = HashMap::new();
    for a in assets {
        buckets.insert(gstr(a, "key"), Vec::new());
    }
    let mut orphan = Vec::new();
    for f in findings {
        let nk = gstr(f, "node_key");
        if !nk.is_empty() && buckets.contains_key(&nk) {
            buckets.get_mut(&nk).unwrap().push(f.clone());
            continue;
        }
        let mut matched = None;
        for a in assets {
            let key = gstr(a, "key");
            let title = gstr(a, "title");
            if !nk.is_empty()
                && (key.contains(&nk)
                    || nk.contains(&key)
                    || (!title.is_empty() && nk.contains(&title)))
            {
                matched = Some(key);
                break;
            }
        }
        if let Some(key) = matched {
            buckets.get_mut(&key).unwrap().push(f.clone());
        } else {
            orphan.push(f.clone());
        }
    }
    let mut groups = Vec::new();
    for a in assets {
        let mut g = Obj::new();
        g.insert("asset".into(), Value::Object(a.clone()));
        put(
            &mut g,
            "findings",
            buckets.remove(&gstr(a, "key")).unwrap_or_default(),
        );
        groups.push(g);
    }
    if !orphan.is_empty() {
        let mut asset = Obj::new();
        put(&mut asset, "key", "_orphan");
        put(&mut asset, "kind", "other");
        put(&mut asset, "title", "未归属资产");
        put(&mut asset, "detail", "");
        let mut g = Obj::new();
        g.insert("asset".into(), Value::Object(asset));
        put(&mut g, "findings", orphan);
        groups.push(g);
    }
    groups
}

fn http_target(project: Option<&Obj>) -> String {
    let mut target = project.map(|p| gstr(p, "target")).unwrap_or_default();
    if !target.is_empty() && !target.starts_with("http") {
        let ports = ports_of(project);
        let port = ports.first().map(as_text).unwrap_or_default();
        if port.is_empty() {
            target = format!("http://{target}");
        } else {
            target = format!("http://{target}:{port}");
        }
    }
    target
}

fn related_edges_for(key: &str, edges: &[&Obj]) -> Vec<Value> {
    let mut out = Vec::new();
    for e in edges {
        let (frm, to) = edge_ends(e);
        if !key.is_empty() && (frm == key || to == key) {
            out.push(Value::Object((*e).clone()));
        }
    }
    out
}

fn node_as_related(n: Option<&Obj>) -> Option<Obj> {
    let n = n?;
    let detail = match n.get("detail") {
        Some(Value::String(s)) => Value::String(s.clone()),
        _ => Value::Null,
    };
    let mut out = Obj::new();
    put(&mut out, "key", g(n, "key"));
    put(&mut out, "type", g(n, "type"));
    put(&mut out, "title", g(n, "title"));
    out.insert("detail".into(), detail);
    put(&mut out, "severity", g(n, "severity"));
    put(&mut out, "risk_score", g(n, "risk_score"));
    let tags = n.get("tags").cloned().unwrap_or(Value::Array(Vec::new()));
    out.insert(
        "tags".into(),
        if tags.is_array() {
            tags
        } else {
            Value::Array(Vec::new())
        },
    );
    Some(out)
}

fn export_findings(
    db: &Db,
    settings: &Settings,
    project_id: &str,
    graph: &Obj,
    project: Option<&Obj>,
    enrich_ai: bool,
) -> Result<Vec<Obj>, String> {
    let target = http_target(project);
    let cfg = project.and_then(|p| p.get("config").and_then(Value::as_object));
    let obj = normalize_objective(
        cfg.map(|c| {
            let o = gstr(c, "objective");
            if o.is_empty() {
                gstr(c, "track")
            } else {
                o
            }
        })
        .as_deref(),
    );
    let nodes = obj_list(graph, "nodes");
    let edges = obj_list(graph, "edges");
    let mut nodes_by_key: HashMap<String, Obj> = HashMap::new();
    for n in &nodes {
        let k = gstr(n, "key");
        if !k.is_empty() {
            nodes_by_key.insert(k, (*n).clone());
        }
    }
    let rows = db.query(
        "SELECT * FROM findings WHERE project_id=?1 ORDER BY created_at DESC",
        &[&project_id],
    )?;
    let mut findings = Vec::new();
    let mut linked = HashSet::new();
    for row in &rows {
        let visible = if objective_is_src(Some(obj)) {
            finding_row_visible(row)
        } else {
            is_visible_finding(row)
        };
        if !visible {
            continue;
        }
        let nk = gstr(row, "node_key");
        let related = if nk.is_empty() {
            None
        } else {
            node_as_related(nodes_by_key.get(&nk))
        };
        let edge_vals = if nk.is_empty() {
            Vec::new()
        } else {
            related_edges_for(&nk, &edges)
        };
        let mut f = serialize_finding_full(row, related.as_ref(), Some(&edge_vals));
        let poc = poc_for_finding(&f, &target);
        f = prepare_finding_report(&f, Some(&poc), None, Some(settings));
        f.insert("poc".into(), Value::Object(poc));
        findings.push(f);
        if !nk.is_empty() {
            linked.insert(nk);
        }
    }
    for n in &nodes {
        if gstr(n, "type") != "vuln"
            || gstr(n, "key").is_empty()
            || linked.contains(&gstr(n, "key"))
        {
            continue;
        }
        let tags = n.get("tags").cloned().unwrap_or(Value::Array(Vec::new()));
        let detail = n.get("detail").cloned().unwrap_or(Value::Null);
        if is_placeholder_node(&gstr(n, "key"), Some(&gstr(n, "title")), &detail, &tags) {
            continue;
        }
        let edge_vals = related_edges_for(&gstr(n, "key"), &edges);
        let mut syn = finding_from_vuln_node(n, Some(&edge_vals));
        let guide = finding_guidance(&syn);
        for (k, v) in guide {
            syn.insert(k, v);
        }
        let poc = poc_for_finding(&syn, &target);
        syn = prepare_finding_report(&syn, Some(&poc), None, Some(settings));
        syn.insert("poc".into(), Value::Object(poc));
        findings.push(syn);
    }
    sort_findings(&mut findings);
    if enrich_ai {
        findings = ai_enrich_writeups(settings, findings);
    }
    let mut out = Vec::new();
    for f in findings {
        let poc = f.get("poc").and_then(Value::as_object).cloned();
        let mut prepared = prepare_finding_report(&f, poc.as_ref(), None, Some(settings));
        if let Some(poc) = poc {
            prepared.insert("poc".into(), Value::Object(poc));
        } else if let Some(existing) = prepared.get("poc").cloned() {
            prepared.insert("poc".into(), existing);
        }
        out.push(prepared);
    }
    Ok(findings_sorted(out))
}

fn build_section(
    project: Option<&Obj>,
    graph: &Obj,
    findings: Vec<Obj>,
    has_shell: bool,
    flags_correct: i64,
) -> Obj {
    let assets = assets_of(project, graph);
    let findings = findings_sorted(findings);
    let criticals = criticals_from(&findings, graph);
    let groups = vulns_by_asset(&findings, &assets);
    let mut sec = Obj::new();
    if let Some(p) = project {
        sec.insert("project".into(), Value::Object(p.clone()));
        put(&mut sec, "name", gstr(p, "name"));
        put(&mut sec, "target", gstr(p, "target"));
    } else {
        sec.insert("project".into(), Value::Object(Obj::new()));
        put(&mut sec, "name", "");
        put(&mut sec, "target", "");
    }
    put(&mut sec, "ports", ports_of(project));
    put(&mut sec, "assets", assets);
    put(&mut sec, "findings", findings);
    put(&mut sec, "criticals", criticals);
    put(&mut sec, "vuln_groups", groups);
    put(&mut sec, "has_shell", has_shell);
    put(&mut sec, "flags_correct", flags_correct);
    let stats = graph
        .get("stats")
        .cloned()
        .unwrap_or(Value::Object(Obj::new()));
    sec.insert("stats".into(), stats);
    sec
}

pub fn build_cluster_report_data(
    db: &Db,
    settings: &Settings,
    project: &Obj,
) -> Result<Obj, String> {
    let pid = gstr(project, "id");
    let rows = db.query(
        "SELECT id FROM projects WHERE parent_id=?1 ORDER BY created_at",
        &[&pid],
    )?;
    let mut children = Vec::new();
    for row in rows {
        children.push(build_report_data(db, settings, &gstr(&row, "id"), false)?);
    }
    let mut stats = Obj::new();
    for k in ["nodes", "edges", "findings", "critical", "high"] {
        put(&mut stats, k, 0i64);
    }
    let mut findings = Vec::new();
    let mut criticals = Vec::new();
    let mut sections = Vec::new();
    let mut merged_nodes = Vec::new();
    let mut merged_edges = Vec::new();
    for child in &children {
        let child_project = child.get("project").and_then(Value::as_object);
        let graph = child.get("graph").and_then(Value::as_object);
        let empty = Obj::new();
        let child_project = child_project.unwrap_or(&empty);
        let graph = graph.unwrap_or(&empty);
        let cid = {
            let id = gstr(child_project, "id");
            if id.is_empty() {
                "child".into()
            } else {
                id
            }
        };
        let prefix = format!("{cid}::");
        let label = {
            let n = gstr(child_project, "name");
            if !n.is_empty() {
                n
            } else {
                let t = gstr(child_project, "target");
                if t.is_empty() {
                    cid.clone()
                } else {
                    t
                }
            }
        };
        for n in obj_list(graph, "nodes") {
            let k = gstr(&n, "key");
            if k.is_empty() {
                continue;
            }
            let mut nn = n.clone();
            put(&mut nn, "key", format!("{prefix}{k}"));
            let title = {
                let t = gstr(&n, "title");
                if t.is_empty() {
                    k
                } else {
                    t
                }
            };
            put(&mut nn, "title", format!("{label} · {title}"));
            merged_nodes.push(nn);
        }
        for e in obj_list(graph, "edges") {
            let (frm, to) = edge_ends(&e);
            if frm.is_empty() || to.is_empty() {
                continue;
            }
            let mut ee = (*e).clone();
            put(&mut ee, "from", format!("{prefix}{frm}"));
            put(&mut ee, "to", format!("{prefix}{to}"));
            merged_edges.push(ee);
        }
        let gst = graph.get("stats").and_then(Value::as_object);
        for key in ["nodes", "edges", "findings", "critical", "high"] {
            let add = gst.map(|s| gint(s, key)).unwrap_or(0);
            let cur = gint(&stats, key);
            put(&mut stats, key, cur + add);
        }
        for mut f in objects_of(child.get("findings").unwrap_or(&Value::Null)) {
            put(&mut f, "project_name", g(child_project, "name"));
            put(&mut f, "project_target", g(child_project, "target"));
            put(&mut f, "project_id", g(child_project, "id"));
            findings.push(f);
        }
        for mut f in objects_of(child.get("criticals").unwrap_or(&Value::Null)) {
            put(&mut f, "project_name", g(child_project, "name"));
            put(&mut f, "project_target", g(child_project, "target"));
            put(&mut f, "project_id", g(child_project, "id"));
            criticals.push(f);
        }
        let child_sections = objects_of(child.get("sections").unwrap_or(&Value::Null));
        if !child_sections.is_empty() {
            sections.extend(child_sections);
        } else {
            sections.push(build_section(
                Some(child_project),
                graph,
                objects_of(child.get("findings").unwrap_or(&Value::Null)),
                gbool(child, "has_shell"),
                gint(child, "flags_correct"),
            ));
        }
    }
    let mut graph = Obj::new();
    put(&mut graph, "nodes", merged_nodes);
    put(&mut graph, "edges", merged_edges);
    put(&mut graph, "findings", findings.clone());
    graph.insert("stats".into(), Value::Object(stats));
    let mut out = Obj::new();
    out.insert("project".into(), Value::Object(project.clone()));
    out.insert("graph".into(), Value::Object(graph));
    put(&mut out, "findings", findings);
    put(&mut out, "criticals", criticals);
    let mut rce = Obj::new();
    put(&mut rce, "path", Vec::<String>::new());
    put(&mut rce, "likelihood", 0);
    out.insert("rce_path".into(), Value::Object(rce));
    put(&mut out, "path_nodes", Vec::<Value>::new());
    put(&mut out, "runs", Vec::<Value>::new());
    put(&mut out, "objective", "cluster");
    put(&mut out, "flags", Vec::<Value>::new());
    put(&mut out, "flags_correct", 0);
    put(&mut out, "flags_score", 0.0);
    put(&mut out, "flags_needed", 0);
    put(&mut out, "generated_at", generated_now());
    put(
        &mut out,
        "has_shell",
        sections.iter().any(|s| gbool(s, "has_shell")),
    );
    let cluster_children: Vec<Obj> = sections
        .iter()
        .map(|s| {
            let mut c = Obj::new();
            c.insert(
                "project".into(),
                s.get("project")
                    .cloned()
                    .unwrap_or(Value::Object(Obj::new())),
            );
            c.insert(
                "stats".into(),
                s.get("stats").cloned().unwrap_or(Value::Object(Obj::new())),
            );
            put(&mut c, "has_shell", gbool(s, "has_shell"));
            put(&mut c, "flags_correct", gint(s, "flags_correct"));
            c
        })
        .collect();
    put(&mut out, "sections", sections);
    put(&mut out, "is_cluster", true);
    put(&mut out, "cluster_children", cluster_children);
    Ok(out)
}

pub fn build_report_data(
    db: &Db,
    settings: &Settings,
    project_id: &str,
    enrich_ai: bool,
) -> Result<Obj, String> {
    let project = get_project(db, project_id)?;
    if project
        .as_ref()
        .is_some_and(|p| gstr(p, "kind") == "cluster")
    {
        return build_cluster_report_data(db, settings, project.as_ref().unwrap());
    }
    let graph = load_graph(db, project_id)?;
    let runs = db.query(
        "SELECT * FROM runs WHERE project_id=?1 ORDER BY started_at DESC",
        &[&project_id],
    )?;
    let findings = export_findings(
        db,
        settings,
        project_id,
        &graph,
        project.as_ref(),
        enrich_ai,
    )?;
    let criticals = criticals_from(&findings, &graph);
    let rce = graph
        .get("rce_path")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let path = rce
        .get("path")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let nodes = obj_list(&graph, "nodes");
    let mut path_nodes = Vec::new();
    for k in &path {
        let key = as_text(k);
        if let Some(n) = nodes.iter().find(|n| gstr(n, "key") == key) {
            path_nodes.push((*n).clone());
        }
    }
    let cfg = project
        .as_ref()
        .and_then(|p| p.get("config").and_then(Value::as_object))
        .cloned()
        .unwrap_or_default();
    let objective_raw = {
        let o = gstr(&cfg, "objective");
        if o.is_empty() {
            "getshell".into()
        } else {
            o
        }
    };
    let objective = normalize_objective(Some(&objective_raw));
    let flag_rows = db.query(
        "SELECT * FROM flags WHERE project_id=?1 ORDER BY created_at",
        &[&project_id],
    )?;
    let flags_correct = flag_rows.iter().filter(|r| gbool(r, "correct")).count() as i64;
    let flags_score: f64 = flag_rows
        .iter()
        .filter(|r| gbool(r, "correct"))
        .map(|r| gfloat(r, "awarded"))
        .sum();
    let flags_needed = {
        let n = gint(&cfg, "flag_count");
        if n == 0 {
            1
        } else {
            n
        }
    };
    let total_score = cfg
        .get("total_score")
        .and_then(|v| v.as_f64().or_else(|| v.as_i64().map(|i| i as f64)));
    let _ = total_score;
    let ctf_done = objective == "flag" && ctf_full_score(flags_correct, None, Some(flags_needed));
    let has_shell = graph
        .get("stats")
        .and_then(Value::as_object)
        .is_some_and(|s| gbool(s, "has_shell"));
    let section = build_section(
        project.as_ref(),
        &graph,
        findings.clone(),
        has_shell,
        flags_correct,
    );
    let mut out = Obj::new();
    out.insert(
        "project".into(),
        project.map(Value::Object).unwrap_or(Value::Null),
    );
    out.insert("graph".into(), Value::Object(graph));
    put(&mut out, "findings", findings);
    put(&mut out, "criticals", criticals);
    out.insert("rce_path".into(), Value::Object(rce));
    put(&mut out, "path_nodes", path_nodes);
    put(&mut out, "runs", runs);
    put(&mut out, "objective", objective);
    put(&mut out, "flags", flag_rows);
    put(&mut out, "flags_correct", flags_correct);
    put(&mut out, "flags_score", flags_score);
    put(&mut out, "flags_needed", flags_needed);
    put(&mut out, "ctf_done", ctf_done);
    put(&mut out, "generated_at", generated_now());
    put(&mut out, "has_shell", has_shell);
    put(&mut out, "sections", vec![section]);
    put(&mut out, "is_cluster", false);
    Ok(out)
}

fn py_float(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{n:.1}")
    } else {
        format!("{n}")
    }
}

pub fn render_markdown(data: &Obj, settings: Option<&Settings>) -> String {
    let project = data.get("project").and_then(Value::as_object);
    let graph = data.get("graph").and_then(Value::as_object);
    let empty = Obj::new();
    let p = project.unwrap_or(&empty);
    let gph = graph.unwrap_or(&empty);
    let obj = {
        let o = gstr(data, "objective");
        if o.is_empty() {
            "getshell".into()
        } else {
            o
        }
    };
    let result = if obj == "flag" {
        let need = {
            let n = gint(data, "flags_needed");
            if n == 0 {
                1
            } else {
                n
            }
        };
        let prog = format!("{}/{}", gint(data, "flags_correct"), need);
        let cfg = p.get("config").and_then(Value::as_object);
        let mut score_bit = format!(" · 分 {}", py_float(gfloat(data, "flags_score")));
        if let Some(cfg) = cfg {
            if cfg.get("total_score").is_some_and(|v| !v.is_null()) {
                score_bit.push('/');
                score_bit.push_str(&as_text(&cfg["total_score"]));
            }
        }
        if gbool(data, "ctf_done") {
            format!("✅ 本题满分 {prog}{score_bit}")
        } else if gint(data, "flags_correct") > 0 {
            format!("🚩 进度 {prog}{score_bit}（未满分，继续）")
        } else {
            "未夺取 flag".into()
        }
    } else if obj == "cluster" {
        let n = data
            .get("sections")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        format!(
            "子项目 {n} 个 · {}",
            if gbool(data, "has_shell") {
                "✅ 至少一个已 getshell"
            } else {
                "尚未 getshell"
            }
        )
    } else if gbool(data, "has_shell") {
        "✅ 已获取权限 (getshell)".into()
    } else {
        "未获取权限".into()
    };
    let stats = gph.get("stats").and_then(Value::as_object);
    let critical_n = stats.map(|s| gint(s, "critical")).unwrap_or(0);
    let kind = if obj == "flag" {
        "夺旗(CTF)"
    } else {
        "渗透测试"
    };
    let target = {
        let t = gstr(p, "target");
        if t.is_empty() {
            "（集群/多资产）".into()
        } else {
            t
        }
    };
    let mut lines = vec![
        format!(
            "# StrikeAgent_AtkBrain-Flash {kind}报告 — {}",
            gstr(p, "name")
        ),
        String::new(),
        format!("- 目标：`{target}`"),
        format!("- 生成时间：{}", gstr(data, "generated_at")),
        format!("- 结果：{result}"),
        format!(
            "- 统计：漏洞 {}（严重 {critical_n}）",
            data.get("findings")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0)
        ),
        String::new(),
        "## 项目 · 资产 · 漏洞".into(),
        String::new(),
    ];
    let sections = objects_of(data.get("sections").unwrap_or(&Value::Null));
    if sections.is_empty() {
        lines.push("_无子项目/资产数据_".into());
    }
    for (i, sec) in sections.iter().enumerate() {
        let name = {
            let n = gstr(sec, "name");
            if !n.is_empty() {
                n
            } else {
                sec.get("project")
                    .and_then(Value::as_object)
                    .map(|p| gstr(p, "name"))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| format!("项目{}", i + 1))
            }
        };
        let target = {
            let t = gstr(sec, "target");
            if t.is_empty() {
                "（无主目标）".into()
            } else {
                t
            }
        };
        let ports = sec
            .get("ports")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let port_txt = if ports.is_empty() {
            "全端口".into()
        } else {
            ports.iter().map(as_text).collect::<Vec<_>>().join(", ")
        };
        let mut result_line = format!(
            "- **结果**：{}",
            if gbool(sec, "has_shell") {
                "已 getshell"
            } else {
                "未获取权限"
            }
        );
        if gint(sec, "flags_correct") > 0 {
            result_line.push_str(&format!(" · flag×{}", gint(sec, "flags_correct")));
        }
        lines.push(format!("### {}. {name}", i + 1));
        lines.push(format!("- **资产目标**：`{target}`"));
        lines.push(format!("- **端口**：{port_txt}"));
        lines.push(result_line);
        lines.push(String::new());
        lines.push("#### 资产清单".into());
        let assets = obj_list(sec, "assets");
        if assets.is_empty() {
            lines.push("- _（仅主目标，无额外资产节点）_".into());
        } else {
            for a in assets {
                let extra = if gstr(&a, "detail").is_empty() {
                    String::new()
                } else {
                    format!(" — {}", gstr(&a, "detail"))
                };
                lines.push(format!(
                    "- `{}` [{}]{extra}",
                    gstr(&a, "title"),
                    gstr(&a, "kind")
                ));
            }
        }
        lines.push(String::new());
        lines.push("#### 漏洞".into());
        let sec_findings = obj_list(sec, "findings");
        if sec_findings.is_empty() {
            lines.push("- _本项目暂无已登记漏洞_".into());
        } else {
            let sec_project = sec.get("project").and_then(Value::as_object).or(project);
            for f in sec_findings {
                let poc = f.get("poc").and_then(Value::as_object);
                lines.push(render_finding_markdown(
                    sec_project,
                    &f,
                    poc,
                    "#####",
                    None,
                    None,
                    settings,
                ));
            }
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn vuln_card_html(f: &Obj) -> String {
    let sev = gstr(f, "severity");
    let klass = if sev == "critical" {
        "crit"
    } else if sev == "high" {
        "high"
    } else if sev == "medium" {
        "med"
    } else {
        ""
    };
    let cat = {
        let c = gstr(f, "category");
        if c.is_empty() {
            "未分类".into()
        } else {
            c
        }
    };
    let node = if gstr(f, "node_key").is_empty() {
        String::new()
    } else {
        format!(" · <code>{}</code>", gstr(f, "node_key"))
    };
    let vs = {
        let s = gstr(f, "verification_status");
        if s.is_empty() {
            "verified".into()
        } else {
            s
        }
    };
    let summary = {
        let a = gstr(f, "report_summary");
        if !a.is_empty() {
            a
        } else {
            let b = gstr(f, "description");
            if b.is_empty() {
                "专职 Pi 撰写中".into()
            } else {
                b
            }
        }
    };
    let impact = {
        let a = gstr(f, "impact_detail");
        if !a.is_empty() {
            a
        } else {
            let b = gstr(f, "impact");
            if b.is_empty() {
                "专职 Pi 撰写中".into()
            } else {
                b
            }
        }
    };
    let rating = {
        let a = gstr(f, "secondary_review");
        if !a.is_empty() {
            a
        } else {
            let b = gstr(f, "report_rating");
            if b.is_empty() {
                "未评级".into()
            } else {
                b
            }
        }
    };
    let repro = gstr(f, "manual_repro");
    let steps = f
        .get("manual_steps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let repro_html = if !repro.is_empty() {
        format!(r#"<div class="vuln-body" style="white-space:pre-wrap">{repro}</div>"#)
    } else if !steps.is_empty() {
        let lis = steps
            .iter()
            .map(|s| format!("<li>{}</li>", as_text(s)))
            .collect::<String>();
        format!(r#"<ol class="repro">{lis}</ol>"#)
    } else {
        r#"<p class="empty">专职复核 Pi 完成二次验证后撰写复现步骤。</p>"#.into()
    };
    let poc = f.get("poc").and_then(Value::as_object);
    let curl = poc
        .map(|p| gstr(p, "curl"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| gstr(f, "poc_curl"));
    let py = poc
        .map(|p| gstr(p, "python"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| gstr(f, "poc_python"));
    let fix = {
        let a = gstr(f, "remediation");
        if !a.is_empty() {
            a
        } else {
            let b = gstr(f, "report_fix");
            if b.is_empty() {
                "专职 Pi 撰写中".into()
            } else {
                b
            }
        }
    };
    let mut html = format!(
        r#"<div class="card {klass}"><span class="badge b-{sev}">{sev}</span> <b>{}</b><span class="meta"> · {cat}{node} · {vs}</span><h4>漏洞简介</h4><div class="vuln-body">{summary}</div><h4>危害</h4><div class="vuln-body">{impact}</div><h4>红队评级</h4><div class="vuln-body">{rating}</div><h4>手动复现</h4>{repro_html}"#,
        gstr(f, "title")
    );
    if !curl.is_empty() {
        html.push_str(&format!("<pre>{curl}</pre>"));
    }
    if !py.is_empty() {
        html.push_str(&format!("<pre>{py}</pre>"));
    }
    html.push_str(&format!(
        r#"<h4>修复方式</h4><div class="vuln-body">{fix}</div></div>"#
    ));
    html
}

const SIMPLE_CSS: &str = r#"
  :root{ --canvas:#f4f7fc; --card:#ffffff; --dark:#eef3fb; --ink:#243044; --body:#4a5a6e;
    --muted:#8b97a8; --coral:#4c7dff; --hair:#e6edf5; --crit:#c64545; --high:#cc785c; --med:#d4a017; --low:#5db8a6; --info:#8e8b82; --ok:#22a06b; }
  *{box-sizing:border-box}
  body{background:radial-gradient(900px 420px at 8% -10%, rgba(196,214,255,.55), transparent 60%),radial-gradient(800px 380px at 100% 0%, rgba(232,220,255,.45), transparent 55%),var(--canvas);color:var(--ink);margin:0;
    font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.55;padding:48px}
  h1,h2,h3{font-family:"Tiempos Headline","EB Garamond",Georgia,serif;font-weight:400;letter-spacing:-.5px}
  h1{font-size:40px;margin:0 0 8px}
  h2{font-size:26px;margin:36px 0 12px;border-bottom:1px solid var(--hair);padding-bottom:8px}
  h3{font-size:20px;margin:28px 0 8px}
  h4{font-size:15px;margin:14px 0 6px;color:var(--body)}
  .meta{color:var(--muted);font-size:14px}
  .stat{display:inline-block;background:var(--card);border-radius:9999px;padding:4px 14px;margin:4px 6px 4px 0;font-size:13px}
  .shell-ok{background:var(--coral);color:#fff;padding:10px 16px;border-radius:12px;display:inline-block;font-weight:600}
  .section{background:#fff;border:1px solid var(--hair);border-radius:14px;padding:22px 24px;margin:18px 0}
  .section-head{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:baseline;margin-bottom:8px}
  .section-head .target{font-family:"JetBrains Mono",monospace;font-size:15px}
  .card{background:var(--card);border-radius:12px;padding:16px 18px;margin:10px 0}
  .crit{border-left:5px solid var(--crit)}
  .high{border-left:5px solid var(--high)}
  .med{border-left:5px solid var(--med)}
  .badge{font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:3px 10px;border-radius:9999px;color:#fff}
  .b-critical{background:var(--crit)} .b-high{background:var(--high)} .b-medium{background:var(--med);color:#243044}
  .b-low{background:var(--low)} .b-info{background:var(--info)}
  pre{background:#eef3fb;color:var(--ink);border:1px solid var(--hair);padding:14px;border-radius:8px;overflow-x:auto;font-family:"JetBrains Mono",monospace;font-size:12.5px;white-space:pre-wrap}
  code{font-family:"JetBrains Mono",monospace}
  ul{padding-left:20px} li{margin:4px 0}
  .vuln-body{white-space:pre-wrap;font-size:14px;margin:0 0 10px;line-height:1.6}
  ol.repro{padding-left:22px} ol.repro li{margin:8px 0;white-space:pre-wrap;font-size:14px}
  table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;border-bottom:1px solid var(--hair);text-align:left}th{color:var(--muted);font-weight:600}
  .asset-tag{display:inline-block;background:var(--card);border-radius:8px;padding:4px 10px;margin:3px 4px 3px 0;font-size:12.5px}
  .empty{color:var(--muted);font-size:14px}
  .foot{margin-top:48px;color:var(--muted);font-size:12px;border-top:1px solid var(--hair);padding-top:16px}
  .toc a{color:var(--ink);text-decoration:none;border-bottom:1px solid var(--hair)}
  .toc li{margin:6px 0}
"#;

pub fn render_html(data: &Obj) -> String {
    let project = data.get("project").and_then(Value::as_object);
    let empty = Obj::new();
    let p = project.unwrap_or(&empty);
    let graph = data
        .get("graph")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let stats = graph.get("stats").and_then(Value::as_object);
    let objective = {
        let o = gstr(data, "objective");
        if o.is_empty() {
            "getshell".into()
        } else {
            o
        }
    };
    let sections = objects_of(data.get("sections").unwrap_or(&Value::Null));
    let findings_n = data
        .get("findings")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let name = gstr(p, "name");
    let target = gstr(p, "target");
    let target_html = if target.is_empty() {
        "集群 / 多资产".into()
    } else {
        format!("目标 <code>{target}</code>")
    };
    let banner = if objective == "flag" {
        if gbool(data, "ctf_done") {
            format!(
                r#"<span class="shell-ok">✅ 本题满分 {}/{} · 分 {}</span>"#,
                gint(data, "flags_correct"),
                gint(data, "flags_needed"),
                py_float(gfloat(data, "flags_score"))
            )
        } else if gint(data, "flags_correct") > 0 {
            format!(
                r#"<span class="shell-ok">🚩 进度 {}/{} · 分 {}（未满分）</span>"#,
                gint(data, "flags_correct"),
                gint(data, "flags_needed"),
                py_float(gfloat(data, "flags_score"))
            )
        } else {
            r#"<span class="stat">未夺取 flag</span>"#.into()
        }
    } else if gbool(data, "is_cluster") {
        let shell = if gbool(data, "has_shell") {
            r#"<span class="shell-ok">✅ 至少一个目标已 getshell</span>"#
        } else {
            r#"<span class="stat">尚未 getshell</span>"#
        };
        format!(
            r#"<span class="stat">子项目 {}</span>{shell}"#,
            sections.len()
        )
    } else if gbool(data, "has_shell") {
        r#"<span class="shell-ok">✅ 已获取目标权限 (getshell)</span>"#.into()
    } else {
        r#"<span class="stat">未获取权限</span>"#.into()
    };
    let high = stats
        .and_then(|s| {
            s.get("high")
                .map(|_| format!(r#"<span class="stat">高危 {}</span>"#, gint(s, "high")))
        })
        .unwrap_or_default();
    let mut toc = String::new();
    if sections.len() > 1 {
        toc.push_str("<h2>目录</h2><ol class=\"toc\">");
        for (i, sec) in sections.iter().enumerate() {
            let name = {
                let n = gstr(sec, "name");
                if n.is_empty() {
                    format!("项目 {}", i + 1)
                } else {
                    n
                }
            };
            let target = {
                let t = gstr(sec, "target");
                if t.is_empty() {
                    "多资产".into()
                } else {
                    t
                }
            };
            let shell = if gbool(sec, "has_shell") {
                " · getshell"
            } else {
                ""
            };
            let nfind = sec
                .get("findings")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            toc.push_str(&format!(r##"<li><a href="#proj-{}">{name} — <code>{target}</code>（漏洞 {nfind}{shell}）</a></li>"##, i + 1));
        }
        toc.push_str("</ol>");
    }
    let mut body = String::new();
    if sections.is_empty() {
        body.push_str(r#"<p class="empty">暂无项目数据。</p>"#);
    }
    for (i, sec) in sections.iter().enumerate() {
        let name = {
            let n = gstr(sec, "name");
            if n.is_empty() {
                "未命名项目".into()
            } else {
                n
            }
        };
        let target = {
            let t = gstr(sec, "target");
            if t.is_empty() {
                "（无主目标）".into()
            } else {
                t
            }
        };
        let ports = sec
            .get("ports")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let port_html = if ports.is_empty() {
            r#"<span class="stat">全端口</span>"#.into()
        } else {
            format!(
                r#"<span class="stat">端口 {}</span>"#,
                ports.iter().map(as_text).collect::<Vec<_>>().join(", ")
            )
        };
        let shell = if gbool(sec, "has_shell") {
            r#"<span class="badge b-critical">getshell</span>"#
        } else {
            ""
        };
        let nfind = sec
            .get("findings")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        let ncrit = sec
            .get("criticals")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        body.push_str(&format!(
            r#"<div class="section" id="proj-{}"><div class="section-head"><h3 style="margin:0">{}. {name}</h3><span class="target">{target}</span>{port_html}{shell}<span class="stat">漏洞 {nfind}</span><span class="stat">严重/高危 {ncrit}</span></div><h4>资产</h4>"#,
            i + 1,
            i + 1
        ));
        let assets = obj_list(sec, "assets");
        if assets.is_empty() {
            body.push_str(r#"<p class="empty">仅登记主目标，无额外资产节点。</p>"#);
        } else {
            for a in assets {
                let detail = gstr(&a, "detail");
                let extra = if detail.is_empty() {
                    String::new()
                } else {
                    format!(" · {detail}")
                };
                body.push_str(&format!(
                    r#"<span class="asset-tag"><b>{}</b> <span class="meta">{}{extra}</span></span>"#,
                    gstr(&a, "title"),
                    gstr(&a, "kind")
                ));
            }
        }
        body.push_str("<h4>漏洞（按资产）</h4>");
        let mut any = false;
        for grp in obj_list(sec, "vuln_groups") {
            let gf = obj_list(&grp, "findings");
            if gf.is_empty() {
                continue;
            }
            any = true;
            let title = grp
                .get("asset")
                .and_then(Value::as_object)
                .map(|a| gstr(a, "title"))
                .unwrap_or_default();
            body.push_str(&format!(r#"<p style="margin:12px 0 4px"><b>{title}</b> <span class="meta">· {} 条</span></p>"#, gf.len()));
            for f in gf {
                body.push_str(&vuln_card_html(&f));
            }
        }
        if !any {
            let sec_findings = obj_list(sec, "findings");
            if sec_findings.is_empty() {
                body.push_str(r#"<p class="empty">本项目暂无已登记漏洞。</p>"#);
            } else {
                for f in sec_findings {
                    body.push_str(&vuln_card_html(&f));
                }
            }
        }
        body.push_str("</div>");
    }
    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>StrikeAgent_AtkBrain-Flash 报告 · {name}</title><style>{SIMPLE_CSS}</style></head><body>
  <h1>StrikeAgent_AtkBrain-Flash 渗透测试报告</h1>
  <div class="meta">{name} &nbsp;·&nbsp; {target_html} &nbsp;·&nbsp; {}</div>
  <p>{banner}</p>
  <div><span class="stat">漏洞 {findings_n}</span><span class="stat">严重 {}</span>{high}<span class="stat">项目 {}</span></div>
  {toc}
  <h2>项目 · 资产 · 漏洞</h2>
  <p class="meta">按项目列出对应资产及其漏洞。每条由专职复核 Pi 撰写简介、危害、红队评级、手动复现与修复方式。</p>
  {body}
  <div class="foot">由 StrikeAgent_AtkBrain-Flash 自动生成 · 仅限授权渗透测试使用</div>
</body></html>"#,
        gstr(data, "generated_at"),
        stats.map(|s| gint(s, "critical")).unwrap_or(0),
        sections.len()
    )
}

fn leak_re() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        re(
            r"(?i)StrikeAgent|AtkBrain-Flash|AtkBrain|GETSHELL|node_key|verification_status|附录|时间线|playbook|frontier|rce_path",
        )
    });
    &RE
}

pub fn sanitize_visible(text: &str) -> String {
    static NODE: LazyLock<Regex> = LazyLock::new(|| re(r"\bnode:vuln:[^\s<]+"));
    static FID: LazyLock<Regex> = LazyLock::new(|| re(r"\bf_[0-9a-f]{8,}\b"));
    let t = leak_re().replace_all(text, "");
    let t = NODE.replace_all(&t, "");
    FID.replace_all(&t, "").into_owned()
}

fn slot_re() -> &'static Regex {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?s)(<!-- SLOT:([a-z0-9_-]+) -->)(.*?)(<!-- /SLOT:\2 -->)"));
    &RE
}

pub fn fill_slot(html: &str, name: &str, content: &str) -> Result<String, String> {
    let pat = format!(
        r"(?s)(<!-- SLOT:{} -->)(.*?)(<!-- /SLOT:{} -->)",
        regex::escape(name),
        regex::escape(name)
    );
    let re = Regex::new(&pat).map_err(|e| e.to_string())?;
    let mut n = 0;
    let out = re.replacen(html, 1, |c: &regex::Captures| {
        n += 1;
        format!(
            "{}\n{}\n{}",
            c.get(1).map(|m| m.as_str()).unwrap_or(""),
            content,
            c.get(3).map(|m| m.as_str()).unwrap_or("")
        )
    });
    if n != 1 {
        return Err(format!("母版缺少唯一槽位 {name}"));
    }
    Ok(out.into_owned())
}

pub fn fill_slots(mut html: String, mapping: &[(String, String)]) -> Result<String, String> {
    for (name, content) in mapping {
        html = fill_slot(&html, name, content)?;
    }
    Ok(html)
}

pub fn slot_names(html: &str) -> Vec<String> {
    slot_re()
        .captures_iter(html)
        .filter_map(|c| c.get(2).map(|m| m.as_str().to_string()))
        .collect()
}

fn sev_bucket(f: &Obj) -> String {
    let s = display_finding_severity(f);
    if matches!(s.as_str(), "critical" | "high" | "medium" | "low" | "info") {
        s
    } else {
        "info".into()
    }
}

fn sev_chip(sev: &str) -> &'static str {
    match sev {
        "critical" => "crit",
        "high" => "high",
        "medium" => "med",
        _ => "low",
    }
}

fn sev_dot(sev: &str) -> &'static str {
    match sev {
        "critical" => "var(--crit)",
        "high" => "var(--high)",
        "medium" => "var(--med)",
        _ => "var(--muted)",
    }
}

fn pn_cls(typ: &str) -> &'static str {
    match typ {
        "target" | "host" | "endpoint" | "info" => "info",
        "service" => "svc",
        "danger" => "warn",
        "vuln" => "crit",
        "foothold" => "hold",
        "goal" => "goal",
        _ => "info",
    }
}

pub fn gate_html(html: &str, has_findings: bool) -> Vec<String> {
    let mut errs = Vec::new();
    if !html.contains("class=\"cover\"") {
        errs.push("missing-cover".into());
    }
    if !html.contains("class=\"grain\"") {
        errs.push("missing-grain".into());
    }
    if !html.contains("sec-head") {
        errs.push("missing-sec-head".into());
    }
    if !html.contains("path-board") {
        errs.push("missing-path-board".into());
    }
    if has_findings && !html.contains("class=\"vf") {
        errs.push("missing-vf".into());
    }
    if html.contains("class=\"vbar\"") {
        errs.push("has-vbar".into());
    }
    errs
}

fn counts_of(findings: &[Obj]) -> Obj {
    let mut c = Obj::new();
    for k in ["critical", "high", "medium", "low", "info"] {
        put(&mut c, k, 0i64);
    }
    for f in findings {
        let s = sev_bucket(f);
        let cur = gint(&c, &s);
        put(&mut c, &s, cur + 1);
    }
    put(&mut c, "total", findings.len() as i64);
    c
}

fn verify_buckets(findings: &[Obj]) -> (i64, i64, i64) {
    let mut verified = 0i64;
    let mut pending = 0i64;
    let mut intel = 0i64;
    for f in findings {
        let st = gstr(f, "verification_status").to_ascii_lowercase();
        if st == "verified" {
            verified += 1;
        } else if st == "pending" || st == "flaky" {
            pending += 1;
        } else {
            intel += 1;
        }
    }
    (verified, pending, intel)
}

fn graph_stats_view(data: &Obj) -> Obj {
    let g = data.get("graph").and_then(Value::as_object);
    let mut st = g
        .and_then(|g| g.get("stats").and_then(Value::as_object))
        .cloned()
        .unwrap_or_default();
    let nodes = g.map(|g| obj_list(g, "nodes")).unwrap_or_default();
    let edges = g.map(|g| obj_list(g, "edges")).unwrap_or_default();
    if !st.contains_key("nodes") {
        put(&mut st, "nodes", nodes.len() as i64);
    }
    if !st.contains_key("edges") {
        put(&mut st, "edges", edges.len() as i64);
    }
    if !st.contains_key("services") {
        let n = nodes
            .iter()
            .filter(|n| matches!(gstr(n, "type").as_str(), "service" | "host" | "endpoint"))
            .count();
        put(&mut st, "services", n as i64);
    }
    st
}

fn severity_bars_svg(counts: &Obj) -> String {
    let total = gint(counts, "total").max(1);
    let rows = [
        (rl("bar.critical"), "critical", "var(--crit)", false),
        (rl("bar.high"), "high", "var(--high)", false),
        (rl("bar.medium"), "medium", "var(--muted-soft)", false),
        (rl("bar.low"), "low", "var(--muted)", true),
    ];
    let mut parts = vec![format!(
        r#"<svg viewBox="0 0 640 190" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:auto" role="img" aria-label="{}">"#,
        esc(rl("chart.sev_aria"), true)
    )];
    for (i, (label, key, col, plus_info)) in rows.iter().enumerate() {
        let mut n = gint(counts, key);
        if *plus_info {
            n += gint(counts, "info");
        }
        let w = if n == 0 {
            0
        } else {
            (420.0 * n as f64 / total as f64).round().max(12.0) as i64
        };
        let ty = 32 + i * 40;
        let ry = 16 + i * 40;
        let tx = 150 + w + 14;
        let n_s = n.to_string();
        parts.push(format!(
            r#"<text x="0" y="{ty}" font-size="13" fill="var(--body)" font-family="inherit">{}</text><rect x="150" y="{ry}" width="420" height="20" rx="10" fill="var(--surface-soft)" stroke="var(--hairline)"/><rect x="150" y="{ry}" width="{w}" height="20" rx="10" fill="{col}"><title>{}</title></rect><text x="{tx}" y="{}" font-size="14" font-weight="700" fill="var(--ink)">{n}</text>"#,
            esc(label, false),
            esc(rlv("n_items", &[("n", &n_s)]), false),
            ty - 1
        ));
    }
    parts.push("</svg>".into());
    parts.join("")
}

fn verify_donut_svg(findings: &[Obj]) -> String {
    let (verified, pending, intel) = verify_buckets(findings);
    let total = (verified + pending + intel).max(1) as f64;
    let r = 74.0;
    let circ = 2.0 * std::f64::consts::PI * r;
    let colors = [
        ("verified", verified, "var(--success)"),
        ("pending", pending, "var(--warning)"),
        ("intel", intel, "var(--muted-soft)"),
    ];
    let mut parts = vec![format!(
        r#"<svg viewBox="0 0 220 200" width="200" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{}">"#,
        esc(rl("chart.verify_aria"), true)
    )];
    let mut offset = 0.0;
    for (_key, n, col) in colors {
        let arc = circ * n as f64 / total;
        let rest = (circ - arc).max(0.0);
        parts.push(format!(
            r#"<circle cx="110" cy="100" r="{r:.0}" fill="none" stroke="{col}" stroke-width="24" stroke-dasharray="{arc:.2} {rest:.2}" stroke-dashoffset="{:.2}" transform="rotate(-90 110 100)"/>"#,
            -offset
        ));
        offset += arc;
    }
    let shown = verified + pending + intel;
    parts.push(format!(
        r#"<text x="110" y="104" text-anchor="middle" font-size="30" font-weight="800" fill="var(--ink)">{shown}</text><text x="110" y="126" text-anchor="middle" font-size="12" fill="var(--muted)">{}</text></svg>"#,
        esc(rl("chart.total"), false)
    ));
    parts.join("")
}

fn path_keys(data: &Obj) -> (Vec<String>, HashMap<String, Obj>) {
    let g = data.get("graph").and_then(Value::as_object);
    let mut nodes = HashMap::new();
    if let Some(g) = g {
        for n in obj_list(g, "nodes") {
            let k = gstr(&n, "key");
            if !k.is_empty() {
                nodes.insert(k, n.clone());
            }
        }
    }
    let mut keys = g
        .and_then(|g| g.get("rce_path"))
        .and_then(Value::as_object)
        .and_then(|p| p.get("path"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(as_text)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        if let Some(g) = g {
            let all = obj_list(g, "nodes");
            for typ in ["target", "service", "danger", "vuln", "goal"] {
                if let Some(hit) = all
                    .iter()
                    .find(|n| gstr(n, "type") == typ && !gstr(n, "key").is_empty())
                {
                    keys.push(gstr(hit, "key"));
                }
            }
            keys.truncate(6);
        }
    }
    if keys.is_empty() {
        let p = data.get("project").and_then(Value::as_object);
        keys.push("_tgt".into());
        let mut n = Obj::new();
        let title = p
            .map(|p| {
                let t = gstr(p, "target");
                if t.is_empty() {
                    gstr(p, "name")
                } else {
                    t
                }
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("auth_target"));
        put(&mut n, "title", title);
        put(&mut n, "type", "target");
        nodes.insert("_tgt".into(), n);
    }
    keys.truncate(9);
    (keys, nodes)
}

fn pn_card(cls: &str, title: &str, detail: &str) -> String {
    format!(
        r#"<div class="pn {cls}"><div class="pk">{}</div><div class="pt">{}</div><div class="pd">{}</div></div>"#,
        esc(cls, false),
        esc(title, false),
        esc(detail, false)
    )
}

fn parrow(label: &str, down: bool) -> String {
    let cls = if down { "parrow down" } else { "parrow" };
    format!(
        r#"<div class="{cls}"><span class="line"></span><span>{}</span></div>"#,
        esc(label, false)
    )
}

fn path_board(data: &Obj, path_note: &str) -> String {
    let (keys, nodes) = path_keys(data);
    let shown: Vec<&str> = keys.iter().take(9).map(String::as_str).collect();
    let mut cards = Vec::new();
    for (i, k) in shown.iter().enumerate() {
        let n = nodes.get(*k);
        let typ = n
            .map(|n| gstr(n, "type"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "info".into());
        let cls = if typ == "goal" || (gbool(data, "has_shell") && i + 1 == shown.len()) {
            "goal"
        } else {
            pn_cls(&typ)
        };
        let title = take_chars(
            &sanitize_visible(
                &n.map(|n| gstr(n, "title"))
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| (*k).to_string()),
            ),
            36,
        );
        let detail_raw = n
            .map(|n| detail_text(n.get("detail").unwrap_or(&Value::Null)))
            .unwrap_or_default();
        let detail = if detail_raw.is_empty() {
            i18n::pn_map(None)
                .get(typ.as_str())
                .cloned()
                .unwrap_or_else(|| rl("pn.info"))
        } else {
            detail_raw
        };
        let detail = take_chars(&sanitize_visible(&detail), 48);
        cards.push((cls, title, detail));
    }
    let words = [
        rl("path.expand"),
        rl("path.enter"),
        rl("path.exploit"),
        rl("path.lateral"),
        rl("path.privesc"),
        rl("path.land"),
    ];
    let mut rows_html = Vec::new();
    for r in (0..cards.len()).step_by(3) {
        let chunk = &cards[r..cards.len().min(r + 3)];
        if r > 0 {
            rows_html.push(parrow(&rl("path.next"), true));
        }
        let mut inner = Vec::new();
        for (j, (cls, title, detail)) in chunk.iter().enumerate() {
            if j > 0 {
                inner.push(parrow(&words[(r + j - 1) % words.len()], false));
            }
            inner.push(pn_card(cls, title, detail));
        }
        rows_html.push(format!(r#"<div class="path-row">{}</div>"#, inner.join("")));
    }
    let note = {
        let s = sanitize_visible(path_note);
        if s.is_empty() {
            rl("path.note")
        } else {
            s
        }
    };
    format!(
        r#"<p class="sec-sub">{}</p><div class="path-board"><div class="path-rows">{}</div><div class="path-legend"><span><i class="l-crit"></i>{}</span><span><i class="l-warn"></i>{}</span><span><i class="l-info"></i>{}</span><span><i class="l-goal"></i>{}</span></div></div><div class="path-caption">{}</div>"#,
        esc(&note, false),
        rows_html.join(""),
        esc(rl("path.leg_crit"), false),
        esc(rl("path.leg_warn"), false),
        esc(rl("path.leg_info"), false),
        esc(rl("path.leg_goal"), false),
        esc(&note, false)
    )
}

fn collect_assets(data: &Obj) -> Vec<Obj> {
    let mut assets = Vec::new();
    for sec in obj_list(data, "sections") {
        assets.extend(objects_of(sec.get("assets").unwrap_or(&Value::Null)));
    }
    if assets.is_empty() {
        if let Some(graph_obj) = data.get("graph").and_then(Value::as_object) {
            for n in obj_list(graph_obj, "nodes") {
                if matches!(
                    gstr(&n, "type").as_str(),
                    "target" | "service" | "host" | "endpoint"
                ) {
                    let mut a = Obj::new();
                    let title = {
                        let t = gstr(&n, "title");
                        if t.is_empty() {
                            gstr(&n, "key")
                        } else {
                            t
                        }
                    };
                    put(&mut a, "title", title);
                    put(&mut a, "kind", g(&n, "type"));
                    put(
                        &mut a,
                        "detail",
                        detail_text(n.get("detail").unwrap_or(&Value::Null)),
                    );
                    assets.push(a);
                }
            }
        }
    }
    if assets.is_empty() {
        if let Some(p) = data.get("project").and_then(Value::as_object) {
            if !gstr(p, "target").is_empty() {
                let mut a = Obj::new();
                put(&mut a, "title", gstr(p, "target"));
                put(&mut a, "kind", "target");
                put(&mut a, "detail", rl("asset.main"));
                assets.push(a);
            }
        }
    }
    assets
}

fn asset_map_svg(assets: &[Obj]) -> String {
    let shown: Vec<&Obj> = assets.iter().take(8).collect();
    if shown.is_empty() {
        return String::new();
    }
    let rows = (shown.len() + 3) / 4;
    let height = (40 + rows * 96).max(220);
    let mut boxes = Vec::new();
    for (i, a) in shown.iter().enumerate() {
        let col = i % 4;
        let row = i / 4;
        let x = 40 + col * 270;
        let y = 28 + row * 96;
        let title = take_chars(
            &sanitize_visible(&{
                let t = gstr(a, "title");
                if t.is_empty() {
                    gstr(a, "key")
                } else {
                    t
                }
            }),
            28,
        );
        let raw_kind = gstr(a, "kind");
        let kind = i18n::kind_map(None)
            .get(raw_kind.as_str())
            .cloned()
            .unwrap_or_else(|| rl("asset"));
        let stroke = if raw_kind == "vuln" || raw_kind == "danger" {
            "#c64545"
        } else if raw_kind == "service" {
            "#5db8a6"
        } else {
            "#4c7dff"
        };
        boxes.push(format!(
            r##"<g filter="url(#am-shadow)"><rect x="{x}" y="{y}" width="240" height="62" rx="14" fill="#ffffff" stroke="{stroke}" stroke-width="1.6"/><text x="{}" y="{}" text-anchor="middle" font-size="12" font-weight="700" fill="{stroke}">{}</text><text x="{}" y="{}" text-anchor="middle" font-size="14" font-weight="700" fill="#243044">{}</text></g>"##,
            x + 120,
            y + 24,
            esc(&kind, false),
            x + 120,
            y + 44,
            esc(&title, false)
        ));
    }
    let n = assets.len().to_string();
    format!(
        r##"<div class="asset-map"><h4>{}</h4><p class="am-sub">{}</p><svg viewBox="0 0 1120 {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{}"><defs><filter id="am-shadow" x="-12%" y="-12%" width="124%" height="140%"><feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#243044" flood-opacity="0.07"/></filter></defs>{}</svg></div>"##,
        esc(rl("asset.map"), false),
        rlv("asset.map_sub", &[("n", &n)]),
        esc(rl("asset.map"), true),
        boxes.join("")
    )
}

fn assets_html(data: &Obj) -> String {
    let assets = collect_assets(data);
    let mut cards = Vec::new();
    let mut extra = Vec::new();
    for (i, a) in assets.iter().enumerate() {
        let title = sanitize_visible(&{
            let t = gstr(a, "title");
            if t.is_empty() {
                gstr(a, "key")
            } else {
                t
            }
        });
        let title = if title.is_empty() { rl("asset") } else { title };
        let kind = i18n::kind_map(None)
            .get(gstr(a, "kind").as_str())
            .cloned()
            .unwrap_or_else(|| rl("asset"));
        let detail = take_chars(&sanitize_visible(&gstr(a, "detail")), 160);
        if i < 12 {
            let danger = if matches!(gstr(a, "kind").as_str(), "vuln" | "danger") {
                " danger"
            } else {
                ""
            };
            cards.push(format!(
                r#"<div class="asset{danger}"><div class="a-name">{}</div><div class="a-role">{}</div><div class="a-badges"><span class="chip">{}</span></div><div class="a-desc">{}</div></div>"#,
                esc(&title, false),
                esc(&kind, false),
                esc(&kind, false),
                esc(&detail, false)
            ));
        } else {
            extra.push(format!(
                r#"<span class="chip">{}</span>"#,
                esc(take_chars(&title, 32), false)
            ));
        }
    }
    let n = assets.len().to_string();
    let mut body = format!(
        r#"<p class="sec-sub">{}</p>{}<div class="assets">{}</div>"#,
        esc(rlv("asset.scope", &[("n", &n)]), false),
        asset_map_svg(&assets),
        cards.join("")
    );
    if !extra.is_empty() {
        body.push_str(&format!(
            r#"<div class="sum-foot" style="margin-top:16px"><b>{}</b> {}</div>"#,
            esc(rl("asset.rest"), false),
            extra.join("")
        ));
    }
    body
}

fn index_table(items: &[Obj]) -> String {
    let sevmap = i18n::sev_map(None);
    let mut rows = Vec::new();
    for it in items {
        let sev = gstr(it, "sev");
        let dot = sev_dot(&sev);
        let label = sevmap
            .get(sev.as_str())
            .cloned()
            .unwrap_or_else(|| sev.clone());
        rows.push(format!(
            r##"<tr><td>{}</td><td><span class="s-dot" style="background:{dot}"></span>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a class="anchor" href="#{}">{}</a></td></tr>"##,
            as_text(it.get("n").unwrap_or(&Value::Null)),
            esc(&label, false),
            esc(gstr(it, "title"), false),
            esc(gstr(it, "cat"), false),
            esc(gstr(it, "verify"), false),
            gstr(it, "anchor"),
            esc(rl("idx.jump"), false)
        ));
    }
    format!(
        r#"<table class="tbl"><thead><tr><th style="width:56px">#</th><th style="width:90px">{}</th><th>{}</th><th style="width:120px">{}</th><th style="width:90px">{}</th><th style="width:64px">{}</th></tr></thead><tbody>{}</tbody></table>"#,
        esc(rl("idx.sev"), false),
        esc(rl("idx.title"), false),
        esc(rl("idx.cat"), false),
        esc(rl("idx.status"), false),
        esc(rl("idx.anchor"), false),
        rows.join("")
    )
}

fn paras(val: &str) -> String {
    let s = val.trim();
    if s.is_empty() {
        return rl("missing_p");
    }
    if s.trim_start().starts_with('<') {
        return sanitize_visible(s);
    }
    let mut parts: Vec<&str> = Regex::new(r"\n{2,}")
        .ok()
        .map(|re| re.split(s).filter(|p| !p.trim().is_empty()).collect())
        .unwrap_or_default();
    if parts.is_empty() {
        parts = vec![s];
    }
    parts
        .into_iter()
        .map(|p| format!("<p>{}</p>", esc(sanitize_visible(p.trim()), false)))
        .collect()
}

fn steps_ol(steps: &[String]) -> String {
    let mut lis = String::new();
    for s in steps {
        if s.trim().is_empty() {
            continue;
        }
        lis.push_str(&format!("<li>{}</li>", esc(sanitize_visible(s), false)));
    }
    if lis.is_empty() {
        lis = format!("<li>{}</li>", esc(rl("missing_steps"), false));
    }
    format!("<ol>{lis}</ol>")
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(as_text)
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn fixes_html(fixes: &[String], verify: &str, enrich: Option<&Obj>) -> String {
    let mut now: Vec<String> = string_list(enrich.and_then(|e| e.get("fixes_now")))
        .into_iter()
        .map(|s| sanitize_visible(&s))
        .filter(|s| !s.is_empty())
        .collect();
    let mut root: Vec<String> = string_list(enrich.and_then(|e| e.get("fixes_root")))
        .into_iter()
        .map(|s| sanitize_visible(&s))
        .filter(|s| !s.is_empty())
        .collect();
    let items: Vec<String> = fixes
        .iter()
        .map(|s| sanitize_visible(s))
        .filter(|s| !s.is_empty())
        .collect();
    if now.is_empty() && root.is_empty() {
        if items.len() >= 2 {
            let mid = (items.len() / 2).max(1);
            now = items[..mid].to_vec();
            root = items[mid..].to_vec();
        } else {
            now = if items.is_empty() {
                vec![rl("fix.default1"), rl("fix.default2")]
            } else {
                items
            };
            root = vec![if sanitize_visible(verify).is_empty() {
                rl("fix.verify")
            } else {
                sanitize_visible(verify)
            }];
        }
    }
    if root.is_empty() {
        root = vec![if sanitize_visible(verify).is_empty() {
            rl("fix.baseline")
        } else {
            sanitize_visible(verify)
        }];
    }
    let ul = |xs: &[String]| {
        xs.iter()
            .map(|x| format!("<li>{}</li>", esc(x, false)))
            .collect::<String>()
    };
    format!(
        r#"<div class="fix-grid"><div class="fix-box"><h5 class="now">⚠ {}</h5><ul>{}</ul></div><div class="fix-box"><h5 class="root">✔ {}</h5><ul>{}</ul></div></div>"#,
        esc(rl("fix.now"), false),
        ul(&now),
        esc(rl("fix.root"), false),
        ul(&root)
    )
}

fn curl_of(f: &Obj) -> String {
    let poc = f.get("poc").and_then(Value::as_object);
    let raw = poc
        .map(|p| gstr(p, "curl"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| gstr(f, "poc_curl"));
    real_poc_text(&raw)
}

fn exploit_html(steps: &[String], f: &Obj, enrich: Option<&Obj>) -> String {
    let precond = enrich
        .map(|e| gstr(e, "prerequisites"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rl("precond"));
    let impact = enrich
        .map(|e| gstr(e, "impact"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            let a = gstr(f, "impact_detail");
            if !a.is_empty() {
                a
            } else {
                let b = gstr(f, "impact");
                if b.is_empty() {
                    rl("impact_default")
                } else {
                    b
                }
            }
        });
    let curl = curl_of(f);
    let pre = if curl.is_empty() {
        String::new()
    } else {
        format!("<pre>{}</pre>", esc(&curl, false))
    };
    format!(
        r#"{}{pre}<p style="font-size:13px;color:var(--muted)"><b>{}</b>{}</p><p style="font-size:13px;color:var(--muted)"><b>{}</b>{}</p>"#,
        steps_ol(steps),
        esc(rl("label.precond"), false),
        esc(sanitize_visible(&precond), false),
        esc(rl("label.impact"), false),
        esc(sanitize_visible(&take_chars(&impact, 400)), false)
    )
}

fn evidence_html(f: &Obj) -> String {
    let curl = curl_of(f);
    let evidence = gstr(f, "evidence");
    let http_raw = gstr(f, "http_raw");
    let url = gstr(f, "proof_url");
    let detail = {
        let a = gstr(f, "verification_detail");
        if a.is_empty() {
            gstr(f, "verify_note")
        } else {
            a
        }
    };
    let mut chunks = Vec::new();
    if !evidence.is_empty() {
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span><span>{}</span></div>"#,
            esc(rl("ev.evidence"), false),
            esc(take_chars(&evidence, 4000), false)
        ));
    }
    if !detail.is_empty() {
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span><span>{}</span></div>"#,
            esc(rl("ev.detail"), false),
            esc(take_chars(&detail, 2000), false)
        ));
    }
    if !url.is_empty() {
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span><span class="mono"><a href="{}" target="_blank" rel="noopener">{}</a></span></div>"#,
            esc(rl("ev.url"), false),
            esc(&url, true),
            esc(&url, false)
        ));
    }
    if !curl.is_empty() {
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span></div><pre>{}</pre>"#,
            esc(rl("ev.curl"), false),
            esc(&curl, false)
        ));
    }
    if !http_raw.is_empty() {
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span></div><pre>{}</pre>"#,
            esc(rl("ev.http"), false),
            esc(take_chars(&http_raw, 4000), false)
        ));
    }
    let steps = string_list(f.get("manual_steps"));
    if !steps.is_empty() {
        let shown: Vec<String> = steps.into_iter().take(8).collect();
        chunks.push(format!(
            r#"<div class="row"><span class="k">{}</span></div>{}"#,
            esc(rl("ev.steps"), false),
            steps_ol(&shown)
        ));
    }
    if chunks.is_empty() {
        chunks.push(format!("<pre>{}</pre>", esc(rl("ev.missing"), false)));
    }
    format!(
        r#"<details class="ev"><summary>{}</summary><div class="ev-body">{}</div></details>"#,
        esc(rl("ev.summary"), false),
        chunks.join("")
    )
}

fn verify_label_slot(f: &Obj) -> String {
    let st = gstr(f, "verification_status").to_ascii_lowercase();
    let vm = i18n::verify_map(None);
    vm.get(st.as_str()).cloned().unwrap_or_else(|| rl("intel"))
}

fn category_of(f: &Obj) -> String {
    let s = sanitize_visible(&gstr(f, "category"));
    if s.is_empty() {
        rl("uncat")
    } else {
        s
    }
}

fn title_of(f: &Obj) -> String {
    let s = sanitize_visible(&gstr(f, "title"));
    if s.is_empty() {
        rl("untitled")
    } else {
        s
    }
}

fn anchor_of(n: usize) -> String {
    format!("vuln-{n:02}")
}

pub fn render_vf_card(f: &Obj, n: usize, enrich: Option<&Obj>) -> String {
    let anchor = anchor_of(n);
    let sev = sev_bucket(f);
    let chip = sev_chip(&sev);
    let vlab = verify_label_slot(f);
    let mut intro = enrich.map(|e| gstr(e, "intro")).unwrap_or_default();
    let mut impact = enrich.map(|e| gstr(e, "impact")).unwrap_or_default();
    let mut steps = string_list(enrich.and_then(|e| e.get("steps")));
    let mut fixes = string_list(enrich.and_then(|e| e.get("fixes")));
    let verify = enrich.map(|e| gstr(e, "verify")).unwrap_or_default();
    if intro.is_empty() {
        intro = {
            let a = gstr(f, "mechanism");
            if !a.is_empty() {
                a
            } else {
                let b = gstr(f, "root_cause");
                if !b.is_empty() {
                    b
                } else {
                    let c = gstr(f, "description");
                    if c.is_empty() {
                        rl("missing")
                    } else {
                        c
                    }
                }
            }
        };
    }
    if impact.is_empty() {
        impact = {
            let a = gstr(f, "impact_detail");
            if !a.is_empty() {
                a
            } else {
                gstr(f, "impact")
            }
        };
    }
    if steps.is_empty() {
        steps = string_list(f.get("manual_steps"));
    }
    if fixes.is_empty() {
        let blob = format!("{intro}{}", title_of(f));
        let second = if blob.contains("口令") || blob.to_ascii_lowercase().contains("password") {
            rl("vf.fix_pwd")
        } else {
            rl("vf.fix_iso")
        };
        fixes = vec![rl("vf.fix_auth"), second];
    }
    let mut intro_html = paras(&intro);
    if !impact.is_empty() && !intro.trim_start().starts_with('<') {
        intro_html.push_str(&paras(&impact));
    }
    let verified = rl("verify.verified");
    let pending = rl("verify.pending");
    let vcolor = if vlab == verified {
        "var(--ok)"
    } else if vlab == pending {
        "var(--warning)"
    } else {
        "var(--muted)"
    };
    let sev_name = i18n::sev_map(None)
        .get(sev.as_str())
        .cloned()
        .unwrap_or_else(|| sev.clone());
    let second = if gbool(f, "secondary_verified") {
        rl("second_yes")
    } else {
        rl("second_no")
    };
    format!(
        r#"<article class="vf {chip}" id="{anchor}"><div class="vhead"><div class="vtitle-row"><span class="sev-chip {chip}">{}</span><h3>{}</h3></div><div class="vmeta"><span>{} {}</span><span>{} <b style="color:{vcolor}">{}</b></span><span>{}</span></div></div><div class="vbody"><div class="vsec"><h4><span class="tick">①</span> {}</h4>{intro_html}</div><div class="vsec"><h4><span class="tick">②</span> {}</h4>{}</div><div class="vsec"><h4><span class="tick g">③</span> {}</h4>{}</div>{}</div></article>"#,
        esc(&sev_name, false),
        esc(title_of(f), false),
        esc(rl("vf.type"), false),
        esc(category_of(f), false),
        esc(rl("vf.status"), false),
        esc(&vlab, false),
        esc(&second, false),
        esc(rl("vf.intro"), false),
        esc(rl("vf.exploit"), false),
        exploit_html(&steps, f, enrich),
        esc(rl("vf.fix"), false),
        fixes_html(&fixes, &verify, enrich),
        evidence_html(f)
    )
}

fn generic_shell_title(title: &str) -> bool {
    let compact = |text: &str| {
        text.chars()
            .filter(|c| {
                !c.is_whitespace()
                    && !matches!(c, ':' | '：' | '（' | '）' | '(' | ')' | '@' | '.' | '-')
                    && !c.is_ascii_digit()
            })
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let raw = compact(title);
    let stripped = compact(&leak_re().replace_all(title, ""));
    let generic = [
        "",
        "getshellroot",
        "getshell",
        "立足点shellroot",
        "立足点shell",
        "root",
    ];
    generic.contains(&raw.as_str()) || generic.contains(&stripped.as_str())
}

fn access_bucket(node: &Obj) -> String {
    let key = gstr(node, "key");
    let title = gstr(node, "title");
    let blob = format!("{key} {title}");
    let low = blob.to_ascii_lowercase();
    let tags: HashSet<String> = tags_of(&g(node, "tags"))
        .into_iter()
        .map(|t| t.to_ascii_lowercase())
        .collect();
    static HOST: LazyLock<Regex> =
        LazyLock::new(|| re(r"(?i)宿主|host[-_ ]?root|hostroot|docker[-_ ]?host|外层宿主"));
    static PORT: LazyLock<Regex> = LazyLock::new(|| re(r"(?:(?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b"));
    static IPV4: LazyLock<Regex> = LazyLock::new(|| re(r"(?:\d{1,3}\.){3}\d{1,3}"));
    if tags.contains("docker-host")
        || tags.contains("host-root")
        || tags.contains("escaped")
        || HOST.is_match(&blob)
        || low.contains("hostroot")
        || low.contains("host-root")
    {
        return "host-root".into();
    }
    for (needle, name) in [
        ("linkvault", "linkvault"),
        ("aegis", "aegis"),
        ("pan-os", "panos"),
        ("panos", "panos"),
        ("gitlab", "gitlab"),
        ("render again", "renderagain"),
        ("renderagain", "renderagain"),
    ] {
        if low.contains(needle) {
            return format!("app:{name}");
        }
    }
    if let Some(c) = PORT.captures(&blob).and_then(|c| c.get(1)) {
        return format!("port:{}", c.as_str());
    }
    if let Some(m) = IPV4.find(&blob) {
        return format!("ip:{}", m.as_str());
    }
    format!("key:{key}")
}

pub fn obtained_access_labels(data: &Obj) -> Vec<String> {
    let nodes = data
        .get("graph")
        .and_then(Value::as_object)
        .map(|g| obj_list(g, "nodes"))
        .unwrap_or_default();
    let mut order = Vec::new();
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for node in nodes {
        if !node_is_landed_shell(
            &gstr(&node, "type"),
            &gstr(&node, "key"),
            &tags_of(&g(&node, "tags")),
            gbool(&node, "is_rce"),
        ) {
            continue;
        }
        let mut title = sanitize_visible(&gstr(&node, "title")).trim().to_string();
        if title.is_empty() || generic_shell_title(&title) {
            title.clear();
        }
        let bucket = access_bucket(&node);
        if !groups.contains_key(&bucket) {
            order.push(bucket.clone());
        }
        groups.entry(bucket).or_default().push(title);
    }
    let app_text: Vec<(String, String)> = order
        .iter()
        .filter(|k| k.starts_with("app:"))
        .map(|k| {
            (
                k.clone(),
                groups.get(k).map(|v| v.join(" ")).unwrap_or_default(),
            )
        })
        .collect();
    let keys: Vec<String> = order.clone();
    for key in keys {
        if key.starts_with("app:") || key == "host-root" {
            continue;
        }
        let token = key.split_once(':').map(|(_, t)| t).unwrap_or("");
        if token.len() < 4 {
            continue;
        }
        let home = app_text
            .iter()
            .find(|(_, text)| text.contains(token))
            .map(|(k, _)| k.clone());
        if let Some(home) = home {
            if let Some(titles) = groups.remove(&key) {
                groups.entry(home).or_default().extend(titles);
            }
        }
    }
    let mut labels = Vec::new();
    for key in &order {
        let Some(titles) = groups.get(key) else {
            continue;
        };
        let mut real: Vec<&str> = titles
            .iter()
            .filter(|s| !s.is_empty())
            .map(String::as_str)
            .collect();
        real.sort_by(|a, b| a.chars().count().cmp(&b.chars().count()).then(a.cmp(b)));
        let label = real.first().copied().unwrap_or("已获取权限");
        labels.push(take_chars(label, 90));
    }
    labels.sort();
    labels
}

fn kpis_html(data: &Obj, counts: &Obj, findings: &[Obj]) -> String {
    let total = gint(counts, "total");
    let crit = gint(counts, "critical");
    let high = gint(counts, "high");
    let med = gint(counts, "medium");
    let low = gint(counts, "low") + gint(counts, "info");
    let (verified, _, _) = verify_buckets(findings);
    let st = graph_stats_view(data);
    let n_svc = {
        let s = gint(&st, "services");
        if s == 0 {
            gint(&st, "nodes")
        } else {
            s
        }
    };
    let p0 = if crit > 0 {
        "P0"
    } else if high > 0 {
        "P1"
    } else {
        "P2"
    };
    let access_n = obtained_access_labels(data).len();
    let goal = if access_n > 0 {
        format!(
            r#"<div class="kpi goal"><div class="k-ico">🏁</div><div class="k-num">{access_n}</div><div class="k-label">{}</div></div>"#,
            esc(rl("kpi.got_access"), false)
        )
    } else {
        format!(
            r#"<div class="kpi"><div class="k-ico">🏁</div><div class="k-num">0</div><div class="k-label">{}</div></div>"#,
            esc(rl("kpi.no_access"), false)
        )
    };
    format!(
        r#"<div class="kpis" style="margin-top:22px"><div class="kpi"><div class="k-ico">🧾</div><div class="k-num">{total}</div><div class="k-label">{}</div></div><div class="kpi crit"><div class="k-ico">🔥</div><div class="k-num">{crit}</div><div class="k-label">{}</div></div><div class="kpi high"><div class="k-ico">⚠️</div><div class="k-num">{high}</div><div class="k-label">{}</div></div><div class="kpi med"><div class="k-ico">📄</div><div class="k-num">{med} / {low}</div><div class="k-label">{}</div></div><div class="kpi teal"><div class="k-ico">🖥️</div><div class="k-num">{n_svc}</div><div class="k-label">{}</div></div><div class="kpi"><div class="k-ico">✅</div><div class="k-num">{verified}</div><div class="k-label">{}</div></div>{goal}<div class="kpi"><div class="k-ico">🎯</div><div class="k-num">{p0}</div><div class="k-label">{}</div></div></div>"#,
        esc(rl("kpi.total"), false),
        esc(rl("kpi.crit"), false),
        esc(rl("kpi.high"), false),
        esc(rl("kpi.medlow"), false),
        esc(rl("kpi.svc"), false),
        esc(rl("verify.verified"), false),
        esc(rl("kpi.fixnow"), false)
    )
}

fn charts_html(findings: &[Obj], counts: &Obj) -> String {
    let total = gint(counts, "total");
    let hot = gint(counts, "critical") + gint(counts, "high");
    let pct = if total == 0 {
        0
    } else {
        (100.0 * hot as f64 / total.max(1) as f64).round() as i64
    };
    let (verified, pending, intel) = verify_buckets(findings);
    let total_s = total.to_string();
    let hot_s = hot.to_string();
    let pct_s = pct.to_string();
    format!(
        r#"<div class="charts"><div class="chart-card"><h4>{}</h4>{}<div class="note">{}</div></div><div class="chart-card"><h4>{}</h4><div class="verify-panel">{}<div class="verify-legend"><div class="row"><i style="background:var(--success)"></i>{} <b>{verified}</b></div><div class="row"><i style="background:var(--warning)"></i>{} <b>{pending}</b></div><div class="row"><i style="background:var(--muted-soft)"></i>{} <b>{intel}</b></div></div></div></div></div>"#,
        esc(rlv("chart.sev_title", &[("n", &total_s)]), false),
        severity_bars_svg(counts),
        esc(
            rlv("chart.sev_note", &[("hot", &hot_s), ("pct", &pct_s)]),
            false
        ),
        esc(rl("chart.verify_title"), false),
        verify_donut_svg(findings),
        esc(rl("verify.verified"), false),
        esc(rl("verify.pending"), false),
        esc(rl("chart.node_records"), false)
    )
}

fn rich_or_block(val: &str) -> String {
    let s = val.trim();
    if s.is_empty() {
        return rl("missing_p");
    }
    if s.contains('<') {
        sanitize_visible(s)
    } else {
        format!("<p>{}</p>", esc(sanitize_visible(s), false))
    }
}

fn default_conclusions(data: &Obj, counts: &Obj) -> String {
    let tops: Vec<&Obj> = obj_list(data, "findings")
        .into_iter()
        .filter(|f| matches!(sev_bucket(f).as_str(), "critical" | "high" | "medium"))
        .take(5)
        .collect();
    if tops.is_empty() {
        return format!(
            r#"<ul class="concl"><li><span class="tag-sev med">{}</span><span>{}</span></li></ul>"#,
            esc(rl("sev.medium"), false),
            esc(rl("sum.empty"), false)
        );
    }
    let sevmap = i18n::sev_map(None);
    let lis = tops
        .iter()
        .map(|f| {
            let sev = sev_bucket(f);
            let label = sevmap
                .get(sev.as_str())
                .cloned()
                .unwrap_or_else(|| sev.clone());
            format!(
                r#"<li><span class="tag-sev {}">{}</span><span>{}</span></li>"#,
                sev_chip(&sev),
                label,
                esc(title_of(f), false)
            )
        })
        .collect::<String>();
    let grade = if gint(counts, "critical") > 0 {
        rl("sev.critical")
    } else if gint(counts, "high") > 0 {
        rl("sev.high")
    } else {
        rl("sum.grade_mid")
    };
    format!(
        r#"<ul class="concl">{lis}</ul><p style="margin-top:12px;font-size:13px;color:var(--body-strong)">{}<b style="color:var(--error)">{}</b>。</p>"#,
        esc(rl("sum.grade"), false),
        esc(&grade, false)
    )
}

fn summary_html(data: &Obj, counts: &Obj, enrich: Option<&Obj>) -> String {
    let p = data.get("project").and_then(Value::as_object);
    let target = p
        .map(|p| gstr(p, "target"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rl("auth_target"));
    let total = gint(counts, "total").to_string();
    let crit = gint(counts, "critical").to_string();
    let high = gint(counts, "high").to_string();
    let shell = if gbool(data, "has_shell") {
        rl("sum.shell_yes")
    } else {
        rl("sum.shell_no")
    };
    let target_esc = esc(&target, false);
    let overview = rlv(
        "sum.overview",
        &[
            ("target", &target_esc),
            ("total", &total),
            ("crit", &crit),
            ("high", &high),
            ("shell", &shell),
        ],
    );
    let left = enrich
        .map(|e| gstr(e, "summary_overview"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("<p>{overview}"));
    let right = enrich
        .map(|e| gstr(e, "summary_conclusions"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default_conclusions(data, counts));
    let note = enrich
        .map(|e| gstr(e, "verify_note"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rl("sum.note"));
    let left_html = if left.trim_start().starts_with('<') {
        left
    } else {
        rich_or_block(&left)
    };
    let right_html = if right.trim_start().starts_with('<') {
        right
    } else {
        rich_or_block(&right)
    };
    let mut left_html = sanitize_visible(&left_html);
    let accesses = obtained_access_labels(data);
    if !accesses.is_empty() {
        let items = accesses
            .iter()
            .map(|l| format!("<li>{}</li>", esc(l, false)))
            .collect::<String>();
        left_html.push_str(&format!(
            "<p><b>{}</b></p><ul>{items}</ul>",
            esc(rl("kpi.got_access"), false)
        ));
    }
    let right_html = sanitize_visible(&right_html);
    let note_html = if note.contains('<') {
        note
    } else {
        esc(sanitize_visible(&note), false)
    };
    format!(
        r#"<div class="sum-grid"><div class="sum-card"><h3><span class="dot"></span>{}</h3>{left_html}</div><div class="sum-card"><h3><span class="dot"></span>{}</h3>{right_html}</div></div><div class="sum-foot"><b>{}</b>{note_html}</div>"#,
        esc(rl("sum.left"), false),
        esc(rl("sum.right"), false),
        esc(rl("sum.verify"), false)
    )
}

fn cover_meta(data: &Obj, enrich: Option<&Obj>) -> String {
    let p = data.get("project").and_then(Value::as_object);
    let name = sanitize_visible(
        &p.map(|p| gstr(p, "name"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("authorized")),
    );
    let target = sanitize_visible(
        &p.map(|p| gstr(p, "target"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("cluster_target")),
    );
    let date = take_chars(&gstr(data, "generated_at"), 10);
    let line1 = sanitize_visible(
        &enrich
            .map(|e| gstr(e, "title_line"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| name.clone()),
    );
    let accent = sanitize_visible(
        &enrich
            .map(|e| gstr(e, "title_accent"))
            .unwrap_or_else(|| target.clone()),
    );
    let h1 = if !accent.is_empty() && !line1.contains(&accent) {
        format!(
            r#"<h1>{}<br><span class="accent">{}</span></h1>"#,
            esc(&line1, false),
            esc(&accent, false)
        )
    } else {
        format!("<h1>{}</h1>", esc(&line1, false))
    };
    let sub = enrich
        .map(|e| gstr(e, "sub"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rlv("cover.sub", &[("name", &name)]));
    let findings = obj_list(data, "findings");
    let owned: Vec<Obj> = findings.iter().map(|f| (*f).clone()).collect();
    let (n_ok, _, _) = verify_buckets(&owned);
    let st = graph_stats_view(data);
    let mut goal = String::new();
    if gbool(data, "has_shell") {
        let gtxt = enrich
            .map(|e| gstr(e, "goal_text"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("cover.goal"));
        let extra = sanitize_visible(
            &enrich
                .map(|e| gstr(e, "goal_detail"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| rl("cover.goal_extra")),
        );
        goal = format!(
            r#"<div class="goal-badge"><span class="flag">{}</span><span style="color:var(--on-dark-soft)">{}</span></div>"#,
            esc(sanitize_visible(&gtxt), false),
            esc(&extra, false)
        );
    }
    let n_ok_s = n_ok.to_string();
    let nodes = gint(&st, "nodes").to_string();
    let edges = gint(&st, "edges").to_string();
    format!(
        r#"<span class="tag">AUTHORIZED PENTEST · {}</span>{h1}<p class="sub">{}</p><div class="meta"><div class="m"><b>{}</b> · {}</div><div class="m"><b>{}</b> · {}</div><div class="m"><b>{}</b> · {}</div><div class="m"><b>{}</b> · {}</div></div>{goal}"#,
        esc(&date, false),
        esc(sanitize_visible(&sub), false),
        esc(rl("cover.entry"), false),
        esc(&target, false),
        esc(rl("cover.nature"), false),
        esc(rl("cover.nature_v"), false),
        esc(rl("cover.verify"), false),
        esc(rlv("cover.verify_v", &[("n", &n_ok_s)]), false),
        esc(rl("cover.graph"), false),
        esc(
            rlv("cover.graph_v", &[("nodes", &nodes), ("edges", &edges)]),
            false
        )
    )
}

fn footer_html(data: &Obj) -> String {
    let p = data.get("project").and_then(Value::as_object);
    let date = take_chars(&gstr(data, "generated_at"), 10);
    let name = sanitize_visible(
        &p.map(|p| gstr(p, "name"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("authorized")),
    );
    let target = sanitize_visible(&p.map(|p| gstr(p, "target")).unwrap_or_default());
    let who = if target.is_empty() {
        name
    } else {
        format!("{name}（{target}）")
    };
    format!(
        r#"<footer><span>{} · {}</span><span>{}</span></footer>"#,
        esc(rl("brand"), false),
        esc(&who, false),
        esc(rlv("footer.src", &[("date", &date)]), false)
    )
}

fn findings_slot(cards: &[String], label: &str) -> String {
    if cards.is_empty() {
        return String::new();
    }
    let n = cards.len().to_string();
    format!(
        r#"<p class="sec-sub">{}</p>{}"#,
        esc(rlv("findings.sub", &[("label", label), ("n", &n)]), false),
        cards.join("")
    )
}

fn drop_empty_finding_sections(html: &str) -> String {
    let mut html = html.to_string();
    for sev in ["critical", "high", "medium", "low"] {
        let pat = format!(r#"(?s)<section class="sec" id="{sev}">.*?</section>\s*"#);
        let Ok(re) = Regex::new(&pat) else { continue };
        html = re
            .replace(&html, |c: &regex::Captures| {
                let m = c.get(0).map(|m| m.as_str()).unwrap_or("");
                if m.contains("class=\"vf") {
                    m.to_string()
                } else {
                    String::new()
                }
            })
            .into_owned();
    }
    html
}

fn patch_finding_heads(html: &str, counts: &[(&str, usize)]) -> String {
    let specs = [
        ("critical", "06", "sec06", "Critical"),
        ("high", "07", "sec07", "High"),
        ("medium", "08", "sec08", "Medium"),
        ("low", "09", "sec09", "Low"),
    ];
    let loc = i18n::get_report_lang();
    let mut html = html.to_string();
    for (sev, num, zk, en_short) in specs {
        let n = counts
            .iter()
            .find(|(k, _)| *k == sev)
            .map(|(_, n)| *n)
            .unwrap_or(0);
        if n == 0 {
            continue;
        }
        let zh_shell = match zk {
            "sec06" => "严重漏洞",
            "sec07" => "高危漏洞",
            "sec08" => "中危漏洞",
            _ => "低危漏洞",
        };
        let old = format!(
            r#"<span class="num">{num}</span><h2>{zh_shell}</h2><span class="en">{en_short} Findings</span>"#
        );
        let title = rl(zk);
        let n_s = n.to_string();
        let count = rlv("count_items", &[("n", &n_s)]);
        let new = if loc == "en" {
            format!(
                r#"<span class="num">{num}</span><h2>{} ({en_short} · {n})</h2>"#,
                esc(&title, false)
            )
        } else {
            let en_lab = rl(&format!("{zk}en"));
            let en_show = if en_lab.is_empty() {
                format!("{en_short} Findings")
            } else {
                en_lab
            };
            format!(
                r#"<span class="num">{num}</span><h2>{}（{en_short} · {}）</h2><span class="en">{}</span>"#,
                esc(&title, false),
                esc(&count, false),
                esc(&en_show, false)
            )
        };
        html = html.replacen(&old, &new, 1);
    }
    html
}

pub fn facts_digest(data: &Obj) -> String {
    let mut findings = Vec::new();
    for f in obj_list(data, "findings") {
        let poc = f.get("poc").and_then(Value::as_object);
        let curl = real_poc_text(
            &poc.map(|p| gstr(p, "curl"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| gstr(&f, "poc_curl")),
        );
        let mut item = Obj::new();
        put(&mut item, "id", g(&f, "id"));
        put(&mut item, "title", g(&f, "title"));
        put(&mut item, "severity", display_finding_severity(&f));
        put(
            &mut item,
            "evidence",
            take_chars(&gstr(&f, "evidence"), 800),
        );
        put(&mut item, "curl", take_chars(&curl, 400));
        put(&mut item, "vs", g(&f, "verification_status"));
        findings.push(item);
    }
    let p = data.get("project").and_then(Value::as_object);
    let path = data
        .get("graph")
        .and_then(Value::as_object)
        .and_then(|g| g.get("rce_path"))
        .and_then(Value::as_object)
        .and_then(|r| r.get("path"))
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let mut blob = Obj::new();
    put(
        &mut blob,
        "pid",
        p.map(|p| g(p, "id")).unwrap_or(Value::Null),
    );
    put(
        &mut blob,
        "name",
        p.map(|p| g(p, "name")).unwrap_or(Value::Null),
    );
    put(
        &mut blob,
        "target",
        p.map(|p| g(p, "target")).unwrap_or(Value::Null),
    );
    put(&mut blob, "has_shell", gbool(data, "has_shell"));
    blob.insert("rce".into(), path);
    put(&mut blob, "findings", findings);
    put(&mut blob, "theme_rev", THEME_REV);
    put(&mut blob, "prompt_rev", PROMPT_REV);
    let text = canon_json(&Value::Object(blob));
    hex::encode(Sha256::digest(text.as_bytes()))
}

pub fn cache_stem(project_id: &str, digest: &str, lang: Option<&str>) -> String {
    let loc = i18n::normalize_locale(lang);
    format!(
        "{}-{}-{loc}",
        take_chars(project_id, 24),
        take_chars(digest, 16)
    )
}

pub fn assemble_deliverable(
    data: &Obj,
    enrich: Option<&Obj>,
    lang: Option<&str>,
) -> Result<String, String> {
    let current = if lang.is_some() {
        lang
    } else {
        Some(i18n::get_report_lang())
    };
    let loc = i18n::set_report_lang(current);
    let shell = load_shell();
    let p = data.get("project").and_then(Value::as_object);
    let findings: Vec<Obj> = obj_list(data, "findings").into_iter().cloned().collect();
    let counts = counts_of(&findings);
    let mut indexed = Vec::new();
    let mut by_sev: HashMap<String, Vec<String>> = ["critical", "high", "medium", "low"]
        .into_iter()
        .map(|k| (k.to_string(), Vec::new()))
        .collect();
    for (i, f) in findings.iter().enumerate() {
        let n = i + 1;
        let sev = sev_bucket(f);
        let bucket = if matches!(sev.as_str(), "critical" | "high" | "medium") {
            sev.clone()
        } else {
            "low".into()
        };
        let anchor = anchor_of(n);
        let enr = enrich
            .and_then(|e| e.get("findings"))
            .and_then(Value::as_object)
            .and_then(|m| {
                m.get(&anchor)
                    .or_else(|| m.get(&gstr(f, "id")))
                    .and_then(Value::as_object)
            });
        let card = render_vf_card(f, n, enr);
        by_sev.entry(bucket.clone()).or_default().push(card);
        let mut row = Obj::new();
        put(&mut row, "n", n as i64);
        put(&mut row, "anchor", anchor);
        put(&mut row, "title", title_of(f));
        put(
            &mut row,
            "sev",
            if bucket == "low" {
                "low"
            } else {
                bucket.as_str()
            },
        );
        put(&mut row, "cat", category_of(f));
        put(&mut row, "verify", verify_label_slot(f));
        indexed.push(row);
    }
    let name = sanitize_visible(
        &p.map(|p| gstr(p, "name"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| rl("authorized")),
    );
    let target = sanitize_visible(&p.map(|p| gstr(p, "target")).unwrap_or_default());
    let doc_title = if target.is_empty() {
        format!("{name} · {}", rl("doc_suffix"))
    } else {
        format!("{name} · {target} · {}", rl("doc_suffix"))
    };
    let mapping = vec![
        ("title".into(), esc(&doc_title, false)),
        ("cover-meta".into(), cover_meta(data, enrich)),
        ("summary".into(), summary_html(data, &counts, enrich)),
        ("kpis".into(), kpis_html(data, &counts, &findings)),
        ("charts".into(), charts_html(&findings, &counts)),
        (
            "path".into(),
            path_board(
                data,
                &enrich.map(|e| gstr(e, "path_note")).unwrap_or_default(),
            ),
        ),
        ("assets".into(), assets_html(data)),
        ("index-table".into(), index_table(&indexed)),
        (
            "findings-critical".into(),
            findings_slot(
                by_sev.get("critical").map(Vec::as_slice).unwrap_or(&[]),
                &rl("sev.critical"),
            ),
        ),
        (
            "findings-high".into(),
            findings_slot(
                by_sev.get("high").map(Vec::as_slice).unwrap_or(&[]),
                &rl("sev.high"),
            ),
        ),
        (
            "findings-medium".into(),
            findings_slot(
                by_sev.get("medium").map(Vec::as_slice).unwrap_or(&[]),
                &rl("sev.medium"),
            ),
        ),
        (
            "findings-low".into(),
            findings_slot(
                by_sev.get("low").map(Vec::as_slice).unwrap_or(&[]),
                &rl("sev.low"),
            ),
        ),
        ("footer".into(), footer_html(data)),
    ];
    let head_counts = [
        (
            "critical",
            by_sev.get("critical").map(|v| v.len()).unwrap_or(0),
        ),
        ("high", by_sev.get("high").map(|v| v.len()).unwrap_or(0)),
        ("medium", by_sev.get("medium").map(|v| v.len()).unwrap_or(0)),
        ("low", by_sev.get("low").map(|v| v.len()).unwrap_or(0)),
    ];
    let finish = |base: String| -> Result<String, String> {
        let html = fill_slots(base, &mapping)?;
        let html = patch_finding_heads(&html, &head_counts);
        Ok(drop_empty_finding_sections(&html))
    };
    let mut html = i18n::apply_shell_chrome(&finish(shell.clone())?, Some(loc));
    static STYLE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)<style[\s\S]*?</style>"));
    let stripped = STYLE.replace_all(&html, "");
    if leak_re().is_match(&stripped) {
        html = leak_re().replace_all(&html, "").into_owned();
    }
    let errs = gate_html(&html, !findings.is_empty());
    if !errs.is_empty() {
        html = i18n::apply_shell_chrome(&finish(load_shell())?, Some(loc));
        let errs = gate_html(&html, !findings.is_empty());
        if !errs.is_empty() {
            return Err(format!("交付母版校验失败：{}", errs.join(",")));
        }
    }
    Ok(html)
}

pub fn parse_claude_enrich(text: &str) -> Obj {
    static THINK: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)<think>[\s\S]*?</think>"));
    static FENCE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)```(?:json)?"));
    let raw = THINK.replace_all(text, "");
    let raw = FENCE.replace_all(&raw, "");
    let objs = json_objects(&raw);
    for data in objs.iter().rev() {
        let Some(m) = data.as_object() else { continue };
        if truth(m.get("title_line").unwrap_or(&Value::Null))
            || truth(m.get("summary_overview").unwrap_or(&Value::Null))
            || truth(m.get("sub").unwrap_or(&Value::Null))
            || truth(m.get("findings").unwrap_or(&Value::Null))
        {
            return m.clone();
        }
    }
    objs.last()
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

pub fn content_disposition(disposition: &str, filename: &str) -> String {
    let mut raw = if filename.is_empty() {
        "report".to_string()
    } else {
        filename.to_string()
    };
    raw = raw.replace(['\r', '\n', '"'], "");
    if raw.is_empty() {
        raw = "report".into();
    }
    let ascii: String = raw.chars().filter(|c| c.is_ascii()).collect();
    let ascii = if ascii.is_empty() {
        "report".to_string()
    } else {
        ascii
    };
    format!(
        r#"{disposition}; filename="{ascii}"; filename*=UTF-8''{}"#,
        quote_component(&raw)
    )
}

fn job_dir(settings: &Settings) -> PathBuf {
    let d = settings.reports_dir.join("export-jobs");
    let _ = std::fs::create_dir_all(&d);
    d
}

fn persist_job(settings: &Settings, job: &Obj) {
    let jid = gstr(job, "id");
    if jid.is_empty() {
        return;
    }
    let mut safe = Obj::new();
    for k in [
        "id",
        "project_id",
        "format",
        "lang",
        "status",
        "percent",
        "message",
        "error",
        "filename",
        "cached",
        "claude",
        "claude_error",
        "pi_role",
        "force",
        "html_path",
        "pdf_path",
    ] {
        safe.insert((*k).to_string(), job.get(k).cloned().unwrap_or(Value::Null));
    }
    if let Ok(text) = serde_json::to_string(&safe) {
        let _ = std::fs::write(job_dir(settings).join(format!("{jid}.json")), text);
    }
}

fn load_job(settings: &Settings, job_id: &str) -> Option<Obj> {
    let path = job_dir(settings).join(format!("{job_id}.json"));
    let text = std::fs::read_to_string(path).ok()?;
    let data: Value = serde_json::from_str(&text).ok()?;
    let obj = data.as_object()?.clone();
    if gstr(&obj, "id") == job_id {
        Some(obj)
    } else {
        None
    }
}

fn job_public(job: &Obj) -> Obj {
    let mut out = Obj::new();
    put(&mut out, "id", g(job, "id"));
    put(&mut out, "project_id", g(job, "project_id"));
    put(&mut out, "format", g(job, "format"));
    let lang = gstr(job, "lang");
    put(
        &mut out,
        "lang",
        if lang.is_empty() { "zh".into() } else { lang },
    );
    put(&mut out, "status", g(job, "status"));
    put(&mut out, "percent", gint(job, "percent"));
    put(&mut out, "message", gstr(job, "message"));
    out.insert(
        "error".into(),
        job.get("error").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "filename".into(),
        job.get("filename").cloned().unwrap_or(Value::Null),
    );
    put(&mut out, "cached", gbool(job, "cached"));
    put(&mut out, "claude", gbool(job, "claude"));
    let err = gstr(job, "claude_error");
    out.insert(
        "claude_error".into(),
        if err.is_empty() {
            Value::Null
        } else {
            Value::String(err)
        },
    );
    let role = gstr(job, "pi_role");
    put(
        &mut out,
        "pi_role",
        if role.is_empty() {
            EXPORT_ROLE.into()
        } else {
            role
        },
    );
    out
}

static JOBS: LazyLock<Mutex<HashMap<String, std::sync::Arc<Mutex<Obj>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LIVE_JOBS: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn should_resume(job: &Obj) -> bool {
    if gstr(job, "status") == "running" {
        return true;
    }
    let err = format!("{} {}", gstr(job, "error"), gstr(job, "message"));
    gstr(job, "status") == "error" && err.contains(RESTART_MARK)
}

fn set_job(
    settings: &Settings,
    job: &std::sync::Arc<Mutex<Obj>>,
    percent: i64,
    message: &str,
    status: &str,
) {
    let mut g = lock(job);
    put(&mut g, "percent", percent.clamp(0, 100));
    put(&mut g, "message", message);
    put(&mut g, "status", status);
    persist_job(settings, &g);
}

pub fn enrich_from_facts(data: &Obj) -> Obj {
    let project = data.get("project").and_then(Value::as_object);
    let name = project
        .map(|p| gstr(p, "name"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "渗透测试".into());
    let target = project.map(|p| gstr(p, "target")).unwrap_or_default();
    let mut findings = Obj::new();
    for (i, f) in obj_list(data, "findings").into_iter().enumerate() {
        let sid = format!("vuln-{:02}", i + 1);
        let repro = {
            let a = gstr(&f, "report_repro").trim().to_string();
            if !a.is_empty() {
                a
            } else {
                let b = gstr(&f, "manual_repro").trim().to_string();
                if b.is_empty() {
                    "未采集".into()
                } else {
                    b
                }
            }
        };
        let fix = {
            let a = gstr(&f, "report_fix").trim().to_string();
            if !a.is_empty() {
                a
            } else {
                let b = gstr(&f, "remediation").trim().to_string();
                if b.is_empty() {
                    "未采集".into()
                } else {
                    b
                }
            }
        };
        let mut slot = Obj::new();
        put(&mut slot, "intro", {
            let a = gstr(&f, "report_summary");
            if !a.is_empty() {
                a
            } else {
                let b = gstr(&f, "description");
                if b.is_empty() {
                    "未采集".into()
                } else {
                    b
                }
            }
        });
        put(&mut slot, "impact", {
            let a = gstr(&f, "report_impact");
            if !a.is_empty() {
                a
            } else {
                gstr(&f, "impact_detail")
            }
        });
        put(&mut slot, "steps", vec![repro]);
        put(&mut slot, "fixes_now", vec![fix]);
        put(&mut slot, "verify", gstr(&f, "report_rating"));
        findings.insert(sid, Value::Object(slot));
    }
    let mut out = Obj::new();
    put(&mut out, "title_line", name.clone());
    put(&mut out, "title_accent", target.clone());
    put(
        &mut out,
        "sub",
        if target.is_empty() {
            name.clone()
        } else {
            target
        },
    );
    put(&mut out, "summary_overview", format!("<p>{name}</p>"));
    out.insert("findings".into(), Value::Object(findings));
    out
}

fn enrich_usable(enrich: &Obj) -> bool {
    if enrich.is_empty() {
        return false;
    }
    truth(enrich.get("title_line").unwrap_or(&Value::Null))
        || truth(enrich.get("summary_overview").unwrap_or(&Value::Null))
        || truth(enrich.get("sub").unwrap_or(&Value::Null))
        || truth(enrich.get("findings").unwrap_or(&Value::Null))
}

fn compact_findings(findings: &[Obj]) -> Vec<Obj> {
    let mut out = Vec::new();
    for (i, f) in findings.iter().take(24).enumerate() {
        let poc = f.get("poc").and_then(Value::as_object);
        let mut item = Obj::new();
        put(&mut item, "slot_id", format!("vuln-{:02}", i + 1));
        put(&mut item, "title", g(&f, "title"));
        put(&mut item, "severity", g(&f, "severity"));
        put(&mut item, "category", g(&f, "category"));
        put(&mut item, "verification", g(&f, "verification_status"));
        put(
            &mut item,
            "secondary_verified",
            gbool(f, "secondary_verified"),
        );
        put(&mut item, "redteam_rating", g(&f, "redteam_rating"));
        put(
            &mut item,
            "description",
            take_chars(&gstr(f, "description"), 2500),
        );
        put(
            &mut item,
            "report_summary",
            take_chars(&gstr(f, "report_summary"), 2500),
        );
        let impact = {
            let a = gstr(f, "report_impact");
            if a.is_empty() {
                gstr(f, "impact_detail")
            } else {
                a
            }
        };
        put(&mut item, "report_impact", take_chars(&impact, 2500));
        let rating = {
            let a = gstr(f, "report_rating");
            if a.is_empty() {
                gstr(f, "redteam_rating_rationale")
            } else {
                a
            }
        };
        put(&mut item, "report_rating", take_chars(&rating, 2500));
        let repro = {
            let a = gstr(f, "report_repro");
            if a.is_empty() {
                gstr(f, "manual_repro")
            } else {
                a
            }
        };
        put(&mut item, "report_repro", take_chars(&repro, 3500));
        let fix = {
            let a = gstr(f, "report_fix");
            if a.is_empty() {
                gstr(f, "remediation")
            } else {
                a
            }
        };
        put(&mut item, "report_fix", take_chars(&fix, 2500));
        put(
            &mut item,
            "evidence",
            take_chars(&gstr(f, "evidence"), 4000),
        );
        let curl = real_poc_text(
            &poc.map(|p| gstr(p, "curl"))
                .unwrap_or_else(|| gstr(f, "poc_curl")),
        );
        put(&mut item, "poc_curl", take_chars(&curl, 2500));
        put(&mut item, "proof_url", g(&f, "proof_url"));
        out.push(item);
    }
    out
}

fn facts_payload(data: &Obj) -> Obj {
    let p = data.get("project").and_then(Value::as_object);
    let gph = data.get("graph").and_then(Value::as_object);
    let nodes = gph.map(|g| obj_list(g, "nodes")).unwrap_or_default();
    let path = gph
        .and_then(|g| g.get("rce_path"))
        .and_then(Value::as_object)
        .and_then(|r| r.get("path"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .take(10)
                .map(|k| {
                    let key = as_text(k);
                    nodes
                        .iter()
                        .find(|n| gstr(n, "key") == key)
                        .map(|n| gstr(n, "title"))
                        .filter(|s| !s.is_empty())
                        .unwrap_or(key)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut assets = Vec::new();
    for sec in obj_list(data, "sections") {
        for a in obj_list(&sec, "assets") {
            if assets.len() >= 40 {
                break;
            }
            let mut item = Obj::new();
            put(&mut item, "title", g(&a, "title"));
            put(&mut item, "kind", g(&a, "kind"));
            put(&mut item, "detail", g(&a, "detail"));
            assets.push(item);
        }
    }
    let findings = obj_list(data, "findings")
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let count = findings.len();
    let mut out = Obj::new();
    let mut project = Obj::new();
    put(
        &mut project,
        "name",
        p.map(|p| g(p, "name")).unwrap_or(Value::Null),
    );
    put(
        &mut project,
        "target",
        p.map(|p| g(p, "target")).unwrap_or(Value::Null),
    );
    out.insert("project".into(), Value::Object(project));
    put(&mut out, "has_shell", g(data, "has_shell"));
    put(
        &mut out,
        "generated_at",
        take_chars(&gstr(data, "generated_at"), 10),
    );
    put(&mut out, "rce_path_titles", path);
    put(&mut out, "assets", assets);
    put(&mut out, "findings", compact_findings(&findings));
    put(&mut out, "finding_count", count as i64);
    out
}

fn export_enrich(
    settings: &Settings,
    facts: &Obj,
    project_id: &str,
    lang: &str,
) -> Result<Obj, String> {
    let loc = i18n::normalize_locale(Some(lang));
    let dumped = serde_json::to_string_pretty(facts).unwrap_or_else(|_| "{}".into());
    let prompt = if loc == "en" {
        format!("# Facts pack (export Pi fills slots only; all JSON prose in English; missing fields: Not collected)\n{}", take_chars(&dumped, 100000))
    } else {
        format!(
            "# 渗透测试事实包（专职导出 Pi 只填槽，禁止整页 HTML）\n{}",
            take_chars(&dumped, 100000)
        )
    };
    let model = role_model(
        settings,
        &[&settings.report_model, &settings.supervisor_model],
    );
    let mut wait = (settings.report_timeout_sec as f64).max(90.0) * 2.0;
    wait = wait.max(60.0).min(240.0);
    if !project_id.is_empty() {
        if let Ok(db) = Db::open(&settings.db_path) {
            let mut payload = Obj::new();
            put(&mut payload, "status", "running");
            put(&mut payload, "role", EXPORT_ROLE);
            put(&mut payload, "message", msg("job_slots", Some(loc), &[]));
            emit_event(&db, project_id, "report_export", &Value::Object(payload));
        }
    }
    let system = i18n::export_system_prompt(Some(loc), EXPORT_SYSTEM);
    let mut last_err = String::new();
    for _ in 0..2 {
        match query_text(&QueryText {
            system_prompt: system.clone(),
            user_prompt: prompt.clone(),
            cwd: settings.data_dir.display().to_string(),
            timeout: wait,
            tools: false,
            model: model.clone(),
            role: EXPORT_ROLE.into(),
            project_id: project_id.to_string(),
        }) {
            Ok(blob) => {
                let parsed = parse_claude_enrich(&blob);
                if enrich_usable(&parsed) {
                    return Ok(parsed);
                }
                last_err = msg("job_bad_json", Some(loc), &[]);
            }
            Err(e) => last_err = take_chars(&e, 400),
        }
    }
    Err(if last_err.is_empty() {
        msg("job_pi_fail", Some(loc), &[("err", "")])
    } else {
        last_err
    })
}

fn safe_name(pid: &str, p: &Obj) -> String {
    static RE: LazyLock<Regex> = LazyLock::new(|| re(r#"[\\/:*?"<>|]+"#));
    let raw = {
        let n = gstr(p, "name");
        if n.is_empty() {
            pid.to_string()
        } else {
            n
        }
    };
    let raw = RE.replace_all(&raw, "_");
    let raw = raw.trim();
    let raw = if raw.is_empty() { pid } else { raw };
    take_chars(raw, 80)
}

fn notify_export(settings: &Settings, pid: &str, status: &str, message: &str) {
    if pid.is_empty() {
        return;
    }
    if let Ok(db) = Db::open(&settings.db_path) {
        let mut payload = Obj::new();
        put(&mut payload, "status", status);
        put(&mut payload, "role", EXPORT_ROLE);
        put(&mut payload, "message", message);
        emit_event(&db, pid, "report_export", &Value::Object(payload));
    }
}

pub fn run_export_job(settings: &Settings, job: &std::sync::Arc<Mutex<Obj>>) {
    let (pid, fmt, loc) = {
        let g = lock(job);
        (
            gstr(&g, "project_id"),
            gstr(&g, "format"),
            i18n::normalize_locale(Some(&gstr(&g, "lang"))),
        )
    };
    {
        let mut g = lock(job);
        put(&mut g, "lang", loc);
    }
    let outcome = (|| -> Result<(), String> {
        let db = Db::open(&settings.db_path)?;
        set_job(
            settings,
            job,
            8,
            &msg("job_facts", Some(loc), &[]),
            "running",
        );
        let data = build_report_data(&db, settings, &pid, false)?;
        let digest = facts_digest(&data);
        let out_dir = &settings.reports_dir;
        std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
        let stem = cache_stem(&pid, &digest, Some(loc));
        let html_path = out_dir.join(format!("{stem}.html"));
        let p = data
            .get("project")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let fname_base = safe_name(&pid, &p);
        let force = lock(job).get("force").map(truth).unwrap_or(true);
        let cached = !force
            && html_path.is_file()
            && html_path.metadata().map(|m| m.len() > 200).unwrap_or(false);
        let html_doc = if cached {
            set_job(
                settings,
                job,
                72,
                &msg("job_cache", Some(loc), &[]),
                "running",
            );
            let mut g = lock(job);
            put(&mut g, "cached", true);
            put(&mut g, "claude", false);
            drop(g);
            std::fs::read_to_string(&html_path).map_err(|e| e.to_string())?
        } else {
            set_job(
                settings,
                job,
                22,
                &msg("job_writing", Some(loc), &[]),
                "running",
            );
            set_job(
                settings,
                job,
                40,
                &msg("job_slots", Some(loc), &[]),
                "running",
            );
            let mut claude_err = String::new();
            let mut enrich = match export_enrich(settings, &facts_payload(&data), &pid, loc) {
                Ok(v) => v,
                Err(e) => {
                    claude_err = take_chars(&e, 400);
                    Obj::new()
                }
            };
            if !enrich_usable(&enrich) {
                if claude_err.is_empty() {
                    claude_err = msg("job_bad_json", Some(loc), &[]);
                }
                enrich = enrich_from_facts(&data);
                let mut g = lock(job);
                put(&mut g, "claude", false);
                put(&mut g, "claude_error", claude_err);
            } else {
                let mut g = lock(job);
                put(&mut g, "claude", true);
                g.insert("claude_error".into(), Value::Null);
            }
            {
                let mut g = lock(job);
                put(&mut g, "pi_role", EXPORT_ROLE);
            }
            set_job(
                settings,
                job,
                62,
                &msg("job_shell", Some(loc), &[]),
                "running",
            );
            let html_doc = assemble_deliverable(&data, Some(&enrich), Some(loc))?;
            set_job(
                settings,
                job,
                82,
                &msg("job_write", Some(loc), &[]),
                "running",
            );
            std::fs::write(&html_path, &html_doc).map_err(|e| e.to_string())?;
            let mut g = lock(job);
            put(&mut g, "cached", false);
            drop(g);
            html_doc
        };
        {
            let mut g = lock(job);
            put(&mut g, "html_path", html_path.display().to_string());
        }
        if fmt == "pdf" {
            set_job(
                settings,
                job,
                90,
                &msg("job_pdf", Some(loc), &[]),
                "running",
            );
            let pdf_path = out_dir.join(format!("{stem}.pdf"));
            let bytes =
                html_to_pdf(&std::fs::read_to_string(&html_path).map_err(|e| e.to_string())?)?;
            std::fs::write(&pdf_path, bytes).map_err(|e| e.to_string())?;
            let mut g = lock(job);
            put(&mut g, "pdf_path", pdf_path.display().to_string());
            put(&mut g, "filename", format!("{fname_base}.pdf"));
        } else {
            let mut g = lock(job);
            put(&mut g, "filename", format!("{fname_base}.html"));
        }
        let claude = gbool(&lock(job), "claude");
        let cached = gbool(&lock(job), "cached");
        let done = if claude {
            msg("job_done_pi", Some(loc), &[])
        } else if cached {
            msg("job_done_cache", Some(loc), &[])
        } else {
            msg("job_done", Some(loc), &[])
        };
        set_job(settings, job, 100, &done, "done");
        notify_export(settings, &pid, "done", &done);
        let _ = html_doc;
        Ok(())
    })();
    if let Err(e) = outcome {
        let percent = gint(&lock(job), "percent");
        let err_s = e.clone();
        {
            let mut g = lock(job);
            put(&mut g, "error", err_s);
        }
        set_job(
            settings,
            job,
            percent,
            &msg("job_fail", Some(loc), &[("err", &e)]),
            "error",
        );
        notify_export(settings, &pid, "error", &take_chars(&e, 200));
    }
}

fn spawn_export(settings: &Settings, job: std::sync::Arc<Mutex<Obj>>) {
    let jid = gstr(&lock(&job), "id");
    if jid.is_empty() || lock(&LIVE_JOBS).contains(&jid) {
        return;
    }
    lock(&LIVE_JOBS).insert(jid.clone());
    let settings = settings.clone();
    let _ = std::thread::Builder::new()
        .name("atk-export".into())
        .spawn(move || {
            run_export_job(&settings, &job);
            lock(&LIVE_JOBS).remove(&jid);
        });
}

pub fn resume_interrupted_exports(settings: &Settings) -> i64 {
    let dir = job_dir(settings);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return 0;
    };
    let mut n = 0i64;
    for ent in rd.flatten() {
        let name = ent.file_name().to_string_lossy().to_string();
        if !name.starts_with("rpt_") || !name.ends_with(".json") {
            continue;
        }
        let stem = name.trim_end_matches(".json");
        let Some(mut job) = load_job(settings, stem) else {
            continue;
        };
        if !should_resume(&job) {
            continue;
        }
        put(&mut job, "status", "running");
        job.insert("error".into(), Value::Null);
        put(&mut job, "message", "后端已恢复，继续生成交付报告");
        let id = gstr(&job, "id");
        persist_job(settings, &job);
        let arc = std::sync::Arc::new(Mutex::new(job));
        lock(&JOBS).insert(id, arc.clone());
        spawn_export(settings, arc);
        n += 1;
    }
    n
}

fn resolve_job(
    settings: &Settings,
    project_id: &str,
    job_id: &str,
) -> Option<std::sync::Arc<Mutex<Obj>>> {
    if let Some(job) = lock(&JOBS).get(job_id).cloned() {
        if gstr(&lock(&job), "project_id") != project_id {
            return None;
        }
        return Some(job);
    }
    let job = load_job(settings, job_id)?;
    if gstr(&job, "project_id") != project_id {
        return None;
    }
    let mut job = job;
    if should_resume(&job) {
        put(&mut job, "status", "running");
        job.insert("error".into(), Value::Null);
        put(&mut job, "message", "后端已恢复，继续生成交付报告");
        persist_job(settings, &job);
        let arc = std::sync::Arc::new(Mutex::new(job));
        lock(&JOBS).insert(job_id.to_string(), arc.clone());
        spawn_export(settings, arc.clone());
        return Some(arc);
    }
    let arc = std::sync::Arc::new(Mutex::new(job));
    lock(&JOBS).insert(job_id.to_string(), arc.clone());
    Some(arc)
}

pub fn get_export_job(settings: &Settings, project_id: &str, job_id: &str) -> Option<Obj> {
    resolve_job(settings, project_id, job_id).map(|job| job_public(&lock(&job)))
}

pub fn export_file_path(settings: &Settings, job_id: &str, project_id: &str) -> Option<PathBuf> {
    let job = resolve_job(settings, project_id, job_id)?;
    let g = lock(&job);
    let fmt = {
        let f = gstr(&g, "format");
        if f.is_empty() {
            "html".into()
        } else {
            f
        }
    };
    let p = if fmt == "pdf" {
        let a = gstr(&g, "pdf_path");
        if a.is_empty() {
            gstr(&g, "html_path")
        } else {
            a
        }
    } else {
        gstr(&g, "html_path")
    };
    if p.is_empty() {
        None
    } else {
        Some(PathBuf::from(p))
    }
}

pub fn start_export_job(
    settings: &Settings,
    project_id: &str,
    fmt: &str,
    force: bool,
    lang: Option<&str>,
) -> Result<Obj, ReportError> {
    let fmt = fmt.trim().to_ascii_lowercase();
    let fmt = if fmt.is_empty() { "html".into() } else { fmt };
    let loc = i18n::normalize_locale(lang.or(Some(i18n::get_locale())));
    if fmt == "md" {
        return Err(ReportError::Gone(ProjectReportMdGone {
            message: msg("md_gone", Some(loc), &[]),
        }));
    }
    if fmt != "html" && fmt != "pdf" {
        return Err(ReportError::Message(msg("format_html_pdf", Some(loc), &[])));
    }
    for existing in lock(&JOBS).values() {
        let g = lock(existing);
        if gstr(&g, "project_id") == project_id
            && gstr(&g, "format") == fmt
            && gstr(&g, "status") == "running"
        {
            return Ok(job_public(&g));
        }
    }
    let job_id = new_id("rpt_");
    let mut job = Obj::new();
    put(&mut job, "id", job_id.clone());
    put(&mut job, "project_id", project_id);
    put(&mut job, "format", fmt);
    put(&mut job, "lang", loc);
    put(&mut job, "status", "running");
    put(&mut job, "percent", 1);
    put(&mut job, "message", msg("job_queued", Some(loc), &[]));
    job.insert("error".into(), Value::Null);
    job.insert("filename".into(), Value::Null);
    put(&mut job, "cached", false);
    put(&mut job, "claude", false);
    job.insert("claude_error".into(), Value::Null);
    put(&mut job, "pi_role", EXPORT_ROLE);
    put(&mut job, "force", force);
    persist_job(settings, &job);
    let public = job_public(&job);
    let arc = std::sync::Arc::new(Mutex::new(job));
    lock(&JOBS).insert(job_id, arc.clone());
    spawn_export(settings, arc);
    Ok(public)
}

pub fn parse_claude_docs(text: &str) -> (String, String) {
    let d = parse_claude_enrich(text);
    let html = {
        let a = gstr(&d, "html_body");
        if !a.is_empty() {
            a
        } else {
            gstr(&d, "summary_overview")
        }
    };
    (html, gstr(&d, "markdown"))
}

pub fn wrap_html(data: &Obj, lang: Option<&str>) -> Result<String, String> {
    assemble_deliverable(data, None, lang)
}

pub fn wrap_markdown(_data: &Obj) -> Result<String, ProjectReportMdGone> {
    Err(ProjectReportMdGone {
        message: "项目总报告请改用 HTML 或 PDF 导出".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Obj {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn braces_inside_strings_stay_in_the_page() {
        let raw = concat!(
            "按事实写：\n",
            r#"{"summary": "入口 a {b} c", "impact": "已证明读到配置", "#,
            r#""rating": "高 critical，二次验证打到了文件", "#,
            r#""repro": "1. 打开入口\n2. 提交参数\n3. 看到文件\n4. 判定成功", "#,
            r#""fix": "收紧该接口鉴权"}"#
        );
        let spec = parse_page(raw);
        assert_eq!(gstr(&spec, "report_summary"), "入口 a {b} c");
        assert!(gstr(&spec, "report_fix").contains('收'));
        assert!(gstr(&spec, "report_fix").contains("收紧"));
    }

    #[test]
    fn failed_progress_is_not_still_writing() {
        let finding = obj(json!({
            "secondary_verified": 1,
            "title": "t",
            "severity": "high",
            "category": "rce"
        }));
        let out = prepare_finding_report(&finding, None, Some("failed"), None);
        assert_eq!(gstr(&out, "report_state"), "failed");
        assert!(!gstr(&out, "impact").contains("正在撰写"));
    }

    #[test]
    fn failed_secondary_keeps_the_page_and_the_reason() {
        let why =
            "换通道重放后没有再看到同样的响应差异，二次验证失败。失败只表示本条没被二次证明。";
        let row = obj(json!({
            "verification_status": "excluded",
            "secondary_verified": 0,
            "title": "缺安全头",
            "severity": "medium",
            "category": "vuln",
            "id": "f1",
            "redteam_rating_rationale": why,
            "report_summary": "入口返回的响应头里没有这些安全头。",
            "report_impact": "页面可以被其他站点嵌入，点击劫持尚未证明。",
            "report_rating": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            "report_repro": "1. 请求首页\n2. 看响应头\n3. 未见 CSP\n4. 二次没有复现嵌入",
            "report_fix": "补上 CSP 与 X-Frame-Options。"
        }));
        let out = prepare_finding_report(&row, None, None, None);
        assert_eq!(gstr(&out, "report_state"), "ready");
        assert_eq!(gstr(&out, "exclusion_reason"), why);
        let md =
            render_finding_markdown(Some(&Obj::new()), &row, None, "#", Some("zh"), None, None);
        assert!(md.contains("漏洞简介"));
        assert!(md.contains("二次验证失败原因"));
        assert!(md.contains(why));
        assert!(md.contains("入口返回的响应头"));
        assert!(!md.contains('排') || !md.contains("排除"));
        assert!(!md.contains("排除"));
    }

    #[test]
    fn verified_body_is_the_page_before_the_formal_sections() {
        let out = prepare_finding_report(
            &obj(json!({
                "verification_status": "verified",
                "secondary_verified": 1,
                "title": "参数回显",
                "description": "参数原样出现在响应里。",
                "evidence": "二次请求再次看到同一处回显。",
                "proof_detail": "复核时复现了这一处回显。",
                "redteam_rating": "6.1",
                "redteam_rating_rationale": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "poc_curl": "curl https://example.test/login"
            })),
            None,
            None,
            None,
        );
        assert_eq!(gstr(&out, "report_state"), "ready");
        assert!(gstr(&out, "report_summary").contains("参数原样出现"));
        assert!(gstr(&out, "report_impact").contains("再次看到"));
        assert!(gstr(&out, "report_rating").contains("CVSS:3.1"));
        assert!(gstr(&out, "report_repro").contains("复核时复现"));
        assert!(!gstr(&out, "impact").contains("正在撰写"));
    }

    #[test]
    fn schedule_holds_the_task_and_records_failure() {
        lock(&SCHEDULED).clear();
        lock(&FAILED).clear();
        let _ = std::mem::take(&mut *lock(&PAGE_TASKS));
        let dir = std::env::temp_dir().join(format!("atkbrain-report-{}", new_id("t")));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("t.db");
        let db = Db::open(&db_path).unwrap();
        db.execute(
            "INSERT INTO projects(id, name, kind, status, created_at, updated_at) VALUES (?1, 'n', 'single', 'idle', 1, 1)",
            &[&"p1"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO findings(id, project_id, title, severity, category, created_at, secondary_verified) VALUES ('f1', 'p1', 't', 'high', 'rce', 1, 1)",
            &[] as &[&dyn rusqlite::ToSql],
        )
        .unwrap();
        let mut env = std::collections::HashMap::new();
        env.insert("ATKBRAIN_DB_PATH".into(), db_path.display().to_string());
        env.insert("ATKBRAIN_DATA_DIR".into(), dir.display().to_string());
        env.insert(
            "ATKBRAIN_REPORTS_DIR".into(),
            dir.join("reports").display().to_string(),
        );
        env.insert("ATKBRAIN_REPORT_AI".into(), "0".into());
        let settings = Settings::from_map(&env, &dir);
        let before = PAGE_RUNS.load(std::sync::atomic::Ordering::SeqCst);
        schedule_page(&settings, "p1", "f1");
        let tasks = std::mem::take(&mut *lock(&PAGE_TASKS));
        assert!(!tasks.is_empty(), "撰写任务必须被保住");
        for task in tasks {
            task.join().unwrap();
        }
        assert!(PAGE_RUNS.load(std::sync::atomic::Ordering::SeqCst) > before);
        assert_eq!(page_activity("f1"), "failed");
        assert!(!lock(&SCHEDULED).contains("f1"));
        clear_page_failure("f1");
        assert_eq!(page_activity("f1"), "idle");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
