//! SRC 入口形态建议，以及入口栈是否和题面一致。句子与原先 Python 相同。

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;

const TYPES: &[(&str, &str, &str)] = &[
    ("xss", "XSS", "html_sink"),
    ("sqli", "SQLi", "web_inject"),
    ("cmd", "命令执行", "web_inject"),
    ("code", "代码执行", "restricted_deserialize"),
    ("lfi", "文件包含", "file_read_chain"),
    ("file", "任意文件", "file_read_chain"),
    ("authz", "越权", "access_control"),
    ("logic", "逻辑", "business_logic"),
    ("leak", "高危信息泄露", "info_to_danger"),
    ("backdoor", "后门", "auth_surface"),
    ("nday", "N-day", "nday"),
];

fn rx(pattern: &str) -> Regex { Regex::new(pattern).expect("surface regex") }
fn re(slot: &'static OnceLock<Regex>, pattern: &'static str) -> &'static Regex { slot.get_or_init(|| rx(pattern)) }
fn oss_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)aliyunoss|oss-cn-|accessdenied|nosuchbucket|私有桶|object.?store|x-oss-") }
fn app_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)\bjson\b|/api|payment|openid|kong|integral|/user|/gift|/order|application/json|game-char|x-token|支付|积分") }
fn param_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)json_api|/api|query|param|search|openid|zoneid|game_id|charid|application/json|表单|查询参数|接口") }
fn authz_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)/user|/gift|/order|openid|charid|\bidor\b|越权|未授权|x-token|game-char|role.?id|uid=|object.?id") }
fn logic_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)pay|amount|price|coupon|count|integral|score|product|改价|订单|优惠|gift|营销|支付|金额|商品") }
fn html_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)text/html|<form|innerhtml|document\.write|html_sink|</html>|vue|react") }
fn cmd_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)\bping\b|\bexec\b|\bcmd\b|nslookup|traceroute|diag(?:nostic)?|shell.?cmd|system\(|popen") }
fn code_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)ssti|template_error|freemarker|velocity|thymeleaf|deserialize|unserialize|pickle|ysoserial|spel\b|ognl|groovy|expr_eval") }
fn lfi_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)\binclude\b|\blfi\b|page=|file=|path=|template=|lang=|view=|php://") }
fn file_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)download|readfile|export|backup|upload|multipart|attachment|path.?traversal|任意文件|\.git\b|zip.?slip") }
fn leak_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)swagger|\.git\b|backup|heapdump|\.env\b|accesskey|act-center-config|user-info|scorelog|site-config|awards?-info") }
fn backdoor_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)/admin|/debug|/console|phpmyadmin|manager/html|/status|webshell|预留口令|隐藏.?管理|kong.?admin") }
fn nday_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)kong\s*0\.\d+|nginx/\d+|apache/\d+|tomcat/?\d+|spring[ -]?boot|shiro|struts|weblogic|openssl/\d+|php/\d+\.\d+|thinkphp|\bversion\b.{0,12}\d+\.\d+") }
fn http_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?i)\bhttps?\b|nginx|kong|/tcp http") }
fn title_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"(?is)<title[^>]*>(.*?)</title>") }
fn space_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); re(&R, r"\s+") }

pub struct TypePick { pub key: String, pub label: String, pub why: String }

fn label_of(key: &str) -> &'static str { TYPES.iter().find(|row| row.0 == key).map(|row| row.1).unwrap_or("") }

fn remember(hits: &mut Vec<(String, String)>, key: &str, why: &str) {
    if hits.iter().any(|row| row.0 == key) { return; }
    hits.push((key.to_string(), why.to_string()));
}

pub fn suggest_src_types(hay: &str) -> (Vec<TypePick>, Vec<TypePick>) {
    let hay = hay.to_ascii_lowercase();
    if hay.trim().is_empty() || !http_re().is_match(&hay) {
        let skipped = TYPES.iter().map(|row| TypePick { key: row.0.into(), label: row.1.into(), why: "入口未建账或非 HTTP：先铺开，不要预开 11 路".into() }).collect();
        return (Vec::new(), skipped);
    }
    let oss = oss_re().is_match(&hay);
    let app = app_re().is_match(&hay);
    let mut hits: Vec<(String, String)> = Vec::new();
    if html_re().is_match(&hay) { remember(&mut hits, "xss", "有 HTML/前端汇，测反射/DOM"); }
    if param_re().is_match(&hay) || app { remember(&mut hits, "sqli", "有 JSON/查询参数，测注入"); }
    if cmd_re().is_match(&hay) { remember(&mut hits, "cmd", "有 ping/exec 类参数"); }
    if code_re().is_match(&hay) { remember(&mut hits, "code", "有模板/反序列化/表达式面"); }
    if lfi_re().is_match(&hay) { remember(&mut hits, "lfi", "有 include/path/file 类参数"); }
    if file_re().is_match(&hay) { remember(&mut hits, "file", "有下载/上传/备份/任意文件面"); }
    if authz_re().is_match(&hay) || (app && param_re().is_match(&hay)) { remember(&mut hits, "authz", "有身份/对象 ID 或未授权 200 接口"); }
    else if oss && !app { remember(&mut hits, "authz", "对象存储面先测桶/对象 ACL 与未授权读"); }
    if logic_re().is_match(&hay) { remember(&mut hits, "logic", "有支付/金额/积分/商品参数，测改价与逻辑"); }
    if leak_re().is_match(&hay) || (oss && !app) {
        let why = if oss && !app { "OSS 子资源/ACL/策略是否外泄" } else { "有配置/备份/敏感接口或密钥线索" };
        remember(&mut hits, "leak", why);
    }
    if backdoor_re().is_match(&hay) { remember(&mut hits, "backdoor", "有管理/调试/隐藏入口迹象"); }
    if nday_re().is_match(&hay) { remember(&mut hits, "nday", "已识别产品或版本，WebSearch 查已知 CVE/N-day"); }
    if hits.is_empty() && !oss {
        remember(&mut hits, "sqli", "HTTP 活体尚无分型，先打参数注入");
        remember(&mut hits, "authz", "HTTP 活体尚无分型，先测未授权");
    }
    let suggested = TYPES.iter().filter_map(|row| hits.iter().find(|hit| hit.0 == row.0).map(|hit| TypePick { key: row.0.into(), label: row.1.into(), why: hit.1.clone() })).collect();
    let skipped = TYPES.iter().filter(|row| !hits.iter().any(|hit| hit.0 == row.0)).map(|row| TypePick { key: row.0.into(), label: row.1.into(), why: "当前图上没有这类入口形态，暂缓".into() }).collect();
    let _ = label_of;
    (suggested, skipped)
}

pub fn format_src_surface_brief(hay: &str) -> String {
    let (suggested, skipped) = suggest_src_types(hay);
    let mut lines = vec!["本轮按入口形态选类型（厂商 11 类是菜单，不是每轮全开）：".to_string()];
    if suggested.is_empty() {
        lines.push("建议测：先铺开入口，再按面选；不要预开 11 路。".into());
    } else {
        let bits: Vec<String> = suggested.iter().map(|p| format!("{}（{}）", p.label, p.why)).collect();
        lines.push(format!("建议测：{}", bits.join("；")));
    }
    if !skipped.is_empty() {
        let bits: Vec<&str> = skipped.iter().map(|p| p.label.as_str()).collect();
        lines.push(format!("暂缓：{}（没有对应面就不要硬派工人）。", bits.join("、")));
    }
    lines.push("有版本指纹才 WebSearch 查 N-day；纯私有 OSS 不要假装有 SQLi/XSS。".into());
    lines.join("\n")
}

const FAMILIES: &[(&str, &[&str])] = &[
    ("php", &[r"(?i)\bphp(?:/[\d.]+)?\b", r"(?i)x-powered-by:\s*php", r"(?i)\bthinkphp\b", r"(?i)\blaravel\b", r"(?i)\bwordpress\b", r"(?i)\.php(?:\b|\?|$|/)"]),
    ("python-web", &[r"(?i)\bwerkzeug\b", r"(?i)\bflask\b", r"(?i)\bdjango\b", r"(?i)\bgunicorn\b", r"(?i)\buvicorn\b", r"(?i)\bwsgiserver\b", r"(?i)\bjinja2?\b"]),
    ("java", &[r"(?i)\btomcat\b", r"(?i)\bweblogic\b", r"(?i)\bspring\b", r"(?i)\bjsessionid\b", r"(?i)\.jsp(?:\b|\?|$|/)"]),
    ("aspnet", &[r"(?i)\basp\.net\b", r"(?i)\baspx\b", r"(?i)\biis/"]),
    ("node", &[r"(?i)\bexpress\b", r"(?i)\bnext\.js\b", r"(?i)x-powered-by:\s*express"]),
];

pub fn graph_stack_text(rows: &[(String, String, String, String)], limit: usize) -> String {
    let limit = if limit == 0 { 24000 } else { limit };
    let mut parts = Vec::new();
    let mut used = 0usize;
    for (key, title, kind, tags) in rows {
        let line = format!("{key} {title} {kind} {tags}");
        used += line.len();
        parts.push(line);
        if used >= limit { break; }
    }
    parts.join(" ").chars().take(limit).collect()
}

pub fn classify_entry_identity(brief: &str, graph_text: &str, live_text: &str) -> (Vec<String>, Vec<String>, bool) {
    let expected = infer_families(&format!("{brief} {graph_text}"));
    let live = infer_families(live_text);
    let mismatch = !expected.is_empty() && !live.is_empty() && live.is_disjoint(&expected);
    (expected.into_iter().collect(), live.into_iter().collect(), mismatch)
}
pub fn default_fanout_roles() -> Vec<String> {
    vec!["web-exploit".into(), "recon".into()]
}

pub fn ensure_live_page_reader(roles: &[String], objective: &str, http: bool, keep_rce: bool) -> Vec<String> {
    let mut cleaned: Vec<String> = roles.iter().map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect();
    let flag = crate::graph::objective_allows_flag(Some(objective));
    let src = crate::graph::objective_is_src(Some(objective));
    if !http || flag || !src { return cleaned; }
    if keep_rce && !cleaned.iter().any(|r| r == "rce-hunt" || r == "privesc") {
        cleaned.insert(0, "rce-hunt".into());
    }
    let preferred = ["web-exploit", "rce-hunt", "recon", "src-hunt"];
    let head: Vec<String> = preferred.iter().copied().filter(|role| cleaned.iter().any(|item| item == role) || role == &"web-exploit" || role == &"recon").map(|role| role.to_string()).collect();
    let rest: Vec<String> = cleaned.into_iter().filter(|r| !head.iter().any(|h| h == r)).collect();
    let mut out = Vec::new();
    for role in head.into_iter().chain(rest) {
        if !out.contains(&role) { out.push(role); }
    }
    out
}

pub fn graph_needs_rce_hunter(kinds: &[String]) -> bool {
    let mut interesting = false;
    for kind in kinds {
        if kind == "foothold" || kind == "goal" { return false; }
        if kind == "vuln" || kind == "credential" { interesting = true; }
    }
    interesting
}

pub fn infer_families(text: &str) -> BTreeSet<String> {
    let mut hit = BTreeSet::new();
    for (name, pats) in FAMILIES {
        if pats.iter().any(|pat| Regex::new(pat).ok().map(|re| re.is_match(text)).unwrap_or(false)) {
            hit.insert((*name).to_string());
        }
    }
    hit
}

pub fn parse_http_identity(raw: &str, headers: &[(String, String)], status: Option<i64>) -> (Option<i64>, String, String, String, Vec<(String, String)>) {
    let title = title_re().captures(raw).map(|c| space_re().replace_all(c.get(1).map(|m| m.as_str()).unwrap_or(""), " ").trim().chars().take(200).collect()).unwrap_or_default();
    let headers: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect();
    let server = headers.iter().find(|(k, _)| k == "server").map(|(_, v)| v.clone()).or_else(|| headers.iter().find(|(k, _)| k == "x-powered-by").map(|(_, v)| v.clone())).unwrap_or_default();
    let body: String = raw.chars().take(4000).collect();
    (status, server.chars().take(80).collect(), title, body, headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_graph_does_not_open_eleven() {
        let text = format_src_surface_brief("");
        assert!(text.contains("不要预开 11 路"));
    }
    #[test]
    fn flask_and_php_mismatch() {
        let expected = infer_families("index.php laravel");
        let live = infer_families("werkzeug flask");
        assert!(expected.contains("php"));
        assert!(live.contains("python-web"));
        assert!(expected.is_disjoint(&live));
    }
}
