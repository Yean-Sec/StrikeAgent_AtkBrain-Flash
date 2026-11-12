//! 螺旋覆盖账本。扫描记录和允许圈，句子与原先 Python 相同。

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::graph::{objective_allows_flag, objective_is_src};

const LEDGER_NAME: &str = "SPIRAL.json";

fn rx(pattern: &str) -> Regex {
    Regex::new(pattern).expect("spiral regex")
}

fn nmap_top() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)--top-ports\s+(\d+)")) }
fn nmap_all() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)(?:^|\s)-p-(?:\s|$)|(?:-p\s*1-65535)")) }
fn nmap_bin() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bnmap\b")) }
fn ffuf() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bffuf\b")) }
fn gobuster_dns() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bgobuster\s+dns\b")) }
fn gobuster_vhost() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bgobuster\s+vhost\b")) }
fn whatweb() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bwhatweb\b")) }
fn nuclei() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bnuclei\b")) }
fn nikto() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\bnikto\b")) }
fn amass() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)\b(?:amass|fierce|dnsenum|dnsrecon)\b")) }
fn ffuf_ext() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?:^|\s)(?:-e|--extensions|-x)\b")) }
fn recursive() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?:^|\s)-r\b|--recursion")) }
fn open_port() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?im)^(\d+)/tcp\s+open")) }
fn url_re() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r#"(?i)https?://[^\s'"\\]+"#)) }
fn flag_target() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"(?i)(?:-d|-u|--url)\s+(\S+)")) }
fn open_target() -> &'static Regex { static R: OnceLock<Regex> = OnceLock::new(); R.get_or_init(|| rx(r"--open\s+(\S+)")) }

fn as_i(value: Option<&Value>, default: i64) -> i64 {
    match value {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|x| x as i64)).unwrap_or(default),
        Some(Value::String(s)) => s.parse::<i64>().unwrap_or(default),
        _ => default,
    }
}

fn s(value: Option<&Value>) -> String {
    value.and_then(|v| v.as_str()).unwrap_or("").to_string()
}

pub fn empty_ledger() -> Value {
    json!({
        "ring": 1,
        "allowed_ring": 1,
        "empty_plans": 0,
        "adjacent_open": false,
        "scans": [],
        "attacked": [],
    })
}

fn ledger_path(workspace: &str) -> std::path::PathBuf {
    Path::new(workspace).join(LEDGER_NAME)
}

pub fn load_ledger(workspace: &str) -> Value {
    let path = ledger_path(workspace);
    let Ok(text) = fs::read_to_string(&path) else { return empty_ledger() };
    let Ok(data) = serde_json::from_str::<Value>(&text) else { return empty_ledger() };
    let Some(obj) = data.as_object() else { return empty_ledger() };
    let mut out = empty_ledger();
    let dst = out.as_object_mut().unwrap();
    dst.insert("ring".into(), json!(as_i(obj.get("ring"), 1).clamp(1, 3)));
    dst.insert("allowed_ring".into(), json!(as_i(obj.get("allowed_ring"), 1).clamp(1, 3)));
    dst.insert("empty_plans".into(), json!(as_i(obj.get("empty_plans"), 0).max(0)));
    dst.insert("adjacent_open".into(), json!(obj.get("adjacent_open").and_then(|v| v.as_bool()).unwrap_or(false)));
    let scans = obj.get("scans").and_then(|v| v.as_array()).map(|items| items.iter().filter(|v| v.is_object()).cloned().collect::<Vec<_>>()).unwrap_or_default();
    let attacked = obj.get("attacked").and_then(|v| v.as_array()).map(|items| items.iter().filter(|v| v.is_object()).cloned().collect::<Vec<_>>()).unwrap_or_default();
    dst.insert("scans".into(), Value::Array(scans));
    dst.insert("attacked".into(), Value::Array(attacked));
    out
}

pub fn save_ledger(workspace: &str, ledger: &Value) {
    let path = ledger_path(workspace);
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    if let Ok(text) = serde_json::to_string_pretty(ledger) {
        let _ = fs::write(path, format!("{text}\n"));
    }
}

fn scan_sig(face: &str, tier: &str, target: &str) -> String {
    format!("{face}|{tier}|{}", target.trim().to_ascii_lowercase())
}

pub fn face_ring(tier: &str) -> i64 {
    match tier.trim().to_ascii_lowercase().as_str() {
        "top100" | "common" | "whatweb" | "san" => 1,
        "top1000" | "medium" | "dnsmap" | "nuclei" => 2,
        "all" | "large" | "nikto" | "dns_full" => 3,
        _ => 1,
    }
}

pub fn infer_ring(ledger: &Value) -> i64 {
    let mut ring = 1;
    if let Some(scans) = ledger.get("scans").and_then(|v| v.as_array()) {
        for scan in scans {
            ring = ring.max(face_ring(&s(scan.get("tier"))));
        }
    }
    if ledger.get("adjacent_open").and_then(|v| v.as_bool()).unwrap_or(false) {
        ring = ring.max(2);
    }
    ring.max(as_i(ledger.get("ring"), 1).clamp(1, 3))
}

pub fn ledger_allowed_ring(ledger: &Value) -> i64 {
    as_i(ledger.get("allowed_ring"), 1).clamp(1, 3)
}

pub fn note_empty_plan(workspace: &str, grew: bool, infra: bool, cap: i64) -> Value {
    let mut ledger = load_ledger(workspace);
    let cap = cap.max(1);
    let mut promoted = false;
    if let Some(obj) = ledger.as_object_mut() {
        if grew {
            obj.insert("empty_plans".into(), json!(0));
        } else if !infra {
            let n = as_i(obj.get("empty_plans"), 0).max(0) + 1;
            let allowed = ledger_allowed_ring(&Value::Object(obj.clone()));
            if n >= cap && allowed < 3 {
                obj.insert("allowed_ring".into(), json!(allowed + 1));
                obj.insert("empty_plans".into(), json!(0));
                promoted = true;
            } else {
                obj.insert("empty_plans".into(), json!(n));
            }
        }
    }
    save_ledger(workspace, &ledger);
    let mut out = load_ledger(workspace);
    if let Some(obj) = out.as_object_mut() {
        obj.insert("promoted".into(), json!(promoted));
    }
    out
}

pub fn redteam_stall_pause_due(no_progress: i64, limit: i64, allowed_ring: i64) -> bool {
    if allowed_ring < 3 { return false; }
    crate::advisor::stall_pause_due(no_progress, limit)
}

fn guess_target(cmd: &str) -> String {
    if let Some(m) = url_re().find(cmd) {
        return m.as_str().trim_end_matches('/').to_ascii_lowercase();
    }
    if let Some(c) = flag_target().captures(cmd) {
        return c.get(1).map(|m| m.as_str().trim_matches(|ch| ch == '\'' || ch == '"' || ch == '/').to_ascii_lowercase()).unwrap_or_default();
    }
    if let Some(c) = open_target().captures(cmd) {
        return c.get(1).map(|m| m.as_str().trim().to_ascii_lowercase()).unwrap_or_default();
    }
    if let Some(last) = cmd.split_whitespace().next_back() {
        let last = last.trim_matches(|ch| ch == '\'' || ch == '"');
        if !last.is_empty() && !last.starts_with('-') && !last.chars().take(4).any(|ch| ch == '/') {
            return last.to_ascii_lowercase();
        }
    }
    String::new()
}

pub fn parse_scan_command(command: &str) -> Option<Value> {
    let target = guess_target(command);
    let low = command.to_ascii_lowercase();
    if nmap_bin().is_match(command) {
        if nmap_all().is_match(command) {
            return Some(json!({"face": "ports", "tier": "all", "target": target, "ban": "nmap -p-"}));
        }
        if let Some(c) = nmap_top().captures(command) {
            let n: i64 = c.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
            if n <= 100 {
                return Some(json!({"face": "ports", "tier": "top100", "target": target, "ban": "nmap --top-ports 100"}));
            }
            return Some(json!({"face": "ports", "tier": "top1000", "target": target, "ban": "nmap --top-ports 1000"}));
        }
        return Some(json!({"face": "ports", "tier": "top1000", "target": target, "ban": "nmap"}));
    }
    if nikto().is_match(command) {
        return Some(json!({"face": "dirs", "tier": "large", "target": target, "ban": "nikto"}));
    }
    if ffuf().is_match(command) || low.contains("gobuster dir") || low.contains("feroxbuster") {
        let large = ffuf_ext().is_match(command) || recursive().is_match(command) || low.contains("backup");
        if large {
            return Some(json!({"face": "dirs", "tier": "large", "target": target, "ban": "ffuf 大圈递归/扩展名"}));
        }
        if command.contains("directory-list-2.3-small.txt") || command.contains("directory-list-2.3-small") {
            return Some(json!({"face": "dirs", "tier": "medium", "target": target, "ban": "ffuf 中档 directory-list-2.3-small"}));
        }
        if command.contains("dirb/common.txt") || command.contains("common.txt") {
            return Some(json!({"face": "dirs", "tier": "common", "target": target, "ban": "ffuf common.txt"}));
        }
        return Some(json!({"face": "dirs", "tier": "common", "target": target, "ban": "ffuf"}));
    }
    if gobuster_dns().is_match(command) {
        let tier = if command.contains("dnsmap.txt") { "dnsmap" } else { "dns" };
        return Some(json!({"face": "dns", "tier": tier, "target": target, "ban": "gobuster dns"}));
    }
    if amass().is_match(command) {
        return Some(json!({"face": "dns", "tier": "dns_full", "target": target, "ban": "amass/fierce"}));
    }
    if gobuster_vhost().is_match(command) || command.contains("Host: FUZZ") {
        return Some(json!({"face": "vhost", "tier": "dnsmap", "target": target, "ban": "gobuster vhost"}));
    }
    if whatweb().is_match(command) {
        return Some(json!({"face": "http", "tier": "whatweb", "target": target, "ban": "whatweb"}));
    }
    if nuclei().is_match(command) {
        return Some(json!({"face": "http", "tier": "nuclei", "target": target, "ban": "nuclei"}));
    }
    None
}

fn hits_from_stdout(face: &str, stdout: &str) -> Vec<String> {
    if face == "ports" {
        return open_port().captures_iter(stdout).filter_map(|c| c.get(1).map(|m| m.as_str().to_string())).take(32).collect();
    }
    if face == "dirs" {
        let mut found = Vec::new();
        for line in stdout.lines() {
            if line.contains("Status:") || line.contains("[200]") || line.contains("[301]") || line.contains("[302]") {
                found.push(line.trim().chars().take(160).collect());
            }
            if found.len() >= 24 { break; }
        }
        return found;
    }
    Vec::new()
}

pub fn record_command(workspace: &str, command: &str, stdout: &str) -> Option<Value> {
    let parsed = parse_scan_command(command)?;
    let mut ledger = load_ledger(workspace);
    let face = s(parsed.get("face"));
    let tier = s(parsed.get("tier"));
    let target = s(parsed.get("target"));
    let sig = scan_sig(&face, &tier, &target);
    let hits = hits_from_stdout(&face, stdout);
    let mut found = false;
    if let Some(scans) = ledger.get_mut("scans").and_then(|v| v.as_array_mut()) {
        for scan in scans.iter_mut() {
            let got = scan_sig(&s(scan.get("face")), &s(scan.get("tier")), &s(scan.get("target")));
            if got != sig { continue; }
            let mut old: Vec<String> = scan.get("hits").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
            for hit in &hits {
                if !old.contains(hit) { old.push(hit.clone()); }
            }
            old.truncate(48);
            if let Some(obj) = scan.as_object_mut() {
                obj.insert("hits".into(), json!(old));
                if let Some(ban) = parsed.get("ban").and_then(|v| v.as_str()) {
                    if !ban.is_empty() { obj.insert("ban".into(), json!(ban)); }
                }
            }
            found = true;
            break;
        }
        if !found {
            scans.push(json!({"face": face, "tier": tier, "target": target, "ban": parsed.get("ban").cloned().unwrap_or(json!("")), "hits": hits}));
        }
    }
    if face == "dirs" && tier == "medium" || face == "vhost" {
        if let Some(obj) = ledger.as_object_mut() { obj.insert("adjacent_open".into(), json!(true)); }
    }
    let ring = infer_ring(&ledger);
    if let Some(obj) = ledger.as_object_mut() { obj.insert("ring".into(), json!(ring)); }
    save_ledger(workspace, &ledger);
    Some(parsed)
}

pub fn note_coverage(workspace: &str, face: &str, tier: &str, target: &str, hits: &[String], attacked: &[Value]) -> Value {
    let fake = if face == "ports" && tier == "top100" {
        format!("nmap --top-ports 100 {target}")
    } else if face == "ports" && tier == "all" {
        format!("nmap -p- {target}")
    } else if face == "ports" {
        format!("nmap --top-ports 1000 {target}")
    } else if tier == "nikto" {
        format!("nikto -h {target}")
    } else if face == "dirs" && tier == "large" {
        format!("ffuf -e php,bak -w /usr/share/wordlists/dirb/common.txt {target}")
    } else if face == "dirs" && tier == "medium" {
        format!("ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt {target}")
    } else if face == "dirs" {
        format!("ffuf -w /usr/share/wordlists/dirb/common.txt {target}")
    } else {
        format!("{face} {tier} {target}")
    };
    let _ = record_command(workspace, &fake, "");
    let mut ledger = load_ledger(workspace);
    let parsed = parse_scan_command(&format!("{face} {tier} {target}")).unwrap_or_else(|| json!({"face": face, "tier": tier, "target": target.to_ascii_lowercase()}));
    let sig = scan_sig(&s(parsed.get("face")), &s(parsed.get("tier")), &s(parsed.get("target")));
    if let Some(scans) = ledger.get_mut("scans").and_then(|v| v.as_array_mut()) {
        for scan in scans.iter_mut() {
            if scan_sig(&s(scan.get("face")), &s(scan.get("tier")), &s(scan.get("target"))) != sig { continue; }
            let mut old: Vec<String> = scan.get("hits").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|v| v.as_str().map(|x| x.to_string())).collect()).unwrap_or_default();
            for hit in hits {
                if !hit.is_empty() && !old.contains(hit) { old.push(hit.clone()); }
            }
            old.truncate(48);
            if let Some(obj) = scan.as_object_mut() { obj.insert("hits".into(), json!(old)); }
            break;
        }
    }
    if let Some(list) = ledger.get_mut("attacked").and_then(|v| v.as_array_mut()) {
        for item in attacked {
            if item.is_object() && !list.contains(item) { list.push(item.clone()); }
        }
        list.truncate(80);
    }
    let ring = infer_ring(&ledger);
    if let Some(obj) = ledger.as_object_mut() { obj.insert("ring".into(), json!(ring)); }
    save_ledger(workspace, &ledger);
    ledger
}

pub fn has_scan(ledger: &Value, face: &str, tier: &str, target: &str) -> bool {
    let want = target.trim().to_ascii_lowercase();
    let Some(scans) = ledger.get("scans").and_then(|v| v.as_array()) else { return false };
    scans.iter().any(|scan| {
        s(scan.get("face")) == face && s(scan.get("tier")) == tier && (want.is_empty() || s(scan.get("target")) == want)
    })
}

pub fn scan_ban_repeats(ledger: &Value, objective: Option<&str>) -> Vec<String> {
    if objective.is_some() && !objective_allows_flag(objective) { return Vec::new(); }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if let Some(scans) = ledger.get("scans").and_then(|v| v.as_array()) {
        for scan in scans {
            let ban = s(scan.get("ban")).trim().to_string();
            if ban.is_empty() || !seen.insert(ban.clone()) { continue; }
            let tgt = s(scan.get("target")).trim().to_string();
            out.push(if tgt.is_empty() { ban } else { format!("{ban} {tgt}") });
        }
    }
    if let Some(attacked) = ledger.get("attacked").and_then(|v| v.as_array()) {
        for item in attacked {
            let path = if s(item.get("url")).trim().is_empty() { s(item.get("path")) } else { s(item.get("url")) };
            let path = path.trim().to_string();
            let tactic = s(item.get("tactic")).trim().to_string();
            if path.is_empty() { continue; }
            let line = format!("{path} {tactic}").trim().to_string();
            if seen.insert(line.clone()) { out.push(line); }
        }
    }
    out.truncate(12);
    out
}

fn hit_txt(scan: &Value) -> String {
    let hits: Vec<String> = scan.get("hits").and_then(|v| v.as_array()).map(|a| a.iter().take(6).map(|v| v.as_str().unwrap_or("").to_string()).collect()).unwrap_or_default();
    if hits.is_empty() { "无命中记录".into() } else { hits.join("、") }
}

fn scan_lines(ledger: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(scans) = ledger.get("scans").and_then(|v| v.as_array()) {
        for scan in scans.iter().take(16) {
            lines.push(format!("  · {}/{} {} — {}", s(scan.get("face")), s(scan.get("tier")), s(scan.get("target")), hit_txt(scan)));
        }
    }
    if let Some(attacked) = ledger.get("attacked").and_then(|v| v.as_array()) {
        if !attacked.is_empty() {
            let bits: Vec<String> = attacked.iter().take(8).map(|a| {
                let url = s(a.get("url"));
                if !url.trim().is_empty() { url } else {
                    let path = s(a.get("path"));
                    if !path.trim().is_empty() { path } else { s(a.get("tactic")) }
                }
            }).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
            lines.push(format!("已测路径：{}", bits.join("、")));
        }
    }
    lines
}

pub fn format_coverage_brief(ledger: &Value, objective: Option<&str>, empty_cap: i64) -> String {
    let present = objective.map(|item| !item.trim().is_empty()).unwrap_or(false);
    let ctf = present && objective_allows_flag(objective);
    let src = present && objective_is_src(objective);
    let scans_empty = ledger.get("scans").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true);
    let attacked_empty = ledger.get("attacked").and_then(|v| v.as_array()).map(|a| a.is_empty()).unwrap_or(true);
    if src {
        if scans_empty && attacked_empty {
            return "已覆盖（账本空）：SRC 先铺开入口，再按入口形态从厂商菜单选类型；nmap top-1000 + 中档目录。不要升圈、不要横向、不要预开 11 路。".into();
        }
        let mut lines = vec!["已覆盖（SRC 不升圈）· 按入口形态选类型挖高危".to_string()];
        lines.extend(scan_lines(ledger));
        lines.push("低/中/高危/严重都要 report_finding 进漏洞页。禁止夺旗、禁止本机直连与 socks/shell 横向。已验证 SSRF 必须 report_pivot_capability。".into());
        return lines.join("\n");
    }
    if ctf {
        if scans_empty && attacked_empty {
            return "已覆盖（账本空）：CTF 先看本题入口活体；枚举开局 top-1000 + 中档；邻题关。相同扫描不要再跑。".into();
        }
        let mut lines = vec!["已覆盖（CTF 不升圈）· 邻题关".to_string()];
        lines.extend(scan_lines(ledger));
        lines.push("评测邻题始终越界。先看入口源码；没有旗再扫描。相同扫描签名不要再跑。".into());
        return lines.join("\n");
    }
    let ring = ledger_allowed_ring(ledger);
    let label = match ring { 2 => "中", 3 => "大", _ => "小" };
    let empty_n = as_i(ledger.get("empty_plans"), 0).max(0);
    let cap = empty_cap.max(1);
    let adj = if ring >= 2 { "旁站开" } else { "旁站关" };
    let head = format!("允许圈={ring}/{label} · 空转 {empty_n}/{cap} · {adj}");
    if scans_empty && attacked_empty {
        let extra = if ring <= 1 { "第 1 圈只打当前入口；top-100 + common.txt。" } else { "" };
        let gate = if ring <= 1 { "禁止抢跑更高档。" } else { "" };
        return format!("已覆盖（螺旋账本空）：{head}。{extra}按本圈完整清单做，不要因小圈做过而省略。{gate}");
    }
    let mut lines = vec![format!("已覆盖：{head}")];
    lines.extend(scan_lines(ledger));
    lines.push("按本圈完整清单做，不要因小圈做过而省略。".into());
    if ledger_allowed_ring(ledger) <= 1 {
        lines.push("第 1 圈禁止抢跑 top-1000、-p-、中档目录、旁站。".into());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_tiers() {
        let top = parse_scan_command("nmap --top-ports 100 10.0.0.8").unwrap();
        assert_eq!(top["tier"], "top100");
        let all = parse_scan_command("nmap -p- 10.0.0.8").unwrap();
        assert_eq!(all["tier"], "all");
        assert!(redteam_stall_pause_due(9, 5, 2) == false);
        assert!(redteam_stall_pause_due(9, 5, 3));
    }
}
