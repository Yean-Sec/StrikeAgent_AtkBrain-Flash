//! 项目的创建、列出和删除。回环地址和 gov/edu 等后缀不能当目标。

use std::collections::{BTreeSet, HashSet};
use std::net::ToSocketAddrs;

use crate::assets::seed_declared;
use crate::config::Settings;
use crate::db::{now, Db};
use crate::graph::objective_allows_flag;
use rusqlite::ToSql;
use serde_json::{json, Map, Value};

fn loads(raw: Option<&Value>) -> Value {
    match raw {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(s)) if s.is_empty() => Value::Null,
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::String(s.clone())),
        Some(other) => other.clone(),
    }
}

fn dumps(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".into()),
    }
}

pub fn clean_target(raw: &str) -> (String, Option<String>) {
    let mut t = raw.trim().to_string();
    if let Some(idx) = t.find("://") {
        t = t[idx + 3..].to_string();
    }
    t = t.split('/').next().unwrap_or("").to_string();
    if t.matches(':').count() == 1 {
        if let Some((host, port)) = t.split_once(':') {
            if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
                return (host.trim().to_ascii_lowercase(), Some(port.to_string()));
            }
        }
    }
    (t.trim().to_ascii_lowercase(), None)
}

pub fn forbidden_project_target_reason(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return Some("目标不能为空".into());
    }
    if h == "localhost" || h == "0.0.0.0" || h == "host.docker.internal" || h == "::1" || h.starts_with("127.") {
        return Some(format!("禁止以回环/本机别名作为项目目标：{h}"));
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return Some(format!("禁止以回环/本机别名作为项目目标：{h}"));
        }
        return None;
    }
    let labels: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    let protected = matches!(tld, "gov" | "edu" | "mil" | "int")
        || (tld.len() == 2 && matches!(sld, "gov" | "edu" | "ac" | "mil" | "go"));
    if protected {
        return Some(format!(
            "禁止攻击政府、教育、军队或学术网域名：{h}。这类后缀不能作为项目目标，也不能连接。"
        ));
    }
    None
}

pub fn assert_safe_project_target(target: &str) -> Result<String, String> {
    let (host, _) = clean_target(target);
    if let Some(reason) = forbidden_project_target_reason(&host) {
        return Err(reason);
    }
    Ok(host)
}

fn is_dotted_v4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().ok().filter(|n| *n <= 255).is_some()
        })
}

fn is_loopback_ip(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    h == "localhost" || h == "::1" || h.starts_with("127.") || h.parse::<std::net::IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

fn is_private_ip(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::IpAddr>() else { return false };
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || ((v6.segments()[0] & 0xffc0) == 0xfe80) || ((v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

pub fn resolve_host(host: &str) -> Vec<String> {
    if is_dotted_v4(host) {
        return vec![host.to_string()];
    }
    let Ok(iter) = (host, 0u16).to_socket_addrs() else { return Vec::new() };
    let mut out = BTreeSet::new();
    for addr in iter {
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            let text = v4.to_string();
            if is_dotted_v4(&text) {
                out.insert(text);
            }
        }
    }
    out.into_iter().collect()
}

pub fn filter_scope_ips(host: &str, ips: &[String], objective: Option<&str>) -> (Vec<String>, Option<String>) {
    if is_dotted_v4(host) {
        return (ips.to_vec(), None);
    }
    let external = !objective_allows_flag(objective);
    let mut kept = Vec::new();
    for ip in ips {
        if is_loopback_ip(ip) {
            continue;
        }
        if external && is_private_ip(ip) {
            continue;
        }
        if !kept.iter().any(|x: &String| x == ip) {
            kept.push(ip.clone());
        }
    }
    let warning = if !ips.is_empty() && kept.is_empty() {
        Some(format!("授权域名 {host} 仅解析到回环/内网（{ips:?}），已不写入 scope.ips。"))
    } else {
        None
    };
    (kept, warning)
}

fn track_of(kind: &str, cfg: &Value) -> Value {
    let mut cfg = cfg.as_object().cloned().unwrap_or_default();
    let explicit = cfg
        .get("track")
        .or_else(|| cfg.get("objective"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let flag = kind == "benchmark" && explicit.is_empty() || explicit == "flag" || explicit == "ctf";
    if flag {
        cfg.insert("track".into(), json!("ctf"));
        cfg.insert("objective".into(), json!("flag"));
    } else {
        cfg.insert("track".into(), json!("agent"));
        cfg.insert("objective".into(), json!("agent"));
    }
    Value::Object(cfg)
}

fn hard_stop(settings: &Settings, objective: &str) -> Value {
    let flag = objective == "flag" || objective == "ctf";
    let runtime = if flag { settings.runtime_hard_stop_sec } else { settings.agent_runtime_hard_stop_sec };
    let minutes = runtime / 60;
    if flag {
        json!({
            "track": "flag",
            "runtime_sec": runtime,
            "max_turns": settings.loop_max_turns,
            "label": format!("硬停：本遍墙钟 {minutes} 分钟；连续 {} 个御主方案无增长记失败。不限轮次。", settings.graph_idle_empty_plans),
            "conditions": [
                format!("本遍墙钟满 {minutes} 分钟 → 记失败"),
                format!("连续 {} 个御主方案无图增长 → 记失败", settings.graph_idle_empty_plans),
                "手动停止"
            ]
        })
    } else {
        json!({
            "track": "agent",
            "runtime_sec": runtime,
            "max_turns": settings.loop_max_turns_agent,
            "label": format!("硬停：墙钟满 {minutes} 分钟，或连续 30 轮没有新节点也没有新漏洞。其余只接受手动停止。"),
            "conditions": [
                format!("墙钟满 {minutes} 分钟 → 记失败"),
                "连续 30 轮没有新节点也没有新漏洞 → 记失败",
                "手动停止"
            ]
        })
    }
}

fn cell_str<'a>(row: &'a Map<String, Value>, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

pub fn serialize_project(row: &Map<String, Value>, settings: &Settings) -> Value {
    let kind = cell_str(row, "kind").to_string();
    let cfg = track_of(&kind, &loads(row.get("config")));
    let objective = cfg.get("objective").and_then(Value::as_str).unwrap_or("agent").to_string();
    let mut scope = loads(row.get("scope"));
    if scope.is_null() {
        scope = json!({});
    }
    json!({
        "id": row.get("id").cloned().unwrap_or(Value::Null),
        "name": row.get("name").cloned().unwrap_or(Value::Null),
        "kind": kind,
        "target": row.get("target").cloned().unwrap_or(Value::Null),
        "ports": loads(row.get("ports")),
        "scope": scope,
        "config": cfg,
        "status": row.get("status").cloned().unwrap_or(json!("idle")),
        "parent_id": row.get("parent_id").cloned().unwrap_or(Value::Null),
        "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
        "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null),
        "hard_stop": hard_stop(settings, &objective),
        "category": row.get("category").cloned().unwrap_or(Value::Null),
        "archived": row.get("archived").and_then(Value::as_i64).unwrap_or(0),
        "queued_at": row.get("queued_at").cloned().unwrap_or(Value::Null),
        "vendor_id": row.get("vendor_id").cloned().unwrap_or(Value::Null),
    })
}

pub fn get_project(db: &Db, settings: &Settings, pid: &str) -> Result<Option<Value>, String> {
    let Some(row) = db.query_one("SELECT * FROM projects WHERE id=?1", &[&pid as &dyn ToSql])? else {
        return Ok(None);
    };
    Ok(Some(serialize_project(&row, settings)))
}

pub fn list_projects(db: &Db, settings: &Settings) -> Result<Vec<Value>, String> {
    let rows = db.query("SELECT * FROM projects WHERE parent_id IS NULL ORDER BY created_at DESC", &[])?;
    Ok(rows.iter().map(|row| serialize_project(row, settings)).collect())
}

pub fn create_single_project(db: &Db, settings: &Settings, name: &str, target: &str, ports: Option<&[i64]>, allow_subdomains: bool, objective: &str) -> Result<Value, String> {
    let flag = objective == "flag" || objective == "ctf";
    let cfg = if flag { json!({"track":"ctf","objective":"flag"}) } else { json!({"track":"agent","objective":"agent"}) };
    create_single_project_full(db, settings, name, target, ports, allow_subdomains, "strict", cfg, None, &[], &[])
}

pub fn create_single_project_full(
    db: &Db,
    settings: &Settings,
    name: &str,
    target: &str,
    ports: Option<&[i64]>,
    allow_subdomains: bool,
    mode: &str,
    mut cfg: Value,
    parent_id: Option<&str>,
    extra_targets: &[String],
    extra_ips: &[String],
) -> Result<Value, String> {
    let (mut host, inline_port) = clean_target(target);
    host = assert_safe_project_target(&host)?;
    let mut ports_owned: Option<Vec<i64>> = ports.map(|p| p.to_vec());
    if let Some(port) = inline_port {
        if ports_owned.as_ref().map(|p| p.is_empty()).unwrap_or(true) {
            if let Ok(n) = port.parse::<i64>() {
                ports_owned = Some(vec![n]);
            }
        }
    }
    let mut extra = Vec::new();
    let mut seen = BTreeSet::from([host.clone()]);
    for raw in extra_targets {
        let (h, _) = clean_target(raw);
        if h.is_empty() || !seen.insert(h.clone()) {
            continue;
        }
        assert_safe_project_target(&h)?;
        extra.push(h);
    }
    let all_targets = std::iter::once(host.clone()).chain(extra.iter().cloned()).collect::<Vec<_>>();
    let mut ips_raw = BTreeSet::new();
    for h in &all_targets {
        ips_raw.extend(resolve_host(h));
    }
    for ip in extra_ips {
        let ip = ip.trim();
        if !ip.is_empty() {
            ips_raw.insert(ip.to_string());
        }
    }
    let objective = cfg.get("objective").and_then(Value::as_str);
    let (mut ips, warning) = filter_scope_ips(&host, &ips_raw.iter().cloned().collect::<Vec<_>>(), objective);
    if let Some(warning) = warning {
        if let Some(obj) = cfg.as_object_mut() {
            obj.insert("dns_warning".into(), Value::from(warning));
        }
    }
    for ip in extra_ips {
        let ip = ip.trim();
        if !ip.is_empty() && !ips.iter().any(|x| x == ip) {
            ips.push(ip.to_string());
        }
    }
    let loops: Vec<String> = ips.iter().filter(|ip| is_loopback_ip(ip)).cloned().collect();
    if !loops.is_empty() && !is_dotted_v4(&host) {
        return Err(format!("目标 {host} 解析到回环地址（{loops:?}），禁止创建项目"));
    }
    if let Some(obj) = cfg.as_object_mut() {
        obj.insert("vhosts".into(), json!(all_targets));
    }
    let scope = json!({
        "targets": all_targets,
        "ips": ips,
        "ports": Value::Null,
        "allow_subdomains": allow_subdomains,
        "mode": if mode.is_empty() { "strict" } else { mode },
    });
    let pid = crate::db::new_id("p_");
    let ts = now();
    let title = if name.trim().is_empty() { host.clone() } else { name.trim().to_string() };
    let ports_json = dumps(&ports_owned.map(|p| json!(p)).unwrap_or(Value::Null));
    let scope_json = dumps(&scope);
    let cfg_json = dumps(&cfg);
    let parent = parent_id.map(|s| s.to_string());
    db.execute(
        "INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at) VALUES (?1,?2,'single',?3,?4,?5,?6,'idle',?7,?8,?8)",
        &[&pid as &dyn ToSql, &title, &host, &ports_json, &scope_json, &cfg_json, &parent, &ts],
    )?;
    let vendor = cfg.get("vendor").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(host.as_str());
    seed_declared(db, &pid, &all_targets, &ips, Some(vendor))?;
    get_project(db, settings, &pid)?.ok_or_else(|| "项目没有写入".into())
}

pub fn rename_project(db: &Db, settings: &Settings, pid: &str, name: &str) -> Result<Value, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("名称不能为空".into());
    }
    if name.chars().count() > 80 {
        return Err("名称过长（最多 80 字）".into());
    }
    let Some(row) = db.query_one("SELECT * FROM projects WHERE id=?1", &[&pid as &dyn ToSql])? else {
        return Err("项目不存在".into());
    };
    let old = cell_str(&row, "name").to_string();
    let ts = now();
    db.execute("UPDATE projects SET name=?1, updated_at=?2 WHERE id=?3", &[&name as &dyn ToSql, &ts, &pid])?;
    let kind = cell_str(&row, "kind");
    let mut renamed_children = 0i64;
    if (kind == "cluster" || kind == "benchmark") && !old.is_empty() && old != name {
        let children = db.query("SELECT id, name FROM projects WHERE parent_id=?1", &[&pid as &dyn ToSql])?;
        let prefix = format!("{old} · ");
        for child in children {
            let id = cell_str(&child, "id").to_string();
            let cname = cell_str(&child, "name");
            let new_c = if let Some(rest) = cname.strip_prefix(&prefix) {
                format!("{name} · {rest}")
            } else if cname == old {
                name.to_string()
            } else {
                continue;
            };
            db.execute("UPDATE projects SET name=?1, updated_at=?2 WHERE id=?3", &[&new_c as &dyn ToSql, &ts, &id])?;
            renamed_children += 1;
        }
    }
    let mut project = get_project(db, settings, pid)?.ok_or_else(|| "项目不存在".to_string())?;
    if let Some(obj) = project.as_object_mut() {
        obj.insert("renamed_children".into(), json!(renamed_children));
    }
    Ok(project)
}

pub fn delete_project(db: &Db, pid: &str) -> Result<(), String> {
    let children = db.query("SELECT id FROM projects WHERE parent_id=?1", &[&pid as &dyn ToSql])?;
    for child in children {
        let id = cell_str(&child, "id").to_string();
        delete_project(db, &id)?;
    }
    db.execute("DELETE FROM finding_http WHERE finding_id IN (SELECT id FROM findings WHERE project_id=?1)", &[&pid as &dyn ToSql])?;
    for table in ["http_exchanges", "project_assets", "nodes", "edges", "findings", "runs", "events", "steering", "intents", "flags"] {
        db.execute(&format!("DELETE FROM {table} WHERE project_id=?1"), &[&pid as &dyn ToSql])?;
    }
    db.execute("DELETE FROM projects WHERE id=?1", &[&pid as &dyn ToSql])?;
    Ok(())
}

pub fn create_offline_ctf_project(db: &Db, settings: &Settings, name: &str, config: Value) -> Result<Value, String> {
    let mut cfg = config.as_object().cloned().unwrap_or_default();
    cfg.insert("offline".into(), json!(true));
    cfg.insert("track".into(), json!("ctf"));
    cfg.insert("objective".into(), json!("flag"));
    let scope = json!({"targets": [], "ips": [], "ports": Value::Null, "allow_subdomains": false, "mode": "strict"});
    let pid = crate::db::new_id("p_");
    let ts = now();
    let title = {
        let t = name.trim();
        if t.is_empty() { "本地题目".to_string() } else { t.to_string() }
    };
    let ports = dumps(&Value::Null);
    let scope_json = dumps(&scope);
    let cfg_json = dumps(&Value::Object(cfg));
    let empty = "";
    db.execute(
        "INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at) VALUES (?1,?2,'single',?3,?4,?5,?6,'idle',NULL,?7,?7)",
        &[&pid as &dyn ToSql, &title, &empty, &ports, &scope_json, &cfg_json, &ts],
    )?;
    get_project(db, settings, &pid)?.ok_or_else(|| "项目没有写入".into())
}

pub fn create_cluster_project(db: &Db, settings: &Settings, name: &str, cleaned: &[String], rejected: &[String], config: Value) -> Result<Value, String> {
    if cleaned.is_empty() {
        let extra = if rejected.is_empty() { String::new() } else { format!("：{:?}", &rejected[..rejected.len().min(5)]) };
        return Err(format!("集群资产均为本机/回环/Fake-IP，已全部拒绝{extra}"));
    }
    let mut hosts = Vec::new();
    let mut seen = BTreeSet::new();
    for asset in cleaned {
        let (host, _) = clean_target(asset);
        let host = host.trim_end_matches('.').to_string();
        if !host.is_empty() && seen.insert(host.clone()) {
            hosts.push(host);
        }
    }
    let targets = if hosts.is_empty() { cleaned.iter().map(|a| a.to_ascii_lowercase()).collect::<Vec<_>>() } else { hosts.clone() };
    let scope = json!({"targets": targets, "ips": [], "ports": Value::Null, "allow_subdomains": false, "mode": "strict"});
    let mut cfg = config.as_object().cloned().unwrap_or_default();
    cfg.insert("assets".into(), json!(cleaned));
    if !rejected.is_empty() {
        cfg.insert("assets_rejected".into(), json!(rejected));
    }
    let pid = crate::db::new_id("p_");
    let ts = now();
    let scope_json = dumps(&scope);
    let cfg_json = dumps(&Value::Object(cfg.clone()));
    let none: Option<String> = None;
    db.execute(
        "INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at) VALUES (?1,?2,'cluster',?3,?3,?4,?5,'idle',NULL,?6,?6)",
        &[&pid as &dyn ToSql, &name, &none, &scope_json, &cfg_json, &ts],
    )?;
    let vendor = cfg.get("vendor").and_then(Value::as_str).filter(|s| !s.trim().is_empty()).unwrap_or(name);
    seed_declared(db, &pid, &hosts, &[], Some(vendor))?;
    get_project(db, settings, &pid)?.ok_or_else(|| "项目没有写入".into())
}

pub fn create_benchmark_project(db: &Db, settings: &Settings, name: &str, base_url: &str, token: &str, config: Value) -> Result<Value, String> {
    let incoming = config.as_object().cloned().unwrap_or_default();
    let raw_obj = incoming.get("objective").or_else(|| incoming.get("track")).and_then(Value::as_str).unwrap_or("").trim().to_string();
    let is_agent = !raw_obj.is_empty() && crate::graph::normalize_objective(Some(raw_obj.as_str())) == "agent";
    let mut cfg = incoming;
    cfg.insert("objective".into(), json!(if is_agent { "agent" } else { "flag" }));
    if is_agent {
        cfg.insert("track".into(), json!("agent"));
    } else if !cfg.contains_key("track") {
        cfg.insert("track".into(), json!("ctf"));
    }
    let autopilot = if is_agent {
        json!(false)
    } else if let Some(v) = cfg.get("autopilot") {
        json!(v.as_bool().unwrap_or(true))
    } else {
        json!(true)
    };
    cfg.insert("autopilot".into(), autopilot);
    cfg.insert("benchmark".into(), json!({"base_url": base_url.trim_end_matches('/'), "token": token}));
    let scope = json!({"targets": [], "ips": [], "ports": Value::Null, "allow_subdomains": false, "mode": "strict"});
    let pid = crate::db::new_id("p_");
    let ts = now();
    let title = if name.trim().is_empty() { "benchmark".to_string() } else { name.trim().to_string() };
    let none: Option<String> = None;
    let scope_json = dumps(&scope);
    let cfg_json = dumps(&Value::Object(cfg));
    db.execute(
        "INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at) VALUES (?1,?2,'benchmark',?3,?3,?4,?5,'idle',NULL,?6,?6)",
        &[&pid as &dyn ToSql, &title, &none, &scope_json, &cfg_json, &ts],
    )?;
    get_project(db, settings, &pid)?.ok_or_else(|| "项目没有写入".into())
}

pub fn ensure_project_target_safe(db: &Db, settings: &Settings, pid: &str) -> Result<Value, String> {
    let Some(project) = get_project(db, settings, pid)? else { return Err("项目不存在".into()) };
    let target = project.get("target").and_then(Value::as_str).unwrap_or("").trim().to_string();
    if !target.is_empty() {
        assert_safe_project_target(&target)?;
    }
    Ok(project)
}

pub fn update_status(db: &Db, pid: &str, status: &str) -> Result<(), String> {
    let ts = now();
    if status == "queued" {
        db.execute(
            "UPDATE projects SET status=?1, updated_at=?2, queued_at=COALESCE(queued_at, ?2) WHERE id=?3",
            &[&status as &dyn ToSql, &ts, &pid],
        )?;
    } else {
        let none: Option<f64> = None;
        db.execute(
            "UPDATE projects SET status=?1, updated_at=?2, queued_at=?3 WHERE id=?4",
            &[&status as &dyn ToSql, &ts, &none, &pid],
        )?;
    }
    Ok(())
}

pub fn update_config(db: &Db, pid: &str, config: &Value) -> Result<(), String> {
    let blob = dumps(config);
    let ts = now();
    db.execute("UPDATE projects SET config=?1, updated_at=?2 WHERE id=?3", &[&blob as &dyn ToSql, &ts, &pid])
}

pub fn update_scope_and_config(db: &Db, pid: &str, scope: &Value, config: &Value) -> Result<(), String> {
    let ts = now();
    db.execute(
        "UPDATE projects SET scope=?1, config=?2, updated_at=?3 WHERE id=?4",
        &[&dumps(scope) as &dyn ToSql, &dumps(config), &ts, &pid],
    )
}

pub fn list_child_ids(db: &Db, pid: &str) -> Result<Vec<String>, String> {
    let rows = db.query("SELECT id FROM projects WHERE parent_id=?1", &[&pid as &dyn ToSql])?;
    Ok(rows.iter().map(|r| cell_str(r, "id").to_string()).filter(|s| !s.is_empty()).collect())
}

pub fn list_child_projects(db: &Db, settings: &Settings, pid: &str) -> Result<Vec<Value>, String> {
    let rows = db.query("SELECT * FROM projects WHERE parent_id=?1 ORDER BY created_at", &[&pid as &dyn ToSql])?;
    Ok(rows.iter().map(|row| serialize_project(row, settings)).collect())
}

pub fn delete_projects(db: &Db, settings: &Settings, ids: &[String]) -> Result<Value, String> {
    let mut seen = HashSet::new();
    let mut deleted = Vec::new();
    let mut missing = Vec::new();
    for raw in ids {
        let pid = raw.trim();
        if pid.is_empty() || !seen.insert(pid.to_string()) {
            continue;
        }
        if get_project(db, settings, pid)?.is_none() {
            missing.push(Value::from(pid));
            continue;
        }
        delete_project(db, pid)?;
        deleted.push(Value::from(pid));
    }
    Ok(json!({"deleted": deleted, "missing": missing}))
}

const HUNT_FAILED: &[&str] = &["graph_idle", "runtime_cap", "turn_cap", "empty_rounds"];

fn row_config(row: &Map<String, Value>) -> Map<String, Value> {
    match loads(row.get("config")) {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

pub fn unstick_transient_resource_errors(db: &Db) -> Result<i64, String> {
    let rows = db.query(
        "SELECT id, config FROM projects WHERE status='error' AND id IN (SELECT DISTINCT project_id FROM events WHERE type='log' AND (payload LIKE '%unable to open database%' OR payload LIKE '%Too many open files%' OR payload LIKE '%[Errno 24]%'))",
        &[],
    )?;
    let ids: Vec<String> = rows.into_iter().filter_map(|row| {
        let reason = row_config(&row).get("completion_reason").and_then(Value::as_str).unwrap_or("").to_string();
        if HUNT_FAILED.contains(&reason.as_str()) { None } else { Some(cell_str(&row, "id").to_string()) }
    }).filter(|s| !s.is_empty()).collect();
    if ids.is_empty() { return Ok(0); }
    let marks = ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 2)).collect::<Vec<_>>().join(",");
    let ts = now();
    let mut params: Vec<&dyn ToSql> = Vec::with_capacity(ids.len() + 1);
    params.push(&ts);
    for id in &ids { params.push(id); }
    db.execute(&format!("UPDATE projects SET status='idle', updated_at=?1 WHERE status='error' AND id IN ({marks})"), &params)?;
    Ok(ids.len() as i64)
}

pub fn reclassify_hunt_failures(db: &Db) -> Result<i64, String> {
    let rows = db.query("SELECT id, config FROM projects WHERE status IN ('idle','completed','stopped')", &[])?;
    let ids: Vec<String> = rows.into_iter().filter_map(|row| {
        let reason = row_config(&row).get("completion_reason").and_then(Value::as_str).unwrap_or("").to_string();
        if HUNT_FAILED.contains(&reason.as_str()) { Some(cell_str(&row, "id").to_string()) } else { None }
    }).filter(|s| !s.is_empty()).collect();
    if ids.is_empty() { return Ok(0); }
    let marks = ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 2)).collect::<Vec<_>>().join(",");
    let ts = now();
    let mut params: Vec<&dyn ToSql> = Vec::with_capacity(ids.len() + 1);
    params.push(&ts);
    for id in &ids { params.push(id); }
    db.execute(&format!("UPDATE projects SET status='error', updated_at=?1 WHERE id IN ({marks})"), &params)?;
    Ok(ids.len() as i64)
}

const MODEL_FAIL_HINTS: &[&str] = &[
    "model", "api key", "api_key", "rate limit", "overloaded", "credit",
    "401", "403", "429", "500", "502", "503", "invalid_request",
    "authentication", "insufficient", "quota",
];

pub fn looks_like_model_failure(message: &str) -> bool {
    let text = message.to_ascii_lowercase();
    MODEL_FAIL_HINTS.iter().any(|hint| text.contains(hint))
}

fn chain_token(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        _ => String::new(),
    }
}

pub fn advance_model_chain(db: &Db, settings: &Settings, project_id: &str) -> Result<Option<String>, String> {
    let Some(project) = get_project(db, settings, project_id)? else {
        return Ok(None);
    };
    let Some(mut cfg) = project.get("config").and_then(|v| v.as_object()).cloned() else {
        return Ok(None);
    };
    let chain: Vec<String> = match cfg.get("model_chain") {
        Some(Value::Array(items)) => items.iter().map(chain_token).filter(|s| !s.is_empty()).collect(),
        _ => Vec::new(),
    };
    if chain.len() < 2 {
        return Ok(None);
    }
    let index = match cfg.get("model_chain_index") {
        Some(Value::Number(number)) => number.as_i64().or_else(|| number.as_f64().map(|n| n as i64)).unwrap_or(0),
        Some(Value::String(text)) => text.parse::<i64>().unwrap_or(0),
        _ => 0,
    };
    let next = index + 1;
    if next < 0 || next as usize >= chain.len() {
        return Ok(None);
    }
    let model = chain[next as usize].clone();
    cfg.insert("model_chain_index".into(), json!(next));
    cfg.insert("model".into(), json!(model.clone()));
    update_config(db, project_id, &Value::Object(cfg))?;
    Ok(Some(model))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use std::collections::HashMap;

    fn temp() -> (Db, Settings) {
        let path = std::env::temp_dir().join(format!("atk-proj-{}.db", crate::db::new_id("t")));
        let db = Db::open(&path).unwrap();
        let settings = Settings::from_map(&HashMap::new(), std::path::Path::new("/tmp/no-repo"));
        (db, settings)
    }

    #[test]
    fn rejects_loopback_and_edu() {
        assert!(assert_safe_project_target("127.0.0.1").is_err());
        assert!(assert_safe_project_target("https://example.edu/a").is_err());
        assert_eq!(assert_safe_project_target("https://Example.com:443/x").unwrap(), "example.com");
    }

    #[test]
    fn create_list_delete() {
        let (db, settings) = temp();
        let project = create_single_project(&db, &settings, "演示", "example.com", None, false, "agent").unwrap();
        let id = project.get("id").and_then(Value::as_str).unwrap().to_string();
        assert_eq!(list_projects(&db, &settings).unwrap().len(), 1);
        delete_project(&db, &id).unwrap();
        assert!(list_projects(&db, &settings).unwrap().is_empty());
    }
}
