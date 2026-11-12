//! 建项和写入漏洞时，把主机登记进厂商资产库并挂到项目上。

use std::collections::BTreeSet;

use crate::db::{new_id, now, Db};
use rusqlite::ToSql;
use serde_json::{Map, Value};

fn norm_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase()
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

fn registrable(host: &str) -> String {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) {
        return h;
    }
    let parts: Vec<&str> = h.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return h;
    }
    const MULTI: &[&str] = &[
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "co.uk", "org.uk", "ac.uk", "gov.uk",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "com.au", "net.au", "org.au", "co.nz", "com.tw", "com.hk", "co.kr",
    ];
    let last2 = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if MULTI.contains(&last2.as_str()) && parts.len() >= 3 {
        return format!("{}.{}.{}", parts[parts.len() - 3], parts[parts.len() - 2], parts[parts.len() - 1]);
    }
    last2
}

fn sensitive_reason(host: &str) -> Option<String> {
    let h = norm_host(host);
    if h.is_empty() || is_dotted_v4(&h) {
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
        Some(format!("禁止攻击政府、教育、军队或学术网域名：{h}"))
    } else {
        None
    }
}

pub fn classify_host(host: &str) -> Option<(&'static str, String)> {
    let h = norm_host(host);
    if h.is_empty() {
        return None;
    }
    if is_dotted_v4(&h) {
        return Some(("ip", h));
    }
    let apex = registrable(&h);
    if h == apex { Some(("root_domain", h)) } else { Some(("subdomain", h)) }
}

fn loads_obj(raw: Option<&Value>) -> Map<String, Value> {
    match raw {
        Some(Value::Object(map)) => map.clone(),
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or_default(),
        _ => Map::new(),
    }
}

fn cell<'a>(row: &'a Map<String, Value>, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

fn deny_reason(db: &Db, kind: &str, identity: &str) -> Result<Option<String>, String> {
    let ident = identity.trim().to_ascii_lowercase();
    let host = if kind == "endpoint" {
        let rest = ident.split_once(' ').map(|(_, r)| r).unwrap_or(ident.as_str());
        host_of_url(rest).unwrap_or_default()
    } else if kind == "service" {
        norm_host(ident.split('|').next().unwrap_or(""))
    } else {
        ident.clone()
    };
    if !host.is_empty() && kind != "app" {
        if let Some(why) = sensitive_reason(&host) {
            return Ok(Some(why));
        }
    }
    let rows = db.query("SELECT pattern, reason FROM asset_denies", &[])?;
    for row in rows {
        let pat = norm_host(cell(&row, "pattern"));
        if pat.is_empty() {
            continue;
        }
        let hit = ident == pat
            || ident.ends_with(&format!(".{pat}"))
            || host == pat
            || host.ends_with(&format!(".{pat}"));
        if hit {
            let why = cell(&row, "reason");
            return Ok(Some(if why.is_empty() { "全局拒绝名单".into() } else { why.to_string() }));
        }
    }
    Ok(None)
}

fn project_row(db: &Db, project_id: &str) -> Result<Option<Map<String, Value>>, String> {
    db.query_one("SELECT * FROM projects WHERE id=?1", &[&project_id as &dyn ToSql])
}

fn allow_ok(cfg: &Map<String, Value>, identity: &str) -> bool {
    let Some(list) = cfg.get("asset_allow").and_then(Value::as_array) else { return true };
    if list.is_empty() {
        return true;
    }
    let norms: BTreeSet<String> = list.iter().filter_map(Value::as_str).map(norm_host).filter(|s| !s.is_empty()).collect();
    norms.contains(&norm_host(identity))
}

fn slash24(ip: &str) -> Option<String> {
    if !is_dotted_v4(ip) {
        return None;
    }
    let parts: Vec<&str> = ip.split('.').collect();
    Some(format!("{}.{}.{}", parts[0], parts[1], parts[2]))
}

fn same_subnet_blocked(db: &Db, project_id: &str, ip: &str, own: bool) -> Result<bool, String> {
    if own {
        return Ok(false);
    }
    let Some(block) = slash24(ip) else { return Ok(false) };
    let rows = db.query(
        "SELECT a.identity FROM assets a JOIN project_assets pa ON pa.asset_id=a.id WHERE pa.project_id=?1 AND pa.in_scope=1 AND a.kind='ip'",
        &[&project_id as &dyn ToSql],
    )?;
    for row in rows {
        let other = cell(&row, "identity");
        if other == ip {
            return Ok(false);
        }
        if slash24(other) == Some(block.clone()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_vendor(db: &Db, name: &str) -> Result<String, String> {
    let label = {
        let t = name.trim();
        if t.is_empty() { "未命名厂商".to_string() } else { t.to_string() }
    };
    if let Some(row) = db.query_one("SELECT id FROM vendors WHERE name=?1", &[&label as &dyn ToSql])? {
        return Ok(cell(&row, "id").to_string());
    }
    let vid = new_id("v_");
    let ts = now();
    db.execute(
        "INSERT INTO vendors(id, name, created_at, updated_at) VALUES (?1,?2,?3,?3)",
        &[&vid as &dyn ToSql, &label, &ts],
    )?;
    Ok(vid)
}

fn vendor_id_for(db: &Db, project_id: &str, vendor_name: Option<&str>) -> Result<String, String> {
    let proj = project_row(db, project_id)?.unwrap_or_default();
    let existing = cell(&proj, "vendor_id").trim().to_string();
    if !existing.is_empty() && vendor_name.map(str::trim).unwrap_or("").is_empty() {
        return Ok(existing);
    }
    let cfg = loads_obj(proj.get("config"));
    let label = vendor_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .or_else(|| cfg.get("vendor").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(|s| s.to_string()))
        .or_else(|| {
            let t = cell(&proj, "target").trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        })
        .unwrap_or_else(|| cell(&proj, "name").to_string());
    let vid = ensure_vendor(db, &label)?;
    let ts = now();
    db.execute("UPDATE projects SET vendor_id=?1, updated_at=?2 WHERE id=?3", &[&vid as &dyn ToSql, &ts, &project_id])?;
    Ok(vid)
}

fn upsert_asset(
    db: &Db,
    vendor_id: &str,
    kind: &str,
    identity: &str,
    project_id: Option<&str>,
    in_scope: bool,
    basis: Option<&str>,
    finding_id: Option<&str>,
) -> Result<Option<String>, String> {
    const KINDS: &[&str] = &["root_domain", "subdomain", "ip", "service", "endpoint", "app"];
    if !KINDS.contains(&kind) {
        return Ok(None);
    }
    let ident = match kind {
        "root_domain" | "subdomain" | "ip" => norm_host(identity),
        "service" => identity.trim().to_ascii_lowercase(),
        _ => identity.trim().to_string(),
    };
    if ident.is_empty() {
        return Ok(None);
    }
    if deny_reason(db, kind, &ident)?.is_some() {
        return Ok(None);
    }
    let ts = now();
    let row = db.query_one(
        "SELECT id FROM assets WHERE vendor_id=?1 AND kind=?2 AND identity=?3",
        &[&vendor_id as &dyn ToSql, &kind, &ident],
    )?;
    let asset_id = if let Some(row) = row {
        let id = cell(&row, "id").to_string();
        db.execute("UPDATE assets SET updated_at=?1 WHERE id=?2", &[&ts as &dyn ToSql, &id])?;
        id
    } else {
        let id = new_id("a_");
        let attrs = "{}";
        db.execute(
            "INSERT INTO assets(id, vendor_id, kind, identity, attrs, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?6)",
            &[&id as &dyn ToSql, &vendor_id, &kind, &ident, &attrs, &ts],
        )?;
        id
    };
    if let Some(project_id) = project_id {
        let link = db.query_one(
            "SELECT in_scope FROM project_assets WHERE project_id=?1 AND asset_id=?2",
            &[&project_id as &dyn ToSql, &asset_id],
        )?;
        let prev = link.as_ref().and_then(|r| r.get("in_scope")).and_then(Value::as_i64).unwrap_or(0) != 0;
        let scoped = i64::from(in_scope || prev);
        if link.is_some() {
            db.execute(
                "UPDATE project_assets SET in_scope=?1, scope_basis=COALESCE(?2, scope_basis), confirmed_at=CASE WHEN ?1=1 THEN COALESCE(confirmed_at, ?3) ELSE confirmed_at END WHERE project_id=?4 AND asset_id=?5",
                &[&scoped as &dyn ToSql, &basis, &ts, &project_id, &asset_id],
            )?;
        } else {
            let confirmed = if scoped == 1 { Some(ts) } else { None };
            db.execute(
                "INSERT INTO project_assets(project_id, asset_id, in_scope, scope_basis, confirmed_at) VALUES (?1,?2,?3,?4,?5)",
                &[&project_id as &dyn ToSql, &asset_id, &scoped, &basis, &confirmed],
            )?;
        }
    }
    if let Some(finding_id) = finding_id.filter(|s| !s.is_empty()) {
        db.execute(
            "INSERT OR IGNORE INTO finding_assets(finding_id, asset_id) VALUES (?1,?2)",
            &[&finding_id as &dyn ToSql, &asset_id],
        )?;
    }
    Ok(Some(asset_id))
}

fn authorize_host(db: &Db, project_id: &str, host: &str) -> Result<(), String> {
    let Some(proj) = project_row(db, project_id)? else { return Ok(()) };
    let Some((kind, ident)) = classify_host(host) else { return Ok(()) };
    let mut scope = loads_obj(proj.get("scope"));
    let key = if kind == "ip" { "ips" } else { "targets" };
    let mut list = scope.get(key).and_then(Value::as_array).cloned().unwrap_or_default();
    let exists = list.iter().any(|v| v.as_str().map(norm_host).as_deref() == Some(ident.as_str()));
    if !exists {
        list.push(Value::from(ident));
        scope.insert(key.into(), Value::Array(list));
        let blob = serde_json::to_string(&Value::Object(scope)).unwrap_or_else(|_| "{}".into());
        let ts = now();
        db.execute("UPDATE projects SET scope=?1, updated_at=?2 WHERE id=?3", &[&blob as &dyn ToSql, &ts, &project_id])?;
    }
    Ok(())
}

pub fn remember_host(
    db: &Db,
    project_id: &str,
    host: &str,
    in_scope: bool,
    vendor_name: Option<&str>,
    finding_id: Option<&str>,
    own_ip: bool,
) -> Result<(), String> {
    let Some((kind, ident)) = classify_host(host) else { return Ok(()) };
    let proj = project_row(db, project_id)?.unwrap_or_default();
    let cfg = loads_obj(proj.get("config"));
    let vid = vendor_id_for(db, project_id, vendor_name)?;
    let mut scoped = in_scope && allow_ok(&cfg, &ident);
    if kind == "ip" && scoped && same_subnet_blocked(db, project_id, &ident, own_ip)? {
        scoped = false;
    }
    let row = upsert_asset(db, &vid, kind, &ident, Some(project_id), scoped, None, finding_id)?;
    if kind == "subdomain" {
        let apex = registrable(&ident);
        if !apex.is_empty() && apex != ident {
            let _ = upsert_asset(db, &vid, "root_domain", &apex, Some(project_id), false, None, finding_id)?;
        }
    }
    if row.is_some() && scoped {
        authorize_host(db, project_id, &ident)?;
    }
    Ok(())
}

pub fn seed_declared(db: &Db, project_id: &str, hosts: &[String], ips: &[String], vendor_name: Option<&str>) -> Result<(), String> {
    for host in hosts {
        remember_host(db, project_id, host, true, vendor_name, None, true)?;
    }
    for ip in ips {
        remember_host(db, project_id, ip, true, vendor_name, None, true)?;
    }
    Ok(())
}

fn host_of_url(raw: &str) -> Option<String> {
    let mut text = raw.trim();
    if let Some(idx) = text.find("://") {
        text = &text[idx + 3..];
    }
    let auth = text.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let host = if let Some(rest) = auth.strip_prefix('[') {
        rest.split(']').next().unwrap_or("").to_string()
    } else {
        auth.split(':').next().unwrap_or("").to_string()
    };
    let host = norm_host(&host);
    if host.is_empty() { None } else { Some(host) }
}

fn hosts_in_text(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut search_from = 0;
    while search_from < lower.len() {
        let slice = &lower[search_from..];
        let http = slice.find("http://");
        let https = slice.find("https://");
        let rel = match (http, https) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let Some(rel) = rel else { break };
        let abs = search_from + rel;
        let scheme_len = if lower[abs..].starts_with("https://") { 8 } else { 7 };
        let tail = &text[abs + scheme_len..];
        let end = tail.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>')).unwrap_or(tail.len());
        if let Some(host) = host_of_url(&tail[..end]) {
            if !out.iter().any(|h| h == &host) {
                out.push(host);
            }
        }
        search_from = abs + scheme_len + end;
        if search_from == abs {
            break;
        }
    }
    out
}

fn endpoint_identity(method: &str, url: &str) -> Option<String> {
    let raw = url.trim();
    if raw.is_empty() {
        return None;
    }
    let owned;
    let text = if raw.contains("://") {
        raw
    } else {
        owned = format!("http://{raw}");
        owned.as_str()
    };
    let (scheme, rest) = text.split_once("://")?;
    let host = host_of_url(rest)?;
    let after = rest.split(['/', '?', '#']).next().unwrap_or("");
    let after = after.rsplit('@').next().unwrap_or(after);
    let port = if after.starts_with('[') {
        after.split(']').nth(1).and_then(|s| s.strip_prefix(':')).filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    } else {
        after.split_once(':').map(|(_, p)| p).filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
    };
    let path_src = rest.split(['?', '#']).next().unwrap_or("");
    let path = path_src.find('/').map(|i| &path_src[i..]).unwrap_or("/");
    let query = rest.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("")).filter(|q| !q.is_empty());
    let port = port.map(|p| format!(":{p}")).unwrap_or_default();
    let query = query.map(|q| format!("?{q}")).unwrap_or_default();
    Some(format!("{} {scheme}://{host}{port}{path}{query}", method.trim().to_ascii_uppercase()))
}

pub fn attach_finding_assets(db: &Db, project_id: &str, finding_id: &str, proof_url: Option<&str>, evidence: Option<&str>) -> Result<(), String> {
    let proof_hosts = hosts_in_text(proof_url.unwrap_or(""));
    for host in &proof_hosts {
        remember_host(db, project_id, host, true, None, Some(finding_id), false)?;
        if let Some(ident) = endpoint_identity("GET", proof_url.unwrap_or("")) {
            let vid = vendor_id_for(db, project_id, None)?;
            let _ = upsert_asset(db, &vid, "endpoint", &ident, Some(project_id), false, None, Some(finding_id))?;
        }
    }
    for host in hosts_in_text(evidence.unwrap_or("")) {
        if proof_hosts.iter().any(|h| h == &host) {
            continue;
        }
        remember_host(db, project_id, &host, false, None, Some(finding_id), false)?;
    }
    let verified = db.query_one("SELECT verification_status FROM findings WHERE id=?1", &[&finding_id as &dyn ToSql])?;
    if verified.as_ref().map(|r| cell(r, "verification_status") == "verified").unwrap_or(false) {
        let ts = now();
        db.execute(
            "UPDATE assets SET verified_at=COALESCE(verified_at, ?1) WHERE id IN (SELECT asset_id FROM finding_assets WHERE finding_id=?2)",
            &[&ts as &dyn ToSql, &finding_id],
        )?;
    }
    Ok(())
}
