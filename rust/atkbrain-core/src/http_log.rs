//! 猎面 HTTP 记录留在库里。对不上方法、URL 和状态码就不绑定。

use crate::db::{now, Db};
use rusqlite::ToSql;
use serde_json::{Map, Value};

const CAP: usize = 200_000;

fn clip(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        return value.to_string();
    }
    let head: String = value.chars().take(limit).collect();
    format!("{head}\n…[已截断]")
}

fn summary(body: &str) -> String {
    let flat = regex::Regex::new(r"\s+").unwrap().replace_all(body, " ");
    flat.trim().chars().take(180).collect()
}

pub fn url_key(url: &str) -> String {
    let mut raw = url.trim().to_string();
    if !raw.contains("://") {
        raw = format!("http://{raw}");
    }
    let Some((_, rest)) = raw.split_once("://") else { return url.trim().to_string() };
    let scheme = raw.split("://").next().unwrap_or("http").to_ascii_lowercase();
    let (authority, pathq) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let hostport = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => (h.to_ascii_lowercase(), format!(":{p}")),
        _ => (hostport.to_ascii_lowercase(), String::new()),
    };
    let (path, query) = match pathq.split_once('?') {
        Some((p, q)) => (if p.is_empty() { "/" } else { p }.to_string(), format!("?{q}")),
        None => (if pathq.is_empty() { "/".into() } else { pathq }, String::new()),
    };
    format!("{scheme}://{host}{port}{path}{query}")
}

fn role_name(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "对照" | "baseline" => Some("对照"),
        "证明" | "proof" => Some("证明"),
        "复核" | "review" => Some("复核"),
        "辅助" | "aux" => Some("辅助"),
        _ => None,
    }
}

pub fn record_exchange(
    db: &Db,
    project_id: &str,
    run_id: Option<&str>,
    method: &str,
    url: &str,
    request_headers: &str,
    request_body: &str,
    status: i64,
    response_headers: &str,
    response_body: &str,
) -> Result<String, String> {
    let eid = crate::db::new_id("hx_");
    let body = clip(response_body, CAP);
    let sum = summary(&body);
    let method = method.to_ascii_uppercase();
    let run = run_id.unwrap_or("");
    let headers = clip(request_headers, 8000);
    let req_body = clip(request_body, 80_000);
    let resp_headers = clip(response_headers, 8000);
    let created = now();
    db.execute(
        "INSERT INTO http_exchanges(id, project_id, run_id, method, url, request_headers, request_body, status, response_headers, response_body, response_summary, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        &[
            &eid as &dyn ToSql,
            &project_id,
            &run,
            &method,
            &url,
            &headers,
            &req_body,
            &status,
            &resp_headers,
            &body,
            &sum,
            &created,
        ],
    )?;
    Ok(eid)
}

fn matches(row: &Map<String, Value>, method: &str, url: &str, status: i64, summary_text: &str) -> bool {
    if method.is_empty() || url.is_empty() {
        return false;
    }
    let row_method = row.get("method").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase();
    if method.to_ascii_uppercase() != row_method {
        return false;
    }
    if url_key(url) != url_key(row.get("url").and_then(Value::as_str).unwrap_or("")) {
        return false;
    }
    let row_status = row.get("status").and_then(Value::as_i64).unwrap_or(0);
    if status != row_status {
        return false;
    }
    let stored = row.get("response_summary").and_then(Value::as_str).unwrap_or("");
    if !summary_text.is_empty() && !stored.is_empty() {
        let a: String = summary_text.chars().take(80).collect();
        let b: String = stored.chars().take(80).collect();
        if !stored.contains(&a) && !summary_text.contains(&b) {
            return false;
        }
    }
    true
}

pub fn bind_finding(db: &Db, finding_id: &str, refs: &[Value]) -> Result<Value, String> {
    let mut bound = Vec::new();
    let mut skipped = 0i64;
    let mut ordinal = 0i64;
    for ref_item in refs {
        let Some(obj) = ref_item.as_object() else { skipped += 1; continue };
        let Some(role) = role_name(obj.get("role").and_then(Value::as_str).unwrap_or("")).map(str::to_string) else { skipped += 1; continue };
        let eid = obj.get("id").and_then(Value::as_str).or_else(|| obj.get("exchange_id").and_then(Value::as_str)).unwrap_or("").trim().to_string();
        if eid.is_empty() { skipped += 1; continue }
        let Some(row) = db.query_one("SELECT * FROM http_exchanges WHERE id=?1", &[&eid as &dyn ToSql])? else { skipped += 1; continue };
        let method = obj.get("method").and_then(Value::as_str).unwrap_or("");
        let url = obj.get("url").and_then(Value::as_str).unwrap_or("");
        let status = obj.get("status").and_then(Value::as_i64).unwrap_or(-1);
        let summary_text = obj.get("summary").or_else(|| obj.get("response_summary")).and_then(Value::as_str).unwrap_or("");
        if !matches(&row, method, url, status, summary_text) { skipped += 1; continue }
        db.execute(
            "INSERT INTO finding_http(finding_id, exchange_id, ordinal, role) VALUES (?1,?2,?3,?4) ON CONFLICT(finding_id, exchange_id) DO UPDATE SET ordinal=excluded.ordinal, role=excluded.role",
            &[&finding_id as &dyn ToSql, &eid, &ordinal, &role],
        )?;
        ordinal += 1;
        bound.push(Value::String(eid));
    }
    Ok(serde_json::json!({"bound": bound, "skipped": skipped}))
}

pub fn bound_exchanges(db: &Db, finding_id: &str) -> Result<Vec<Map<String, Value>>, String> {
    db.query(
        "SELECT h.*, f.ordinal, f.role FROM finding_http f JOIN http_exchanges h ON h.id=f.exchange_id WHERE f.finding_id=?1 ORDER BY f.ordinal ASC",
        &[&finding_id as &dyn ToSql],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_key_ignores_host_case() {
        assert_eq!(url_key("HTTPS://Example.com/a?x=1"), url_key("https://example.com/a?x=1"));
    }
}
