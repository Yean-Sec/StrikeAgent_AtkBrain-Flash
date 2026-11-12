//! SQLite：单连接、WAL，表结构和已有库的补列与 Python 控制台一致。

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params_from_iter, types::ValueRef, Connection, OptionalExtension, ToSql};
use serde_json::{Map, Value};

const SCHEMA: &str = include_str!("schema.sql");

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        migrate(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn execute(&self, sql: &str, params: &[&dyn ToSql]) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(sql, params_from_iter(params.iter())).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn query(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Vec<Map<String, Value>>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
        let cols: Vec<String> = stmt.column_names().into_iter().map(str::to_string).collect();
        let mut rows = stmt.query(params_from_iter(params.iter())).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let mut item = Map::new();
            for (i, name) in cols.iter().enumerate() {
                item.insert(name.clone(), cell(row, i)?);
            }
            out.push(item);
        }
        Ok(out)
    }

    pub fn query_one(&self, sql: &str, params: &[&dyn ToSql]) -> Result<Option<Map<String, Value>>, String> {
        Ok(self.query(sql, params)?.into_iter().next())
    }
}

pub fn new_id(prefix: &str) -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("{prefix}{}", hex::encode(bytes))
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn cell(row: &rusqlite::Row<'_>, i: usize) -> Result<Value, String> {
    match row.get_ref(i).map_err(|e| e.to_string())? {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(n) => Ok(Value::from(n)),
        ValueRef::Real(n) => Ok(serde_json::Number::from_f64(n).map(Value::Number).unwrap_or(Value::Null)),
        ValueRef::Text(t) => Ok(Value::String(String::from_utf8_lossy(t).into_owned())),
        ValueRef::Blob(b) => Ok(Value::String(hex::encode(b))),
    }
}

fn columns(conn: &Connection, table: &str) -> Result<Vec<String>, String> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})")).map_err(|e| e.to_string())?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    Ok(names)
}

fn add_missing(conn: &Connection, table: &str, adds: &[(&str, &str)]) -> Result<(), String> {
    let have = columns(conn, table)?;
    for (name, def) in adds {
        if !have.iter().any(|c| c == name) {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {name} {def}"), [])
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn migrate(conn: &Connection) -> Result<(), String> {
    add_missing(
        conn,
        "intents",
        &[
            ("strategy_key", "TEXT"),
            ("evidence_fingerprint", "TEXT"),
            ("priority", "REAL NOT NULL DEFAULT 0.5"),
            ("attempt_count", "INTEGER NOT NULL DEFAULT 0"),
            ("failure_fingerprint", "TEXT"),
            ("result_summary", "TEXT"),
            ("active_run_id", "TEXT"),
            ("updated_at", "REAL"),
            ("paused", "INTEGER NOT NULL DEFAULT 0"),
            ("pending_steer", "TEXT"),
            ("depends_on", "TEXT"),
        ],
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_intents_frontier ON intents(project_id, status, priority DESC);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_strategy_dedupe
           ON intents(project_id, strategy_key)
           WHERE strategy_key IS NOT NULL AND strategy_key <> '';",
    )
    .map_err(|e| e.to_string())?;

    add_missing(
        conn,
        "findings",
        &[
            ("verification_status", "TEXT NOT NULL DEFAULT 'verified'"),
            ("verified_at", "REAL"),
            ("proof_type", "TEXT"),
            ("proof_canary", "TEXT"),
            ("proof_url", "TEXT"),
            ("proof_detail", "TEXT"),
            ("secondary_verified", "INTEGER NOT NULL DEFAULT 0"),
            ("redteam_rating", "TEXT"),
            ("redteam_rating_rationale", "TEXT"),
            ("report_summary", "TEXT"),
            ("report_impact", "TEXT"),
            ("report_rating", "TEXT"),
            ("report_repro", "TEXT"),
            ("report_fix", "TEXT"),
            ("disposition", "TEXT"),
            ("retest_conclusion", "TEXT"),
        ],
    )?;
    conn.execute_batch(
        "UPDATE findings SET verified_at=COALESCE(verified_at, created_at)
           WHERE verification_status='verified' AND verified_at IS NULL;
         UPDATE findings SET verification_status='verified',
                verified_at=COALESCE(verified_at, created_at)
           WHERE secondary_verified=1
             AND IFNULL(verification_status,'') IN ('pending','flaky','');
         CREATE INDEX IF NOT EXISTS idx_findings_verification
           ON findings(project_id, verification_status);",
    )
    .map_err(|e| e.to_string())?;

    add_missing(
        conn,
        "projects",
        &[
            ("category", "TEXT"),
            ("archived", "INTEGER NOT NULL DEFAULT 0"),
            ("queued_at", "REAL"),
            ("vendor_id", "TEXT"),
        ],
    )?;
    add_missing(
        conn,
        "auth_users",
        &[
            ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
            ("bootstrap_login_done", "INTEGER NOT NULL DEFAULT 0"),
        ],
    )?;

    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)")
        .map_err(|e| e.to_string())?;
    let mark: Option<String> = conn
        .query_row("SELECT v FROM schema_kv WHERE k='playbook_reset'", [], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    if mark.as_deref() != Some("claude_v1") {
        conn.execute("DELETE FROM memory WHERE kind='lesson'", []).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO schema_kv(k, v) VALUES('playbook_reset', 'claude_v1')",
            [],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_wal_and_reads_a_project() {
        let path = std::env::temp_dir().join(format!("atkbrain-core-{}.db", new_id("t")));
        let db = Db::open(&path).unwrap();
        let id = new_id("p_");
        let ts = now();
        db.execute(
            "INSERT INTO projects(id, name, kind, status, created_at, updated_at) VALUES (?1, ?2, 'single', 'idle', ?3, ?3)",
            &[&id, &"n".to_string(), &ts],
        )
        .unwrap();
        let row = db.query_one("SELECT name, status FROM projects WHERE id=?1", &[&id]).unwrap().unwrap();
        assert_eq!(row.get("name").and_then(Value::as_str), Some("n"));
        assert_eq!(row.get("status").and_then(Value::as_str), Some("idle"));
        Db::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
    }
}
