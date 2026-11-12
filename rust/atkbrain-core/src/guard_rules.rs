//! 自定义命令拦截。内置规则只读，这里只追加用户规则。

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

const BUILTIN: &[(&str, &str, &str, &str)] = &[
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

#[derive(Clone, Debug)]
pub struct GuardRule {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub reason: String,
    pub enabled: bool,
    pub category: String,
    pub builtin: bool,
}

pub fn builtin_rules() -> Vec<GuardRule> {
    BUILTIN
        .iter()
        .map(|(id, name, category, pattern)| GuardRule {
            id: (*id).into(),
            name: (*name).into(),
            pattern: (*pattern).into(),
            reason: String::new(),
            enabled: true,
            category: (*category).into(),
            builtin: true,
        })
        .collect()
}

fn builtin_ids() -> Vec<String> {
    builtin_rules().into_iter().map(|r| r.id).collect()
}

pub fn rules_path(data_dir: &Path) -> PathBuf {
    data_dir.join("guard-rules.json")
}

fn read_custom(path: &Path) -> Vec<GuardRule> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    let Ok(raw) = serde_json::from_str::<Value>(&text) else { return Vec::new() };
    let rows = raw.get("rules").cloned().unwrap_or(raw);
    let Some(rows) = rows.as_array() else { return Vec::new() };
    let ids = builtin_ids();
    let mut out = Vec::new();
    for row in rows {
        let rid = row.get("id").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if rid.is_empty() || rid.starts_with("builtin-") || ids.iter().any(|id| id == &rid) {
            continue;
        }
        out.push(GuardRule {
            id: rid,
            name: row.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string(),
            pattern: row.get("pattern").and_then(Value::as_str).unwrap_or("").to_string(),
            reason: row.get("reason").and_then(Value::as_str).unwrap_or("").trim().to_string(),
            enabled: row.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            category: "custom".into(),
            builtin: false,
        });
    }
    out
}

fn write_custom(path: &Path, rows: &[GuardRule]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let rules: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "name": row.name,
                "pattern": row.pattern,
                "reason": row.reason,
                "enabled": row.enabled,
            })
        })
        .collect();
    let text = serde_json::to_string_pretty(&json!({"rules": rules})).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn list_custom(data_dir: &Path) -> Vec<GuardRule> {
    read_custom(&rules_path(data_dir))
}

pub fn create_rule(data_dir: &Path, name: &str, pattern: &str, reason: &str, enabled: bool) -> Result<GuardRule, String> {
    let title = name.trim();
    if title.is_empty() {
        return Err("需要规则名称".into());
    }
    if pattern.trim().is_empty() {
        return Err("需要正则".into());
    }
    if pattern.len() > 400 {
        return Err("正则过长".into());
    }
    regex::Regex::new(pattern).map_err(|e| format!("正则不合法：{e}"))?;
    let mut rows = list_custom(data_dir);
    let row = GuardRule {
        id: format!("c-{}", crate::db::new_id("")),
        name: title.chars().take(80).collect(),
        pattern: pattern.to_string(),
        reason: reason.trim().chars().take(200).collect(),
        enabled,
        category: "custom".into(),
        builtin: false,
    };
    rows.push(row.clone());
    write_custom(&rules_path(data_dir), &rows)?;
    Ok(row)
}

pub fn set_enabled(data_dir: &Path, rule_id: &str, enabled: bool) -> Result<GuardRule, String> {
    let rid = rule_id.trim();
    if rid.starts_with("builtin-") || builtin_ids().iter().any(|id| id == rid) {
        return Err("内置规则不能修改".into());
    }
    let mut rows = list_custom(data_dir);
    for row in &mut rows {
        if row.id == rid {
            row.enabled = enabled;
            let out = row.clone();
            write_custom(&rules_path(data_dir), &rows)?;
            return Ok(out);
        }
    }
    Err("规则不存在".into())
}

pub fn delete_rule(data_dir: &Path, rule_id: &str) -> Result<(), String> {
    let rid = rule_id.trim();
    if rid.starts_with("builtin-") || builtin_ids().iter().any(|id| id == rid) {
        return Err("内置规则不能删除".into());
    }
    let rows = list_custom(data_dir);
    let kept: Vec<_> = rows.iter().filter(|row| row.id != rid).cloned().collect();
    if kept.len() == rows.len() {
        return Err("规则不存在".into());
    }
    write_custom(&rules_path(data_dir), &kept)
}

pub fn custom_block_reason(data_dir: &Path, command: &str) -> Option<String> {
    let text = command;
    if text.trim().is_empty() {
        return None;
    }
    let sample: String = text.chars().take(8000).collect();
    for row in list_custom(data_dir) {
        if !row.enabled {
            continue;
        }
        let Ok(re) = regex::Regex::new(&row.pattern) else { continue };
        if re.is_match(&sample) {
            let why = if row.reason.trim().is_empty() { row.name } else { row.reason };
            return Some(format!("拦截自定义规则：{why}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_rule_blocks_and_builtin_stays() {
        let dir = std::env::temp_dir().join(format!("atk-guard-{}", crate::db::new_id("g")));
        std::fs::create_dir_all(&dir).unwrap();
        let row = create_rule(&dir, "拒绝标记", "FORBIDDEN_MARK", "", true).unwrap();
        assert!(custom_block_reason(&dir, "echo FORBIDDEN_MARK").unwrap().contains("拒绝标记"));
        assert!(set_enabled(&dir, "builtin-rm-root", false).is_err());
        delete_rule(&dir, &row.id).unwrap();
        assert!(custom_block_reason(&dir, "echo FORBIDDEN_MARK").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
