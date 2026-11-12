//! 本机版本与远程 tag 比较。落后才提示可更新。

use std::path::Path;

const FALLBACK: &str = "0.5.0-beta.1";

pub fn normalize_ver(raw: &str) -> String {
    let s = raw.trim();
    if s.len() > 1 && s.to_ascii_lowercase().starts_with('v') && s[1..].chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return s[1..].to_string();
    }
    s.to_string()
}

pub fn parse_ver(raw: &str) -> Option<Vec<u64>> {
    let s = normalize_ver(raw);
    if s.is_empty() {
        return None;
    }
    let core = s.split('+').next().unwrap_or("").split('-').next().unwrap_or("");
    if core.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for bit in core.split('.') {
        if bit.is_empty() || !bit.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        parts.push(bit.parse::<u64>().ok()?);
    }
    if parts.is_empty() { None } else { Some(parts) }
}

pub fn local_version(repo_root: &Path) -> String {
    let text = std::fs::read_to_string(repo_root.join("VERSION")).unwrap_or_default();
    let line = text.lines().next().unwrap_or("").trim();
    if line.is_empty() { FALLBACK.to_string() } else { line.to_string() }
}

pub fn status_for(local: &str, remote: Option<&str>) -> (&'static str, String, bool) {
    let Some(remote) = remote.filter(|s| !s.is_empty()) else {
        return ("latest", "已是最新".into(), true);
    };
    match (parse_ver(local), parse_ver(remote)) {
        (Some(lv), Some(rv)) if rv > lv => (
            "update_available",
            format!("有新版本 v{}", normalize_ver(remote)),
            false,
        ),
        (Some(_), Some(_)) => ("latest", "已是最新".into(), true),
        _ if normalize_ver(local) == normalize_ver(remote) => ("latest", "已是最新".into(), true),
        _ => (
            "update_available",
            format!("有新版本 v{}", normalize_ver(remote)),
            false,
        ),
    }
}

pub fn repo_slug(raw: &str) -> String {
    let mut s = raw.trim().to_string();
    for prefix in ["https://github.com/", "http://github.com/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    s = s.trim_matches('/').to_string();
    if let Some(rest) = s.strip_suffix(".git") {
        s = rest.to_string();
    }
    if s.is_empty() {
        "Yean-Sec/StrikeAgent_AtkBrain-Flash".into()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_numeric_and_prerelease() {
        assert_eq!(parse_ver("0.5.0"), Some(vec![0, 5, 0]));
        assert_eq!(parse_ver("v1.2.3-beta.1"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn status_matches_python() {
        let (st, _, latest) = status_for("0.5.0", Some("0.6.0"));
        assert_eq!(st, "update_available");
        assert!(!latest);
        let (st, _, latest) = status_for("0.6.0", Some("0.5.0"));
        assert_eq!(st, "latest");
        assert!(latest);
        let (st, _, latest) = status_for("1.0.0", None);
        assert_eq!(st, "latest");
        assert!(latest);
    }
}
