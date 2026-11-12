//! 升级 tag 只允许发行号里的字符，拒绝由路径或分隔符组成的字符串。

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn upgrade_script(repo_root: &Path) -> PathBuf {
    repo_root.join("scripts").join("atkbrain-upgrade.sh")
}

pub fn validate_tag(tag: &str) -> Result<String, String> {
    let raw = tag.trim();
    if raw.is_empty()
        || !raw
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err("illegal tag".into());
    }
    Ok(raw.to_string())
}

pub fn start_upgrade(repo_root: &Path, data_dir: &Path, tag: &str, github_repo: &str, github_token: &str) -> Result<PathBuf, String> {
    let script = upgrade_script(repo_root);
    if !script.is_file() {
        return Err(script.display().to_string());
    }
    let raw = validate_tag(tag)?;
    let log_dir = data_dir.join("logs");
    std::fs::create_dir_all(&log_dir).map_err(|e| e.to_string())?;
    let log_path = log_dir.join("upgrade.log");
    let logf = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/bin/bash");
    cmd.arg(&script)
        .arg(&raw)
        .current_dir(repo_root)
        .stdout(logf.try_clone().map_err(|e| e.to_string())?)
        .stderr(logf);
    if !github_repo.is_empty() {
        cmd.env("ATKBRAIN_GITHUB_REPO", github_repo);
    }
    if !github_token.is_empty() {
        cmd.env("ATKBRAIN_GITHUB_TOKEN", github_token);
    }
    cmd.env("ATKBRAIN_UPGRADE_PID", std::process::id().to_string());
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(log_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_metacharacters() {
        assert!(validate_tag("v1.0;rm").is_err());
        assert!(validate_tag("../x").is_err());
        assert!(validate_tag("").is_err());
        assert_eq!(validate_tag("v1.2.3").unwrap(), "v1.2.3");
    }
}
