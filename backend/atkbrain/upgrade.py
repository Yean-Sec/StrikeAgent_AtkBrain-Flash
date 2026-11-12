"""后台拉起 scripts/atkbrain-upgrade.sh。tag 必须来自 check_latest，不要信客户端。"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import REPO_ROOT, settings


def live_hunt_ids() -> list[str]:
    from atkbrain_native import hunt_manager as manager

    snap = manager.snapshot()
    out: list[str] = []
    for key in ("running", "queued"):
        for item in snap.get(key) or []:
            s = str(item or "").strip()
            if s and s not in out:
                out.append(s)
    return out


def upgrade_script() -> Path:
    return Path(REPO_ROOT) / "scripts" / "atkbrain-upgrade.sh"


def start_upgrade(tag: str) -> Path:
    script = upgrade_script()
    if not script.is_file():
        raise FileNotFoundError(str(script))
    raw = str(tag or "").strip()
    if raw.startswith("v") and len(raw) > 1 and raw[1].isdigit():
        # 脚本同时认 v1.2 与 1.2；统一交给脚本原样。
        pass
    if not raw or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-" for ch in raw):
        raise ValueError("illegal tag")
    log_dir = Path(settings.data_dir) / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "upgrade.log"
    env = os.environ.copy()
    env["ATKBRAIN_UPGRADE_PID"] = str(os.getpid())
    slug = str(getattr(settings, "github_repo", "") or "").strip()
    if slug:
        env["ATKBRAIN_GITHUB_REPO"] = slug
    token = str(getattr(settings, "github_token", "") or "").strip()
    if token:
        env["ATKBRAIN_GITHUB_TOKEN"] = token
    logf = open(log_path, "ab")
    try:
        subprocess.Popen(
            ["/bin/bash", str(script), raw],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
        )
    finally:
        logf.close()
    return log_path
