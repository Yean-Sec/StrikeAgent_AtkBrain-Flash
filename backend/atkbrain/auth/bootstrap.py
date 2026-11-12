"""首次从环境变量写入管理员哈希；日常不要把明文口令留在 unit 里。"""
from __future__ import annotations

import os
from pathlib import Path

from ..config import settings
from atkbrain_native import ensure_auth_keys, hash_password
from .store import any_user, get_user, upsert_admin


def env_truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in ("1", "true", "yes", "on")


def env_no_auth() -> bool:
    return env_truthy(getattr(settings, "auth_no_auth", "") or "")


async def login_required() -> bool:
    if env_no_auth():
        return False
    return True


def bootstrap_secret_path() -> Path:
    return Path(settings.data_dir) / "admin_bootstrap.secret"


def write_bootstrap_secret(password: str) -> None:
    path = bootstrap_secret_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(str(password or ""), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    os.chmod(path, 0o600)


def read_bootstrap_secret() -> str:
    path = bootstrap_secret_path()
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def clear_bootstrap_secret() -> None:
    path = bootstrap_secret_path()
    try:
        if path.is_file():
            path.unlink()
    except Exception:
        pass


async def bootstrap_admin() -> None:
    try:
        ensure_auth_keys()
    except Exception as e:
        print(f"[startup] 认证密钥生成失败：{e}")
        raise
    user = (getattr(settings, "admin_user", None) or "admin").strip() or "admin"
    password = (getattr(settings, "admin_password", None) or "").strip()
    reset = bool(getattr(settings, "admin_password_reset", False))
    existing = await get_user(user) or await any_user()
    if existing and not reset:
        return
    if not password:
        password = "admin"
        if existing and reset:
            print("[startup] ATKBRAIN_ADMIN_PASSWORD_RESET 已开但没有新口令，跳过")
            return
    hashed = hash_password(password)
    await upsert_admin(user, hashed)
    write_bootstrap_secret(password)
    print(f"[startup] 管理员已写入（用户 {user}；哈希进库，明文仅本机 0600）")
