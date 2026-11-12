"""管理员、会话、挑战的 SQLite 读写。会话只存哈希。"""
from __future__ import annotations

import json
import time

from ..db import db, new_id, now
from atkbrain_native import token_hash


async def get_user(username: str) -> dict | None:
    name = (username or "").strip()
    if not name:
        return None
    return await db.fetchone("SELECT * FROM auth_users WHERE username=?", (name,))


async def any_user() -> dict | None:
    return await db.fetchone("SELECT * FROM auth_users ORDER BY created_at LIMIT 1")


async def upsert_admin(username: str, password_hash: str) -> dict:
    ts = now()
    existing = await get_user(username)
    if existing:
        await db.execute(
            "UPDATE auth_users SET password_hash=?, updated_at=? WHERE id=?",
            (password_hash, ts, existing["id"]),
        )
        row = await db.fetchone("SELECT * FROM auth_users WHERE id=?", (existing["id"],))
        return row or existing
    uid = new_id("u_")
    await db.execute(
        """INSERT INTO auth_users(id, username, password_hash, totp_secret, totp_enabled,
           must_change_password, bootstrap_login_done, created_at, updated_at)
           VALUES(?,?,?,?,0,0,0,?,?)""",
        (uid, username, password_hash, None, ts, ts),
    )
    row = await db.fetchone("SELECT * FROM auth_users WHERE id=?", (uid,))
    return row or {"id": uid, "username": username}


async def set_totp_secret(user_id: str, secret: str | None, *, enabled: bool) -> None:
    await db.execute(
        "UPDATE auth_users SET totp_secret=?, totp_enabled=?, updated_at=? WHERE id=?",
        (secret, 1 if enabled else 0, now(), user_id),
    )


async def put_challenge(kind: str, secret: str, ttl: float, extra: dict | None = None) -> str:
    cid = new_id("c_")
    await db.execute(
        """INSERT INTO auth_challenges(id, kind, secret, expires_at, consumed, extra, created_at)
           VALUES(?,?,?,?,0,?,?)""",
        (cid, kind, secret, time.time() + ttl, json.dumps(extra or {}, ensure_ascii=False), now()),
    )
    return cid


async def peek_challenge(cid: str, kind: str) -> dict | None:
    row = await db.fetchone("SELECT * FROM auth_challenges WHERE id=? AND kind=?", (cid, kind))
    if not row:
        return None
    if int(row.get("consumed") or 0):
        return None
    if float(row.get("expires_at") or 0) < time.time():
        return None
    extra = row.get("extra")
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except Exception:
            extra = {}
    row["extra"] = extra if isinstance(extra, dict) else {}
    return row


async def take_challenge(cid: str, kind: str) -> dict | None:
    row = await peek_challenge(cid, kind)
    if not row:
        return None
    await db.execute("UPDATE auth_challenges SET consumed=1 WHERE id=?", (cid,))
    return row


async def create_session(user_id: str, token: str, max_age: float) -> None:
    sid = new_id("s_")
    ts = now()
    await db.execute(
        """INSERT INTO auth_sessions(id, token_hash, user_id, expires_at, created_at, last_seen)
           VALUES(?,?,?,?,?,?)""",
        (sid, token_hash(token), user_id, ts + max_age, ts, ts),
    )


async def get_session(token: str) -> dict | None:
    if not token:
        return None
    row = await db.fetchone(
        "SELECT * FROM auth_sessions WHERE token_hash=?",
        (token_hash(token),),
    )
    if not row:
        return None
    if float(row.get("expires_at") or 0) < time.time():
        await db.execute("DELETE FROM auth_sessions WHERE id=?", (row["id"],))
        return None
    return row


async def touch_session(session_id: str, max_age: float | None = None) -> None:
    """只刷新 last_seen。expires_at 在登录时写死，不滑动续期。"""
    del max_age
    ts = now()
    await db.execute(
        "UPDATE auth_sessions SET last_seen=? WHERE id=?",
        (ts, session_id),
    )


async def revoke_session(token: str) -> None:
    if not token:
        return
    await db.execute("DELETE FROM auth_sessions WHERE token_hash=?", (token_hash(token),))


async def user_by_id(user_id: str) -> dict | None:
    return await db.fetchone("SELECT * FROM auth_users WHERE id=?", (user_id,))


def user_flag(user: dict | None, name: str) -> bool:
    if not user:
        return False
    try:
        return int(user.get(name) or 0) != 0
    except (TypeError, ValueError):
        return False


async def set_password_hash(user_id: str, password_hash: str, *, must_change: bool | None = None) -> None:
    ts = now()
    if must_change is None:
        await db.execute(
            "UPDATE auth_users SET password_hash=?, updated_at=? WHERE id=?",
            (password_hash, ts, user_id),
        )
        return
    await db.execute(
        "UPDATE auth_users SET password_hash=?, must_change_password=?, updated_at=? WHERE id=?",
        (password_hash, 1 if must_change else 0, ts, user_id),
    )


async def set_must_change(user_id: str, value: bool) -> None:
    await db.execute(
        "UPDATE auth_users SET must_change_password=?, updated_at=? WHERE id=?",
        (1 if value else 0, now(), user_id),
    )


async def consume_bootstrap_login(user_id: str, password_hash: str) -> bool:
    """第一次成功登录抢锁。已消费则返回 False，避免重复轮换口令。"""
    ts = now()
    async with db._lock:
        cur = await db.conn.execute(
            """UPDATE auth_users
               SET password_hash=?, must_change_password=1, bootstrap_login_done=1, updated_at=?
               WHERE id=? AND IFNULL(bootstrap_login_done,0)=0""",
            (password_hash, ts, user_id),
        )
        await db.conn.commit()
        return int(cur.rowcount or 0) > 0


async def mark_bootstrap_login_done(user_id: str) -> None:
    """已用非默认口令登录：只记已消费，不改哈希、不强制改密。"""
    await db.execute(
        """UPDATE auth_users SET bootstrap_login_done=1, updated_at=?
           WHERE id=? AND IFNULL(bootstrap_login_done,0)=0""",
        (now(), user_id),
    )
