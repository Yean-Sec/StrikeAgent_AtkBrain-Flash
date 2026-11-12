"""登录、公钥、会话、改密、可选 TOTP。绑定 TOTP 必须已登录。"""
from __future__ import annotations

import time

import pyotp
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import settings
from atkbrain_native import msg
from .bootstrap import (
    login_required,
    write_bootstrap_secret,
)
from .cookies import apply_session_cookie, clear_session_cookie
from atkbrain_native import (
    decrypt_password_blob,
    dummy_verify,
    hash_password,
    new_session_token,
    public_pem,
    verify_password,
)
from .gate import auth_ok, client_ip, origin_ok, session_from_request
from atkbrain_native import generate_bootstrap_password, password_policy_code
from .rate import assert_not_locked, clear_fails, record_login_fail
from .store import (
    consume_bootstrap_login,
    create_session,
    get_user,
    mark_bootstrap_login_done,
    peek_challenge,
    put_challenge,
    revoke_session,
    set_must_change,
    set_password_hash,
    set_totp_secret,
    take_challenge,
    user_by_id,
    user_flag,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

FAIL = "验证失败"
TICKET_TTL = 120


def _fail_detail() -> str:
    return msg("auth_fail")


class LoginBody(BaseModel):
    username: str = ""
    password_cipher: str = ""
    ticket: str = ""
    totp: str = ""
    pending_id: str = ""


class TotpConfirm(BaseModel):
    code: str = Field(default="", min_length=6, max_length=8)
    setup_id: str = ""


class PasswordBody(BaseModel):
    ticket: str = ""
    new_cipher: str = ""
    old_cipher: str = ""


def _retry_after(until: float) -> int:
    return max(1, int(until - time.time()))


def _locked(until: float) -> JSONResponse:
    return JSONResponse(
        {"detail": _fail_detail(), "retry_after": _retry_after(until)},
        status_code=429,
        headers={"Retry-After": str(_retry_after(until))},
    )


def _policy_fail(code: str) -> JSONResponse:
    texts = {
        "len": "口令至少 8 位",
        "upper": "口令须含大写字母",
        "lower": "口令须含小写字母",
        "digit": "口令须含数字",
    }
    return JSONResponse(
        {"detail": "password-policy", "code": code, "message": texts.get(code, "口令不符合要求")},
        status_code=400,
    )


@router.get("/me")
async def auth_me(request: Request):
    required = await login_required()
    sess = await session_from_request(request)
    user = (sess or {}).get("user") if sess else None
    totp_on = bool(user and int(user.get("totp_enabled") or 0))
    any_u = user
    if any_u is None:
        from .store import any_user
        any_u = await any_user()
    show_defaults = not user_flag(any_u, "bootstrap_login_done")
    return {
        "required": required,
        "authenticated": bool(user),
        "username": (user or {}).get("username") if user else None,
        "totp_enabled": totp_on,
        "must_change_password": user_flag(user, "must_change_password"),
        "show_default_creds": bool(show_defaults and required and not user),
        "default_username": (getattr(settings, "admin_user", None) or "admin") if show_defaults and not user else None,
    }


@router.get("/pubkey")
async def auth_pubkey():
    ticket = await put_challenge("login", "1", TICKET_TTL)
    return {"alg": "RSA-OAEP-SHA256", "pem": public_pem(), "ticket": ticket, "ttl": TICKET_TTL}


def _factory_password() -> str:
    return (getattr(settings, "admin_password", None) or "admin").strip() or "admin"


async def _maybe_rotate_bootstrap(user: dict, *, used_default: bool) -> dict:
    if user_flag(user, "bootstrap_login_done"):
        return user
    uid = str(user.get("id") or "")
    if not uid:
        return user
    if not used_default:
        await mark_bootstrap_login_done(uid)
        fresh = await user_by_id(uid)
        return fresh or user
    plain = generate_bootstrap_password(8)
    hashed = hash_password(plain)
    won = await consume_bootstrap_login(uid, hashed)
    if not won:
        fresh = await user_by_id(uid)
        return fresh or user
    write_bootstrap_secret(plain)
    fresh = await user_by_id(uid)
    return fresh or {**user, "must_change_password": 1, "bootstrap_login_done": 1}


async def _finish_login(request: Request, user: dict, *, used_default: bool = False) -> JSONResponse:
    user = await _maybe_rotate_bootstrap(user, used_default=used_default)
    token = new_session_token()
    from .cookies import session_ttl_sec
    max_age = float(session_ttl_sec())
    await create_session(str(user["id"]), token, max_age)
    body = {
        "ok": True,
        "username": user.get("username"),
        "totp_enabled": bool(int(user.get("totp_enabled") or 0)),
        "must_change_password": user_flag(user, "must_change_password"),
    }
    resp = JSONResponse(body)
    apply_session_cookie(resp, token, request)
    return resp


@router.post("/login")
async def auth_login(request: Request, body: LoginBody):
    if not origin_ok(request):
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    ip = client_ip(request)
    username = (body.username or "").strip()
    until = await assert_not_locked(f"ip:{ip}", f"user:{username.lower()}")
    if until:
        return _locked(until)

    if body.pending_id:
        pending = await take_challenge(body.pending_id, "pending")
        if not pending:
            await record_login_fail(ip, username)
            return JSONResponse({"detail": _fail_detail()}, status_code=401)
        extra = pending.get("extra") or {}
        user = await get_user(str(extra.get("username") or ""))
        if not user or not int(user.get("totp_enabled") or 0):
            await record_login_fail(ip, username)
            return JSONResponse({"detail": _fail_detail()}, status_code=401)
        secret = str(user.get("totp_secret") or "")
        if not secret or not pyotp.TOTP(secret).verify((body.totp or "").strip(), valid_window=1):
            await record_login_fail(ip, str(user.get("username") or ""))
            return JSONResponse({"detail": _fail_detail()}, status_code=401)
        await clear_fails(f"ip:{ip}", f"user:{(user.get('username') or '').lower()}")
        return await _finish_login(request, user, used_default=bool((pending.get("extra") or {}).get("bootstrap_rotate")))

    ticket = (body.ticket or "").strip()
    ch = await take_challenge(ticket, "login")
    if not ch:
        await record_login_fail(ip, username)
        return JSONResponse({"detail": _fail_detail()}, status_code=401)

    try:
        blob = decrypt_password_blob(body.password_cipher)
    except Exception:
        await record_login_fail(ip, username)
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    if str(blob.get("c") or "") != ticket:
        await record_login_fail(ip, username)
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    password = str(blob.get("p") or "")
    user = await get_user(username)
    if not user:
        dummy_verify(password)
        await record_login_fail(ip, username)
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    if not verify_password(password, str(user.get("password_hash") or "")):
        await record_login_fail(ip, username)
        return JSONResponse({"detail": _fail_detail()}, status_code=401)

    if int(user.get("totp_enabled") or 0) and (user.get("totp_secret") or ""):
        pending_id = await put_challenge(
            "pending", "1", 120,
            extra={
                "username": user.get("username"),
                "uid": user.get("id"),
                "bootstrap_rotate": password == _factory_password(),
            },
        )
        return {"ok": False, "need_totp": True, "pending_id": pending_id}

    await clear_fails(f"ip:{ip}", f"user:{username.lower()}")
    return await _finish_login(request, user, used_default=password == _factory_password())


@router.post("/logout")
async def auth_logout(request: Request):
    sess = await session_from_request(request)
    if sess:
        await revoke_session(str(sess.get("token") or ""))
    resp = JSONResponse({"ok": True})
    clear_session_cookie(resp, request)
    return resp


@router.post("/password")
async def auth_password(request: Request, body: PasswordBody):
    if not origin_ok(request):
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    if not await auth_ok(request):
        return JSONResponse({"detail": "login-required"}, status_code=401)
    sess = await session_from_request(request)
    if not sess:
        return JSONResponse({"detail": "login-required"}, status_code=401)
    user = sess["user"]
    ticket = (body.ticket or "").strip()
    ch = await take_challenge(ticket, "login")
    if not ch:
        return JSONResponse({"detail": _fail_detail()}, status_code=400)
    try:
        new_blob = decrypt_password_blob(body.new_cipher)
    except Exception:
        return JSONResponse({"detail": _fail_detail()}, status_code=400)
    if str(new_blob.get("c") or "") != ticket:
        return JSONResponse({"detail": _fail_detail()}, status_code=400)
    new_pw = str(new_blob.get("p") or "")
    code = password_policy_code(new_pw)
    if code:
        return _policy_fail(code)
    must_change = user_flag(user, "must_change_password")
    if not must_change:
        if not (body.old_cipher or "").strip():
            return JSONResponse({"detail": "need-old-password"}, status_code=400)
        try:
            old_blob = decrypt_password_blob(body.old_cipher)
        except Exception:
            return JSONResponse({"detail": _fail_detail()}, status_code=400)
        if str(old_blob.get("c") or "") != ticket:
            return JSONResponse({"detail": _fail_detail()}, status_code=400)
        if not verify_password(str(old_blob.get("p") or ""), str(user.get("password_hash") or "")):
            return JSONResponse({"detail": _fail_detail()}, status_code=401)
    hashed = hash_password(new_pw)
    await set_password_hash(str(user["id"]), hashed, must_change=False)
    await set_must_change(str(user["id"]), False)
    write_bootstrap_secret(new_pw)
    return {"ok": True, "must_change_password": False}


@router.get("/totp/setup")
async def totp_setup(request: Request):
    if not await auth_ok(request):
        return JSONResponse({"detail": "login-required"}, status_code=401)
    sess = await session_from_request(request)
    if not sess:
        return JSONResponse({"detail": "login-required"}, status_code=401)
    if user_flag(sess.get("user"), "must_change_password"):
        return JSONResponse({"detail": "password-change-required"}, status_code=403)
    user = sess["user"]
    if int(user.get("totp_enabled") or 0) and user.get("totp_secret"):
        return JSONResponse({"detail": "already-bound"}, status_code=409)
    secret = pyotp.random_base32()
    setup_id = await put_challenge("totp-setup", secret, 300, extra={"uid": user["id"]})
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=str(user.get("username") or "admin"),
        issuer_name="StrikeAgent",
    )
    return {"otpauth_url": uri, "secret": secret, "setup_id": setup_id}


@router.post("/totp/confirm")
async def totp_confirm(request: Request, body: TotpConfirm):
    if not await auth_ok(request):
        return JSONResponse({"detail": "login-required"}, status_code=401)
    sess = await session_from_request(request)
    if not sess:
        return JSONResponse({"detail": "login-required"}, status_code=401)
    if user_flag(sess.get("user"), "must_change_password"):
        return JSONResponse({"detail": "password-change-required"}, status_code=403)
    user = sess["user"]
    row = await peek_challenge(body.setup_id, "totp-setup")
    if not row:
        return JSONResponse({"detail": _fail_detail()}, status_code=400)
    extra = row.get("extra") or {}
    if str(extra.get("uid") or "") != str(user["id"]):
        return JSONResponse({"detail": _fail_detail()}, status_code=400)
    secret = str(row.get("secret") or "")
    if not pyotp.TOTP(secret).verify((body.code or "").strip(), valid_window=1):
        return JSONResponse({"detail": _fail_detail()}, status_code=401)
    await take_challenge(body.setup_id, "totp-setup")
    await set_totp_secret(str(user["id"]), secret, enabled=True)
    return {"ok": True, "totp_enabled": True}
