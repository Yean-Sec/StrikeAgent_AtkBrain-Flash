"""RSA 往返、锁定期、错误密文、无登录票拒登、转发头 Cookie Secure、未登录不能换 TOTP。"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from starlette.requests import Request

from .bootstrap import env_truthy
from .cookies import cookie_kwargs, cookie_secure, remaining_cookie_max_age, session_ttl_sec, DEFAULT_SESSION_TTL_SEC
from atkbrain_native import auth_key_path, auth_use_dir, decrypt_password_blob, encrypt_password_blob
from .routes import LoginBody, auth_login, totp_setup
from . import rate


def http_request(
    *,
    scheme: str = "http",
    headers: list[tuple[str, str]] | None = None,
    path: str = "/",
    client: str = "127.0.0.1",
    query: str = "",
) -> Request:
    hdrs = []
    for k, v in headers or []:
        hdrs.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    qs = query.encode("latin-1") if query else b""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": scheme,
        "path": path,
        "raw_path": path.encode(),
        "query_string": qs,
        "headers": hdrs,
        "client": (client, 9),
        "server": ("test", 80),
    }
    return Request(scope)


class CryptoRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.td = tempfile.TemporaryDirectory()
        auth_use_dir(self.td.name)

    def tearDown(self) -> None:
        auth_use_dir("")
        self.td.cleanup()

    def test_roundtrip(self) -> None:
        blob = encrypt_password_blob("s3cret!", "c_abc123def456")
        out = decrypt_password_blob(blob)
        self.assertEqual(out["p"], "s3cret!")
        self.assertEqual(out["c"], "c_abc123def456")
        self.assertEqual(os.stat(auth_key_path()).st_mode & 0o777, 0o600)

    def test_bad_cipher(self) -> None:
        with self.assertRaises(Exception):
            decrypt_password_blob("not-valid-base64-$$$")

    def test_stale_blob(self) -> None:
        blob = encrypt_password_blob("s3cret!", "c_abc123def456", ts=time.time() - 400)
        with self.assertRaises(ValueError):
            decrypt_password_blob(blob)


class CookieSecureTests(unittest.TestCase):
    def test_https_scheme(self) -> None:
        req = http_request(scheme="https")
        self.assertTrue(cookie_secure(req))
        self.assertTrue(cookie_kwargs(req)["secure"])
        self.assertEqual(cookie_kwargs(req)["samesite"], "lax")
        self.assertTrue(cookie_kwargs(req)["httponly"])

    def test_forwarded_proto(self) -> None:
        req = http_request(scheme="http", headers=[("x-forwarded-proto", "https, http")])
        self.assertTrue(cookie_secure(req))

    def test_plain_http(self) -> None:
        req = http_request(scheme="http")
        self.assertFalse(cookie_secure(req))

    def test_default_ttl_is_one_day(self) -> None:
        self.assertEqual(DEFAULT_SESSION_TTL_SEC, 24 * 3600)
        self.assertGreaterEqual(session_ttl_sec(), 1)

    def test_remaining_cookie_max_age(self) -> None:
        self.assertEqual(remaining_cookie_max_age(time.time() - 10), 0)
        left = remaining_cookie_max_age(time.time() + 90)
        self.assertTrue(80 <= left <= 90)
        req = http_request(scheme="http")
        kw = cookie_kwargs(req, max_age=left)
        self.assertEqual(kw["max_age"], left)
        self.assertLess(kw["max_age"], DEFAULT_SESSION_TTL_SEC)


class SessionTtlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from ..db import db

        self.db = db
        self.td = tempfile.TemporaryDirectory()
        self.old_path = db.path
        self.old_conn = db._conn
        db._conn = None
        db.path = os.path.join(self.td.name, "auth-test.db")
        await db.connect()

    async def asyncTearDown(self) -> None:
        await self.db.close()
        self.db.path = self.old_path
        self.db._conn = self.old_conn
        self.td.cleanup()

    async def test_touch_does_not_slide_expiry(self) -> None:
        from atkbrain_native import new_session_token
        from .store import create_session, get_session, touch_session

        token = new_session_token()
        await create_session("u_test", token, 3600)
        row = await get_session(token)
        self.assertIsNotNone(row)
        exp = float(row["expires_at"])
        await asyncio.sleep(0.05)
        await touch_session(row["id"], 99_999)
        row2 = await get_session(token)
        self.assertEqual(float(row2["expires_at"]), exp)
        self.assertGreaterEqual(float(row2["last_seen"]), float(row["last_seen"]))


class EnvFlagTests(unittest.TestCase):
    def test_empty_is_not_off(self) -> None:
        self.assertFalse(env_truthy(""))
        self.assertFalse(env_truthy("0"))
        self.assertTrue(env_truthy("1"))
        self.assertTrue(env_truthy("YES"))


class ForceHttpsTests(unittest.TestCase):
    def setUp(self) -> None:
        from ..config import settings

        self.settings = settings
        self.old_force = bool(settings.force_https)
        self.old_origin = str(getattr(settings, "public_origin", "") or "")

    def tearDown(self) -> None:
        self.settings.force_https = self.old_force
        self.settings.public_origin = self.old_origin

    def test_off_does_not_redirect(self) -> None:
        from .https_redirect import https_redirect_target

        self.settings.force_https = False
        self.settings.public_origin = "https://atkbrain.example.com"
        req = http_request(client="203.0.113.1", path="/AbCdef12/login")
        self.assertIsNone(https_redirect_target(req))

    def test_loopback_skips(self) -> None:
        from .https_redirect import https_redirect_target

        self.settings.force_https = True
        self.settings.public_origin = "https://atkbrain.example.com"
        req = http_request(client="127.0.0.1", path="/")
        self.assertIsNone(https_redirect_target(req))

    def test_wan_http_redirects_to_public_origin(self) -> None:
        from .https_redirect import https_redirect_target

        self.settings.force_https = True
        self.settings.public_origin = "https://atkbrain.example.com"
        req = http_request(client="203.0.113.1", path="/AbCdef12/login", query="x=1")
        self.assertEqual(
            https_redirect_target(req),
            "https://atkbrain.example.com/AbCdef12/login?x=1",
        )

    def test_wan_without_origin_uses_2334(self) -> None:
        from .https_redirect import https_redirect_target

        self.settings.force_https = True
        self.settings.public_origin = ""
        req = http_request(
            client="203.0.113.1",
            path="/AbCdef12/login",
            headers=[("host", "203.0.113.9:2333")],
        )
        self.assertEqual(
            https_redirect_target(req),
            "https://203.0.113.9:2334/AbCdef12/login",
        )

    def test_public_console_url_keeps_2334(self) -> None:
        from .entry import public_console_url

        self.settings.force_https = True
        self.settings.public_origin = ""
        with patch("atkbrain.auth.entry.entry_prefix", return_value="/AbCdef12"), \
             patch("atkbrain.auth.entry.guess_lan_ip", return_value="10.0.0.8"):
            self.assertEqual(
                public_console_url(),
                "https://10.0.0.8:2334/AbCdef12/login",
            )

    def test_forwarded_proto_https_skips(self) -> None:
        from .https_redirect import https_redirect_target

        self.settings.force_https = True
        self.settings.public_origin = "https://atkbrain.example.com"
        req = http_request(
            scheme="http",
            client="203.0.113.1",
            headers=[("x-forwarded-proto", "https")],
        )
        self.assertIsNone(https_redirect_target(req))

    def test_public_console_url_uses_origin(self) -> None:
        from .entry import public_console_url

        self.settings.force_https = True
        self.settings.public_origin = "https://atkbrain.example.com"
        with patch("atkbrain.auth.entry.entry_prefix", return_value="/AbCdef12"):
            self.assertEqual(
                public_console_url(),
                "https://atkbrain.example.com/AbCdef12/login",
            )


class LockoutTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from ..db import db

        self.db = db
        self.td = tempfile.TemporaryDirectory()
        self.old_path = db.path
        self.old_conn = db._conn
        db._conn = None
        db.path = os.path.join(self.td.name, "auth-test.db")
        await db.connect()

    async def asyncTearDown(self) -> None:
        await self.db.close()
        self.db.path = self.old_path
        self.db._conn = self.old_conn
        self.td.cleanup()

    async def test_user_lock_after_five(self) -> None:
        until = 0.0
        for _ in range(rate.FAIL_LIMIT_USER):
            until = await rate.record_login_fail("9.9.9.9", "Admin")
        self.assertGreater(until, time.time())
        locked = await rate.assert_not_locked("user:admin")
        self.assertGreater(locked, time.time())


class LoginGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_ticket_rejected(self) -> None:
        with patch("atkbrain.auth.routes.assert_not_locked", AsyncMock(return_value=0)), \
             patch("atkbrain.auth.routes.take_challenge", AsyncMock(return_value=None)), \
             patch("atkbrain.auth.routes.record_login_fail", AsyncMock()) as login_fail, \
             patch("atkbrain.auth.routes.client_ip", return_value="1.2.3.4"):
            resp = await auth_login(http_request(), LoginBody(username="admin"))
        self.assertEqual(resp.status_code, 401)
        login_fail.assert_awaited()

    async def test_totp_setup_requires_login(self) -> None:
        with patch("atkbrain.auth.routes.auth_ok", AsyncMock(return_value=False)):
            resp = await totp_setup(http_request(path="/api/auth/totp/setup"))
        self.assertEqual(resp.status_code, 401)

    async def test_totp_setup_rejects_rebind(self) -> None:
        sess = {"user": {"id": "u1", "username": "admin", "totp_enabled": 1, "totp_secret": "x"}}
        with patch("atkbrain.auth.routes.auth_ok", AsyncMock(return_value=True)), \
             patch("atkbrain.auth.routes.session_from_request", AsyncMock(return_value=sess)):
            resp = await totp_setup(http_request(path="/api/auth/totp/setup"))
        self.assertEqual(resp.status_code, 409)


if __name__ == "__main__":
    unittest.main()
