"""口令策略与一次性首登轮换。"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atkbrain_native import generate_bootstrap_password, password_policy_code


class PolicyTests(unittest.TestCase):
    def test_rejects(self):
        self.assertEqual(password_policy_code("short"), "len")
        self.assertEqual(password_policy_code("alllower1"), "upper")
        self.assertEqual(password_policy_code("ALLUPPER1"), "lower")
        self.assertEqual(password_policy_code("NoDigitsX"), "digit")
        self.assertIsNone(password_policy_code("GoodPass1"))

    def test_bootstrap_charset(self):
        pw = generate_bootstrap_password(8)
        self.assertEqual(len(pw), 8)
        self.assertTrue(any(c.isupper() for c in pw))
        self.assertTrue(any(c.islower() for c in pw))
        self.assertFalse(any(c.isdigit() for c in pw))


class BootstrapOnceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from ..db import db
        from atkbrain_native import auth_use_dir

        self.db = db
        self._auth_use_dir = auth_use_dir
        self.td = tempfile.TemporaryDirectory()
        self.old_path = db.path
        self.old_conn = db._conn
        db._conn = None
        db.path = os.path.join(self.td.name, "auth-test.db")
        await db.connect()
        self._auth_use_dir(self.td.name)

    async def asyncTearDown(self):
        self._auth_use_dir("")
        await self.db.close()
        self.db.path = self.old_path
        self.db._conn = self.old_conn
        self.td.cleanup()

    async def test_consume_once(self):
        from atkbrain_native import hash_password
        from .store import consume_bootstrap_login, upsert_admin, user_by_id

        u = await upsert_admin("admin", hash_password("admin"))
        first = await consume_bootstrap_login(u["id"], hash_password("AaBbCcDd"))
        second = await consume_bootstrap_login(u["id"], hash_password("EeFfGgHh"))
        self.assertTrue(first)
        self.assertFalse(second)
        row = await user_by_id(u["id"])
        self.assertEqual(int(row["bootstrap_login_done"]), 1)
        self.assertEqual(int(row["must_change_password"]), 1)


class AdminSecretFileTests(unittest.TestCase):
    def test_write_read_mode_600(self):
        from . import bootstrap

        td = tempfile.TemporaryDirectory()
        try:
            p = Path(td.name) / "admin_bootstrap.secret"
            with patch.object(bootstrap, "bootstrap_secret_path", lambda: p):
                bootstrap.write_bootstrap_secret("GoodPass1")
                self.assertEqual(bootstrap.read_bootstrap_secret(), "GoodPass1")
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
