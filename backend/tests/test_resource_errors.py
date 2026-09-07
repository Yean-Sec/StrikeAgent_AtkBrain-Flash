"""本机 FD/SQLite 资源抖动不得把子项目钉死成 error。"""
from __future__ import annotations

import unittest

from atkbrain.engine.loop import is_transient_resource_error


class TransientResourceErrorTests(unittest.TestCase):
    def test_sqlite_cantopen(self):
        self.assertTrue(is_transient_resource_error(Exception("unable to open database file")))

    def test_emfile_errno(self):
        self.assertTrue(is_transient_resource_error(OSError(24, "Too many open files")))

    def test_enfile_errno(self):
        self.assertTrue(is_transient_resource_error(OSError(23, "Too many open files in system")))

    def test_locked_db(self):
        self.assertTrue(is_transient_resource_error(Exception("database is locked")))

    def test_unrelated_stays_sticky(self):
        self.assertFalse(is_transient_resource_error(ValueError("目标不在作业对象内")))
        self.assertFalse(is_transient_resource_error(RuntimeError("loop exhausted")))


if __name__ == "__main__":
    unittest.main()
