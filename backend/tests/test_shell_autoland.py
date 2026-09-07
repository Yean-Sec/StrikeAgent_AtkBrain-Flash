"""远程 id 回显自动落立足点：行首 uid=+gid=，排除本机身份。"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from atkbrain.agents.tools import live_exec_user


class LiveExecUserTests(unittest.TestCase):
    def test_www_data_id_line_counts(self):
        blob = (
            "exit_code=0  0.32s\n"
            "----- STDOUT -----\n"
            "== cmd: id; uname -a\n"
            "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
            "Linux box 6.6.0 #1 SMP x86_64 GNU/Linux\n"
        )
        with patch("atkbrain.agents.tools._local_unix_identity", return_value=("0", "root")):
            self.assertEqual(live_exec_user(blob), "www-data")

    def test_local_id_is_ignored(self):
        uid = str(os.getuid())
        blob = f"uid={uid}(root) gid={uid}(root) groups={uid}(root)\n"
        with patch("atkbrain.agents.tools._local_unix_identity", return_value=(uid, "root")):
            self.assertIsNone(live_exec_user(blob))

    def test_uid_inside_access_log_line_is_ignored(self):
        blob = (
            '10.254.0.19 - - [05/Sep/2026:07:42:54] '
            '"GET /index.php HTTP/1.1" 200 120 '
            '"[[[uid=33(www-data) gid=33(www-data) groups=33(www-data)]]]"\n'
        )
        with patch("atkbrain.agents.tools._local_unix_identity", return_value=("0", "root")):
            self.assertIsNone(live_exec_user(blob))

    def test_passwd_file_is_not_id(self):
        blob = "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        with patch("atkbrain.agents.tools._local_unix_identity", return_value=("0", "root")):
            self.assertIsNone(live_exec_user(blob))


if __name__ == "__main__":
    unittest.main()
