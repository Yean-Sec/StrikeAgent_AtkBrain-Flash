"""Pi 扩展拉工具表时，项目还没登记也要能列出工具。"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ..config import settings
from .agent_tools import ensure_project_tools, list_agent_tools, unregister_project_tools


class AgentToolsRegisterTests(unittest.IsolatedAsyncioTestCase):
    def tearDown(self) -> None:
        unregister_project_tools("p_tools_missing")
        unregister_project_tools("p_tools_reg")

    async def test_missing_project_stays_unregistered(self) -> None:
        with patch("atkbrain_native.get_project", return_value=None):
            self.assertFalse(ensure_project_tools("p_tools_missing"))
            res = await list_agent_tools("p_tools_missing")
        self.assertEqual(res.status_code, 404)

    async def test_existing_project_lists_tools(self) -> None:
        project = {
            "id": "p_tools_reg",
            "target": "example.com",
            "ports": [80],
            "scope": {
                "targets": ["example.com"],
                "ips": [],
                "allow_subdomains": False,
                "mode": "strict",
            },
            "config": {"objective": "agent", "track": "agent"},
        }
        saved = settings.workspaces_dir
        try:
            with tempfile.TemporaryDirectory() as tmp:
                settings.workspaces_dir = Path(tmp)
                with patch("atkbrain_native.get_project", return_value=project):
                    res = await list_agent_tools("p_tools_reg")
        finally:
            settings.workspaces_dir = saved
        self.assertIsInstance(res, dict)
        names = [t["name"] for t in res["tools"]]
        self.assertIn("run_cmd", names)
        self.assertIn("http_request", names)
        self.assertNotIn("report_flag", names)


if __name__ == "__main__":
    unittest.main()
