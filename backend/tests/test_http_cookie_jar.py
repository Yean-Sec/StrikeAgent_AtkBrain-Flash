"""HTTP 工具 cookie 持久化回归：登录态必须跨 http_request 调用保持。

锁定修复：此前 http() 每次现开现关客户端、不保存 cookie，导致「登录成功→下一请求丢
session→被重定向回登录页」的死循环（a-05 现象）。现在用持久会话保持 cookie，登录后
访问受保护页应成功。
"""
import asyncio
import http.server
import socketserver
import threading
import unittest

from atkbrain.agents.context import AgentContext
from atkbrain.exec.guard import Guard
from atkbrain.scope import Scope


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # 静音
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        if self.path.startswith("/secret"):
            if "sid=ok" in cookie:
                self.send_response(200); self.end_headers(); self.wfile.write(b"SECRET_OK")
            else:
                self.send_response(302); self.send_header("Location", "/login"); self.end_headers()
        elif self.path.startswith("/login"):
            self.send_response(200); self.send_header("Set-Cookie", "sid=ok; Path=/"); self.end_headers()
            self.wfile.write(b"login")
        else:
            self.send_response(200); self.end_headers(); self.wfile.write(b"root")

    def do_POST(self):
        self.send_response(302); self.send_header("Set-Cookie", "sid=ok; Path=/")
        self.send_header("Location", "/secret"); self.end_headers()


class HttpCookieJarTest(unittest.TestCase):
    def setUp(self) -> None:
        self.srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self) -> None:
        self.srv.shutdown()

    def _ctx(self) -> AgentContext:
        scope = Scope(targets=["127.0.0.1"], mode="strict")
        return AgentContext(
            project_id="t", workspace_dir="/tmp", loot_dir="/tmp",
            scope=scope, guard=Guard(scope, ""),
        )

    def test_session_persists_across_requests(self):
        base = f"http://127.0.0.1:{self.port}"
        ctx = self._ctx()

        async def run():
            pre = await ctx.http(base + "/secret")
            self.assertNotIn("SECRET_OK", pre.get("body") or "")  # 未登录被弹回
            await ctx.http(base + "/login", method="POST", data="u=a&p=b")
            self.assertIn("sid", ctx._cookies)                    # cookie 已入池
            post = await ctx.http(base + "/secret")
            return post

        post = asyncio.run(run())
        self.assertEqual(post.get("status"), 200)
        self.assertIn("SECRET_OK", post.get("body") or "")


if __name__ == "__main__":
    unittest.main()
