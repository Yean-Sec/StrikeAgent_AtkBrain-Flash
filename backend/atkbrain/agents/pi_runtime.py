"""Pi RPC 运行时：拉起 `pi --mode rpc`，用 LF JSONL 对话。

从者 / 角色工人带图工具扩展。
无工具一次性会话按 role 分开，互不复用进程：
御主 supervisor、自进化 evolve、漏洞页 finding-page、交付报告 report-export。
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from ..config import REPO_ROOT, settings

_LIVE: dict[int, str] = {}

# 猎面留下内置 read 给 Pi 加载 SKILL.md；其余官方内置工具一律排除。
EXCLUDE_BUILTIN_TOOLS = "bash,powershell,edit,write,grep,find,ls"

EmitFn = Callable[..., Awaitable[None]]


def live_pi_count() -> int:
    dead = [pid for pid in _LIVE if not _pid_alive(pid)]
    for pid in dead:
        _LIVE.pop(pid, None)
    return len(_LIVE)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def extension_path() -> Path:
    p = REPO_ROOT / "pi" / "extensions" / "atkbrain-tools.ts"
    if p.is_file():
        return p
    return Path(__file__).resolve().parents[3] / "pi" / "extensions" / "atkbrain-tools.ts"


def tools_base_url() -> str:
    port = int(getattr(settings, "port", 5003) or 5003)
    return f"http://127.0.0.1:{port}"


def pi_bin() -> str:
    return (
        (getattr(settings, "pi_bin", None) or "").strip()
        or os.environ.get("ATKBRAIN_PI_BIN")
        or "pi"
    )


def pi_model() -> str:
    return (
        (getattr(settings, "pi_model", None) or "").strip()
        or (getattr(settings, "claude_model", None) or "").strip()
        or "deepseek-flash"
    )


def pi_provider() -> str:
    return (getattr(settings, "pi_provider", None) or "deepseek").strip() or "deepseek"


def ensure_pi_agent_dir(*, hosted: bool | None = None) -> Path:
    """保证 ~/.pi/agent 有 models.json / settings.json。托管时改写网关 baseUrl。"""
    from ..llm_gateway import GATEWAY_SUFFIX, hosted_enabled, rewrite_llm_url_for_gateway

    home = Path(os.environ.get("HOME") or "/root")
    agent = home / ".pi" / "agent"
    agent.mkdir(parents=True, exist_ok=True)
    settings_path = agent / "settings.json"
    if not settings_path.is_file():
        settings_path.write_text(
            json.dumps(
                {
                    "enableInstallTelemetry": False,
                    "defaultProjectTrust": "always",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("enableInstallTelemetry", False)
        data["defaultProjectTrust"] = "always"
        settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    use_gw = hosted if hosted is not None else hosted_enabled()
    base = "https://api.deepseek.com"
    if use_gw:
        base = rewrite_llm_url_for_gateway("https://api.deepseek.com")
        if GATEWAY_SUFFIX not in base:
            base = "http://api.deepseek.com.tsecbench.gw"
    models = {
        "providers": {
            "deepseek": {
                "baseUrl": base,
                "api": "openai-completions",
                "apiKey": "$DEEPSEEK_API_KEY",
                "models": [
                    {
                        "id": "deepseek-flash",
                        "name": "deepseek-flash",
                        "contextWindow": 1000000,
                        "maxTokens": 384000,
                        "input": ["text"],
                        "reasoning": True,
                        "thinkingLevelMap": {
                            "minimal": None, "low": None, "medium": None,
                            "high": "high", "xhigh": "max",
                        },
                        "cost": {
                            "input": 0.14, "output": 0.28,
                            "cacheRead": 0.028, "cacheWrite": 0,
                        },
                        "compat": {
                            "requiresReasoningContentOnAssistantMessages": True,
                            "thinkingFormat": "deepseek",
                            "reasoningEffortMap": {
                                "minimal": "high", "low": "high", "medium": "high",
                                "high": "high", "xhigh": "max",
                            },
                        },
                    }
                ],
            }
        }
    }
    models_path = agent / "models.json"
    if use_gw or not models_path.is_file():
        models_path.write_text(json.dumps(models, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return agent


def _child_env(*, project_id: str | None, tools: bool) -> dict[str, str]:
    env = dict(os.environ)
    key = (env.get("DEEPSEEK_API_KEY") or env.get("ANTHROPIC_AUTH_TOKEN") or "").strip()
    if key:
        env["DEEPSEEK_API_KEY"] = key
        env.setdefault("ANTHROPIC_AUTH_TOKEN", key)
    env["PI_TELEMETRY"] = "0"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_OFFLINE"] = "1"
    env.setdefault("PI_CODING_AGENT_DIR", str(Path(env.get("HOME") or "/root") / ".pi" / "agent"))
    if project_id:
        env["ATKBRAIN_PROJECT_ID"] = project_id
        env["ATKBRAIN_TOOLS_BASE"] = tools_base_url()
        env["ATKBRAIN_API"] = tools_base_url()
    token = (getattr(settings, "api_token", None) or "").strip()
    if token:
        env["ATKBRAIN_API_TOKEN"] = token
    return env


class PiSession:
    """一条 Pi RPC 进程。每轮猎面新建，不续对话。"""

    def __init__(
        self,
        *,
        cwd: str,
        system_prompt: str,
        project_id: str = "",
        role: str = "lead",
        tools: bool = True,
        emit: EmitFn | None = None,
        run_id: str | None = None,
        on_activity: Callable[[], None] | None = None,
        model: str = "",
        skill_paths: list[str] | None = None,
    ) -> None:
        self.cwd = cwd
        self.system_prompt = system_prompt or ""
        self.project_id = project_id
        self.role = role
        self.tools = tools
        self.model = (model or "").strip()
        self.skill_paths = [
            str(Path(p).expanduser())
            for p in (skill_paths or [])
            if str(p).strip()
        ]
        self._emit = emit
        self.run_id = run_id
        self.on_activity = on_activity
        self.proc: asyncio.subprocess.Process | None = None
        self._req = 0
        self._closed = False
        self.texts: list[str] = []
        self.tool_uses = 0
        self._reader_task: asyncio.Task | None = None
        self._settled = asyncio.Event()
        self._prompt_ok: asyncio.Future | None = None
        self._buf = b""
        self._prompt_file = ""
        self._text_acc: list[str] = []
        self._thought_acc: list[str] = []
        self._last_text = ""
        self._last_thought = ""

    def _cmd(self) -> list[str]:
        os.makedirs(self.cwd, exist_ok=True)
        prompt_path = os.path.join(self.cwd, f".pi-system-{self.role}.txt")
        Path(prompt_path).write_text(self.system_prompt, encoding="utf-8")
        self._prompt_file = prompt_path
        cmd = [
            pi_bin(),
            "--mode", "rpc",
            "--no-session",
            "--offline",
            "-a",
            "--provider", pi_provider(),
            "--model", self.model or pi_model(),
            "--system-prompt", "StrikeAgent_AtkBrain-Flash",
            "--append-system-prompt", prompt_path,
        ]
        if self.tools:
            ext = extension_path()
            cmd.extend([
                "--no-context-files",
                "--no-extensions", "-e", str(ext),
                "--no-skills",
                "--exclude-tools", EXCLUDE_BUILTIN_TOOLS,
            ])
            for raw in self.skill_paths:
                p = Path(raw)
                if not p.is_absolute():
                    p = Path(self.cwd) / p
                if p.is_file() or p.is_dir():
                    cmd.extend(["--skill", str(p.resolve())])
        else:
            cmd.extend([
                "--no-tools", "--no-builtin-tools", "--no-extensions",
                "--no-skills", "--no-context-files",
            ])
        return cmd

    async def start(self) -> None:
        ensure_pi_agent_dir()
        cmd = self._cmd()
        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.cwd,
            env=_child_env(project_id=self.project_id or None, tools=self.tools),
            start_new_session=True,
        )
        if self.proc.pid:
            _LIVE[self.proc.pid] = self.project_id or self.role
        self._reader_task = asyncio.create_task(self._read_loop())
        asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        if not self.proc or not self.proc.stderr:
            return
        err_path = os.path.join(self.cwd, "logs")
        try:
            os.makedirs(err_path, exist_ok=True)
            f = open(os.path.join(err_path, f"pi-{self.role}.err.log"), "ab")
        except OSError:
            f = None
        try:
            while True:
                chunk = await self.proc.stderr.read(4096)
                if not chunk:
                    break
                if f:
                    f.write(chunk)
                    f.flush()
        finally:
            if f:
                f.close()

    async def _read_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while True:
                chunk = await self.proc.stdout.read(65536)
                if not chunk:
                    break
                self._buf += chunk
                while True:
                    i = self._buf.find(b"\n")
                    if i < 0:
                        break
                    raw = self._buf[:i]
                    self._buf = self._buf[i + 1:]
                    if raw.endswith(b"\r"):
                        raw = raw[:-1]
                    if not raw.strip():
                        continue
                    try:
                        event = json.loads(raw.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    if isinstance(event, dict):
                        await self._on_event(event)
        finally:
            self._settled.set()
            if self._prompt_ok and not self._prompt_ok.done():
                self._prompt_ok.set_result(False)

    async def _on_event(self, event: dict) -> None:
        typ = str(event.get("type") or "")
        if typ == "response":
            fut = self._prompt_ok
            if fut and not fut.done() and str(event.get("command") or "") == "prompt":
                fut.set_result(bool(event.get("success")))
            return
        if self.on_activity:
            try:
                self.on_activity()
            except Exception:
                pass
        if typ in ("agent_settled", "message_end"):
            await self._flush_streams()
            if typ == "agent_settled":
                self._settled.set()
            return
        if typ == "agent_end" and not event.get("willRetry"):
            # 仍可能 compaction；以 settled 为准，这里只收文本兜底
            return
        if typ == "message_update":
            ev = event.get("assistantMessageEvent") or {}
            et = str(ev.get("type") or "")
            if et == "text_delta":
                d = str(ev.get("delta") or "")
                if d:
                    self.texts.append(d)
                    self._text_acc.append(d)
            elif et == "text_end":
                content = str(ev.get("content") or "")
                await self._flush_text(content)
            elif et == "thinking_delta":
                d = str(ev.get("delta") or "")
                if d:
                    self._thought_acc.append(d)
            elif et == "thinking_end":
                content = str(ev.get("content") or "")
                await self._flush_thought(content)
            elif et == "toolcall_start":
                await self._flush_streams()
                name = str(ev.get("toolName") or "")
                if name and name.lower() not in _GRAPH_TOOLS:
                    self.tool_uses += 1
                    await self._emit_safe("tool", {"tool": name, "role": self.role})
            return
        if typ == "tool_execution_start":
            name = str(event.get("toolName") or event.get("name") or "")
            if name.lower() in _GRAPH_TOOLS:
                self.tool_uses += 1
            return
        if typ == "compaction_start":
            await self._emit_safe(
                "log",
                {"level": "info", "message": "Pi 上下文接近上限，正在自动压缩。"},
            )

    async def _flush_text(self, content: str = "") -> None:
        text = (content or "".join(self._text_acc)).strip()
        self._text_acc = []
        if text and text != self._last_text:
            self._last_text = text
            await self._emit_safe("text", {"text": text[:8000], "role": self.role})

    async def _flush_thought(self, content: str = "") -> None:
        text = (content or "".join(self._thought_acc)).strip()
        self._thought_acc = []
        if text and text != self._last_thought:
            self._last_thought = text
            await self._emit_safe(
                "thought",
                {"message": text[:8000], "kind": "reasoning", "role": self.role},
            )

    async def _flush_streams(self) -> None:
        await self._flush_thought()
        await self._flush_text()

    async def _emit_safe(self, kind: str, payload: dict) -> None:
        if not self._emit or not self.project_id:
            return
        try:
            await self._emit(self.project_id, kind, payload, run_id=self.run_id)
        except TypeError:
            try:
                await self._emit(self.project_id, kind, payload)
            except Exception:
                pass
        except Exception:
            pass

    async def _send(self, obj: dict) -> None:
        if not self.proc or not self.proc.stdin or self.proc.stdin.is_closing():
            raise RuntimeError("pi rpc stdin closed")
        self.proc.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        await self.proc.stdin.drain()

    async def prompt(self, message: str, *, timeout: float = 0) -> str:
        self.texts = []
        self._text_acc = []
        self._thought_acc = []
        self._last_text = ""
        self._last_thought = ""
        self._settled = asyncio.Event()
        loop = asyncio.get_running_loop()
        self._prompt_ok = loop.create_future()
        self._req += 1
        await self._send({"id": f"p{self._req}", "type": "prompt", "message": message})
        try:
            await asyncio.wait_for(self._prompt_ok, timeout=30)
        except Exception:
            pass
        wait = float(timeout or 0)
        try:
            if wait > 0:
                await asyncio.wait_for(self._settled.wait(), timeout=wait)
            else:
                await self._settled.wait()
        except TimeoutError:
            await self.abort()
            raise
        return "".join(self.texts).strip()

    async def abort(self) -> None:
        try:
            await self._send({"type": "abort"})
        except Exception:
            pass
        try:
            self._settled.set()
        except Exception:
            pass
        fut = self._prompt_ok
        if fut is not None and not fut.done():
            fut.set_result(False)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._flush_streams()
        except Exception:
            pass
        proc = self.proc
        pid = proc.pid if proc else None
        try:
            await self.abort()
        except Exception:
            pass
        if proc and proc.stdin and not proc.stdin.is_closing():
            try:
                proc.stdin.close()
            except Exception:
                pass
        if proc and proc.returncode is None:
            try:
                if pid:
                    os.killpg(pid, signal.SIGTERM)
            except OSError:
                try:
                    proc.terminate()
                except Exception:
                    pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=4)
            except Exception:
                try:
                    if pid:
                        os.killpg(pid, signal.SIGKILL)
                except OSError:
                    try:
                        proc.kill()
                    except Exception:
                        pass
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if pid:
            _LIVE.pop(pid, None)
        self.proc = None


_GRAPH_TOOLS = frozenset({
    "run_cmd", "http_request", "add_node", "add_edge", "report_finding",
    "report_shell", "report_pivot_capability", "propose_intents",
    "resolve_intent", "mark_honeypot", "note", "report_flag", "request_hint",
    "note_scan_coverage",
})


async def query_text(
    *,
    system_prompt: str,
    user_prompt: str,
    cwd: str | None = None,
    timeout: float = 90,
    tools: bool = False,
    model: str | None = None,
    role: str = "oneshot",
    project_id: str = "",
) -> str:
    """一次性无工具（默认）Pi 查询，返回纯文本。role 区分御主/蒸馏/漏洞页/导出，不混用进程。"""
    work = cwd or str(settings.data_dir)
    os.makedirs(work, exist_ok=True)
    sess = PiSession(
        cwd=work,
        system_prompt=system_prompt,
        tools=tools,
        role=(role or "oneshot").strip() or "oneshot",
        model=(model or "").strip(),
        project_id=project_id or "",
    )
    t0 = time.monotonic()
    try:
        await sess.start()
        remain = max(5.0, float(timeout or 90) - (time.monotonic() - t0))
        return await sess.prompt(user_prompt, timeout=remain)
    finally:
        await sess.close()
