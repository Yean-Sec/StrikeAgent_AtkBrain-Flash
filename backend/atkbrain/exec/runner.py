"""在工作目录执行一条 shell 命令。"""
from __future__ import annotations

import asyncio
import os
import signal
import time
from dataclasses import dataclass

from ..config import settings
from atkbrain_native import Guard, GuardDecision

_LIVE_CMDS: dict[int, str] = {}


def kill_cmds_for_project(project_id: str) -> int:
    """停猎时杀掉本项目仍在跑的 shell（start_new_session，取消 await 会漏）。"""
    want = (project_id or "").strip()
    if not want:
        return 0
    n = 0
    for pid, owner in list(_LIVE_CMDS.items()):
        if owner != want:
            continue
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        _LIVE_CMDS.pop(pid, None)
        n += 1
    return n


_PROXY_ENV_KEYS = (
    "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
    "ALL_PROXY", "all_proxy", "no_proxy", "NO_PROXY",
)


@dataclass
class CmdResult:
    exit_code: int
    stdout: str
    stderr: str
    blocked: bool = False
    reason: str = ""
    category: str = ""
    duration: float = 0.0


async def run_shell(
    command: str,
    *,
    cwd: str,
    guard: Guard,
    timeout: int | None = None,
    extra_env: dict[str, str] | None = None,
    project_id: str | None = None,
) -> CmdResult:
    decision: GuardDecision = guard.check_command(command)
    if not decision.allow:
        return CmdResult(
            exit_code=-1, stdout="", stderr="",
            blocked=True, reason=decision.reason, category=decision.category,
        )
    if timeout is None:
        limit = int(getattr(settings, "cmd_timeout", 0) or 0)
    else:
        try:
            limit = int(timeout)
        except (TypeError, ValueError):
            limit = int(getattr(settings, "cmd_timeout", 0) or 0)
    t0 = time.monotonic()
    env = None
    if extra_env or project_id:
        from atkbrain_native import objective_allows_flag
        if extra_env and objective_allows_flag(getattr(guard, "objective", None)):
            extra_env = None
    if extra_env or project_id:
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        if project_id:
            env["ATKBRAIN_PROJECT_ID"] = str(project_id)
        try:
            if extra_env:
                from ..proxy.enforce import proxy_url_from_env, wrap_proxychains
                from ..proxy.pool import pool as _proxy_pool
                chain = _proxy_pool.pick_chain(8)
                px = proxy_url_from_env(extra_env)
                if px and px not in chain:
                    chain = [px, *[u for u in chain if u != px]]
                if chain:
                    command = wrap_proxychains(command, chain)
                    for k in _PROXY_ENV_KEYS:
                        env.pop(k, None)
        except FileNotFoundError as e:
            return CmdResult(
                exit_code=-1, stdout="", stderr=str(e),
                blocked=True,
                reason="红队/SRC 需要 proxychains4 才能强制走代理，本机未安装。",
                category="proxy",
                duration=time.monotonic() - t0,
            )
        except Exception as e:
            return CmdResult(
                exit_code=-1, stdout="", stderr=str(e),
                blocked=True,
                reason=f"无法套上出口代理：{e}",
                category="proxy",
                duration=time.monotonic() - t0,
            )
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
        if proc.pid and project_id:
            _LIVE_CMDS[int(proc.pid)] = str(project_id)
        try:
            if limit <= 0:
                out_b, err_b = await proc.communicate()
            else:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=limit)
        except asyncio.CancelledError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            try:
                await proc.wait()
            except Exception:
                pass
            raise
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            await proc.wait()
            return CmdResult(
                exit_code=-1, stdout="", stderr=f"timeout after {limit}s",
                duration=time.monotonic() - t0,
            )
        return CmdResult(
            exit_code=int(proc.returncode or 0),
            stdout=(out_b or b"").decode("utf-8", "replace"),
            stderr=(err_b or b"").decode("utf-8", "replace"),
            duration=round(time.monotonic() - t0, 2),
        )
    except asyncio.CancelledError:
        raise
    except Exception as e:
        return CmdResult(
            exit_code=-1, stdout="", stderr=str(e),
            duration=time.monotonic() - t0,
        )
    finally:
        if "proc" in locals() and getattr(proc, "pid", None):
            _LIVE_CMDS.pop(int(proc.pid), None)
