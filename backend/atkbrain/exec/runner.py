"""在工作目录执行一条 shell 命令。"""
from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass

from ..config import settings
from .guard import Guard, GuardDecision


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
    if extra_env:
        from ..objective import objective_allows_flag
        if objective_allows_flag(getattr(guard, "objective", None)):
            extra_env = None
    if extra_env:
        env = os.environ.copy()
        env.update(extra_env)
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        try:
            if limit <= 0:
                out_b, err_b = await proc.communicate()
            else:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=limit)
        except asyncio.TimeoutError:
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
    except Exception as e:
        return CmdResult(
            exit_code=-1, stdout="", stderr=str(e),
            duration=time.monotonic() - t0,
        )
