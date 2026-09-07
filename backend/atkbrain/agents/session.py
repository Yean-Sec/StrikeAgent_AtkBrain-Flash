"""ProjectAgent：每个项目独立的 Claude Code 猎面。

- 装配 ClaudeAgentOptions：禁用内置 Bash/WebFetch，改用 StrikeAgent_AtkBrain-Flash 图工具；挂子智能体；bypassPermissions。
- 指挥官与自监督都是全新 Claude Code：每轮不续接旧对话，局面只靠攻击图/简报，避免上下文污染。
- run_turn：先开新会话再发本轮编排指令，消费流式消息并翻译成事件。
- 支持人工 steering 在轮次间注入（写入本轮指令，不挂在旧对话上）。
"""
from __future__ import annotations

import asyncio
import json
import os
import random
import re
import time as _time

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    HookMatcher,
    PermissionResultAllow,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)


async def _auto_allow(tool_name, tool_input, ctx):
    """编程式自动批准所有工具调用（headless）。替代 root 下被禁用的 --dangerously-skip-permissions。"""
    return PermissionResultAllow(behavior="allow")

from ..config import settings, REPO_ROOT
from ..events import emit
from ..exec.guard import Guard
from ..objective import objective_allows_flag
from ..scope import Scope
from .context import AgentContext
from .prompts import build_brief, build_subagents, build_system_prompt, builtin_allowed_tools
from .tools import SERVER_NAME, build_server, tool_names

BUILTIN_ALLOWED = builtin_allowed_tools("getshell")

# 主 Claude CLI spawn/connect 全局闸（惰性绑定当前事件循环）
_spawn_sem: asyncio.Semaphore | None = None
_spawn_sem_loop: asyncio.AbstractEventLoop | None = None

_DEAD_CLI_RE = re.compile(
    r"Cannot write to terminated process|terminated process|exit code:\s*-?11|"
    r"SIGSEGV|Broken pipe|Connection reset",
    re.I,
)
_CONTROL_TIMEOUT_RE = re.compile(r"Control request timeout", re.I)


def is_dead_cli_error(exc: BaseException | str) -> bool:
    return bool(_DEAD_CLI_RE.search(str(exc or "")))


def is_retryable_connect_error(exc: BaseException | str) -> bool:
    """进程已死或 CLI initialize/control 握手超时：清残留后换 client 再连。"""
    msg = str(exc or "")
    return is_dead_cli_error(msg) or bool(_CONTROL_TIMEOUT_RE.search(msg))


def _get_spawn_sem() -> asyncio.Semaphore:
    global _spawn_sem, _spawn_sem_loop
    loop = asyncio.get_running_loop()
    n = max(1, int(getattr(settings, "claude_spawn_max_concurrent", 1) or 1))
    if _spawn_sem is None or _spawn_sem_loop is not loop:
        _spawn_sem = asyncio.Semaphore(n)
        _spawn_sem_loop = loop
    return _spawn_sem


def spawn_jitter_seconds(*, max_sec: float | None = None) -> float:
    """首次 connect 错峰秒数：均匀随机 [0, max]。max<=0 则 0。"""
    mx = float(max_sec if max_sec is not None else getattr(settings, "claude_spawn_jitter_max_sec", 0) or 0)
    if mx <= 0:
        return 0.0
    return random.uniform(0.0, mx)


# #region agent log
def _dbg(loc: str, message: str, hyp: str | None = None, **data) -> None:
    try:
        line = json.dumps({
            "sessionId": "c5cf65",
            "timestamp": int(_time.time() * 1000),
            "location": loc,
            "message": message,
            "hypothesisId": hyp,
            "data": data or None,
        }, ensure_ascii=False)
        with open("/home/kali/atkbrain/.cursor/debug-c5cf65.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
# #endregion


class ProjectAgent:
    def __init__(self, project: dict, scope: Scope) -> None:
        self.project = project
        self.project_id = project["id"]
        self.scope = scope
        cfg = project.get("config") or {}

        self.workspace_dir = os.path.join(str(settings.workspaces_dir), self.project_id)
        os.makedirs(self.workspace_dir, exist_ok=True)
        os.makedirs(os.path.join(self.workspace_dir, "loot"), exist_ok=True)

        _objective = cfg.get("objective", settings.default_objective)
        self.guard = Guard(scope, "", objective=_objective)
        self.objective = _objective
        _allows_flag = objective_allows_flag(self.objective)
        flags_needed = int(cfg.get("flag_count") or 1) if _allows_flag else 1
        bm = cfg.get("benchmark") if (_allows_flag and isinstance(cfg.get("benchmark"), dict)) else None
        self.ctx = AgentContext(
            project_id=self.project_id, workspace_dir=self.workspace_dir,
            loot_dir=os.path.join(self.workspace_dir, "loot"),
            scope=scope, guard=self.guard,
            objective=self.objective, project=project, flags_needed=flags_needed,
            benchmark=bm,
        )
        self.server = build_server(self.ctx)
        self._full_score_aborting = False
        self.ctx.abort_run = self._abort_on_full_score
        # 题目简报（description + 元信息）：注入系统提示并落盘 BRIEF.md，消除“题面没进视野”致盲。
        self.brief = build_brief(project)
        self._write_brief()
        self.model = cfg.get("model", settings.claude_model)
        # 只作日志；不再用这个 ID 续接旧对话（会把上一轮脏上下文带进下一轮）。
        self.last_session_id: str | None = None
        self.options = self._build_options()
        self.client = ClaudeSDKClient(self.options)
        self._connected = False
        self._spawn_jitter_done = False
        self._task_slots = 0
        self._wait_tool_ids: set[str] = set()

    def _build_options(
        self, *, resume: str | None = None, continue_conversation: bool = False,
    ) -> ClaudeAgentOptions:
        """构造 SDK options。resume/continue 默认关闭，避免跨轮对话污染。"""
        mcp_servers = {SERVER_NAME: self.server}
        allowed = tool_names(self.objective) + list(builtin_allowed_tools(self.objective))
        disallowed = ["Bash", "WebFetch"]
        if objective_allows_flag(self.objective):
            disallowed.append("WebSearch")
        opts: dict = dict(
            mcp_servers=mcp_servers,
            allowed_tools=allowed,
            disallowed_tools=disallowed,
            can_use_tool=_auto_allow,
            system_prompt=build_system_prompt(
                self.scope, self.workspace_dir, self.objective, self.brief,
            ),
            cwd=self.workspace_dir,
            setting_sources=["project"],
            agents=build_subagents(self.objective),
            model=self.model,
            fallback_model=settings.claude_fallback_model,
            max_turns=settings.turn_max_agent_turns,
            resume=resume,
            continue_conversation=continue_conversation,
            max_buffer_size=32 * 1024 * 1024,
            hooks={
                "PreCompact": [HookMatcher(hooks=[self._on_precompact])],
                "PreToolUse": [HookMatcher(hooks=[self._on_pre_tool_use])],
                "PostToolUse": [HookMatcher(hooks=[self._on_post_tool_use])],
                "Stop": [HookMatcher(hooks=[self._on_stop])],
            },
        )
        if bool(getattr(settings, "claude_add_repo_dir", False)):
            opts["add_dirs"] = [str(REPO_ROOT)]
        return ClaudeAgentOptions(**opts)

    async def _on_precompact(self, _input, _tool_use_id, _hook_context) -> dict:
        """让时间线显式区分 Claude 自动压缩和会话被系统重置。"""
        await emit(
            self.project_id,
            "log",
            {"level": "info", "message": "Claude 上下文接近上限，正在自动压缩（非清空，会保留摘要与关键结论）。"},
            run_id=self.ctx.run_id,
        )
        return {}

    def _full_score_hook_block(self) -> dict:
        """PreToolUse / Stop：满分后禁止继续，结束当前 Claude 回合。"""
        return {
            "continue_": False,
            "stopReason": "本题已满分，立即收工换题",
            "decision": "block",
            "reason": "本题已满分，立即停止，不要再调用工具。",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "本题已满分，立即收工换题",
            },
        }

    @staticmethod
    def _hook_tool_name(inp) -> str:
        if isinstance(inp, dict):
            return str(inp.get("tool_name") or inp.get("toolName") or "")
        return str(getattr(inp, "tool_name", None) or getattr(inp, "toolName", None) or "")

    def _deny_extra_task(self) -> dict:
        return {
            "continue_": True,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "已有子智能体在跑；等它结束后再派下一个，避免占满全局 Claude 配额。"
                ),
            },
        }

    async def _on_pre_tool_use(self, _input, _tool_use_id, _hook_context) -> dict:
        if self.ctx.goal_reached:
            return self._full_score_hook_block()
        if self._hook_tool_name(_input) == "Task":
            cap = max(1, int(getattr(settings, "claude_per_project", 2) or 2) - 1)
            if int(self._task_slots or 0) >= cap:
                return self._deny_extra_task()
            self._task_slots = int(self._task_slots or 0) + 1
        return {}

    async def _on_post_tool_use(self, _input, _tool_use_id, _hook_context) -> dict:
        if self._hook_tool_name(_input) == "Task" and int(self._task_slots or 0) > 0:
            self._task_slots -= 1
        return {}

    async def _on_stop(self, _input, _tool_use_id, _hook_context) -> dict:
        if self.ctx.goal_reached:
            return {
                "continue_": False,
                "stopReason": "本题已满分，立即收工换题",
            }
        return {}

    async def _abort_on_full_score(self) -> None:
        """关靶场容器并打断主会话，让 loop 在本回合结束时按 completed 收口并立刻补下一题。"""
        if self._full_score_aborting:
            return
        self._full_score_aborting = True
        await emit(
            self.project_id, "log",
            {"level": "info", "message": "本题满分，立即收工并释放靶场槽位，切换下一题。"},
            run_id=self.ctx.run_id,
        )
        try:
            if self.ctx.project:
                from .. import benchmark as bm
                await bm.close_challenge(self.ctx.project)
        except Exception:
            pass
        try:
            await self.interrupt()
        except Exception:
            pass

    def _write_brief(self) -> None:
        """把题目简报落盘到工作区 BRIEF.md，便于 Read/人工查看（非必须，失败忽略）。"""
        if not self.brief:
            return
        try:
            with open(os.path.join(self.workspace_dir, "BRIEF.md"), "w", encoding="utf-8") as f:
                f.write("# 题目简报\n\n" + self.brief + "\n")
        except OSError:
            pass

    def _kill_workspace_cli(self) -> int:
        killed = 0
        try:
            import subprocess as _sp
            out = _sp.check_output(["pgrep", "-f", "_bundled/claude"], text=True)
        except Exception:
            return 0
        for line in out.splitlines():
            pid_s = line.strip()
            if not pid_s.isdigit():
                continue
            pid = int(pid_s)
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
            except OSError:
                continue
            if cwd == self.workspace_dir or cwd.startswith(self.workspace_dir + os.sep):
                try:
                    os.kill(pid, 9)
                    killed += 1
                except OSError:
                    pass
        return killed

    async def connect(self, *, jitter: bool = False) -> None:
        """连接主 Claude CLI。立刻 connect；jitter 保留兼容、已忽略。"""
        if self._connected:
            return
        _ = jitter
        self._spawn_jitter_done = True
        sem = _get_spawn_sem()
        retries = max(1, int(getattr(settings, "claude_connect_retries", 4) or 4))
        settle_ms = max(0, int(getattr(settings, "claude_spawn_settle_ms", 400) or 0))
        last_exc: BaseException | None = None
        async with sem:
            if self._connected:
                return
            for attempt in range(1, retries + 1):
                if settle_ms:
                    await asyncio.sleep(settle_ms / 1000.0)
                # #region agent log
                _dbg("session.py:connect_pre", "main CLI connect under spawn lock",
                     hyp="H-MAIN1", project_id=self.project_id,
                     has_session=bool(self.last_session_id), attempt=attempt,
                     add_repo=bool(getattr(settings, "claude_add_repo_dir", False)))
                # #endregion
                t0 = _time.time()
                try:
                    await self.client.connect()
                    self._connected = True
                    # #region agent log
                    _dbg("session.py:connect_ok", "main CLI connected",
                         hyp="H-MAIN1", project_id=self.project_id,
                         elapsed=round(_time.time() - t0, 2), attempt=attempt)
                    # #endregion
                    return
                except Exception as e:
                    self._connected = False
                    last_exc = e
                    dead = is_dead_cli_error(e)
                    retryable = is_retryable_connect_error(e)
                    # #region agent log
                    _dbg("session.py:connect_fail", "main CLI connect failed",
                         hyp="H-MAIN1", project_id=self.project_id,
                         elapsed=round(_time.time() - t0, 2),
                         attempt=attempt, dead=dead,
                         exc_type=type(e).__name__, exc_msg=repr(e)[:240])
                    # #endregion
                    if not retryable or attempt >= retries:
                        break
                    killed = self._kill_workspace_cli()
                    # 换全新 client，避免写已死 transport
                    self.options = self._build_options()
                    self.client = ClaudeSDKClient(self.options)
                    self.last_session_id = None
                    # #region agent log
                    _dbg("session.py:connect_retry", "backoff before reconnect",
                         hyp="H-CF", project_id=self.project_id,
                         attempt=attempt, killed=killed,
                         sleep_s=round(1.5 * attempt, 1))
                    # #endregion
                    await asyncio.sleep(1.5 * attempt)
        assert last_exc is not None
        raise last_exc

    async def close(self) -> None:
        if self._connected:
            try:
                await self.client.disconnect()
            except Exception:
                pass
            self._connected = False
        # 关闭持久 HTTP 客户端（保留 cookie 池，重置会话后可复用登录态）
        try:
            await self.ctx.aclose()
        except Exception:
            pass

    async def interrupt(self) -> None:
        if not self._connected or self.client is None:
            return
        try:
            await self.client.interrupt()
        except Exception:
            self._connected = False

    async def reset_session(self) -> None:
        """断开并准备一条空 SDK 会话，不续接旧对话。"""
        await self.begin_fresh_session(connect=False)

    async def begin_fresh_session(self, *, connect: bool = True) -> None:
        """丢掉旧 Claude 对话，开一条全新会话。

        保留 AgentContext（cookie、已夺 flag、攻击图在库里）。不 resume session_id。
        """
        try:
            await self.interrupt()
        except Exception:
            pass
        if self.client is not None and self._connected:
            try:
                await self.client.disconnect()
            except Exception:
                pass
        self._connected = False
        self.last_session_id = None
        self.options = self._build_options()
        self.client = ClaudeSDKClient(self.options)
        # #region agent log
        _dbg("session.py:fresh", "new Claude Code session, no resume",
             hyp="H-FRESH", project_id=self.project_id)
        # #endregion
        if connect:
            await self.connect(jitter=False)

    async def resume_session(self) -> bool:
        """兼容旧调用名：一律全新会话，绝不续接旧对话。返回 False。"""
        await self.begin_fresh_session(connect=True)
        return False

    async def recover_dead_cli(self) -> None:
        """SIGSEGV(-11) / 进程已死后：清残留 CLI、丢弃 session，串行拉起全新 CLI。

        禁止对已死 transport 做 interrupt/query，否则会再次抛
        ``Cannot write to terminated process (exit code: -11)``，重建本身失败。
        """
        # #region agent log
        _dbg("session.py:recover_dead", "force fresh CLI after SIGSEGV/dead",
             hyp="H-MAIN3", project_id=self.project_id,
             old_session=bool(self.last_session_id))
        # #endregion
        self.last_session_id = None
        self._connected = False
        killed = self._kill_workspace_cli()
        self.client = None
        try:
            await self.ctx.aclose()
        except Exception:
            pass
        # #region agent log
        _dbg("session.py:recover_kill", "killed workspace claude leftovers",
             hyp="H-CF", project_id=self.project_id, killed=killed)
        # #endregion
        self.options = self._build_options()
        self.client = ClaudeSDKClient(self.options)
        await asyncio.sleep(1.5)
        await self.connect(jitter=False)

    def set_run(self, run_id: str) -> None:
        self.ctx.run_id = run_id

    async def run_turn(self, instruction: str) -> dict:
        """执行一轮：先开全新 Claude Code，再发指令。返回本轮文本汇总。"""
        try:
            self._task_slots = 0
            self._wait_tool_ids = set()
            await self.begin_fresh_session(connect=True)
            try:
                self.ctx.mark_activity()
            except Exception:
                pass
            await self.client.query(instruction)
            texts: list[str] = []
            tool_uses = 0
            async for msg in self.client.receive_response():
                await self._translate(msg, texts_out=texts)
                if isinstance(msg, AssistantMessage):
                    for b in msg.content:
                        if isinstance(b, ToolUseBlock):
                            tool_uses += 1
                if self.ctx.goal_reached:
                    try:
                        await self.interrupt()
                    except Exception:
                        pass
                    break
            return {
                "text": "\n".join(texts).strip(),
                "tool_uses": tool_uses,
                "goal_reached": self.ctx.goal_reached,
            }
        except Exception as e:
            if is_dead_cli_error(e):
                self._connected = False
            raise

    async def _translate(self, msg, texts_out: list[str]) -> None:
        if isinstance(msg, AssistantMessage):
            try:
                self.ctx.mark_activity()
            except Exception:
                pass
            for b in msg.content:
                if isinstance(b, TextBlock) and b.text.strip():
                    texts_out.append(b.text)
                    await emit(self.project_id, "text", {"text": b.text}, run_id=self.ctx.run_id)
                elif isinstance(b, ThinkingBlock):
                    t = getattr(b, "thinking", "") or ""
                    if t.strip():
                        await emit(self.project_id, "thought", {"message": t[:2000], "kind": "reasoning"}, run_id=self.ctx.run_id)
                elif isinstance(b, ToolUseBlock):
                    wait_names = {"Task", "TaskOutput", "TaskCreate", "Agent"}
                    if b.name in wait_names:
                        uid = str(getattr(b, "id", "") or "")
                        if uid:
                            self._wait_tool_ids.add(uid)
                        try:
                            self.ctx.cmd_inflight = int(getattr(self.ctx, "cmd_inflight", 0) or 0) + 1
                        except Exception:
                            pass
                    # StrikeAgent_AtkBrain-Flash 自有工具会自行发事件，这里只翻译内置工具，避免重复
                    if not b.name.startswith(f"mcp__{SERVER_NAME}__"):
                        payload = {"tool": b.name, "input": _preview(b.input)}
                        # Task 委派：单独摊开，便于监控主→子协同
                        if b.name == "Task" and isinstance(b.input, dict):
                            payload["subagent"] = (
                                b.input.get("subagent_type")
                                or b.input.get("agent")
                                or b.input.get("name")
                                or ""
                            )
                            payload["description"] = str(
                                b.input.get("description") or b.input.get("prompt") or ""
                            )[:300]
                        await emit(self.project_id, "tool", payload, run_id=self.ctx.run_id)
        elif isinstance(msg, UserMessage):
            for b in getattr(msg, "content", []) or []:
                if isinstance(b, ToolResultBlock):
                    try:
                        self.ctx.mark_activity()
                    except Exception:
                        pass
                    uid = str(getattr(b, "tool_use_id", "") or "")
                    if uid and uid in getattr(self, "_wait_tool_ids", ()):
                        self._wait_tool_ids.discard(uid)
                        try:
                            self.ctx.cmd_inflight = max(
                                0, int(getattr(self.ctx, "cmd_inflight", 0) or 0) - 1,
                            )
                        except Exception:
                            pass
                    name = getattr(b, "tool_use_id", "")
                    # 内置工具的结果（atkbrain 工具已自发结果事件）
                    content = b.content
                    if isinstance(content, list):
                        txt = " ".join(
                            c.get("text", "") for c in content if isinstance(c, dict) and c.get("type") == "text"
                        )
                    else:
                        txt = str(content)
                    if txt and "mcp__atkbrain__" not in str(name):
                        await emit(self.project_id, "tool_result", {"preview": txt[:800]}, run_id=self.ctx.run_id)
        elif isinstance(msg, ResultMessage):
            self.last_session_id = getattr(msg, "session_id", None) or self.last_session_id
            await emit(
                self.project_id, "turn",
                {"subtype": getattr(msg, "subtype", ""),
                 "num_turns": getattr(msg, "num_turns", None),
                 "duration_ms": getattr(msg, "duration_ms", None),
                 "total_cost_usd": getattr(msg, "total_cost_usd", None)},
                run_id=self.ctx.run_id,
            )


def _preview(obj) -> str:
    try:
        import json
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return s[:400]
