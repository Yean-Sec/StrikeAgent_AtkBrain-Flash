"""ProjectAgent：每个项目独立的 Pi 猎面。

- 从者与角色工人都是全新 Pi RPC：每轮不续接旧对话，局面只靠攻击图/简报。
- 项目内工人无上限；Python 按御主方案并发拉起，不再走 Task。
- 图工具经 HTTP /agent-tools 由 Pi 扩展调用。
"""
from __future__ import annotations

import asyncio
import os
import re

from ..config import settings
from ..events import emit
from ..exec.guard import Guard
from ..objective import objective_allows_flag, objective_is_src
from ..scope import Scope
from .context import AgentContext
from .mcp_http import register_project_mcp, unregister_project_mcp
from .pi_runtime import PiSession
from .project_skills import skill_abs_paths
from .prompts import (
    build_brief,
    build_finding_review_instruction,
    build_subagents,
    build_system_prompt,
    default_fanout_roles,
    finding_review_system_prompt,
    FINDING_REVIEW_ROLE,
)
from .tools import tool_names

_DEAD_CLI_RE = re.compile(
    r"Cannot write to terminated process|terminated process|exit code:\s*-?11|"
    r"SIGSEGV|Broken pipe|Connection reset|pi rpc stdin closed",
    re.I,
)


def is_dead_cli_error(exc: BaseException | str) -> bool:
    return bool(_DEAD_CLI_RE.search(str(exc or "")))


def is_retryable_connect_error(exc: BaseException | str) -> bool:
    msg = str(exc or "")
    return is_dead_cli_error(msg) or "pi " in msg.lower() or "rpc" in msg.lower()


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
        self._sessions: list[PiSession] = []
        self._full_score_aborting = False
        self.ctx.abort_run = self._abort_on_full_score
        self.brief = build_brief(project)
        self._write_brief()
        self._project_skill_names = self._write_skills()
        self.model = (cfg.get("model") or "").strip() or settings.claude_model
        if self.model.lower() in ("sonnet", "haiku", "opus") or self.model.lower().startswith("claude"):
            self.model = settings.claude_model
        self._roles = build_subagents(self.objective)
        self.last_session_id: str | None = None
        self._connected = False
        register_project_mcp(self.ctx)

    def _write_brief(self) -> None:
        if not self.brief:
            return
        try:
            with open(os.path.join(self.workspace_dir, "BRIEF.md"), "w", encoding="utf-8") as f:
                f.write("# 题目简报\n\n" + self.brief + "\n")
        except OSError:
            pass

    def _write_skills(self) -> list[str]:
        try:
            from .project_skills import install_into_workspace
            return install_into_workspace(self.workspace_dir, objective=self.objective)
        except OSError:
            return []

    def _lead_system(self) -> str:
        return build_system_prompt(
            self.scope, self.workspace_dir, self.objective, self.brief,
        )

    def _role_system(self, role: str) -> str:
        spec = self._roles.get(role) or {}
        prompt = str(spec.get("prompt") or "")
        tools = ", ".join(tool_names(self.objective))
        return (
            f"{prompt}\n\n"
            f"工作目录：{self.workspace_dir}\n"
            f"可用工具：{tools}。禁止再开子进程或套娃。\n"
            f"{('题目简报：\\n' + self.brief) if self.brief else ''}"
        )

    def _fanout_roles(self) -> list[str]:
        raw = list(getattr(self.ctx, "fanout_roles", None) or [])
        known = set(self._roles)
        out: list[str] = []
        seen: set[str] = set()
        for r in raw:
            n = str(r or "").strip().lower()
            if n == FINDING_REVIEW_ROLE:
                continue
            if n in known and n not in seen:
                out.append(n)
                seen.add(n)
        if not out:
            for n in default_fanout_roles(self.objective):
                if n in known and n not in seen:
                    out.append(n)
                    seen.add(n)
        return out

    async def connect(self, *, jitter: bool = False) -> None:
        _ = jitter
        self._connected = True

    async def close(self) -> None:
        await self._close_sessions()
        self._connected = False
        unregister_project_mcp(self.project_id)
        try:
            await self.ctx.aclose()
        except Exception:
            pass

    async def interrupt(self) -> None:
        sessions = list(self._sessions)
        for s in sessions:
            try:
                await s.abort()
            except Exception:
                pass
        await self._close_sessions()

    async def _close_sessions(self) -> None:
        sessions = list(self._sessions)
        self._sessions = []
        if not sessions:
            return
        await asyncio.gather(*(s.close() for s in sessions), return_exceptions=True)

    async def reset_session(self) -> None:
        await self.begin_fresh_session(connect=False)

    async def begin_fresh_session(self, *, connect: bool = True) -> None:
        await self._close_sessions()
        self.last_session_id = None
        self._connected = bool(connect)

    async def resume_session(self) -> bool:
        await self.begin_fresh_session(connect=True)
        return False

    async def recover_dead_cli(self) -> None:
        await self._close_sessions()
        try:
            await self.ctx.aclose()
        except Exception:
            pass
        await asyncio.sleep(0.4)
        self._connected = True

    def set_run(self, run_id: str) -> None:
        self.ctx.run_id = run_id

    async def _abort_on_full_score(self) -> None:
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

    async def _run_one(self, role: str, system_prompt: str, instruction: str) -> dict:
        sess = PiSession(
            cwd=self.workspace_dir,
            system_prompt=system_prompt,
            project_id=self.project_id,
            role=role,
            tools=True,
            emit=emit,
            run_id=self.ctx.run_id,
            on_activity=self.ctx.mark_activity,
            model=self.model,
            skill_paths=skill_abs_paths(self.workspace_dir, self._project_skill_names),
        )
        self._sessions.append(sess)
        try:
            await sess.start()
            text = await sess.prompt(instruction, timeout=0)
            return {"text": text, "tool_uses": int(sess.tool_uses or 0), "role": role}
        except Exception as e:
            if is_dead_cli_error(e):
                self._connected = False
            raise
        finally:
            try:
                await sess.close()
            except Exception:
                pass
            try:
                self._sessions.remove(sess)
            except ValueError:
                pass

    async def run_turn(self, instruction: str) -> dict:
        try:
            self.ctx.task_subagents = []
        except Exception:
            pass
        await self.begin_fresh_session(connect=True)
        try:
            self.ctx.mark_activity()
        except Exception:
            pass
        roles = self._fanout_roles()
        try:
            self.ctx.task_subagents = list(roles)
        except Exception:
            pass
        pending: list[dict] = []
        try:
            from ..graph.store import findings_pending_secondary
            pending = await findings_pending_secondary(self.project_id)
        except Exception:
            pending = []
        pi_names = ["从者"] + list(roles)
        if pending:
            pi_names.append(FINDING_REVIEW_ROLE)
        await emit(
            self.project_id, "log",
            {
                "level": "info",
                "message": "本回合并发 Pi：" + "、".join(pi_names)
                + (f"（专职二次验证 {len(pending)} 条）" if pending else ""),
            },
            run_id=self.ctx.run_id,
        )
        if pending:
            await emit(
                self.project_id, "finding_review",
                {
                    "status": "running",
                    "count": len(pending),
                    "ids": [str(f.get("id") or "") for f in pending if f.get("id")],
                    "titles": [str(f.get("title") or "")[:80] for f in pending],
                    "role": FINDING_REVIEW_ROLE,
                },
                run_id=self.ctx.run_id,
            )
        lead_instr = instruction
        extra_lead = []
        if roles:
            extra_lead.append(
                "本回合调度已并发拉起角色会话："
                + "、".join(f"`{r}`" for r in roles)
                + "。你负责计划、短验证、写图与汇总；不要再开子进程。"
            )
        if pending:
            extra_lead.append(
                f"另有专职 `{FINDING_REVIEW_ROLE}` 处理 {len(pending)} 条未二次验证漏洞；"
                "你不要把二次验证当本回合主线。"
            )
        if extra_lead:
            lead_instr = instruction + "\n\n" + "\n".join(extra_lead)
        jobs = [
            self._run_one("lead", self._lead_system(), lead_instr),
        ]
        for role in roles:
            jobs.append(self._run_one(role, self._role_system(role), instruction))
        if pending:
            jobs.append(
                self._run_one(
                    FINDING_REVIEW_ROLE,
                    finding_review_system_prompt(self.workspace_dir, self.objective),
                    build_finding_review_instruction(pending),
                )
            )

        results = await asyncio.gather(*jobs, return_exceptions=True)
        texts: list[str] = []
        tool_uses = 0
        first_err: BaseException | None = None
        for item in results:
            if isinstance(item, BaseException):
                if first_err is None:
                    first_err = item
                continue
            texts.append(str(item.get("text") or ""))
            tool_uses += int(item.get("tool_uses") or 0)
        if pending:
            try:
                from ..projects import get_project as _gp_rev
                from ..report.pi_finding_page import fill_missing_pi_pages
                await fill_missing_pi_pages(
                    self.project_id, project=await _gp_rev(self.project_id),
                )
            except Exception:
                pass
            try:
                await emit(
                    self.project_id, "finding_review",
                    {
                        "status": "done",
                        "count": len(pending),
                        "ids": [str(f.get("id") or "") for f in pending if f.get("id")],
                        "role": FINDING_REVIEW_ROLE,
                    },
                    run_id=self.ctx.run_id,
                )
            except Exception:
                pass
        if self.ctx.goal_reached:
            try:
                await self.interrupt()
            except Exception:
                pass
        if first_err and not texts and not self.ctx.goal_reached:
            raise first_err
        return {
            "text": "\n".join(t for t in texts if t).strip(),
            "tool_uses": tool_uses,
            "goal_reached": self.ctx.goal_reached,
            "task_subagents": list(getattr(self.ctx, "task_subagents", None) or []),
        }


def _preview(obj) -> str:
    try:
        import json
        s = json.dumps(obj, ensure_ascii=False)
    except Exception:
        s = str(obj)
    return s[:400]


def _get_spawn_sem() -> asyncio.Semaphore:
    """兼容旧调用：项目内 Pi 不设闸。"""
    return asyncio.Semaphore(10_000)
