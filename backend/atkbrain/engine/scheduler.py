"""运行调度：全局并发信号量（可运行时调整）+ 项目运行生命周期 + steering 队列。"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from ..config import benchmark_slot_limit, settings


class DynamicSemaphore:
    """并发上限可在运行时调整的信号量。"""

    def __init__(self, value: int) -> None:
        self._limit = value
        self._active = 0
        self._cond = asyncio.Condition()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def active(self) -> int:
        return self._active

    async def set_limit(self, value: int) -> None:
        async with self._cond:
            self._limit = max(1, value)
            self._cond.notify_all()

    async def acquire(self) -> None:
        async with self._cond:
            while self._active >= self._limit:
                await self._cond.wait()
            self._active += 1

    async def release(self) -> None:
        async with self._cond:
            self._active = max(0, self._active - 1)
            self._cond.notify_all()

    def force_active(self, n: int) -> None:
        """纠偏泄漏：把占槽数掰回真实持有数，并唤醒排队者。"""
        self._active = max(0, int(n))
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        async def _wake() -> None:
            async with self._cond:
                self._cond.notify_all()

        loop.create_task(_wake())


@dataclass
class RunHandle:
    project_id: str
    task: asyncio.Task | None = None
    agent: object | None = None                       # ProjectAgent
    steering: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=100))
    status: str = "starting"
    run_id: str | None = None
    hard_restart: bool = False  # True=清图+新容器+烧 attempt；False=续跑
    user_stop: bool = False     # True=人工暂停，重启后不要自动拉起
    slot_held: bool = False     # 已拿到本赛道项目并发槽
    slot_kind: str = "redteam"  # redteam | ctf
    bench_held: bool = False    # 兼容旧句柄；现与 ctf 槽合一，不再单独占


def hunt_slot_kind(project: dict | None, objective: str | None = None) -> str:
    """CTF / 评测 CTF 子题走 ctf 槽；红队与 SRC（含胶水 SRC 子猎）走红队槽。"""
    from ..objective import objective_allows_flag, objective_is_src
    from .. import benchmark as bmk
    obj = objective
    if not obj and project:
        cfg = project.get("config") or {}
        obj = (cfg.get("objective") or cfg.get("track") or "") if isinstance(cfg, dict) else ""
    if objective_is_src(obj):
        return "redteam"
    if project and bmk.is_benchmark_sub(project):
        return "ctf"
    return "ctf" if objective_allows_flag(obj) else "redteam"


class RunManager:
    """两道互不占槽的项目闸 + 编排会话展示：
    - 红队 `redteam_sem`：红队与 SRC 同时跑的数量（默认 5）。
    - CTF `ctf_sem`：CTF / 评测子题（默认 3，上限 20）。
    - 会话层 `claude_per_project`：每项目 2 路（从者 + 御主）。
      顶栏 Claude Code 显示两道合计 × 2（默认 8 项目 → 16 路）。
    """

    def __init__(self) -> None:
        rt_limit = min(settings.max_redteam_concurrency, settings.max_redteam_concurrency_cap)
        ctf_limit = benchmark_slot_limit()
        self.redteam_sem = DynamicSemaphore(max(1, rt_limit))
        self.ctf_sem = DynamicSemaphore(max(1, ctf_limit))
        # 旧名：只代表红队槽。CTF 不再走这道闸。
        self.project_sem = self.redteam_sem
        self.sem = self.redteam_sem
        self.bench_sem = self.ctf_sem
        self.claude_per_project = max(1, int(getattr(settings, "claude_per_project", 2) or 2))
        self.max_claude = 0
        self._relink_claude_cap()
        self.handles: dict[str, RunHandle] = {}
        self.shutting_down = False

    def slot_sem(self, kind: str) -> DynamicSemaphore:
        return self.ctf_sem if kind == "ctf" else self.redteam_sem

    @property
    def claude_active(self) -> int:
        """当前在跑的 Agent 会话数 ≈ (红队占槽 + CTF 占槽) × 每项目会话。"""
        return (self.redteam_sem.active + self.ctf_sem.active) * self.claude_per_project

    def is_running(self, project_id: str) -> bool:
        h = self.handles.get(project_id)
        # zombie/stopping：句柄残留但不再占用调度语义，允许重新 start
        if not h or not h.task or h.task.done():
            return False
        if h.status in ("done", "stopping", "zombie"):
            return False
        return True

    def is_queued(self, project_id: str) -> bool:
        """已 start 但还在等项目并发槽（sem.acquire 之前），未真正开跑。

        UI 应显示「排队中」，不要算进「运行中」——否则会出现「并发已满、列表却多一条运行中」。
        """
        h = self.handles.get(project_id)
        if not h or not h.task or h.task.done():
            return False
        return h.status == "starting"

    def get(self, project_id: str) -> RunHandle | None:
        return self.handles.get(project_id)

    def _relink_claude_cap(self) -> None:
        """红队/CTF 项目并发变化后，顶栏 Claude Code 显示两道合计 × 每项目会话。"""
        total_projects = self.redteam_sem.limit + self.ctf_sem.limit
        self.max_claude = min(
            total_projects * self.claude_per_project,
            settings.max_concurrency_cap,
        )

    async def set_concurrency(self, value: int, *, track: str = "redteam") -> int:
        """按赛道设置项目并发。track=ctf 只动 CTF 槽，红队反之。"""
        kind = "ctf" if str(track or "").strip().lower() in ("ctf", "flag", "benchmark") else "redteam"
        if kind == "ctf":
            return await self.set_ctf_concurrency(value)
        return await self.set_redteam_concurrency(value)

    async def set_redteam_concurrency(self, value: int) -> int:
        value = max(1, min(int(value), settings.max_redteam_concurrency_cap))
        await self.redteam_sem.set_limit(value)
        self._relink_claude_cap()
        return value

    async def set_ctf_concurrency(self, value: int) -> int:
        cap = int(getattr(settings, "max_ctf_concurrency_cap", 20) or 20)
        if cap <= 0:
            cap = 20
        value = max(1, min(int(value), cap))
        await self.ctf_sem.set_limit(value)
        settings.benchmark_max_concurrency = value
        self._relink_claude_cap()
        return value

    # 语义更清晰的别名
    async def set_project_concurrency(self, value: int) -> int:
        return await self.set_redteam_concurrency(value)

    def set_claude_per_project(self, value: int) -> int:
        """每项目固定 2 个 Claude：从者 + 御主。"""
        self.claude_per_project = 2
        self._relink_claude_cap()
        return self.claude_per_project

    def _drop_handle(self, project_id: str, handle: RunHandle | None = None) -> None:
        cur = self.handles.get(project_id)
        if cur is None:
            return
        if handle is None or cur is handle:
            self.handles.pop(project_id, None)

    async def release_handle_slots(self, handle: RunHandle | None) -> None:
        """幂等释放句柄占的项目槽。僵尸收口与 loop finally 都走这里，避免双 release。"""
        if handle is None:
            return
        if handle.slot_held:
            handle.slot_held = False
            await self.slot_sem(handle.slot_kind).release()
        if handle.bench_held:
            handle.bench_held = False

    def _slot_holders(self, kind: str | None = None) -> list[str]:
        out: list[str] = []
        for pid, h in self.handles.items():
            if not h.slot_held:
                continue
            if h.status != "running":
                continue
            if not h.task or h.task.done():
                continue
            if kind and h.slot_kind != kind:
                continue
            out.append(pid)
        return out

    def start(self, project_id: str, *, hard_restart: bool = False) -> RunHandle:
        from .loop import run_project_loop  # 延迟导入避免环依赖

        if self.is_running(project_id):
            return self.handles[project_id]

        # 清掉已结束或僵尸句柄，避免 UI 显示 running 却无法再次启动
        old = self.handles.pop(project_id, None)
        if old and old.task and not old.task.done():
            old.status = "zombie"
            old.task.cancel()
            if old.slot_held:
                asyncio.create_task(self.release_handle_slots(old))

        handle = RunHandle(project_id=project_id, hard_restart=hard_restart)
        self.handles[project_id] = handle

        def _cleanup(t: asyncio.Task, pid: str = project_id, owned: RunHandle = handle) -> None:
            cur = self.handles.get(pid)
            if cur is owned:
                self.handles.pop(pid, None)

        handle.task = asyncio.create_task(run_project_loop(self, project_id))
        handle.task.add_done_callback(_cleanup)
        return handle

    async def stop(self, project_id: str) -> bool:
        h = self.handles.get(project_id)
        if not h:
            return False
        h.user_stop = True
        h.status = "stopping"
        try:
            from .hunt_resume import forget_resume
            forget_resume(project_id)
        except Exception:
            pass
        if h.agent is not None:
            try:
                await h.agent.interrupt()  # type: ignore[attr-defined]
            except Exception:
                pass
        if h.task and not h.task.done():
            h.task.cancel()
            try:
                await asyncio.wait_for(h.task, timeout=12)
            except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                # 取消后仍卡住（例如 SDK 忽略 cancel）→ 降级为 zombie，解除 is_running 占位
                if not h.task.done():
                    h.status = "zombie"
                    await self.release_handle_slots(h)
                    return True
        await self.release_handle_slots(h)
        self._drop_handle(project_id, h)
        return True

    def steer(self, project_id: str, message: str) -> bool:
        """把人工指令投入项目的 steering 队列，在下一个安全 checkpoint 注入。"""
        h = self.handles.get(project_id)
        if not h or not self.is_running(project_id):
            return False
        try:
            h.steering.put_nowait(message)
            return True
        except asyncio.QueueFull:
            return False

    def drain_steering(self, project_id: str) -> list[str]:
        h = self.handles.get(project_id)
        if not h:
            return []
        out: list[str] = []
        while True:
            try:
                out.append(h.steering.get_nowait())
            except asyncio.QueueEmpty:
                break
        return out

    def snapshot(self) -> dict:
        # 顺手清掉已 done 的残留句柄
        for pid, h in list(self.handles.items()):
            if h.task is None or h.task.done():
                if h.status != "zombie":
                    self.handles.pop(pid, None)
        live_rt = self._slot_holders("redteam")
        live_ctf = self._slot_holders("ctf")
        live = live_rt + live_ctf
        queued = [pid for pid in self.handles if self.is_queued(pid)]
        if self.redteam_sem.active != len(live_rt):
            self.redteam_sem.force_active(len(live_rt))
        if self.ctf_sem.active != len(live_ctf):
            self.ctf_sem.force_active(len(live_ctf))
        rt_cap = settings.max_redteam_concurrency_cap
        ctf_cap = max(1, int(getattr(settings, "max_ctf_concurrency_cap", 20) or 20))
        return {
            "concurrency_limit": self.redteam_sem.limit + self.ctf_sem.limit,
            "active": len(live),
            "cap": rt_cap + ctf_cap,
            "running": live,
            "queued": queued,
            "redteam": {
                "active": len(live_rt),
                "limit": self.redteam_sem.limit,
                "cap": rt_cap,
            },
            "ctf": {
                "active": len(live_ctf),
                "limit": self.ctf_sem.limit,
                "cap": ctf_cap,
            },
            "projects": {
                "active": len(live),
                "limit": self.redteam_sem.limit + self.ctf_sem.limit,
                "cap": rt_cap + ctf_cap,
            },
            "claude": {
                "active": self.claude_active,
                "limit": self.max_claude,
                "cap": settings.max_concurrency_cap,
                "per_project": self.claude_per_project,
            },
        }

    async def checkpoint_for_shutdown(self, timeout: float = 8.0) -> None:
        """关机前取消猎循环并等猎钟落盘。必须在关闭数据库之前调用。"""
        self.shutting_down = True
        tasks = [
            h.task for h in list(self.handles.values())
            if h.task is not None and not h.task.done()
        ]
        for t in tasks:
            t.cancel()
        if not tasks:
            return
        try:
            await asyncio.wait(tasks, timeout=max(0.5, float(timeout or 0)))
        except Exception:
            pass


manager = RunManager()
