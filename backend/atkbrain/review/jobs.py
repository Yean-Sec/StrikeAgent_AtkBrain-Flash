"""单条二次验证 / 红队评级：内存任务；活猎复用 ProjectAgent，idle 开短会话。"""
from __future__ import annotations

import asyncio
import os
import time
import uuid
from typing import Any

from atkbrain_native import msg

_JOBS: dict[str, dict[str, Any]] = {}
_ACTIVE: dict[tuple[str, str, str], str] = {}
_IDLE_LOCKS: dict[str, asyncio.Lock] = {}
_JOBS_LOCK = asyncio.Lock()


class ReviewBusy(Exception):
    def __init__(self, message: str = "") -> None:
        super().__init__(message or msg("review_busy"))


def _modes_conflict(held: str, want: str) -> bool:
    if held == want:
        return True
    return held == "both" or want == "both"


def _busy_for(pid: str, fid: str, mode: str) -> str | None:
    for (p, f, m), jid in _ACTIVE.items():
        if p == pid and f == fid and _modes_conflict(m, mode):
            return jid
    return None


def snapshot(job_id: str) -> dict[str, Any] | None:
    job = _JOBS.get(job_id)
    if not job:
        return None
    return dict(job)


def list_active() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for jid in _ACTIVE.values():
        job = _JOBS.get(jid)
        if job and job.get("status") in ("queued", "running"):
            out.append(dict(job))
    return out


_WAIT_DETAILS = {"已拉起 Pi，等待模型", "等待模型回复"}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def note_review_pid(job_id: str, pid: int) -> None:
    job = _JOBS.get(job_id)
    if not job or pid <= 0:
        return
    job["pi_pid"] = int(pid)


def pulse_review(job_id: str) -> None:
    """进程还在等模型时刷新时间。不把正在调用的工具盖掉。"""
    job = _JOBS.get(job_id)
    if not job or job.get("status") != "running":
        return
    job["updated_at"] = time.time()
    cur = str(job.get("detail") or "")
    if not cur or cur in _WAIT_DETAILS:
        job["detail"] = "等待模型回复"


def note_review_beat(job_id: str, detail: str) -> None:
    """Pi 已经在跑时刷新动作。排队中的任务不因心跳变成进行中。"""
    job = _JOBS.get(job_id)
    if not job or job.get("status") != "running":
        return
    text = str(detail or "").strip()
    if not text:
        return
    job["detail"] = text[:80]
    job["updated_at"] = time.time()


def mark_running(job_id: str, detail: str) -> None:
    job = _JOBS.get(job_id)
    if not job or job.get("status") not in ("queued", "running"):
        return
    now = time.time()
    job["status"] = "running"
    if not job.get("started_at"):
        job["started_at"] = now
    text = str(detail or "").strip()
    if text:
        job["detail"] = text[:80]
    job["updated_at"] = now


def review_state(pid: str, fid: str) -> dict[str, dict[str, Any]]:
    """这条漏洞上二次验证 / 红队评级各自的真实状态。排队和进行中分开。"""
    out: dict[str, dict[str, Any]] = {}
    now = time.time()
    for (p, f, m), jid in list(_ACTIVE.items()):
        if p != pid or f != fid:
            continue
        job = _JOBS.get(jid)
        if not job or job.get("status") not in ("queued", "running"):
            continue
        modes = ["secondary", "rating"] if m == "both" else [m]
        created = float(job.get("created_at") or now)
        started = float(job.get("started_at") or 0) or created
        updated = float(job.get("updated_at") or created)
        status = str(job.get("status") or "")
        detail = str(job.get("detail") or "")
        pi_pid = int(job.get("pi_pid") or 0)
        if status == "running" and pi_pid and not _pid_alive(pi_pid):
            status = "dead"
            detail = "Pi 进程已退出"
            release(jid, status="error", error="pi exited")
        view = {
            "status": status,
            "started_at": started if status == "running" else created,
            "updated_at": updated,
            "detail": detail,
        }
        for mode in modes:
            if mode in ("secondary", "rating"):
                out[mode] = view
    return out


def reviewing_modes(pid: str, fid: str) -> set[str]:
    modes: set[str] = set()
    for (p, f, m), jid in _ACTIVE.items():
        if p != pid or f != fid:
            continue
        job = _JOBS.get(jid)
        if not job or job.get("status") != "running":
            continue
        if m == "both":
            modes.add("secondary")
            modes.add("rating")
        else:
            modes.add(m)
    return modes


def claim(pid: str, fid: str, mode: str, *, source: str = "manual") -> dict[str, Any]:
    mode = str(mode or "").strip().lower()
    if mode not in ("secondary", "rating", "both"):
        raise ValueError("mode")
    if _busy_for(pid, fid, mode):
        raise ReviewBusy()
    jid = uuid.uuid4().hex[:16]
    job = {
        "id": jid,
        "job_id": jid,
        "project_id": pid,
        "finding_id": fid,
        "mode": mode,
        "source": source,
        "status": "queued",
        "error": "",
        "detail": "排队，尚未拉起 Pi",
        "created_at": time.time(),
        "updated_at": time.time(),
        "started_at": 0.0,
    }
    _JOBS[jid] = job
    _ACTIVE[(pid, fid, mode)] = jid
    return dict(job)


def try_claim(pid: str, fid: str, mode: str, *, source: str = "auto") -> dict[str, Any] | None:
    try:
        return claim(pid, fid, mode, source=source)
    except ReviewBusy:
        return None


def release(job_id: str, *, status: str = "done", error: str = "") -> None:
    job = _JOBS.get(job_id)
    if not job:
        return
    job["status"] = status
    job["error"] = error or ""
    job["updated_at"] = time.time()
    key = (str(job.get("project_id") or ""), str(job.get("finding_id") or ""), str(job.get("mode") or ""))
    if _ACTIVE.get(key) == job_id:
        _ACTIVE.pop(key, None)


def _idle_lock(pid: str) -> asyncio.Lock:
    lock = _IDLE_LOCKS.get(pid)
    if lock is None:
        lock = asyncio.Lock()
        _IDLE_LOCKS[pid] = lock
    return lock


def live_hunt_agent(pid: str) -> Any | None:
    from atkbrain_native import hunt_manager as manager

    if not manager.is_running(pid):
        return None
    handle = manager.get(pid)
    agent = getattr(handle, "agent", None) if handle else None
    if agent is None or getattr(agent, "_stopped", False):
        return None
    return agent


async def _run_on_live(agent: Any, finding: dict, mode: str, job_id: str = "") -> None:
    await agent.review_one(finding, mode, job_id=job_id)


async def _run_idle(project: dict, finding: dict, mode: str, job_id: str = "") -> None:
    from atkbrain_native import run_review_job
    await asyncio.to_thread(run_review_job, project, finding, mode, job_id)


async def _execute(job_id: str, project: dict, finding: dict, mode: str) -> None:
    pid = str(project.get("id") or "")
    try:
        from atkbrain_native import run_review_job
        await asyncio.to_thread(run_review_job, project, finding, mode, job_id)
        release(job_id, status="done")
    except Exception as e:
        release(job_id, status="error", error=str(e)[:240])


_DRAINING: set[str] = set()
_DRAIN_SEM = asyncio.Semaphore(2)
# 同一条、同一种复核连续没写回库，就先搁下，换下一条。避免一条卡死整队。
REVIEW_ATTEMPT_CAP = 3


def review_attempt_key(fid: str, mode: str) -> tuple[str, str]:
    return (str(fid or ""), str(mode or "both"))


def review_attempt_open(attempts: dict[tuple[str, str], int], fid: str, mode: str) -> bool:
    key = review_attempt_key(fid, mode)
    try:
        n = int(attempts.get(key, 0) or 0)
    except (TypeError, ValueError):
        n = 0
    return n < REVIEW_ATTEMPT_CAP


def note_review_attempt(attempts: dict[tuple[str, str], int], fid: str, mode: str) -> int:
    key = review_attempt_key(fid, mode)
    try:
        n = int(attempts.get(key, 0) or 0) + 1
    except (TypeError, ValueError):
        n = 1
    attempts[key] = n
    return n


def schedule_drain(project: dict | None) -> None:
    """猎停后或启动时，把还没二次验证/没评级的漏洞一条条做完。不在关机时新开 Pi。"""
    if not isinstance(project, dict):
        return
    pid = str(project.get("id") or "")
    if not pid or pid in _DRAINING:
        return
    try:
        from atkbrain_native import hunt_manager as manager
        if getattr(manager, "shutting_down", False):
            return
    except Exception:
        return
    live = live_hunt_agent(pid)
    if live is not None:
        kick = getattr(live, "_kick_review", None)
        if callable(kick):
            try:
                kick()
            except Exception:
                pass
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    _DRAINING.add(pid)
    loop.create_task(_drain(project))


async def _drain(project: dict) -> None:
    from ..events import emit
    from atkbrain_native import findings_pending_review

    pid = str(project.get("id") or "")
    attempts: dict[tuple[str, str], int] = {}
    announced = False
    try:
        async with _DRAIN_SEM:
            while True:
                try:
                    from atkbrain_native import hunt_manager as manager
                    if getattr(manager, "shutting_down", False):
                        return
                except Exception:
                    pass
                live = live_hunt_agent(pid)
                if live is not None:
                    kick = getattr(live, "_kick_review", None)
                    if callable(kick):
                        try:
                            kick()
                        except Exception:
                            pass
                    return
                try:
                    pending = findings_pending_review(pid)
                except Exception:
                    return
                item = None
                mode = ""
                for f in pending:
                    fid = str(f.get("id") or "")
                    raw = str(f.get("_review_mode") or "both")
                    modes = ["secondary", "rating"] if raw == "both" else [raw]
                    picked = ""
                    for cand in modes:
                        if cand in ("secondary", "rating") and review_attempt_open(attempts, fid, cand):
                            picked = cand
                            break
                    if not fid or not picked:
                        continue
                    item = f
                    mode = picked
                    break
                if item is None or not mode:
                    return
                if not announced:
                    announced = True
                    try:
                        await emit(
                            pid, "log",
                            {"level": "info", "message": "猎面已停，未完成的二次验证会继续做到队列结束。"},
                        )
                    except Exception:
                        pass
                fid = str(item.get("id") or "")
                job = try_claim(pid, fid, mode, source="auto")
                if job is None:
                    note_review_attempt(attempts, fid, mode)
                    continue
                one = dict(item)
                one["_review_mode"] = mode
                one["_job_id"] = job["id"]
                try:
                    await _run_idle(project, one, mode, job["id"])
                    release(job["id"], status="done")
                except Exception as e:
                    release(job["id"], status="error", error=str(e)[:240])
                still = []
                try:
                    still = findings_pending_review(pid)
                except Exception:
                    still = []
                still_needs = False
                for row in still:
                    if str(row.get("id") or "") != fid:
                        continue
                    need = str(row.get("_review_mode") or "both")
                    if need == mode or need == "both":
                        still_needs = True
                if still_needs:
                    n = note_review_attempt(attempts, fid, mode)
                    if n >= REVIEW_ATTEMPT_CAP:
                        print(f"[review] {pid} {fid} {mode} 已试 {n} 次仍未写回，先验下一条")
    finally:
        _DRAINING.discard(pid)


async def resume_pending_reviews() -> None:
    """进程起来后，把空闲项目里没做完的复核接着做。正在跑的猎自己会拉起复核。"""
    await asyncio.sleep(3)
    try:
        from atkbrain_native import hunt_manager as manager
        if getattr(manager, "shutting_down", False):
            return
    except Exception:
        return
    from ..db import db
    from atkbrain_native import findings_pending_review
    from atkbrain_native import get_project

    try:
        rows = await db.fetchall("SELECT id, status FROM projects")
    except Exception:
        return
    for row in rows or []:
        if str(row.get("status") or "") == "running":
            continue
        pid = str(row.get("id") or "")
        if not pid:
            continue
        try:
            pending = findings_pending_review(pid)
        except Exception:
            continue
        if not pending:
            continue
        try:
            proj = get_project(pid)
        except Exception:
            proj = None
        if proj:
            schedule_drain(proj)


def start_manual(project: dict, finding: dict, mode: str) -> dict[str, Any]:
    pid = str(project.get("id") or "")
    fid = str(finding.get("id") or "")
    job = claim(pid, fid, mode, source="manual")
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_execute(job["id"], project, finding, mode))
    except RuntimeError:
        release(job["id"], status="error", error="no event loop")
        raise
    return snapshot(job["id"]) or job
