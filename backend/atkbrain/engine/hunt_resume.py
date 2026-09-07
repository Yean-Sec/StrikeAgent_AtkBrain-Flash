"""后端重启后续跑：只接回当时占槽的项目，不把集群 start_all 排队整表拉起来。"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from ..config import settings
from ..project_status import HUNT_FAILED_REASONS

RESUME_NAME = "hunt_resume.json"
_lock = threading.Lock()


def resume_path() -> Path:
    return Path(settings.data_dir) / RESUME_NAME


def _read_ids(path: Path) -> list[str]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    if isinstance(raw, dict):
        raw = raw.get("ids") or []
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        pid = str(item or "").strip()
        if pid and pid not in seen:
            seen.add(pid)
            out.append(pid)
    return out


def _write_ids(path: Path, ids: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"ids": ids}, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def remember_resume(pid: str) -> None:
    """进程被杀/重启时记下占槽项目，启动后接续。"""
    pid = str(pid or "").strip()
    if not pid:
        return
    path = resume_path()
    with _lock:
        ids = _read_ids(path)
        if pid not in ids:
            ids.append(pid)
        _write_ids(path, ids)


def forget_resume(pid: str) -> None:
    """人工暂停：不要在下次启动时自动拉起。"""
    pid = str(pid or "").strip()
    if not pid:
        return
    path = resume_path()
    with _lock:
        if not path.exists():
            return
        ids = [x for x in _read_ids(path) if x != pid]
        if ids:
            _write_ids(path, ids)
        else:
            try:
                path.unlink()
            except OSError:
                pass


def save_resume_ids(ids: list[str]) -> None:
    cleaned: list[str] = []
    seen: set[str] = set()
    for item in ids:
        pid = str(item or "").strip()
        if pid and pid not in seen:
            seen.add(pid)
            cleaned.append(pid)
    path = resume_path()
    with _lock:
        if cleaned:
            _write_ids(path, cleaned)
        elif path.exists():
            try:
                path.unlink()
            except OSError:
                pass


def take_resume_ids() -> list[str]:
    """读完即删，避免下次启动误拉。"""
    path = resume_path()
    with _lock:
        ids = _read_ids(path)
        try:
            path.unlink()
        except OSError:
            pass
        return ids


def pick_resume_ids(*, db_running: list[str], saved: list[str], cap: int = 0) -> list[str]:
    """优雅退出清单优先，再补 DB 里仍标 running 的（SIGKILL 来不及写文件）。cap<=0 表示不截断。"""
    out: list[str] = []
    seen: set[str] = set()
    for pid in [*(saved or []), *(db_running or [])]:
        pid = str(pid or "").strip()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
        if cap > 0 and len(out) >= cap:
            break
    return out


def should_autoresume(project: dict | None) -> bool:
    if not isinstance(project, dict):
        return False
    if project.get("kind") == "cluster":
        return False
    if project.get("status") in ("completed", "error"):
        return False
    cfg = project.get("config") or {}
    if not isinstance(cfg, dict):
        cfg = {}
    if cfg.get("env_closed"):
        return False
    if cfg.get("completion_reason") in ("env_closed", "env_unreachable"):
        return False
    if cfg.get("completion_reason") in HUNT_FAILED_REASONS:
        return False
    if cfg.get("completion_reason") == "runtime_review_stop":
        return False
    try:
        from ..objective import ctf_full_score, objective_allows_flag
        if objective_allows_flag(cfg.get("objective") or cfg.get("track")):
            bm = cfg.get("benchmark") if isinstance(cfg.get("benchmark"), dict) else {}
            got = int(bm.get("correct_flag_count") or 0)
            if got > 0 and ctf_full_score(flags_correct=got, flag_count=cfg.get("flag_count")):
                return False
    except Exception:
        pass
    return True


def cancel_project_status(
    *,
    user_stop: bool,
    handle_status: str,
    slot_held: bool,
) -> str | None:
    """CancelledError 后的项目状态。None=不动（被替换的僵尸句柄）。"""
    if handle_status == "zombie":
        return None
    if user_stop or handle_status == "stopping":
        return "idle"
    if slot_held:
        return "running"
    return None


async def start_saved_hunts(manager, db_running: list[str]) -> list[str]:
    """启动时把上次占槽的项目拉起来，数量不超过当前并发上限。"""
    from ..projects import get_project, update_status

    saved = take_resume_ids()
    cap = max(1, int(getattr(getattr(manager, "project_sem", None), "limit", 5) or 5))
    picked: list[str] = []
    idle_ids: list[str] = []
    for pid in pick_resume_ids(db_running=db_running, saved=saved, cap=0):
        try:
            proj = await get_project(pid)
        except Exception:
            proj = None
        if not should_autoresume(proj):
            if (proj or {}).get("status") == "running":
                idle_ids.append(pid)
            continue
        parent_id = (proj or {}).get("parent_id")
        if parent_id:
            try:
                parent = await get_project(parent_id)
            except Exception:
                parent = None
            pcfg = (parent or {}).get("config") or {}
            if isinstance(pcfg, dict) and (
                pcfg.get("env_closed")
                or pcfg.get("completion_reason") in ("env_closed", "env_unreachable")
            ):
                idle_ids.append(pid)
                continue
        if len(picked) >= cap:
            idle_ids.append(pid)
            continue
        picked.append(pid)
    for pid in db_running:
        if pid not in picked and pid not in idle_ids:
            idle_ids.append(pid)
    for pid in idle_ids:
        try:
            await update_status(pid, "idle")
        except Exception:
            pass
    for pid in picked:
        try:
            manager.start(pid, hard_restart=False)
        except Exception as e:
            print(f"[startup] 续跑 {pid} 失败：{e}")
            try:
                await update_status(pid, "idle")
            except Exception:
                pass
    return picked

