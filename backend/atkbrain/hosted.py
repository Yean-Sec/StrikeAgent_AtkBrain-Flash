"""托管运行：容器启动后自行拉题开打。"""
from __future__ import annotations

from .llm_gateway import hosted_enabled


def hosted_focus_codes() -> list[str]:
    """启动时限题列表。空=全量。题号来自环境变量，不写进源码。"""
    from .benchmark import parse_focus_codes
    from .config import settings

    return parse_focus_codes(getattr(settings, "benchmark_focus_codes", "") or "")


def hosted_parent_extra() -> dict:
    extra = {"autopilot": True, "track": "ctf", "objective": "flag"}
    focus = hosted_focus_codes()
    if focus:
        extra["focus_codes"] = focus
    return extra


async def _apply_focus_to_parent(parent_id: str) -> None:
    """复用已有父项目时，把当前环境变量里的 focus 写进 config。"""
    focus = hosted_focus_codes()
    if not focus:
        return
    from .projects import get_project, update_config

    parent = await get_project(parent_id)
    if not parent:
        return
    cfg = dict(parent.get("config") or {})
    if parse_focus_equal(cfg.get("focus_codes"), focus):
        return
    cfg["focus_codes"] = focus
    await update_config(parent_id, cfg)
    print(f"[startup] hosted：限题 {len(focus)} 道 unique_code")


def parse_focus_equal(current, wanted: list[str]) -> bool:
    from .benchmark import parse_focus_codes

    return parse_focus_codes(current) == list(wanted or [])


async def ensure_hosted_benchmark() -> dict | None:
    """ATKBRAIN_HOSTED=1 且已注入答题 API 时，确保存在 autopilot 评测父项目。"""
    if not hosted_enabled():
        return None
    from .config import settings
    from .db import db
    from .projects import create_benchmark_project

    base = (settings.benchmark_base_url or "").strip()
    token = (settings.benchmark_token or "").strip()
    if not base or not token:
        print("[startup] hosted：尚未注入 BENCHMARK_BASE_URL / BENCHMARK_TOKEN，无法自动开打")
        return None
    rows = await db.fetchall(
        "SELECT id FROM projects WHERE kind='benchmark' AND parent_id IS NULL ORDER BY created_at"
    )
    if rows:
        pid = str(rows[0]["id"])
        try:
            await _apply_focus_to_parent(pid)
        except Exception as e:
            print(f"[startup] hosted：写入 focus_codes 失败：{e}")
        print(f"[startup] hosted：复用评测项目 {pid}")
        return None
    extra = hosted_parent_extra()
    proj = await create_benchmark_project(
        "StrikeAgent_AtkBrain-Flash",
        base,
        token,
        extra,
    )
    focus = extra.get("focus_codes") or []
    if focus:
        print(
            f"[startup] hosted：已创建评测项目 {proj['id']}，"
            f"限题 {len(focus)} 道，autopilot 即将开打"
        )
    else:
        print(f"[startup] hosted：已创建评测项目 {proj['id']}，autopilot 即将拉题开打")
    return proj
