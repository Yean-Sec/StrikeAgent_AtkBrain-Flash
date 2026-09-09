"""全局配置。环境变量前缀 ATKBRAIN_。"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from .llm_gateway import (
    apply_llm_gateway,
    apply_platform_env_aliases,
    gateway_enabled,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPO_ROOT = BASE_DIR.parent

# 平台托管注入 BENCHMARK_*（无前缀）；必须在 Settings() 之前别名。
apply_platform_env_aliases()
if gateway_enabled():
    _gw = apply_llm_gateway()
    if _gw:
        print("[config] LLM API 已改写为 tsecbench 网关: " + ", ".join(sorted(_gw)))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATKBRAIN_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 5003
    frontend_port: int = 5001

    data_dir: Path = DATA_DIR
    db_path: Path = DATA_DIR / "atkbrain.db"
    workspaces_dir: Path = DATA_DIR / "workspaces"
    loot_dir: Path = DATA_DIR / "loot"
    reports_dir: Path = DATA_DIR / "reports"

    max_redteam_concurrency: int = 5           # 红队/SRC 默认同时猎数；上限 20，与 CTF 互不占槽
    max_redteam_concurrency_cap: int = 20
    max_ctf_concurrency: int = 3               # CTF 默认同时猎数；上限 20，不是 3
    max_ctf_concurrency_cap: int = 20
    max_project_concurrency: int = 5           # 旧名，等同红队默认
    max_project_concurrency_cap: int = 20
    max_concurrency: int = 16                  # 默认展示：红队 5 + CTF 3，每项目 2 路编排
    max_concurrency_cap: int = 80              # (红队 cap 20 + CTF cap 20) × 2

    # 从者 + 御主各一路编排会话；从者派出的 Task 子智能体不占这道闸、不设上限。
    claude_per_project: int = 2
    claude_per_project_cap: int = 2
    claude_spawn_max_concurrent: int = 20
    claude_spawn_jitter_max_sec: float = 0.0
    claude_spawn_settle_ms: int = 0
    claude_connect_retries: int = 4
    claude_add_repo_dir: bool = False

    loop_max_turns: int = 0           # CTF 不限轮次（含评测）；停猎看墙钟 / 图空转
    loop_max_turns_src: int = 30      # SRC：第 30 轮必须停，记失败
    src_runtime_hard_stop_sec: int = 3 * 60 * 60  # SRC：180 分钟墙钟硬停
    loop_max_turns_benchmark: int = 0  # 已弃用：评测 CTF 不走轮次硬停
    loop_stall_limit: int = 10
    loop_stall_limit_flag: int = 0     # CTF：不走「连续 N 轮无进展」暂停，改看 6 个空方案
    loop_spiral_empty_plans: int = 6  # 红队：连续这么多御主方案无高质量增长才升圈
    # 换路监督：连续 N 轮无高质量进展 → 软转向（method/chain）；再加重 → 硬空转可打断 hold。
    # 与红队/SRC 同一套门闩；CTF 只换赛道目标和时长。暂停本猎看 loop_stall_limit。
    loop_supervise_soft_turns: int = 3
    loop_supervise_hard_turns: int = 10
    # 旧开口闸：现改为每轮必问御主。保留以免外部配置报未知项。
    advisor_first_turns: int = 2
    # 旧周期闸，开口不再按轮次取模；保留以免外部配置报未知项。
    advisor_min_turn_interval: int = 3
    # 御主注入非 noop 指令后，运行时审查仍用此窗口判断验证是否做完。
    # 硬空转（no_progress≥loop_supervise_hard_turns 且 method/chain）才允许提前打断。赛道无关。
    advisor_hold_turns: int = 3
    # 未验证路线包连续未执行这么多次 → 作废旧绑定，御主按全局重开多路线。收成走廊不刷新。
    advisor_bind_refresh_misses: int = 3
    supervisor_model: str = ""
    # 御主一次性 Claude Code 总等待（冷启动 CLI + 生成 + 重试）。到点从者自走。
    supervisor_timeout_sec: int = 360
    # 御主问 Claude Code：0=在总墙钟内一直重试；>0 时次数与墙钟谁先到谁停。
    supervisor_consult_max_attempts: int = 0
    supervisor_consult_retry_base_sec: float = 4.0
    supervisor_cooldown_sec: float = 8.0
    supervisor_fail_cooldown_sec: float = 0.0
    # 一份监督方案至少经过这么多「有工具」的御主回合（旧 dwell；主门闩已改 advisor_hold_turns）。
    supervisor_plan_dwell_turns: int = 2
    # 连续这么多回合无有效进展才再问顾问（旧闸；主门闩已改 stall_class + advisor_min_turn_interval）。
    supervisor_consult_stall_turns: int = 2
    evolve_ai: bool = True
    evolve_model: str = ""
    evolve_timeout_sec: int = 90
    report_ai: bool = True
    report_model: str = ""
    report_timeout_sec: int = 90
    turn_max_agent_turns: int = 60
    turn_max_seconds: int = 0          # 0=单轮不限时（整场墙钟仍生效）
    # 不中途打断从者。0=关闭中途让出（默认）。360s 只卡等御主令。
    turn_advisor_yield_sec: int = 0
    # 回合内无思考/工具/命令才当会话卡死；不是顾问让出，也不卡长命令。
    turn_hang_sec: int = 8 * 60
    cmd_timeout: int = 0               # 0=单条命令不限时
    graph_idle_pause_sec: int = 0                    # CTF：不再按墙钟判图空转（改看方案数）
    graph_idle_empty_plans: int = 6                  # CTF：连续这么多御主方案无新节点/交旗/本地长计算 → 失败
    graph_idle_cmd_progress_sec: int = 60            # 成功 run_cmd 达此时长视为图仍在推进
    runtime_review_after_sec: int = 0                # CTF：不再做御主运行时审查
    runtime_review_interval_sec: int = 0
    runtime_hard_stop_sec: int = 40 * 60             # CTF 第 1 遍：40 分钟强制停止
    runtime_hard_stop_pass2_sec: int = 120 * 60      # CTF 第 2 遍（回头啃未出/未齐 flag）
    runtime_hard_stop_pass3_sec: int = 180 * 60      # CTF 第 3 遍
    runtime_hard_stop_pass_step_sec: int = 60 * 60   # 第 4 遍起每次再加 60 分钟
    redteam_runtime_hard_stop_sec: int = 4 * 60 * 60 # 红队：4 小时强制停止
    entry_unreachable_yield_sec: int = 0

    claude_model: str = "sonnet"
    claude_fallback_model: str = "haiku"
    claude_bin: str = os.environ.get("ATKBRAIN_CLAUDE_BIN", "claude")

    default_objective: str = "getshell"
    api_token: str = ""

    benchmark_base_url: str = ""
    benchmark_token: str = ""
    # 评测父项目同时开打的子题数。默认 3；上限与红队相同 20，由顶栏 CTF 并发调节。
    benchmark_max_concurrency: int = 3
    benchmark_max_concurrency_cap: int = 20
    benchmark_run_budget_sec: int = 0
    benchmark_run_budget_cap: int = 0
    benchmark_autopilot: bool = True
    benchmark_autopilot_interval_sec: int = 15
    benchmark_autopilot_resume: bool = False
    benchmark_no_flag_rotate_sec: int = 0
    # 第二遍 0 flag：0=不提前让槽，打到该遍墙钟硬上限。hard 不再另加时长。
    benchmark_hard_no_flag_rotate_sec: int = 0
    # 覆盖期：每道本轮最多占槽这么久（含部分正确 flag；不按平台满分卡死）。与第 1 遍硬停对齐。
    benchmark_first_pass_dwell_sec: int = 40 * 60
    # 与 first_pass 对齐：排队再长也不把覆盖预算往下压（短会话会把「开过」记脏）。
    benchmark_coverage_dwell_floor_sec: int = 40 * 60
    # 覆盖期未到本遍硬顶时：图闲置至少这么久才切。到硬顶一律让槽。
    benchmark_coverage_grow_grace_sec: int = 8 * 60
    # 短于此时长的 launch→close 不算一次真正 attempt（避免空会话饿死未开过的题）。
    benchmark_min_attempt_sec: int = 120
    # 0 分猎未满此时长时，空回合/会话故障只重建会话，不关容器让槽。
    benchmark_min_hunt_sec: int = 180
    # start 后等入口 TCP 就绪的上限；0 表示不等。
    benchmark_entry_ready_sec: int = 45
    # 连续这么多 tick 空槽且仍有未开题 → 打看门狗日志（tick 本身仍会 start）。
    benchmark_watchdog_idle_ticks: int = 3
    lab_src_rotate_sec: int = 60 * 60
    benchmark_entry_down_rebind_sec: int = 90
    benchmark_entry_down_yield_sec: int = 8 * 60
    redteam_entry_down_yield_sec: int = 8 * 60
    benchmark_autopilot_second_pass: bool = True
    benchmark_max_attempts: int = 8
    benchmark_multiflag_threshold: int = 3
    benchmark_max_multiflag_concurrent: int = 1
    # 只打这些 unique_code（逗号分隔）。空=全量。托管分阶段冒烟用，不写死题号。
    benchmark_focus_codes: str = ""

    def ensure_dirs(self) -> None:
        for p in [self.data_dir, self.workspaces_dir, self.loot_dir, self.reports_dir]:
            Path(p).mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()


def benchmark_slot_limit() -> int:
    """CTF / 评测同时开打的子题数。默认 3，上限 20，与顶栏 CTF 并发同一道闸。"""
    try:
        n = int(getattr(settings, "benchmark_max_concurrency", 3) or 3)
    except (TypeError, ValueError):
        n = 3
    try:
        cap = int(getattr(settings, "max_ctf_concurrency_cap", None)
                  or getattr(settings, "benchmark_max_concurrency_cap", 20) or 20)
    except (TypeError, ValueError):
        cap = 20
    if cap <= 0:
        cap = 20
    return max(1, min(n, cap))
