"""本仓库猎面专用的 Claude Code skills。

源文件在仓库根 `.claude/skills/`（进 git）。会话启动时按赛道拷进该猎工作区
`backend/data/workspaces/<pid>/.claude/skills/`。不写 `~/.claude`。
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..config import REPO_ROOT
from ..objective import objective_allows_flag, objective_is_src

SKILLS_ROOT = REPO_ROOT / ".claude" / "skills"
SHARED_SKILLS = ("kali-kit",)
CTF_SKILLS = ("recon-fanout",)
REDTEAM_SKILLS = ("recon-spiral",)
SRC_SKILLS = ("src-hunt-playbook",)


def skill_names(*, objective: str | None = None) -> list[str]:
    if not SKILLS_ROOT.is_dir():
        return []
    if objective is None:
        names: list[str] = []
        for p in sorted(SKILLS_ROOT.iterdir()):
            if p.is_dir() and (p / "SKILL.md").is_file():
                names.append(p.name)
        return names
    if objective_allows_flag(objective):
        extra = CTF_SKILLS
    elif objective_is_src(objective):
        extra = SRC_SKILLS
    else:
        extra = REDTEAM_SKILLS
    wanted = (*SHARED_SKILLS, *extra)
    return [n for n in wanted if (SKILLS_ROOT / n / "SKILL.md").is_file()]


def _materialize_kali_kit(dst_root: Path) -> None:
    """用当前仓库根生成 kali-kit，保证 JSFinder / bypass-403 绝对路径正确。"""
    from .kali_kit import skill_markdown
    dest = dst_root / "kali-kit"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "SKILL.md").write_text(skill_markdown(), encoding="utf-8")


def install_into_workspace(workspace: str | Path, *, objective: str | None = None) -> list[str]:
    """把本赛道 skill 拷到猎面工作区，返回名称供 ClaudeAgentOptions.skills。"""
    names = skill_names(objective=objective)
    dst_root = Path(workspace) / ".claude" / "skills"
    try:
        dst_root.mkdir(parents=True, exist_ok=True)
        wanted = set(names)
        for extra in list(dst_root.iterdir()):
            if extra.is_dir() and extra.name not in wanted:
                shutil.rmtree(extra, ignore_errors=True)
        for name in names:
            src = SKILLS_ROOT / name
            dst = dst_root / name
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=True)
        if "kali-kit" in wanted:
            _materialize_kali_kit(dst_root)
    except OSError:
        pass
    return names
