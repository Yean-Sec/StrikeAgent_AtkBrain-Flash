"""渲染每项目的 Cordis 组合：写入绝对插件路径。"""
from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).resolve().parent
PLUGIN = _DIR / "atkbrain-tools.js"
TEMPLATE = _DIR / "pentest.cordis.yml"


def render_cordis(dest: Path | str) -> Path:
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("__ATKBRAIN_TOOLS_PLUGIN__", str(PLUGIN.resolve()))
    dest.write_text(text, encoding="utf-8")
    return dest
