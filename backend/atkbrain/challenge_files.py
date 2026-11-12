"""CTF 题目附件：落在项目 workspace/challenge，并抄给集群子项目。"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from .config import settings
from .db import db
from atkbrain_native import get_project, update_config

MAX_CHALLENGE_BYTES = 80 * 1024 * 1024
MAX_CHALLENGE_FILES = 20
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,180}$")
_EXT = frozenset({
    "zip", "tar", "gz", "tgz", "7z", "rar",
    "php", "html", "htm", "js", "jsx", "ts", "json", "txt", "xml", "yml", "yaml",
    "sql", "war", "jar", "py", "rb", "go", "java", "asp", "aspx", "jsp", "css", "md", "csv",
    "elf", "so", "bin", "exe", "dll", "apk", "dex", "class", "pyc", "out",
    "png", "jpg", "jpeg", "gif", "bmp", "wav", "mp3", "mp4", "pdf", "svg",
    "pcap", "pcapng", "cap",
    "pem", "pub", "key", "enc", "sage",
    "doc", "docx", "ppt", "pptx", "xls", "xlsx",
})


def challenge_dir(project_id: str) -> Path:
    return Path(settings.workspaces_dir) / project_id / "challenge"


def safe_challenge_name(raw: str) -> str:
    """只保留文件名。无后缀的二进制允许；其它必须在题型附件后缀里。"""
    name = os.path.basename(str(raw or "").replace("\\", "/")).strip().replace("\x00", "")
    name = name.lstrip(".")
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("文件名无效")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    if not name or not _NAME_RE.fullmatch(name):
        raise ValueError("文件名无效")
    parts = [part.lower() for part in name.split(".")[1:]]
    if parts and not any(part in _EXT for part in parts):
        raise ValueError(f"不支持的附件类型 .{parts[-1]}")
    return name


def _unique_path(dest: Path, name: str) -> Path:
    path = dest / name
    if not path.exists():
        return path
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    else:
        ext = "." + ext
    n = 2
    while True:
        candidate = dest / f"{stem}_{n}{ext}"
        if not candidate.exists():
            return candidate
        n += 1


async def _set_attachment_names(project_id: str, names: list[str]) -> None:
    project = get_project(project_id)
    if not project:
        return
    cfg = dict(project.get("config") or {})
    cfg["attachments"] = list(names)
    update_config(project_id, cfg)


def _list_files(project_id: str) -> list[Path]:
    folder = challenge_dir(project_id)
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file() and not p.name.startswith("."))


async def copy_challenge_files(src_id: str, dst_id: str) -> list[str]:
    """把父项目附件抄到子项目。父目录没有文件时不动子项目。"""
    if not src_id or not dst_id or src_id == dst_id:
        return []
    files = _list_files(src_id)
    if not files:
        return []
    dest = challenge_dir(dst_id)
    dest.mkdir(parents=True, exist_ok=True)
    names: list[str] = []
    for src in files:
        target = dest / src.name
        if not target.exists() or target.stat().st_size != src.stat().st_size:
            shutil.copyfile(src, target)
        names.append(src.name)
    await _set_attachment_names(dst_id, names)
    return names


async def save_challenge_uploads(project_id: str, uploads: list[tuple[str, bytes]]) -> list[str]:
    """写入附件，并抄给已经生成的子项目。"""
    if not uploads:
        raise ValueError("请选择附件")
    existing = _list_files(project_id)
    if len(existing) + len(uploads) > MAX_CHALLENGE_FILES:
        raise ValueError(f"附件最多 {MAX_CHALLENGE_FILES} 个")
    dest = challenge_dir(project_id)
    dest.mkdir(parents=True, exist_ok=True)
    for filename, data in uploads:
        if len(data) > MAX_CHALLENGE_BYTES:
            raise ValueError(f"{filename or '附件'} 超过 80MB")
        name = safe_challenge_name(filename)
        path = _unique_path(dest, name)
        path.write_bytes(data)
    names = [p.name for p in _list_files(project_id)]
    await _set_attachment_names(project_id, names)
    rows = await db.fetchall("SELECT id FROM projects WHERE parent_id=?", (project_id,))
    for row in rows or []:
        child = row["id"] if not isinstance(row, dict) else row.get("id")
        if child:
            await copy_challenge_files(project_id, str(child))
    return names
