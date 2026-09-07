"""同源 PDF：HTML 原样下载；仅在转 PDF 前于内存中适配。"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

WIDE_CSS = """
@media print, all {
  @page { size: 1280px 1810px; margin: 28px 36px 40px 36px; }
  html, body {
    print-color-adjust: exact;
    -webkit-print-color-adjust: exact;
  }
  .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .kpis { grid-template-columns: repeat(4, 1fr) !important; }
  .sum-grid, .charts, .fix-grid { grid-template-columns: 1fr 1fr !important; }
  .assets { grid-template-columns: repeat(3, 1fr) !important; }
  .path-row { flex-wrap: nowrap !important; }
  details.ev > *:not(summary) { display: block !important; }
}
"""


def adapt_html_for_pdf(html: str) -> str:
    """内存副本：展开证据、去掉点击提示、注入宽版分页。不写回 HTML 文件。"""
    out = html.replace("<details>", "<details open>")
    out = out.replace("<details ", "<details open ")
    out = out.replace("（点击展开）", "")
    out = out.replace("（点击折叠）", "")
    if "</style>" in out:
        out = out.replace("</style>", WIDE_CSS + "\n</style>", 1)
    else:
        out = out.replace("</head>", f"<style>{WIDE_CSS}</style></head>", 1)
    return out


def _chromium_bin() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        p = shutil.which(name)
        if p:
            return p
    return None


def chromium_pdf(html: str) -> bytes | None:
    binary = _chromium_bin()
    if not binary:
        return None
    with tempfile.TemporaryDirectory(prefix="atkbrain-pdf-") as td:
        src = Path(td) / "report.html"
        dest = Path(td) / "report.pdf"
        src.write_text(html, encoding="utf-8")
        cmd = [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--allow-file-access-from-files",
            "--no-pdf-header-footer",
            f"--print-to-pdf={dest}",
            "--virtual-time-budget=12000",
            src.as_uri(),
        ]
        try:
            subprocess.run(cmd, check=True, timeout=120, capture_output=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return None
        if dest.exists() and dest.stat().st_size > 100:
            return dest.read_bytes()
    return None


def weasy_pdf(html: str) -> bytes | None:
    try:
        from weasyprint import HTML as _WeasyHTML  # type: ignore
    except Exception:
        return None
    try:
        return _WeasyHTML(string=html).write_pdf()
    except Exception:
        return None


def html_to_pdf(html: str) -> bytes:
    adapted = adapt_html_for_pdf(html)
    pdf = chromium_pdf(adapted)
    if pdf:
        return pdf
    pdf = weasy_pdf(adapted)
    if pdf:
        return pdf
    raise RuntimeError("PDF 引擎不可用：未找到 Chromium，且 WeasyPrint 失败")
