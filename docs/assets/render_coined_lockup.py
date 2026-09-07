#!/usr/bin/env python3
"""Render the coined-term lockup GIF: 自循环 / 机械换路."""
from __future__ import annotations

import math
import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1000, 360
SCALE = 2
FPS = 12
DURATION = 6.0
NFRAMES = int(FPS * DURATION)

CANVAS = (250, 249, 245, 255)
INK = (20, 20, 19, 255)
MUTED = (108, 106, 100, 255)
SOFT = (142, 139, 130, 255)
HAIR = (230, 223, 216, 255)
PRIMARY = (204, 120, 92, 255)
PRIMARY_DIM = (204, 120, 92, 90)

SERIF = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc"
SERIF_R = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc"
LATO = "/usr/share/fonts/truetype/lato/Lato-Regular.ttf"
LATO_L = "/usr/share/fonts/truetype/lato/Lato-Light.ttf"
LATO_B = "/usr/share/fonts/truetype/lato/Lato-Bold.ttf"
SC = 2

TERMS = [
    ("01", "自", "循环", "SELF-LOOP"),
    ("02", "机械", "换路", "MECHANICAL PIVOT"),
]


def font(path: str, size: int, index: int | None = None) -> ImageFont.FreeTypeFont:
    kw = {"index": index} if index is not None else {}
    return ImageFont.truetype(path, size * SCALE, **kw)


def mix(a, b, t: float):
    t = max(0.0, min(1.0, t))
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(4))


def ease(t: float) -> float:
    t = max(0.0, min(1.0, t))
    return t * t * (3 - 2 * t)


def tracked_width(text: str, fnt, tracking: int) -> float:
    total = 0.0
    for i, ch in enumerate(text):
        b = fnt.getbbox(ch)
        total += b[2] - b[0]
        if i < len(text) - 1:
            total += tracking
    return total


def draw_tracked(draw, text, cx, y, fnt, fill, tracking: int = 0):
    x = cx - tracked_width(text, fnt, tracking) / 2
    for i, ch in enumerate(text):
        b = fnt.getbbox(ch)
        draw.text((x - b[0], y), ch, font=fnt, fill=fill)
        x += (b[2] - b[0]) + (tracking if i < len(text) - 1 else 0)


def draw_pair(draw, cx, y, zi, rest, fnt, c_zi, c_rest):
    w_zi = fnt.getbbox(zi)
    w_rest = fnt.getbbox(rest)
    total = (w_zi[2] - w_zi[0]) + (w_rest[2] - w_rest[0])
    x = cx - total / 2
    draw.text((x - w_zi[0], y), zi, font=fnt, fill=c_zi)
    x += w_zi[2] - w_zi[0]
    draw.text((x - w_rest[0], y), rest, font=fnt, fill=c_rest)


def active_index(t: float) -> tuple[int, float]:
    slot = DURATION / max(1, len(TERMS))
    i = min(len(TERMS) - 1, int(t / slot))
    local = (t - i * slot) / slot
    if local < 0.82:
        enter = 1.0
    else:
        enter = ease((1.0 - local) / 0.18)
    return i, enter


def render_frame(t: float) -> Image.Image:
    img = Image.new("RGBA", (W * SCALE, H * SCALE), CANVAS)
    d = ImageDraw.Draw(img)
    cx = W * SCALE / 2
    act, enter = active_index(t)
    cols = [0.34, 0.66]
    col_x = [W * SCALE * x for x in cols]

    f_kicker = font(LATO, 11)
    f_claim = font(SERIF_R, 15, SC)
    f_num = font(LATO_L, 11)
    f_zh = font(SERIF, 44, SC)
    f_en = font(LATO, 13)
    f_foot = font(LATO_L, 11)

    draw_tracked(
        d, "STRIKEAGENT-ATKBRAIN-FLASH", cx, 36 * SCALE, f_kicker,
        mix(SOFT, PRIMARY, 0.55 + 0.45 * math.sin(t * math.pi * 2 / DURATION) ** 2),
        tracking=3 * SCALE,
    )
    draw_tracked(d, "本项目提出", cx, 58 * SCALE, f_claim, INK, tracking=3 * SCALE)

    y_line = 92 * SCALE
    d.line((cx - 120 * SCALE, y_line, cx + 120 * SCALE, y_line), fill=HAIR, width=SCALE)

    for i, (num, zi, rest, en) in enumerate(TERMS):
        x = col_x[i]
        on = i == act
        weight = 0.42 + 0.58 * enter if on else 0.52
        c_body = mix(SOFT, INK, weight)
        c_zi = mix(c_body, PRIMARY, 0.15 + 0.85 * enter) if on else c_body
        c_en = mix(SOFT, PRIMARY, enter) if on else SOFT
        c_num = mix(SOFT, PRIMARY, enter) if on else SOFT
        y_lift = -6 * SCALE * enter if on else 0

        draw_tracked(d, num, x, (118 * SCALE) + y_lift, f_num, c_num, tracking=3 * SCALE)
        draw_pair(d, x, (148 * SCALE) + y_lift, zi, rest, f_zh, c_zi, c_body)
        draw_tracked(d, en, x, (214 * SCALE) + y_lift, f_en, c_en, tracking=4 * SCALE)

        if on:
            uw = 72 * SCALE + 36 * SCALE * enter
            uy = 252 * SCALE + y_lift
            d.line((x - uw / 2, uy, x + uw / 2, uy), fill=mix(PRIMARY_DIM, PRIMARY, enter), width=2 * SCALE)

    draw_tracked(
        d,
        "Self-Loop  ·  Mechanical Pivot",
        cx,
        300 * SCALE,
        f_foot,
        mix(SOFT, MUTED, 0.7),
        tracking=2 * SCALE,
    )
    return img.resize((W, H), Image.Resampling.LANCZOS)


def main() -> None:
    out_dir = Path("/tmp/coined-lockup-frames")
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    paths = []
    for i in range(NFRAMES):
        t = i / FPS
        frame = render_frame(t).convert("P", palette=Image.Palette.ADAPTIVE, colors=64)
        p = out_dir / f"f{i:03d}.png"
        frame.save(p, optimize=True)
        paths.append(p)
        print(f"frame {i+1}/{NFRAMES}", flush=True)
    dest = Path(__file__).resolve().parent / "coined-lockup.gif"
    import subprocess

    subprocess.check_call(
        [
            "magick",
            "-delay",
            "8",
            "-loop",
            "0",
            *[str(p) for p in paths],
            "-fuzz",
            "4%",
            "-layers",
            "optimize",
            str(dest),
        ]
    )
    print("wrote", dest, "bytes", dest.stat().st_size)


if __name__ == "__main__":
    main()
