#!/usr/bin/env python3
"""Render the README architecture diagram (cream / terracotta)."""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1400, 1120
SCALE = 2
OUT = Path(__file__).with_name("architecture.png")

BG = (250, 249, 245, 255)
INK = (20, 20, 19, 255)
MUTED = (108, 106, 100, 255)
SOFT = (142, 139, 130, 255)
HAIR = (230, 223, 216, 255)
CARD = (255, 254, 252, 255)
PRIMARY = (204, 120, 92, 255)
PRIMARY_DIM = (204, 120, 92, 36)

SERIF_B = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc"
SERIF_R = "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc"
LATO = "/usr/share/fonts/truetype/lato/Lato-Regular.ttf"
LATO_B = "/usr/share/fonts/truetype/lato/Lato-Bold.ttf"
LATO_L = "/usr/share/fonts/truetype/lato/Lato-Light.ttf"


def font(path: str, size: int, index: int | None = None) -> ImageFont.FreeTypeFont:
    kw = {"index": index} if index is not None else {}
    try:
        return ImageFont.truetype(path, size * SCALE, **kw)
    except OSError:
        return ImageFont.load_default()


def rr(d: ImageDraw.ImageDraw, xy, r, fill=None, outline=None, width=1):
    d.rounded_rectangle(xy, radius=r * SCALE, fill=fill, outline=outline, width=width * SCALE)


def tx(d, xy, text, fnt, fill=INK, anchor="lt"):
    d.text(xy, text, font=fnt, fill=fill, anchor=anchor)


def arrow_down(d, x, y0, y1):
    d.line([(x, y0), (x, y1 - 10 * SCALE)], fill=PRIMARY, width=2 * SCALE)
    d.polygon(
        [(x, y1), (x - 6 * SCALE, y1 - 10 * SCALE), (x + 6 * SCALE, y1 - 10 * SCALE)],
        fill=PRIMARY,
    )


def main() -> None:
    im = Image.new("RGBA", (W * SCALE, H * SCALE), BG)
    d = ImageDraw.Draw(im)
    f_kicker = font(LATO_B, 11)
    f_title = font(SERIF_B, 28)
    f_sub = font(SERIF_R, 13)
    f_h = font(SERIF_B, 15)
    f_en = font(LATO, 10)
    f_body = font(SERIF_R, 12)
    f_small = font(SERIF_R, 11)
    f_num = font(LATO_B, 10)

    S = SCALE
    # header
    tx(d, (W * S / 2, 36 * S), "STRIKEAGENT-ATKBRAIN", f_kicker, PRIMARY, "mt")
    tx(d, (W * S / 2, 68 * S), "架构", f_title, INK, "mt")
    tx(
        d,
        (W * S / 2, 108 * S),
        "控制台调度猎面 · 攻击图自循环 · 监督出方案 · 收工蒸馏进下一局",
        f_sub,
        MUTED,
        "mt",
    )
    d.line([(520 * S, 128 * S), (880 * S, 128 * S)], fill=HAIR, width=S)

    # layer: console
    rr(d, (40 * S, 148 * S, 1360 * S, 268 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 164 * S), "01  控制台", f_h, INK)
    tx(d, (180 * S, 168 * S), "Vite  :5001", f_en, MUTED)
    chips = [
        (70, "项目  单目标 / 集群 / 评测"),
        (330, "猎面  攻击图 · 时间线 · 漏洞 · 对话"),
        (700, "交付报告"),
        (880, "人工 steering"),
        (1080, "设置 · 并发"),
    ]
    for x, label in chips:
        rr(d, (x * S, 200 * S, (x + 230 if x != 330 else x + 340) * S, 244 * S), 6, PRIMARY_DIM, None, 0)
        tx(d, ((x + 12) * S, 222 * S), label, f_small, INK, "lm")

    arrow_down(d, 700 * S, 268 * S, 292 * S)

    # layer: api
    rr(d, (40 * S, 292 * S, 1360 * S, 400 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 308 * S), "02  API 与调度", f_h, INK)
    tx(d, (220 * S, 312 * S), "FastAPI  :5003", f_en, MUTED)
    api = [
        (70, 240, "REST  项目 / 图 / 发现 / 报告 / 记忆"),
        (340, 260, "WebSocket  轮次事件推到控制台"),
        (630, 280, "RunManager  默认 10 项目 × 2 路 Claude"),
        (940, 280, "Hunt clock  空转 / 挂起 / 硬停止"),
    ]
    for x, w, label in api:
        rr(d, (x * S, 344 * S, (x + w) * S, 380 * S), 6, (247, 244, 240, 255), HAIR, 1)
        tx(d, ((x + 12) * S, 362 * S), label, f_small, INK, "lm")

    arrow_down(d, 700 * S, 400 * S, 428 * S)

    # triad columns
    cols = [
        (
            40,
            "03  自循环",
            "SELF-LOOP",
            False,
            [
                "每轮新开 Claude 会话，局面只靠图与简报",
                "注入：steering + 攻击图快照 + 可迁移剧本",
                "御主推进一轮，MCP 实时 add_node / finding",
                "验证后监督开口，路线包绑定再进入下一轮",
            ],
        ),
        (
            500,
            "04  自监督",
            "SELF-SUPERVISE",
            False,
            [
                "只在轮次边界、当前验证结束后复盘",
                "无工具：读全局简报，只输出 JSON 方案",
                "must_intents / prefer_tactics 硬约束",
                "未执行则收紧同一绑定，禁止同义换路散文",
            ],
        ),
        (
            960,
            "05  自进化",
            "SELF-EVOLVE",
            True,
            [
                "收工把 episode 蒸馏成 lesson / playbook",
                "剧本去 IP、URL、题面路径，只留手法链",
                "按指纹取回，回灌御主与监督简报",
                "赢局加分、输局衰减，跨项目复用",
            ],
        ),
    ]
    for x, title, en, hot, lines in cols:
        outline = PRIMARY if hot else HAIR
        rr(d, (x * S, 428 * S, (x + 400) * S, 720 * S), 10, CARD, outline, 2 if hot else 1)
        if hot:
            d.rectangle([(x * S, 716 * S), ((x + 400) * S, 720 * S)], fill=PRIMARY)
        tx(d, ((x + 20) * S, 448 * S), title, f_h, PRIMARY if hot else INK)
        tx(d, ((x + 20) * S, 478 * S), en, f_en, PRIMARY if hot else MUTED)
        yy = 516
        for i, line in enumerate(lines, 1):
            tx(d, ((x + 20) * S, yy * S), f"{i:02d}", f_num, PRIMARY)
            tx(d, ((x + 48) * S, yy * S), line, f_body, INK, "lt")
            yy += 44

    arrow_down(d, 700 * S, 720 * S, 748 * S)

    # bottom infrastructure
    rr(d, (40 * S, 748 * S, 1360 * S, 1068 * S), 10, CARD, HAIR, 1)
    tx(d, (60 * S, 764 * S), "06  受控执行与落盘", f_h, INK)
    tx(d, (240 * S, 768 * S), "MCP 是智能体对外的唯一通道", f_en, MUTED)

    blocks = [
        (
            70,
            310,
            "MCP 工具",
            "run_cmd  ·  http_request\nadd_node / add_edge\nreport_finding / report_shell\npropose_intents  ·  note",
        ),
        (
            400,
            300,
            "执行层",
            "Guard 作业与范围校验\n本机 Kali 渗透工具\n工作区 loot / 产物\n禁止打控制台自身端口",
        ),
        (
            720,
            300,
            "攻击图  SQLite",
            "target / service / vuln / foothold\n橙线 RCE  ·  紫线横向 PIVOTS_TO\nIntent 开放 / 验证 / 否证\n节点实时推到控制台",
        ),
        (
            1040,
            280,
            "交付",
            "HTML / Markdown / PDF\n关键攻击路径\n资产画像\nfinding 机制与复现步骤",
        ),
    ]
    for x, w, title, body in blocks:
        rr(d, (x * S, 804 * S, (x + w) * S, 1036 * S), 8, (247, 244, 240, 255), HAIR, 1)
        tx(d, ((x + 16) * S, 824 * S), title, f_h, INK)
        yy = 860
        for line in body.split("\n"):
            tx(d, ((x + 16) * S, yy * S), line, f_small, MUTED)
            yy += 36

    im_rgb = Image.new("RGB", im.size, BG[:3])
    im_rgb.paste(im, mask=im.split()[-1])
    im_rgb.save(OUT, "PNG", optimize=True)
    print(f"wrote {OUT} {im_rgb.size}")


if __name__ == "__main__":
    main()
