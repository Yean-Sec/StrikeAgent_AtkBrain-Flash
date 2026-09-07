"""报告插图：攻击关系图 + 统计图，色板与控制台主题一致。"""
from __future__ import annotations

import html
from collections import Counter

from ..graph.model import display_finding_severity

# 与 frontend/src/theme.ts / styles.css :root 对齐
THEME = {
    "primary": "#cc785c",
    "primaryActive": "#a9583e",
    "ink": "#141413",
    "body": "#3d3d3a",
    "muted": "#6c6a64",
    "hairline": "#e6dfd8",
    "canvas": "#faf9f5",
    "surfaceSoft": "#f5f0e8",
    "surfaceCard": "#efe9de",
    "surfaceDark": "#181715",
    "onDark": "#faf9f5",
    "accentTeal": "#5db8a6",
    "accentAmber": "#e8a55a",
    "success": "#5db872",
    "warning": "#d4a017",
    "error": "#c64545",
    "goal": "#f23636",
    "danger": "#f08c2a",
}

NODE_FILL = {
    "target": "#141413",
    "info": "#8e8b82",
    "service": "#5db8a6",
    "danger": "#f08c2a",
    "vuln": "#c64545",
    "credential": "#a9583e",
    "foothold": "#cc785c",
    "honeypot": "#6c6a64",
    "goal": "#f23636",
}

NODE_LABEL = {
    "target": "目标",
    "info": "信息",
    "service": "服务",
    "danger": "危险点",
    "vuln": "漏洞",
    "credential": "凭证",
    "foothold": "立足点",
    "honeypot": "蜜罐",
    "goal": "GETSHELL",
}

COL_X = {
    "target": 90,
    "info": 250,
    "service": 250,
    "honeypot": 250,
    "danger": 430,
    "credential": 430,
    "vuln": 610,
    "foothold": 790,
    "goal": 970,
}

SEV_COLOR = {
    "critical": "#c64545",
    "high": "#d4a017",
    "medium": "#8e8b82",
    "low": "#b8b3a8",
    "info": "#a09d96",
}


def _esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def report_css() -> str:
    t = THEME
    return f"""
:root {{
  --primary: {t["primary"]}; --primary-active: {t["primaryActive"]};
  --ink: {t["ink"]}; --body: {t["body"]}; --muted: {t["muted"]};
  --hairline: {t["hairline"]}; --canvas: {t["canvas"]};
  --surface-soft: {t["surfaceSoft"]}; --surface-card: {t["surfaceCard"]};
  --surface-dark: {t["surfaceDark"]}; --on-dark: {t["onDark"]};
  --accent-teal: {t["accentTeal"]}; --accent-amber: {t["accentAmber"]};
  --success: {t["success"]}; --warning: {t["warning"]}; --error: {t["error"]};
  --goal: {t["goal"]};
  --font-serif: "Noto Serif CJK SC","Noto Serif SC","EB Garamond",Georgia,serif;
  --font-sans: "Noto Sans CJK SC","Noto Sans SC","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
  --font-mono: ui-monospace,"Cascadia Mono","Segoe UI Mono",Consolas,monospace;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--canvas); color: var(--ink);
  font-family: var(--font-sans); line-height: 1.6; padding: 0;
}}
.report-hero {{
  background: var(--surface-dark); color: var(--on-dark);
  padding: 36px 48px 28px; border-bottom: 4px solid var(--primary);
}}
.report-hero h1 {{
  font-family: var(--font-serif); font-weight: 400; font-size: 34px;
  letter-spacing: -.5px; margin: 0 0 8px;
}}
.report-hero .meta {{ color: var(--muted); font-size: 14px; }}
.report-hero .meta code {{ color: var(--accent-amber); }}
.kpi-row {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }}
.kpi {{
  background: #252320; border: 1px solid #3a3732; border-radius: 999px;
  padding: 6px 14px; font-size: 13px; color: var(--on-dark);
}}
.kpi b {{ color: var(--primary); font-weight: 600; }}
.wrap {{ padding: 32px 48px 64px; max-width: 1080px; margin: 0 auto; }}
h2 {{
  font-family: var(--font-serif); font-weight: 400; font-size: 24px;
  border-bottom: 1px solid var(--hairline); padding-bottom: 8px; margin: 36px 0 14px;
}}
h3 {{ font-size: 18px; margin: 22px 0 8px; }}
h4 {{ font-size: 14px; color: var(--body); margin: 14px 0 6px; }}
.figure {{
  background: #fff; border: 1px solid var(--hairline); border-radius: 14px;
  padding: 16px; margin: 14px 0 22px; overflow-x: auto;
}}
.figure figcaption {{
  font-size: 12px; color: var(--muted); margin-top: 8px; text-align: center;
}}
.charts {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
@media (max-width: 860px) {{ .charts {{ grid-template-columns: 1fr; }} .wrap, .report-hero {{ padding-left: 20px; padding-right: 20px; }} }}
.card {{
  background: var(--surface-card); border-radius: 12px; padding: 16px 18px; margin: 12px 0;
  border-left: 5px solid var(--primary);
}}
.card.crit {{ border-left-color: var(--error); }}
.card.high {{ border-left-color: var(--warning); }}
.badge {{
  font-size: 11px; letter-spacing: 1px; text-transform: uppercase;
  padding: 3px 10px; border-radius: 999px; color: #fff; background: var(--muted);
}}
.b-critical {{ background: var(--error); }}
.b-high {{ background: var(--warning); color: #141413; }}
.b-medium {{ background: #8e8b82; }}
.b-low {{ background: #b8b3a8; color: #141413; }}
.b-info {{ background: #d8d2c6; color: #141413; }}
pre {{
  background: var(--surface-dark); color: var(--on-dark); padding: 14px;
  border-radius: 8px; overflow-x: auto; font-family: var(--font-mono); font-size: 12.5px;
  white-space: pre-wrap;
}}
code {{ font-family: var(--font-mono); font-size: 0.92em; }}
.vuln-body {{ white-space: pre-wrap; font-size: 14px; margin: 0 0 10px; }}
ol.repro li {{ margin: 8px 0; white-space: pre-wrap; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 10px 16px; font-size: 12px; color: var(--muted); margin: 8px 0; }}
.legend i {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }}
.foot {{ margin-top: 48px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--hairline); padding-top: 16px; }}
.claude-body img {{ max-width: 100%; border-radius: 8px; }}
.claude-body table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.claude-body th, .claude-body td {{ padding: 8px; border-bottom: 1px solid var(--hairline); text-align: left; }}
""".strip()


def graph_svg(graph: dict, *, max_nodes: int = 56) -> str:
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    if not nodes:
        return _empty_svg("攻击图暂无节点")
    pri = {"goal": 0, "vuln": 1, "foothold": 2, "danger": 3, "target": 4, "credential": 5, "service": 6}
    nodes = sorted(nodes, key=lambda n: (pri.get(str(n.get("type")), 9), -float(n.get("risk_score") or 0)))
    if len(nodes) > max_nodes:
        nodes = nodes[:max_nodes]
    keys = {str(n.get("key")) for n in nodes}
    buckets: dict[str, list] = {}
    for n in nodes:
        buckets.setdefault(str(n.get("type") or "info"), []).append(n)
    pos: dict[str, tuple[float, float]] = {}
    max_y = 80.0
    for typ, group in buckets.items():
        x = COL_X.get(typ, 520)
        for i, n in enumerate(group):
            y = 56 + i * 46
            pos[str(n.get("key"))] = (x, y)
            max_y = max(max_y, y)
    w, h = 1080, int(max_y + 70)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%" '
        f'style="background:{THEME["canvas"]};font-family:system-ui,sans-serif">',
        f'<rect width="{w}" height="{h}" fill="{THEME["canvas"]}"/>',
    ]
    for e in edges:
        a = pos.get(str(e.get("from") or e.get("src") or ""))
        b = pos.get(str(e.get("to") or e.get("dst") or ""))
        if not a or not b:
            continue
        rel = str(e.get("relation") or "")
        why = str(e.get("rationale") or "").lower()
        hop = rel == "LEADS_TO" and (
            "pivot_capability" in why
            or (
                str(e.get("to") or e.get("dst") or "").startswith(("info:host:", "info:scope-expanded:"))
                and str(e.get("from") or e.get("src") or "").startswith(("foothold:", "goal:shell"))
            )
        )
        col = "#6d5cf0" if rel == "PIVOTS_TO" or hop else (
            THEME["primary"] if e.get("on_rce_path") or rel in ("EXPLOITS", "ESCALATES_TO") else "#cbc4b6"
        )
        sw = 2.4 if col != "#cbc4b6" else 1.2
        parts.append(
            f'<line x1="{a[0]}" y1="{a[1]}" x2="{b[0]}" y2="{b[1]}" '
            f'stroke="{col}" stroke-width="{sw}" stroke-opacity=".85"/>'
        )
    for n in nodes:
        k = str(n.get("key") or "")
        if k not in pos:
            continue
        x, y = pos[k]
        typ = str(n.get("type") or "info")
        fill = NODE_FILL.get(typ, THEME["muted"])
        title = str(n.get("title") or k)
        if len(title) > 16:
            title = title[:15] + "…"
        r = 8 + min(10, float(n.get("risk_score") or 0) / 12)
        parts.append(f'<circle cx="{x}" cy="{y}" r="{r:.1f}" fill="{fill}" stroke="#fff" stroke-width="2"/>')
        parts.append(
            f'<text x="{x}" y="{y + r + 12}" text-anchor="middle" font-size="10" fill="{THEME["body"]}">{_esc(title)}</text>'
        )
    lx = 24
    for typ, label in (("target", "目标"), ("service", "服务"), ("danger", "危险点"),
                       ("vuln", "漏洞"), ("foothold", "立足点"), ("goal", "GETSHELL")):
        fill = NODE_FILL[typ]
        parts.append(f'<circle cx="{lx}" cy="{h - 18}" r="5" fill="{fill}"/>')
        parts.append(f'<text x="{lx + 10}" y="{h - 14}" font-size="10" fill="{THEME["muted"]}">{label}</text>')
        lx += 88
    parts.append("</svg>")
    _ = keys
    return "".join(parts)


def _empty_svg(msg: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 120" width="100%">'
        f'<rect width="640" height="120" fill="{THEME["surfaceSoft"]}"/>'
        f'<text x="320" y="66" text-anchor="middle" fill="{THEME["muted"]}" font-size="14">{_esc(msg)}</text>'
        f"</svg>"
    )


def severity_bar_svg(findings: list[dict]) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    c = Counter(display_finding_severity(f) for f in findings)
    total = max(1, sum(c[s] for s in order))
    w, h = 480, 168
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%">'
        f'<rect width="{w}" height="{h}" fill="#fff"/>'
        f'<text x="16" y="22" font-size="13" fill="{THEME["ink"]}">漏洞严重度分布</text>'
    ]
    for i, sev in enumerate(order):
        n = c[sev]
        bw = 0 if total == 0 else (n / total) * 320
        y = 40 + i * 24
        parts.append(f'<text x="16" y="{y + 12}" font-size="11" fill="{THEME["muted"]}">{sev}</text>')
        parts.append(f'<rect x="88" y="{y}" width="320" height="14" rx="7" fill="{THEME["surfaceSoft"]}"/>')
        parts.append(
            f'<rect x="88" y="{y}" width="{max(bw, 0):.1f}" height="14" rx="7" fill="{SEV_COLOR[sev]}"/>'
        )
        parts.append(f'<text x="418" y="{y + 12}" font-size="11" fill="{THEME["body"]}">{n}</text>')
    parts.append("</svg>")
    return "".join(parts)


def type_bar_svg(graph: dict) -> str:
    c = Counter(str(n.get("type") or "info") for n in graph.get("nodes") or [])
    types = [t for t in ("target", "service", "danger", "vuln", "credential", "foothold", "goal", "info") if c[t]]
    if not types:
        return _empty_svg("暂无节点类型统计")
    total = max(1, sum(c[t] for t in types))
    w, h = 480, 36 + 24 * len(types)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%">'
        f'<rect width="{w}" height="{h}" fill="#fff"/>'
        f'<text x="16" y="22" font-size="13" fill="{THEME["ink"]}">攻击图节点类型</text>'
    ]
    for i, typ in enumerate(types):
        n = c[typ]
        bw = (n / total) * 300
        y = 40 + i * 24
        parts.append(
            f'<text x="16" y="{y + 12}" font-size="11" fill="{THEME["muted"]}">{_esc(NODE_LABEL.get(typ, typ))}</text>'
        )
        parts.append(f'<rect x="88" y="{y}" width="300" height="14" rx="7" fill="{THEME["surfaceSoft"]}"/>')
        parts.append(
            f'<rect x="88" y="{y}" width="{bw:.1f}" height="14" rx="7" fill="{NODE_FILL.get(typ, THEME["muted"])}"/>'
        )
        parts.append(f'<text x="400" y="{y + 12}" font-size="11" fill="{THEME["body"]}">{n}</text>')
    parts.append("</svg>")
    return "".join(parts)


def rce_path_svg(graph: dict) -> str:
    rce = graph.get("rce_path") or {}
    path = rce.get("path") or []
    if len(path) < 2:
        return ""
    by_key = {n.get("key"): n for n in graph.get("nodes") or []}
    w = max(420, 40 + len(path) * 130)
    h = 86
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="100%">'
        f'<rect width="{w}" height="{h}" fill="#fff"/>'
        f'<text x="16" y="18" font-size="12" fill="{THEME["muted"]}">RCE 最优路径</text>'
    ]
    for i, k in enumerate(path):
        x = 24 + i * 130
        n = by_key.get(k) or {}
        fill = NODE_FILL.get(str(n.get("type") or "info"), THEME["primary"])
        title = str(n.get("title") or k)
        if len(title) > 12:
            title = title[:11] + "…"
        parts.append(f'<rect x="{x}" y="32" width="110" height="36" rx="8" fill="{fill}"/>')
        parts.append(
            f'<text x="{x + 55}" y="54" text-anchor="middle" font-size="11" fill="#fff">{_esc(title)}</text>'
        )
        if i < len(path) - 1:
            parts.append(
                f'<path d="M{x + 114} 50 L{x + 126} 50" stroke="{THEME["primary"]}" '
                f'stroke-width="2" marker-end="url(#arr)"/>'
            )
    parts.insert(2, f'<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">'
                  f'<path d="M0,0 L6,3 L0,6" fill="{THEME["primary"]}"/></marker></defs>')
    parts.append("</svg>")
    return "".join(parts)
