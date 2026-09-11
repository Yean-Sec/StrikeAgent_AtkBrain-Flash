"""交付报告：复制母版，只填 SLOT，禁止模型重写整页 HTML。"""
from __future__ import annotations

import hashlib
import html as _html
import json
import math
import re
from pathlib import Path
from typing import Any

from .writeup import real_poc_text
from ..graph.model import display_finding_severity

THEME_REV = "2026.09.02.1"
PROMPT_REV = "2026.09.02.1"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
SHELL_NAME = "deliverable_shell.html"

_SLOT_RE = re.compile(
    r"(<!-- SLOT:([a-z0-9_-]+) -->)(.*?)(<!-- /SLOT:\2 -->)",
    re.S,
)

SEV_LABEL = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}
SEV_CHIP = {
    "critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "low",
}
SEV_DOT = {
    "critical": "var(--crit)",
    "high": "var(--high)",
    "medium": "var(--muted-soft)",
    "low": "var(--muted)",
    "info": "var(--muted)",
}
KIND_LABEL = {
    "target": "目标", "service": "服务", "host": "主机", "endpoint": "入口", "info": "资产",
}
VERIFY_LABEL = {
    "verified": "已验证", "pending": "待复验", "flaky": "待复验",
}
PN_CLS = {
    "target": "info", "service": "info", "host": "info", "endpoint": "info", "info": "info",
    "danger": "warn",
    "vuln": "crit", "foothold": "crit",
    "goal": "goal",
}
PN_KIND = {
    "target": "入口", "service": "服务", "danger": "缺陷", "vuln": "漏洞",
    "foothold": "立足点", "goal": "权限", "info": "节点", "host": "主机", "endpoint": "入口",
}

LEAK_RE = re.compile(
    r"StrikeAgent|AtkBrain-Flash|AtkBrain|GETSHELL|node_key|verification_status|"
    r"附录|时间线|playbook|frontier|rce_path",
    re.I,
)


def load_shell() -> str:
    return (TEMPLATES_DIR / SHELL_NAME).read_text(encoding="utf-8")


def fill_slot(html: str, name: str, content: str) -> str:
    pat = re.compile(
        rf"(<!-- SLOT:{re.escape(name)} -->)(.*?)(<!-- /SLOT:{re.escape(name)} -->)",
        re.S,
    )

    def repl(m: re.Match) -> str:
        return m.group(1) + "\n" + (content or "") + "\n" + m.group(3)

    out, n = pat.subn(repl, html, count=1)
    if n != 1:
        raise ValueError(f"母版缺少唯一槽位 {name}")
    return out


def fill_slots(html: str, mapping: dict[str, str]) -> str:
    for name, content in mapping.items():
        html = fill_slot(html, name, content or "")
    return html


def slot_names(html: str) -> list[str]:
    return [m.group(2) for m in _SLOT_RE.finditer(html)]


def _esc(s: Any) -> str:
    return _html.escape("" if s is None else str(s), quote=False)


def _esc_attr(s: Any) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def sanitize_visible(text: str) -> str:
    t = LEAK_RE.sub("", text or "")
    t = re.sub(r"\bnode:vuln:[^\s<]+", "", t)
    t = re.sub(r"\bf_[0-9a-f]{8,}\b", "", t)
    return t


def _sev(f: dict) -> str:
    s = display_finding_severity(f)
    return s if s in SEV_LABEL else "info"


def _verify_label(f: dict) -> str:
    st = str(f.get("verification_status") or "").lower()
    if st in VERIFY_LABEL:
        return VERIFY_LABEL[st]
    return "情报记录"


def _category(f: dict) -> str:
    return sanitize_visible(str(f.get("category") or "未分类")) or "未分类"


def _title(f: dict) -> str:
    return sanitize_visible(str(f.get("title") or "未命名漏洞")) or "未命名漏洞"


def _anchor(n: int) -> str:
    return f"vuln-{n:02d}"


def facts_digest(data: dict) -> str:
    findings = []
    for f in data.get("findings") or []:
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
        findings.append({
            "id": f.get("id"),
            "title": f.get("title"),
            "severity": display_finding_severity(f),
            "evidence": (f.get("evidence") or "")[:800],
            "curl": real_poc_text(poc.get("curl") or f.get("poc_curl") or "")[:400],
            "vs": f.get("verification_status"),
        })
    p = data.get("project") or {}
    blob = json.dumps({
        "pid": p.get("id"), "name": p.get("name"), "target": p.get("target"),
        "has_shell": bool(data.get("has_shell")),
        "rce": ((data.get("graph") or {}).get("rce_path") or {}).get("path") or [],
        "findings": findings,
        "theme_rev": THEME_REV, "prompt_rev": PROMPT_REV,
    }, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def cache_stem(project_id: str, digest: str) -> str:
    return f"{project_id[:24]}-{digest[:16]}"


def gate_html(html: str, *, has_findings: bool) -> list[str]:
    errs: list[str] = []
    if 'class="cover"' not in html:
        errs.append("missing-cover")
    if 'class="grain"' not in html:
        errs.append("missing-grain")
    if "sec-head" not in html:
        errs.append("missing-sec-head")
    if "path-board" not in html:
        errs.append("missing-path-board")
    if has_findings and 'class="vf' not in html:
        errs.append("missing-vf")
    if 'class="vbar"' in html:
        errs.append("has-vbar")
    return errs


def _counts(findings: list[dict]) -> dict[str, int]:
    c = {k: 0 for k in SEV_LABEL}
    for f in findings:
        c[_sev(f)] = c.get(_sev(f), 0) + 1
    c["total"] = len(findings)
    return c


def _verify_buckets(findings: list[dict]) -> dict[str, int]:
    buckets = {"已验证": 0, "待复验": 0, "情报记录": 0}
    for f in findings:
        buckets[_verify_label(f)] = buckets.get(_verify_label(f), 0) + 1
    return buckets


def _graph_stats(data: dict) -> dict[str, int]:
    g = data.get("graph") or {}
    st = dict(g.get("stats") or {})
    nodes = list(g.get("nodes") or [])
    edges = list(g.get("edges") or [])
    st.setdefault("nodes", len(nodes))
    st.setdefault("edges", len(edges))
    st.setdefault("services", sum(1 for n in nodes if str(n.get("type") or "") in ("service", "host", "endpoint")))
    return st


def _severity_bars_svg(counts: dict[str, int]) -> str:
    total = max(1, int(counts.get("total") or 0))
    rows = [
        ("严重 critical", "critical", "var(--crit)"),
        ("高危 high", "high", "var(--high)"),
        ("中危 medium", "medium", "var(--muted-soft)"),
        ("低危 low", "low", "var(--muted)"),
    ]
    parts = [
        '<svg viewBox="0 0 640 190" xmlns="http://www.w3.org/2000/svg" '
        'style="width:100%;height:auto" role="img" aria-label="漏洞严重度分布">'
    ]
    for i, (lab, key, col) in enumerate(rows):
        n = int(counts.get(key) or 0)
        if key == "low":
            n += int(counts.get("info") or 0)
        w = 0 if n == 0 else max(12, round(420 * n / total))
        ty = 32 + i * 40
        ry = 16 + i * 40
        tx = 150 + w + 14
        parts.append(
            f'<text x="0" y="{ty}" font-size="13" fill="var(--body)" font-family="inherit">{lab}</text>'
            f'<rect x="150" y="{ry}" width="420" height="20" rx="10" fill="var(--surface-soft)" stroke="var(--hairline)"/>'
            f'<rect x="150" y="{ry}" width="{w}" height="20" rx="10" fill="{col}"><title>{n} 条</title></rect>'
            f'<text x="{tx}" y="{ty - 1}" font-size="14" font-weight="700" fill="var(--ink)">{n}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _verify_donut_svg(findings: list[dict]) -> str:
    buckets = _verify_buckets(findings)
    total = max(1, sum(buckets.values()))
    r, circ = 74.0, 2 * math.pi * 74
    colors = [("已验证", "var(--success)"), ("待复验", "var(--warning)"), ("情报记录", "var(--muted-soft)")]
    parts = [
        '<svg viewBox="0 0 220 200" width="200" xmlns="http://www.w3.org/2000/svg" '
        'role="img" aria-label="验证状态分布">'
    ]
    offset = 0.0
    for lab, col in colors:
        n = buckets[lab]
        arc = circ * n / total
        rest = max(circ - arc, 0)
        parts.append(
            f'<circle cx="110" cy="100" r="{r:.0f}" fill="none" stroke="{col}" '
            f'stroke-width="24" stroke-dasharray="{arc:.2f} {rest:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 110 100)"/>'
        )
        offset += arc
    shown = sum(buckets.values())
    parts.append(
        f'<text x="110" y="104" text-anchor="middle" font-size="30" font-weight="800" fill="var(--ink)">{shown}</text>'
        f'<text x="110" y="126" text-anchor="middle" font-size="12" fill="var(--muted)">漏洞总数</text></svg>'
    )
    return "".join(parts)


def _path_keys(data: dict) -> tuple[list[str], dict[str, dict]]:
    g = data.get("graph") or {}
    nodes = {str(n.get("key")): n for n in (g.get("nodes") or []) if n.get("key")}
    keys = list(((g.get("rce_path") or {}).get("path")) or [])
    if not keys:
        for typ in ("target", "service", "danger", "vuln", "goal"):
            hit = next((n for n in (g.get("nodes") or []) if n.get("type") == typ), None)
            if hit and hit.get("key"):
                keys.append(str(hit["key"]))
        keys = keys[:6]
    if not keys:
        p = data.get("project") or {}
        keys = ["_tgt"]
        nodes["_tgt"] = {"title": p.get("target") or p.get("name") or "授权目标", "type": "target"}
    return keys[:9], nodes


def _pn_card(n: dict, *, cls: str, title: str, detail: str) -> str:
    pk = cls
    return (
        f'<div class="pn {cls}"><div class="pk">{_esc(pk)}</div>'
        f'<div class="pt">{_esc(title)}</div><div class="pd">{_esc(detail)}</div></div>'
    )


def _parrow(label: str, *, down: bool = False) -> str:
    cls = "parrow down" if down else "parrow"
    return f'<div class="{cls}"><span class="line"></span><span>{_esc(label)}</span></div>'


def _path_board(data: dict, path_note: str) -> str:
    keys, nodes = _path_keys(data)
    cards: list[tuple[str, str, str]] = []
    shown = keys[:9]
    for i, k in enumerate(shown):
        n = nodes.get(k) or {"title": k, "type": "info"}
        typ = str(n.get("type") or "info")
        cls = "goal" if typ == "goal" or (data.get("has_shell") and i == len(shown) - 1) else PN_CLS.get(typ, "info")
        title = sanitize_visible(str(n.get("title") or k))[:36]
        detail = sanitize_visible(str(n.get("detail") or PN_KIND.get(typ, "节点")))[:48]
        cards.append((cls, title, detail))
    rows_html: list[str] = []
    row_size = 3
    arrow_words = ["扩展", "进入", "利用", "横向", "提权", "落地"]
    for r in range(0, len(cards), row_size):
        chunk = cards[r:r + row_size]
        if r:
            rows_html.append(_parrow("进入下一跳", down=True))
        inner: list[str] = []
        for j, (cls, title, detail) in enumerate(chunk):
            if j:
                inner.append(_parrow(arrow_words[(r + j - 1) % len(arrow_words)]))
            inner.append(_pn_card({}, cls=cls, title=title, detail=detail))
        rows_html.append(f'<div class="path-row">{"".join(inner)}</div>')
    note = sanitize_visible(path_note) or "路径由授权范围内已验证环节串联，不含推测跳步。"
    return (
        f'<p class="sec-sub">{_esc(note)}</p>'
        '<div class="path-board"><div class="path-rows">'
        f"{''.join(rows_html)}</div>"
        '<div class="path-legend">'
        '<span><i class="l-crit"></i>关键缺陷节点</span>'
        '<span><i class="l-warn"></i>过渡 / 扩展节点</span>'
        '<span><i class="l-info"></i>情报与服务节点</span>'
        '<span><i class="l-goal"></i>权限落地目标</span>'
        f'</div></div><div class="path-caption">{_esc(note)}</div>'
    )


def _collect_assets(data: dict) -> list[dict]:
    assets: list[dict] = []
    for sec in data.get("sections") or []:
        assets.extend(sec.get("assets") or [])
    if not assets:
        for n in ((data.get("graph") or {}).get("nodes") or []):
            if str(n.get("type") or "") in ("target", "service", "host", "endpoint"):
                assets.append({
                    "title": n.get("title") or n.get("key"),
                    "kind": n.get("type"),
                    "detail": n.get("detail") or "",
                })
    if not assets:
        p = data.get("project") or {}
        if p.get("target"):
            assets = [{"title": p.get("target"), "kind": "target", "detail": "授权主目标"}]
    return assets


def _asset_map_svg(assets: list[dict]) -> str:
    shown = assets[:8]
    if not shown:
        return ""
    rows = (len(shown) + 3) // 4
    height = max(220, 40 + rows * 96)
    boxes = []
    for i, a in enumerate(shown):
        col, row = i % 4, i // 4
        x = 40 + col * 270
        y = 28 + row * 96
        title = sanitize_visible(str(a.get("title") or a.get("key") or "资产"))[:28]
        kind = KIND_LABEL.get(str(a.get("kind") or ""), "资产")
        stroke = "#c64545" if str(a.get("kind") or "") in ("vuln", "danger") else "#cc785c"
        boxes.append(
            f'<g filter="url(#am-shadow)">'
            f'<rect x="{x}" y="{y}" width="240" height="62" rx="14" fill="#fffdf8" '
            f'stroke="{stroke}" stroke-width="1.6"/>'
            f'<text x="{x + 120}" y="{y + 24}" text-anchor="middle" font-size="12" '
            f'font-weight="700" fill="{stroke}">{_esc(kind)}</text>'
            f'<text x="{x + 120}" y="{y + 44}" text-anchor="middle" font-size="14" '
            f'font-weight="700" fill="#141413">{_esc(title)}</text></g>'
        )
    return (
        '<div class="asset-map"><h4>资产关系图</h4>'
        f'<p class="am-sub">授权范围内主要测绘对象，共 <b>{len(assets)}</b> 条。</p>'
        f'<svg viewBox="0 0 1120 {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="资产关系图">'
        "<defs><filter id=\"am-shadow\" x=\"-12%\" y=\"-12%\" width=\"124%\" height=\"140%\">"
        '<feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#141413" flood-opacity="0.07"/>'
        "</filter></defs>"
        f"{''.join(boxes)}</svg></div>"
    )


def _assets_html(data: dict) -> str:
    assets = _collect_assets(data)
    cards = []
    extra = []
    for i, a in enumerate(assets):
        title = sanitize_visible(str(a.get("title") or a.get("key") or "资产"))
        kind = KIND_LABEL.get(str(a.get("kind") or ""), "资产")
        detail = sanitize_visible(str(a.get("detail") or ""))[:160]
        danger = " danger" if str(a.get("kind") or "") in ("vuln", "danger") else ""
        if i < 12:
            cards.append(
                f'<div class="asset{danger}">'
                f'<div class="a-name">{_esc(title)}</div>'
                f'<div class="a-role">{_esc(kind)}</div>'
                f'<div class="a-badges"><span class="chip">{_esc(kind)}</span></div>'
                f'<div class="a-desc">{_esc(detail)}</div></div>'
            )
        else:
            extra.append(f'<span class="chip">{_esc(title[:32])}</span>')
    body = (
        f'<p class="sec-sub">授权范围内识别 {len(assets)} 项资产 / 服务。</p>'
        f"{_asset_map_svg(assets)}"
        f'<div class="assets">{"".join(cards)}</div>'
    )
    if extra:
        body += f'<div class="sum-foot" style="margin-top:16px"><b>其余资产：</b> {"".join(extra)}</div>'
    return body


def _index_table(items: list[dict]) -> str:
    rows = []
    for it in items:
        sev = it["sev"]
        dot = SEV_DOT.get(sev, "var(--muted)")
        rows.append(
            f"<tr><td>{it['n']}</td>"
            f'<td><span class="s-dot" style="background:{dot}"></span>{_esc(SEV_LABEL.get(sev, sev))}</td>'
            f"<td>{_esc(it['title'])}</td>"
            f"<td>{_esc(it['cat'])}</td><td>{_esc(it['verify'])}</td>"
            f'<td><a class="anchor" href="#{it["anchor"]}">跳转</a></td></tr>'
        )
    return (
        '<table class="tbl"><thead><tr>'
        '<th style="width:56px">#</th><th style="width:90px">严重度</th>'
        "<th>漏洞 / 发现</th>"
        '<th style="width:120px">类型</th><th style="width:90px">状态</th>'
        '<th style="width:64px">锚点</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _paras(val: str) -> str:
    s = str(val or "").strip()
    if not s:
        return "<p>未采集。</p>"
    if s.lstrip().startswith("<"):
        return sanitize_visible(s)
    parts = [p.strip() for p in re.split(r"\n{2,}", s) if p.strip()]
    if not parts:
        parts = [s]
    return "".join(f"<p>{_esc(sanitize_visible(p))}</p>" for p in parts)


def _steps_ol(steps: list[str]) -> str:
    lis = "".join(f"<li>{_esc(sanitize_visible(s))}</li>" for s in steps if str(s).strip())
    if not lis:
        lis = "<li>未采集可执行复现步骤；请结合证据区原始请求复核。</li>"
    return f"<ol>{lis}</ol>"


def _fixes_html(fixes: list[str], verify: str, enrich: dict | None = None) -> str:
    now = [sanitize_visible(x) for x in list((enrich or {}).get("fixes_now") or []) if str(x).strip()]
    root = [sanitize_visible(x) for x in list((enrich or {}).get("fixes_root") or []) if str(x).strip()]
    items = [sanitize_visible(x) for x in fixes if str(x).strip()]
    if not now and not root:
        if len(items) >= 2:
            mid = max(1, len(items) // 2)
            now, root = items[:mid], items[mid:]
        else:
            now = items or ["关闭不必要的暴露面。", "对相关接口实施鉴权与最小权限。"]
            root = [sanitize_visible(verify) or "修复后按「②利用」逐步复测，关键请求应失败或不再回显敏感数据。"]
    if not root:
        root = [sanitize_visible(verify) or "纳入基线：复杂度策略、最小权限与暴露面收敛。"]
    return (
        '<div class="fix-grid">'
        '<div class="fix-box"><h5 class="now">⚠ 立即缓解</h5>'
        f"<ul>{''.join(f'<li>{_esc(x)}</li>' for x in now)}</ul></div>"
        '<div class="fix-box"><h5 class="root">✔ 根治</h5>'
        f"<ul>{''.join(f'<li>{_esc(x)}</li>' for x in root)}</ul></div></div>"
    )


def _curl_of(f: dict) -> str:
    poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
    return real_poc_text(poc.get("curl") or f.get("poc_curl") or "")


def _exploit_html(steps: list[str], f: dict, enrich: dict | None = None) -> str:
    precond = str((enrich or {}).get("prerequisites") or "攻击前置条件见验证证据、PoC 与关联节点。")
    impact = str((enrich or {}).get("impact") or f.get("impact_detail") or f.get("impact") or "影响以已验证证据为准；应结合关联资产与权限边界进行复核。")
    curl = _curl_of(f)
    pre = f"<pre>{_esc(curl)}</pre>" if curl else ""
    return (
        f"{_steps_ol(steps)}{pre}"
        f'<p style="font-size:13px;color:var(--muted)"><b>前置条件：</b>{_esc(sanitize_visible(precond))}</p>'
        f'<p style="font-size:13px;color:var(--muted)"><b>影响：</b>{_esc(sanitize_visible(str(impact)[:400]))}</p>'
    )


def _evidence_html(f: dict) -> str:
    curl = _curl_of(f)
    evidence = str(f.get("evidence") or "")
    http_raw = str(f.get("http_raw") or "")
    url = str(f.get("proof_url") or "")
    detail = str(f.get("verification_detail") or f.get("verify_note") or "")
    chunks = []
    if evidence:
        chunks.append(
            f'<div class="row"><span class="k">证据</span><span>{_esc(evidence[:4000])}</span></div>'
        )
    if detail:
        chunks.append(
            f'<div class="row"><span class="k">验证细节</span><span>{_esc(detail[:2000])}</span></div>'
        )
    if url:
        href = _esc_attr(url)
        chunks.append(
            f'<div class="row"><span class="k">证明 URL</span>'
            f'<span class="mono"><a href="{href}" target="_blank" rel="noopener">{_esc(url)}</a></span></div>'
        )
    if curl:
        chunks.append(f'<div class="row"><span class="k">PoC curl</span></div><pre>{_esc(curl)}</pre>')
    if http_raw:
        chunks.append(
            f'<div class="row"><span class="k">原始 HTTP</span></div><pre>{_esc(http_raw[:4000])}</pre>'
        )
    steps = list(f.get("manual_steps") or [])
    if steps:
        chunks.append('<div class="row"><span class="k">复现步骤</span></div>' + _steps_ol(steps[:8]))
    if not chunks:
        chunks.append("<pre>未采集可展示证据。</pre>")
    return (
        '<details class="ev"><summary>证据 / PoC 复现（点击展开）</summary>'
        f'<div class="ev-body">{"".join(chunks)}</div></details>'
    )


def render_vf_card(f: dict, *, n: int, enrich: dict | None = None) -> str:
    """按参考交付报告输出 .vf 卡片（①简介 / ②利用 / ③修复）。"""
    anchor = _anchor(n)
    sev = _sev(f)
    chip = SEV_CHIP[sev]
    vlab = _verify_label(f)
    intro = impact = verify = ""
    steps: list[str] = []
    fixes: list[str] = []
    if enrich:
        intro = str(enrich.get("intro") or "")
        impact = str(enrich.get("impact") or "")
        steps = list(enrich.get("steps") or [])
        fixes = list(enrich.get("fixes") or [])
        verify = str(enrich.get("verify") or "")
    if not intro:
        intro = str(f.get("mechanism") or f.get("root_cause") or f.get("description") or "未采集")
    if not impact:
        impact = str(f.get("impact_detail") or f.get("impact") or "")
    if not steps:
        steps = list(f.get("manual_steps") or [])
    if not fixes:
        fixes = [
            "对受影响入口实施鉴权、参数校验与最小权限。",
            "关闭默认口令与不必要的管理面暴露。" if "口令" in (intro + _title(f)) else "移除或隔离相关危险功能。",
        ]
    intro_html = _paras(intro)
    if impact and not str(intro).lstrip().startswith("<"):
        intro_html += _paras(impact)
    vcolor = "var(--ok)" if vlab == "已验证" else ("var(--warning)" if vlab == "待复验" else "var(--muted)")
    return (
        f'<article class="vf {chip}" id="{anchor}">'
        f'<div class="vhead">'
        f'<div class="vtitle-row"><span class="sev-chip {chip}">{_esc(SEV_LABEL[sev])}</span>'
        f"<h3>{_esc(_title(f))}</h3></div>"
        f'<div class="vmeta"><span>类型 {_esc(_category(f))}</span>'
        f'<span>状态 <b style="color:{vcolor}">{_esc(vlab)}</b></span>'
        f'<span>{"已二次验证" if f.get("secondary_verified") else "未二次验证"}</span>'
        f'</div></div>'
        f'<div class="vbody">'
        f'<div class="vsec"><h4><span class="tick">①</span> 简介 / 技术成因</h4>{intro_html}</div>'
        f'<div class="vsec"><h4><span class="tick">②</span> 利用方式（编号分步复现）</h4>'
        f"{_exploit_html(steps, f, enrich)}</div>"
        f'<div class="vsec"><h4><span class="tick g">③</span> 修复方式</h4>'
        f"{_fixes_html(fixes, verify, enrich)}</div>"
        f"{_evidence_html(f)}"
        f"</div></article>"
    )


def _kpis_html(data: dict, counts: dict[str, int], findings: list[dict]) -> str:
    total = counts.get("total") or 0
    crit = counts.get("critical") or 0
    high = counts.get("high") or 0
    med = counts.get("medium") or 0
    low = (counts.get("low") or 0) + (counts.get("info") or 0)
    buckets = _verify_buckets(findings)
    st = _graph_stats(data)
    n_svc = int(st.get("services") or st.get("nodes") or 0)
    p0 = "P0" if crit else ("P1" if high else "P2")
    if data.get("has_shell"):
        goal = (
            '<div class="kpi goal"><div class="k-ico">🏁</div><div class="k-num">1</div>'
            '<div class="k-label">已获取权限</div></div>'
        )
    else:
        goal = (
            '<div class="kpi"><div class="k-ico">🏁</div><div class="k-num">0</div>'
            '<div class="k-label">尚未获取权限</div></div>'
        )
    return (
        '<div class="kpis" style="margin-top:22px">'
        f'<div class="kpi"><div class="k-ico">🧾</div><div class="k-num">{total}</div>'
        '<div class="k-label">漏洞发现总数</div></div>'
        f'<div class="kpi crit"><div class="k-ico">🔥</div><div class="k-num">{crit}</div>'
        '<div class="k-label">严重 Critical</div></div>'
        f'<div class="kpi high"><div class="k-ico">⚠️</div><div class="k-num">{high}</div>'
        '<div class="k-label">高危 High</div></div>'
        f'<div class="kpi med"><div class="k-ico">📄</div><div class="k-num">{med} / {low}</div>'
        '<div class="k-label">中危 / 低危</div></div>'
        f'<div class="kpi teal"><div class="k-ico">🖥️</div><div class="k-num">{n_svc}</div>'
        '<div class="k-label">服务节点</div></div>'
        f'<div class="kpi"><div class="k-ico">✅</div><div class="k-num">{buckets["已验证"]}</div>'
        '<div class="k-label">已验证</div></div>'
        f"{goal}"
        f'<div class="kpi"><div class="k-ico">🎯</div><div class="k-num">{p0}</div>'
        '<div class="k-label">建议立即整改项</div></div>'
        "</div>"
    )


def _charts_html(findings: list[dict], counts: dict[str, int]) -> str:
    total = counts.get("total") or 0
    n_c = counts.get("critical") or 0
    n_h = counts.get("high") or 0
    hot = n_c + n_h
    pct = round(100 * hot / max(1, total)) if total else 0
    buckets = _verify_buckets(findings)
    return (
        '<div class="charts">'
        f'<div class="chart-card"><h4>严重度分布（{total} 项发现）</h4>'
        f"{_severity_bars_svg(counts)}"
        f'<div class="note">严重/高危合计 {hot} 项，占 {pct}%。</div></div>'
        '<div class="chart-card"><h4>验证状态分布</h4>'
        '<div class="verify-panel">'
        f"{_verify_donut_svg(findings)}"
        '<div class="verify-legend">'
        f'<div class="row"><i style="background:var(--success)"></i>已验证 <b>{buckets["已验证"]}</b></div>'
        f'<div class="row"><i style="background:var(--warning)"></i>待复验 <b>{buckets["待复验"]}</b></div>'
        f'<div class="row"><i style="background:var(--muted-soft)"></i>节点级记录 <b>{buckets["情报记录"]}</b></div>'
        "</div></div></div></div>"
    )


def _rich_or_block(val: str) -> str:
    s = str(val or "").strip()
    if not s:
        return "<p>未采集。</p>"
    if "<" in s:
        return sanitize_visible(s)
    return f"<p>{_esc(sanitize_visible(s))}</p>"


def _summary_html(data: dict, counts: dict[str, int], enrich: dict | None) -> str:
    p = data.get("project") or {}
    target = p.get("target") or "授权目标"
    left = (enrich or {}).get("summary_overview") or (
        f"<p>对授权目标 <code>{_esc(target)}</code> 开展授权渗透测试。"
        f"共登记 {counts.get('total') or 0} 项风险，其中严重 {counts.get('critical') or 0} 项、"
        f"高危 {counts.get('high') or 0} 项。"
        + ("测试过程中已证实可获取目标服务器权限。" if data.get("has_shell") else "测试过程中尚未证实服务器权限落地。")
        + "</p>"
    )
    right = (enrich or {}).get("summary_conclusions") or _default_conclusions(data, counts)
    note = (enrich or {}).get("verify_note") or (
        "全部验证以最小影响方式执行，未改动业务数据。漏洞分级：严重 = 可直接导致权限失陷或平台接管；"
        "高危 = 可直接导致数据泄露或构成命令执行前置面；中低危 = 信息泄露与配置类风险。"
    )
    left_html = left if str(left).lstrip().startswith("<") else _rich_or_block(left)
    right_html = right if str(right).lstrip().startswith("<") else _rich_or_block(right)
    note_html = note if "<" in str(note) else _esc(sanitize_visible(note))
    return (
        '<div class="sum-grid">'
        '<div class="sum-card"><h3><span class="dot"></span>测试概况与结论</h3>'
        f"{sanitize_visible(str(left_html))}</div>"
        '<div class="sum-card"><h3><span class="dot"></span>关键结论</h3>'
        f"{sanitize_visible(str(right_html))}</div></div>"
        f'<div class="sum-foot"><b>验证说明：</b>{note_html}</div>'
    )


def _default_conclusions(data: dict, counts: dict[str, int]) -> str:
    tops = [f for f in (data.get("findings") or []) if _sev(f) in ("critical", "high", "medium")][:5]
    if not tops:
        return "<ul class=\"concl\"><li><span class=\"tag-sev med\">中危</span><span>未发现严重或高危项；仍建议复核中低危暴露面。</span></li></ul>"
    lis = "".join(
        f'<li><span class="tag-sev {SEV_CHIP[_sev(f)]}">{SEV_LABEL[_sev(f)]}</span>'
        f"<span>{_esc(_title(f))}</span></li>"
        for f in tops
    )
    grade = "严重" if counts.get("critical") else ("高危" if counts.get("high") else "中低")
    return (
        f'<ul class="concl">{lis}</ul>'
        f'<p style="margin-top:12px;font-size:13px;color:var(--body-strong)">'
        f'整体风险评级：<b style="color:var(--error)">{grade}</b>。</p>'
    )


def _cover_meta(data: dict, enrich: dict | None) -> str:
    p = data.get("project") or {}
    name = sanitize_visible(str(p.get("name") or "授权项目"))
    target = sanitize_visible(str(p.get("target") or "（集群 / 多资产）"))
    date = str(data.get("generated_at") or "")[:10]
    line1 = sanitize_visible(str((enrich or {}).get("title_line") or name))
    accent = sanitize_visible(str((enrich or {}).get("title_accent") or target))
    if accent and accent not in line1:
        h1 = f"<h1>{_esc(line1)}<br><span class=\"accent\">{_esc(accent)}</span></h1>"
    else:
        h1 = f"<h1>{_esc(line1)}</h1>"
    sub = (enrich or {}).get("sub") or f"{name}授权范围内公开服务面渗透测试。"
    findings = list(data.get("findings") or [])
    n_ok = _verify_buckets(findings)["已验证"]
    st = _graph_stats(data)
    goal = ""
    if data.get("has_shell"):
        gtxt = (enrich or {}).get("goal_text") or "已获取目标服务器权限"
        extra = sanitize_visible(str((enrich or {}).get("goal_detail") or "授权验证已证实"))
        goal = (
            f'<div class="goal-badge"><span class="flag">{_esc(sanitize_visible(str(gtxt)))}</span>'
            f'<span style="color:var(--on-dark-soft)">{_esc(extra)}</span></div>'
        )
    return (
        f'<span class="tag">AUTHORIZED PENTEST · {_esc(date)}</span>'
        f"{h1}"
        f'<p class="sub">{_esc(sanitize_visible(str(sub)))}</p>'
        '<div class="meta">'
        f'<div class="m"><b>入口目标</b> · {_esc(target)}</div>'
        '<div class="m"><b>测试性质</b> · 授权渗透测试（仅限授权环境）</div>'
        f'<div class="m"><b>验证结论</b> · {n_ok} 项已验证</div>'
        f'<div class="m"><b>攻击图</b> · {int(st.get("nodes") or 0)} 节点 / {int(st.get("edges") or 0)} 边</div>'
        "</div>"
        f"{goal}"
    )


def _footer_html(data: dict) -> str:
    p = data.get("project") or {}
    date = str(data.get("generated_at") or "")[:10]
    name = sanitize_visible(str(p.get("name") or "授权项目"))
    target = sanitize_visible(str(p.get("target") or ""))
    who = name + (f"（{target}）" if target else "")
    return (
        "<footer>"
        f"<span>授权渗透测试交付报告 · {_esc(who)}</span>"
        f"<span>数据来源：授权测试取证记录 · {_esc(date)}</span>"
        "</footer>"
    )


def _findings_slot(cards: list[str], label: str) -> str:
    if not cards:
        return ""
    n = len(cards)
    return f'<p class="sec-sub">{_esc(label)}项共 {n} 项，每一项均附证据与复现路径。</p>' + "".join(cards)


def _drop_empty_finding_sections(html: str) -> str:
    for sev in ("critical", "high", "medium", "low"):
        html = re.sub(
            rf'<section class="sec" id="{sev}">.*?</section>\s*',
            lambda m: m.group(0) if 'class="vf' in m.group(0) else "",
            html,
            count=1,
            flags=re.S,
        )
    return html


def _patch_finding_heads(html: str, by_sev: dict[str, list[str]]) -> str:
    specs = [
        ("critical", "06", "严重漏洞", "Critical", "Critical Findings — 简介 / 利用 / 修复 全文"),
        ("high", "07", "高危漏洞", "High", "High Findings — 简介 / 利用 / 修复 全文"),
        ("medium", "08", "中危漏洞", "Medium", "Medium Findings — 简介 / 利用 / 修复 全文"),
        ("low", "09", "低危漏洞", "Low", "Low Findings — 简介 / 利用 / 修复 全文"),
    ]
    for sev, num, zh, en_short, en_long in specs:
        n = len(by_sev.get(sev) or [])
        if n == 0:
            continue
        old = f'<span class="num">{num}</span><h2>{zh}</h2><span class="en">{en_short} Findings</span>'
        new = (
            f'<span class="num">{num}</span><h2>{zh}（{en_short} · {n} 项）</h2>'
            f'<span class="en">{en_long}</span>'
        )
        html = html.replace(old, new, 1)
    return html


def assemble_deliverable(data: dict, *, enrich: dict | None = None) -> str:
    """复制母版后只改 SLOT。enrich 为模型 JSON（可选）。"""
    html = load_shell()
    p = data.get("project") or {}
    findings = list(data.get("findings") or [])
    counts = _counts(findings)
    indexed = []
    by_sev: dict[str, list[str]] = {"critical": [], "high": [], "medium": [], "low": []}
    for i, f in enumerate(findings, 1):
        sev = _sev(f)
        bucket = sev if sev in by_sev else "low"
        enr = None
        if enrich and isinstance(enrich.get("findings"), dict):
            enr = enrich["findings"].get(_anchor(i)) or enrich["findings"].get(str(f.get("id") or ""))
        card = render_vf_card(f, n=i, enrich=enr)
        by_sev[bucket].append(card)
        indexed.append({
            "n": i, "anchor": _anchor(i), "title": _title(f),
            "sev": "low" if bucket == "low" else bucket,
            "cat": _category(f), "verify": _verify_label(f), "f": f,
        })
    name = sanitize_visible(str(p.get("name") or "授权项目"))
    target = sanitize_visible(str(p.get("target") or ""))
    doc_title = f"{name}{(' · ' + target) if target else ''} · 授权渗透测试交付报告"
    mapping = {
        "title": _esc(doc_title),
        "cover-meta": _cover_meta(data, enrich),
        "summary": _summary_html(data, counts, enrich),
        "kpis": _kpis_html(data, counts, findings),
        "charts": _charts_html(findings, counts),
        "path": _path_board(data, str((enrich or {}).get("path_note") or "")),
        "assets": _assets_html(data),
        "index-table": _index_table(indexed),
        "findings-critical": _findings_slot(by_sev["critical"], "严重"),
        "findings-high": _findings_slot(by_sev["high"], "高危"),
        "findings-medium": _findings_slot(by_sev["medium"], "中危"),
        "findings-low": _findings_slot(by_sev["low"], "低危"),
        "footer": _footer_html(data),
    }
    html = fill_slots(html, mapping)
    html = _patch_finding_heads(html, by_sev)
    html = _drop_empty_finding_sections(html)
    stripped = re.sub(r"<style[\s\S]*?</style>", "", html, flags=re.I)
    if LEAK_RE.search(stripped):
        html = LEAK_RE.sub("", html)
    errs = gate_html(html, has_findings=bool(findings))
    if errs:
        html = fill_slots(load_shell(), mapping)
        html = _patch_finding_heads(html, by_sev)
        html = _drop_empty_finding_sections(html)
        errs = gate_html(html, has_findings=bool(findings))
        if errs:
            raise RuntimeError("交付母版校验失败：" + ",".join(errs))
    return html


def parse_claude_enrich(text: str) -> dict:
    raw = (text or "").strip()
    blob = raw
    m = re.search(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", raw)
    if m:
        blob = m.group(1)
    else:
        obj = re.search(r"\{[\s\S]*\}", raw)
        if obj:
            blob = obj.group(0)
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}
