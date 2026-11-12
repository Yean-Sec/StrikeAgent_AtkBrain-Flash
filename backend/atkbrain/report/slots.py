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
from atkbrain_native import display_finding_severity, node_is_landed_shell
from atkbrain_native import (
    apply_shell_chrome, get_report_lang, kind_map, lab, normalize_locale,
    pn_map, set_report_lang, sev_map, verify_map,
)

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
    "medium": "var(--med)",
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
    "target": "info", "service": "svc", "host": "info", "endpoint": "info", "info": "info",
    "danger": "warn",
    "vuln": "crit", "foothold": "hold",
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
    vm = verify_map()
    if st in vm:
        return vm[st]
    return lab("intel")


def _category(f: dict) -> str:
    return sanitize_visible(str(f.get("category") or lab("uncat"))) or lab("uncat")


def _title(f: dict) -> str:
    return sanitize_visible(str(f.get("title") or lab("untitled"))) or lab("untitled")


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


def cache_stem(project_id: str, digest: str, lang: object = "zh") -> str:
    loc = normalize_locale(lang)
    return f"{project_id[:24]}-{digest[:16]}-{loc}"


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
    buckets = {"verified": 0, "pending": 0, "intel": 0}
    for f in findings:
        st = str(f.get("verification_status") or "").lower()
        if st == "verified":
            buckets["verified"] += 1
        elif st in ("pending", "flaky"):
            buckets["pending"] += 1
        else:
            buckets["intel"] += 1
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
        (lab("bar.critical"), "critical", "var(--crit)"),
        (lab("bar.high"), "high", "var(--high)"),
        (lab("bar.medium"), "medium", "var(--muted-soft)"),
        (lab("bar.low"), "low", "var(--muted)"),
    ]
    parts = [
        '<svg viewBox="0 0 640 190" xmlns="http://www.w3.org/2000/svg" '
        f'style="width:100%;height:auto" role="img" aria-label="{_esc_attr(lab("chart.sev_aria"))}">'
    ]
    for i, (label, key, col) in enumerate(rows):
        n = int(counts.get(key) or 0)
        if key == "low":
            n += int(counts.get("info") or 0)
        w = 0 if n == 0 else max(12, round(420 * n / total))
        ty = 32 + i * 40
        ry = 16 + i * 40
        tx = 150 + w + 14
        parts.append(
            f'<text x="0" y="{ty}" font-size="13" fill="var(--body)" font-family="inherit">{_esc(label)}</text>'
            f'<rect x="150" y="{ry}" width="420" height="20" rx="10" fill="var(--surface-soft)" stroke="var(--hairline)"/>'
            f'<rect x="150" y="{ry}" width="{w}" height="20" rx="10" fill="{col}"><title>{_esc(lab("n_items", n=n))}</title></rect>'
            f'<text x="{tx}" y="{ty - 1}" font-size="14" font-weight="700" fill="var(--ink)">{n}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _verify_donut_svg(findings: list[dict]) -> str:
    buckets = _verify_buckets(findings)
    total = max(1, sum(buckets.values()))
    r, circ = 74.0, 2 * math.pi * 74
    colors = [("verified", "var(--success)"), ("pending", "var(--warning)"), ("intel", "var(--muted-soft)")]
    parts = [
        '<svg viewBox="0 0 220 200" width="200" xmlns="http://www.w3.org/2000/svg" '
        f'role="img" aria-label="{_esc_attr(lab("chart.verify_aria"))}">'
    ]
    offset = 0.0
    for key, col in colors:
        n = buckets[key]
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
        f'<text x="110" y="126" text-anchor="middle" font-size="12" fill="var(--muted)">{_esc(lab("chart.total"))}</text></svg>'
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
        nodes["_tgt"] = {"title": p.get("target") or p.get("name") or lab("auth_target"), "type": "target"}
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
        detail = sanitize_visible(str(n.get("detail") or pn_map().get(typ, lab("pn.info"))))[:48]
        cards.append((cls, title, detail))
    rows_html: list[str] = []
    row_size = 3
    arrow_words = [
        lab("path.expand"), lab("path.enter"), lab("path.exploit"),
        lab("path.lateral"), lab("path.privesc"), lab("path.land"),
    ]
    for r in range(0, len(cards), row_size):
        chunk = cards[r:r + row_size]
        if r:
            rows_html.append(_parrow(lab("path.next"), down=True))
        inner: list[str] = []
        for j, (cls, title, detail) in enumerate(chunk):
            if j:
                inner.append(_parrow(arrow_words[(r + j - 1) % len(arrow_words)]))
            inner.append(_pn_card({}, cls=cls, title=title, detail=detail))
        rows_html.append(f'<div class="path-row">{"".join(inner)}</div>')
    note = sanitize_visible(path_note) or lab("path.note")
    return (
        f'<p class="sec-sub">{_esc(note)}</p>'
        '<div class="path-board"><div class="path-rows">'
        f"{''.join(rows_html)}</div>"
        '<div class="path-legend">'
        f'<span><i class="l-crit"></i>{_esc(lab("path.leg_crit"))}</span>'
        f'<span><i class="l-warn"></i>{_esc(lab("path.leg_warn"))}</span>'
        f'<span><i class="l-info"></i>{_esc(lab("path.leg_info"))}</span>'
        f'<span><i class="l-goal"></i>{_esc(lab("path.leg_goal"))}</span>'
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
            assets = [{"title": p.get("target"), "kind": "target", "detail": lab("asset.main")}]
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
        title = sanitize_visible(str(a.get("title") or a.get("key") or lab("asset")))[:28]
        raw_kind = str(a.get("kind") or "")
        kind = kind_map().get(raw_kind, lab("asset"))
        stroke = "#c64545" if raw_kind in ("vuln", "danger") else ("#5db8a6" if raw_kind == "service" else "#4c7dff")
        boxes.append(
            f'<g filter="url(#am-shadow)">'
            f'<rect x="{x}" y="{y}" width="240" height="62" rx="14" fill="#ffffff" '
            f'stroke="{stroke}" stroke-width="1.6"/>'
            f'<text x="{x + 120}" y="{y + 24}" text-anchor="middle" font-size="12" '
            f'font-weight="700" fill="{stroke}">{_esc(kind)}</text>'
            f'<text x="{x + 120}" y="{y + 44}" text-anchor="middle" font-size="14" '
            f'font-weight="700" fill="#243044">{_esc(title)}</text></g>'
        )
    return (
        '<div class="asset-map"><h4>' + _esc(lab("asset.map")) + '</h4>'
        f'<p class="am-sub">{lab("asset.map_sub", n=len(assets))}</p>'
        f'<svg viewBox="0 0 1120 {height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{_esc_attr(lab("asset.map"))}">'
        "<defs><filter id=\"am-shadow\" x=\"-12%\" y=\"-12%\" width=\"124%\" height=\"140%\">"
        '<feDropShadow dx="0" dy="1.5" stdDeviation="2" flood-color="#243044" flood-opacity="0.07"/>'
        "</filter></defs>"
        f"{''.join(boxes)}</svg></div>"
    )


def _assets_html(data: dict) -> str:
    assets = _collect_assets(data)
    cards = []
    extra = []
    for i, a in enumerate(assets):
        title = sanitize_visible(str(a.get("title") or a.get("key") or lab("asset")))
        kind = kind_map().get(str(a.get("kind") or ""), lab("asset"))
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
        f'<p class="sec-sub">{_esc(lab("asset.scope", n=len(assets)))}</p>'
        f"{_asset_map_svg(assets)}"
        f'<div class="assets">{"".join(cards)}</div>'
    )
    if extra:
        body += f'<div class="sum-foot" style="margin-top:16px"><b>{_esc(lab("asset.rest"))}</b> {"".join(extra)}</div>'
    return body


def _index_table(items: list[dict]) -> str:
    rows = []
    for it in items:
        sev = it["sev"]
        dot = SEV_DOT.get(sev, "var(--muted)")
        rows.append(
            f"<tr><td>{it['n']}</td>"
            f'<td><span class="s-dot" style="background:{dot}"></span>{_esc(sev_map().get(sev, sev))}</td>'
            f"<td>{_esc(it['title'])}</td>"
            f"<td>{_esc(it['cat'])}</td><td>{_esc(it['verify'])}</td>"
            f'<td><a class="anchor" href="#{it["anchor"]}">{_esc(lab("idx.jump"))}</a></td></tr>'
        )
    return (
        '<table class="tbl"><thead><tr>'
        f'<th style="width:56px">#</th><th style="width:90px">{_esc(lab("idx.sev"))}</th>'
        f"<th>{_esc(lab('idx.title'))}</th>"
        f'<th style="width:120px">{_esc(lab("idx.cat"))}</th><th style="width:90px">{_esc(lab("idx.status"))}</th>'
        f'<th style="width:64px">{_esc(lab("idx.anchor"))}</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _paras(val: str) -> str:
    s = str(val or "").strip()
    if not s:
        return lab("missing_p")
    if s.lstrip().startswith("<"):
        return sanitize_visible(s)
    parts = [p.strip() for p in re.split(r"\n{2,}", s) if p.strip()]
    if not parts:
        parts = [s]
    return "".join(f"<p>{_esc(sanitize_visible(p))}</p>" for p in parts)


def _steps_ol(steps: list[str]) -> str:
    lis = "".join(f"<li>{_esc(sanitize_visible(s))}</li>" for s in steps if str(s).strip())
    if not lis:
        lis = f"<li>{_esc(lab('missing_steps'))}</li>"
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
            now = items or [lab("fix.default1"), lab("fix.default2")]
            root = [sanitize_visible(verify) or lab("fix.verify")]
    if not root:
        root = [sanitize_visible(verify) or lab("fix.baseline")]
    return (
        '<div class="fix-grid">'
        f'<div class="fix-box"><h5 class="now">⚠ {_esc(lab("fix.now"))}</h5>'
        f"<ul>{''.join(f'<li>{_esc(x)}</li>' for x in now)}</ul></div>"
        f'<div class="fix-box"><h5 class="root">✔ {_esc(lab("fix.root"))}</h5>'
        f"<ul>{''.join(f'<li>{_esc(x)}</li>' for x in root)}</ul></div></div>"
    )


def _curl_of(f: dict) -> str:
    poc = f.get("poc") if isinstance(f.get("poc"), dict) else {}
    return real_poc_text(poc.get("curl") or f.get("poc_curl") or "")


def _exploit_html(steps: list[str], f: dict, enrich: dict | None = None) -> str:
    precond = str((enrich or {}).get("prerequisites") or lab("precond"))
    impact = str((enrich or {}).get("impact") or f.get("impact_detail") or f.get("impact") or lab("impact_default"))
    curl = _curl_of(f)
    pre = f"<pre>{_esc(curl)}</pre>" if curl else ""
    return (
        f"{_steps_ol(steps)}{pre}"
        f'<p style="font-size:13px;color:var(--muted)"><b>{_esc(lab("label.precond"))}</b>{_esc(sanitize_visible(precond))}</p>'
        f'<p style="font-size:13px;color:var(--muted)"><b>{_esc(lab("label.impact"))}</b>{_esc(sanitize_visible(str(impact)[:400]))}</p>'
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
            f'<div class="row"><span class="k">{_esc(lab("ev.evidence"))}</span><span>{_esc(evidence[:4000])}</span></div>'
        )
    if detail:
        chunks.append(
            f'<div class="row"><span class="k">{_esc(lab("ev.detail"))}</span><span>{_esc(detail[:2000])}</span></div>'
        )
    if url:
        href = _esc_attr(url)
        chunks.append(
            f'<div class="row"><span class="k">{_esc(lab("ev.url"))}</span>'
            f'<span class="mono"><a href="{href}" target="_blank" rel="noopener">{_esc(url)}</a></span></div>'
        )
    if curl:
        chunks.append(f'<div class="row"><span class="k">{_esc(lab("ev.curl"))}</span></div><pre>{_esc(curl)}</pre>')
    if http_raw:
        chunks.append(
            f'<div class="row"><span class="k">{_esc(lab("ev.http"))}</span></div><pre>{_esc(http_raw[:4000])}</pre>'
        )
    steps = list(f.get("manual_steps") or [])
    if steps:
        chunks.append('<div class="row"><span class="k">' + _esc(lab("ev.steps")) + '</span></div>' + _steps_ol(steps[:8]))
    if not chunks:
        chunks.append(f"<pre>{_esc(lab('ev.missing'))}</pre>")
    return (
        f'<details class="ev"><summary>{_esc(lab("ev.summary"))}</summary>'
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
        intro = str(f.get("mechanism") or f.get("root_cause") or f.get("description") or lab("missing"))
    if not impact:
        impact = str(f.get("impact_detail") or f.get("impact") or "")
    if not steps:
        steps = list(f.get("manual_steps") or [])
    if not fixes:
        fixes = [
            lab("vf.fix_auth"),
            lab("vf.fix_pwd") if "口令" in (intro + _title(f)) or "password" in (intro + _title(f)).lower() else lab("vf.fix_iso"),
        ]
    intro_html = _paras(intro)
    if impact and not str(intro).lstrip().startswith("<"):
        intro_html += _paras(impact)
    vcolor = "var(--ok)" if vlab == lab("verify.verified") else ("var(--warning)" if vlab == lab("verify.pending") else "var(--muted)")
    return (
        f'<article class="vf {chip}" id="{anchor}">'
        f'<div class="vhead">'
        f'<div class="vtitle-row"><span class="sev-chip {chip}">{_esc(sev_map()[sev])}</span>'
        f"<h3>{_esc(_title(f))}</h3></div>"
        f'<div class="vmeta"><span>{_esc(lab("vf.type"))} {_esc(_category(f))}</span>'
        f'<span>{_esc(lab("vf.status"))} <b style="color:{vcolor}">{_esc(vlab)}</b></span>'
        f'<span>{_esc(lab("second_yes") if f.get("secondary_verified") else lab("second_no"))}</span>'
        f'</div></div>'
        f'<div class="vbody">'
        f'<div class="vsec"><h4><span class="tick">①</span> {_esc(lab("vf.intro"))}</h4>{intro_html}</div>'
        f'<div class="vsec"><h4><span class="tick">②</span> {_esc(lab("vf.exploit"))}</h4>'
        f"{_exploit_html(steps, f, enrich)}</div>"
        f'<div class="vsec"><h4><span class="tick g">③</span> {_esc(lab("vf.fix"))}</h4>'
        f"{_fixes_html(fixes, verify, enrich)}</div>"
        f"{_evidence_html(f)}"
        f"</div></article>"
    )


_HOST_ROOT_RE = re.compile(r"宿主|host[-_ ]?root|hostroot|docker[-_ ]?host|外层宿主", re.I)
_PORT_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}):(\d{2,5})\b")
_IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
_APP_NAMES = (
    ("linkvault", "linkvault"),
    ("aegis", "aegis"),
    ("pan-os", "panos"),
    ("panos", "panos"),
    ("gitlab", "gitlab"),
    ("render again", "renderagain"),
    ("renderagain", "renderagain"),
)


def _node_tags(node: dict) -> set[str]:
    return {str(t).lower() for t in (node.get("tags") or [])}


def _generic_shell_title(title: str) -> bool:
    def compact(text: str) -> str:
        return re.sub(r"[\s:：（）()@.\d-]", "", text or "").lower()

    raw = compact(title)
    stripped = compact(LEAK_RE.sub("", title or ""))
    generic = {"", "getshellroot", "getshell", "立足点shellroot", "立足点shell", "root"}
    return raw in generic or stripped in generic


def _access_bucket(node: dict) -> str:
    key = str(node.get("key") or "")
    title = str(node.get("title") or "")
    blob = f"{key} {title}"
    low = blob.lower()
    tags = _node_tags(node)
    if tags & {"docker-host", "host-root", "escaped"} or _HOST_ROOT_RE.search(blob) or "hostroot" in low or "host-root" in low:
        return "host-root"
    for needle, name in _APP_NAMES:
        if needle in low:
            return f"app:{name}"
    port = _PORT_RE.search(blob)
    if port:
        return f"port:{port.group(1)}"
    ips = _IPV4_RE.findall(blob)
    if ips:
        return f"ip:{ips[0]}"
    return f"key:{key}"


def _merge_access_buckets(groups: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {k: list(v) for k, v in groups.items()}
    app_text = {
        key: " ".join(titles)
        for key, titles in merged.items()
        if key.startswith("app:")
    }
    for key, titles in list(merged.items()):
        if key.startswith("app:") or key == "host-root":
            continue
        token = key.split(":", 1)[1]
        if len(token) < 4:
            continue
        home = next((app for app, text in app_text.items() if token and token in text), "")
        if not home:
            continue
        merged[home].extend(titles)
        del merged[key]
    return merged


def obtained_access_labels(data: dict) -> list[str]:
    """已落地的命令执行，按主机或应用去重。同一处权限只算一条。"""
    nodes = list(((data.get("graph") or {}).get("nodes")) or [])
    groups: dict[str, list[str]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if not node_is_landed_shell(
            str(node.get("type") or ""),
            str(node.get("key") or ""),
            list(node.get("tags") or []),
            bool(node.get("is_rce")),
        ):
            continue
        title = sanitize_visible(str(node.get("title") or "")).strip()
        if not title or _generic_shell_title(title):
            title = ""
        groups.setdefault(_access_bucket(node), []).append(title)
    labels: list[str] = []
    for titles in _merge_access_buckets(groups).values():
        real = [item for item in titles if item]
        labels.append((sorted(real, key=lambda item: (len(item), item))[0] if real else "已获取权限")[:90])
    labels.sort()
    return labels


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
    access_n = len(obtained_access_labels(data))
    if access_n:
        goal = (
            f'<div class="kpi goal"><div class="k-ico">🏁</div><div class="k-num">{access_n}</div>'
            f'<div class="k-label">{_esc(lab("kpi.got_access"))}</div></div>'
        )
    else:
        goal = (
            '<div class="kpi"><div class="k-ico">🏁</div><div class="k-num">0</div>'
            f'<div class="k-label">{_esc(lab("kpi.no_access"))}</div></div>'
        )
    return (
        '<div class="kpis" style="margin-top:22px">'
        f'<div class="kpi"><div class="k-ico">🧾</div><div class="k-num">{total}</div>'
        f'<div class="k-label">{_esc(lab("kpi.total"))}</div></div>'
        f'<div class="kpi crit"><div class="k-ico">🔥</div><div class="k-num">{crit}</div>'
        f'<div class="k-label">{_esc(lab("kpi.crit"))}</div></div>'
        f'<div class="kpi high"><div class="k-ico">⚠️</div><div class="k-num">{high}</div>'
        f'<div class="k-label">{_esc(lab("kpi.high"))}</div></div>'
        f'<div class="kpi med"><div class="k-ico">📄</div><div class="k-num">{med} / {low}</div>'
        f'<div class="k-label">{_esc(lab("kpi.medlow"))}</div></div>'
        f'<div class="kpi teal"><div class="k-ico">🖥️</div><div class="k-num">{n_svc}</div>'
        f'<div class="k-label">{_esc(lab("kpi.svc"))}</div></div>'
        f'<div class="kpi"><div class="k-ico">✅</div><div class="k-num">{buckets["verified"]}</div>'
        f'<div class="k-label">{_esc(lab("verify.verified"))}</div></div>'
        f"{goal}"
        f'<div class="kpi"><div class="k-ico">🎯</div><div class="k-num">{p0}</div>'
        f'<div class="k-label">{_esc(lab("kpi.fixnow"))}</div></div>'
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
        f'<div class="chart-card"><h4>{_esc(lab("chart.sev_title", n=total))}</h4>'
        f"{_severity_bars_svg(counts)}"
        f'<div class="note">{_esc(lab("chart.sev_note", hot=hot, pct=pct))}</div></div>'
        f'<div class="chart-card"><h4>{_esc(lab("chart.verify_title"))}</h4>'
        '<div class="verify-panel">'
        f"{_verify_donut_svg(findings)}"
        '<div class="verify-legend">'
        f'<div class="row"><i style="background:var(--success)"></i>{_esc(lab("verify.verified"))} <b>{buckets["verified"]}</b></div>'
        f'<div class="row"><i style="background:var(--warning)"></i>{_esc(lab("verify.pending"))} <b>{buckets["pending"]}</b></div>'
        f'<div class="row"><i style="background:var(--muted-soft)"></i>{_esc(lab("chart.node_records"))} <b>{buckets["intel"]}</b></div>'
        "</div></div></div></div>"
    )


def _rich_or_block(val: str) -> str:
    s = str(val or "").strip()
    if not s:
        return lab("missing_p")
    if "<" in s:
        return sanitize_visible(s)
    return f"<p>{_esc(sanitize_visible(s))}</p>"


def _summary_html(data: dict, counts: dict[str, int], enrich: dict | None) -> str:
    p = data.get("project") or {}
    target = p.get("target") or lab("auth_target")
    left = (enrich or {}).get("summary_overview") or (
        f"<p>{lab('sum.overview', target=_esc(target), total=counts.get('total') or 0, crit=counts.get('critical') or 0, high=counts.get('high') or 0, shell=(lab('sum.shell_yes') if data.get('has_shell') else lab('sum.shell_no')))}"
    )
    right = (enrich or {}).get("summary_conclusions") or _default_conclusions(data, counts)
    note = (enrich or {}).get("verify_note") or lab("sum.note")
    left_html = left if str(left).lstrip().startswith("<") else _rich_or_block(left)
    right_html = right if str(right).lstrip().startswith("<") else _rich_or_block(right)
    accesses = obtained_access_labels(data)
    if accesses:
        items = "".join(f"<li>{_esc(label)}</li>" for label in accesses)
        left_html += f'<p><b>{_esc(lab("kpi.got_access"))}</b></p><ul>{items}</ul>'
    note_html = note if "<" in str(note) else _esc(sanitize_visible(note))
    return (
        '<div class="sum-grid">'
        f'<div class="sum-card"><h3><span class="dot"></span>{_esc(lab("sum.left"))}</h3>'
        f"{sanitize_visible(str(left_html))}</div>"
        f'<div class="sum-card"><h3><span class="dot"></span>{_esc(lab("sum.right"))}</h3>'
        f"{sanitize_visible(str(right_html))}</div></div>"
        f'<div class="sum-foot"><b>{_esc(lab("sum.verify"))}</b>{note_html}</div>'
    )


def _default_conclusions(data: dict, counts: dict[str, int]) -> str:
    tops = [f for f in (data.get("findings") or []) if _sev(f) in ("critical", "high", "medium")][:5]
    if not tops:
        return f"<ul class=\"concl\"><li><span class=\"tag-sev med\">{_esc(lab('sev.medium'))}</span><span>{_esc(lab('sum.empty'))}</span></li></ul>"
    lis = "".join(
        f'<li><span class="tag-sev {SEV_CHIP[_sev(f)]}">{sev_map()[_sev(f)]}</span>'
        f"<span>{_esc(_title(f))}</span></li>"
        for f in tops
    )
    grade = lab("sev.critical") if counts.get("critical") else (lab("sev.high") if counts.get("high") else lab("sum.grade_mid"))
    return (
        f'<ul class="concl">{lis}</ul>'
        f'<p style="margin-top:12px;font-size:13px;color:var(--body-strong)">'
        f'{_esc(lab("sum.grade"))}<b style="color:var(--error)">{_esc(grade)}</b>。</p>'
    )


def _cover_meta(data: dict, enrich: dict | None) -> str:
    p = data.get("project") or {}
    name = sanitize_visible(str(p.get("name") or lab("authorized")))
    target = sanitize_visible(str(p.get("target") or lab("cluster_target")))
    date = str(data.get("generated_at") or "")[:10]
    line1 = sanitize_visible(str((enrich or {}).get("title_line") or name))
    accent = sanitize_visible(str((enrich or {}).get("title_accent") or target))
    if accent and accent not in line1:
        h1 = f"<h1>{_esc(line1)}<br><span class=\"accent\">{_esc(accent)}</span></h1>"
    else:
        h1 = f"<h1>{_esc(line1)}</h1>"
    sub = (enrich or {}).get("sub") or lab("cover.sub", name=name)
    findings = list(data.get("findings") or [])
    n_ok = _verify_buckets(findings)["verified"]
    st = _graph_stats(data)
    goal = ""
    if data.get("has_shell"):
        gtxt = (enrich or {}).get("goal_text") or lab("cover.goal")
        extra = sanitize_visible(str((enrich or {}).get("goal_detail") or lab("cover.goal_extra")))
        goal = (
            f'<div class="goal-badge"><span class="flag">{_esc(sanitize_visible(str(gtxt)))}</span>'
            f'<span style="color:var(--on-dark-soft)">{_esc(extra)}</span></div>'
        )
    return (
        f'<span class="tag">AUTHORIZED PENTEST · {_esc(date)}</span>'
        f"{h1}"
        f'<p class="sub">{_esc(sanitize_visible(str(sub)))}</p>'
        '<div class="meta">'
        f'<div class="m"><b>{_esc(lab("cover.entry"))}</b> · {_esc(target)}</div>'
        f'<div class="m"><b>{_esc(lab("cover.nature"))}</b> · {_esc(lab("cover.nature_v"))}</div>'
        f'<div class="m"><b>{_esc(lab("cover.verify"))}</b> · {_esc(lab("cover.verify_v", n=n_ok))}</div>'
        f'<div class="m"><b>{_esc(lab("cover.graph"))}</b> · {_esc(lab("cover.graph_v", nodes=int(st.get("nodes") or 0), edges=int(st.get("edges") or 0)))}</div>'
        "</div>"
        f"{goal}"
    )


def _footer_html(data: dict) -> str:
    p = data.get("project") or {}
    date = str(data.get("generated_at") or "")[:10]
    name = sanitize_visible(str(p.get("name") or lab("authorized")))
    target = sanitize_visible(str(p.get("target") or ""))
    who = name + (f"（{target}）" if target else "")
    return (
        "<footer>"
        f"<span>{_esc(lab('brand'))} · {_esc(who)}</span>"
        f"<span>{_esc(lab('footer.src', date=date))}</span>"
        "</footer>"
    )


def _findings_slot(cards: list[str], label: str) -> str:
    if not cards:
        return ""
    n = len(cards)
    return f'<p class="sec-sub">{_esc(lab("findings.sub", label=label, n=n))}</p>' + "".join(cards)


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
        ("critical", "06", "sec06", "Critical"),
        ("high", "07", "sec07", "High"),
        ("medium", "08", "sec08", "Medium"),
        ("low", "09", "sec09", "Low"),
    ]
    loc = get_report_lang()
    for sev, num, zk, en_short in specs:
        n = len(by_sev.get(sev) or [])
        if n == 0:
            continue
        zh_shell = {
            "sec06": "严重漏洞", "sec07": "高危漏洞", "sec08": "中危漏洞", "sec09": "低危漏洞",
        }[zk]
        old = f'<span class="num">{num}</span><h2>{zh_shell}</h2><span class="en">{en_short} Findings</span>'
        title = lab(zk)
        count = lab("count_items", n=n)
        if loc == "en":
            new = f'<span class="num">{num}</span><h2>{_esc(title)} ({en_short} · {n})</h2>'
        else:
            new = (
                f'<span class="num">{num}</span><h2>{_esc(title)}（{en_short} · {count}）</h2>'
                f'<span class="en">{_esc(lab(zk + "en") or (en_short + " Findings"))}</span>'
            )
        html = html.replace(old, new, 1)
    return html


def assemble_deliverable(data: dict, *, enrich: dict | None = None, lang: object = None) -> str:
    """复制母版后只改 SLOT。enrich 为模型 JSON（可选）。"""
    loc = set_report_lang(lang if lang is not None else get_report_lang())
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
    name = sanitize_visible(str(p.get("name") or lab("authorized")))
    target = sanitize_visible(str(p.get("target") or ""))
    doc_title = f"{name}{(' · ' + target) if target else ''} · {lab('doc_suffix')}"
    mapping = {
        "title": _esc(doc_title),
        "cover-meta": _cover_meta(data, enrich),
        "summary": _summary_html(data, counts, enrich),
        "kpis": _kpis_html(data, counts, findings),
        "charts": _charts_html(findings, counts),
        "path": _path_board(data, str((enrich or {}).get("path_note") or "")),
        "assets": _assets_html(data),
        "index-table": _index_table(indexed),
        "findings-critical": _findings_slot(by_sev["critical"], lab("sev.critical")),
        "findings-high": _findings_slot(by_sev["high"], lab("sev.high")),
        "findings-medium": _findings_slot(by_sev["medium"], lab("sev.medium")),
        "findings-low": _findings_slot(by_sev["low"], lab("sev.low")),
        "footer": _footer_html(data),
    }
    html = fill_slots(html, mapping)
    html = _patch_finding_heads(html, by_sev)
    html = _drop_empty_finding_sections(html)
    html = apply_shell_chrome(html, loc)
    stripped = re.sub(r"<style[\s\S]*?</style>", "", html, flags=re.I)
    if LEAK_RE.search(stripped):
        html = LEAK_RE.sub("", html)
    errs = gate_html(html, has_findings=bool(findings))
    if errs:
        html = fill_slots(load_shell(), mapping)
        html = _patch_finding_heads(html, by_sev)
        html = _drop_empty_finding_sections(html)
        html = apply_shell_chrome(html, loc)
        errs = gate_html(html, has_findings=bool(findings))
        if errs:
            raise RuntimeError("交付母版校验失败：" + ",".join(errs))
    return html


def _json_objects(raw: str) -> list[dict]:
    """从正文里按括号配对取出 JSON 对象，后出现的优先留给调用方倒序挑选。"""
    out: list[dict] = []
    i = 0
    n = len(raw)
    while i < n:
        start = raw.find("{", i)
        if start < 0:
            break
        depth = 0
        in_str = False
        esc = False
        end = -1
        for j in range(start, n):
            ch = raw[j]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = j
                    break
        if end < 0:
            break
        blob = raw[start:end + 1]
        data = None
        for candidate in (blob, re.sub(r",\s*([}\]])", r"\1", blob)):
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                data = parsed
                break
        if data is not None:
            out.append(data)
        i = end + 1
    return out


def parse_claude_enrich(text: str) -> dict:
    raw = re.sub(r"<think>[\s\S]*?</think>", "", text or "", flags=re.I)
    raw = re.sub(r"```(?:json)?", "", raw, flags=re.I)
    objs = _json_objects(raw)
    for data in reversed(objs):
        if (
            data.get("title_line")
            or data.get("summary_overview")
            or data.get("sub")
            or data.get("findings")
        ):
            return data
    return objs[-1] if objs else {}
