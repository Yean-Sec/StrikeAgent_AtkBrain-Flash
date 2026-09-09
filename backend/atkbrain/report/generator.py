"""报告生成：聚合项目/攻击图/发现，渲染 Markdown / HTML / PDF。

报告以「项目 → 资产 → 漏洞」清单为主；攻击关系图在控制台实时查看。
"""
from __future__ import annotations

import datetime as _dt

from jinja2 import Template

from ..db import db
from ..graph import store as gstore
from ..graph.model import SEVERITY_ORDER, display_finding_severity, is_placeholder_node
from ..graph.verify import is_visible_finding
from ..objective import finding_row_visible, normalize_objective, objective_is_src, sort_findings_by_severity
from ..projects import get_project
from .finding_report import (
    finding_guidance,
    prepare_finding_report,
    render_finding_markdown,
    serialize_finding_full,
)
from .poc import poc_for_finding
from .writeup import ai_enrich_writeups, finding_from_vuln_node

try:
    from weasyprint import HTML as _WeasyHTML  # type: ignore
    _HAS_WEASY = True
except Exception:  # pragma: no cover
    _WeasyHTML = None
    _HAS_WEASY = False


def _ports_of(project: dict | None) -> list:
    if not project:
        return []
    ports = project.get("ports")
    if isinstance(ports, list):
        return ports
    cfg = project.get("config") or {}
    p2 = cfg.get("ports")
    return p2 if isinstance(p2, list) else []


def _assets_of(project: dict | None, graph: dict) -> list[dict]:
    """从目标字段 + 攻击图 target/service 节点提炼资产清单。"""
    assets: list[dict] = []
    seen: set[str] = set()
    target = (project or {}).get("target") or ""
    ports = _ports_of(project)
    if target:
        key = f"target:{target}"
        seen.add(key)
        assets.append({
            "key": key,
            "kind": "target",
            "title": target,
            "detail": f"端口 {', '.join(str(p) for p in ports)}" if ports else "全端口/默认",
        })
    for n in graph.get("nodes") or []:
        ntype = str(n.get("type") or "")
        if ntype not in ("target", "service", "endpoint", "host"):
            continue
        key = str(n.get("key") or "")
        if not key or key in seen:
            continue
        # 跳过与主目标重复的 target 节点
        if ntype == "target" and target and target in key:
            continue
        seen.add(key)
        title = str(n.get("title") or key)
        detail = n.get("detail")
        if isinstance(detail, dict):
            detail = ", ".join(f"{k}={v}" for k, v in list(detail.items())[:6])
        elif not isinstance(detail, str):
            detail = ""
        assets.append({
            "key": key,
            "kind": ntype,
            "title": title,
            "detail": (detail or "")[:200],
        })
    return assets


def _findings_sorted(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings or []:
        item = dict(f)
        item["severity"] = display_finding_severity(item)
        item["critical"] = item["severity"] == "critical"
        out.append(item)
    return sorted(
        out,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 0),
        reverse=True,
    )


def _criticals_from(findings: list[dict], graph: dict) -> list[dict]:
    criticals = [f for f in findings if display_finding_severity(f) in ("high", "critical")]
    if criticals:
        return criticals
    # 回退：若没有显式高危发现，则用高危/严重节点合成关键项，保证报告不空
    out: list[dict] = []
    for n in sorted(graph.get("nodes") or [], key=lambda x: x.get("risk_score", 0), reverse=True):
        if n.get("is_rce") or SEVERITY_ORDER.get(n.get("severity", "info"), 0) >= SEVERITY_ORDER["high"]:
            out.append({
                "severity": "critical" if n.get("is_rce") else n.get("severity", "high"),
                "category": (n.get("tags") or ["vuln"])[0] if n.get("tags") else n.get("type", "vuln"),
                "title": n.get("title", n.get("key", "")),
                "node_key": n.get("key"),
                "description": (n.get("detail") if isinstance(n.get("detail"), str) else None),
                "evidence": None, "poc_curl": None, "poc_python": None, "cvss": None,
                "critical": True,
            })
    return out


def _vulns_by_asset(findings: list[dict], assets: list[dict]) -> list[dict]:
    """按资产归组漏洞；无 node_key 的归入「未归属」。"""
    asset_keys = {a["key"] for a in assets}
    title_by_key = {a["key"]: a["title"] for a in assets}
    buckets: dict[str, list[dict]] = {a["key"]: [] for a in assets}
    orphan: list[dict] = []
    for f in findings:
        nk = str(f.get("node_key") or "")
        if nk and nk in buckets:
            buckets[nk].append(f)
        elif nk and nk in asset_keys:
            buckets[nk].append(f)
        else:
            # 尝试模糊匹配：finding 的 node_key 含子串资产 key / title
            matched = None
            for a in assets:
                if nk and (a["key"] in nk or nk in a["key"] or a["title"] in nk):
                    matched = a["key"]
                    break
            if matched:
                buckets[matched].append(f)
            else:
                orphan.append(f)
    groups = []
    for a in assets:
        groups.append({
            "asset": a,
            "findings": buckets.get(a["key"]) or [],
        })
    if orphan:
        groups.append({
            "asset": {"key": "_orphan", "kind": "other", "title": "未归属资产", "detail": ""},
            "findings": orphan,
        })
    # 仅保留有漏洞的资产组；若全都没有漏洞，仍保留资产列表供「资产」段展示
    return groups


def _http_target(project: dict | None) -> str:
    target = (project or {}).get("target") or ""
    if target and not str(target).startswith("http"):
        ports = _ports_of(project)
        target = "http://" + str(target) + (f":{ports[0]}" if ports else "")
    return str(target)


def _related_edges_for(key: str, edges: list) -> list[dict]:
    out: list[dict] = []
    for e in edges or []:
        frm = e.get("from") or e.get("src")
        to = e.get("to") or e.get("dst")
        if key and (frm == key or to == key):
            out.append(e)
    return out


def _node_as_related(n: dict | None) -> dict | None:
    if not n:
        return None
    detail = n.get("detail")
    return {
        "key": n.get("key"),
        "type": n.get("type"),
        "title": n.get("title"),
        "detail": detail if isinstance(detail, str) else None,
        "severity": n.get("severity"),
        "risk_score": n.get("risk_score"),
        "tags": n.get("tags") or [],
    }


async def _export_findings(project_id: str, graph: dict, project: dict | None,
                           *, enrich_ai: bool = False) -> list[dict]:
    """DB 全量 finding（不截断）+ 图上无 finding 的 vuln 节点，并补详报字段。"""
    target = _http_target(project)
    cfg = (project or {}).get("config") or {}
    obj = normalize_objective(cfg.get("objective") or cfg.get("track"))
    nodes_by_key = {n["key"]: n for n in (graph.get("nodes") or []) if n.get("key")}
    edges = graph.get("edges") or []
    rows = await db.fetchall(
        "SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC",
        (project_id,),
    )
    findings: list[dict] = []
    linked: set[str] = set()
    for row in rows:
        if objective_is_src(obj):
            if not finding_row_visible(obj, row):
                continue
        elif not is_visible_finding(row):
            continue
        nk = row["node_key"]
        related = _node_as_related(nodes_by_key.get(nk)) if nk else None
        f = serialize_finding_full(
            row,
            related_node=related,
            related_edges=_related_edges_for(nk, edges) if nk else [],
        )
        poc = poc_for_finding(f, target)
        f = prepare_finding_report(f, poc=poc)
        f["poc"] = poc
        findings.append(f)
        if nk:
            linked.add(str(nk))
    for n in graph.get("nodes") or []:
        if n.get("type") != "vuln" or not n.get("key") or str(n["key"]) in linked:
            continue
        tags = n.get("tags") if isinstance(n.get("tags"), list) else []
        if is_placeholder_node(n.get("key"), n.get("title"), n.get("detail"), tags):
            continue
        syn = finding_from_vuln_node(n, related_edges=_related_edges_for(n["key"], edges))
        syn.update(finding_guidance(syn))
        poc = poc_for_finding(syn, target)
        syn = prepare_finding_report(syn, poc=poc)
        syn["poc"] = poc
        findings.append(syn)
    findings = sort_findings_by_severity(findings)
    if enrich_ai:
        findings = await ai_enrich_writeups(findings)
    out: list[dict] = []
    for f in findings:
        poc = f.get("poc") if isinstance(f.get("poc"), dict) else None
        prepared = prepare_finding_report(f, poc=poc)
        prepared["poc"] = poc or prepared.get("poc")
        out.append(prepared)
    return _findings_sorted(out)


def _build_section(project: dict | None, graph: dict, findings: list[dict], *,
                   has_shell: bool = False, flags_correct: int = 0) -> dict:
    assets = _assets_of(project, graph)
    findings = _findings_sorted(findings)
    criticals = _criticals_from(findings, graph)
    return {
        "project": project or {},
        "name": (project or {}).get("name") or "",
        "target": (project or {}).get("target") or "",
        "ports": _ports_of(project),
        "assets": assets,
        "findings": findings,
        "criticals": criticals,
        "vuln_groups": _vulns_by_asset(findings, assets),
        "has_shell": has_shell,
        "flags_correct": flags_correct,
        "stats": (graph or {}).get("stats") or {},
    }


async def build_report_data(project_id: str, *, enrich_ai: bool = False) -> dict:
    project = await get_project(project_id)
    if project and project.get("kind") == "cluster":
        return await build_cluster_report_data(project)
    graph = await gstore.get_graph(project_id)
    runs = await db.fetchall(
        "SELECT * FROM runs WHERE project_id=? ORDER BY started_at DESC", (project_id,)
    )
    findings = await _export_findings(project_id, graph, project, enrich_ai=enrich_ai)
    criticals = _criticals_from(findings, graph)
    rce = graph.get("rce_path", {})
    path_nodes = []
    node_by_key = {n["key"]: n for n in graph["nodes"]}
    for k in rce.get("path", []):
        if k in node_by_key:
            path_nodes.append(node_by_key[k])
    cfg = (project or {}).get("config") or {}
    from ..objective import ctf_full_score, normalize_objective
    objective = normalize_objective(cfg.get("objective", "getshell"))
    flag_rows = await db.fetchall(
        "SELECT * FROM flags WHERE project_id=? ORDER BY created_at", (project_id,)
    )
    flags_correct = len([r for r in flag_rows if r["correct"]])
    flags_score = sum(float(r["awarded"] or 0) for r in flag_rows if r["correct"])
    flags_needed = int(cfg.get("flag_count") or 0) or 1
    ctf_done = (
        objective == "flag"
        and ctf_full_score(
            flags_correct=flags_correct, flag_count=flags_needed,
            flags_score=flags_score, total_score=cfg.get("total_score"),
        )
    )
    has_shell = graph["stats"].get("has_shell", False)
    section = _build_section(project, graph, findings, has_shell=has_shell, flags_correct=flags_correct)
    return {
        "project": project,
        "graph": graph,
        "findings": findings,
        "criticals": criticals,
        "rce_path": rce,
        "path_nodes": path_nodes,
        "runs": runs,
        "objective": objective,
        "flags": flag_rows,
        "flags_correct": flags_correct,
        "flags_score": flags_score,
        "flags_needed": flags_needed,
        "ctf_done": ctf_done,
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "has_shell": has_shell,
        "sections": [section],
        "is_cluster": False,
    }


async def build_cluster_report_data(project: dict) -> dict:
    """集群总报告：按子项目分章；插图用带前缀的合并攻击图。"""
    rows = await db.fetchall("SELECT id FROM projects WHERE parent_id=? ORDER BY created_at", (project["id"],))
    children = [await build_report_data(row["id"]) for row in rows]
    stats = {"nodes": 0, "edges": 0, "findings": 0, "critical": 0, "high": 0}
    findings: list[dict] = []
    criticals: list[dict] = []
    sections: list[dict] = []
    merged_nodes: list[dict] = []
    merged_edges: list[dict] = []
    for child in children:
        child_project = child["project"] or {}
        graph = child["graph"]
        cid = str(child_project.get("id") or "child")
        prefix = f"{cid}::"
        label = child_project.get("name") or child_project.get("target") or cid
        for n in graph.get("nodes") or []:
            k = n.get("key")
            if not k:
                continue
            nn = dict(n)
            nn["key"] = prefix + str(k)
            nn["title"] = f"{label} · {n.get('title') or k}"
            merged_nodes.append(nn)
        for e in graph.get("edges") or []:
            frm, to = e.get("from"), e.get("to")
            if not frm or not to:
                continue
            ee = dict(e)
            ee["from"] = prefix + str(frm)
            ee["to"] = prefix + str(to)
            merged_edges.append(ee)
        for key in ("nodes", "edges", "findings", "critical"):
            stats[key] = stats.get(key, 0) + int(graph.get("stats", {}).get(key) or 0)
        stats["high"] = stats.get("high", 0) + int(graph.get("stats", {}).get("high") or 0)
        # 给 finding 打上所属项目/目标，便于总览
        for f in child.get("findings") or []:
            findings.append({
                **f,
                "project_name": child_project.get("name"),
                "project_target": child_project.get("target"),
                "project_id": child_project.get("id"),
            })
        for f in child.get("criticals") or []:
            criticals.append({
                **f,
                "project_name": child_project.get("name"),
                "project_target": child_project.get("target"),
                "project_id": child_project.get("id"),
            })
        if child.get("sections"):
            sections.extend(child["sections"])
        else:
            sections.append(_build_section(
                child_project, graph, child.get("findings") or [],
                has_shell=child.get("has_shell", False),
                flags_correct=child.get("flags_correct", 0),
            ))
    graph = {"nodes": merged_nodes, "edges": merged_edges, "findings": findings, "stats": stats}
    return {
        "project": project, "graph": graph, "findings": findings, "criticals": criticals,
        "rce_path": {"path": [], "likelihood": 0}, "path_nodes": [], "runs": [],
        "objective": "cluster", "flags": [], "flags_correct": 0, "flags_score": 0, "flags_needed": 0,
        "generated_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "has_shell": any(s.get("has_shell") for s in sections),
        "sections": sections,
        "is_cluster": True,
        "cluster_children": [
            {
                "project": s["project"],
                "stats": s["stats"],
                "has_shell": s["has_shell"],
                "flags_correct": s.get("flags_correct", 0),
            }
            for s in sections
        ],
    }


def render_markdown(data: dict) -> str:
    p = data["project"] or {}
    g = data["graph"]
    obj = data.get("objective", "getshell")
    if obj == "flag":
        need = data.get("flags_needed") or 1
        prog = f"{data['flags_correct']}/{need}"
        cfg = ((data.get("project") or {}).get("config") or {})
        score_bit = f" · 分 {data.get('flags_score') or 0}"
        if cfg.get("total_score"):
            score_bit += f"/{cfg.get('total_score')}"
        if data.get("ctf_done"):
            result = f"✅ 本题满分 {prog}{score_bit}"
        elif data["flags_correct"]:
            result = f"🚩 进度 {prog}{score_bit}（未满分，继续）"
        else:
            result = "未夺取 flag"
    elif obj == "cluster":
        result = f"子项目 {len(data.get('sections') or [])} 个 · " + (
            "✅ 至少一个已 getshell" if data["has_shell"] else "尚未 getshell"
        )
    else:
        result = "✅ 已获取权限 (getshell)" if data["has_shell"] else "未获取权限"
    lines = [
        f"# StrikeAgent_AtkBrain-Flash {'夺旗(CTF)' if obj == 'flag' else '渗透测试'}报告 — {p.get('name','')}",
        "",
        f"- 目标：`{p.get('target','') or '（集群/多资产）'}`",
        f"- 生成时间：{data['generated_at']}",
        f"- 结果：{result}",
        f"- 统计：漏洞 {len(data.get('findings') or [])}（严重 {g['stats'].get('critical', 0)}）",
        "",
        "## 项目 · 资产 · 漏洞",
        "",
    ]
    sections = data.get("sections") or []
    if not sections:
        lines.append("_无子项目/资产数据_")
    for i, sec in enumerate(sections, 1):
        name = sec.get("name") or sec.get("project", {}).get("name") or f"项目{i}"
        target = sec.get("target") or "（无主目标）"
        ports = sec.get("ports") or []
        port_txt = ", ".join(str(x) for x in ports) if ports else "全端口"
        lines += [
            f"### {i}. {name}",
            f"- **资产目标**：`{target}`",
            f"- **端口**：{port_txt}",
            f"- **结果**：{'已 getshell' if sec.get('has_shell') else '未获取权限'}"
            + (f" · flag×{sec.get('flags_correct')}" if sec.get("flags_correct") else ""),
            "",
            "#### 资产清单",
        ]
        if sec.get("assets"):
            for a in sec["assets"]:
                extra = f" — {a['detail']}" if a.get("detail") else ""
                lines.append(f"- `{a['title']}` [{a.get('kind','')}]{extra}")
        else:
            lines.append("- _（仅主目标，无额外资产节点）_")
        lines += ["", "#### 漏洞"]
        if sec.get("findings"):
            for f in sec["findings"]:
                lines.append(render_finding_markdown(
                    sec.get("project") or p, f, poc=f.get("poc") if isinstance(f.get("poc"), dict) else None,
                    heading="#####",
                ))
        else:
            lines.append("- _本项目暂无已登记漏洞_")
        lines.append("")
    return "\n".join(lines)


_HTML_TMPL = Template(r"""
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>StrikeAgent_AtkBrain-Flash 报告 · {{ p.name }}</title>
<style>
  :root{ --canvas:#faf9f5; --card:#efe9de; --dark:#181715; --ink:#141413; --body:#3d3d3a;
    --muted:#6c6a64; --coral:#cc785c; --hair:#e6dfd8; --crit:#c64545; --high:#d4a017; --ok:#5db872; }
  *{box-sizing:border-box}
  body{background:var(--canvas);color:var(--ink);margin:0;
    font-family:Inter,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.55;padding:48px}
  h1,h2,h3{font-family:"Tiempos Headline","EB Garamond",Georgia,serif;font-weight:400;letter-spacing:-.5px}
  h1{font-size:40px;margin:0 0 8px}
  h2{font-size:26px;margin:36px 0 12px;border-bottom:1px solid var(--hair);padding-bottom:8px}
  h3{font-size:20px;margin:28px 0 8px}
  h4{font-size:15px;margin:14px 0 6px;color:var(--body)}
  .meta{color:var(--muted);font-size:14px}
  .stat{display:inline-block;background:var(--card);border-radius:9999px;padding:4px 14px;margin:4px 6px 4px 0;font-size:13px}
  .shell-ok{background:var(--coral);color:#fff;padding:10px 16px;border-radius:12px;display:inline-block;font-weight:600}
  .section{background:#fffdf8;border:1px solid var(--hair);border-radius:14px;padding:22px 24px;margin:18px 0}
  .section-head{display:flex;flex-wrap:wrap;gap:10px 18px;align-items:baseline;margin-bottom:8px}
  .section-head .target{font-family:"JetBrains Mono",monospace;font-size:15px}
  .card{background:var(--card);border-radius:12px;padding:16px 18px;margin:10px 0}
  .crit{border-left:5px solid var(--crit)}
  .high{border-left:5px solid var(--high)}
  .med{border-left:5px solid #6b8cae}
  .badge{font-size:11px;letter-spacing:1px;text-transform:uppercase;padding:3px 10px;border-radius:9999px;color:#fff}
  .b-critical{background:var(--crit)} .b-high{background:var(--high);color:#141413} .b-medium{background:#8e8b82}
  .b-low{background:#b8b3a8;color:#141413} .b-info{background:#d8d2c6;color:#141413}
  pre{background:var(--dark);color:#faf9f5;padding:14px;border-radius:8px;overflow-x:auto;font-family:"JetBrains Mono",monospace;font-size:12.5px;white-space:pre-wrap}
  code{font-family:"JetBrains Mono",monospace}
  ul{padding-left:20px} li{margin:4px 0}
  .vuln-body{white-space:pre-wrap;font-size:14px;margin:0 0 10px;line-height:1.6}
  ol.repro{padding-left:22px} ol.repro li{margin:8px 0;white-space:pre-wrap;font-size:14px}
  code{font-family:"JetBrains Mono",monospace}
  ul{padding-left:20px} li{margin:4px 0}
  table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:9px;border-bottom:1px solid var(--hair);text-align:left}th{color:var(--muted);font-weight:600}
  .asset-tag{display:inline-block;background:var(--card);border-radius:8px;padding:4px 10px;margin:3px 4px 3px 0;font-size:12.5px}
  .empty{color:var(--muted);font-size:14px}
  .foot{margin-top:48px;color:var(--muted);font-size:12px;border-top:1px solid var(--hair);padding-top:16px}
  .toc a{color:var(--ink);text-decoration:none;border-bottom:1px solid var(--hair)}
  .toc li{margin:6px 0}
</style></head><body>
  <h1>StrikeAgent_AtkBrain-Flash 渗透测试报告</h1>
  <div class="meta">{{ p.name }} &nbsp;·&nbsp; {% if p.target %}目标 <code>{{ p.target }}</code>{% else %}集群 / 多资产{% endif %} &nbsp;·&nbsp; {{ generated_at }}</div>
  <p>
  {% if objective == 'flag' %}
    {% if ctf_done %}<span class="shell-ok">✅ 本题满分 {{ flags_correct }}/{{ flags_needed }} · 分 {{ flags_score }}</span>
    {% elif flags_correct %}<span class="shell-ok">🚩 进度 {{ flags_correct }}/{{ flags_needed }} · 分 {{ flags_score }}（未满分）</span>
    {% else %}<span class="stat">未夺取 flag</span>{% endif %}
  {% elif is_cluster %}
    <span class="stat">子项目 {{ sections|length }}</span>
    {% if has_shell %}<span class="shell-ok">✅ 至少一个目标已 getshell</span>{% else %}<span class="stat">尚未 getshell</span>{% endif %}
  {% else %}
    {% if has_shell %}<span class="shell-ok">✅ 已获取目标权限 (getshell)</span>{% else %}<span class="stat">未获取权限</span>{% endif %}
  {% endif %}
  </p>
  <div>
    <span class="stat">漏洞 {{ findings|length }}</span>
    <span class="stat">严重 {{ g.stats.critical or 0 }}</span>
    {% if g.stats.high is defined %}<span class="stat">高危 {{ g.stats.high or 0 }}</span>{% endif %}
    <span class="stat">项目 {{ sections|length }}</span>
  </div>

  {% if sections|length > 1 %}
  <h2>目录</h2>
  <ol class="toc">
  {% for sec in sections %}
    <li><a href="#proj-{{ loop.index }}">{{ sec.name or ('项目 ' ~ loop.index) }} — <code>{{ sec.target or '多资产' }}</code>
      （漏洞 {{ sec.findings|length }}{% if sec.has_shell %} · getshell{% endif %}）</a></li>
  {% endfor %}
  </ol>
  {% endif %}

  {% macro vuln_card(f) %}
  <div class="card {% if f.severity in ['critical'] %}crit{% elif f.severity in ['high'] %}high{% elif f.severity in ['medium'] %}med{% endif %}">
    <span class="badge b-{{ f.severity }}">{{ f.severity }}</span>
    <b>{{ f.title }}</b>
    <span class="meta"> · {{ f.category or '未分类' }}{% if f.node_key %} · <code>{{ f.node_key }}</code>{% endif %} · {{ f.verification_status or 'verified' }}</span>
    <h4>漏洞简介</h4>
    <div class="vuln-body">{{ f.description or '未采集' }}</div>
    <h4>危害</h4>
    <div class="vuln-body">{{ f.impact_detail or f.impact or '未采集' }}</div>
    <h4>手动复现</h4>
    {% if f.manual_steps %}
    <ol class="repro">
      {% for s in f.manual_steps %}<li>{{ s }}</li>{% endfor %}
    </ol>
    {% else %}
    <p class="empty">未采集可复现步骤。</p>
    {% endif %}
    {% set curl = (f.poc.curl if f.poc else none) or f.poc_curl %}
    {% set pyp = (f.poc.python if f.poc else none) or f.poc_python %}
    {% if curl %}<pre>{{ curl }}</pre>{% endif %}
    {% if pyp %}<pre>{{ pyp }}</pre>{% endif %}
    {% if not curl and not pyp and not f.manual_steps %}<p class="empty">未采集可执行 PoC。</p>{% endif %}
    <h4>红队评级</h4>
    <div class="vuln-body">{{ f.secondary_review or '未评级' }}</div>
  </div>
  {% endmacro %}

  <h2>项目 · 资产 · 漏洞</h2>
  <p class="meta">按项目列出对应资产及其漏洞。每条含简介、危害、手动复现与红队评级。</p>

  {% if not sections %}
  <p class="empty">暂无项目数据。</p>
  {% endif %}

  {% for sec in sections %}
  <div class="section" id="proj-{{ loop.index }}">
    <div class="section-head">
      <h3 style="margin:0">{{ loop.index }}. {{ sec.name or '未命名项目' }}</h3>
      <span class="target">{{ sec.target or '（无主目标）' }}</span>
      {% if sec.ports %}<span class="stat">端口 {{ sec.ports|join(', ') }}</span>{% else %}<span class="stat">全端口</span>{% endif %}
      {% if sec.has_shell %}<span class="badge b-critical">getshell</span>{% endif %}
      <span class="stat">漏洞 {{ sec.findings|length }}</span>
      <span class="stat">严重/高危 {{ sec.criticals|length }}</span>
    </div>

    <h4>资产</h4>
    {% if sec.assets %}
      {% for a in sec.assets %}
        <span class="asset-tag"><b>{{ a.title }}</b> <span class="meta">{{ a.kind }}{% if a.detail %} · {{ a.detail }}{% endif %}</span></span>
      {% endfor %}
    {% else %}
      <p class="empty">仅登记主目标，无额外资产节点。</p>
    {% endif %}

    <h4>漏洞（按资产）</h4>
    {% set ns = namespace(any=false) %}
    {% for grp in sec.vuln_groups %}
      {% if grp.findings %}
        {% set ns.any = true %}
        <p style="margin:12px 0 4px"><b>{{ grp.asset.title }}</b> <span class="meta">· {{ grp.findings|length }} 条</span></p>
        {% for f in grp.findings %}{{ vuln_card(f) }}{% endfor %}
      {% endif %}
    {% endfor %}
    {% if not ns.any %}
      {% if sec.findings %}
        {% for f in sec.findings %}{{ vuln_card(f) }}{% endfor %}
      {% else %}
        <p class="empty">本项目暂无已登记漏洞。</p>
      {% endif %}
    {% endif %}
  </div>
  {% endfor %}

  <div class="foot">由 StrikeAgent_AtkBrain-Flash 自动生成 · 仅限授权渗透测试使用</div>
</body></html>
""")


def render_html(data: dict) -> str:
    return _HTML_TMPL.render(
        p=data["project"] or {}, g=data["graph"], findings=data["findings"],
        criticals=data["criticals"], rce_path=data.get("rce_path") or {},
        path_nodes=data.get("path_nodes") or [],
        generated_at=data["generated_at"], has_shell=data["has_shell"],
        objective=data.get("objective", "getshell"), flags=data.get("flags", []),
        flags_correct=data.get("flags_correct", 0), flags_score=data.get("flags_score", 0),
        flags_needed=data.get("flags_needed", 0),
        ctf_done=bool(data.get("ctf_done")),
        sections=data.get("sections") or [],
        is_cluster=bool(data.get("is_cluster")),
        cluster_children=data.get("cluster_children") or [],
    )


def render_pdf(html: str) -> bytes | None:
    if not _HAS_WEASY:
        return None
    try:
        return _WeasyHTML(string=html).write_pdf()
    except Exception:
        return None
