"""厂商声称修复后，只重放这一条漏洞已经绑定的流量。"""
from __future__ import annotations

from .db import db, new_id, now
from atkbrain_native import bound_exchanges

STILL = "still_reproducible"
FIXED = "fixed"
UNSURE = "inconclusive"
LABELS = {
    STILL: "仍可复现",
    FIXED: "已修复",
    UNSURE: "无法确认",
}


async def _replay_one(row: dict) -> tuple[int | None, str]:
    import httpx

    method = str(row.get("method") or "GET").upper()
    url = str(row.get("url") or "")
    body = row.get("request_body") or None
    headers = {}
    raw = row.get("request_headers") or ""
    if isinstance(raw, str) and raw.strip().startswith("{"):
        try:
            import json
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                headers = {str(k): str(v) for k, v in loaded.items()}
        except Exception:
            headers = {}
    async with httpx.AsyncClient(timeout=12.0, follow_redirects=False) as client:
        resp = await client.request(method, url, headers=headers, content=body)
        return resp.status_code, resp.text[:4000]


def _judge(old_status: int, new_status: int | None, new_body: str) -> str:
    if new_status is None:
        return UNSURE
    if new_status in (404, 410):
        return FIXED
    if new_status == old_status:
        return STILL
    if old_status and new_status >= 400 and old_status < 400:
        return FIXED
    return UNSURE


async def retest_finding(project_id: str, finding_id: str) -> dict:
    row = await db.fetchone(
        "SELECT * FROM findings WHERE id=? AND project_id=?",
        (finding_id, project_id),
    )
    if not row:
        raise ValueError("漏洞不存在")
    exchanges = bound_exchanges(finding_id)
    proof = [x for x in exchanges if x.get("role") == "证明"] or list(exchanges)
    rid = new_id("run_")
    await db.execute(
        "INSERT INTO runs(id, project_id, status, started_at) VALUES(?,?,?,?)",
        (rid, project_id, "running", now()),
    )
    if not proof:
        conclusion = UNSURE
    else:
        votes: list[str] = []
        for item in proof:
            try:
                status, body = await _replay_one(item)
            except Exception:
                votes.append(UNSURE)
                continue
            votes.append(_judge(int(item.get("status") or 0), status, body))
        if votes and all(v == FIXED for v in votes):
            conclusion = FIXED
        elif votes and all(v == STILL for v in votes):
            conclusion = STILL
        else:
            conclusion = UNSURE
    if conclusion == FIXED:
        await db.execute(
            "UPDATE findings SET disposition=?, retest_conclusion=? WHERE id=?",
            ("fixed", conclusion, finding_id),
        )
    else:
        await db.execute(
            "UPDATE findings SET retest_conclusion=? WHERE id=?",
            (conclusion, finding_id),
        )
    await db.execute(
        "UPDATE runs SET status=?, goal_reached=0, turns=1, summary=?, ended_at=? WHERE id=?",
        ("completed", f"复测 {LABELS[conclusion]}", now(), rid),
    )
    fresh = await db.fetchone("SELECT disposition, retest_conclusion, evidence, report_repro FROM findings WHERE id=?", (finding_id,))
    return {
        "finding_id": finding_id,
        "run_id": rid,
        "conclusion": conclusion,
        "label": LABELS[conclusion],
        "disposition": (fresh or {}).get("disposition"),
        "evidence_unchanged": (fresh or {}).get("evidence") == row.get("evidence"),
        "report_unchanged": (fresh or {}).get("report_repro") == row.get("report_repro"),
    }
