"""每个高危发现一键导出可复现脚本（curl / python）。"""
from __future__ import annotations

from ..graph.model import normalize_severity
from ..graph.verify import is_high_severity


def poc_for_finding(finding: dict, target: str = "") -> dict:
    """返回 {curl, python}。

    优先用智能体给出的真实 PoC。高危/严重**禁止**用合成模板冒充证明；
    中危及以下在缺失时可给骨架模板。
    """
    curl = (finding.get("poc_curl") or "").strip() or None
    py = (finding.get("poc_python") or "").strip() or None
    category = (finding.get("category") or "").lower()
    title = finding.get("title") or "finding"
    evidence = finding.get("evidence") or ""
    sev = normalize_severity(category, finding.get("severity"))
    high = is_high_severity(sev, category)

    if not curl:
        if high:
            curl = (
                "# 无人工复现 PoC（高危/严重禁止使用合成模板）。\n"
                "# 请在 report_finding 时填写真实 poc_curl，或依据证据手工复现。\n"
                f"# title: {title}\n"
                f"# category: {category}\n"
                f"# evidence: {evidence[:200]}"
            )
        else:
            curl = _synth_curl(category, target, evidence)
    if not py:
        if high:
            py = (
                f'#!/usr/bin/env python3\n'
                f'"""无人工复现 PoC：{title} ({category})\n'
                f'高危/严重禁止自动合成利用脚本。请使用 agent 提供的真实 poc_python。\n'
                f'证据片段：{evidence[:200]}\n'
                f'"""\n'
                f'raise SystemExit("missing real poc_python for high/critical finding")\n'
            )
        else:
            py = _synth_python(category, target, title, evidence)
    # 附上手动验证证明摘要（若有）
    proof_bits = []
    if finding.get("proof_canary"):
        proof_bits.append(f"# proof_canary: {finding.get('proof_canary')}")
    if finding.get("proof_url"):
        proof_bits.append(f"# proof_url: {finding.get('proof_url')}")
    if finding.get("proof_detail"):
        proof_bits.append(f"# proof_detail: {str(finding.get('proof_detail'))[:240]}")
    if proof_bits:
        curl = "\n".join(proof_bits) + "\n" + curl
    return {"curl": curl, "python": py}


def _synth_curl(category: str, target: str, evidence: str) -> str:
    base = target or "http://TARGET"
    ua = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
    hint = f"# 依据发现证据手工调整以下请求：\n# {evidence[:200]}\n" if evidence else ""
    if category in ("sqli",):
        return f"{hint}curl -sk -A '{ua}' '{base}/?id=1%27' -H 'Content-Type: application/x-www-form-urlencoded'"
    if category in ("rce", "command_injection"):
        return f"{hint}curl -sk -A '{ua}' '{base}/?cmd=id'"
    if category in ("file_read", "lfi", "arbitrary_file_read"):
        return f"{hint}curl -sk -A '{ua}' '{base}/?file=../../../../etc/passwd'"
    if category in ("ssrf",):
        return f"{hint}curl -sk -A '{ua}' '{base}/?url=http://127.0.0.1/'"
    return f"{hint}curl -sk -A '{ua}' '{base}/'"


def _synth_python(category: str, target: str, title: str, evidence: str) -> str:
    base = target or "http://TARGET"
    return f'''#!/usr/bin/env python3
"""PoC: {title} ({category})
自动生成骨架，请依据证据补全利用细节。
证据片段：{evidence[:200]}
"""
import requests

TARGET = "{base}"
UA = {{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"}}


def exploit():
    s = requests.Session()
    s.verify = False
    # TODO: 依据 [{category}] 漏洞构造实际利用请求
    r = s.get(TARGET, headers=UA, timeout=15)
    print("status:", r.status_code)
    print(r.text[:500])


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    exploit()
'''
