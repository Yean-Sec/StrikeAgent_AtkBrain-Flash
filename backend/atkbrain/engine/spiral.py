"""螺旋覆盖账本：扫描记录 + 红队允许圈。CTF 仍用签名去重、不升圈。"""
from __future__ import annotations

import json
import re
from pathlib import Path

LEDGER_NAME = "SPIRAL.json"
RING_LABELS = {1: "小", 2: "中", 3: "大"}
_TIER_RING = {
    "top100": 1,
    "common": 1,
    "whatweb": 1,
    "san": 1,
    "top1000": 2,
    "medium": 2,
    "dnsmap": 2,
    "nuclei": 2,
    "all": 3,
    "large": 3,
    "nikto": 3,
    "dns_full": 3,
}

_NMAP_TOP = re.compile(r"--top-ports\s+(\d+)", re.I)
_NMAP_ALL = re.compile(r"(?:^|\s)-p-(?:\s|$)|(?:-p\s*1-65535)", re.I)
_NMAP_BIN = re.compile(r"\bnmap\b", re.I)
_FFUF = re.compile(r"\bffuf\b", re.I)
_GOBUSTER_DNS = re.compile(r"\bgobuster\s+dns\b", re.I)
_GOBUSTER_VHOST = re.compile(r"\bgobuster\s+vhost\b", re.I)
_WHATWEB = re.compile(r"\bwhatweb\b", re.I)
_NUCLEI = re.compile(r"\bnuclei\b", re.I)
_NIKTO = re.compile(r"\bnikto\b", re.I)
_AMASS = re.compile(r"\b(?:amass|fierce|dnsenum|dnsrecon)\b", re.I)
_FFUF_EXT = re.compile(r"(?:^|\s)(?:-e|--extensions|-x)\b", re.I)
_RECURSIVE = re.compile(r"(?:^|\s)-r\b|--recursion", re.I)
_WL_COMMON = "directory-list-2.3-small.txt"
_WL_SMALL = "dirb/common.txt"
_WL_DNS = "dnsmap.txt"
_OPEN_PORT = re.compile(r"^(\d+)/tcp\s+open", re.M | re.I)
_FFUF_HIT = re.compile(r"https?://\S+|Status:\s*\d+", re.I)


def ledger_path(workspace: str | Path) -> Path:
    return Path(workspace) / LEDGER_NAME


def empty_ledger() -> dict:
    return {
        "ring": 1,
        "allowed_ring": 1,
        "empty_plans": 0,
        "adjacent_open": False,
        "scans": [],
        "attacked": [],
    }


def load_ledger(workspace: str | Path) -> dict:
    p = ledger_path(workspace)
    if not p.is_file():
        return empty_ledger()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty_ledger()
    if not isinstance(data, dict):
        return empty_ledger()
    out = empty_ledger()
    try:
        out["ring"] = max(1, min(3, int(data.get("ring") or 1)))
    except (TypeError, ValueError):
        out["ring"] = 1
    try:
        out["allowed_ring"] = max(1, min(3, int(data.get("allowed_ring") or 1)))
    except (TypeError, ValueError):
        out["allowed_ring"] = 1
    try:
        out["empty_plans"] = max(0, int(data.get("empty_plans") or 0))
    except (TypeError, ValueError):
        out["empty_plans"] = 0
    out["adjacent_open"] = bool(data.get("adjacent_open"))
    scans = data.get("scans")
    if isinstance(scans, list):
        out["scans"] = [s for s in scans if isinstance(s, dict)]
    attacked = data.get("attacked")
    if isinstance(attacked, list):
        out["attacked"] = [a for a in attacked if isinstance(a, dict)]
    return out


def save_ledger(workspace: str | Path, ledger: dict) -> None:
    p = ledger_path(workspace)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def _scan_sig(face: str, tier: str, target: str) -> str:
    t = (target or "").strip().lower()
    return f"{face}|{tier}|{t}"


def face_ring(tier: str) -> int:
    return _TIER_RING.get((tier or "").strip().lower(), 1)


def infer_ring(ledger: dict) -> int:
    ring = 1
    for s in ledger.get("scans") or []:
        ring = max(ring, face_ring(str(s.get("tier") or "")))
    if ledger.get("adjacent_open"):
        ring = max(ring, 2)
    try:
        ring = max(ring, min(3, int(ledger.get("ring") or 1)))
    except (TypeError, ValueError):
        pass
    return ring


def ledger_allowed_ring(ledger: dict) -> int:
    try:
        return max(1, min(3, int(ledger.get("allowed_ring") or 1)))
    except (TypeError, ValueError):
        return 1


def _empty_plan_cap(limit: int | None = None) -> int:
    if limit is not None:
        try:
            return max(1, int(limit))
        except (TypeError, ValueError):
            pass
    try:
        from ..config import settings
        return max(1, int(getattr(settings, "loop_spiral_empty_plans", 6) or 6))
    except (TypeError, ValueError):
        return 6


def note_empty_plan(
    workspace: str | Path, *, grew: bool, infra: bool = False, limit: int | None = None,
) -> dict:
    """红队：有高质量增长则空转清零；非 infra 空转 +1；满 6 且未到大圈则升圈。"""
    ledger = load_ledger(workspace)
    cap = _empty_plan_cap(limit)
    promoted = False
    if grew:
        ledger["empty_plans"] = 0
    elif not infra:
        try:
            n = max(0, int(ledger.get("empty_plans") or 0)) + 1
        except (TypeError, ValueError):
            n = 1
        ar = ledger_allowed_ring(ledger)
        if n >= cap and ar < 3:
            ledger["allowed_ring"] = ar + 1
            ledger["empty_plans"] = 0
            promoted = True
        else:
            ledger["empty_plans"] = n
    save_ledger(workspace, ledger)
    out = load_ledger(workspace)
    out["promoted"] = promoted
    return out


def redteam_stall_pause_due(no_progress: int, limit: int, allowed_ring: int) -> bool:
    """红队整猎 stall 暂停：只有已经在第 3 圈之后才允许。"""
    try:
        ar = int(allowed_ring or 1)
    except (TypeError, ValueError):
        ar = 1
    if ar < 3:
        return False
    from .advisor_schedule import stall_pause_due
    return stall_pause_due(no_progress, limit)


def parse_scan_command(command: str) -> dict | None:
    """识别 nmap/ffuf/gobuster/whatweb/nuclei/nikto 档位。无法识别则 None。"""
    cmd = command or ""
    target = _guess_target(cmd)
    if _NMAP_BIN.search(cmd):
        if _NMAP_ALL.search(cmd):
            return {"face": "ports", "tier": "all", "target": target, "ban": "nmap -p-"}
        m = _NMAP_TOP.search(cmd)
        if m:
            n = int(m.group(1))
            if n <= 100:
                return {"face": "ports", "tier": "top100", "target": target, "ban": "nmap --top-ports 100"}
            return {"face": "ports", "tier": "top1000", "target": target, "ban": "nmap --top-ports 1000"}
        return {"face": "ports", "tier": "top1000", "target": target, "ban": "nmap"}
    if _NIKTO.search(cmd):
        return {"face": "dirs", "tier": "large", "target": target, "ban": "nikto"}
    if _FFUF.search(cmd) or "gobuster dir" in cmd.lower() or "feroxbuster" in cmd.lower():
        large_tech = bool(
            _FFUF_EXT.search(cmd)
            or _RECURSIVE.search(cmd)
            or "backup" in cmd.lower()
        )
        if large_tech:
            return {"face": "dirs", "tier": "large", "target": target, "ban": "ffuf 大圈递归/扩展名"}
        if _WL_COMMON in cmd or "directory-list-2.3-small" in cmd:
            return {"face": "dirs", "tier": "medium", "target": target, "ban": "ffuf 中档 directory-list-2.3-small"}
        if _WL_SMALL in cmd or "common.txt" in cmd:
            return {"face": "dirs", "tier": "common", "target": target, "ban": "ffuf common.txt"}
        return {"face": "dirs", "tier": "common", "target": target, "ban": "ffuf"}
    if _GOBUSTER_DNS.search(cmd):
        tier = "dnsmap" if _WL_DNS in cmd else "dns"
        return {"face": "dns", "tier": tier, "target": target, "ban": "gobuster dns"}
    if _AMASS.search(cmd):
        return {"face": "dns", "tier": "dns_full", "target": target, "ban": "amass/fierce"}
    if _GOBUSTER_VHOST.search(cmd) or "Host: FUZZ" in cmd:
        return {"face": "vhost", "tier": "dnsmap", "target": target, "ban": "gobuster vhost"}
    if _WHATWEB.search(cmd):
        return {"face": "http", "tier": "whatweb", "target": target, "ban": "whatweb"}
    if _NUCLEI.search(cmd):
        return {"face": "http", "tier": "nuclei", "target": target, "ban": "nuclei"}
    return None


def _guess_target(cmd: str) -> str:
    m = re.search(r"https?://[^\s'\"\\]+", cmd, re.I)
    if m:
        return m.group(0).rstrip("/").lower()
    m = re.search(r"(?:-d|-u|--url)\s+(\S+)", cmd, re.I)
    if m:
        return m.group(1).strip("'\"/").lower()
    m = re.search(r"--open\s+(\S+)", cmd)
    if m:
        return m.group(1).strip().lower()
    parts = cmd.split()
    if parts:
        last = parts[-1].strip("'\"")
        if last and not last.startswith("-") and "/" not in last[:4]:
            return last.lower()
    return ""


def _hits_from_stdout(face: str, stdout: str) -> list[str]:
    text = stdout or ""
    if face == "ports":
        return [m.group(1) for m in _OPEN_PORT.finditer(text)][:32]
    if face == "dirs":
        found: list[str] = []
        for line in text.splitlines():
            if "Status:" in line or "[200]" in line or "[301]" in line or "[302]" in line:
                found.append(line.strip()[:160])
            if len(found) >= 24:
                break
        return found
    return []


def record_command(workspace: str | Path, command: str, *, stdout: str = "") -> dict | None:
    parsed = parse_scan_command(command)
    if not parsed:
        return None
    ledger = load_ledger(workspace)
    sig = _scan_sig(parsed["face"], parsed["tier"], parsed["target"])
    hits = _hits_from_stdout(parsed["face"], stdout)
    existing = next((s for s in ledger["scans"] if _scan_sig(s.get("face", ""), s.get("tier", ""), s.get("target", "")) == sig), None)
    if existing is None:
        row = {
            "face": parsed["face"],
            "tier": parsed["tier"],
            "target": parsed["target"],
            "ban": parsed.get("ban") or "",
            "hits": hits,
        }
        ledger["scans"].append(row)
    else:
        old = list(existing.get("hits") or [])
        for h in hits:
            if h not in old:
                old.append(h)
        existing["hits"] = old[:48]
        if parsed.get("ban"):
            existing["ban"] = parsed["ban"]
    if parsed["face"] == "dirs" and parsed["tier"] == "medium":
        ledger["adjacent_open"] = True
    if parsed["face"] == "vhost":
        ledger["adjacent_open"] = True
    ledger["ring"] = infer_ring(ledger)
    save_ledger(workspace, ledger)
    return parsed


def note_coverage(
    workspace: str | Path,
    *,
    face: str,
    tier: str,
    target: str = "",
    hits: list[str] | None = None,
    attacked: list[dict] | None = None,
) -> dict:
    cmd_hint = f"{face} {tier} {target}".strip()
    parsed = parse_scan_command(cmd_hint) or {
        "face": face, "tier": tier, "target": (target or "").lower(), "ban": cmd_hint,
    }
    fake_cmd = f"{face} {tier} {target} {tier}"
    if face == "ports" and tier == "top100":
        fake_cmd = f"nmap --top-ports 100 {target}"
    elif face == "ports" and tier == "all":
        fake_cmd = f"nmap -p- {target}"
    elif face == "ports":
        fake_cmd = f"nmap --top-ports 1000 {target}"
    elif tier == "nikto" or face == "http" and tier == "nikto":
        fake_cmd = f"nikto -h {target}"
    elif face == "dirs" and tier == "large":
        fake_cmd = f"ffuf -e php,bak -w /usr/share/wordlists/dirb/common.txt {target}"
    elif face == "dirs" and tier == "medium":
        fake_cmd = f"ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt {target}"
    elif face == "dirs":
        fake_cmd = f"ffuf -w /usr/share/wordlists/dirb/common.txt {target}"
    record_command(workspace, fake_cmd, stdout="")
    ledger = load_ledger(workspace)
    sig = _scan_sig(parsed["face"], parsed["tier"], parsed["target"])
    for s in ledger["scans"]:
        if _scan_sig(s.get("face", ""), s.get("tier", ""), s.get("target", "")) == sig:
            extra = [str(h) for h in (hits or []) if h]
            old = list(s.get("hits") or [])
            for h in extra:
                if h not in old:
                    old.append(h)
            s["hits"] = old[:48]
            break
    for item in attacked or []:
        if isinstance(item, dict) and item not in ledger["attacked"]:
            ledger["attacked"].append(item)
    ledger["attacked"] = ledger["attacked"][:80]
    ledger["ring"] = infer_ring(ledger)
    save_ledger(workspace, ledger)
    return ledger


def has_scan(ledger: dict, face: str, tier: str, target: str = "") -> bool:
    want = (target or "").strip().lower()
    for s in ledger.get("scans") or []:
        if s.get("face") != face or s.get("tier") != tier:
            continue
        if want and (s.get("target") or "") != want:
            continue
        return True
    return False


def adjacent_allowed(ledger: dict) -> bool:
    if ledger.get("adjacent_open"):
        return True
    return has_scan(ledger, "dirs", "medium")


def scan_ban_repeats(ledger: dict, *, objective: str | None = None) -> list[str]:
    """CTF 仍把扫描签名当禁令。红队只记账、不禁重复。"""
    from ..objective import objective_allows_flag
    if objective is not None and not objective_allows_flag(objective):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for s in ledger.get("scans") or []:
        ban = str(s.get("ban") or "").strip()
        if not ban or ban in seen:
            continue
        seen.add(ban)
        tgt = str(s.get("target") or "").strip()
        out.append(f"{ban} {tgt}".strip() if tgt else ban)
    for a in ledger.get("attacked") or []:
        path = str(a.get("url") or a.get("path") or "").strip()
        tactic = str(a.get("tactic") or "").strip()
        if path:
            line = f"{path} {tactic}".strip()
            if line not in seen:
                seen.add(line)
                out.append(line)
    return out[:12]


def format_coverage_brief(ledger: dict, *, objective: str | None = None) -> str:
    from ..objective import objective_allows_flag, objective_is_src
    ctf = bool(objective and objective_allows_flag(objective))
    src = bool(objective and objective_is_src(objective))
    scans = ledger.get("scans") or []
    if src:
        if not scans and not ledger.get("attacked"):
            return (
                "已覆盖（账本空）：SRC 先铺开入口，再按入口形态从厂商菜单选类型；"
                "nmap top-1000 + 中档目录。不要升圈、不要横向、不要预开 11 路。"
            )
        lines = ["已覆盖（SRC 不升圈）· 按入口形态选类型挖高危"]
        for s in scans[:16]:
            hits = s.get("hits") or []
            hit_txt = "、".join(str(h) for h in hits[:6]) if hits else "无命中记录"
            tgt = s.get("target") or ""
            lines.append(
                f"  · {s.get('face')}/{s.get('tier')} {tgt} — {hit_txt}"
            )
        attacked = ledger.get("attacked") or []
        if attacked:
            bits = []
            for a in attacked[:8]:
                bits.append(str(a.get("url") or a.get("path") or a.get("tactic") or "").strip())
            lines.append("已测路径：" + "、".join(x for x in bits if x))
        lines.append("低/中/高危/严重都要 report_finding 进漏洞页。禁止横向与夺旗。")
        return "\n".join(lines)
    if ctf:
        ring = infer_ring(ledger)
        label = RING_LABELS.get(ring, "小")
        adj_txt = "邻题关"
        if not scans and not ledger.get("attacked"):
            return (
                "已覆盖（账本空）：CTF 先看本题入口活体；枚举开局 top-1000 + 中档；邻题关。相同扫描不要再跑。"
            )
        lines = ["已覆盖（CTF 不升圈）· 邻题关"]
    else:
        ring = ledger_allowed_ring(ledger)
        label = RING_LABELS.get(ring, "小")
        try:
            empty_n = max(0, int(ledger.get("empty_plans") or 0))
        except (TypeError, ValueError):
            empty_n = 0
        cap = _empty_plan_cap()
        adj_txt = "旁站开" if ring >= 2 else "旁站关"
        head = f"允许圈={ring}/{label} · 空转 {empty_n}/{cap} · {adj_txt}"
        if not scans and not ledger.get("attacked"):
            extra = "第 1 圈只打当前入口；top-100 + common.txt。" if ring <= 1 else ""
            gate = "禁止抢跑更高档。" if ring <= 1 else ""
            return (
                f"已覆盖（螺旋账本空）：{head}。{extra}"
                f"按本圈完整清单做，不要因小圈做过而省略。{gate}"
            )
        lines = [f"已覆盖：{head}"]
    for s in scans[:16]:
        hits = s.get("hits") or []
        hit_txt = "、".join(str(h) for h in hits[:6]) if hits else "无命中记录"
        tgt = s.get("target") or ""
        lines.append(
            f"  · {s.get('face')}/{s.get('tier')} {tgt} — {hit_txt}"
        )
    attacked = ledger.get("attacked") or []
    if attacked:
        bits = []
        for a in attacked[:8]:
            bits.append(str(a.get("url") or a.get("path") or a.get("tactic") or "").strip())
        lines.append("已测路径：" + "、".join(x for x in bits if x))
    if ctf:
        lines.append("评测邻题始终越界。先看入口源码；没有旗再扫描。相同扫描签名不要再跑。")
    else:
        lines.append("按本圈完整清单做，不要因小圈做过而省略。")
        if ledger_allowed_ring(ledger) <= 1:
            lines.append("第 1 圈禁止抢跑 top-1000、-p-、中档目录、旁站。")
    return "\n".join(lines)
