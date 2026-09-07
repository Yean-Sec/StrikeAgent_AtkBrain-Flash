"""TSec Benchmark（CTF 评测平台）对接（对应 CHALLENGES_API.md）。

一套核心循环复用：benchmark 父项目持有 base_url + token；每道题 = 一个 objective=flag 的
单目标子项目。本模块只负责**控制面** API（拉题/起容器/提交 flag/关容器/得分聚合）；对靶标的
攻击流量仍走沙箱 + 守卫 + 隐蔽，与 getshell 赛道完全一致。

设计上刻意与"通用 flag 赛道"解耦：objective=flag 不依赖本模块也能独立用于任意 CTF；本模块
只是其可选的"自动拉题 + 自动提交"后端，避免把系统写死到某一评测平台。
"""
from __future__ import annotations

import asyncio
import re

import httpx

from .config import settings
from .db import db, new_id, now, _dumps, _loads
from .scope import Scope

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_UC_NUM_RE = re.compile(r"(\d+)")


def unique_code_seq(uc: str) -> tuple:
    """题号自然序，不绑某一套前缀或赛制。

    `web-2` < `web-10`，`a-01` < `e1-01` < `f2-08`，没有连字符的 `rev2` 也能排。
    """
    u = str(uc or "").strip().lower()
    if not u:
        return ((0, ""),)
    key: list[tuple[int, object]] = []
    for part in _UC_NUM_RE.split(u):
        if part == "":
            continue
        if part.isdigit():
            key.append((1, int(part)))
        else:
            key.append((0, part))
    return tuple(key)


def focus_code_key(uc: str | None) -> str:
    """unique_code 匹配键：去空白、忽略大小写。不改平台原始题号。"""
    return str(uc or "").strip().casefold()


def parse_focus_codes(raw) -> list[str]:
    """把环境变量或配置里的 unique_code 列表解析成去重保序。空则不限题。

    接受 list，或逗号/分号/空白分隔的字符串。不写死任何赛题号。
    """
    items: list[str] = []
    if raw is None:
        return []
    if isinstance(raw, (list, tuple, set)):
        items = [str(x).strip() for x in raw]
    else:
        text = str(raw).replace(";", ",").replace("\n", ",").replace("\t", ",")
        for chunk in text.split(","):
            items.extend(p.strip() for p in chunk.split())
    out: list[str] = []
    seen: set[str] = set()
    for c in items:
        if not c:
            continue
        key = focus_code_key(c)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def is_real_run_duration(
    started_at: float | None,
    ended_at: float | None,
    *,
    now_ts: float,
    min_sec: float,
) -> bool:
    """会话是否长到算一次真正 attempt。进行中的 run 用 now_ts 当结束时刻。"""
    try:
        started = float(started_at or 0)
    except (TypeError, ValueError):
        return False
    if started <= 0:
        return False
    try:
        ended = float(ended_at) if ended_at else float(now_ts)
    except (TypeError, ValueError):
        ended = float(now_ts)
    return (ended - started) >= float(min_sec or 0)


def count_real_attempts_from_runs(
    rows: list[dict] | None,
    *,
    min_sec: float,
    now_ts: float,
) -> int:
    n = 0
    for r in rows or []:
        if is_real_run_duration(
            r.get("started_at"), r.get("ended_at"), now_ts=now_ts, min_sec=min_sec,
        ):
            n += 1
    return n


def coverage_dwell_sec(
    *,
    waiting_fresh: int,
    concurrency: int,
    default_sec: int,
    floor_sec: int,
) -> int:
    """首轮 0 分让槽时长：固定 default，不因未开题排队长短压缩。

    压缩会把「点名 16 分钟没打完」记成真正 attempt，回头按分排队时低分题再也进不来。
    waiting/concurrency/floor 保留调用签名；floor 若大于 default 才抬高，绝不往下压。
    """
    default = max(0, int(default_sec or 0))
    floor = max(0, int(floor_sec or 0))
    del waiting_fresh, concurrency
    return max(default, floor) if default or floor else 0


def rotate_dwell_sec(difficulty: str | None, *, default_sec: int | None = None) -> int:
    """第二遍 0 flag dwell。默认 0：不提前让槽，由单题 60 分钟墙钟收口。"""
    base = int(
        default_sec
        if default_sec is not None
        else (settings.benchmark_no_flag_rotate_sec or 0)
    )
    if str(difficulty or "").strip().lower() == "hard":
        hard = int(getattr(settings, "benchmark_hard_no_flag_rotate_sec", 0) or 0)
        return max(base, hard)
    return base


async def real_attempt_counts(
    project_ids: list[str],
    *,
    min_sec: float | None = None,
    now_ts: float | None = None,
) -> dict[str, int]:
    """按 runs 墙钟统计真正 attempt；短会话不计。"""
    ids = [str(x) for x in project_ids if x]
    if not ids:
        return {}
    min_s = float(min_sec if min_sec is not None else settings.benchmark_min_attempt_sec or 0)
    ts = float(now_ts if now_ts is not None else now())
    q = ",".join("?" * len(ids))
    rows = await db.fetchall(
        f"SELECT project_id, started_at, ended_at FROM runs WHERE project_id IN ({q})",
        tuple(ids),
    )
    out: dict[str, int] = {i: 0 for i in ids}
    by: dict[str, list[dict]] = {i: [] for i in ids}
    for r in rows or []:
        pid = str(r.get("project_id") or "")
        if pid in by:
            by[pid].append(r)
    for pid, rs in by.items():
        out[pid] = count_real_attempts_from_runs(rs, min_sec=min_s, now_ts=ts)
    return out


_CLOSED_RE = re.compile(
    r"already\s+finished|task[_\s-]?finished|task_not_found|"
    r"(?:task|contest|environment|benchmark)\s+expired|\bexpired\b|"
    r"已结束|已过期|过期|比赛结束|环境(已)?(关闭|关停|到期)",
    re.I,
)


class BenchmarkError(Exception):
    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
        self.status = status


def is_capacity_error(exc: BaseException) -> bool:
    """平台「同时最多 N 道」额度占满（可重试，不应把子项目打成硬 error）。"""
    if not isinstance(exc, BenchmarkError):
        return False
    msg = (exc.message or "").lower()
    return exc.code == "invalid_state" and ("max active" in msg or "最多" in (exc.message or ""))


def is_environment_closed_error(exc: BaseException) -> bool:
    """评测任务/环境已到期关停：应停测、停验，禁止 autopilot 重试。"""
    if not isinstance(exc, BenchmarkError) or is_capacity_error(exc):
        return False
    blob = f"{exc.code} {exc.message}"
    if exc.code in ("task_not_found",) or (exc.status == 404 and "task_not_found" in blob.lower()):
        return True
    return bool(_CLOSED_RE.search(blob))


def is_transient_platform_error(exc: BaseException) -> bool:
    """可稍后重试的平台态错误：额度满、临时不可用。不含环境到期。"""
    if is_environment_closed_error(exc):
        return False
    if is_capacity_error(exc):
        return True
    if not isinstance(exc, BenchmarkError):
        return False
    if exc.code in ("network_error", "unavailable", "timeout"):
        return True
    return False


class BenchmarkClient:
    """Challenges API 薄封装（BENCHMARK_TOKEN 头鉴权）。"""

    def __init__(self, base_url: str, token: str, timeout: int = 30) -> None:
        self.base = (base_url or "").rstrip("/")
        self.token = token or ""
        self.timeout = timeout

    @property
    def _headers(self) -> dict:
        return {"BENCHMARK_TOKEN": self.token}

    async def _request(self, method: str, path: str, *, params=None, json=None):
        if not self.base:
            raise BenchmarkError("not_configured", "未配置 BENCHMARK_BASE_URL")
        url = f"{self.base}{path}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as cli:
                r = await cli.request(method, url, params=params, json=json, headers=self._headers)
        except Exception as e:  # 网络/VPN 未连通
            raise BenchmarkError("network_error", f"请求失败: {e}")
        if r.status_code == 200:
            try:
                return r.json()
            except Exception:
                return {}
        code, msg = "http_error", r.text[:300]
        try:
            b = r.json()
            code = b.get("code") or ("validation_error" if r.status_code == 422 else code)
            msg = b.get("message") or b.get("detail") or msg
        except Exception:
            pass
        raise BenchmarkError(str(code), str(msg), r.status_code)

    async def list_challenges(self) -> list:
        return await self._request("GET", "/openapi/v1/challenges")

    async def start(self, unique_code: str) -> dict:
        return await self._request("POST", "/openapi/v1/challenges/start", params={"unique_code": unique_code})

    async def hint(self, unique_code: str) -> dict:
        return await self._request("GET", "/openapi/v1/challenges/hint", params={"unique_code": unique_code})

    async def submit(self, unique_code: str, flag: str) -> dict:
        return await self._request("POST", "/openapi/v1/challenges/submit",
                                   json={"unique_code": unique_code, "flag": flag})

    async def close(self, unique_code: str) -> dict:
        return await self._request("POST", "/openapi/v1/challenges/close", params={"unique_code": unique_code})


# ---- 地址/Scope 辅助 --------------------------------------------------------

def _split_hostport(addr: str) -> tuple[str, int | None]:
    a = (addr or "").strip()
    if "://" in a:
        a = a.split("://", 1)[1]
    a = a.split("/")[0]
    if a.count(":") == 1:
        h, p = a.split(":")
        if p.isdigit():
            return h.lower(), int(p)
    return a.lower(), None


def scope_from_addrs(addrs: list[str]) -> Scope:
    hosts: list[str] = []
    ips: set[str] = set()
    ports: list[int] = []
    for a in addrs or []:
        h, p = _split_hostport(a)
        if not h:
            continue
        hosts.append(h)
        if _IP_RE.match(h):
            ips.add(h)
        if p:
            ports.append(p)
    return Scope(targets=sorted(set(hosts)), ips=ips,
                 ports=sorted(set(ports)) or None, mode="strict")


async def addrs_tcp_alive(addrs: list, timeout: float = 3.0) -> bool:
    """平台返回的 container_addr 里是否有任一端口能 TCP 握手。"""
    for a in addrs or []:
        host, port = _split_hostport(str(a))
        if not host:
            continue
        try:
            conn = asyncio.open_connection(host, int(port or 80))
            _reader, writer = await asyncio.wait_for(conn, timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


async def wait_addrs_ready(
    addrs: list,
    *,
    timeout_sec: float,
    interval_sec: float = 1.5,
    probe_timeout: float = 3.0,
) -> bool:
    """start 后等到任一入口 TCP 通。timeout<=0 只探一次。"""
    if await addrs_tcp_alive(addrs, timeout=probe_timeout):
        return True
    try:
        limit = float(timeout_sec or 0)
    except (TypeError, ValueError):
        limit = 0.0
    if limit <= 0:
        return False
    try:
        step = float(interval_sec or 1.5)
    except (TypeError, ValueError):
        step = 1.5
    step = max(0.2, step)
    deadline = now() + limit
    while now() < deadline:
        await asyncio.sleep(step)
        if await addrs_tcp_alive(addrs, timeout=probe_timeout):
            return True
    return False


def catalog_missing_codes(local_codes: list[str] | set[str], catalog: list | None) -> list[str]:
    """平台题单里有、本地子项目没有的 unique_code（保序）。"""
    have = {str(x or "").strip() for x in (local_codes or []) if str(x or "").strip()}
    missing: list[str] = []
    seen: set[str] = set()
    for ch in catalog or []:
        if isinstance(ch, dict):
            uc = str(ch.get("unique_code") or "").strip()
        else:
            uc = str(ch or "").strip()
        if not uc or uc in have or uc in seen:
            continue
        seen.add(uc)
        missing.append(uc)
    return missing


# ---- 配置/客户端解析 --------------------------------------------------------

def _bm_cfg(project: dict) -> dict:
    return (project.get("config") or {}).get("benchmark") or {}


async def _client_for_parent(parent: dict) -> BenchmarkClient:
    bm = _bm_cfg(parent)
    return BenchmarkClient(bm.get("base_url") or settings.benchmark_base_url,
                           bm.get("token") or settings.benchmark_token)


async def _client_for_sub(sub: dict) -> tuple[BenchmarkClient, str | None]:
    """子项目：token 从父 benchmark 项目取（不在子项目冗余存 token）。"""
    from .projects import get_project
    bm = _bm_cfg(sub)
    uc = bm.get("unique_code")
    base = bm.get("base_url") or settings.benchmark_base_url
    token = settings.benchmark_token
    if sub.get("parent_id"):
        parent = await get_project(sub["parent_id"])
        if parent:
            pbm = _bm_cfg(parent)
            base = pbm.get("base_url") or base
            token = pbm.get("token") or token
    return BenchmarkClient(base, token), uc


async def probe_environment(project: dict) -> str:
    """ok = 平台任务仍在；closed = 已到期关停；unreachable = 平台 API 暂时连不上。"""
    try:
        if project.get("kind") == "benchmark":
            client = await _client_for_parent(project)
        else:
            client, _uc = await _client_for_sub(project)
        await client.list_challenges()
        return "ok"
    except BenchmarkError as e:
        if is_environment_closed_error(e):
            return "closed"
        if e.code in ("network_error", "unavailable", "timeout", "not_configured") or e.status in (502, 503, 504):
            return "unreachable"
        return "ok"
    except Exception:
        return "unreachable"


async def parent_env_closed(project: dict | None) -> bool:
    if not project:
        return False
    cfg = project.get("config") or {}
    if cfg.get("env_closed"):
        return True
    pid = project.get("parent_id")
    if not pid:
        return False
    from .projects import get_project
    parent = await get_project(pid)
    return bool(((parent or {}).get("config") or {}).get("env_closed"))


async def mark_environment_closed(sub_project: dict, reason: str) -> None:
    parent_id = sub_project.get("parent_id")
    target_id = parent_id or sub_project.get("id")
    if not target_id:
        return
    from .projects import get_project, update_config
    p = await get_project(target_id)
    if not p:
        return
    cfg = dict(p.get("config") or {})
    cfg["env_closed"] = True
    cfg["env_closed_reason"] = (reason or "")[:240]
    cfg["autopilot"] = False
    await update_config(target_id, cfg)


async def clear_environment_closed(project_id: str) -> None:
    from .projects import get_project, update_config
    p = await get_project(project_id)
    if not p:
        return
    cfg = dict(p.get("config") or {})
    if not cfg.get("env_closed"):
        return
    cfg.pop("env_closed", None)
    cfg.pop("env_closed_reason", None)
    # mark_environment_closed 会顺手关掉 autopilot；平台仍活时必须重新打开，
    # 否则误杀后 tick 会永远 skipped=autopilot_off。
    if cfg.get("autopilot") is False:
        cfg["autopilot"] = True
    await update_config(project_id, cfg)


async def stop_parent_child_runs(
    parent_id: str | None,
    *,
    except_id: str | None = None,
) -> list[str]:
    """停掉评测父项目下仍在跑/排队的子题，并把库里的 running/queued 改回 idle。

    except_id 是正在收口的当前 loop，取消自己会把自己打成 CancelledError。
    排队任务也要停：它们已经占着调度句柄，关停后若只挡新开题，界面仍会显示「运行中/排队中」。
    """
    if not parent_id:
        return []
    from .engine.scheduler import manager
    from .projects import update_status
    rows = await db.fetchall("SELECT id, status FROM projects WHERE parent_id=?", (parent_id,))
    live_ids = [
        r["id"] for r in rows
        if r["id"] != except_id and manager.is_running(r["id"])
    ]
    if live_ids:
        await asyncio.gather(*(manager.stop(sid) for sid in live_ids), return_exceptions=True)
    stopped = list(live_ids)
    for r in rows:
        kid = r["id"]
        if except_id and kid == except_id:
            continue
        st = str(r["status"] or "")
        if kid in stopped or st in ("running", "queued"):
            try:
                await update_status(kid, "idle")
            except Exception:
                pass
    return stopped


async def stop_sibling_runs(sub_project: dict, *, except_id: str | None = None) -> list[str]:
    """停掉同一评测父项目下其它仍在跑/排队的子题（当前 loop 自己 break，不要 stop 自己）。"""
    if not sub_project:
        return []
    if sub_project.get("kind") == "benchmark":
        parent_id = sub_project.get("id")
    else:
        parent_id = sub_project.get("parent_id")
    return await stop_parent_child_runs(parent_id, except_id=except_id)


async def gate_start_against_closed_env(project: dict | None) -> str | None:
    """已标记关停则拒绝启动；平台若已恢复则清标记。返回拒绝文案或 None。"""
    if not project:
        return None
    if not (is_benchmark_sub(project) or project.get("kind") == "benchmark"):
        return None
    if not await parent_env_closed(project):
        return None
    gate = await probe_environment(project)
    if gate == "ok":
        pid = project["id"] if project.get("kind") == "benchmark" else (project.get("parent_id") or project.get("id"))
        if pid:
            await clear_environment_closed(pid)
        return None
    return "评测环境已结束或平台不可达，已停止测试与验证。"


async def _merge_parent_config(project_id: str, patch: dict) -> None:
    from .projects import get_project, update_config
    p = await get_project(project_id)
    if not p:
        return
    cfg = p.get("config") or {}
    cfg.update(patch)
    await update_config(project_id, cfg)


# ---- 编排 -------------------------------------------------------------------

async def import_challenges(project_id: str) -> dict:
    """拉题并为每道题创建 objective=flag 的子项目（去重）；题目清单缓存进父项目 config。"""
    from .projects import get_project
    parent = await get_project(project_id)
    if not parent or parent.get("kind") != "benchmark":
        raise BenchmarkError("bad_project", "非 benchmark 项目")
    client = await _client_for_parent(parent)
    challenges = await client.list_challenges()

    existing = await db.fetchall("SELECT config FROM projects WHERE parent_id=?", (project_id,))
    have = set()
    for e in existing:
        uc = ((_loads(e["config"]) or {}).get("benchmark") or {}).get("unique_code")
        if uc:
            have.add(uc)

    base = (_bm_cfg(parent).get("base_url") or settings.benchmark_base_url)
    created = []
    for ch in challenges or []:
        uc = ch.get("unique_code")
        if not uc or uc in have:
            continue
        sid = await _create_challenge_subproject(project_id, ch, base, parent=parent)
        created.append({"id": sid, "unique_code": uc,
                        "description": ch.get("description"), "flag_count": ch.get("flag_count")})
    await _merge_parent_config(project_id, {"challenges": challenges})
    return {"total": len(challenges or []), "created": len(created), "subprojects": created}


async def _create_challenge_subproject(parent_id: str, ch: dict, base: str, parent: dict | None = None) -> str:
    pid = new_id("p_")
    ts = now()
    uc = ch.get("unique_code")
    benchmark = {"unique_code": uc, "base_url": base}  # token 只在父项目
    # 导入列表已带进度时，可作为本地 flag 行缺失前的平台基准。
    if ch.get("correct_flag_count") is not None:
        benchmark["correct_flag_count"] = ch["correct_flag_count"]
    pcfg = (parent or {}).get("config") or {}
    from .objective import cfg_is_lab_src
    lab_src = cfg_is_lab_src(pcfg)
    cfg = {
        "objective": "src" if lab_src else "flag",
        "track": "src" if lab_src else "ctf",
        "stealth": True if lab_src else False,
        "proxy": False,
        "benchmark": benchmark,
        "flag_count": ch.get("flag_count"),
        "total_score": ch.get("total_score"),
        "difficulty": ch.get("difficulty"),
        "description": ch.get("description"),
    }
    hint = ch.get("hint") or ch.get("tip") or ch.get("prompt")
    if hint:
        cfg["hint"] = hint
    # 起容器前无 target/scope；start_challenge 后再回填
    scope = Scope(targets=[], mode="strict")
    await db.execute(
        """INSERT INTO projects(id, name, kind, target, ports, scope, config, status, parent_id, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (pid, uc or "challenge", "single", None, None, _dumps(scope.to_dict()),
         _dumps(cfg), "idle", parent_id, ts, ts),
    )
    return pid


async def start_challenge(sub_project: dict, *, retries: int = 5) -> dict | None:
    """为子项目起容器，拿 container_addr 并回填 target/scope。返回 {addrs, target, scope}。

    平台关闭容器与释放额度存在短暂窗口；对 max-active 额度错误先清孤儿再短退避重试，
    避免本地 bench_sem 已拿到但平台仍报满时把整题打成硬错误。
    """
    client, uc = await _client_for_sub(sub_project)
    if not uc:
        return None
    parent_id = sub_project.get("parent_id")
    res = None
    last_err: BenchmarkError | None = None
    for i in range(max(1, retries)):
        try:
            res = await client.start(uc)
            break
        except BenchmarkError as e:
            last_err = e
            if is_environment_closed_error(e):
                raise
            if is_capacity_error(e) and i + 1 < max(1, retries):
                # 先关掉本地未在跑却仍占槽的孤儿，再退避重试
                try:
                    await reconcile_orphan_containers(parent_id)
                except Exception:
                    pass
                await asyncio.sleep(1.2 * (i + 1))
                continue
            raise
    else:
        if last_err:
            raise last_err
        return None
    assert res is not None
    addrs = res.get("container_addr") or []
    bound = await _bind_container(sub_project, addrs)
    bound["reused"] = False
    return bound


async def _bind_container(sub_project: dict, addrs: list) -> dict:
    """把平台返回的 container_addr 写回子项目 target/scope。

    只替换入口身份；此前经跳板扩进来的内网 IP 必须保留。
    入口重绑不得把横向资产整表覆盖成容器公网地址。
    """
    from .scope_pivot import (
        hydrate_scope_from_graph,
        merge_scope_keep_pivots,
        peer_challenge_entry_hosts,
    )
    scope = scope_from_addrs(addrs)
    old = Scope.from_dict(sub_project.get("scope") or {})
    stale: set[str] = set()
    for a in list((_bm_cfg(sub_project).get("container_addr")) or []):
        h, _p = _split_hostport(str(a))
        if h:
            stale.add(h)
    t = str(sub_project.get("target") or "").split(":")[0].strip().lower()
    if t:
        stale.add(t)
    pid = str(sub_project.get("id") or "")
    peers: set[str] = set()
    if pid:
        try:
            peers = await peer_challenge_entry_hosts(pid)
        except Exception:
            peers = set()
    scope = merge_scope_keep_pivots(
        old, scope, stale_entry_hosts=stale, reject_hosts=peers,
    )
    if pid:
        try:
            await hydrate_scope_from_graph(pid, scope, reject_hosts=peers)
        except Exception:
            pass
    target = scope.targets[0] if scope.targets else None
    cfg = dict(sub_project.get("config") or {})
    cfg.setdefault("benchmark", {})["container_addr"] = addrs
    ready_to = float(getattr(settings, "benchmark_entry_ready_sec", 0) or 0)
    if ready_to > 0:
        try:
            await wait_addrs_ready(addrs, timeout_sec=ready_to)
        except Exception:
            pass
    fps: dict = {}
    surfaces: dict = {}
    try:
        from .entry_fingerprint import fingerprint_entry, pick_focus_addr
        fps, surfaces = await fingerprint_entry([str(a) for a in (addrs or [])], timeout=2.0)
    except Exception:
        fps = {}
        surfaces = {}
        pick_focus_addr = None  # type: ignore
    if fps and pick_focus_addr:
        cfg["benchmark"]["entry_fp"] = fps
        try:
            focus = pick_focus_addr([str(a) for a in (addrs or [])], fps)
        except Exception:
            focus = ""
        if focus:
            cfg["benchmark"]["entry_focus"] = focus
            h = str(focus).split(":")[0].strip()
            if h:
                target = h
    if surfaces:
        cfg["benchmark"]["entry_surface"] = surfaces
    await db.execute(
        "UPDATE projects SET target=?, ports=?, scope=?, config=?, updated_at=? WHERE id=?",
        (target, _dumps(scope.ports), _dumps(scope.to_dict()), _dumps(cfg), now(), sub_project["id"]),
    )
    return {"addrs": addrs, "target": target, "scope": scope}


async def reuse_open_container(sub_project: dict) -> dict | None:
    """平台上该题容器仍开着则复用（不新开、不烧 attempt）。"""
    client, uc = await _client_for_sub(sub_project)
    if not uc:
        return None
    try:
        challenges = await client.list_challenges()
    except Exception:
        return None
    ch = next((c for c in (challenges or []) if str(c.get("unique_code") or "") == str(uc)), None)
    if not ch:
        return None
    st = str(ch.get("container_status") or "stopped")
    if st == "stopped":
        return None
    addrs = ch.get("container_addr") or []
    if not addrs:
        addrs = list((_bm_cfg(sub_project).get("container_addr")) or [])
    if not addrs:
        try:
            res = await client.start(uc)
            addrs = res.get("container_addr") or []
        except BenchmarkError:
            return None
    if not addrs:
        return None
    if not await addrs_tcp_alive(addrs):
        # 平台仍标 open、传输层已死：关掉再让 ensure/start 换新箱，避免空等僵尸。
        await close_challenge(sub_project)
        return None
    bound = await _bind_container(sub_project, addrs)
    bound["reused"] = True
    return bound


async def revive_challenge(sub_project: dict, *, force_new: bool = False) -> dict | None:
    """入口不可达时重建评测容器：不清图、不烧 attempt。

    与 hard_restart 不同：这是基础设施恢复，不是换题。force_new 时先 close 再 start，
    用于「平台仍显示 open 但传输层已死」的僵尸容器。
    """
    if force_new:
        await close_challenge(sub_project)
        return await start_challenge(sub_project)
    return await ensure_challenge(sub_project, hard_restart=False)


async def ensure_challenge(sub_project: dict, *, hard_restart: bool = False) -> dict | None:
    """续跑：优先复用仍开启的容器；没有则起新容器但由调用方决定是否清图。

    hard_restart=True：强制走 start（新容器）。
    """
    if not hard_restart:
        reused = await reuse_open_container(sub_project)
        if reused:
            return reused
    return await start_challenge(sub_project)


async def submit_flag(sub_project: dict, flag: str) -> dict:
    """提交 flag，返回平台结果或结构化错误（duplicate 视为已得分）。"""
    client, uc = await _client_for_sub(sub_project)
    if not uc:
        return {"correct": None, "error": "no_unique_code"}
    try:
        res = await client.submit(uc, flag)
    except BenchmarkError as e:
        if is_environment_closed_error(e):
            try:
                await mark_environment_closed(sub_project, f"submit:{e}"[:240])
                await stop_sibling_runs(sub_project, except_id=sub_project.get("id"))
            except Exception:
                pass
        return {"correct": False, "error": e.code, "message": e.message,
                "duplicate": e.code == "duplicate"}
    cache = {
        key: res[key]
        for key in ("cumulative_score", "correct_flag_count")
        if res.get(key) is not None
    }
    if cache:
        from .projects import update_config
        cfg = sub_project.get("config") or {}
        cfg.setdefault("benchmark", {}).update(cache)
        await update_config(sub_project["id"], cfg)
    return res


async def close_challenge(sub_project: dict) -> None:
    """关闭子项目容器；失败短重试，避免静默残留占满平台 3 槽。"""
    try:
        client, uc = await _client_for_sub(sub_project)
    except Exception:
        return
    if not uc:
        return
    for i in range(3):
        try:
            await client.close(uc)
            return
        except Exception:
            if i + 1 >= 3:
                return
            await asyncio.sleep(0.6 * (i + 1))


async def reconcile_orphan_containers(parent_id: str | None = None, *, timeout: int = 8) -> dict:
    """关闭「本地未在跑」却仍占用平台额度的孤儿容器。

    与 reconcile_open_containers（启动时全关）不同：运行中只关 keep 集合之外的容器，
    避免误杀正在攻击的题。返回 {closed, active_before, keep}。
    """
    from .engine.scheduler import manager

    closed = 0
    active_before = 0
    keep: set[str] = set()
    try:
        if parent_id:
            parents = await db.fetchall("SELECT * FROM projects WHERE id=?", (parent_id,))
        else:
            parents = await db.fetchall("SELECT * FROM projects WHERE kind='benchmark'")
        # 本地正在跑的子题 unique_code 必须保留
        running_subs = await db.fetchall("SELECT * FROM projects WHERE parent_id IS NOT NULL")
        for s in running_subs:
            if manager.is_running(s["id"]):
                uc = ((_loads(s["config"]) or {}).get("benchmark") or {}).get("unique_code")
                if uc:
                    keep.add(str(uc))
    except Exception:
        return {"closed": 0, "active_before": 0, "keep": []}

    for p in parents or []:
        try:
            cfg = _loads(p["config"]) or {}
            bm = cfg.get("benchmark") or {}
            base = bm.get("base_url") or settings.benchmark_base_url
            token = bm.get("token") or settings.benchmark_token
            if not base or not token:
                continue
            client = BenchmarkClient(base, token, timeout=timeout)
            challenges = await client.list_challenges()
            for ch in challenges or []:
                st = ch.get("container_status") or "stopped"
                if st == "stopped":
                    continue
                active_before += 1
                uc = ch.get("unique_code")
                if not uc or str(uc) in keep:
                    continue
                try:
                    await client.close(uc)
                    closed += 1
                except Exception:
                    pass
        except Exception:
            continue
    return {"closed": closed, "active_before": active_before, "keep": sorted(keep)}


async def record_flag(project_id: str, unique_code: str | None, value: str, *,
                      submitted: bool, correct: bool, awarded: float, flag_index) -> str:
    fid = new_id("fl_")
    await db.execute(
        """INSERT INTO flags(id, project_id, unique_code, flag_index, value, submitted, correct, awarded, created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (fid, project_id, unique_code, flag_index, value, int(bool(submitted)),
         int(bool(correct)), float(awarded or 0), now()),
    )
    return fid


async def flag_already_incorrect(project_id: str, value: str) -> bool:
    """该值是否已经提交过且被判错。禁止换路径把同一干扰项再交一遍。"""
    v = (value or "").strip()
    if not project_id or not v:
        return False
    try:
        row = await db.fetchone(
            "SELECT id FROM flags WHERE project_id=? AND value=? AND submitted=1 AND correct=0 LIMIT 1",
            (project_id, v),
        )
        return bool(row)
    except Exception:
        return False


async def reconcile_open_containers(timeout: int = 8, *, keep_unfinished: bool = False) -> dict:
    """对账平台容器。默认关掉非 stopped 的题，回收「同时最多 3 道」额度。

    keep_unfinished=True：保留本地尚未通关子题的容器，便于后端重启后点「继续」而不是重新开题。
    已通关 / 本地没有对应子项目的容器仍关闭。
    """
    closed = 0
    keep: set[str] = set()
    if keep_unfinished:
        try:
            subs = await db.fetchall("SELECT * FROM projects WHERE parent_id IS NOT NULL")
            done = await _completed_sub_ids(list(subs or []))
            for s in subs or []:
                if s["id"] in done:
                    continue
                uc = ((_loads(s["config"]) or {}).get("benchmark") or {}).get("unique_code")
                if uc:
                    keep.add(str(uc))
        except Exception:
            keep = set()
    try:
        parents = await db.fetchall("SELECT * FROM projects WHERE kind='benchmark'")
    except Exception:
        return {"closed": 0, "kept": sorted(keep)}
    for p in parents:
        try:
            cfg = _loads(p["config"]) or {}
            bm = cfg.get("benchmark") or {}
            base = bm.get("base_url") or settings.benchmark_base_url
            token = bm.get("token") or settings.benchmark_token
            if not base or not token:
                continue
            client = BenchmarkClient(base, token, timeout=timeout)
            challenges = await client.list_challenges()
            for ch in challenges or []:
                if (ch.get("container_status") or "stopped") == "stopped":
                    continue
                uc = ch.get("unique_code")
                if uc and str(uc) in keep:
                    continue
                try:
                    await client.close(uc)
                    closed += 1
                except Exception:
                    pass
        except Exception:
            continue
    return {"closed": closed, "kept": sorted(keep)}


async def _completed_sub_ids(subs: list[dict]) -> set[str]:
    """已通关子项目集合：flag 数齐即收工（平台总分差不是漏旗）。"""
    from .objective import ctf_full_score
    done: set[str] = set()
    for s in subs:
        cfg = _loads(s["config"]) or {}
        rows = await db.fetchall(
            "SELECT flag_index, awarded FROM flags WHERE project_id=? AND correct=1", (s["id"],)
        )
        idxs = {r["flag_index"] for r in rows if r["flag_index"] is not None}
        local_got = len(idxs) if idxs else len(rows)
        local_score = sum(float(r.get("awarded") or 0) for r in rows)
        bm = cfg.get("benchmark") or {}
        got = int(bm["correct_flag_count"]) if bm.get("correct_flag_count") is not None else local_got
        score = float(bm["cumulative_score"]) if bm.get("cumulative_score") is not None else local_score
        if ctf_full_score(
            flags_correct=got,
            flag_count=cfg.get("flag_count"),
            flags_score=score,
            total_score=cfg.get("total_score"),
        ):
            done.add(s["id"])
    return done


async def _flag_progress_map(subs: list[dict]) -> dict[str, int]:
    """子项目 → 已正确 flag 数（按 flag_index 去重；无 index 时按行数）。"""
    out: dict[str, int] = {}
    for s in subs:
        rows = await db.fetchall(
            "SELECT flag_index FROM flags WHERE project_id=? AND correct=1", (s["id"],)
        )
        idxs = {r["flag_index"] for r in rows if r["flag_index"] is not None}
        out[s["id"]] = len(idxs) if idxs else len(rows)
    return out


def include_in_autopilot(
    *,
    attempts: int,
    correct_flags: int,
    resume: bool = False,
    second_pass: bool = True,
    any_fresh: bool = False,
    easy_fresh: bool = False,
    nonhard_fresh: bool = False,
    hard: bool = False,
    easy: bool = False,
    fresh_remaining: bool | None = None,
) -> bool:
    """空槽要不要拉这道闲置题。按题号覆盖，不按易/难跳过。

    未开过的始终可入选。未开完前不拉已尝试的回头题（含已有分但闲着的）。
    全部 unique_code 都开过一轮后，再回头啃 0 flag / 续啃。
    """
    del easy_fresh, nonhard_fresh, hard, easy
    if fresh_remaining is not None and not any_fresh:
        any_fresh = bool(fresh_remaining)
    att = int(attempts or 0)
    if att <= 0:
        return True
    if any_fresh:
        return False
    if int(correct_flags or 0) > 0 or resume:
        return True
    return bool(second_pass)


def schedule_fill_ids(
    pool: list[dict],
    *,
    started: set[str],
    running: set[str],
    attempts: dict[str, int],
    progress: dict[str, int],
    any_fresh: bool,
    real_attempts: dict[str, int] | None = None,
    scores: dict[str, int] | None = None,
) -> list[str]:
    """空槽填充顺序：覆盖期只开未真正跑过的题号；覆盖完先续啃再 0 flag 回头。

    real_attempts 缺省时等同 attempts。短会话应传入更小的 real_attempts，
    这样从未真正跑过的 0 分题在覆盖期仍算 fresh，覆盖完排在已尝试的 0 分题前面。
    """
    skip = set(started) | set(running)
    items = [s for s in pool if s.get("id") and s["id"] not in skip]
    att = real_attempts if real_attempts is not None else attempts

    def seq(s: dict) -> tuple:
        return (int(s.get("focus_rank") or 10_000), unique_code_seq(str(s.get("unique_code") or "")))

    def _score(s: dict) -> int:
        if scores and s["id"] in scores:
            try:
                return int(scores.get(s["id"]) or 0)
            except (TypeError, ValueError):
                return 0
        try:
            return int(s.get("total_score") or 0)
        except (TypeError, ValueError):
            return 0

    if any_fresh:
        # 从未 launch 的题优先占槽：短会话幽灵（attempts>0 但 real==0）不得挤掉未开过的题。
        never = [s for s in items if int(attempts.get(s["id"], 0) or 0) <= 0]
        if never:
            never.sort(key=seq)
            return [s["id"] for s in never]
        fresh = [s for s in items if int(att.get(s["id"], 0) or 0) <= 0]
        fresh.sort(key=seq)
        return [s["id"] for s in fresh]
    continues = [s for s in items if int(progress.get(s["id"], 0) or 0) > 0]
    zeros = [s for s in items if int(progress.get(s["id"], 0) or 0) <= 0]
    continues.sort(key=seq)
    zeros.sort(key=lambda s: (
        0 if int(att.get(s["id"], 0) or 0) <= 0 else 1,
        -_score(s),
        seq(s),
    ))
    return [s["id"] for s in continues + zeros]


def leftover_fill_ids(
    pool: list[dict],
    *,
    started: set[str],
    running: set[str],
    progress: dict[str, int],
    easy_ids: set[str] | None = None,
    deprio_ids: set[str] | None = None,
    attempts: dict[str, int] | None = None,
    any_fresh: bool = False,
    real_attempts: dict[str, int] | None = None,
    scores: dict[str, int] | None = None,
) -> list[str]:
    """兼容旧测试名：转调按题号顺序的填充。"""
    del easy_ids, deprio_ids
    att = attempts or {}
    if not att:
        att = {s["id"]: 0 for s in pool if s.get("id")}
    return schedule_fill_ids(
        pool, started=started, running=running,
        attempts=att, progress=progress, any_fresh=any_fresh,
        real_attempts=real_attempts, scores=scores,
    )


def count_remaining_fresh(
    items: list[dict],
    *,
    completed: set[str],
    busy: set[str],
    real_attempts: dict[str, int],
) -> int:
    """还没真正跑过（real attempt=0）且当前没占槽的题数。短会话幽灵也算 fresh。"""
    n = 0
    done = set(completed or ())
    live = set(busy or ())
    for s in items or []:
        sid = s.get("id")
        if not sid or sid in done or sid in live:
            continue
        if int((real_attempts or {}).get(sid, 0) or 0) <= 0:
            n += 1
    return n


def open_autopilot_slots(limit: int, occupying_ids: set[str] | list[str]) -> int:
    """评测并发空位数。dying / 刚让槽的 id 不要算进 occupying。"""
    return max(0, int(limit) - len(set(occupying_ids)))


def hunt_idle_sec(cfg: dict | None) -> float:
    """猎程图闲置秒数。无 hunt 时钟视为已停住，允许让槽。"""
    raw = (cfg or {}).get("hunt") if isinstance(cfg, dict) else None
    if not isinstance(raw, dict) or not raw:
        return 1e9
    try:
        return max(0.0, float(raw.get("idle_sec") or 0))
    except (TypeError, ValueError):
        return 1e9


def leftover_round_dwell_sec(*, leftover_waiting: int, default_sec: int) -> int:
    """覆盖完后：排队续啃题 > 0 时每道本轮最多 default 再让槽；
    续啃题能塞进并发槽时 dwell=0，打到 flag 数齐或单题硬上限。"""
    if int(leftover_waiting or 0) <= 0:
        return 0
    return max(0, int(default_sec or 0))


def pick_dwell_yield(
    running: list[dict],
    *,
    progress: dict[str, int],
    elapsed_sec: dict[str, float],
    waiting: int,
    dwell_sec: int,
    dwell_for: dict[str, int] | None = None,
    idle_sec: dict[str, float] | None = None,
    grow_grace_sec: int = 0,
    yield_partial: bool = False,
    hard_cap_sec: int = 0,
) -> list[str]:
    """本轮已啃满 dwell 且后面还有要做的题时，只让 1 个槽。

    默认已有正确 flag 不让（第二遍独占到 flag 数齐）。覆盖期 / 续啃轮转把
    yield_partial=True：部分 flag 也最多占满 hard_cap，避免为扣分后的「满分」卡死。
    一次只切一道。grow_grace：图还在长则未到 hard_cap 前不切。
    hard_cap>0 且本轮已满此时长：即使图在长、即使有部分 flag，也让槽。
    """
    if waiting <= 0:
        return []
    grace = max(0, int(grow_grace_sec or 0))
    cap = max(0, int(hard_cap_sec or 0))
    victims: list[dict] = []
    for s in running:
        sid = s["id"]
        got = int(progress.get(sid, 0) or 0)
        elapsed = float(elapsed_sec.get(sid, 0) or 0)
        hit_cap = cap > 0 and elapsed >= cap
        if got > 0 and not (yield_partial or hit_cap):
            continue
        need = int((dwell_for or {}).get(sid, dwell_sec) or dwell_sec)
        if not hit_cap:
            if need <= 0:
                continue
            if elapsed < need:
                continue
            if grace > 0:
                idle = float((idle_sec or {}).get(sid, 1e9) or 1e9)
                if idle < grace:
                    continue
        victims.append(s)
    if not victims:
        return []
    victims.sort(key=lambda s: -float(elapsed_sec.get(s["id"], 0) or 0))
    return [victims[0]["id"]]


def pick_yield_for_easies(
    running: list[dict],
    progress: dict[str, int],
    easy_ids: set[str],
    idle_easies: int,
) -> list[str]:
    """已废弃：易题插队会把后面的 f 组一直挤掉。保留符号以免旧测试导入失败。"""
    del running, progress, easy_ids, idle_easies
    return []


def is_worthy_rotate_waiter(*, attempts: int, correct_flags: int, easy: bool) -> bool:
    """超时让槽的排队对象：从未开过、已有分续啃、易题。同类 0 flag 难题不算。"""
    if int(correct_flags or 0) > 0:
        return True
    if int(attempts or 0) <= 0:
        return True
    return bool(easy)


def pick_lab_src_rotate(
    running: list[dict],
    elapsed_sec: dict[str, float],
    idle_waiting: int,
    rotate_sec: int,
) -> list[str]:
    """实验室 SRC 胶水：墙钟到点就让槽，无视 flag/易题（SRC 不夺旗）。

    不改 CTF 的 pick_zero_flag_rotate。idle_waiting 只计尚未真正开跑的子题。
    """
    if rotate_sec <= 0 or idle_waiting <= 0:
        return []
    victims: list[dict] = []
    for s in running:
        if float(elapsed_sec.get(s["id"], 0) or 0) < rotate_sec:
            continue
        victims.append(s)
    victims.sort(key=lambda s: -float(elapsed_sec.get(s["id"], 0) or 0))
    return [s["id"] for s in victims[:idle_waiting]]


def pick_zero_flag_rotate(
    running: list[dict],
    progress: dict[str, int],
    elapsed_sec: dict[str, float],
    idle_waiting: int,
    rotate_sec: int,
) -> list[str]:
    """0 flag 超时且有更值得占槽的排队题 → 停最老的若干道。

    idle_waiting 只应计入从未开过 / 已有分 / 易题，不要把剩余 0 flag 难题算进去。
    已有正确 flag 的续啃永不轮换。rotate_sec<=0 关闭。
    最多停 idle_waiting 道，避免把槽腾空却填不满。
    """
    if rotate_sec <= 0 or idle_waiting <= 0:
        return []
    victims: list[dict] = []
    for s in running:
        sid = s["id"]
        if int(progress.get(sid, 0) or 0) > 0:
            continue
        if float(elapsed_sec.get(sid, 0) or 0) < rotate_sec:
            continue
        victims.append(s)
    victims.sort(key=lambda s: -float(elapsed_sec.get(s["id"], 0) or 0))
    return [s["id"] for s in victims[:idle_waiting]]


async def _running_elapsed_sec(project_ids: list[str]) -> dict[str, float]:
    """当前 running run 已持续的秒数（按 MAX(started_at)）。缺 run 行视为 0。"""
    if not project_ids:
        return {}
    now_ts = now()
    q = ",".join("?" * len(project_ids))
    rows = await db.fetchall(
        f"SELECT project_id, MAX(started_at) AS t FROM runs "
        f"WHERE status='running' AND project_id IN ({q}) GROUP BY project_id",
        tuple(project_ids),
    )
    out: dict[str, float] = {}
    for r in rows:
        t = r.get("t")
        if t is None:
            continue
        out[str(r["project_id"])] = max(0.0, now_ts - float(t))
    return out


async def autopilot_tick(parent_id: str) -> dict:
    """把评测并发槽填满：按题号顺序做，每题至少开一轮，不按易/难跳过。

    同时最多 benchmark_max_concurrency 道真正在跑，不把几十道塞进排队。
    空槽优先下一道从未开过的题。覆盖期每题最多约 60 分钟（不因排队压缩），
    到点让槽——含已有部分正确 flag，不按平台满分占槽。全部开过一轮后回头续啃
    （hard_restart=False，猎程/攻击图接着上次），不重开推理。续啃队列仍多于空槽
    时继续按 60 分钟一轮转；能塞进并发槽后打到正确 flag 数齐或单题硬上限。
    """
    from .engine.scheduler import manager
    from .engine.hunt_clock import (
        autopilot_env_gate_action,
        note_autopilot_watchdog,
        parent_keep_alive_status,
    )
    from .projects import get_project, update_status

    parent = await get_project(parent_id)
    if not parent or parent.get("kind") != "benchmark":
        return {"running": 0, "started": 0, "remaining": 0}
    marked_closed = bool((parent.get("config") or {}).get("env_closed"))
    if marked_closed:
        try:
            probe = await probe_environment(parent)
        except Exception:
            probe = "unreachable"
        gate = autopilot_env_gate_action(marked_closed=True, probe=probe)
        if gate == "drain":
            stopped = await stop_parent_child_runs(parent_id)
            return {"running": 0, "started": 0, "remaining": 0, "skipped": "env_closed", "stopped": stopped, "probe": probe}
        if gate == "resume":
            try:
                await clear_environment_closed(parent_id)
            except Exception:
                pass
            parent = await get_project(parent_id) or parent
            print("[autopilot] 平台仍活，已清 env_closed 并恢复填槽")
    if (parent.get("config") or {}).get("autopilot") is False:
        return {"running": 0, "started": 0, "remaining": 0, "skipped": "autopilot_off"}

    # 每轮先清孤儿容器，避免平台 3 槽被已结束题占满 → UI 只剩 1~2 个真在跑
    try:
        orphans = await reconcile_orphan_containers(parent_id)
    except Exception:
        orphans = {"closed": 0}

    subs = await db.fetchall("SELECT * FROM projects WHERE parent_id=?", (parent_id,))
    if not subs:
        try:
            imported = await import_challenges(parent_id)
            print(
                f"[autopilot] 拉题 total={imported.get('total', 0)} "
                f"created={imported.get('created', 0)}"
            )
        except Exception as e:
            return {
                "running": 0, "started": 0, "remaining": 0,
                "skipped": "import_failed", "error": str(e)[:240],
            }
        subs = await db.fetchall("SELECT * FROM projects WHERE parent_id=?", (parent_id,))
        if not subs:
            return {"running": 0, "started": 0, "remaining": 0, "skipped": "no_challenges"}
    else:
        local_codes = []
        for s in subs:
            uc = str(((_loads(s.get("config")) or {}).get("benchmark") or {}).get("unique_code") or "")
            if uc:
                local_codes.append(uc)
        cached = (parent.get("config") or {}).get("challenges") or []
        if catalog_missing_codes(local_codes, cached):
            try:
                imported = await import_challenges(parent_id)
                if imported.get("created"):
                    print(f"[autopilot] 补齐题单 created={imported.get('created')}")
                    subs = await db.fetchall(
                        "SELECT * FROM projects WHERE parent_id=?", (parent_id,),
                    ) or subs
            except Exception as e:
                print(f"[autopilot] 补齐题单失败: {e}")
    completed = await _completed_sub_ids(subs)
    nxt_status = parent_keep_alive_status(
        parent.get("status"),
        env_closed=False,
        has_unfinished=len(completed) < len(subs),
    )
    if nxt_status:
        try:
            await update_status(parent_id, nxt_status)
        except Exception:
            pass
    progress = await _flag_progress_map(subs)
    running = [s for s in subs if manager.is_running(s["id"])]
    # 满分仍占槽：打断会话让 loop 按 completed 收口。本 tick 把它们从 occupying
    # 里剔除，立刻 start 替补（堵在 bench_sem 上，等 dying 释放后全速接上）。
    released: list[str] = []
    for s in list(running):
        if s["id"] not in completed:
            continue
        h = manager.get(s["id"])
        try:
            if h and h.agent is not None:
                h.agent.ctx.goal_reached = True  # type: ignore[attr-defined]
                abort = getattr(h.agent, "_abort_on_full_score", None)
                if callable(abort):
                    await abort()
                else:
                    await h.agent.interrupt()  # type: ignore[attr-defined]
            else:
                await manager.stop(s["id"])
            released.append(s["id"])
        except Exception:
            pass
    for s in subs:
        if s["id"] in completed and s.get("status") != "completed" and not manager.is_running(s["id"]):
            try:
                await update_status(s["id"], "completed")
                cfg = _loads(s["config"]) or {}
                if cfg.get("completion_reason") != "goal_reached":
                    cfg["completion_reason"] = "goal_reached"
                    from .projects import update_config
                    await update_config(s["id"], cfg)
            except Exception:
                pass

    exclude_live = set(released)
    limit = max(1, int(settings.benchmark_max_concurrency or 10))

    def _live() -> tuple[list[dict], int]:
        live = [
            s for s in subs
            if manager.is_running(s["id"]) and not manager.is_queued(s["id"])
            and s["id"] not in exclude_live
        ]
        return live, open_autopilot_slots(limit, [s["id"] for s in live])

    queued = [s for s in subs if manager.is_queued(s["id"])]
    running, slots = _live()

    from .objective import cfg_is_lab_src
    lab_src = cfg_is_lab_src(parent.get("config") or {})

    def _cfg(s: dict) -> dict:
        return _loads(s["config"]) or {}

    def _att(s: dict) -> int:
        return int((_cfg(s).get("benchmark") or {}).get("attempts") or 0)

    real_map = await real_attempt_counts([s["id"] for s in subs])

    def _real(s: dict) -> int:
        return int(real_map.get(s["id"], 0) or 0)

    def _score_of(s: dict) -> int:
        try:
            return int(_cfg(s).get("total_score") or 0)
        except (TypeError, ValueError):
            return 0

    def _fc(s: dict) -> int:
        return int(_cfg(s).get("flag_count") or 1)

    def _uc(s: dict) -> str:
        return str((_cfg(s).get("benchmark") or {}).get("unique_code") or "")

    def _is_mf(s: dict) -> bool:
        return _fc(s) >= int(settings.benchmark_multiflag_threshold or 3)

    max_mf = int(settings.benchmark_max_multiflag_concurrent or 1)
    stopped: list[str] = []

    async def _yield_victim(vid: str, message: str) -> None:
        victim = next((x for x in running if x["id"] == vid), None)
        if not victim:
            return
        try:
            await manager.stop(vid)
        except Exception:
            pass
        try:
            await close_challenge(victim)
        except Exception:
            pass
        if _att(victim) == 0:
            try:
                await bump_attempt(victim)
            except Exception:
                pass
        try:
            from .events import emit
            await emit(vid, "log", {"level": "info", "message": message})
        except Exception:
            pass
        stopped.append(vid)

    # 超额排队不占调度：只保留真正在跑的槽，下一题等空槽再按题号开。
    if queued:
        for s in list(queued):
            try:
                await manager.stop(s["id"])
            except Exception:
                pass
        running, slots = _live()

    pool = [
        s for s in subs
        if s["id"] not in completed and not manager.is_running(s["id"])
        and _real(s) < settings.benchmark_max_attempts
    ]
    _pcfg = parent.get("config") or {}
    _raw_focus = _pcfg.get("focus_codes")
    if not isinstance(_raw_focus, list) or not _raw_focus:
        _raw_focus = (_bm_cfg(parent).get("focus_codes") or [])
    focus_list = parse_focus_codes(_raw_focus)
    if not focus_list:
        focus_list = parse_focus_codes(getattr(settings, "benchmark_focus_codes", "") or "")
    focus = {focus_code_key(c) for c in focus_list}
    focus_index = {focus_code_key(c): i for i, c in enumerate(focus_list)}
    if focus:
        pool = [s for s in pool if focus_code_key(_uc(s)) in focus]
    scope = [s for s in subs if (not focus or focus_code_key(_uc(s)) in focus)]
    any_fresh = any(_real(s) == 0 and s["id"] not in completed for s in scope)

    candidates = [
        s for s in pool
        if include_in_autopilot(
            attempts=_real(s),
            correct_flags=progress.get(s["id"], 0),
            resume=bool(settings.benchmark_autopilot_resume),
            second_pass=bool(settings.benchmark_autopilot_second_pass),
            any_fresh=any_fresh,
        )
    ]
    cand_meta = [{
        "id": s["id"],
        "unique_code": _uc(s),
        "focus_rank": focus_index.get(focus_code_key(_uc(s)), 10_000),
        "total_score": _score_of(s),
    } for s in candidates]
    by_id = {s["id"]: s for s in candidates}
    running_mf = sum(1 for s in running if _is_mf(s))

    if slots <= 0 and running_mf > max_mf:
        mf_run = [s for s in running if _is_mf(s)]
        mf_run.sort(key=lambda s: (progress.get(s["id"], 0), unique_code_seq(_uc(s))))
        for victim in mf_run[: max(0, running_mf - max_mf)]:
            await _yield_victim(
                victim["id"],
                "多 flag 链路占槽过多，暂停本题把槽让给按题号排队的下一题（攻击图保留）。",
            )
        if stopped:
            exclude_live.update(stopped)
            running, slots = _live()
            running_mf = sum(1 for s in running if _is_mf(s))

    if slots <= 0:
        elapsed_map = await _running_elapsed_sec([s["id"] for s in running])
        if lab_src:
            rotate_sec = int(getattr(settings, "lab_src_rotate_sec", 3600) or 3600)
            idle_waiting = len(pool)
            for vid in pick_lab_src_rotate(running, elapsed_map, idle_waiting, rotate_sec):
                mins = max(1, rotate_sec // 60)
                await _yield_victim(
                    vid,
                    f"实验室 SRC 胶水：本题已跑满 {mins} 分钟，暂停给尚未开过的资产让槽"
                    "（攻击图与已验证发现保留）。",
                )
        else:
            first_dwell = int(getattr(settings, "benchmark_first_pass_dwell_sec", 60 * 60) or 0)
            if any_fresh:
                waiting = sum(1 for s in candidates if _real(s) == 0)
                dwell = coverage_dwell_sec(
                    waiting_fresh=waiting,
                    concurrency=limit,
                    default_sec=first_dwell,
                    floor_sec=int(getattr(settings, "benchmark_coverage_dwell_floor_sec", 60 * 60) or 0),
                )
                dwell_for = None
                grow_grace = int(getattr(settings, "benchmark_coverage_grow_grace_sec", 8 * 60) or 0)
                yield_partial = True
                hard_cap = first_dwell
                why = "覆盖预算到点，按题号让槽给尚未开过的题；猎程保留，回头接着打"
            else:
                waiting = len(candidates)
                dwell = leftover_round_dwell_sec(
                    leftover_waiting=waiting, default_sec=first_dwell,
                )
                dwell_for = None
                grow_grace = 0
                yield_partial = waiting > 0
                hard_cap = first_dwell if waiting > 0 else 0
                why = (
                    f"续啃队列还有 {waiting} 题，本轮到点让槽给下一道；猎程/攻击图接着上次，不重开"
                    if waiting > 0 else "续啃"
                )
            idle_map = {s["id"]: hunt_idle_sec(_cfg(s)) for s in running}
            for vid in pick_dwell_yield(
                running, progress=progress, elapsed_sec=elapsed_map,
                waiting=waiting, dwell_sec=dwell, dwell_for=dwell_for,
                idle_sec=idle_map, grow_grace_sec=grow_grace,
                yield_partial=yield_partial, hard_cap_sec=hard_cap,
            ):
                need = int((dwell_for or {}).get(vid, dwell) or dwell) or hard_cap or first_dwell
                mins = max(1, int(need) // 60)
                got = int(progress.get(vid, 0) or 0)
                flag_bit = f"已交 {got} 个正确 flag，" if got else "正确 flag 未齐，"
                await _yield_victim(
                    vid,
                    f"本题{flag_bit}本轮已满 {mins} 分钟，{why}。",
                )
        if stopped:
            exclude_live.update(stopped)
            running, slots = _live()
            running_mf = sum(1 for s in running if _is_mf(s))

    started: list[str] = []
    picked_mf = 0
    att_map = {s["id"]: _att(s) for s in candidates}
    real_att_map = {s["id"]: _real(s) for s in candidates}
    score_map = {s["id"]: _score_of(s) for s in candidates}
    ordered = schedule_fill_ids(
        cand_meta,
        started=set(),
        running=set(exclude_live) | {s["id"] for s in running},
        attempts=att_map,
        progress=progress,
        any_fresh=any_fresh,
        real_attempts=real_att_map,
        scores=score_map,
    )
    for sid in ordered:
        if len(started) >= slots:
            break
        s = by_id.get(sid)
        if not s or manager.is_running(sid):
            continue
        if _is_mf(s) and (running_mf + picked_mf) >= max_mf:
            continue
        try:
            manager.start(sid, hard_restart=False)
        except Exception as e:
            print(f"[autopilot] start {sid} 失败: {e}")
            continue
        started.append(sid)
        if _is_mf(s):
            picked_mf += 1

    remaining_fresh = count_remaining_fresh(
        scope,
        completed=completed,
        busy=set(started) | {s["id"] for s in running},
        real_attempts=real_map,
    )
    prev_ticks = 0
    try:
        prev_ticks = int((parent.get("config") or {}).get("autopilot_idle_ticks") or 0)
    except (TypeError, ValueError):
        prev_ticks = 0
    ticks, tripped = note_autopilot_watchdog(
        running=len(running) + len(started),
        started=len(started),
        remaining_fresh=remaining_fresh,
        prev_ticks=prev_ticks,
        trip_after=int(getattr(settings, "benchmark_watchdog_idle_ticks", 0) or 0),
    )
    if ticks != prev_ticks:
        try:
            await _merge_parent_config(parent_id, {"autopilot_idle_ticks": ticks})
        except Exception:
            pass
    if tripped:
        msg = (
            f"评测看门狗：空槽且仍有 {remaining_fresh} 道从未启动的题，"
            "正在补齐题单并重试填槽（不把父任务标完成）。"
        )
        print(f"[autopilot] {msg}")
        try:
            from .events import emit
            await emit(parent_id, "log", {"level": "error", "message": msg})
        except Exception:
            pass
        try:
            imported = await import_challenges(parent_id)
            if imported.get("created"):
                print(f"[autopilot] watchdog 补齐 created={imported.get('created')}")
        except Exception as e:
            print(f"[autopilot] watchdog 补齐失败: {e}")

    return {
        "running": len(running),
        "started": len(started),
        "stopped": stopped,
        "orphans_closed": orphans.get("closed", 0),
        "remaining": max(0, len(candidates) - len(started)),
        "picked": [_uc(by_id[i]) for i in started if i in by_id],
        "any_fresh": any_fresh,
        "remaining_fresh": remaining_fresh,
        "watchdog_ticks": ticks,
    }


def is_benchmark_sub(project: dict | None) -> bool:
    """是否为 benchmark 子题（有 parent + config.benchmark）。"""
    if not project or not project.get("parent_id"):
        return False
    cfg = project.get("config") or {}
    return bool(cfg.get("benchmark"))


def restart_needs_confirm(project: dict | None) -> bool:
    """已起过容器的 benchmark 子题再启动会清图+烧 attempt，必须人工确认。

    attempts>0 表示至少成功起过一次容器；此时禁止 autopilot / 静默 start。
    """
    if not is_benchmark_sub(project):
        return False
    bm = ((project or {}).get("config") or {}).get("benchmark") or {}
    return int(bm.get("attempts") or 0) > 0


def restart_confirm_detail(project: dict) -> dict:
    """给 409 响应 / UI 确认框用的说明。"""
    cfg = project.get("config") or {}
    bm = cfg.get("benchmark") or {}
    return {
        "code": "restart_needs_confirm",
        "message": (
            "重新启动将起新容器、清空攻击图并消耗一次 attempt；"
            "已提交的 flag 与历史日志会保留。请确认后重试。"
        ),
        "unique_code": bm.get("unique_code"),
        "attempts": int(bm.get("attempts") or 0),
        "correct_flag_count": int(bm.get("correct_flag_count") or 0),
        "target": project.get("target"),
    }


async def bump_attempt(sub_project: dict) -> None:
    """某题真正开始一次 run 时 +1 尝试次数（用于自动重试上限与调度优先级）。"""
    from .projects import update_config
    cfg = sub_project.get("config") or {}
    bm = cfg.setdefault("benchmark", {})
    bm["attempts"] = int(bm.get("attempts") or 0) + 1
    try:
        await update_config(sub_project["id"], cfg)
    except Exception:
        pass


async def scoreboard(project_id: str) -> dict:
    """按平台缓存聚合；旧项目缺缓存时按本地 flags 表回退。"""
    from .engine.scheduler import manager as _mgr
    from .graph import store as gstore
    from .objective import ctf_full_score, ctf_needed_flags
    from .projects import get_project
    parent = await get_project(project_id)
    env_closed = bool(((parent or {}).get("config") or {}).get("env_closed"))
    subs = await db.fetchall("SELECT * FROM projects WHERE parent_id=? ORDER BY created_at", (project_id,))
    stats_map = await gstore.get_stats_batch([s["id"] for s in subs])
    items = []
    cumulative = 0.0
    total_flags = 0
    correct_flags = 0
    for s in subs:
        cfg = _loads(s["config"]) or {}
        uc = (cfg.get("benchmark") or {}).get("unique_code")
        fc = ctf_needed_flags(flag_count=cfg.get("flag_count"))
        rows = await db.fetchall("SELECT * FROM flags WHERE project_id=? AND correct=1", (s["id"],))
        idxs = {r["flag_index"] for r in rows if r["flag_index"] is not None}
        local_got = len(idxs) if idxs else len(rows)
        local_score = sum(float(r["awarded"] or 0) for r in rows)
        bm = cfg.get("benchmark") or {}
        got = int(bm["correct_flag_count"]) if bm.get("correct_flag_count") is not None else local_got
        score = float(bm["cumulative_score"]) if bm.get("cumulative_score") is not None else local_score
        cumulative += score
        total_flags += fc
        correct_flags += got
        st = stats_map.get(s["id"]) or {}
        queued = _mgr.is_queued(s["id"])
        live = _mgr.is_running(s["id"]) and not queued
        done = ctf_full_score(
            flags_correct=got, flag_count=fc,
            flags_score=score, total_score=cfg.get("total_score"),
        )
        if done:
            status = "completed"
        elif queued:
            status = "queued"
        elif live:
            status = "running"
        else:
            status = s["status"]
            if env_closed and status in ("running", "queued"):
                status = "idle"
        items.append({
            "subproject_id": s["id"], "unique_code": uc, "name": s["name"], "status": status,
            "queued": queued,
            "flag_count": fc, "correct_flag_count": got, "score": score,
            "difficulty": cfg.get("difficulty"), "total_score": cfg.get("total_score"),
            "is_completed": done,
            "has_shell": bool(st.get("has_shell")),
            "lateral_active": bool(st.get("lateral_active")),
        })
    return {"cumulative_score": cumulative, "total_flags": total_flags,
            "correct_flags": correct_flags, "challenges": items,
            "slot_limit": int(settings.benchmark_max_concurrency),
            "slot_running": sum(1 for c in items if c.get("status") == "running"),
            "slot_queued": sum(1 for c in items if c.get("queued") or c.get("status") == "queued")}
