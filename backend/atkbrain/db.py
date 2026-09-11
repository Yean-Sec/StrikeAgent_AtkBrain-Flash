"""SQLite 数据层（aiosqlite）。

采用单连接 + WAL + 异步锁的轻量封装，满足后台自循环任务与 WebSocket 读写的并发需求。
表：projects / nodes / edges / findings / runs / events / memory / steering / intents / flags。
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any, Iterable

import aiosqlite

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'single',   -- single | cluster
    target      TEXT,                              -- 域名或 IP（单目标）
    ports       TEXT,                              -- json 列表或 null
    scope       TEXT,                              -- json：授权边界白名单
    config      TEXT,                              -- json：并发/模型
    status      TEXT NOT NULL DEFAULT 'idle',
    parent_id   TEXT,                              -- 集群子项目指向父项目
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    key         TEXT NOT NULL,                     -- 项目内稳定键（upsert 用）
    type        TEXT NOT NULL,                     -- target|info|service|danger|vuln|credential|foothold|honeypot|goal
    title       TEXT NOT NULL,
    detail      TEXT,
    severity    TEXT NOT NULL DEFAULT 'info',      -- info|low|medium|high|critical
    is_rce      INTEGER NOT NULL DEFAULT 0,
    risk_score  REAL NOT NULL DEFAULT 0,
    tags        TEXT,                              -- json 列表
    status      TEXT NOT NULL DEFAULT 'open',      -- open|confirmed|dead|quarantined
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    UNIQUE(project_id, key)
);

CREATE TABLE IF NOT EXISTS edges (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    src          TEXT NOT NULL,                    -- node key
    dst          TEXT NOT NULL,                    -- node key
    relation     TEXT NOT NULL DEFAULT 'LEADS_TO', -- LEADS_TO|EXPLOITS|ESCALATES_TO|PIVOTS_TO|CONTAINS
    weight       REAL NOT NULL DEFAULT 0.5,        -- 成功概率 0..1
    rationale    TEXT,
    on_rce_path  INTEGER NOT NULL DEFAULT 0,
    created_at   REAL NOT NULL,
    UNIQUE(project_id, src, dst, relation)
);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    node_key    TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    category    TEXT NOT NULL DEFAULT 'info',      -- rce|file_read|file_write|db_access|authz|unauth|admin_access|ssrf|sqli|...
    title       TEXT NOT NULL,
    description TEXT,
    evidence    TEXT,
    poc_curl    TEXT,
    poc_python  TEXT,
    cvss        REAL,
    created_at  REAL NOT NULL,
    verification_status TEXT NOT NULL DEFAULT 'verified',
    verified_at REAL,
    proof_type  TEXT,
    proof_canary TEXT,
    proof_url   TEXT,
    proof_detail TEXT,
    secondary_verified INTEGER NOT NULL DEFAULT 0,
    redteam_rating TEXT,
    redteam_rating_rationale TEXT,
    report_summary TEXT,
    report_impact TEXT,
    report_rating TEXT,
    report_repro TEXT,
    report_fix TEXT
);

CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running',  -- running|completed|stopped|error
    goal_reached INTEGER NOT NULL DEFAULT 0,
    turns        INTEGER NOT NULL DEFAULT 0,
    summary      TEXT,
    started_at   REAL NOT NULL,
    ended_at     REAL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  TEXT NOT NULL,
    run_id      TEXT,
    ts          REAL NOT NULL,
    type        TEXT NOT NULL,                     -- log|thought|tool|tool_result|node|edge|finding|shell|intent|steer|status|turn
    payload     TEXT
);

CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    project_id  TEXT,                              -- null = 全局经验
    target_fp   TEXT,                              -- 目标指纹（技术栈/产品）
    version     INTEGER NOT NULL DEFAULT 1,
    kind        TEXT NOT NULL DEFAULT 'episode',   -- episode | lesson
    tags        TEXT,
    content     TEXT NOT NULL,
    outcome     TEXT,                              -- shell | partial | fail
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS steering (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    ts          REAL NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    content     TEXT NOT NULL,
    applied     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS intents (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    from_keys   TEXT,                              -- json 列表
    description TEXT NOT NULL,
    rationale   TEXT,
    est_success REAL NOT NULL DEFAULT 0.5,
    status      TEXT NOT NULL DEFAULT 'open',      -- open|active|verified|disproved|deferred
    strategy_key TEXT,                             -- stable source + tactic identity
    evidence_fingerprint TEXT,                     -- source evidence version
    priority    REAL NOT NULL DEFAULT 0.5,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    failure_fingerprint TEXT,
    result_summary TEXT,
    active_run_id TEXT,
    created_at  REAL NOT NULL,
    updated_at  REAL
);

CREATE TABLE IF NOT EXISTS flags (
    id           TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL,
    unique_code  TEXT,                              -- 同项目内可选去重键
    flag_index   INTEGER,                           -- 多 flag 题的序号
    value        TEXT NOT NULL,                     -- 捕获的 flag 值
    submitted    INTEGER NOT NULL DEFAULT 1,        -- 已记入本项目
    correct      INTEGER NOT NULL DEFAULT 1,        -- 本局记为正确
    awarded      REAL NOT NULL DEFAULT 0,           -- 本题计分（无单独分值时为 0）
    created_at   REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flags_project ON flags(project_id);
CREATE INDEX IF NOT EXISTS idx_nodes_project ON nodes(project_id);
CREATE INDEX IF NOT EXISTS idx_edges_project ON edges(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_events_project ON events(project_id, id);
CREATE INDEX IF NOT EXISTS idx_intents_project ON intents(project_id, status);
CREATE INDEX IF NOT EXISTS idx_memory_fp ON memory(target_fp);
"""


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def now() -> float:
    return time.time()


def _dumps(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return json.dumps(v, ensure_ascii=False)


def _loads(v: Any) -> Any:
    if v is None or v == "":
        return None
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (json.JSONDecodeError, TypeError):
        return v


class Database:
    def __init__(self, path: str | None = None) -> None:
        self.path = str(path or settings.db_path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA foreign_keys=ON;")
        await self._conn.executescript(SCHEMA)
        await self._migrate_schema()
        await self._conn.commit()

    async def _migrate_schema(self) -> None:
        """为已有数据库补齐推理前沿字段，保持开发中的数据库可直接升级。"""
        cur = await self._conn.execute("PRAGMA table_info(intents)")
        columns = {row[1] for row in await cur.fetchall()}
        await cur.close()
        additions = {
            "strategy_key": "TEXT",
            "evidence_fingerprint": "TEXT",
            "priority": "REAL NOT NULL DEFAULT 0.5",
            "attempt_count": "INTEGER NOT NULL DEFAULT 0",
            "failure_fingerprint": "TEXT",
            "result_summary": "TEXT",
            "active_run_id": "TEXT",
            "updated_at": "REAL",
        }
        for name, definition in additions.items():
            if name not in columns:
                await self._conn.execute(f"ALTER TABLE intents ADD COLUMN {name} {definition}")
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_intents_frontier "
            "ON intents(project_id, status, priority DESC)"
        )
        # 无 strategy_key 的 intent 不参加去重索引。
        await self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_strategy_dedupe "
            "ON intents(project_id, strategy_key) "
            "WHERE strategy_key IS NOT NULL AND strategy_key <> ''"
        )

        # findings：状态与证明字段
        cur = await self._conn.execute("PRAGMA table_info(findings)")
        fcols = {row[1] for row in await cur.fetchall()}
        await cur.close()
        finding_adds = {
            "verification_status": "TEXT NOT NULL DEFAULT 'verified'",
            "verified_at": "REAL",
            "proof_type": "TEXT",
            "proof_canary": "TEXT",
            "proof_url": "TEXT",
            "proof_detail": "TEXT",
            "secondary_verified": "INTEGER NOT NULL DEFAULT 0",
            "redteam_rating": "TEXT",
            "redteam_rating_rationale": "TEXT",
            "report_summary": "TEXT",
            "report_impact": "TEXT",
            "report_rating": "TEXT",
            "report_repro": "TEXT",
            "report_fix": "TEXT",
        }
        for name, definition in finding_adds.items():
            if name not in fcols:
                await self._conn.execute(f"ALTER TABLE findings ADD COLUMN {name} {definition}")
        await self._conn.execute(
            """UPDATE findings SET verified_at=COALESCE(verified_at, created_at)
               WHERE verification_status='verified' AND verified_at IS NULL"""
        )
        await self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_verification "
            "ON findings(project_id, verification_status)"
        )

        # 自进化剧本改为 Claude 蒸馏；一次性清掉旧机械路线。
        await self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL)"
        )
        cur = await self._conn.execute(
            "SELECT v FROM schema_kv WHERE k='playbook_reset'"
        )
        kv = await cur.fetchone()
        await cur.close()
        mark = ""
        if kv is not None:
            try:
                mark = kv[0] if not isinstance(kv, dict) else str(kv.get("v") or "")
            except Exception:
                mark = str(kv[0] if kv else "")
        if mark != "claude_v1":
            await self._conn.execute("DELETE FROM memory WHERE kind='lesson'")
            await self._conn.execute(
                "INSERT OR REPLACE INTO schema_kv(k, v) VALUES('playbook_reset', 'claude_v1')"
            )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        assert self._conn is not None, "Database not connected"
        return self._conn

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        async with self._lock:
            await self.conn.execute(sql, tuple(params))
            await self.conn.commit()

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        cur = await self.conn.execute(sql, tuple(params))
        row = await cur.fetchone()
        await cur.close()
        return dict(row) if row else None

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        cur = await self.conn.execute(sql, tuple(params))
        rows = await cur.fetchall()
        await cur.close()
        return [dict(r) for r in rows]


# 全局单例
db = Database()
