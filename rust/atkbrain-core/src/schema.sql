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

CREATE TABLE IF NOT EXISTS auth_users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    bootstrap_login_done INTEGER NOT NULL DEFAULT 0,
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id          TEXT PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     TEXT NOT NULL,
    expires_at  REAL NOT NULL,
    created_at  REAL NOT NULL,
    last_seen   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    secret      TEXT NOT NULL,
    expires_at  REAL NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    extra       TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_lockouts (
    key         TEXT PRIMARY KEY,
    fails       INTEGER NOT NULL DEFAULT 0,
    window_start REAL NOT NULL,
    locked_until REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash ON auth_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_exp ON auth_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_exp ON auth_challenges(expires_at);

CREATE TABLE IF NOT EXISTS vendors (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id          TEXT PRIMARY KEY,
    vendor_id   TEXT NOT NULL,
    kind        TEXT NOT NULL,                     -- root_domain|subdomain|ip|service|endpoint|app
    identity    TEXT NOT NULL,
    attrs       TEXT,
    verified_at REAL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    UNIQUE(vendor_id, kind, identity)
);

CREATE TABLE IF NOT EXISTS project_assets (
    project_id  TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    in_scope    INTEGER NOT NULL DEFAULT 0,
    scope_basis TEXT,
    confirmed_at REAL,
    PRIMARY KEY (project_id, asset_id)
);

CREATE TABLE IF NOT EXISTS finding_assets (
    finding_id  TEXT NOT NULL,
    asset_id    TEXT NOT NULL,
    PRIMARY KEY (finding_id, asset_id)
);

CREATE TABLE IF NOT EXISTS asset_denies (
    id          TEXT PRIMARY KEY,
    pattern     TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS http_exchanges (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    run_id      TEXT,
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    request_headers TEXT,
    request_body TEXT,
    status      INTEGER,
    response_headers TEXT,
    response_body TEXT,
    response_summary TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_http (
    finding_id  TEXT NOT NULL,
    exchange_id TEXT NOT NULL,
    ordinal     INTEGER NOT NULL,
    role        TEXT NOT NULL,
    PRIMARY KEY (finding_id, exchange_id)
);

CREATE TABLE IF NOT EXISTS webhook_outbox (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT,
    payload     TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    created_at  REAL NOT NULL,
    sent_at     REAL
);

CREATE TABLE IF NOT EXISTS project_templates (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    track       TEXT,
    clocks      TEXT,
    model_chain TEXT,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS command_confirms (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL,
    intent_id   TEXT,
    command     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending',
    reason      TEXT,
    created_at  REAL NOT NULL,
    decided_at  REAL
);

CREATE INDEX IF NOT EXISTS idx_assets_vendor ON assets(vendor_id, kind);
CREATE INDEX IF NOT EXISTS idx_http_project ON http_exchanges(project_id, created_at);
CREATE INDEX IF NOT EXISTS idx_project_assets_scope ON project_assets(project_id, in_scope);
