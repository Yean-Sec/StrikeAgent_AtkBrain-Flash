import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api";
import type { Project } from "../types";
import { Modal } from "../components/Modal";
import { ImportProgressBar, isImportPaused, isImportRunning, type ImportProgress } from "../components/ImportProgressBar";
import { fadeInUp } from "../anim";
import { PaginationBar, pageItems, readPageSize } from "../components/PaginationBar";
import { colors } from "../theme";
import { listStatusOf } from "../projectStatus";

function trackOf(p: Project): "redteam" | "ctf" {
  const t = (p.config as any)?.track;
  if (t === "ctf") return "ctf";
  if (p.kind === "benchmark") return "ctf";
  const obj = (p.config as any)?.objective;
  if (obj === "flag") return "ctf";
  return "redteam";
}

function trackLabel(p: Project): string {
  return { redteam: "红队", ctf: "CTF" }[trackOf(p)];
}

type BatchAction = "start" | "stop" | "delete";
const STATUS_LABEL: Record<string, string> = { all: "全部", running: "进行中", completed: "已完成", idle: "未完成", stopped: "已暂停", error: "失败" };
function statusOf(p: Project) { return listStatusOf(p); }

export function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState(""); const [kind, setKind] = useState("all"); const [track, setTrack] = useState("all"); const [status, setStatus] = useState("all");
  const [pendingAction, setPendingAction] = useState<BatchAction | null>(null);
  const [rename, setRename] = useState<Project | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(readPageSize);
  const [params, setParams] = useSearchParams();
  const heroRef = useRef<HTMLDivElement>(null);
  const load = () => api.listProjects().then(setProjects).catch(() => {});
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t); }, []);
  useEffect(() => { if (heroRef.current) fadeInUp(heroRef.current.children); }, []);
  useEffect(() => { if (params.get("create") === "1") { setShowCreate(true); setParams({}, { replace: true }); } }, [params, setParams]);
  useEffect(() => { const alive = new Set(projects.map((p) => p.id)); setSelected((old) => new Set([...old].filter((id) => alive.has(id)))); }, [projects]);
  const visible = projects.filter((p) => (!query || `${p.name} ${p.target || ""}`.toLowerCase().includes(query.toLowerCase())) && (kind === "all" || (kind === "single" ? p.kind === "single" : p.kind !== "single")) && (track === "all" || trackOf(p) === track) && (status === "all" || statusOf(p) === status));
  useEffect(() => { setPage(1); }, [query, kind, track, status]);
  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize) || 1);
  const curPage = Math.min(page, pageCount);
  const paged = pageItems(visible, curPage, pageSize);
  const toggle = (id: string) => setSelected((old) => { const next = new Set(old); next.has(id) ? next.delete(id) : next.add(id); return next; });
  const selectAll = () => setSelected(new Set(visible.map((p) => p.id)));
  const pageAllSelected = paged.length > 0 && paged.every((p) => selected.has(p.id));
  const togglePage = () => {
    if (pageAllSelected) {
      const drop = new Set(paged.map((p) => p.id));
      setSelected((old) => new Set([...old].filter((id) => !drop.has(id))));
    } else {
      setSelected((old) => new Set([...old, ...paged.map((p) => p.id)]));
    }
  };
  const runBatch = async () => {
    const ids = [...selected]; if (!pendingAction || !ids.length) return;
    setBusy(true);
    try { if (pendingAction === "delete") await api.batchDeleteProjects(ids); if (pendingAction === "start") await api.batchStartProjects(ids); if (pendingAction === "stop") await api.batchStopProjects(ids); setSelected(new Set()); await load(); }
    catch (e: any) { alert(e?.message || "批量操作失败"); } finally { setBusy(false); setPendingAction(null); }
  };
  return <div className="page-container projects-page">
    <div ref={heroRef} className="spread" style={{ alignItems: "flex-end", marginBottom: 26 }}><div><p className="eyebrow">PROJECTS</p><h1>审计列表</h1><p className="muted" style={{ marginTop: 8 }}>管理所有授权渗透任务与集群。</p></div><button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ 新建项目</button></div>
    <section className="project-list-toolbar"><input className="input project-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索项目名称或目标" /><Filter value={kind} onChange={setKind} options={[["all", "全部形态"], ["single", "单个项目"], ["cluster", "集群"]]} /><Filter value={track} onChange={setTrack} options={[["all", "全部赛道"], ["ctf", "CTF"], ["redteam", "红队"]]} /></section>
    <div className="status-filters">{Object.entries(STATUS_LABEL).map(([key, label]) => <button key={key} className={status === key ? "active" : ""} onClick={() => setStatus(key)}>{label} <b>{key === "all" ? projects.length : projects.filter((p) => statusOf(p) === key).length}</b></button>)}</div>
    <div className="batch-toolbar"><span className="muted">已选 {selected.size}/{visible.length}</span><button className="btn btn-secondary btn-sm" onClick={selectAll} disabled={!visible.length || busy}>全选筛选结果</button><button className="btn btn-secondary btn-sm" onClick={() => setSelected(new Set())} disabled={!selected.size || busy}>取消选择</button><div style={{ flex: 1 }} /><button className="btn btn-primary btn-sm" onClick={() => setPendingAction("start")} disabled={!selected.size || busy}>批量开始</button><button className="btn btn-secondary btn-sm" onClick={() => setPendingAction("stop")} disabled={!selected.size || busy}>批量暂停</button><button className="btn btn-danger btn-sm" onClick={() => setPendingAction("delete")} disabled={!selected.size || busy}>批量删除</button></div>
    <div className="project-table-wrap"><table className="project-table"><thead><tr><th><input type="checkbox" checked={pageAllSelected} onChange={togglePage} /></th><th>项目名称</th><th>形态 / 赛道</th><th>状态</th><th>节点</th><th>服务</th><th>高危</th><th>严重</th><th>更新时间</th></tr></thead><tbody>{paged.map((p) => <ProjectRow key={p.id} p={p} selected={selected.has(p.id)} onToggle={() => toggle(p.id)} onRename={() => setRename(p)} />)}</tbody></table>{!visible.length && <div className="empty-list">没有符合当前筛选条件的项目。</div>}</div>
    {visible.length > 0 && <PaginationBar total={visible.length} page={curPage} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} />}
    {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreated={load} />}
    {rename && <RenameDialog project={rename} onClose={() => setRename(null)} onSaved={() => { setRename(null); load(); }} />}
    {pendingAction && <BatchConfirm action={pendingAction} count={selected.size} projects={projects.filter((p) => selected.has(p.id))} onClose={() => setPendingAction(null)} onConfirm={runBatch} busy={busy} />}
  </div>;
}

function Filter({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: [string, string][] }) { return <select className="select compact-filter" value={value} onChange={(e) => onChange(e.target.value)}>{options.map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select>; }
function ProjectRow({ p, selected, onToggle, onRename }: { p: Project; selected: boolean; onToggle: () => void; onRename: () => void }) {
  const nav = useNavigate(); const s: any = p.stats || {}; const color: Record<string, string> = { running: colors.success, completed: colors.primary, idle: colors.mutedSoft, error: colors.error, stopped: colors.muted };
  return <tr className={selected ? "selected" : ""} onClick={() => nav(`/project/${p.id}`)}><td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selected} onChange={onToggle} /></td><td><strong>{p.name}</strong><span className="table-sub mono">{p.target || (p.kind === "benchmark" ? "CTF 评测" : "多资产集群")}</span></td><td><span className="badge badge-pill">{p.kind === "single" ? "单项目" : p.kind === "benchmark" ? "CTF 集群" : "集群"}</span><span className="table-sub">{trackLabel(p)}</span></td><td><span className="row" style={{ gap: 6 }}><span className="pulse-dot" style={{ background: color[statusOf(p)] || colors.muted }} />{STATUS_LABEL[statusOf(p)] || statusOf(p)}</span></td><td>{s.nodes || 0}</td><td>{s.services || 0}</td><td>{s.high || 0}</td><td className={s.critical ? "danger-number" : ""}>{s.critical || 0}</td><td><span className="table-sub">{new Date((p.updated_at || p.created_at) * 1000).toLocaleString()}</span><button className="row-rename" onClick={(e) => { e.stopPropagation(); onRename(); }}>编辑</button></td></tr>;
}
function BatchConfirm({ action, count, projects, onClose, onConfirm, busy }: { action: BatchAction; count: number; projects: Project[]; onClose: () => void; onConfirm: () => void; busy: boolean }) {
  const label = { start: "启动", stop: "暂停", delete: "删除" }[action]; const running = projects.filter((p) => p.running || p.status === "running").length;
  return <Modal title={`确认批量${label}`} onClose={onClose}><p>将对 <b>{count}</b> 个项目执行“{label}”。</p><div className="confirm-impact">运行中项目：<b>{running}</b>　集群：<b>{projects.filter((p) => p.kind !== "single").length}</b></div><p className="muted">{action === "delete" ? "删除会级联删除子项目、攻击图、发现与运行记录，且不可恢复。" : action === "stop" ? "暂停会中断正在执行的 Agent 会话；当前轮次不会继续。" : "启动会占用并发槽位。"}</p><div className="row" style={{ justifyContent: "flex-end", marginTop: 22 }}><button className="btn btn-secondary" onClick={onClose} disabled={busy}>取消</button><button className={`btn ${action === "delete" ? "btn-danger" : "btn-primary"}`} onClick={onConfirm} disabled={busy}>{busy ? "处理中…" : `确认${label}`}</button></div></Modal>;
}
function RenameDialog({ project, onClose, onSaved }: { project: Project; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(project.name); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const save = async () => { if (!name.trim()) return setErr("名称不能为空"); setBusy(true); try { await api.renameProject(project.id, name.trim()); onSaved(); } catch (e: any) { setErr(e?.message || "改名失败"); } finally { setBusy(false); } };
  return <Modal title="重命名项目" onClose={onClose}><p className="muted">{project.kind === "single" ? "新名称会显示在项目列表和报告中。" : "集群改名会同步更新子项目的显示前缀，不影响攻击数据。"}</p><input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()} />{err && <p className="error-text">{err}</p>}<div className="row" style={{ justifyContent: "flex-end", marginTop: 20 }}><button className="btn btn-secondary" onClick={onClose}>取消</button><button className="btn btn-primary" onClick={save} disabled={busy}>{busy ? "保存中…" : "保存名称"}</button></div></Modal>;
}

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const nav = useNavigate();
  const [kind, setKind] = useState<"single" | "cluster">("single");
  const [track, setTrack] = useState<"redteam" | "ctf">("redteam");
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [ports, setPorts] = useState("");
  const [assets, setAssets] = useState("");
  const [baseUrl, setBaseUrl] = useState("https://tsecbench.zc.tencent.com");
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [importProgress, setImportProgress] = useState<ImportProgress | null>(null);
  const [importKick, setImportKick] = useState(0);
  const importPoll = useRef<ReturnType<typeof setTimeout> | null>(null);

  const enterProject = (id: string) => {
    if (importPoll.current) clearTimeout(importPoll.current);
    onCreated();
    onClose();
    nav(`/project/${id}`);
  };

  useEffect(() => {
    if (!createdId) return;
    let stop = false;
    const tick = async () => {
      if (stop) return;
      try {
        const p = await api.importProgress(createdId) as ImportProgress;
        if (stop) return;
        setImportProgress(p);
        if (isImportRunning(p)) {
          importPoll.current = setTimeout(tick, 400);
        } else if (p.phase === "error") {
          setErr(p.message || "导入失败");
        } else if (isImportPaused(p)) {
          setBusy(false);
        } else if (p.phase === "done") {
          enterProject(createdId);
        }
      } catch {
        if (!stop) importPoll.current = setTimeout(tick, 1200);
      }
    };
    tick();
    return () => {
      stop = true;
      if (importPoll.current) clearTimeout(importPoll.current);
    };
  }, [createdId, importKick]);

  const submit = async () => {
    setBusy(true); setErr("");
    try {
      const clusterBenchmark = kind === "cluster" && track === "ctf";
      const body: any = { kind: clusterBenchmark ? "benchmark" : kind, name, track };
      if (kind === "single") {
        body.target = target.trim();
        if (!body.target) throw new Error("请填写目标");
        if (ports.trim()) body.ports = ports.split(/[,\s]+/).filter(Boolean).map(Number);
        body.allow_subdomains = false;
      } else if (clusterBenchmark) {
        if (!baseUrl.trim() || !token.trim()) throw new Error("请填写 BENCHMARK_BASE_URL 与 BENCHMARK_TOKEN");
        body.base_url = baseUrl.trim();
        body.token = token.trim();
      } else {
        const lines = assets.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        if (!lines.length) throw new Error("请填写资产列表");
        body.assets = [assets];
        setImportProgress({
          phase: "spawn",
          done: 0,
          total: lines.length,
          message: `正在登记 ${lines.length} 条资产…`,
        });
      }
      const p: any = await api.createProject(body);
      if (kind === "cluster" && !clusterBenchmark && (p.importing || p.import_progress)) {
        setCreatedId(p.id);
        setImportProgress(p.import_progress || { phase: "spawn", done: 0, total: 0, message: "正在导入…" });
        return;
      }
      onCreated();
      onClose();
      nav(`/project/${p.id}`);
    } catch (e: any) {
      setErr(e.message || "创建失败");
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    if (createdId) onCreated();
    onClose();
  };

  return (
    <Modal title="新建渗透项目" onClose={handleClose}>
      <div className="field">
        <span>项目形态</span>
        <div className="row" style={{ gap: 8, marginTop: 4, flexWrap: "wrap" }}>
          <button className={`btn ${kind === "single" ? "btn-primary" : "btn-secondary"}`} onClick={() => setKind("single")}>单目标</button>
          <button className={`btn ${kind === "cluster" ? "btn-primary" : "btn-secondary"}`} onClick={() => setKind("cluster")}>集群（批量资产）</button>
        </div>
      </div>

      <div className="field" style={{ marginTop: 12 }}>
        <span>赛道</span>
        <div className="row" style={{ gap: 8, marginTop: 4, flexWrap: "wrap" }}>
          <button type="button" className={`btn btn-sm ${track === "redteam" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTrack("redteam")}>红队（getshell）</button>
          <button type="button" className={`btn btn-sm ${track === "ctf" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTrack("ctf")}>CTF（flag）</button>
        </div>
        <span style={{ fontSize: 12, color: "var(--muted)", marginTop: 6, display: "block" }}>
          {track === "redteam" && "红队：拿到服务器 shell 即完成本项目。"}
          {track === "ctf" && (kind === "cluster" ? "集群 CTF = 靶场评测：填 base_url + token，拉题按题自建 flag 子项目并跑分。" : "单目标 CTF：夺齐 flag（及分数，若有）即满分收工。")}
        </span>
      </div>

      <label className="field" style={{ marginTop: 12 }}>
        <span>项目名称</span>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "single" ? "可留空，默认用目标" : "项目名称（必填）"} />
      </label>

      {kind === "single" && (
        <>
          <label className="field">
            <span>目标（域名或 IP，可带端口如 host:8787）</span>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="192.168.236.1:8787 或 example.com" />
          </label>
          <label className="field">
            <span>指定端口（可选，逗号分隔；留空=该主机全端口在边界内）</span>
            <input className="input" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="80,443,8787" />
          </label>
          <span style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14, display: "block" }}>
            边界按域名/IP 唯一身份（同主机任意端口合法）；子域与第三方域默认不纳入，除非内网跳板授权横向。
          </span>
        </>
      )}

      {kind === "cluster" && track !== "ctf" && (
        <label className="field">
          <span>资产列表（CSV/TXT 内容，逐行或逗号分隔 IP/域名）</span>
          <div className="row" style={{ gap: 10, margin: "6px 0 8px", flexWrap: "wrap", alignItems: "center" }}>
            <label className="btn btn-secondary btn-sm" style={{ cursor: "pointer" }}>
              选择文件
              <input
                type="file"
                accept=".txt,.csv,.list,text/plain"
                hidden
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (!f) return;
                  const text = await f.text();
                  setAssets((prev) => (prev ? `${prev.trim()}\n${text}` : text));
                }}
              />
            </label>
            <span className="muted" style={{ fontSize: 12 }}>同主机（含 www / http(s) / 路径）创建时自动去重</span>
          </div>
          <textarea className="input" rows={5} value={assets} onChange={(e) => setAssets(e.target.value)} placeholder={"10.0.0.5\nexample.com\n10.0.0.6:8080"} />
          <span style={{ fontSize: 12, color: "var(--muted)", marginTop: 6, display: "block" }}>
            创建后按主机划分子项目并启动；已出现过的主机不会重复建项。
          </span>
        </label>
      )}

      {kind === "cluster" && track === "ctf" && (
        <>
          <label className="field">
            <span>BENCHMARK_BASE_URL（评测平台 API 基址）</span>
            <input className="input" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://tsecbench.zc.tencent.com" />
          </label>
          <label className="field">
            <span>BENCHMARK_TOKEN（跑分任务下发）</span>
            <input className="input" value={token} onChange={(e) => setToken(e.target.value)} placeholder="a1b2c3d4-..." />
          </label>
          <span style={{ fontSize: 12, color: "var(--muted)", marginBottom: 14, display: "block" }}>
            创建后进入评测页，点「拉取题目」按题自动建 flag 子项目。需先连靶场 VPN。
          </span>
        </>
      )}

      {err && <div style={{ color: "var(--error)", marginBottom: 12, fontSize: 14 }}>{err}</div>}
      {(busy || importProgress) && kind === "cluster" && track !== "ctf" && (
        <ImportProgressBar
          progress={importProgress || { phase: "spawn", done: 0, total: 0, message: "正在创建集群…" }}
          onPause={createdId ? async () => {
            try {
              const p = await api.pauseImport(createdId);
              setImportProgress(p);
            } catch (e: any) {
              setErr(e.message || "暂停导入失败");
            }
          } : undefined}
          onResume={createdId ? async () => {
            try {
              const r = await api.resumeImport(createdId);
              setImportProgress(r.import_progress || r);
              setBusy(true);
              setImportKick((n) => n + 1);
            } catch (e: any) {
              setErr(e.message || "继续导入失败");
            }
          } : undefined}
        />
      )}
      <div className="row" style={{ justifyContent: "flex-end", gap: 10 }}>
        <button className="btn btn-secondary" onClick={handleClose} disabled={busy}>取消</button>
        {createdId ? (
          <button className="btn btn-primary" onClick={() => enterProject(createdId)}>进入项目查看</button>
        ) : (
          <button className="btn btn-primary" disabled={busy} onClick={submit}>{busy ? "创建中…" : "创建并进入"}</button>
        )}
      </div>
    </Modal>
  );
}
