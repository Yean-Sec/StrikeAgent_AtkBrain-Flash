import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api";
import type { Project } from "../../types";
import { Badge } from "../../components/Badge";
import { BatchSelectionBar } from "../../components/BatchSelectionBar";
import { PaginationBar, pageItems, readPageSize } from "../../components/PaginationBar";
import { colors } from "../../theme";
import { ReportExportControls } from "../report/ExportReport";

const statusColor: Record<string, string> = {
  running: colors.success, queued: colors.warning, completed: colors.primary, idle: colors.mutedSoft, error: colors.error, stopped: colors.muted,
};
const statusLabel: Record<string, string> = {
  running: "运行中", queued: "排队中", completed: "已完成", idle: "空闲", error: "失败", stopped: "已停止",
};

const STATUS_FILTER: Record<string, string> = {
  all: "全部", running: "进行中", completed: "已完成", idle: "未完成", stopped: "已暂停", error: "失败",
};

function filterStatusOf(c: Board["challenges"][number]): string {
  if (c.is_completed || c.status === "completed") return "completed";
  if (c.status === "queued" || c.queued || c.status === "running") return "running";
  if (c.status === "error") return "error";
  if (c.status === "stopped") return "stopped";
  return "idle";
}

interface Board {
  cumulative_score: number;
  total_flags: number;
  correct_flags: number;
  slot_limit?: number;
  slot_running?: number;
  slot_queued?: number;
  challenges: {
    subproject_id: string; unique_code?: string; name: string; status: string;
    flag_count: number; correct_flag_count: number; score: number;
    difficulty?: string; total_score?: number; is_completed: boolean;
    has_shell?: boolean; lateral_active?: boolean; queued?: boolean;
  }[];
}

export function BenchmarkDashboard({ project }: { project: Project }) {
  const [board, setBoard] = useState<Board | null>(null);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(readPageSize);

  const bm = project.config?.benchmark || {};
  const labSrc = (project.config as any)?.track === "src" || (project.config as any)?.objective === "src";
  const envClosed = Boolean((project.config as any)?.env_closed);

  const load = () => api.scoreboard(project.id).then(setBoard).catch(() => {});
  useEffect(() => {
    load();
    const t = setInterval(load, 12000);
    return () => clearInterval(t);
  }, [project.id]);

  const chs = board?.challenges || [];
  const slotLimit = board?.slot_limit || 3;
  const runningCount = chs.filter((c) => c.status === "running").length;
  const queuedCount = chs.filter((c) => c.status === "queued" || c.queued).length;
  const liveCount = chs.filter((c) => c.status === "running" || c.status === "queued" || c.queued).length;
  const completed = chs.filter((c) => c.is_completed).length;
  const unfinishedIdle = chs.filter((c) => !c.is_completed && c.status !== "running" && c.status !== "queued").length;
  const visible = statusFilter === "all" ? chs : chs.filter((c) => filterStatusOf(c) === statusFilter);
  useEffect(() => { setPage(1); }, [statusFilter, project.id]);
  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize) || 1);
  const curPage = Math.min(page, pageCount);
  const paged = pageItems(visible, curPage, pageSize);
  const selectedCount = selectedIds.length;
  const allSelected = paged.length > 0 && paged.every((c) => selectedIds.includes(c.subproject_id));
  const toggleSelected = (id: string) => {
    setSelectedIds((ids) => ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]);
  };
  const toggleAll = () => setSelectedIds(
    allSelected
      ? selectedIds.filter((id) => !paged.some((c) => c.subproject_id === id))
      : Array.from(new Set([...selectedIds, ...paged.map((c) => c.subproject_id)])),
  );

  const doImport = async () => {
    setBusy("import"); setErr("");
    try { await api.bmImport(project.id); await load(); }
    catch (e: any) { setErr(e.message || "拉题失败（检查 base_url/token/VPN）"); }
    finally { setBusy(""); }
  };
  const startAll = async () => {
    setBusy("start"); setErr("");
    try {
      await api.startAll(project.id, false);
      await load();
    } catch (e: any) { setErr(e.message || "批量启动失败"); }
    finally { setBusy(""); }
  };

  const startUnfinished = async () => {
    const idle = chs.filter((c) => !c.is_completed && c.status !== "running");
    if (!idle.length) {
      setErr(chs.length > 0 && completed === chs.length
        ? (labSrc ? "没有可启动的未完成资产" : "全部题目已通关")
        : (labSrc ? "没有可启动的未完成资产（都在运行中）" : "没有可启动的未完成题目（都在运行中或已通关）"));
      return;
    }
    const tip = labSrc
      ? `将按资产编号顺序续跑未完成项（同时最多 3 个，做完或让槽后再开下一个，不会一次排队几十个）。已有攻击图会保留。确认？`
      : `将按题号顺序续跑未通关题（同时最多 3 道，每题至少做一轮；0 分题啃一段时间才会把槽让给后面还没开过的题）。已有攻击图会保留。已满分的 ${completed} 道不会动。确认？`;
    if (!window.confirm(tip)) return;
    setBusy("unfinished");
    setErr("");
    try {
      const res = await api.startAll(project.id, false, true);
      if (!res?.unfinished_only && !res?.scheduled) {
        for (let i = 0; i < idle.length; i++) {
          await api.start(idle[i].subproject_id, false);
          if (i < idle.length - 1) await new Promise((r) => setTimeout(r, 800));
        }
      }
      await load();
    } catch (e: any) { setErr(e.message || "批量启动未完成题目失败"); }
    finally { setBusy(""); }
  };

  const stopAll = async () => {
    if (!liveCount) return;
    if (!window.confirm(`将暂停当前 ${liveCount} 道运行中/排队的${labSrc ? "资产" : "题"}。攻击图保留，稍后可点「启动未完成」续跑。确认？`)) return;
    setBusy("stop"); setErr("");
    try { await api.stopAll(project.id); await load(); }
    catch (e: any) { setErr(e.message || "批量暂停失败"); }
    finally { setBusy(""); }
  };

  const runSelected = async () => {
    if (!selectedCount || !window.confirm(`将运行选中的 ${selectedCount} 道题。平台同时最多 3 道，其余排队；已有攻击图会保留。是否继续？`)) return;
    setBusy("sel-start"); setErr("");
    try { await api.batchStartProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量运行失败"); }
    finally { setBusy(""); }
  };
  const pauseSelected = async () => {
    if (!selectedCount || !window.confirm(`将暂停选中的 ${selectedCount} 道题。正在执行的 Agent 会停止，攻击图保留，稍后可续跑。是否继续？`)) return;
    setBusy("sel-stop"); setErr("");
    try { await api.batchStopProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量暂停失败"); }
    finally { setBusy(""); }
  };
  const deleteSelected = async () => {
    if (!selectedCount || !window.confirm(`将永久删除选中的 ${selectedCount} 道题及其攻击图、发现、报告和运行记录。已提交的 flag 会计分牌仍在，此操作不可撤销。是否继续？`)) return;
    setBusy("sel-del"); setErr("");
    try { await api.batchDeleteProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量删除失败"); }
    finally { setBusy(""); }
  };

  return (
    <div className="container" style={{ paddingTop: 24, paddingBottom: 40 }}>
      <Link to="/" className="muted" style={{ fontSize: 13 }}>&larr; 返回项目列表</Link>
      <div className="spread" style={{ margin: "10px 0 18px", alignItems: "flex-start" }}>
        <div>
          <div className="row" style={{ gap: 10 }}>
            <h1 style={{ fontSize: 34 }}>{project.name}</h1>
            <Badge>{labSrc ? "SRC 集群" : "CTF 评测"}</Badge>
            <Badge coral>{labSrc ? "厂商清单挖洞" : "FLAG 赛道"}</Badge>
          </div>
          <div className="row" style={{ gap: 12, marginTop: 6 }}>
            <span className="mono muted" style={{ fontSize: 13 }}>{bm.base_url || "未配置 base_url"}</span>
            <span className="muted" style={{ fontSize: 13 }}>{labSrc ? "资产" : "题目"} {chs.length} · 完成 {completed} · 运行中 {runningCount}/{slotLimit}{queuedCount ? ` · 排队 ${queuedCount}` : ""}</span>
          </div>
        </div>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <ReportExportControls projectId={project.id} disabled={!!busy} />
          <button className="btn btn-secondary" disabled={!!busy} onClick={doImport}>{busy === "import" ? "拉题中…" : "拉取题目"}</button>
          {chs.length > 0 && (
            <button
              className="btn btn-primary"
              disabled={!!busy || envClosed || unfinishedIdle === 0}
              onClick={startUnfinished}
              title={envClosed ? "评测环境已到期" : undefined}
            >
              {busy === "unfinished" ? "启动中…" : unfinishedIdle > 0 ? `启动未完成（${unfinishedIdle}）` : "启动未完成"}
            </button>
          )}
          {chs.length > 0 && <button className="btn btn-ghost" disabled={!!busy || envClosed} onClick={startAll} title={envClosed ? "评测环境已到期" : undefined}>{busy === "start" ? "启动中…" : "全部启动"}</button>}
          {chs.length > 0 && (
            <button className="btn btn-secondary" disabled={!!busy || liveCount === 0} onClick={stopAll}>
              {busy === "stop" ? "暂停中…" : "全部暂停"}
            </button>
          )}
        </div>
      </div>

      {err && <div style={{ color: "var(--error)", marginBottom: 12, fontSize: 14 }}>{err}</div>}
      {envClosed && (
        <div className="import-progress is-error" style={{ marginBottom: 16 }}>
          <div className="import-progress-head">
            <strong>评测环境已到期关停</strong>
            <span className="muted">{String((project.config as any)?.env_closed_reason || "平台任务结束或不可达")}</span>
          </div>
          <p className="muted" style={{ margin: "8px 0 0", fontSize: 13 }}>已停止测试、验证与自动补位，避免对着失效靶机空转。平台恢复后可再启动。</p>
        </div>
      )}

      {labSrc ? (
        <div className="card-cream" style={{ marginBottom: 20, padding: 18 }}>
          <div className="row" style={{ gap: 28, alignItems: "baseline" }}>
            <div className="stack"><span className="serif" style={{ fontSize: 34, color: colors.primary }}>{chs.length}</span><span className="muted" style={{ fontSize: 12 }}>评测资产（胶水拉起）</span></div>
            <div className="stack"><span className="serif" style={{ fontSize: 28 }}>{completed}/{chs.length}</span><span className="muted" style={{ fontSize: 12 }}>已完成</span></div>
          </div>
          <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>按真实 SRC 挖厂商清单类型，不夺旗、不走公网代理池。需先连靶场 VPN。</p>
        </div>
      ) : (
        <div className="card-cream" style={{ marginBottom: 20, padding: 18 }}>
          <div className="row" style={{ gap: 28, alignItems: "baseline" }}>
            <div className="stack"><span className="serif" style={{ fontSize: 34, color: colors.primary }}>{board?.cumulative_score ?? 0}</span><span className="muted" style={{ fontSize: 12 }}>累计得分</span></div>
            <div className="stack"><span className="serif" style={{ fontSize: 28 }}>{board?.correct_flags ?? 0}/{board?.total_flags ?? 0}</span><span className="muted" style={{ fontSize: 12 }}>已夺 flag / 总数</span></div>
            <div className="stack"><span className="serif" style={{ fontSize: 28 }}>{completed}/{chs.length}</span><span className="muted" style={{ fontSize: 12 }}>已通关题目</span></div>
          </div>
        </div>
      )}

      <h3 style={{ marginBottom: 12 }}>{labSrc ? "资产（每题 = 一个 SRC 子项目，评测只负责起容器）" : "题目（每题 = 一个 flag 赛道子项目）"}</h3>
      {chs.length > 0 && (
        <div className="status-filters">
          {Object.entries(STATUS_FILTER).map(([key, label]) => (
            <button key={key} className={statusFilter === key ? "active" : ""} onClick={() => setStatusFilter(key)}>
              {label} <b>{key === "all" ? chs.length : chs.filter((c) => filterStatusOf(c) === key).length}</b>
            </button>
          ))}
        </div>
      )}
      <BatchSelectionBar
        count={selectedCount}
        noun="题目"
        busy={!!busy}
        onRun={runSelected}
        onPause={pauseSelected}
        onDelete={deleteSelected}
        onClear={() => setSelectedIds([])}
      />
      {chs.length === 0 ? (
        <div className="card-cream" style={{ textAlign: "center", padding: 48 }}>
          <p className="muted">{labSrc
            ? "尚无资产。点击「拉取题目」从评测平台拉起容器（胶水），再按 SRC 挖。需 base_url/token 且靶场 VPN 已连。"
            : "尚无题目。点击「拉取题目」从评测平台拉题并按题自动创建子项目（需 base_url/token 且靶场 VPN 已连）。"}</p>
        </div>
      ) : visible.length === 0 ? (
        <div className="empty-list">没有符合当前筛选条件的题目。</div>
      ) : (
        <ChallengesTable
          challenges={paged}
          selectedIds={selectedIds}
          allSelected={allSelected}
          onToggle={toggleSelected}
          onToggleAll={toggleAll}
          labSrc={labSrc}
        />
      )}
      {visible.length > 0 && (
        <PaginationBar
          total={visible.length}
          page={curPage}
          pageSize={pageSize}
          onPage={setPage}
          onPageSize={setPageSize}
        />
      )}
    </div>
  );
}

function ChallengesTable({
  challenges, selectedIds, allSelected, onToggle, onToggleAll, labSrc = false,
}: {
  challenges: Board["challenges"];
  selectedIds: string[];
  allSelected: boolean;
  onToggle: (id: string) => void;
  onToggleAll: () => void;
  labSrc?: boolean;
}) {
  const nav = useNavigate();
  return (
    <div className="project-table-wrap">
      <table className="project-table">
        <thead><tr><th><input type="checkbox" checked={allSelected} onChange={onToggleAll} aria-label="全选题目" /></th><th>状态</th><th>{labSrc ? "资产" : "题目"}</th><th>难度</th>{labSrc ? null : <><th>Flag</th><th>得分</th><th>完成度</th></>}<th>攻击状态</th></tr></thead>
        <tbody>
          {challenges.map((c) => {
            const pct = c.flag_count ? Math.round((c.correct_flag_count / c.flag_count) * 100) : 0;
            const flagCell = `${c.correct_flag_count}/${c.flag_count || 1}${c.total_score ? ` · ${c.score}/${c.total_score}` : c.score ? ` · ${c.score}` : ""}`;
            return (
              <tr key={c.subproject_id} className={selectedIds.includes(c.subproject_id) ? "selected" : ""} onClick={() => nav(`/project/${c.subproject_id}`)}>
                <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selectedIds.includes(c.subproject_id)} onChange={() => onToggle(c.subproject_id)} aria-label={`选择 ${c.unique_code || c.name}`} /></td>
                <td><span className="row" style={{ gap: 7 }}><span className="pulse-dot" style={{ background: statusColor[c.status] || colors.muted }} />{statusLabel[c.status] || c.status}</span></td>
                <td><b>{c.unique_code || c.name}</b></td>
                <td>{c.difficulty || "—"}</td>
                {labSrc ? null : <><td>{flagCell}</td><td>{c.score}{c.total_score ? ` / ${c.total_score}` : ""}</td><td>{pct}%</td></>}
                <td>{c.is_completed ? <Badge coral>已完成</Badge> : c.lateral_active ? <span className="badge">横向</span> : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
