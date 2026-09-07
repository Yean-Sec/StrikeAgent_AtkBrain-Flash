import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../../api";
import type { Project } from "../../types";
import { Badge } from "../../components/Badge";
import { BatchSelectionBar } from "../../components/BatchSelectionBar";
import { ImportProgressBar, isImportPaused, isImportRunning, type ImportProgress } from "../../components/ImportProgressBar";
import { PaginationBar, pageItems, readPageSize } from "../../components/PaginationBar";
import { colors } from "../../theme";
import { huntFailedReason, listStatusOf } from "../../projectStatus";
import { ReportExportControls } from "../report/ExportReport";

const statusColor: Record<string, string> = {
  running: colors.success, queued: colors.warning, completed: colors.primary, idle: colors.mutedSoft, error: colors.error, stopped: colors.muted,
};
const statusLabel: Record<string, string> = {
  running: "运行中", queued: "排队中", completed: "已完成", idle: "空闲", error: "失败", stopped: "已停止", goal_reached: "已完成",
};

const STATUS_FILTER: Record<string, string> = {
  all: "全部", running: "进行中", completed: "已完成", idle: "未完成", stopped: "已暂停", error: "失败",
};

/** 展示态：排队（等并发槽）优先于笼统的 running */
function displayStatus(p: Project): string {
  if (p.queued) return "queued";
  if (p.running) return "running";
  if (huntFailedReason(p)) return "error";
  return p.status || "idle";
}

/** 筛选桶：与项目列表同一套 */
function filterStatusOf(p: Project): string {
  return listStatusOf(p);
}

function vhostsOf(p: Project): string[] {
  const fromCfg = Array.isArray(p.config?.vhosts) ? p.config.vhosts : [];
  const fromScope = Array.isArray(p.scope?.targets) ? p.scope.targets : [];
  const raw = (fromCfg.length ? fromCfg : fromScope).map((x: unknown) => String(x || "").trim()).filter(Boolean);
  const primary = String(p.target || "").toLowerCase().replace(/\.$/, "");
  const seen = new Set<string>();
  const out: string[] = [];
  for (const h of raw) {
    const k = h.toLowerCase().replace(/\.$/, "");
    if (!k || k === primary || seen.has(k)) continue;
    seen.add(k);
    out.push(h);
  }
  return out;
}

export function ClusterDashboard({
  project,
  onProjectUpdate,
}: {
  project: Project;
  onProjectUpdate?: (p: Project) => void;
}) {
  const [subs, setSubs] = useState<Project[]>([]);
  const [busy, setBusy] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importProgress, setImportProgress] = useState<ImportProgress | null>(
    () => (project.config?.import_progress as ImportProgress) || null,
  );
  const [summary, setSummary] = useState<any>(null);
  const [err, setErr] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [newAssets, setNewAssets] = useState("");
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState(project.name);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(readPageSize);
  const importPoll = useRef<ReturnType<typeof setTimeout> | null>(null);

  const assets: string[] = project.config?.assets || project.scope?.targets || [];

  const load = () => api.subprojects(project.id).then(setSubs).catch(() => {});
  useEffect(() => {
    load();
    const t = setInterval(load, importing ? 1500 : 8000);
    return () => clearInterval(t);
  }, [project.id, importing]);
  useEffect(() => {
    if (!editingName) setNameDraft(project.name);
  }, [project.name, editingName]);

  const pollImport = async () => {
    try {
      const p = await api.importProgress(project.id) as ImportProgress;
      setImportProgress(p);
      const running = isImportRunning(p);
      setImporting(running);
      if (running) {
        importPoll.current = setTimeout(pollImport, 400);
      } else if ((p.phase === "done" || p.phase === "error") && p.total) {
        await load();
        if (p.phase === "done") {
          setSummary((prev: any) => ({
            assets: assets.length,
            hosts: p.total,
            subprojects_created: p.created ?? prev?.subprojects_created,
            started: p.started ?? prev?.started,
          }));
          window.setTimeout(() => setImportProgress((cur) => (cur?.phase === "done" ? null : cur)), 2500);
        }
        if (p.phase === "error") setErr(p.message || "导入失败");
      } else if (isImportPaused(p)) {
        await load();
      }
    } catch {
      setImporting((was) => {
        if (was) importPoll.current = setTimeout(pollImport, 1200);
        return was;
      });
    }
  };

  useEffect(() => {
    pollImport();
    return () => { if (importPoll.current) clearTimeout(importPoll.current); };
  }, [project.id]);

  const saveName = async () => {
    const next = nameDraft.trim();
    if (!next) {
      setErr("名称不能为空");
      return;
    }
    if (next === project.name) {
      setEditingName(false);
      return;
    }
    setBusy(true); setErr("");
    try {
      const p = await api.renameProject(project.id, next);
      onProjectUpdate?.(p);
      setEditingName(false);
      await load();
    } catch (e: any) {
      setErr(e.message || "改名失败");
    } finally {
      setBusy(false);
    }
  };

  /** 可选：重新探测存活（非主路径；创建时已按 host 直建并启动） */
  const triage = async () => {
    setBusy(true); setErr("");
    try {
      const r = await api.triage(project.id);
      setSummary(r);
      await load();
    } catch (e: any) {
      setErr(e.message || "重新探测失败");
    } finally { setBusy(false); }
  };

  const refold = async () => {
    setBusy(true); setErr("");
    try {
      const r = await api.refoldMachines(project.id);
      setSummary({
        ...r,
        message: `已按同机折叠 ${r.merged_groups || 0} 组，删除 ${r.deleted || 0} 个子项目`
          + (r.skipped_running ? `，跳过 ${r.skipped_running} 组（有在跑）` : ""),
      });
      await load();
    } catch (e: any) {
      setErr(e.message || "按同机折叠失败");
    } finally { setBusy(false); }
  };

  const startAll = async () => {
    setBusy(true); setErr("");
    try { await api.startAll(project.id); await load(); }
    catch (e: any) { setErr(e.message || "批量启动失败"); }
    finally { setBusy(false); }
  };

  const stopAll = async () => {
    setBusy(true); setErr("");
    try { await api.stopAll(project.id); await load(); }
    catch (e: any) { setErr(e.message || "批量暂停失败"); }
    finally { setBusy(false); }
  };

  const pauseImport = async () => {
    setBusy(true); setErr("");
    try {
      const p = await api.pauseImport(project.id) as ImportProgress;
      setImportProgress(p);
      if (isImportRunning(p)) {
        if (importPoll.current) clearTimeout(importPoll.current);
        importPoll.current = setTimeout(pollImport, 200);
      } else {
        setImporting(false);
        await load();
      }
    } catch (e: any) {
      setErr(e.message || "暂停导入失败");
    } finally {
      setBusy(false);
    }
  };

  const resumeImport = async () => {
    setBusy(true); setErr("");
    try {
      const r = await api.resumeImport(project.id);
      const p = (r.import_progress || r) as ImportProgress;
      setImportProgress(p);
      setImporting(true);
      if (importPoll.current) clearTimeout(importPoll.current);
      importPoll.current = setTimeout(pollImport, 200);
    } catch (e: any) {
      setErr(e.message || "继续导入失败");
    } finally {
      setBusy(false);
    }
  };

  const addAssets = async () => {
    const blob = newAssets.trim();
    if (!blob) {
      setErr("请输入至少一个域名 / URL / IP");
      return;
    }
    const lineHint = blob.split(/\r?\n/).filter((s) => s.trim()).length;
    setBusy(true); setErr("");
    setImporting(true);
    setImportProgress({
      phase: "spawn", done: 0, total: lineHint, message: `已提交 ${lineHint} 条，正在按主机去重…`,
    });
    try {
      const r = await api.addClusterAssets(project.id, [blob], true);
      if (r.project && onProjectUpdate) onProjectUpdate(r.project);
      const skipN = r.skipped_dup_count ?? (r.skipped_dup || []).length;
      setSummary({
        assets: r.assets_total,
        hosts: r.pending_hosts ?? (r.added || []).length,
        subprojects_created: r.pending_hosts ?? r.subprojects_created,
        started: 0,
        added: (r.added || []).length,
        skipped: skipN,
        skippedUrls: r.skipped_dup_urls,
        rejected: (r.rejected || []).length,
        message: r.message,
      });
      setNewAssets("");
      if (r.rejected?.length) {
        setErr(`部分资产被拒绝：${r.rejected.map((x: any) => x.asset).join(", ")}`);
      }
      if (!r.importing) {
        setImporting(false);
        setImportProgress(null);
        await load();
      } else {
        setImportProgress(r.import_progress || r);
        if (importPoll.current) clearTimeout(importPoll.current);
        importPoll.current = setTimeout(pollImport, 200);
      }
    } catch (e: any) {
      setErr(e.message || "新增失败");
      setImporting(false);
      setImportProgress(null);
    } finally {
      setBusy(false);
    }
  };

  const onPickAssetFile = async (file?: File | null) => {
    if (!file) return;
    const text = await file.text();
    setNewAssets((prev) => (prev ? `${prev.trim()}\n${text}` : text));
  };

  const runningCount = subs.filter((s) => s.running && !s.queued).length;
  const queuedCount = subs.filter((s) => s.queued).length;
  const visible = statusFilter === "all" ? subs : subs.filter((p) => filterStatusOf(p) === statusFilter);
  useEffect(() => { setPage(1); }, [statusFilter, project.id]);
  const pageCount = Math.max(1, Math.ceil(visible.length / pageSize) || 1);
  const curPage = Math.min(page, pageCount);
  const paged = pageItems(visible, curPage, pageSize);
  const selectedCount = selectedIds.length;
  const allSelected = paged.length > 0 && paged.every((s) => selectedIds.includes(s.id));
  const toggleSelected = (id: string) => {
    setSelectedIds((ids) => ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]);
  };
  const toggleAll = () => setSelectedIds(allSelected ? selectedIds.filter((id) => !paged.some((s) => s.id === id)) : Array.from(new Set([...selectedIds, ...paged.map((s) => s.id)])));
  const runSelected = async () => {
    if (!selectedCount || !window.confirm(`将运行选中的 ${selectedCount} 个子项目。它们会占用 Agent 并发，是否继续？`)) return;
    setBusy(true); setErr("");
    try { await api.batchStartProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量运行失败"); }
    finally { setBusy(false); }
  };
  const pauseSelected = async () => {
    if (!selectedCount || !window.confirm(`将暂停选中的 ${selectedCount} 个子项目。正在执行的 Agent 会停止，仍可稍后重新运行，是否继续？`)) return;
    setBusy(true); setErr("");
    try { await api.batchStopProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量暂停失败"); }
    finally { setBusy(false); }
  };
  const deleteSelected = async () => {
    if (!selectedCount || !window.confirm(`将永久删除选中的 ${selectedCount} 个子项目及其攻击图、发现、报告和运行记录。此操作不可撤销，是否继续？`)) return;
    setBusy(true); setErr("");
    try { await api.batchDeleteProjects(selectedIds); setSelectedIds([]); await load(); }
    catch (e: any) { setErr(e.message || "批量删除失败"); }
    finally { setBusy(false); }
  };

  return (
    <div className="container" style={{ paddingTop: 24, paddingBottom: 40 }}>
      <Link to="/" className="muted" style={{ fontSize: 13 }}>&larr; 返回项目列表</Link>
      <div className="spread" style={{ margin: "10px 0 18px", alignItems: "flex-start" }}>
        <div>
          <div className="row" style={{ gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            {editingName ? (
              <>
                <input
                  className="input"
                  value={nameDraft}
                  autoFocus
                  disabled={busy}
                  onChange={(e) => setNameDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") saveName();
                    if (e.key === "Escape") { setEditingName(false); setNameDraft(project.name); }
                  }}
                  style={{ fontSize: 22, fontWeight: 600, maxWidth: 360 }}
                />
                <button className="btn btn-primary btn-sm" disabled={busy} onClick={saveName}>保存</button>
                <button
                  className="btn btn-secondary btn-sm"
                  disabled={busy}
                  onClick={() => { setEditingName(false); setNameDraft(project.name); }}
                >
                  取消
                </button>
              </>
            ) : (
              <>
                <h1 style={{ fontSize: 34 }}>{project.name}</h1>
                <Badge>集群</Badge>
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={busy}
                  onClick={() => { setNameDraft(project.name); setEditingName(true); setErr(""); }}
                  title="修改集群名称"
                >
                  改名
                </button>
              </>
            )}
          </div>
          <div className="row" style={{ gap: 12, marginTop: 6 }}>
            <span className="muted" style={{ fontSize: 13 }}>
              资产 {assets.length} · 子项目 {subs.length} · 运行中 {runningCount}
              {queuedCount > 0 ? ` · 排队 ${queuedCount}` : ""}
            </span>
          </div>
        </div>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <ReportExportControls projectId={project.id} disabled={busy} />
          <button className="btn btn-primary" disabled={busy} onClick={() => { setShowAdd((v) => !v); setErr(""); }}>
            {showAdd ? "取消" : "新增项目"}
          </button>
          <button className="btn btn-primary" disabled={busy || subs.length === 0} onClick={startAll}>
            {busy ? "处理中…" : "全部启动"}
          </button>
          <button className="btn btn-secondary" disabled={busy || runningCount === 0} onClick={stopAll}>
            全部暂停
          </button>
          <button className="btn btn-secondary" disabled={busy} onClick={triage} title="可选：HTTP 存活探测并补建子项目">
            重新探测（可选）
          </button>
          <button
            className="btn btn-secondary"
            disabled={busy || subs.length === 0}
            onClick={refold}
            title="把 idle/error 子项目按同一 FQDN 或同一非 CDN 源站 IP 合成一台机；在跑的不动，不会自动启动"
          >
            按同机折叠
          </button>
        </div>
      </div>

      <ImportProgressBar
        progress={importProgress}
        title={isImportPaused(importProgress) ? "导入已暂停" : (isImportRunning(importProgress) ? "正在导入资产" : undefined)}
        onPause={pauseImport}
        onResume={resumeImport}
        busy={busy}
      />

      {showAdd && (
        <div className="card-cream" style={{ marginBottom: 20, padding: 18 }}>
          <h3 style={{ marginBottom: 8, fontSize: 16 }}>向集群追加目标</h3>
          <p className="muted" style={{ fontSize: 13, marginBottom: 10 }}>
            每行一个域名 / URL / IP:端口。同一主机名的不同端口会并进一台机；解析到同一非 CDN 源站 IP 的不同域名也会合成一个子项目，端口只扫一次。CDN 边缘 IP 不合并且各建独立项目。
          </p>
          <div className="row" style={{ gap: 10, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
            <label className="btn btn-secondary btn-sm" style={{ cursor: busy || importing ? "not-allowed" : "pointer" }}>
              选择文件（如 合集_可访问.txt）
              <input
                type="file"
                accept=".txt,.csv,.list,text/plain"
                hidden
                disabled={busy || importing}
                onChange={(e) => { onPickAssetFile(e.target.files?.[0]); e.target.value = ""; }}
              />
            </label>
            <span className="muted" style={{ fontSize: 12 }}>文件内容会追加到下面文本框，确认后再导入</span>
          </div>
          <textarea
            className="input"
            rows={4}
            value={newAssets}
            onChange={(e) => setNewAssets(e.target.value)}
            placeholder={"https://example.com\nother.target.com\n10.0.0.8:8080"}
            disabled={busy || importing}
            style={{ width: "100%", marginBottom: 12 }}
          />
          <div className="row" style={{ gap: 10 }}>
            <button className="btn btn-primary" disabled={busy || importing} onClick={addAssets}>
              {busy || importing ? "添加中…" : "确认添加并启动"}
            </button>
            <button className="btn btn-secondary" disabled={busy} onClick={() => { setShowAdd(false); setNewAssets(""); }}>
              取消
            </button>
          </div>
        </div>
      )}

      {err && <div style={{ color: "var(--error)", marginBottom: 12, fontSize: 14 }}>{err}</div>}

      {summary && (
        <div className="card-cream" style={{ marginBottom: 20, padding: 18 }}>
          <div className="row" style={{ gap: 22, fontSize: 14, flexWrap: "wrap" }}>
            {summary.added != null && <span>新写入资产 <b style={{ color: colors.success }}>{summary.added}</b></span>}
            {summary.skipped != null && (
              <span>
                跳过已有子项目 <b>{summary.skipped}</b>
                {summary.skippedUrls != null ? ` 个主机（${summary.skippedUrls} 条 URL）` : ""}
              </span>
            )}
            {summary.rejected != null && summary.rejected > 0 && <span>拒绝 <b style={{ color: colors.error }}>{summary.rejected}</b></span>}
            <span>资产 <b>{summary.assets}</b></span>
            <span>将补建子项目 <b style={{ color: colors.primary }}>{summary.hosts}</b></span>
            {summary.live_hosts != null && <span>存活主机 <b style={{ color: colors.success }}>{summary.live_hosts}</b></span>}
            {summary.live_endpoints != null && <span>存活端点 <b>{summary.live_endpoints}</b></span>}
            {summary.subprojects_created > 0 && <span>新建子项目 <b style={{ color: colors.primary }}>{summary.subprojects_created}</b></span>}
            {summary.started != null && <span>已启动 <b>{summary.started}</b></span>}
          </div>
          {summary.message && <p className="muted" style={{ marginTop: 8, fontSize: 13 }}>{summary.message}</p>}
        </div>
      )}

      <h3 style={{ marginBottom: 12 }}>子项目（每个授权主机一个单目标闭环）</h3>
      <div className="status-filters">
        {Object.entries(STATUS_FILTER).map(([key, label]) => (
          <button key={key} className={statusFilter === key ? "active" : ""} onClick={() => setStatusFilter(key)}>
            {label} <b>{key === "all" ? subs.length : subs.filter((p) => filterStatusOf(p) === key).length}</b>
          </button>
        ))}
      </div>
      <BatchSelectionBar
        count={selectedCount}
        busy={busy}
        onRun={runSelected}
        onPause={pauseSelected}
        onDelete={deleteSelected}
        onClear={() => setSelectedIds([])}
      />
      {subs.length === 0 ? (
        <div className="card-cream" style={{ textAlign: "center", padding: 48 }}>
          <p className="muted">暂无子项目。可点「新增项目」直接追加，或「重新探测」补建：</p>
          <div className="mono muted" style={{ fontSize: 12, marginTop: 12, whiteSpace: "pre-wrap" }}>{assets.join("  ") || "（无资产）"}</div>
        </div>
      ) : visible.length === 0 ? (
        <div className="empty-list">没有符合当前筛选条件的子项目。</div>
      ) : (
        <SubprojectsTable
          projects={paged}
          selectedIds={selectedIds}
          allSelected={allSelected}
          onToggle={toggleSelected}
          onToggleAll={toggleAll}
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

function SubprojectsTable({
  projects, selectedIds, allSelected, onToggle, onToggleAll,
}: {
  projects: Project[];
  selectedIds: string[];
  allSelected: boolean;
  onToggle: (id: string) => void;
  onToggleAll: () => void;
}) {
  const nav = useNavigate();
  return (
    <div className="project-table-wrap">
      <table className="project-table">
        <thead><tr><th><input type="checkbox" checked={allSelected} onChange={onToggleAll} aria-label="全选子项目" /></th><th>状态</th><th>目标</th><th>同机</th><th>端口</th><th>节点</th><th>服务</th><th>高危</th><th>严重</th><th>攻击状态</th></tr></thead>
        <tbody>
          {projects.map((p) => {
            const s = p.stats;
            const aliases = vhostsOf(p);
            return (
              <tr key={p.id} className={selectedIds.includes(p.id) ? "selected" : ""} onClick={() => nav(`/project/${p.id}`)}>
                <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selectedIds.includes(p.id)} onChange={() => onToggle(p.id)} aria-label={`选择 ${p.target || p.name}`} /></td>
                <td>
                  <span className="row" style={{ gap: 7, alignItems: "center", flexWrap: "wrap" }}>
                    <span className="pulse-dot" style={{ background: statusColor[displayStatus(p)] || colors.muted }} />
                    {statusLabel[displayStatus(p)] || p.status}
                    {p.queued ? <span className="badge" style={{ background: "rgba(217,190,132,0.16)", color: "#d9be84", borderColor: "rgba(217,190,132,0.35)" }} title="已启动，等待顶部「并发项目」空出槽位后才会真正开跑">等并发槽</span> : null}
                    {!p.running && p.config?.completion_reason === "entry_dead" ? <span className="badge" style={{ background: "rgba(217,190,132,0.16)", color: "#d9be84", borderColor: "rgba(217,190,132,0.35)" }} title="入口连续不可达；站点恢复后可再启动">入口不可达</span> : null}
                    {!p.running && (p.config?.completion_reason === "env_closed" || p.config?.completion_reason === "env_unreachable" || p.config?.env_closed) ? <span className="badge" style={{ background: "rgba(198,69,69,.12)", color: "#c64545", borderColor: "rgba(198,69,69,.35)" }} title="评测任务已到期或平台不可达">环境已到期</span> : null}
                  </span>
                </td>
                <td>
                  <b>{p.target || p.name}</b>
                  {aliases.length > 0 ? (
                    <div className="muted" style={{ fontSize: 12, marginTop: 2 }} title={aliases.join(", ")}>
                      同机 {aliases.length + 1} 个域名
                    </div>
                  ) : null}
                </td>
                <td className="mono" title={aliases.join(", ") || undefined}>{aliases.length ? aliases.length : "—"}</td>
                <td className="mono">{(p.ports || []).join(", ") || "全端口"}</td>
                <td>{s?.nodes ?? 0}</td><td>{s?.services ?? 0}</td>
                <td className={(s?.high ?? 0) > 0 ? "danger-number" : ""}>{s?.high ?? 0}</td>
                <td className={(s?.critical ?? 0) > 0 ? "danger-number" : ""}>{s?.critical ?? 0}</td>
                <td>{s?.has_shell ? <Badge coral>GETSHELL</Badge> : s?.lateral_active ? <span className="badge">横向</span> : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
