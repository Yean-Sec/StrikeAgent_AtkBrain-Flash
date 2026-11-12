import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, formatApiError } from "../api";
import type { Project } from "../types";
import { Modal } from "../components/Modal";
import { ImportProgressBar, isImportPaused, isImportRunning, type ImportProgress } from "../components/ImportProgressBar";
import { fadeInUp } from "../anim";
import { PaginationBar, pageItems, readPageSize } from "../components/PaginationBar";
import { colors } from "../theme";
import { listStatusOf } from "../projectStatus";
import { useT } from "../i18n";

function trackOf(p: Project): "agent" | "ctf" {
  const tr = String((p.config as any)?.track || "").toLowerCase();
  const obj = String((p.config as any)?.objective || "").toLowerCase();
  if (tr === "ctf" || obj === "flag" || obj === "ctf") return "ctf";
  if (p.kind === "benchmark" && !tr && !obj) return "ctf";
  return "agent";
}

type BatchAction = "start" | "stop" | "delete";
function statusOf(p: Project) { return listStatusOf(p); }

const STATUS_KEYS = ["all", "running", "completed", "idle", "stopped", "error"] as const;

export function ProjectsPage() {
  const { t } = useT();
  const [projects, setProjects] = useState<Project[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState(""); const [kind, setKind] = useState("all"); const [track, setTrack] = useState("all"); const [status, setStatus] = useState("all");
  const [pendingAction, setPendingAction] = useState<BatchAction | null>(null);
  const [batchErr, setBatchErr] = useState("");
  const [rename, setRename] = useState<Project | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(readPageSize);
  const [params, setParams] = useSearchParams();
  const heroRef = useRef<HTMLDivElement>(null);
  const load = () => api.listProjects().then(setProjects).catch(() => {});
  useEffect(() => { load(); const tmr = setInterval(load, 15000); return () => clearInterval(tmr); }, []);
  useEffect(() => { if (heroRef.current) fadeInUp(heroRef.current.children); }, []);
  useEffect(() => { if (params.get("create") === "1") { setShowCreate(true); setParams({}, { replace: true }); } }, [params, setParams]);
  useEffect(() => { const alive = new Set(projects.map((p) => p.id)); setSelected((old) => new Set([...old].filter((id) => alive.has(id)))); }, [projects]);
  const visible = projects.filter((p) => (!query || `${p.name} ${p.target || ""}`.toLowerCase().includes(query.toLowerCase())) && (kind === "all" || (kind === "single" ? p.kind === "single" : p.kind !== "single")) && (track === "all" || (track === "agent" ? trackOf(p) !== "ctf" : trackOf(p) === track)) && (status === "all" || statusOf(p) === status));
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
  const archiveSelected = async () => {
    const ids = [...selected];
    if (!ids.length) return;
    setBusy(true);
    setBatchErr("");
    try {
      await api.archiveProjects(ids);
      setSelected(new Set());
      load();
    } catch (e: any) {
      setBatchErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };
  const saveTemplateSelected = async () => {
    const id = [...selected][0];
    if (!id) return;
    setBusy(true);
    setBatchErr("");
    try {
      await api.saveProjectTemplate(id, projects.find((p) => p.id === id)?.name || "");
      setBatchErr(t("projects.templateSaved"));
    } catch (e: any) {
      setBatchErr(String(e?.message || e));
    } finally {
      setBusy(false);
    }
  };
  const runBatch = async () => {
    const ids = [...selected]; if (!pendingAction || !ids.length) return;
    setBusy(true);
    setBatchErr("");
    try {
      let result: { failed?: { id?: string; error?: string }[] } | undefined;
      if (pendingAction === "delete") result = await api.batchDeleteProjects(ids);
      if (pendingAction === "start") result = await api.batchStartProjects(ids);
      if (pendingAction === "stop") result = await api.batchStopProjects(ids);
      const failed = result?.failed || [];
      if (failed.length) {
        setBatchErr(failed.map((f) => `${f.id || ""} ${f.error || ""}`.trim()).join("；"));
      }
      setSelected(new Set());
      await load();
    } catch (e: any) {
      setBatchErr(formatApiError(e, t("projects.batchFailed")));
    } finally {
      setBusy(false);
      setPendingAction(null);
    }
  };
  const statusFilterLabel = (key: string) => ({
    all: t("projects.statusAll"),
    running: t("projects.statusRunning"),
    completed: t("projects.statusCompleted"),
    idle: t("projects.statusIdle"),
    stopped: t("projects.statusStopped"),
    error: t("projects.statusError"),
  } as Record<string, string>)[key] || key;
  return <div className="page-container projects-page">
    <div ref={heroRef} className="spread" style={{ alignItems: "flex-end", marginBottom: 26 }}><div><p className="eyebrow">PROJECTS</p><h1>{t("projects.title")}</h1><p className="muted" style={{ marginTop: 8 }}>{t("projects.subtitle")}</p></div><button className="btn btn-primary" onClick={() => setShowCreate(true)}>+ {t("shell.newProject")}</button></div>
    <section className="project-list-toolbar"><input className="input project-search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("projects.search")} /><Filter value={kind} onChange={setKind} options={[["all", t("projects.kindAll")], ["single", t("projects.kindSingle")], ["cluster", t("projects.kindCluster")]]} /><Filter value={track} onChange={setTrack} options={[["all", t("projects.trackAll")], ["agent", t("projects.trackAgent")], ["ctf", "CTF"]]} /></section>
    <div className="status-filters">{STATUS_KEYS.map((key) => <button key={key} className={status === key ? "active" : ""} onClick={() => setStatus(key)}>{statusFilterLabel(key)} <b>{key === "all" ? projects.length : projects.filter((p) => statusOf(p) === key).length}</b></button>)}</div>
    <div className="batch-toolbar"><span className="muted">{t("projects.selected", { n: selected.size, total: visible.length })}</span><button className="btn btn-secondary btn-sm" onClick={selectAll} disabled={!visible.length || busy}>{t("projects.selectFiltered")}</button><button className="btn btn-secondary btn-sm" onClick={() => setSelected(new Set())} disabled={!selected.size || busy}>{t("projects.clearSelect")}</button><div style={{ flex: 1 }} /><button className="btn btn-primary btn-sm" onClick={() => setPendingAction("start")} disabled={!selected.size || busy}>{t("projects.batchStart")}</button><button className="btn btn-secondary btn-sm" onClick={() => setPendingAction("stop")} disabled={!selected.size || busy}>{t("projects.batchStop")}</button><button className="btn btn-secondary btn-sm" onClick={() => { void archiveSelected(); }} disabled={!selected.size || busy}>{t("projects.archive")}</button><button className="btn btn-secondary btn-sm" onClick={() => { void saveTemplateSelected(); }} disabled={selected.size !== 1 || busy}>{t("projects.saveTemplate")}</button><button className="btn btn-danger btn-sm" onClick={() => setPendingAction("delete")} disabled={!selected.size || busy}>{t("projects.batchDelete")}</button></div>
    {batchErr ? <p className="error-text" style={{ margin: "8px 0 0" }}>{batchErr}</p> : null}
    <div className="project-table-wrap"><table className="project-table"><thead><tr><th><input type="checkbox" checked={pageAllSelected} onChange={togglePage} /></th><th>{t("projects.colName")}</th><th>{t("projects.colKind")}</th><th>{t("projects.colStatus")}</th><th>{t("projects.colNodes")}</th><th>{t("projects.colServices")}</th><th>{t("projects.colHigh")}</th><th>{t("projects.colCritical")}</th><th>{t("projects.colUpdated")}</th></tr></thead><tbody>{paged.map((p) => <ProjectRow key={p.id} p={p} selected={selected.has(p.id)} onToggle={() => toggle(p.id)} onRename={() => setRename(p)} />)}</tbody></table>{!visible.length && <div className="empty-list">{t("projects.empty")}</div>}</div>
    {visible.length > 0 && <PaginationBar total={visible.length} page={curPage} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} />}
    {showCreate && <CreateModal onClose={() => setShowCreate(false)} onCreated={load} />}
    {rename && <RenameDialog project={rename} onClose={() => setRename(null)} onSaved={() => { setRename(null); load(); }} />}
    {pendingAction && <BatchConfirm action={pendingAction} count={selected.size} projects={projects.filter((p) => selected.has(p.id))} onClose={() => setPendingAction(null)} onConfirm={runBatch} busy={busy} />}
  </div>;
}

function Filter({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: [string, string][] }) { return <select className="select compact-filter" value={value} onChange={(e) => onChange(e.target.value)}>{options.map(([v, label]) => <option key={v} value={v}>{label}</option>)}</select>; }
function ProjectRow({ p, selected, onToggle, onRename }: { p: Project; selected: boolean; onToggle: () => void; onRename: () => void }) {
  const { t } = useT();
  const nav = useNavigate(); const s: any = p.stats || {}; const color: Record<string, string> = { running: colors.success, completed: colors.primary, idle: colors.mutedSoft, error: colors.error, stopped: colors.muted };
  const track = trackOf(p);
  const trackText = track === "ctf" ? "CTF" : t("projects.trackAgent");
  const kindText = p.kind === "single" ? t("projects.single") : p.kind === "benchmark" ? (track === "agent" ? t("projects.srcCluster") : t("projects.ctfCluster")) : t("projects.cluster");
  const subText = p.target || (p.kind === "benchmark" ? (track === "agent" ? t("projects.srcGlue") : t("projects.ctfBench")) : t("projects.multiAsset"));
  const listStatus = statusOf(p);
  const listStatusText = ({
    all: t("projects.statusAll"),
    running: t("projects.statusRunning"),
    completed: t("projects.statusCompleted"),
    idle: t("projects.statusIdle"),
    stopped: t("projects.statusStopped"),
    error: t("projects.statusError"),
    queued: t("status.queued"),
  } as Record<string, string>)[listStatus] || listStatus;
  return <tr className={selected ? "selected" : ""} onClick={() => nav(`/project/${p.id}`)}><td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selected} onChange={onToggle} /></td><td><strong>{p.name}</strong>{p.archived ? <span className="table-sub"> {t("projects.archived")}</span> : null}<span className="table-sub mono">{subText}</span></td><td><span className="badge badge-pill">{kindText}</span><span className="table-sub">{trackText}</span></td><td><span className="row" style={{ gap: 6 }}><span className="pulse-dot" style={{ background: color[listStatus] || colors.muted }} />{listStatusText}</span></td><td>{s.nodes || 0}</td><td>{s.services || 0}</td><td>{s.high || 0}</td><td className={s.critical ? "danger-number" : ""}>{s.critical || 0}</td><td><span className="table-sub">{new Date((p.updated_at || p.created_at) * 1000).toLocaleString()}</span><button className="row-rename" onClick={(e) => { e.stopPropagation(); onRename(); }}>{t("common.edit")}</button></td></tr>;
}
function BatchConfirm({ action, count, projects, onClose, onConfirm, busy }: { action: BatchAction; count: number; projects: Project[]; onClose: () => void; onConfirm: () => void; busy: boolean }) {
  const { t } = useT();
  const label = { start: t("common.start"), stop: t("common.pause"), delete: t("common.delete") }[action]; const running = projects.filter((p) => statusOf(p) === "running" || statusOf(p) === "queued").length;
  return <Modal title={t("projects.confirmBatch", { action: label })} onClose={onClose}><p>{t("projects.confirmBatchBody", { n: count, action: label })}</p><div className="confirm-impact">{t("projects.confirmImpact", { running, clusters: projects.filter((p) => p.kind !== "single").length })}</div><p className="muted">{action === "delete" ? t("projects.deleteWarn") : action === "stop" ? t("projects.stopWarn") : t("projects.startWarn")}</p><div className="row" style={{ justifyContent: "flex-end", marginTop: 22 }}><button className="btn btn-secondary" onClick={onClose} disabled={busy}>{t("common.cancel")}</button><button className={`btn ${action === "delete" ? "btn-danger" : "btn-primary"}`} onClick={onConfirm} disabled={busy}>{busy ? t("common.processing") : t("projects.confirmAction", { action: label })}</button></div></Modal>;
}
function RenameDialog({ project, onClose, onSaved }: { project: Project; onClose: () => void; onSaved: () => void }) {
  const { t } = useT();
  const [name, setName] = useState(project.name); const [busy, setBusy] = useState(false); const [err, setErr] = useState("");
  const save = async () => { if (!name.trim()) return setErr(t("projects.nameRequired")); setBusy(true); try { await api.renameProject(project.id, name.trim()); onSaved(); } catch (e: any) { setErr(e?.message || t("projects.renameFailed")); } finally { setBusy(false); } };
  return <Modal title={t("projects.renameTitle")} onClose={onClose}><p className="muted">{project.kind === "single" ? t("projects.renameSingle") : t("projects.renameCluster")}</p><input className="input" autoFocus value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && save()} />{err && <p className="error-text">{err}</p>}<div className="row" style={{ justifyContent: "flex-end", marginTop: 20 }}><button className="btn btn-secondary" onClick={onClose}>{t("common.cancel")}</button><button className="btn btn-primary" onClick={save} disabled={busy}>{busy ? t("common.saving") : t("projects.saveName")}</button></div></Modal>;
}

const CTF_TYPES = ["web", "pwn", "reverse", "misc", "crypto"] as const;
type CtfType = typeof CTF_TYPES[number];

function targetLines(text: string): string[] {
  const header = new Set(["host", "ip", "target", "url", "domain", "资产", "目标"]);
  const out: string[] = [];
  for (const rawLine of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    let raw = rawLine.trim();
    if (!raw || raw.startsWith("#") || raw.startsWith("//") || raw.startsWith(";")) continue;
    raw = raw.replace(/[,;，]+$/, "");
    if (!raw) continue;
    const parts = raw.includes("://") ? [raw] : raw.split(",");
    for (const part of parts) {
      const item = part.trim().replace(/[,;，]+$/, "");
      if (!item || header.has(item.toLowerCase())) continue;
      out.push(item);
    }
  }
  return out;
}

function CreateModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { t } = useT();
  const nav = useNavigate();
  const [track, setTrack] = useState<"agent" | "ctf">("agent");
  const [ctfType, setCtfType] = useState<CtfType>("web");
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [note, setNote] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [importProgress, setImportProgress] = useState<ImportProgress | null>(null);
  const [importKick, setImportKick] = useState(0);
  const importPoll = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingHuntId = useRef<string | null>(null);

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
          setErr(p.message || t("projects.importFailed"));
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
    const lines = targetLines(targets);
    const batch = lines.length > 1;
    try {
      if (track === "ctf" && !ctfType) throw new Error(t("projects.needCtfType"));
      if (!lines.length && !(track === "ctf" && files.length)) throw new Error(track === "ctf" ? t("projects.needTargetOrFile") : t("projects.needTarget"));
      const body: any = { name, track, output_lang: "zh", hint: note.trim() };
      if (track === "ctf") body.ctf_category = ctfType;
      if (!lines.length) {
        body.kind = "single";
      } else if (!batch) {
        body.kind = "single";
        body.target = lines[0];
        body.allow_subdomains = false;
      } else {
        body.kind = "cluster";
        body.assets = [targets];
        setImportProgress({
          phase: "merge",
          done: 0,
          total: lines.length,
          message: t("projects.mergingZone"),
        });
      }
      let id = pendingHuntId.current;
      if (!id) {
        const p: any = await api.createProject(body);
        id = p.id;
        if (track === "ctf" && files.length) {
          try {
            await api.uploadChallengeFiles(id, files);
          } catch (uploadErr) {
            setCreatedId(id);
            throw uploadErr;
          }
        }
        if (batch && (p.importing || p.import_progress)) {
          setCreatedId(id);
          setImportProgress(p.import_progress || { phase: "spawn", done: 0, total: 0, message: t("projects.importing") });
          return;
        }
        pendingHuntId.current = id;
      }
      await api.start(id, false);
      pendingHuntId.current = null;
      onCreated();
      onClose();
      nav(`/project/${id}`);
    } catch (e: any) {
      setErr(e.message || t("projects.createFailed"));
    } finally {
      setBusy(false);
    }
  };

  const handleClose = () => {
    if (createdId) onCreated();
    onClose();
  };

  const typeSummary: Record<CtfType, string> = {
    web: t("projects.ctfWeb"),
    pwn: t("projects.ctfPwn"),
    reverse: t("projects.ctfReverse"),
    misc: t("projects.ctfMisc"),
    crypto: t("projects.ctfCrypto"),
  };
  const typeLabel: Record<CtfType, string> = {
    web: "Web",
    pwn: "PWN",
    reverse: "逆向",
    misc: "杂项",
    crypto: "密码学",
  };

  return (
    <Modal title={t("projects.createTitle")} onClose={handleClose} wide>
      <div className="create-entries">
        <button type="button" className={`btn ${track === "agent" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTrack("agent")}>{t("projects.entryAgent")}</button>
        <button type="button" className={`btn ${track === "ctf" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTrack("ctf")}>{t("projects.entryCtf")}</button>
      </div>
      {track === "ctf" && (
        <div className="field" style={{ marginTop: 14 }}>
          <span>{t("projects.ctfType")}</span>
          <div className="ctf-types">
            {CTF_TYPES.map((key) => (
              <button key={key} type="button" className={`btn btn-sm ${ctfType === key ? "btn-primary" : "btn-secondary"}`} onClick={() => setCtfType(key)}>{typeLabel[key]}</button>
            ))}
          </div>
          <span style={{ fontSize: 12, color: "var(--muted)", marginTop: 6, display: "block", lineHeight: 1.55 }}>{typeSummary[ctfType]}</span>
          <div className="field" style={{ marginTop: 12 }}>
            <span>{t("projects.ctfFiles")}</span>
            <div className="row" style={{ gap: 8, marginTop: 4 }}>
              <label className="btn btn-secondary btn-sm" style={{ cursor: "pointer" }}>
                {t("projects.pickFile")}
                <input
                  type="file"
                  multiple
                  hidden
                  onChange={(e) => {
                    const picked = Array.from(e.target.files || []);
                    e.target.value = "";
                    if (!picked.length) return;
                    setFiles((prev) => [...prev, ...picked]);
                  }}
                />
              </label>
            </div>
            {files.length > 0 && (
              <div className="file-picks">
                {files.map((file, i) => <span key={`${file.name}-${i}`}>{file.name}</span>)}
              </div>
            )}
            <span style={{ fontSize: 12, color: "var(--muted)", marginTop: 6, display: "block" }}>{t("projects.ctfFilesHint")}</span>
          </div>
        </div>
      )}

      <label className="field" style={{ marginTop: 12 }}>
        <span>{t("projects.name")}</span>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={t("projects.namePhSingle")} />
      </label>
      <div className="create-split" style={{ marginTop: 12 }}>
        <div className="field">
          <span>{t("projects.targetBox")}</span>
          <div className="row" style={{ gap: 8, margin: "6px 0 8px" }}>
            <label className="btn btn-secondary btn-sm" style={{ cursor: "pointer" }}>
              {t("projects.pickTargets")}
              <input
                type="file"
                accept=".txt,.csv,.list,text/plain"
                hidden
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (!f) return;
                  const text = await f.text();
                  setTargets((prev) => (prev.trim() ? `${prev.trim()}\n${text}` : text));
                }}
              />
            </label>
          </div>
          <textarea className="input" rows={6} value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={"example.com\n192.168.236.1:8787"} />
          <span style={{ fontSize: 12, color: "var(--muted)", marginTop: 6, display: "block" }}>{t("projects.targetHint")}</span>
        </div>
        <label className="field">
          <span>{t("projects.extraInfo")}</span>
          <textarea className="input" rows={8} value={note} onChange={(e) => setNote(e.target.value)} placeholder={track === "ctf" ? t("projects.extraCtf") : t("projects.extraAgent")} style={{ marginTop: 6 }} />
        </label>
      </div>

      {err && <div style={{ color: "var(--error)", marginBottom: 12, fontSize: 14 }}>{err}</div>}
      {(busy || importProgress) && targetLines(targets).length > 1 && (
        <ImportProgressBar
          progress={importProgress || { phase: "spawn", done: 0, total: 0, message: t("projects.creatingCluster") }}
          onPause={createdId ? async () => {
            try {
              const p = await api.pauseImport(createdId);
              setImportProgress(p);
            } catch (e: any) {
              setErr(e.message || t("projects.pauseImportFailed"));
            }
          } : undefined}
          onResume={createdId ? async () => {
            try {
              const r = await api.resumeImport(createdId);
              setImportProgress(r.import_progress || r);
              setBusy(true);
              setImportKick((n) => n + 1);
            } catch (e: any) {
              setErr(e.message || t("projects.resumeImportFailed"));
            }
          } : undefined}
        />
      )}
      <div className="row" style={{ justifyContent: "flex-end", gap: 10 }}>
        <button className="btn btn-secondary" onClick={handleClose} disabled={busy}>{t("common.cancel")}</button>
        {createdId ? (
          <button className="btn btn-primary" onClick={() => enterProject(createdId)}>{t("projects.enterProject")}</button>
        ) : (
          <button className="btn btn-primary" disabled={busy} onClick={submit}>
            {busy ? t("projects.importingBtn") : t("projects.createEnter")}
          </button>
        )}
      </div>
    </Modal>
  );
}
