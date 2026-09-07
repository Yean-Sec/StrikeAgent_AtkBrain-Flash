export type ImportProgress = {
  phase?: string;
  done?: number;
  total?: number;
  created?: number;
  started?: number;
  current?: string;
  message?: string;
  importing?: boolean;
  stale?: boolean;
};

const PHASE_LABEL: Record<string, string> = {
  parse: "解析资产",
  spawn: "创建子项目",
  start: "排队启动",
  done: "导入完成",
  error: "导入失败",
  idle: "空闲",
  paused: "已暂停导入",
};

export function isImportRunning(p?: ImportProgress | null): boolean {
  const phase = (p?.phase || "").toLowerCase();
  if (!p || p.stale) return false;
  return phase === "parse" || phase === "spawn" || phase === "start";
}

export function isImportPaused(p?: ImportProgress | null): boolean {
  return (p?.phase || "").toLowerCase() === "paused";
}

export function ImportProgressBar({
  progress,
  title,
  onPause,
  onResume,
  busy,
}: {
  progress?: ImportProgress | null;
  title?: string;
  onPause?: () => void;
  onResume?: () => void;
  busy?: boolean;
}) {
  if (!progress) return null;
  const phase = (progress.phase || "").toLowerCase();
  if (!phase || phase === "idle" || progress.stale) return null;
  const total = Math.max(0, Number(progress.total) || 0);
  const done = Math.max(0, Number(progress.done) || 0);
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : (phase === "done" ? 100 : 8);
  const label = PHASE_LABEL[phase] || phase;
  const err = phase === "error";
  const paused = phase === "paused";
  const running = isImportRunning(progress);
  return (
    <div className={`import-progress${err ? " is-error" : ""}${paused ? " is-paused" : ""}`} role="status" aria-live="polite">
      <div className="import-progress-head">
        <strong>{title || label}</strong>
        <span className="mono">
          {total > 0 ? `${done}/${total} · ${pct}%` : (progress.message || label)}
        </span>
      </div>
      <div className="import-progress-track">
        <div
          className={`import-progress-fill${total <= 0 && phase !== "done" && !paused ? " is-indeterminate" : ""}`}
          style={{ width: `${Math.max(err ? 100 : 4, pct)}%` }}
        />
      </div>
      <div className="import-progress-meta muted">
        {progress.message || (progress.current ? `当前 ${progress.current}` : "请稍候，正在写入子项目…")}
        {typeof progress.created === "number" && progress.created > 0 ? ` · 已建 ${progress.created}` : ""}
        {typeof progress.started === "number" && progress.started > 0 ? ` · 已启动 ${progress.started}` : ""}
      </div>
      {(onPause || onResume) && (running || paused) && (
        <div className="import-progress-actions">
          {running && onPause && (
            <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={onPause}>
              {busy ? "处理中…" : "暂停导入"}
            </button>
          )}
          {paused && onResume && (
            <button type="button" className="btn btn-primary btn-sm" disabled={busy} onClick={onResume}>
              {busy ? "处理中…" : "继续导入"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
