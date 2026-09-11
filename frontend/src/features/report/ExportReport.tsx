import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { Modal } from "../../components/Modal";

export type ReportExportJob = {
  id: string;
  project_id: string;
  format: string;
  status: "running" | "done" | "error" | string;
  percent: number;
  message?: string;
  error?: string | null;
  filename?: string | null;
  cached?: boolean;
  claude?: boolean;
  claude_error?: string | null;
  pi_role?: string;
};

function DownloadIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true">
      <path d="M8 2.2v7.2" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      <path d="M5.2 7.4 8 10.2l2.8-2.8" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M3 12.2h10" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}

function ChevronIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden="true">
      <path d="M2 3.5 5 6.5 8 3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function ReportExportControls({
  projectId,
  extraClass,
  disabled = false,
}: {
  projectId: string;
  extraClass?: string;
  disabled?: boolean;
}) {
  const [menu, setMenu] = useState(false);
  const [open, setOpen] = useState(false);
  const [job, setJob] = useState<ReportExportJob | null>(null);
  const [err, setErr] = useState("");
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);

  const stopPoll = () => {
    if (poll.current) {
      clearInterval(poll.current);
      poll.current = null;
    }
  };

  useEffect(() => () => stopPoll(), []);

  useEffect(() => {
    if (!menu) return;
    const onDoc = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setMenu(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [menu]);

  const start = async (fmt: "html" | "pdf") => {
    setMenu(false);
    setErr("");
    setOpen(true);
    setJob({
      id: "",
      project_id: projectId,
      format: fmt,
      status: "running",
      percent: 1,
      message: fmt === "pdf" ? "专职导出 Pi 排队中…" : "专职导出 Pi 排队中…",
    });
    try {
      const j = await api.startReportExport(projectId, fmt);
      setJob(j);
      stopPoll();
      const tick = async (): Promise<boolean> => {
        try {
          const s = await api.reportExportStatus(projectId, j.id);
          setJob(s);
          if (s.status === "done" || s.status === "error") {
            stopPoll();
            return false;
          }
          return true;
        } catch (e: any) {
          setErr(String(e?.message || e));
          stopPoll();
          return false;
        }
      };
      if (await tick()) {
        poll.current = setInterval(() => { void tick(); }, 700);
      }
    } catch (e: any) {
      setErr(String(e?.message || e));
      setJob((prev) => (prev ? { ...prev, status: "error", message: String(e?.message || e) } : prev));
    }
  };

  const pct = Math.max(job?.status === "error" ? 100 : 4, Math.min(100, Number(job?.percent) || 0));
  const running = job?.status === "running";
  const done = job?.status === "done";
  const failed = job?.status === "error";
  const isPdf = (job?.format || "") === "pdf";

  const openFile = () => {
    if (!job?.id) return;
    const a = document.createElement("a");
    a.href = api.reportExportFileUrl(projectId, job.id);
    a.download = job.filename || "";
    a.target = "_blank";
    a.rel = "noopener";
    a.click();
  };

  return (
    <>
      <div className={`report-export ${extraClass || ""}`} ref={wrapRef}>
        <button
          className="btn-export-outline"
          type="button"
          disabled={disabled}
          aria-haspopup="menu"
          aria-expanded={menu}
          onClick={() => setMenu((v) => !v)}
        >
          <DownloadIcon />
          <span>报告导出</span>
          <ChevronIcon />
        </button>
        {menu && (
          <div className="report-export-menu" role="menu">
            <button type="button" role="menuitem" onClick={() => start("html")}>导出 HTML</button>
            <button type="button" role="menuitem" onClick={() => start("pdf")}>导出 PDF</button>
          </div>
        )}
      </div>
      {open && (
        <Modal title="生成交付报告" onClose={() => { if (!running) { setOpen(false); stopPoll(); } }}>
          <p className="muted" style={{ fontSize: 13, marginTop: 0 }}>
            {isPdf
              ? "由专职导出 Pi 撰写封面、摘要与漏洞卡片，再套入母版并渲染 PDF。与猎洞、二次验证、自进化不是同一条会话。请勿关闭。"
              : "由专职导出 Pi 撰写封面、摘要与漏洞卡片，再套入母版后下载。与猎洞、二次验证、自进化不是同一条会话。请勿关闭。"}
          </p>
          <div className={`import-progress${failed ? " is-error" : ""}`} role="status" aria-live="polite">
            <div className="import-progress-head">
              <strong>{failed ? "生成失败" : done ? "报告已就绪" : "正在生成"}</strong>
              <span className="mono">{Math.round(pct)}%</span>
            </div>
            <div className="import-progress-track">
              <div
                className={`import-progress-fill${running && pct < 8 ? " is-indeterminate" : ""}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <div className="import-progress-meta muted">
              {err || job?.error || job?.message || "请稍候…"}
              {done && job?.claude ? " · 专职导出 Pi 已撰写" : ""}
              {done && job?.claude_error ? ` · 导出 Pi 未完成：${job.claude_error}` : ""}
            </div>
          </div>
          <div className="row" style={{ gap: 8, marginTop: 16 }}>
            {done && (
              <button className="btn btn-primary" type="button" onClick={openFile}>
                下载 {isPdf ? "PDF" : "HTML"}
              </button>
            )}
            <button
              className="btn btn-secondary"
              type="button"
              disabled={running}
              onClick={() => { setOpen(false); stopPoll(); }}
            >
              {running ? "生成中…" : "关闭"}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
