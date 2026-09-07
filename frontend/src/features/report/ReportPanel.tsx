import { useEffect, useState } from "react";
import { api } from "../../api";
import { ReportExportControls } from "./ExportReport";

export function ReportPanel({ projectId }: { projectId: string }) {
  const [runs, setRuns] = useState<any[]>([]);
  useEffect(() => {
    api.runs(projectId).then(setRuns).catch(() => {});
  }, [projectId]);

  return (
    <div className="scroll-y" style={{ maxHeight: 520 }}>
      <div className="card-cream" style={{ padding: 16, marginBottom: 14 }}>
        <b style={{ fontSize: 15 }}>导出渗透报告</b>
        <p className="muted" style={{ fontSize: 13, margin: "6px 0 12px" }}>
          按交付母版导出 HTML / PDF（封面、执行摘要、路径板、漏洞卡片 ①简介 / ②利用 / ③修复）。
        </p>
        <ReportExportControls projectId={projectId} />
      </div>

      <b style={{ fontSize: 14 }}>运行历史</b>
      {runs.length === 0 && <p className="muted" style={{ fontSize: 13 }}>暂无运行记录。</p>}
      {runs.map((r) => (
        <div key={r.id} className="card-cream" style={{ padding: 12, marginTop: 8 }}>
          <div className="spread">
            <span className="badge badge-pill">{r.status}</span>
            {r.goal_reached ? <span className="badge badge-coral">GETSHELL</span> : null}
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>{r.turns} 轮 · {r.summary ? r.summary.slice(0, 160) : "—"}</div>
        </div>
      ))}
    </div>
  );
}
