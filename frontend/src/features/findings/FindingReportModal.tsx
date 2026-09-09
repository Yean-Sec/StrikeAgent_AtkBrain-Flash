import { useEffect, useState } from "react";
import { api } from "../../api";
import type { Finding, FindingDetail } from "../../types";
import { Modal } from "../../components/Modal";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge } from "../../components/Badge";
import { displayFindingSeverity, scrubCandidateRceLabel } from "../../theme";

export function FindingReportModal({
  projectId, finding, onClose,
}: { projectId: string; finding: Finding; onClose: () => void }) {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    let cancelled = false;
    setErr("");
    setDetail(null);
    api.getFinding(projectId, finding.id)
      .then((d) => { if (!cancelled) setDetail(d); })
      .catch((e) => { if (!cancelled) setErr(String(e?.message || e)); });
    return () => { cancelled = true; };
  }, [projectId, finding.id]);

  const downloadMd = () => {
    window.open(api.findingReportUrl(projectId, finding.id), "_blank");
  };

  const d = detail;
  const poc = d?.poc;
  const shownSev = displayFindingSeverity(d || finding);
  const title = `[${shownSev.toUpperCase()}] ${scrubCandidateRceLabel(finding.title) || finding.title}`;
  const curl = (poc?.curl || d?.poc_curl || "").trim();

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="finding-report">
        <div className="row" style={{ gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <SeverityBadge severity={shownSev} />
          <VerifyBadge status={finding.verification_status || detail?.verification_status} />
          <SecondaryVerifyBadge done={!!(finding.secondary_verified || detail?.secondary_verified)} />
          <span className="muted" style={{ fontSize: 12 }}>{finding.category}</span>
          <div style={{ flex: 1 }} />
          <button className="btn btn-primary btn-sm" onClick={downloadMd}>下载 Markdown</button>
        </div>

        {err && <p style={{ color: "var(--error)", fontSize: 13 }}>{err}</p>}
        {!d && !err && <p className="muted" style={{ fontSize: 13 }}>加载完整报告…</p>}

        {d && (
          <>
            <h3>漏洞简介</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.description || "未采集"}
            </p>

            <h3>危害</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.impact_detail || d.impact || "以证据为准。"}
            </p>

            <h3>手动复现</h3>
            <ol>
              {(d.manual_steps || []).map((s, i) => (
                <li key={i}>{s.replace(/^\d+\.\s*/, "")}</li>
              ))}
            </ol>
            {curl ? (
              <pre style={{ maxHeight: 280 }}>{curl}</pre>
            ) : (
              !d.manual_steps?.length && <p className="muted" style={{ fontSize: 12 }}>未采集可复现步骤。</p>
            )}

            <h3>红队评级</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.secondary_review || d.redteam_rating_rationale || "未评级。"}
            </p>

            <div className="row" style={{ gap: 8, marginTop: 20, borderTop: "1px solid var(--hair)", paddingTop: 14 }}>
              <button className="btn btn-primary" onClick={downloadMd}>下载本漏洞 Markdown 报告</button>
              <button className="btn btn-secondary" onClick={onClose}>关闭</button>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
