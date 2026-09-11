import { useEffect, useState } from "react";
import { api } from "../../api";
import type { Finding, FindingDetail } from "../../types";
import { Modal } from "../../components/Modal";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge } from "../../components/Badge";
import { displayFindingSeverity, scrubCandidateRceLabel } from "../../theme";

function SectionBody({ text, pending }: { text?: string; pending?: boolean }) {
  const body = (text || "").trim();
  if (!body) {
    return (
      <p className="muted" style={{ fontSize: 13, margin: 0 }}>
        {pending
          ? "专职复核 Pi 完成二次验证与红队评级后撰写本段，不使用模板套话。"
          : "未采集"}
      </p>
    );
  }
  return (
    <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap", lineHeight: 1.65 }}>
      {body}
    </p>
  );
}

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
  const pending = !!(d?.report_pending ?? (!d && !finding.secondary_verified));
  const summary = d?.report_summary || d?.description || finding.description || "";
  const impact = d?.report_impact || d?.impact_detail || d?.impact || "";
  const rating = d?.report_rating || d?.secondary_review || d?.redteam_rating_rationale || "";
  const repro = d?.report_repro || d?.manual_repro || "";
  const fix = d?.report_fix || d?.remediation || "";

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
        {!d && !err && (
          <p className="muted" style={{ fontSize: 13 }}>
            {finding.secondary_verified
              ? "专职 Pi 正在撰写漏洞页…"
              : "加载完整报告…二次验证未完成时由专职复核 Pi 验证、评级后再撰写。"}
          </p>
        )}

        {d && (
          <>
            {pending && (
              <p className="muted" style={{ fontSize: 12, margin: "0 0 12px" }}>
                本页由专职复核 Pi 在二次验证与红队评级之后撰写。尚未完成本条时不套用模板。
              </p>
            )}

            <h3>漏洞简介</h3>
            <SectionBody text={summary} pending={pending && !summary} />

            <h3>危害</h3>
            <SectionBody text={impact} pending={pending} />

            <h3>红队评级</h3>
            <SectionBody text={rating} pending={pending} />

            <h3>手动复现</h3>
            <SectionBody text={repro} pending={pending} />
            {curl ? <pre style={{ maxHeight: 280 }}>{curl}</pre> : null}

            <h3>修复方式</h3>
            <SectionBody text={fix} pending={pending} />

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
