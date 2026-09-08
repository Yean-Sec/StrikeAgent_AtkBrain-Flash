import { useEffect, useState } from "react";
import { api } from "../../api";
import type { Finding, FindingDetail } from "../../types";
import { Modal } from "../../components/Modal";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge } from "../../components/Badge";
import { displayFindingSeverity, scrubCandidateRceLabel } from "../../theme";

function fmtTs(ts?: number) {
  if (!ts) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

export function FindingReportModal({
  projectId, finding, onClose,
}: { projectId: string; finding: Finding; onClose: () => void }) {
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState<"curl" | "python">("curl");

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

  return (
    <Modal title={title} onClose={onClose} wide>
      <div className="finding-report">
        <div className="row" style={{ gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <SeverityBadge severity={shownSev} />
          <VerifyBadge status={finding.verification_status || detail?.verification_status} />
          <SecondaryVerifyBadge done={!!(finding.secondary_verified || detail?.secondary_verified)} />
          <span className="muted" style={{ fontSize: 12 }}>{finding.category}</span>
          {finding.cvss != null && <span className="muted" style={{ fontSize: 12 }}>CVSS {finding.cvss}</span>}
          <div style={{ flex: 1 }} />
          <button className="btn btn-primary btn-sm" onClick={downloadMd}>下载 Markdown</button>
        </div>

        {err && <p style={{ color: "var(--error)", fontSize: 13 }}>{err}</p>}
        {!d && !err && <p className="muted" style={{ fontSize: 13 }}>加载完整报告…</p>}

        {d && (
          <>
            <div className="section meta-grid">
              <span>漏洞 ID</span><span className="kbd">{d.id}</span>
              <span>关联节点</span><span className="kbd">{d.node_key || "-"}{d.related_node?.title ? ` · ${d.related_node.title}` : ""}</span>
              <span>验证时间</span><span>{fmtTs(d.verified_at || d.created_at)}</span>
              <span>创建时间</span><span>{fmtTs(d.created_at)}</span>
            </div>

            {d.mechanism && (
              <>
                <h3>漏洞原理</h3>
                <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>{d.mechanism}</p>
              </>
            )}

            <h3>漏洞说明</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.root_cause || d.description || "未采集"}
            </p>

            <h3>危害与影响</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.impact_detail || d.impact || "以证据与关联节点为准。"}
            </p>

            {d.affected_scope && (
              <>
                <h3>影响资产与攻击入口</h3>
                <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>{d.affected_scope}</p>
              </>
            )}

            {d.param_analysis && (
              <>
                <h3>参数与可控点</h3>
                <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>{d.param_analysis}</p>
              </>
            )}
            {d.http_raw && (
              <>
                <h3>原始 HTTP 请求</h3>
                <pre style={{ maxHeight: 280 }}>{d.http_raw}</pre>
              </>
            )}
            {(d.expected_result || (d.expected_signals && d.expected_signals.length > 0)) && (
              <>
                <h3>复现成功判定</h3>
                {d.expected_result && (
                  <p style={{ fontSize: 13, whiteSpace: "pre-wrap" }}>{d.expected_result}</p>
                )}
                {d.expected_signals && d.expected_signals.length > 0 && (
                  <ul>{d.expected_signals.map((s) => <li key={s}>{s}</li>)}</ul>
                )}
              </>
            )}

            <h3>二次验证与红队评级</h3>
            <p style={{ fontSize: 13, margin: 0, whiteSpace: "pre-wrap" }}>
              {d.secondary_review || d.redteam_rating_rationale || "尚未做二次验证与红队评级。二者须同一轮完成，并在本节写清过程与理由。"}
            </p>

            <div className="finding-guidance-grid">
              <section><h3>攻击前置条件</h3><p>{d.prerequisites || "见证据与关联节点。"}</p></section>
              <section><h3>修复建议</h3><p>{d.remediation || "修复根因后请按相同路径回归验证。"}</p></section>
              <section><h3>风险说明</h3><p>{d.cvss_explanation || (d.cvss != null ? `CVSS ${d.cvss}` : "未提供 CVSS。")}</p></section>
            </div>

            <h3>证明材料</h3>
            <div className="section" style={{ padding: 12, background: "var(--surface, #f6f4ef)", borderRadius: 8, fontSize: 13 }}>
              <div className="meta-grid">
                <span>状态</span><span><b><VerifyBadge status={d.verification_status} /></b></span>
                {d.proof_type && <><span>证明类型</span><span className="kbd">{d.proof_type}</span></>}
                {d.proof_canary && <><span>Canary</span><span className="kbd">{d.proof_canary}</span></>}
                {d.proof_url && (
                  <>
                    <span>证明 URL</span>
                    <span style={{ wordBreak: "break-all" }}>
                      <a href={d.proof_url} target="_blank" rel="noreferrer">{d.proof_url}</a>
                    </span>
                  </>
                )}
              </div>
              {d.proof_detail && <pre>{d.proof_detail}</pre>}
              {!d.proof_detail && !d.proof_canary && !d.proof_url && (
                <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>无独立 proof 字段；见手动验证步骤与证据。</p>
              )}
            </div>

            <h3>手动复现</h3>
            <ol>
              {(d.manual_steps || []).map((s, i) => (
                <li key={i}>{s.replace(/^\d+\.\s*/, "")}</li>
              ))}
            </ol>

            <h3>证据</h3>
            {d.evidence ? <pre style={{ maxHeight: 280 }}>{d.evidence}</pre> : <p className="muted" style={{ fontSize: 12 }}>无 evidence</p>}

            <h3>PoC</h3>
            <div className="row" style={{ gap: 6, marginBottom: 6 }}>
              <button className={`btn btn-sm ${tab === "curl" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTab("curl")}>curl</button>
              <button className={`btn btn-sm ${tab === "python" ? "btn-primary" : "btn-secondary"}`} onClick={() => setTab("python")}>python</button>
              {poc && (
                <button className="btn btn-sm btn-ghost" onClick={() => navigator.clipboard.writeText(poc[tab] || "")}>复制</button>
              )}
            </div>
            {poc ? <pre style={{ maxHeight: 280 }}>{poc[tab]}</pre> : <p className="muted" style={{ fontSize: 12 }}>无 PoC</p>}

            {d.related_node && (
              <>
                <h3>关联攻击图节点</h3>
                <p style={{ fontSize: 13, margin: 0 }}>
                  <span className="kbd">{d.related_node.key}</span>
                  {" "}[{d.related_node.type}/{d.related_node.severity}] {d.related_node.title}
                  {d.related_node.risk_score != null ? ` (risk=${d.related_node.risk_score})` : ""}
                </p>
                {(d.node_detail_unique || (d.node_detail_unique === undefined && d.related_node.detail)) ? (
                  <pre>{d.node_detail_unique || d.related_node.detail}</pre>
                ) : null}
              </>
            )}

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
