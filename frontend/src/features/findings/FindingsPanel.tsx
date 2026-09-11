import { useMemo, useState } from "react";
import type { Finding, GraphNode, RTEvent } from "../../types";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge, RedteamRatingBadge } from "../../components/Badge";
import { FindingReportModal } from "./FindingReportModal";
import { displayFindingSeverity, isPlaceholderGraphNode, scrubCandidateRceLabel } from "../../theme";

export const NODE_VULN_ID_PREFIX = "node-vuln:";

const SEV_RANK: Record<string, number> = {
  critical: 4, high: 3, medium: 2, low: 1, info: 0,
};

/** 漏洞列表：非 rejected 的低/中/高危/严重都展示，按危害从高到低。 */
export function filterVisibleFindings(findings: Finding[], _opts?: { src?: boolean }): Finding[] {
  return findings.filter((f) => {
    const vs = (f.verification_status || "verified").toLowerCase();
    return vs !== "rejected";
  });
}

export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const ra = SEV_RANK[displayFindingSeverity(a)] ?? 0;
    const rb = SEV_RANK[displayFindingSeverity(b)] ?? 0;
    if (rb !== ra) return rb - ra;
    return (b.created_at || 0) - (a.created_at || 0);
  });
}

export function findingFromVulnNode(n: GraphNode): Finding {
  const detail = typeof n.detail === "string" ? n.detail : undefined;
  const sev = (n.severity || "info").toLowerCase();
  return {
    id: `${NODE_VULN_ID_PREFIX}${n.key}`,
    node_key: n.key,
    severity: n.severity || "info",
    category: (n.tags && n.tags.find((t) => t && !t.startsWith("host:"))) || "vuln",
    title: scrubCandidateRceLabel(n.title) || n.title || n.key,
    description: detail,
    critical: n.is_rce || sev === "critical",
    created_at: n.created_at || 0,
    verification_status: "pending",
  };
}

export function collectVulns(findings: Finding[], nodes: GraphNode[] = [], opts?: { src?: boolean }): Finding[] {
  const fromFindings = filterVisibleFindings(findings, opts);
  const linked = new Set(fromFindings.map((f) => f.node_key).filter(Boolean) as string[]);
  const extras = nodes
    .filter((n) => n.type === "vuln" && n.key && !linked.has(n.key) && !isPlaceholderGraphNode(n))
    .map(findingFromVulnNode);
  return sortFindingsBySeverity([...fromFindings, ...extras]);
}

export function isNodeOnlyVuln(f: Finding): boolean {
  return String(f.id || "").startsWith(NODE_VULN_ID_PREFIX);
}

export type FindingReviewState = {
  running: boolean;
  count: number;
  ids: string[];
  titles: string[];
};

export function latestFindingReview(events: RTEvent[]): FindingReviewState {
  let running = false;
  let count = 0;
  let ids: string[] = [];
  let titles: string[] = [];
  for (const ev of events) {
    const p = ev.payload || {};
    if (ev.type === "finding_review") {
      running = String(p.status || "") === "running";
      count = Number(p.count || 0) || count;
      if (Array.isArray(p.ids)) ids = p.ids.map(String).filter(Boolean);
      if (Array.isArray(p.titles)) titles = p.titles.map(String).filter(Boolean);
      continue;
    }
    if (String(p.role || "") === "finding-review") {
      running = true;
      continue;
    }
    const msg = String(p.message || "");
    if (ev.type === "log" && msg.includes("专职二次验证")) {
      const m = msg.match(/专职二次验证\s*(\d+)/);
      if (m) count = Number(m[1]) || count;
      running = true;
    }
  }
  return { running, count, ids, titles };
}

export function FindingReviewBanner({ review }: { review: FindingReviewState }) {
  if (!review.running) return null;
  return (
    <div className="finding-review-banner" role="status">
      <span className="finding-review-dot" />
      <div>
        <b>正在二次验证与红队评级</b>
        <span className="muted"> · 专职 Pi 复核 {review.count || review.titles.length} 条已发现漏洞</span>
        {review.titles.length > 0 && (
          <ul className="finding-review-titles">
            {review.titles.slice(0, 6).map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function FindingsPanel({
  projectId, findings, nodes = [], onSelectNode, src = false, review,
}: {
  projectId: string;
  findings: Finding[];
  nodes?: GraphNode[];
  onSelectNode?: (n: GraphNode) => void;
  src?: boolean;
  review?: FindingReviewState;
}) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const visible = useMemo(() => collectVulns(findings, nodes, { src }), [findings, nodes, src]);
  const reviewingIds = new Set(review?.running ? review.ids : []);
  const reviewingAll = !!review?.running && reviewingIds.size === 0;

  if (!visible.length) {
    return (
      <>
        {review ? <FindingReviewBanner review={review} /> : null}
        <p className="muted" style={{ fontSize: 14 }}>
          暂无漏洞。
        </p>
      </>
    );
  }

  const onClick = (f: Finding) => {
    if (isNodeOnlyVuln(f)) {
      const node = nodes.find((n) => n.key === f.node_key);
      if (node && onSelectNode) onSelectNode(node);
      return;
    }
    setSelected(f);
  };

  return (
    <>
      {review ? <FindingReviewBanner review={review} /> : null}
      <div className="scroll-y" style={{ maxHeight: 520 }}>
        {visible.map((f) => {
          const reviewing = !f.secondary_verified && (reviewingAll || reviewingIds.has(String(f.id || "")));
          return (
            <div
              key={f.id}
              className="card-cream"
              style={{ padding: 14, marginBottom: 10, cursor: "pointer" }}
              onClick={() => onClick(f)}
            >
              <div className="spread">
                <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                  <SeverityBadge severity={displayFindingSeverity(f)} />
                  <VerifyBadge status={f.verification_status} />
                  <SecondaryVerifyBadge done={!!f.secondary_verified} reviewing={reviewing} />
                  <RedteamRatingBadge rating={f.redteam_rating} reviewing={reviewing} />
                  <b style={{ fontSize: 14 }}>{scrubCandidateRceLabel(f.title) || f.title}</b>
                </div>
                <span className="muted" style={{ fontSize: 12 }}>{f.category}</span>
              </div>
              <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>
                {isNodeOnlyVuln(f)
                  ? "图上漏洞节点 · 点击查看节点详情"
                  : reviewing
                    ? "专职 Pi 正在二次验证并做红队评级"
                    : "点击查看完整漏洞报告 · MD 下载"}
              </p>
            </div>
          );
        })}
      </div>
      {selected && !isNodeOnlyVuln(selected) && (
        <FindingReportModal
          projectId={projectId}
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </>
  );
}
