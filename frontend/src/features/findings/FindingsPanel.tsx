import { useMemo, useState } from "react";
import type { Finding, GraphNode, RTEvent } from "../../types";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge, RedteamRatingBadge } from "../../components/Badge";
import { FindingReportModal } from "./FindingReportModal";
import { displayFindingSeverity, isPlaceholderGraphNode, scrubCandidateRceLabel } from "../../theme";
import { useT } from "../../i18n";

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

export function collectVulns(findings: Finding[], nodes: GraphNode[] = [], opts?: { src?: boolean; linkedNodeKeys?: string[] }): Finding[] {
  const fromFindings = filterVisibleFindings(findings, opts);
  const linked = new Set<string>([
    ...(fromFindings.map((f) => f.node_key).filter(Boolean) as string[]),
    ...(opts?.linkedNodeKeys || []),
  ]);
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

function findingNeedsReview(f: Finding): boolean {
  if (isNodeOnlyVuln(f)) return false;
  const failed = (f.verification_status || "").toLowerCase() === "excluded";
  const needRate = !String(f.redteam_rating || "").trim();
  if (failed) return needRate;
  return !f.secondary_verified || needRate;
}

/** 事件里的名单会比写库晚。已经二次验证并有红队评级的，不再算进「正在」。 */
export function liveReviewQueue(review: FindingReviewState, findings: Finding[]): Finding[] {
  if (!review.running || !findings.length) return [];
  const pending = findings.filter(findingNeedsReview);
  if (!review.ids.length) return pending;
  const ids = new Set(review.ids.map(String));
  return pending.filter((f) => ids.has(String(f.id || "")));
}

export function latestFindingReview(events: RTEvent[]): FindingReviewState {
  let running = false;
  let count = 0;
  let ids: string[] = [];
  let titles: string[] = [];
  for (const ev of events) {
    if (ev.type !== "finding_review") continue;
    const p = ev.payload || {};
    running = String(p.status || "") === "running";
    if (running) {
      count = Number(p.count || 0) || count;
      if (Array.isArray(p.ids)) ids = p.ids.map(String).filter(Boolean);
      if (Array.isArray(p.titles)) titles = p.titles.map(String).filter(Boolean);
    } else {
      count = 0;
      ids = [];
      titles = [];
    }
  }
  return { running, count, ids, titles };
}

export function reviewIsLive(review: FindingReviewState, findings: Finding[] = []): boolean {
  if (!review.running) return false;
  if (!findings.length) return review.ids.length > 0 || review.titles.length > 0 || review.count > 0;
  return liveReviewQueue(review, findings).length > 0;
}

export function FindingReviewBanner({ review, findings = [] }: { review: FindingReviewState; findings?: Finding[] }) {
  const { t } = useT();
  if (!reviewIsLive(review, findings)) return null;
  const open = liveReviewQueue(review, findings);
  const titles = open.length
    ? open.map((f) => String(f.title || "")).filter(Boolean)
    : review.titles;
  const n = open.length || review.count || titles.length;
  return (
    <div className="finding-review-banner" role="status">
      <span className="finding-review-dot" />
      <div>
        <b>{t("findings.reviewing")}</b>
        <span className="muted">{t("findings.reviewN", { n })}</span>
        {titles.length > 0 && (
          <ul className="finding-review-titles">
            {titles.slice(0, 6).map((title) => (
              <li key={title}>{title}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function FindingsPanel({
  projectId, findings, nodes = [], linkedNodeKeys = [], onSelectNode, src = false, review,
}: {
  projectId: string;
  findings: Finding[];
  nodes?: GraphNode[];
  linkedNodeKeys?: string[];
  onSelectNode?: (n: GraphNode) => void;
  src?: boolean;
  review?: FindingReviewState;
}) {
  const { t } = useT();
  const [selected, setSelected] = useState<Finding | null>(null);
  const visible = useMemo(
    () => collectVulns(findings, nodes, { src, linkedNodeKeys }),
    [findings, nodes, src, linkedNodeKeys],
  );
  const reviewingIds = useMemo(() => {
    if (!review) return new Set<string>();
    return new Set(liveReviewQueue(review, visible).map((f) => String(f.id || "")));
  }, [review, visible]);

  if (!visible.length) {
    return (
      <>
        {review ? <FindingReviewBanner review={review} findings={visible} /> : null}
        <p className="muted" style={{ fontSize: 14 }}>
          {t("findings.empty")}
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
      {review ? <FindingReviewBanner review={review} findings={visible} /> : null}
      <div className="scroll-y" style={{ maxHeight: 520 }}>
        {visible.map((f) => {
          const excluded = (f.verification_status || "").toLowerCase() === "excluded";
          const inQueue = !isNodeOnlyVuln(f);
          const needSec = inQueue && !excluded && !f.secondary_verified;
          const needRate = inQueue && !String(f.redteam_rating || "").trim();
          const inReview = reviewingIds.has(String(f.id || ""));
          const secReviewing = needSec && inReview;
          const rateReviewing = needRate && inReview;
          const reviewing = secReviewing || rateReviewing;
          const reviewTip = secReviewing && rateReviewing
            ? t("findings.reviewTip")
            : secReviewing
              ? t("findings.reviewTipSec")
              : t("findings.reviewTipRate");
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
                  {!excluded && (
                    <SecondaryVerifyBadge done={!!f.secondary_verified} reviewing={secReviewing} />
                  )}
                  <RedteamRatingBadge rating={f.redteam_rating} score={f.cvss} reviewing={rateReviewing} />
                  <b style={{ fontSize: 14 }}>{scrubCandidateRceLabel(f.title) || f.title}</b>
                </div>
                <span className="muted" style={{ fontSize: 12 }}>{f.category}</span>
              </div>
              <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>
                {isNodeOnlyVuln(f)
                  ? t("findings.nodeTip")
                  : reviewing
                    ? reviewTip
                    : t("findings.openTip")}
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
