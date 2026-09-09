import { useMemo, useState } from "react";
import type { Finding, GraphNode } from "../../types";
import { SeverityBadge, VerifyBadge, SecondaryVerifyBadge } from "../../components/Badge";
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

export function isNodeOnlyVuln(f: Finding): boolean {
  return String(f.id || "").startsWith(NODE_VULN_ID_PREFIX);
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

export function FindingsPanel({
  projectId, findings, nodes = [], onSelectNode, src = false,
}: {
  projectId: string;
  findings: Finding[];
  nodes?: GraphNode[];
  onSelectNode?: (n: GraphNode) => void;
  src?: boolean;
}) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const visible = useMemo(() => collectVulns(findings, nodes, { src }), [findings, nodes, src]);

  if (!visible.length) {
    return (
      <p className="muted" style={{ fontSize: 14 }}>
        暂无漏洞。
      </p>
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
      <div className="scroll-y" style={{ maxHeight: 520 }}>
        {visible.map((f) => (
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
                  <SecondaryVerifyBadge done={!!f.secondary_verified} />
                  <b style={{ fontSize: 14 }}>{scrubCandidateRceLabel(f.title) || f.title}</b>
                </div>
                <span className="muted" style={{ fontSize: 12 }}>{f.category}</span>
              </div>
              <p className="muted" style={{ fontSize: 12, margin: "8px 0 0" }}>
                {isNodeOnlyVuln(f)
                  ? "图上漏洞节点 · 点击查看节点详情"
                  : "点击查看完整漏洞报告 · MD 下载"}
              </p>
            </div>
        ))}
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
