import type { Graph, GraphNode } from "../../types";
import { SeverityBadge } from "../../components/Badge";
import { displayFindingSeverity, formatNodeDetail, graphNodeDisplaySeverity, graphNodeDisplayType, graphNodeTypeLabel, nodeTypeColor, showsShellStar, scrubCandidateRceLabel } from "../../theme";

function formatUnix(ts?: number) {
  if (!ts) return "";
  const d = new Date(ts > 1e12 ? ts : ts * 1000);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

export function NodeDetail({ node, graph }: { node: GraphNode | null; graph: Graph }) {
  if (!node) return <p className="muted" style={{ fontSize: 14 }}>点击攻击图中的节点查看详情。</p>;
  const inbound = graph.edges.filter((e) => e.to === node.key);
  const outbound = graph.edges.filter((e) => e.from === node.key);
  const related = graph.findings.filter((f) => f.node_key === node.key);
  const detail = formatNodeDetail(node.detail);
  return (
    <div className="scroll-y" style={{ maxHeight: 520 }}>
      <div className="row" style={{ gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <span className="badge badge-pill" style={{ background: nodeTypeColor[graphNodeDisplayType(node)], color: "#fff" }}>
          {graphNodeTypeLabel(node)}
        </span>
        <SeverityBadge severity={graphNodeDisplaySeverity(node)} />
        {node.status && <span className="badge badge-pill">{node.status}</span>}
        {showsShellStar(node) && <span className="badge badge-coral">GETSHELL</span>}
      </div>
      <h3 style={{ marginBottom: 4 }}>{scrubCandidateRceLabel(node.title) || node.title}</h3>
      <div className="mono muted" style={{ fontSize: 12, marginBottom: 6, wordBreak: "break-all" }}>{node.key}</div>
      <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
        风险 {node.risk_score}
        {formatUnix(node.created_at) ? ` · 创建 ${formatUnix(node.created_at)}` : ""}
        {formatUnix(node.updated_at) ? ` · 更新 ${formatUnix(node.updated_at)}` : ""}
      </div>
      {node.tags?.length > 0 && (
        <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 10 }}>
          {node.tags.map((t) => <span key={t} className="badge badge-pill" style={{ fontSize: 11 }}>{t}</span>)}
        </div>
      )}
      {detail && (
        <pre style={{ background: "var(--surface-card)", padding: 10, borderRadius: 8, overflow: "auto", fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
          {detail}
        </pre>
      )}
      {(inbound.length > 0 || outbound.length > 0) && (
        <div style={{ marginTop: 12 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>攻击链关系</div>
          {inbound.map((e) => (
            <div key={e.id} style={{ fontSize: 13, wordBreak: "break-all" }}>
              ← <span className="kbd">{e.from}</span> <span className="muted">{e.relation}{e.rationale ? ` · ${e.rationale}` : ""} (w={e.weight})</span>
            </div>
          ))}
          {outbound.map((e) => (
            <div key={e.id} style={{ fontSize: 13, wordBreak: "break-all" }}>
              → <span className="kbd">{e.to}</span> <span className="muted">{e.relation}{e.rationale ? ` · ${e.rationale}` : ""} (w={e.weight})</span>
            </div>
          ))}
        </div>
      )}
      {related.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>关联发现</div>
          {related.map((f) => (
            <div key={f.id} style={{ fontSize: 13 }}>
              <SeverityBadge severity={displayFindingSeverity(f)} /> {scrubCandidateRceLabel(f.title) || f.title}
              {f.description ? <div className="muted" style={{ fontSize: 12, whiteSpace: "pre-wrap" }}>{f.description}</div> : null}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
