import { useMemo, useState } from "react";
import type { Graph, GraphNode } from "../../types";
import { graphNodeTypeLabel, nodeTypeLabel, scrubCandidateRceLabel } from "../../theme";

export function AllNodesPanel({ graph, onSelect }: { graph: Graph; onSelect: (node: GraphNode) => void }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const types = useMemo(() => [...new Set(graph.nodes.map((n) => n.type))].sort(), [graph.nodes]);
  const nodes = graph.nodes.filter((n) => (type === "all" || n.type === type) && (!query || `${n.title} ${n.key} ${(n.tags || []).join(" ")}`.toLowerCase().includes(query.toLowerCase())));
  return <div className="nodes-panel">
    <div className="nodes-filter"><input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索节点、主机或标签" /><select className="select" value={type} onChange={(e) => setType(e.target.value)}><option value="all">全部节点</option>{types.map((value) => <option key={value} value={value}>{nodeTypeLabel[value] || value}</option>)}</select></div>
    <p className="muted" style={{ fontSize: 12, margin: "0 0 8px" }}>显示 {nodes.length}/{graph.nodes.length} 个节点</p>
    <div className="nodes-list">{nodes.map((node) => <button key={node.key} className="node-row" onClick={() => onSelect(node)}><span className={`node-type-dot n-${node.type}`} /><span><b>{scrubCandidateRceLabel(node.title) || node.title}</b><small>{node.key} · risk {node.risk_score}</small></span><em>{graphNodeTypeLabel(node)}</em></button>)}</div>
  </div>;
}
