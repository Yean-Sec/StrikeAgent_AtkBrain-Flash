import { useMemo } from "react";
import type { Finding, Graph, GraphNode } from "../../types";
import { SeverityBadge } from "../../components/Badge";
import { nodeTypeColor } from "../../theme";

/** 从攻击图提取已发现的服务节点（可选附带指纹类 info） */
export function filterDiscoveredServices(nodes: GraphNode[]): GraphNode[] {
  return nodes
    .filter((n) => n.type === "service")
    .sort((a, b) => {
      const pa = portHint(a.key);
      const pb = portHint(b.key);
      if (pa !== pb) return pa - pb;
      return (a.title || a.key).localeCompare(b.title || b.key, "zh");
    });
}

function portHint(key: string): number {
  // svc:80/http · svc:host:8080/http · svc:192.168.1.1:443/https
  const m = key.match(/(?::|\/)(\d{1,5})(?:\/|$)/) || key.match(/^svc:(\d{1,5})\b/);
  return m ? Number(m[1]) : 99999;
}

function detailText(detail: unknown): string {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  try {
    return JSON.stringify(detail);
  } catch {
    return String(detail);
  }
}

export function ServicesPanel({
  graph,
  onSelect,
}: {
  graph: Graph;
  onSelect: (n: GraphNode) => void;
}) {
  const services = useMemo(() => filterDiscoveredServices(graph.nodes), [graph.nodes]);
  const findingsByKey = useMemo(() => {
    const m = new Map<string, Finding[]>();
    for (const f of graph.findings || []) {
      if (!f.node_key) continue;
      const arr = m.get(f.node_key) || [];
      arr.push(f);
      m.set(f.node_key, arr);
    }
    return m;
  }, [graph.findings]);

  if (!services.length) {
    return (
      <p className="muted" style={{ fontSize: 14, padding: 4 }}>
        尚未发现服务节点。Agent 识别到开放端口/协议后会出现在此（攻击图中的 service）。
      </p>
    );
  }

  return (
    <div className="scroll-y" style={{ maxHeight: 520 }}>
      <div className="spread" style={{ marginBottom: 10, padding: "0 2px" }}>
        <span className="muted" style={{ fontSize: 12 }}>开放端口 / 协议 / 指纹</span>
        <span className="badge">{services.length} 个服务</span>
      </div>
      {services.map((n) => {
        const related = findingsByKey.get(n.key) || [];
        const snippet = detailText(n.detail).replace(/\s+/g, " ").trim().slice(0, 140);
        const tags = n.tags || [];
        const tagSet = new Set(tags.map((t) => t.toLowerCase()));
        const uaSplit = tagSet.has("ua_split") || tagSet.has("ua-split");
        const uaMobile = tagSet.has("ua:mobile") || tagSet.has("ua-mobile") || tagSet.has("mobile");
        const uaDesktop = tagSet.has("ua:desktop") || tagSet.has("ua-desktop") || tagSet.has("desktop");
        return (
          <div
            key={n.id || n.key}
            className="card-cream"
            style={{
              padding: 14,
              marginBottom: 10,
              cursor: "pointer",
            }}
            onClick={() => onSelect(n)}
          >
            <div className="spread" style={{ gap: 8, alignItems: "flex-start" }}>
              <div className="row" style={{ gap: 8, flexWrap: "wrap", flex: 1 }}>
                <span
                  className="badge badge-pill"
                  style={{ background: nodeTypeColor.service || "#5b8def", color: "#fff", fontSize: 11 }}
                >
                  service
                </span>
                {uaSplit && (
                  <span className="badge badge-pill" style={{ fontSize: 11, background: "rgba(212,160,23,0.2)", color: "#8a6a00" }}>
                    UA分流
                  </span>
                )}
                {uaMobile && (
                  <span className="badge badge-pill" style={{ fontSize: 11, background: "rgba(91,141,239,0.18)", color: "#2a5bb8" }}>
                    移动端
                  </span>
                )}
                {uaDesktop && !uaMobile && (
                  <span className="badge badge-pill" style={{ fontSize: 11, background: "rgba(0,0,0,0.06)", color: "var(--muted)" }}>
                    PC端
                  </span>
                )}
                {n.status && (
                  <span className="kbd" style={{ fontSize: 11 }}>{n.status}</span>
                )}
                <SeverityBadge severity={n.severity || "info"} />
                <b style={{ fontSize: 14 }}>{n.title || n.key}</b>
              </div>
              {related.length > 0 && (
                <span className="muted" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
                  {related.length} 关联发现
                </span>
              )}
            </div>
            <div className="mono muted" style={{ fontSize: 12, marginTop: 6 }}>{n.key}</div>
            {n.tags?.length > 0 && (
              <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 8 }}>
                {n.tags.slice(0, 8).map((t) => (
                  <span key={t} className="badge badge-pill" style={{ fontSize: 11 }}>{t}</span>
                ))}
              </div>
            )}
            {snippet && (
              <p className="muted" style={{ fontSize: 12, margin: "8px 0 0", lineHeight: 1.45 }}>
                {snippet}{snippet.length >= 140 ? "…" : ""}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
