import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY,
} from "d3-force";
import type { Graph, GraphEdge, GraphNode } from "../../types";
import { nodeTypeColor, graphNodeTypeLabel, graphNodeDisplayType, graphNodeDisplaySeverity, isGetshellNode, showsShellStar, severityColor, severityLabel, displayFindingSeverity, lateralColor, formatNodeDetail, scrubCandidateRceLabel } from "../../theme";
import { popIn } from "../../anim";

interface SimNode extends GraphNode {
  x: number; y: number; vx?: number; vy?: number; fx?: number | null; fy?: number | null;
}

const W = 900;
const H = 560;
const TARGET_X = 96;
const TARGET_Y = 96;
/** 多个黑色目标（入口 / 内网跳板）水平分区间距 */
const TARGET_GAP = 520;
const MIN_ZOOM_K = 0.08;
const MIN_FIT_K = 0.05;
const MAX_K = 3.2;
const FIT_PAD = 36;
/** 未连线节点相对所属目标的最远距离，防止飞出把全览缩没 */
const ORPHAN_MAX_R = 360;
/** 按攻击链阶段向外分层，避免全部挤在目标周围 */
const TYPE_RING: Record<string, number> = {
  target: 0,
  info: 150,
  service: 170,
  danger: 250,
  vuln: 330,
  credential: 290,
  foothold: 410,
  goal: 500,
  honeypot: 220,
};

const LEGEND_TYPES: Record<string, string> = {
  target: "目标",
  service: "服务",
  danger: "危险点",
  vuln: "漏洞",
  credential: "凭证",
  foothold: "立足点",
  info: "信息",
};

function graphTitle(title?: string) {
  const t = scrubCandidateRceLabel(title) || title || "";
  return t.length > 22 ? t.slice(0, 21) + "…" : t;
}

function formatUnix(ts?: number) {
  if (!ts) return "";
  const d = new Date(ts > 1e12 ? ts : ts * 1000);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString();
}

function radiusOf(n: GraphNode) {
  return 9 + (n.risk_score / 100) * 16;
}

function collideRadius(n: GraphNode) {
  // 预留标签宽度，避免字体重叠看起来像「节点粘在一起」
  const labelBudget = Math.min(90, 8 + n.title.length * 2.4);
  return Math.max(radiusOf(n) + 22, labelBudget * 0.55);
}

function ringOf(type: string) {
  return TYPE_RING[type] ?? 260;
}

function hostOfNode(n: { key: string; type?: string; tags?: string[] }) {
  for (const t of n.tags || []) {
    if (typeof t === "string" && t.startsWith("host:")) {
      return t.slice(5).trim().toLowerCase().replace(/\.$/, "");
    }
  }
  const at = n.key.match(/@((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9][\w.-]*)$/i);
  if (at) return at[1].toLowerCase();
  if (n.type === "target" && n.key.startsWith("target:")) {
    return n.key.slice(7).split(":")[0].toLowerCase();
  }
  return "";
}

/** 跳板发现内网（SSRF/shell 可达），尚未在邻机落下已验证 shell。 */
function isPivotDiscoveryEdge(e: { relation?: string; rationale?: string; from?: string; to?: string }) {
  if (e.relation === "PIVOTS_TO") return false;
  if (e.relation && e.relation !== "LEADS_TO") return false;
  const why = String(e.rationale || "").toLowerCase();
  if (why.includes("pivot_capability")) return true;
  const to = String(e.to || "");
  const from = String(e.from || "");
  const dstHost = to.startsWith("info:host:") || to.startsWith("info:scope-expanded:");
  const srcCtrl = from.startsWith("foothold:") || from.startsWith("goal:shell");
  return dstHost && srcCtrl;
}

/**
 * 按攻击拓扑而不是 key 排目标区域：
 * 入口 → PIVOTS_TO 跳板 → 由已控主机发现的内网服务 → 其余目标。
 * 这样横向线始终向下一个区域延展，不会因为 IP/字典序出现折返。
 */
function orderedTargets(
  nodes: { key: string; type: string; tags?: string[] }[],
  edges: { from: string; to: string; relation?: string }[] = [],
) {
  const ts = nodes.filter((n) => n.type === "target");
  const fallback = ts.slice().sort((a, b) => {
    const al = (a.tags || []).includes("lateral") ? 1 : 0;
    const bl = (b.tags || []).includes("lateral") ? 1 : 0;
    return al - bl || a.key.localeCompare(b.key);
  });
  if (fallback.length < 2) return fallback;

  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const targetByHost = new Map(
    fallback
      .map((n) => [hostOfNode(n), n.key] as const)
      .filter(([host]) => !!host),
  );
  const children = new Map<string, { key: string; priority: number }[]>();
  for (const edge of edges) {
    if (!targetByHost.has(hostOfNode(byKey.get(edge.from) || { key: "" }))) continue;
    const dst = byKey.get(edge.to);
    if (!dst || dst.type !== "target") continue;
    const parent = targetByHost.get(hostOfNode(byKey.get(edge.from) || { key: "" }))!;
    if (parent === dst.key) continue;
    const priority = edge.relation === "PIVOTS_TO" ? 0 : 1;
    const list = children.get(parent) || [];
    if (!list.some((item) => item.key === dst.key)) list.push({ key: dst.key, priority });
    children.set(parent, list);
  }

  const primary = fallback.find((n) => !(n.tags || []).includes("lateral")) || fallback[0];
  const result: typeof fallback = [];
  const seen = new Set<string>();
  const visit = (key: string) => {
    if (seen.has(key)) return;
    const node = byKey.get(key);
    if (!node || node.type !== "target") return;
    seen.add(key);
    result.push(node);
    const next = (children.get(key) || [])
      .slice()
      .sort((a, b) => a.priority - b.priority || a.key.localeCompare(b.key));
    next.forEach((item) => visit(item.key));
  };
  visit(primary.key);
  fallback.forEach((node) => visit(node.key));
  return result;
}

function targetSlot(index: number) {
  return {
    x: TARGET_X + index * TARGET_GAP,
    y: TARGET_Y + (index % 2) * 40,
  };
}

/**
 * 每个节点归属哪个黑色目标：
 * - target 自己
 * - host: tag / @ip 匹配的 target:ip
 * - 否则被某 target CONTAINS/PIVOTS_TO 指向
 * - 默认入口 target
 */
function assignHomeTargets(
  nodes: GraphNode[],
  edges: { from: string; to: string; relation?: string }[],
): Map<string, string> {
  const targets = orderedTargets(nodes, edges);
  const home = new Map<string, string>();
  if (!targets.length) return home;
  const primary = targets[0].key;
  const byHost = new Map<string, string>();
  for (const t of targets) {
    const h = hostOfNode(t);
    if (h) byHost.set(h, t.key);
    home.set(t.key, t.key);
  }
  for (const n of nodes) {
    if (n.type === "target") continue;
    const h = hostOfNode(n);
    if (h && byHost.has(h)) home.set(n.key, byHost.get(h)!);
    else home.set(n.key, primary);
  }
  for (const e of edges) {
    const fromHome = home.get(e.from);
    const fromIsTarget = nodes.find((n) => n.key === e.from)?.type === "target";
    if (fromIsTarget && home.has(e.to)) {
      // target 发出的边：子节点归该 target
      home.set(e.to, e.from);
    } else if (e.relation === "PIVOTS_TO" && fromHome) {
      // 横向线指向新 target，不改来源归属
      continue;
    }
  }
  return home;
}

function seedPosition(
  n: GraphNode,
  index: number,
  total: number,
  homeKey: string,
  slots: Map<string, { x: number; y: number }>,
) {
  const anchor = slots.get(homeKey) || { x: TARGET_X, y: TARGET_Y };
  if (n.type === "target") return { ...anchor };
  const ring = ringOf(n.type);
  const angle = (index + 1) * 2.399963229728653 + (n.type.length % 5) * 0.35;
  const jitter = ((index * 37) % 17) - 8;
  const r = ring + jitter;
  return {
    x: anchor.x + Math.cos(angle) * r,
    y: anchor.y + Math.sin(angle) * r * 0.92 + Math.min(40, total),
  };
}

function isFinitePos(n: { x?: number; y?: number }) {
  return Number.isFinite(n.x) && Number.isFinite(n.y);
}

function connectedKeySet(edges: { from: string; to: string }[]) {
  const s = new Set<string>();
  for (const e of edges) {
    s.add(e.from);
    s.add(e.to);
  }
  return s;
}

const CHAIN_RANK: Record<string, number> = {
  target: 0, service: 1, info: 2, honeypot: 2, danger: 3, vuln: 4,
  credential: 5, foothold: 6, goal: 7,
};

/** 每个节点只保留一条主干入边，避免 service/info/target 同时指向同一漏洞造成蜘蛛网。 */
function chainDisplayEdges(nodes: GraphNode[], edges: GraphEdge[]): GraphEdge[] {
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  const valid = edges.filter((e) => byKey.has(e.from) && byKey.has(e.to) && e.from !== e.to);
  if (valid.length <= 1) return valid;
  const keep = new Set<string>();
  for (const e of valid) {
    if (e.relation === "PIVOTS_TO" || e.on_rce_path || e.relation === "EXPLOITS" || e.relation === "ESCALATES_TO" || isPivotDiscoveryEdge(e)) {
      keep.add(e.id);
    }
  }
  const reached = new Set(nodes.filter((n) => n.type === "target").map((n) => n.key));
  for (const e of valid) {
    if (e.relation === "PIVOTS_TO") reached.add(e.to);
  }
  const incoming = new Map<string, GraphEdge[]>();
  for (const e of valid) {
    const list = incoming.get(e.to) || [];
    list.push(e);
    incoming.set(e.to, list);
  }
  const score = (e: GraphEdge) => {
    const srcT = byKey.get(e.from)?.type || "";
    const dstT = byKey.get(e.to)?.type || "";
    const gap = (CHAIN_RANK[dstT] ?? 8) - (CHAIN_RANK[srcT] ?? 8);
    const step = gap === 1 ? 0 : (gap > 1 ? gap : 30);
    return [e.on_rce_path ? 0 : 1, step, -(e.weight || 0)] as const;
  };
  const pick = (cands: GraphEdge[]) => {
    cands.sort((a, b) => {
      const sa = score(a);
      const sb = score(b);
      return sa[0] - sb[0] || sa[1] - sb[1] || sa[2] - sb[2];
    });
    return cands[0];
  };
  let grew = true;
  while (grew) {
    grew = false;
    for (const n of nodes) {
      if (reached.has(n.key)) continue;
      const cands = (incoming.get(n.key) || []).filter((e) => reached.has(e.from));
      if (!cands.length) continue;
      keep.add(pick(cands).id);
      reached.add(n.key);
      grew = true;
    }
  }
  for (const n of nodes) {
    if (reached.has(n.key)) continue;
    const cands = incoming.get(n.key) || [];
    if (!cands.length) continue;
    keep.add(pick(cands).id);
    reached.add(n.key);
  }
  return valid.filter((e) => keep.has(e.id));
}

function isOrphanNode(n: GraphNode, connected: Set<string>) {
  return n.type !== "target" && !connected.has(n.key);
}

/** 用主簇（已连线 + 目标）做包围盒；离群未连线点不拖垮缩放 */
function computeFit(
  nodes: SimNode[],
  viewport: { width: number; height: number },
  connected: Set<string>,
  pad = FIT_PAD,
) {
  if (!nodes.length) return { x: 0, y: 0, k: 1 };
  const finite = nodes.filter(isFinitePos);
  if (!finite.length) return { x: 0, y: 0, k: 1 };

  const core = finite.filter((n) => n.type === "target" || connected.has(n.key));
  const base = core.length ? core : finite;

  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const n of base) {
    const r = collideRadius(n);
    minX = Math.min(minX, n.x - r);
    minY = Math.min(minY, n.y - r);
    maxX = Math.max(maxX, n.x + r);
    maxY = Math.max(maxY, n.y + r + 14);
  }

  const coreKeys = new Set(base.map((n) => n.key));
  const cx0 = (minX + maxX) / 2;
  const cy0 = (minY + maxY) / 2;
  const coreSpan = Math.max(maxX - minX, maxY - minY, 160);
  // 仅吸收「贴着主簇」的孤立点；飞太远的不参与适配
  const absorbR = Math.max(ORPHAN_MAX_R * 0.85, coreSpan * 0.55);

  for (const n of finite) {
    if (coreKeys.has(n.key)) continue;
    const d = Math.hypot(n.x - cx0, n.y - cy0);
    if (d > absorbR) continue;
    const r = collideRadius(n);
    minX = Math.min(minX, n.x - r);
    minY = Math.min(minY, n.y - r);
    maxX = Math.max(maxX, n.x + r);
    maxY = Math.max(maxY, n.y + r + 14);
  }

  const bw = Math.max(80, maxX - minX);
  const bh = Math.max(80, maxY - minY);
  const k = Math.min((viewport.width - 2 * pad) / bw, (viewport.height - 2 * pad) / bh, MAX_K);
  const kClamped = Math.max(MIN_FIT_K, k);
  const cx = (minX + maxX) / 2;
  const cy = (minY + maxY) / 2;
  return {
    k: kClamped,
    x: viewport.width / 2 - cx * kClamped,
    y: viewport.height / 2 - cy * kClamped,
  };
}

/** 把未连线节点拉回所属目标附近，避免斥力推飞 */
function restrainOrphans(
  nodes: SimNode[],
  connected: Set<string>,
  draggingKey: string | null,
  home: Map<string, string>,
  slots: Map<string, { x: number; y: number }>,
) {
  const byKey = new Map(nodes.map((n) => [n.key, n]));
  for (const n of nodes) {
    if (!isOrphanNode(n, connected) || !isFinitePos(n)) continue;
    if (draggingKey && n.key === draggingKey) continue;
    const hk = home.get(n.key) || "";
    const anchor = byKey.get(hk) && isFinitePos(byKey.get(hk)!)
      ? byKey.get(hk)!
      : (slots.get(hk) || { x: TARGET_X, y: TARGET_Y });
    const dx = n.x - anchor.x;
    const dy = n.y - anchor.y;
    const dist = Math.hypot(dx, dy) || 1;
    const cap = Math.min(ORPHAN_MAX_R, ringOf(n.type) + 90);
    if (dist > cap) {
      const s = cap / dist;
      n.x = anchor.x + dx * s;
      n.y = anchor.y + dy * s;
      n.vx = (n.vx || 0) * 0.2;
      n.vy = (n.vy || 0) * 0.2;
    }
  }
}

/** 检测是否严重塌缩：多数节点挤在一起 */
function isCollapsed(nodes: SimNode[]) {
  if (nodes.length < 3) return false;
  const pts = nodes.filter((n) => n.type !== "target" && isFinitePos(n));
  if (pts.length < 2) return false;
  let minD = Infinity;
  let close = 0;
  for (let i = 0; i < pts.length; i++) {
    for (let j = i + 1; j < pts.length; j++) {
      const dx = pts[i].x - pts[j].x;
      const dy = pts[i].y - pts[j].y;
      const d = Math.hypot(dx, dy);
      minD = Math.min(minD, d);
      const need = collideRadius(pts[i]) + collideRadius(pts[j]);
      if (d < need * 0.55) close += 1;
    }
  }
  const pairs = (pts.length * (pts.length - 1)) / 2;
  return minD < 12 || close / pairs > 0.35;
}

function topologyKey(graph: Graph) {
  const nk = graph.nodes.map((n) => n.key).sort().join(",");
  const ek = graph.edges.map((e) => `${e.from}>${e.to}`).sort().join(",");
  return `${nk}|${ek}|chain`;
}

export function AttackGraph({ graph, onSelect, selectedKey, onClear }: { graph: Graph; onSelect: (n: GraphNode) => void; selectedKey?: string; onClear?: () => void }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<any>(null);
  const nodesRef = useRef<SimNode[]>([]);
  const linksRef = useRef<any[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const viewRef = useRef({ x: 0, y: 0, k: 1 });
  const viewportRef = useRef({ width: W, height: H });
  const fitPendingRef = useRef(true);
  const autoFitRef = useRef(true);
  const fitFrameRef = useRef<number | null>(null);
  const topoRef = useRef("");
  const tickCountRef = useRef(0);
  const relayoutRef = useRef(0);
  const connectedRef = useRef<Set<string>>(new Set());
  const homeRef = useRef<Map<string, string>>(new Map());
  const slotsRef = useRef<Map<string, { x: number; y: number }>>(new Map());
  const [, setFrame] = useState(0);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [fullscreen, setFullscreen] = useState(false);
  const [viewport, setViewport] = useState({ width: W, height: H });
  const dragRef = useRef<{
    node: SimNode | null; panning: boolean; sx: number; sy: number; ox: number; oy: number;
  }>({ node: null, panning: false, sx: 0, sy: 0, ox: 0, oy: 0 });

  // 每个已获取 RCE 的 target 都有一条独立橙色最优路径；兼容旧快照仅含 path 的情形。
  const rcePaths = useMemo(() => {
    const paths = graph.rce_path?.paths;
    return paths?.length ? paths : (graph.rce_path?.path?.length ? [graph.rce_path.path] : []);
  }, [graph.rce_path?.path, graph.rce_path?.paths]);
  const rcePairs = useMemo(() => {
    const pairs = new Set<string>();
    for (const path of rcePaths) {
      for (let i = 0; i < path.length - 1; i++) {
        pairs.add(`${path[i]}\0${path[i + 1]}`);
      }
    }
    return pairs;
  }, [rcePaths]);
  // 防御性保护：即使服务端历史标记尚未重算，橙色路径也绝不覆盖 PIVOTS_TO 紫线。
  const pivotPairs = useMemo(
    () => new Set(
      graph.edges
        .filter((e) => e.relation === "PIVOTS_TO")
        .map((e) => `${e.from}\0${e.to}`),
    ),
    [graph.edges],
  );
  const topo = useMemo(() => topologyKey(graph), [graph.nodes, graph.edges]);
  const graphRef = useRef(graph);
  graphRef.current = graph;

  const applyView = useCallback((next: { x: number; y: number; k: number }) => {
    viewRef.current = next;
    setView(next);
  }, []);

  const fitToNodes = useCallback((keepPending = false) => {
    const next = computeFit(nodesRef.current, viewportRef.current, connectedRef.current);
    applyView(next);
    fitPendingRef.current = keepPending;
  }, [applyView]);

  const syncViewportAndFit = useCallback(() => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect?.width || !rect.height) return;
    const next = { width: rect.width, height: rect.height };
    viewportRef.current = next;
    setViewport((previous) => (
      previous.width === next.width && previous.height === next.height ? previous : next
    ));
    if (autoFitRef.current) fitToNodes();
  }, [fitToNodes]);

  const scheduleViewportFit = useCallback(() => {
    requestAnimationFrame(() => requestAnimationFrame(syncViewportAndFit));
  }, [syncViewportAndFit]);

  const applyForces = useCallback((
    sim: any,
    links: any[],
    connected: Set<string>,
    nodes: SimNode[],
    home: Map<string, string>,
    slots: Map<string, { x: number; y: number }>,
  ) => {
    const byKey = new Map(nodes.map((n) => [n.key, n]));
    sim
      .force("charge", forceManyBody<SimNode>()
        .strength((d) => {
          if (d.type === "target") return -280;
          if (isOrphanNode(d, connected)) return -140;
          return -520;
        })
        .distanceMax(720))
      .force("link", forceLink(links as any)
        .id((d: any) => d.key)
        .distance((l: any) => {
          // 横向边拉长，把跳板目标推到另一区域
          if (l.relation === "PIVOTS_TO") return TARGET_GAP * 0.85;
          if (isPivotDiscoveryEdge(l)) return TARGET_GAP * 0.62;
          const s = typeof l.source === "object" ? l.source as SimNode : null;
          const t = typeof l.target === "object" ? l.target as SimNode : null;
          const ra = ringOf(s?.type || "service");
          const rb = ringOf(t?.type || "vuln");
          return Math.max(120, Math.abs(ra - rb) * 0.55 + 90);
        })
        .strength((l: any) => (l.relation === "PIVOTS_TO" || isPivotDiscoveryEdge(l) ? 0.45 : 0.28)))
      .force("collide", forceCollide<SimNode>()
        .radius((d) => collideRadius(d) + (d.type === "target" ? 20 : 0))
        .strength(0.95)
        .iterations(4))
      // 每个节点绕「自己的黑色目标」成环发散（多目标分区）
      .force("cluster", () => {
        for (const n of nodes) {
          if (n.type === "target" || !isFinitePos(n)) continue;
          const hk = home.get(n.key);
          const homeNode = hk ? byKey.get(hk) : null;
          const anchor = homeNode && isFinitePos(homeNode)
            ? homeNode
            : (hk && slots.get(hk)) || { x: TARGET_X, y: TARGET_Y };
          const desired = Math.min(
            ringOf(n.type),
            isOrphanNode(n, connected) ? ORPHAN_MAX_R * 0.75 : ringOf(n.type),
          );
          const dx = n.x - anchor.x;
          const dy = n.y - anchor.y;
          const dist = Math.hypot(dx, dy) || 0.01;
          const k = isOrphanNode(n, connected) ? 0.14 : 0.07;
          const f = (dist - desired) * k;
          n.vx = (n.vx || 0) - (dx / dist) * f;
          n.vy = (n.vy || 0) - (dy / dist) * f;
        }
      })
      .force("radial", null)
      .force("orphanX", null)
      .force("orphanY", null)
      .force("anchorX", null)
      .force("anchorY", null)
      // 每个黑色目标钉在自己的分区槽位
      .force("targetX", forceX<SimNode>((d) => (
        d.type === "target" ? (slots.get(d.key)?.x ?? TARGET_X) : TARGET_X
      )).strength((d) => (d.type === "target" ? 0.98 : 0)))
      .force("targetY", forceY<SimNode>((d) => (
        d.type === "target" ? (slots.get(d.key)?.y ?? TARGET_Y) : TARGET_Y
      )).strength((d) => (d.type === "target" ? 0.98 : 0)));
  }, []);

  const reseedLayout = useCallback((nodes: SimNode[]) => {
    const home = homeRef.current;
    const slots = slotsRef.current;
    nodes.forEach((n, i) => {
      if (n.type === "target") {
        const slot = slots.get(n.key) || targetSlot(0);
        n.x = slot.x;
        n.y = slot.y;
        n.fx = slot.x;
        n.fy = slot.y;
        n.vx = 0;
        n.vy = 0;
        return;
      }
      const p = seedPosition(n, i, nodes.length, home.get(n.key) || "", slots);
      n.x = p.x;
      n.y = p.y;
      n.vx = 0;
      n.vy = 0;
      n.fx = null;
      n.fy = null;
    });
  }, []);

  // 重建/协调仿真：只在拓扑变化时跑。snapshot/轮询换新数组不得重绑 forceLink（否则边端点错位、点叠成一团）。
  useEffect(() => {
    const g = graphRef.current;
    const existing = new Map(nodesRef.current.map((n) => [n.key, n]));
    const topoChanged = topo !== topoRef.current;
    topoRef.current = topo;

    const home = assignHomeTargets(g.nodes, g.edges);
    const slots = new Map<string, { x: number; y: number }>();
    orderedTargets(g.nodes, g.edges).forEach((t, i) => slots.set(t.key, targetSlot(i)));
    homeRef.current = home;
    slotsRef.current = slots;

    const nodes: SimNode[] = g.nodes.map((n, i) => {
      const prev = existing.get(n.key);
      if (prev && isFinitePos(prev)) {
        prev.title = n.title;
        prev.detail = n.detail;
        prev.severity = n.severity;
        prev.is_rce = n.is_rce;
        prev.risk_score = n.risk_score;
        prev.tags = n.tags;
        prev.status = n.status;
        prev.type = n.type;
        prev.created_at = n.created_at;
        prev.updated_at = n.updated_at;
        return prev;
      }
      const p = seedPosition(n, i, g.nodes.length, home.get(n.key) || "", slots);
      if (n.type === "target") {
        const slot = slots.get(n.key) || targetSlot(0);
        return { ...n, x: slot.x, y: slot.y, fx: slot.x, fy: slot.y };
      }
      return { ...n, x: p.x, y: p.y };
    });

    const targetsStacked = (() => {
      const ts = nodes.filter((n) => n.type === "target" && isFinitePos(n));
      if (ts.length < 2) return false;
      for (let i = 0; i < ts.length; i++) {
        for (let j = i + 1; j < ts.length; j++) {
          if (Math.hypot(ts[i].x - ts[j].x, ts[i].y - ts[j].y) < TARGET_GAP * 0.4) return true;
        }
      }
      return false;
    })();

    for (const n of nodes) {
      if (n.type === "target" && !dragRef.current.node) {
        const slot = slots.get(n.key) || targetSlot(0);
        if (!existing.has(n.key) || targetsStacked) {
          n.fx = slot.x;
          n.fy = slot.y;
          n.x = slot.x;
          n.y = slot.y;
        } else {
          n.fx = n.x;
          n.fy = n.y;
        }
      }
    }

    if (topoChanged && nodes.length > 2 && (nodesRef.current.length === 0 || isCollapsed(nodes) || targetsStacked)) {
      reseedLayout(nodes);
      relayoutRef.current = 0;
    }

    nodesRef.current = nodes;

    const byKey = new Map(nodes.map((n) => [n.key, n]));
    const visibleEdges = chainDisplayEdges(g.nodes, g.edges);
    const links = visibleEdges
      .map((e) => ({ ...e, source: byKey.get(e.from), target: byKey.get(e.to) }))
      .filter((l) => l.source && l.target);
    linksRef.current = links;
    const connected = connectedKeySet(visibleEdges);
    connectedRef.current = connected;

    for (const n of nodes) {
      if (!seenRef.current.has(n.key) && isOrphanNode(n, connected)) {
        const anchor = slots.get(home.get(n.key) || "") || { x: TARGET_X, y: TARGET_Y };
        const ang = (seenRef.current.size + 1) * 2.399963229728653;
        const r = Math.min(ringOf(n.type), 210);
        n.x = anchor.x + Math.cos(ang) * r;
        n.y = anchor.y + Math.sin(ang) * r * 0.9;
        n.vx = 0;
        n.vy = 0;
      }
    }

    simRef.current?.stop();
    tickCountRef.current = 0;
    const sim = forceSimulation<SimNode>(nodes).alphaDecay(0.022).velocityDecay(0.32);
    applyForces(sim, links, connected, nodes, home, slots);
    sim
      .on("tick", () => {
        tickCountRef.current += 1;
        restrainOrphans(
          nodesRef.current,
          connectedRef.current,
          dragRef.current.node?.key ?? null,
          homeRef.current,
          slotsRef.current,
        );
        if (
          tickCountRef.current === 45
          && relayoutRef.current < 2
          && isCollapsed(nodesRef.current)
          && !dragRef.current.node
        ) {
          relayoutRef.current += 1;
          reseedLayout(nodesRef.current);
          applyForces(
            simRef.current, linksRef.current, connectedRef.current,
            nodesRef.current, homeRef.current, slotsRef.current,
          );
          simRef.current?.alpha(1).restart();
        }
        if (fitFrameRef.current == null) {
            fitFrameRef.current = requestAnimationFrame(() => {
              fitFrameRef.current = null;
              setFrame((f) => f + 1);
              if (tickCountRef.current === 8 && autoFitRef.current) fitToNodes();
            });
        }
      })
      .on("end", () => {
        if (autoFitRef.current) fitToNodes();
      });
    simRef.current = sim;

    const fresh = nodes.filter((n) => !seenRef.current.has(n.key));
    fresh.forEach((n) => seenRef.current.add(n.key));
    if (fresh.length) {
      autoFitRef.current = true;
      fitPendingRef.current = true;
      requestAnimationFrame(() => {
        const els = fresh
          .map((n) => svgRef.current?.querySelector(`[data-node="${CSS.escape(n.key)}"]`))
          .filter(Boolean);
        if (els.length) popIn(els as any);
      });
    }

    return () => {
      sim.stop();
      if (simRef.current === sim) simRef.current = null;
    };
  }, [topo, fitToNodes, applyForces, reseedLayout]);

  // 指针锚定滚轮缩放
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = svg.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      const mx = ((e.clientX - rect.left) / rect.width) * viewportRef.current.width;
      const my = ((e.clientY - rect.top) / rect.height) * viewportRef.current.height;
      const v = viewRef.current;
      const factor = e.deltaY < 0 ? 1.12 : 0.9;
      const k2 = Math.min(MAX_K, Math.max(MIN_ZOOM_K, v.k * factor));
      const wx = (mx - v.x) / v.k;
      const wy = (my - v.y) / v.k;
      autoFitRef.current = false;
      applyView({ k: k2, x: mx - wx * k2, y: my - wy * k2 });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, [applyView]);

  useEffect(() => {
    const onFs = () => {
      const el = wrapRef.current;
      const active = !!el && document.fullscreenElement === el;
      setFullscreen(active);
      autoFitRef.current = true;
      fitPendingRef.current = true;
      scheduleViewportFit();
    };
    document.addEventListener("fullscreenchange", onFs);
    return () => document.removeEventListener("fullscreenchange", onFs);
  }, [scheduleViewportFit]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => {
      autoFitRef.current = true;
      fitPendingRef.current = true;
      scheduleViewportFit();
    });
    ro.observe(el);
    scheduleViewportFit();
    return () => ro.disconnect();
  }, [scheduleViewportFit]);

  const clientToSvg = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    return {
      x: ((clientX - rect.left) / rect.width) * viewportRef.current.width,
      y: ((clientY - rect.top) / rect.height) * viewportRef.current.height,
    };
  };

  const toWorld = (clientX: number, clientY: number) => {
    const s = clientToSvg(clientX, clientY);
    const v = viewRef.current;
    return { x: (s.x - v.x) / v.k, y: (s.y - v.y) / v.k };
  };

  const onDown = (e: React.MouseEvent, n?: SimNode) => {
    if (n) {
      dragRef.current.node = n;
      n.fx = null;
      n.fy = null;
      autoFitRef.current = false;
      simRef.current?.alphaTarget(0.25).restart();
    } else {
      autoFitRef.current = false;
      dragRef.current.panning = true;
      dragRef.current.sx = e.clientX;
      dragRef.current.sy = e.clientY;
      dragRef.current.ox = viewRef.current.x;
      dragRef.current.oy = viewRef.current.y;
    }
  };
  const onMove = (e: React.MouseEvent) => {
    const d = dragRef.current;
    if (d.node) {
      const w = toWorld(e.clientX, e.clientY);
      d.node.fx = w.x;
      d.node.fy = w.y;
    } else if (d.panning && svgRef.current) {
      const rect = svgRef.current.getBoundingClientRect();
      const dx = ((e.clientX - d.sx) / rect.width) * viewportRef.current.width;
      const dy = ((e.clientY - d.sy) / rect.height) * viewportRef.current.height;
      applyView({ ...viewRef.current, x: d.ox + dx, y: d.oy + dy });
    }
  };
  const onUp = () => {
    const d = dragRef.current;
    if (d.node) {
      if (d.node.type === "target") {
        // 拖完钉在落点，保持多目标分区；不弹回单一原点
        d.node.fx = d.node.x;
        d.node.fy = d.node.y;
      } else {
        d.node.fx = null;
        d.node.fy = null;
      }
      simRef.current?.alphaTarget(0);
    }
    d.node = null;
    d.panning = false;
  };

  const toggleFullscreen = async () => {
    const el = wrapRef.current;
    if (!el) return;
    try {
      if (document.fullscreenElement === el) await document.exitFullscreen();
      else await el.requestFullscreen();
    } catch {
      /* 浏览器拒绝全屏时忽略 */
    }
  };

  const relayout = () => {
    reseedLayout(nodesRef.current);
    relayoutRef.current = 0;
    tickCountRef.current = 0;
    autoFitRef.current = true;
    fitPendingRef.current = true;
    applyForces(
      simRef.current, linksRef.current, connectedRef.current,
      nodesRef.current, homeRef.current, slotsRef.current,
    );
    simRef.current?.alpha(1).restart();
  };

  const nodes = nodesRef.current;
  const links = linksRef.current;
  const selectedNode = selectedKey ? nodes.find((n) => n.key === selectedKey) : null;
  const selectedData = (selectedKey && graph.nodes.find((n) => n.key === selectedKey)) || selectedNode;
  const selectedInbound = selectedData ? graph.edges.filter((e) => e.to === selectedData.key) : [];
  const selectedOutbound = selectedData ? graph.edges.filter((e) => e.from === selectedData.key) : [];
  const selectedFindings = selectedData ? graph.findings.filter((f) => f.node_key === selectedData.key) : [];
  const selectedDetail = selectedData ? formatNodeDetail(selectedData.detail) : "";
  const popW = Math.min(420, viewport.width - 24);
  const popH = Math.min(420, viewport.height * 0.72);

  return (
    <div
      ref={wrapRef}
      className={`graph-wrap${fullscreen ? " graph-wrap-fs" : ""}`}
      style={{ height: fullscreen ? "100%" : H }}
    >
      <div className="graph-controls">
        <button type="button" className="graph-ctrl-btn" title="重新散开布局" onClick={relayout}>
          重布
        </button>
        <button type="button" className="graph-ctrl-btn" title="适配全部节点" onClick={() => { autoFitRef.current = true; fitToNodes(); }}>
          适配
        </button>
        <button
          type="button"
          className="graph-ctrl-btn"
          title={fullscreen ? "退出全屏" : "全屏显示"}
          onClick={toggleFullscreen}
        >
          {fullscreen ? "退出全屏" : "全屏"}
        </button>
      </div>

      {graph.stats?.lateral_active && (
        <div className="graph-lateral-banner">
          <span className="graph-lateral-dot" />
          内网横向进行中
          {graph.stats.hosts_footed ? ` · ${graph.stats.hosts_footed} 台主机` : ""}
        </div>
      )}

      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        viewBox={`0 0 ${viewport.width} ${viewport.height}`}
        preserveAspectRatio="none"
        onMouseMove={onMove}
        onMouseUp={onUp}
        onMouseLeave={onUp}
        onMouseDown={(e) => { if (e.target === svgRef.current) { onClear?.(); onDown(e); } }}
        style={{ cursor: dragRef.current.panning ? "grabbing" : "default", display: "block" }}
      >
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {links.map((l: any) => {
            // 只高亮路径上相邻节点对，避免路径上任意两点的捷径边被当成最优路径
            const onRce = l.on_rce_path || rcePairs.has(`${l.from}\0${l.to}`);
            // 内网横向边（PIVOTS_TO）优先用专用醒目样式，即便同时在 RCE 路径上
            const cls = l.relation === "PIVOTS_TO"
              ? "graph-edge-pivot"
              : (isPivotDiscoveryEdge(l)
                ? "graph-edge-pivot-hop"
                : (onRce ? "graph-edge-rce" : "graph-edge"));
            return (
              <line
                key={l.id}
                x1={l.source.x} y1={l.source.y} x2={l.target.x} y2={l.target.y}
                className={cls}
              />
            );
          })}
          {(() => {
            const segments = rcePaths.flatMap((path) => {
              const pts = path
                .map((k) => nodes.find((n) => n.key === k))
                .filter((n): n is SimNode => !!n && Number.isFinite(n.x) && Number.isFinite(n.y));
              if (pts.length < 2) return [];
              const own: SimNode[][] = [];
              let cur: SimNode[] = [pts[0]];
              for (let i = 1; i < pts.length; i++) {
                const a = pts[i - 1];
                const b = pts[i];
                if (pivotPairs.has(`${a.key}\0${b.key}`)) {
                  if (cur.length >= 2) own.push(cur);
                  cur = [b];
                } else {
                  cur.push(b);
                }
              }
              if (cur.length >= 2) own.push(cur);
              return own;
            });
            return segments.map((seg, i) => (
              <polyline
                key={`rce-path-${i}`}
                className="graph-rce-path"
                points={seg.map((n) => `${n.x},${n.y}`).join(" ")}
                fill="none"
              />
            ));
          })()}
          {nodes.map((n) => {
            const r = radiusOf(n);
            const color = nodeTypeColor[graphNodeDisplayType(n)] || "#8e8b82";
            const critical = n.severity === "critical" || isGetshellNode(n) || showsShellStar(n);
            const selected = n.key === selectedKey;
            const isLateral = (n.tags || []).some((t) => t === "lateral" || t === "pivot");
            return (
              <g
                key={n.key}
                data-node={n.key}
                transform={`translate(${n.x},${n.y})`}
                style={{ cursor: "pointer" }}
                onMouseDown={(e) => { e.stopPropagation(); onDown(e, n); }}
                onClick={(e) => { e.stopPropagation(); onSelect(n); }}
              >
                {isLateral && (
                  <circle
                    className="ring-lateral"
                    r={r + 8}
                    fill="none"
                    stroke={lateralColor}
                    strokeWidth={2.5}
                  />
                )}
                {critical && (
                  <circle
                    className="ring-pulse"
                    r={r + 6}
                    fill="none"
                    stroke={severityColor[graphNodeDisplaySeverity(n)] || color}
                    strokeWidth={2}
                  />
                )}
                {selected && (
                  <circle r={r + 9} fill="none" stroke="var(--primary)" strokeWidth={2} strokeDasharray="3 3" />
                )}
                <circle r={r} fill={color} stroke={severityColor[graphNodeDisplaySeverity(n)] || "#fff"} strokeWidth={2.5} />
                {showsShellStar(n) && (
                  <text textAnchor="middle" dy={4} fontSize={14} fill="#fff">★</text>
                )}
                <text className="graph-node-label" textAnchor="middle" dy={r + 12}>
                  {graphTitle(n.title)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      {selectedNode && selectedData && Number.isFinite(selectedNode.x) && Number.isFinite(selectedNode.y) && (
        <div
          className="graph-node-popover"
          onMouseDown={(e) => e.stopPropagation()}
          onClick={(e) => e.stopPropagation()}
          style={{
            left: Math.min(Math.max(selectedNode.x * view.k + view.x + 20, 12), viewport.width - popW - 12),
            top: Math.min(Math.max(selectedNode.y * view.k + view.y - 40, 12), viewport.height - popH - 12),
          }}
        >
          <div className="node-popover-type">
            {graphNodeTypeLabel(selectedData)}
            {" · "}
            {severityLabel[graphNodeDisplaySeverity(selectedData)] || graphNodeDisplaySeverity(selectedData)}
            {selectedData.status ? ` · ${selectedData.status}` : ""}
            {showsShellStar(selectedData) ? " · GETSHELL / RCE" : ""}
          </div>
          <strong>{scrubCandidateRceLabel(selectedData.title) || selectedData.title}</strong>
          <div className="node-popover-key">{selectedData.key}</div>
          <div className="node-popover-meta">
            风险 {selectedData.risk_score}
            {formatUnix(selectedData.created_at) ? ` · 创建 ${formatUnix(selectedData.created_at)}` : ""}
            {formatUnix(selectedData.updated_at) ? ` · 更新 ${formatUnix(selectedData.updated_at)}` : ""}
          </div>
          {!!selectedData.tags?.length && (
            <div className="node-popover-tags">
              {selectedData.tags.map((t) => <span key={t} className="node-popover-tag">{t}</span>)}
            </div>
          )}
          {selectedDetail && <pre className="node-popover-detail">{selectedDetail}</pre>}
          {(selectedInbound.length > 0 || selectedOutbound.length > 0) && (
            <div className="node-popover-sec">
              <div className="node-popover-sec-title">攻击链关系</div>
              {selectedInbound.map((e) => (
                <div key={e.id} className="node-popover-rel">← {e.from} · {e.relation}{e.rationale ? ` · ${e.rationale}` : ""}</div>
              ))}
              {selectedOutbound.map((e) => (
                <div key={e.id} className="node-popover-rel">→ {e.to} · {e.relation}{e.rationale ? ` · ${e.rationale}` : ""}</div>
              ))}
            </div>
          )}
          {selectedFindings.length > 0 && (
            <div className="node-popover-sec">
              <div className="node-popover-sec-title">关联发现</div>
              {selectedFindings.map((f) => (
                <div key={f.id} className="node-popover-rel">
                  [{severityLabel[displayFindingSeverity(f)] || displayFindingSeverity(f)}] {scrubCandidateRceLabel(f.title) || f.title}
                  {f.description ? ` — ${f.description}` : ""}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="legend">
        {Object.entries(LEGEND_TYPES).map(([k, label]) => (
          <span className="row" key={k}>
            <i className="dot" style={{ background: nodeTypeColor[k] }} /> {label}
          </span>
        ))}
        <span className="row">
          <i style={{ width: 16, height: 3, background: "var(--primary)", display: "inline-block" }} /> RCE 最优路径
        </span>
        <span className="row">
          <i style={{ width: 16, height: 3, background: lateralColor, display: "inline-block" }} /> 内网横向 (shell→新主机)
        </span>
        <span className="row">
          <i style={{
            width: 16, height: 0, borderTop: `2px dashed ${lateralColor}`, display: "inline-block", opacity: 0.85,
          }} /> 跳板可达 (发现内网)
        </span>
        <span className="row">
          <span style={{
            width: 14, height: 14, borderRadius: "50%", background: nodeTypeColor.goal,
            color: "#fff", fontSize: 10, display: "inline-flex", alignItems: "center", justifyContent: "center",
          }}>★</span>
          {" "}GETSHELL / RCE
        </span>
      </div>
    </div>
  );
}
