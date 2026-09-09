import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import type { Finding, Graph, GraphEdge, GraphNode, Project, RTEvent } from "../types";
import { useProjectSocket } from "../ws";
import { AttackGraph } from "../features/graph/AttackGraph";
import { NodeDetail } from "../features/graph/NodeDetail";
import { Timeline } from "../features/timeline/Timeline";
import { SupervisorPanel, countSupervisorRecords } from "../features/timeline/SupervisorPanel";
import { FindingsPanel, collectVulns, filterVisibleFindings } from "../features/findings/FindingsPanel";
import { ServicesPanel } from "../features/services/ServicesPanel";
import { MemoryPanel } from "../features/memory/MemoryPanel";
import { ChatDock } from "../features/chat/ChatDock";
import { ClusterDashboard } from "../features/cluster/ClusterDashboard";
import { BenchmarkDashboard } from "../features/benchmark/BenchmarkDashboard";
import { ReportExportControls } from "../features/report/ExportReport";
import { colors, displayFindingSeverity } from "../theme";
import { huntFailedReason } from "../projectStatus";
import { animate } from "animejs";
import { countUp } from "../anim";

const EMPTY: Graph = { nodes: [], edges: [], findings: [], intents: [], frontier: {}, rce_path: { path: [], likelihood: 0 }, stats: { nodes: 0, edges: 0, findings: 0, critical: 0, has_shell: false, frontier_open: 0 } };
const GRAPH_EVENTS = new Set(["node", "edge", "finding", "rce_path", "shell", "lateral"]);

function layoutKey(g: Graph) {
  return `${g.nodes.map((n) => n.key).sort().join(",")}|${g.edges.map((e) => `${e.from}>${e.to}`).sort().join(",")}`;
}

/** 拓扑未变时保住 nodes/edges 数组引用，避免关系图仿真被 snapshot/轮询打断。 */
function keepLayoutIfUnchanged(prev: Graph, next: Graph): Graph {
  if (!next) return prev;
  if (layoutKey(prev) !== layoutKey(next)) return next;
  const fresh = new Map((next.nodes || []).map((n) => [n.key, n]));
  for (const n of prev.nodes) {
    const nn = fresh.get(n.key);
    if (nn && nn.title && nn.title !== n.title) n.title = nn.title;
  }
  return {
    ...prev,
    stats: next.stats ?? prev.stats,
    findings: next.findings ?? prev.findings,
    intents: next.intents ?? prev.intents,
    frontier: next.frontier ?? prev.frontier,
    rce_path: next.rce_path ?? prev.rce_path,
  };
}

function applyGraphEvent(g: Graph, ev: RTEvent): Graph {
  const p = ev.payload || {};
  if (ev.type === "node" && p.key) {
    const node = p as GraphNode;
    const nodes = g.nodes.some((n) => n.key === node.key)
      ? g.nodes.map((n) => (n.key === node.key ? { ...n, ...node } : n))
      : [...g.nodes, node];
    return {
      ...g,
      nodes,
      stats: {
        ...g.stats,
        nodes: nodes.length,
        services: nodes.filter((n) => n.type === "service").length,
      },
    };
  }
  if (ev.type === "edge" && (p.from || p.src) && (p.to || p.dst)) {
    const edge: GraphEdge = {
      id: p.id,
      from: p.from || p.src,
      to: p.to || p.dst,
      relation: p.relation,
      weight: p.weight ?? 0,
      rationale: p.rationale,
      on_rce_path: !!p.on_rce_path,
    };
    const same = (x: GraphEdge) =>
      (edge.id && x.id === edge.id)
      || (x.from === edge.from && x.to === edge.to && x.relation === edge.relation);
    const edges = g.edges.some(same)
      ? g.edges.map((x) => (same(x) ? { ...x, ...edge } : x))
      : [...g.edges, edge];
    return { ...g, edges, stats: { ...g.stats, edges: edges.length } };
  }
  if (ev.type === "finding" && p.id) {
    const finding = p as Finding;
    const findings = g.findings.some((f) => f.id === finding.id)
      ? g.findings.map((f) => (f.id === finding.id ? { ...f, ...finding } : f))
      : [finding, ...g.findings];
    const visible = filterVisibleFindings(findings);
    return {
      ...g,
      findings,
      stats: {
        ...g.stats,
        findings: visible.length,
        high: visible.filter((f) => displayFindingSeverity(f) === "high").length,
        critical: visible.filter((f) => displayFindingSeverity(f) === "critical").length,
      },
    };
  }
  if (ev.type === "rce_path") {
    return { ...g, rce_path: { ...g.rce_path, ...p } };
  }
  if (ev.type === "shell") {
    return { ...g, stats: { ...g.stats, has_shell: true } };
  }
  if (ev.type === "lateral") {
    return {
      ...g,
      stats: {
        ...g.stats,
        lateral_active: true,
        hosts_footed: p.hosts_footed ?? g.stats.hosts_footed,
        pivot_edges: p.pivot_edges ?? g.stats.pivot_edges,
      },
    };
  }
  return g;
}
const MAX_EVENTS = 2000;
const PINNED_EVENT_TYPES = new Set(["steer", "drift_alert", "supervisor"]);

/** 工具洪水下仍保留纠偏指令；其余只留最近 MAX_EVENTS。 */
function capEvents(evs: RTEvent[]): RTEvent[] {
  if (evs.length <= MAX_EVENTS) return evs;
  const pinned: RTEvent[] = [];
  const rest: RTEvent[] = [];
  for (const e of evs) (PINNED_EVENT_TYPES.has(e.type) ? pinned : rest).push(e);
  const room = Math.max(0, MAX_EVENTS - pinned.length);
  const tail = rest.slice(-room);
  const byId = new Map<string | number, RTEvent>();
  for (const e of [...pinned, ...tail]) {
    const k = e.id ?? `${e.type}:${e.ts}`;
    byId.set(k, e);
  }
  return [...byId.values()].sort((a, b) => Number(a.id || a.ts) - Number(b.id || b.ts));
}

export function ProjectPage() {
  const { id } = useParams();
  const [project, setProject] = useState<Project | null>(null);
  const [graph, setGraph] = useState<Graph>(EMPTY);
  const [events, setEvents] = useState<RTEvent[]>([]);
  const [running, setRunning] = useState(false);
  const [queued, setQueued] = useState(false);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [tab, setTab] = useState<"timeline" | "findings" | "services" | "memory" | "supervisor">("timeline");
  const [liveWs, setLiveWs] = useState(false);
  const [loadErr, setLoadErr] = useState("");
  const refetchTimer = useRef<any>();
  const headRef = useRef<HTMLDivElement>(null);
  const pendingEvs = useRef<RTEvent[]>([]);
  const flushRaf = useRef<number | null>(null);
  const needGraphRefetch = useRef(false);

  useEffect(() => {
    if (!id) return;
    setProject(null);
    setLoadErr("");
    setLiveWs(false);
    setEvents([]);
    setGraph(EMPTY);
    api.getProject(id).then((p) => {
      setProject(p);
      setGraph(p.graph || EMPTY);
      setRunning(!!p.running);
      setQueued(!!p.queued);
      setLiveWs(p.kind === "single");
    }).catch((e: any) => {
      setLoadErr(String(e?.message || e || "加载失败"));
    });
  }, [id]);

  useEffect(() => {
    if (!id || !liveWs) return;
    api.events(id).then((evs) => {
      setEvents(capEvents(evs));
    }).catch(() => {});
  }, [id, liveWs]);

  useEffect(() => {
    // 只动透明度：translateY 会在页头留下 transform，把报告导出弹层钉死在标题栏里。
    if (headRef.current) animate(headRef.current, { opacity: [0, 1], duration: 420, ease: "outCubic" });
  }, [project?.id]);

  const scheduleRefetch = () => {
    needGraphRefetch.current = true;
    clearTimeout(refetchTimer.current);
    // 节点/边已由 WS 即时合并；短延迟再拉全图，补齐 intents/stats/RCE 路径
    refetchTimer.current = setTimeout(() => {
      if (!id || !needGraphRefetch.current) return;
      needGraphRefetch.current = false;
      api.graph(id).then((g) => {
        setGraph((prev) => keepLayoutIfUnchanged(prev, g));
      }).catch(() => {});
    }, 400);
  };

  const flushEvents = () => {
    flushRaf.current = null;
    const batch = pendingEvs.current;
    pendingEvs.current = [];
    if (!batch.length) return;
    const graphPatch: RTEvent[] = [];
    for (const ev of batch) {
      if (GRAPH_EVENTS.has(ev.type)) graphPatch.push(ev);
      if (ev.type === "status") {
        const s = ev.payload?.status;
        if (s === "queued") {
          setQueued(true);
          setRunning(true);
        }
        if (s === "running") {
          setQueued(false);
          setRunning(true);
        }
        if (["completed", "stopped", "error", "goal_reached"].includes(s) && ev.payload?.turn === undefined) {
          if (s !== "goal_reached") {
            setRunning(false);
            setQueued(false);
          }
          const reason = ev.payload?.reason as string | undefined;
          setProject((prev) => {
            if (!prev) return prev;
            const nextStatus = s === "goal_reached" ? "completed" : (s === "stopped" ? "idle" : s);
            const cfg = { ...(prev.config || {}) };
            if (reason) cfg.completion_reason = reason;
            else if (s === "completed" || s === "goal_reached") cfg.completion_reason = "goal_reached";
            return { ...prev, status: nextStatus, config: cfg };
          });
        }
      }
      if (ev.type === "shell") setRunning(false);
    }
    setEvents((prev) => capEvents([...prev, ...batch]));
    if (graphPatch.length) {
      setGraph((g) => graphPatch.reduce(applyGraphEvent, g));
      scheduleRefetch();
    }
  };

  const { send } = useProjectSocket(liveWs ? id : undefined, {
    onSnapshot: (g, r, q) => {
      setGraph((prev) => keepLayoutIfUnchanged(prev, g));
      setRunning(r);
      if (typeof q === "boolean") setQueued(q);
    },
    onEvent: (ev) => {
      pendingEvs.current.push(ev);
      if (flushRaf.current == null) {
        flushRaf.current = requestAnimationFrame(flushEvents);
      }
    },
  });

  useEffect(() => () => {
    clearTimeout(refetchTimer.current);
    if (flushRaf.current != null) cancelAnimationFrame(flushRaf.current);
  }, []);

  // 运行中兜底轮询：WS 丢包时关系图仍能跟上
  useEffect(() => {
    if (!id || !liveWs || !running || queued) return;
    const t = setInterval(() => {
      api.graph(id).then((g) => {
        setGraph((prev) => keepLayoutIfUnchanged(prev, g));
      }).catch(() => {});
    }, 8000);
    return () => clearInterval(t);
  }, [id, liveWs, running, queued]);

  /** 默认续跑（保留攻击图）。重新开题才清图。 */
  const startResume = async (): Promise<boolean> => {
    if (!id) return false;
    try {
      await api.start(id, false);
      setRunning(true);
      setQueued(true);
      return true;
    } catch (e: any) {
      setLoadErr(String(e?.message || e || "启动失败"));
      return false;
    }
  };
  const startHardRestart = async () => {
    if (!id) return;
    const tip = "重新开题将清空攻击图；已提交的 flag 与历史日志会保留。确认？";
    if (!window.confirm(tip)) return;
    try {
      await api.start(id, true);
      setRunning(true);
      setQueued(true);
    } catch (e: any) {
      setLoadErr(String(e?.message || e || "重新开题失败"));
    }
  };
  const start = async () => { await startResume(); };
  const stop = async () => { if (id) { await api.stop(id).catch(() => {}); setRunning(false); } };
  const handleSend = async (msg: string) => {
    if (!id) return;
    if (!running) {
      const ok = await startResume();
      if (!ok) return;
      await new Promise((r) => setTimeout(r, 300));
    }
    send({ type: "steer", content: msg });
  };

  const onSelect = (n: GraphNode) => { setSelected(n); };

  if (!project) {
    return (
      <div className="container" style={{ paddingTop: 40 }}>
        <p className={loadErr ? "" : "muted"} style={loadErr ? { color: "var(--error)" } : undefined}>
          {loadErr || "加载中…"}
        </p>
      </div>
    );
  }
  if (project.kind === "benchmark") return <BenchmarkDashboard project={project} />;
  if (project.kind !== "single") {
    return <ClusterDashboard project={project} onProjectUpdate={setProject} />;
  }

  const isFlag = project.config?.objective === "flag" || project.config?.track === "ctf";
  const isSrc = project.config?.objective === "src" || project.config?.track === "src";
  const visibleFindings = collectVulns(graph.findings, graph.nodes, { src: isSrc });
  const visibleHigh = visibleFindings.filter(
    (f) => displayFindingSeverity(f) === "high",
  ).length;
  const visibleCritical = visibleFindings.filter(
    (f) => displayFindingSeverity(f) === "critical",
  ).length;
  const serviceCount = graph.nodes.filter((n) => n.type === "service").length;
  const supervisorCount = countSupervisorRecords(events);
  const statusColor: Record<string, string> = { running: colors.success, queued: colors.warning, completed: colors.primary, idle: colors.mutedSoft, error: colors.error, stopped: colors.muted };
  const statusLabel: Record<string, string> = { running: "运行中", queued: "排队中", completed: "已完成", idle: "空闲", error: "失败", stopped: "已停止", goal_reached: "已完成" };
  const shownStatus = queued ? "queued" : running ? "running" : (huntFailedReason(project) ? "error" : (project.status || "idle"));
  const needed = Number(project.config?.flag_count) || 1;
  const canResume = (graph.stats?.nodes || 0) > 0 || events.length > 0;
  const flagsCorrect = graph.nodes.filter((n) =>
    n.type === "goal" && (
      String(n.key || "").startsWith("goal:flag")
      || (n.tags || []).some((t) => t === "flag" || t === "getflag")
    )
  ).length;
  const totalScore = Number(project.config?.total_score) || 0;
  const ctfFull = isFlag && flagsCorrect >= needed;
  const ctfProgress = isFlag
    ? `${flagsCorrect}/${needed}${totalScore ? ` · ${totalScore}` : ""}`
    : "";
  const stopReason = !running ? project.config?.completion_reason : "";

  return (
    <div className="container" style={{ paddingTop: 24, paddingBottom: 40 }}>
      <div ref={headRef}>
        <Link to={project.parent_id ? `/project/${project.parent_id}` : "/"} className="muted" style={{ fontSize: 13 }}>
          &larr; {project.parent_id ? "返回上级集群" : "返回项目列表"}
        </Link>
        <div className="project-head">
          <div>
            <div className="row" style={{ gap: 10 }}>
              <h1 style={{ fontSize: 34 }}>{project.name}</h1>
              {isFlag ? (
                ctfFull
                  ? <span className="badge badge-coral" style={{ fontSize: 13 }}>已完成 {ctfProgress}</span>
                  : flagsCorrect > 0
                    ? <span className="badge" style={{ fontSize: 13 }}>{ctfProgress} 未满分</span>
                    : null
              ) : isSrc ? (
                (visibleHigh + visibleCritical) > 0
                  ? <span className="badge" style={{ fontSize: 13 }}>已验证高危 {visibleHigh + visibleCritical}</span>
                  : null
              ) : (
                graph.stats.has_shell && <span className="badge badge-coral" style={{ fontSize: 13 }}>GETSHELL 已达成</span>
              )}
              {!isSrc && graph.stats.lateral_active && (
                <span className="badge" style={{ fontSize: 13, background: "rgba(109,92,240,0.14)", color: "#4a3fb0", border: "1px solid #6d5cf0" }}>
                  内网横向{graph.stats.hosts_footed ? ` · ${graph.stats.hosts_footed} 台` : ""}
                </span>
              )}
            </div>
            <div className="row" style={{ gap: 12, marginTop: 6 }}>
              <span className="mono muted" style={{ fontSize: 14 }}>{project.target || "集群"}</span>
              <span className="row" style={{ gap: 6 }}>
                <span className="pulse-dot" style={{ background: statusColor[shownStatus] || colors.muted }} />
                <span className="muted" style={{ fontSize: 13 }}>{statusLabel[shownStatus] || shownStatus}</span>
                {queued ? (
                  <span className="badge" style={{ background: "rgba(217,190,132,0.16)", color: "#d9be84", borderColor: "rgba(217,190,132,0.35)" }} title="已启动，等待本赛道（红队/SRC 或 CTF）并发槽空出后才会真正开跑">等并发槽</span>
                ) : null}
                {stopReason === "entry_dead" ? (
                  <span className="badge" style={{ background: "rgba(217,190,132,0.16)", color: "#d9be84", borderColor: "rgba(217,190,132,0.35)" }} title="入口连续不可达；站点恢复后可再启动">入口不可达</span>
                ) : null}
                {stopReason === "env_closed" || stopReason === "env_unreachable" || project.config?.env_closed ? (
                  <span className="badge" style={{ background: "rgba(198,69,69,.12)", color: "#c64545", borderColor: "rgba(198,69,69,.35)" }} title="评测任务已到期或平台不可达，已停止空转">环境已到期</span>
                ) : null}
              </span>
              {isFlag ? (
                <span className="muted" style={{ fontSize: 13 }} title="CTF 只看正确 flag 收工">
                  正确 flag <b style={{ color: colors.primary }}>{flagsCorrect}/{needed}</b>
                </span>
              ) : isSrc ? (
                <span className="muted" style={{ fontSize: 13 }} title="SRC 看已验证高危/严重，单条不停工">
                  高危/严重 <b style={{ color: colors.primary }}>{visibleHigh + visibleCritical}</b>
                </span>
              ) : null}
              <span
                className="muted"
                style={{ fontSize: 13 }}
                title="沿橙线各边 weight 的乘积，只给控制台看。不是校准过的 getshell/夺旗概率，不参与调度、收工或御主决策。"
              >
                RCE 概率 ≈ <b style={{ color: colors.primary }}>{graph.rce_path?.likelihood ?? 0}</b>
              </span>
            </div>
          </div>
          <div className="project-head-metrics">
            <div className="project-head-stats">
              <Stat value={graph.stats.nodes} label="节点" />
              <Stat value={visibleFindings.length} label="漏洞" />
              <Stat value={visibleHigh} label="高危" warn={visibleHigh > 0} />
              <Stat value={visibleCritical} label="严重" danger={visibleCritical > 0} />
              <Stat value={graph.stats.frontier_open || graph.frontier?.open || 0} label="前沿" />
            </div>
            <div className="project-head-actions">
              {id ? <ReportExportControls projectId={id} /> : null}
              {running ? <button className="btn btn-danger" onClick={stop}>停止</button> : (
                canResume && isFlag ? (
                  <button className="btn btn-ghost" onClick={startHardRestart} title="清空攻击图后重新开题">重新开题</button>
                ) : null
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="project-split">
        <div className="project-graph-pane">
          <AttackGraph graph={graph} onSelect={onSelect} selectedKey={selected?.key} onClear={() => setSelected(null)} />
        </div>
        <div className="card-cream project-side-pane">
          <div className="tabs project-side-tabs">
            {([["timeline", "时间线"], ["findings", `漏洞 ${visibleFindings.length || ""}`], ["services", `发现的服务 ${serviceCount || ""}`], ["memory", "自进化"], ["supervisor", `自监督 ${supervisorCount || ""}`]] as const).map(([k, label]) => (
              <div key={k} className={`tab ${tab === k ? "active" : ""}`} onClick={() => setTab(k)}>{label}</div>
            ))}
          </div>
          <div className="project-side-body">
            {selected && (
              <div className="project-node-detail">
                <NodeDetail node={graph.nodes.find((n) => n.key === selected.key) || selected} graph={graph} />
              </div>
            )}
            {tab === "timeline" && <Timeline events={events} />}
            {tab === "findings" && (
              <FindingsPanel
                projectId={id!}
                findings={graph.findings}
                nodes={graph.nodes}
                onSelectNode={onSelect}
                src={isSrc}
              />
            )}
            {tab === "services" && <ServicesPanel graph={graph} onSelect={onSelect} />}
            {tab === "memory" && <MemoryPanel projectId={id!} />}
            {tab === "supervisor" && <SupervisorPanel events={events} />}
          </div>
        </div>
      </div>

      <div style={{ marginTop: 20 }}>
        <ChatDock events={events} running={running} queued={queued} onSend={handleSend} onStart={start} onStop={stop} startLabel={canResume ? "继续渗透" : "启动自动渗透"} />
      </div>
    </div>
  );
}

function Stat({ value, label, danger, warn }: { value: number; label: string; danger?: boolean; warn?: boolean }) {
  const ref = useRef<HTMLSpanElement>(null);
  const prev = useRef(0);
  useEffect(() => {
    if (ref.current && value !== prev.current) {
      countUp(ref.current, value, 600);
      prev.current = value;
    }
  }, [value]);
  const color = danger ? colors.error : warn ? colors.warning : colors.ink;
  return (
    <div className="stack" style={{ alignItems: "center" }}>
      <span ref={ref} className="serif" style={{ fontSize: 30, color }}>{value}</span>
      <span className="muted" style={{ fontSize: 12 }}>{label}</span>
    </div>
  );
}
