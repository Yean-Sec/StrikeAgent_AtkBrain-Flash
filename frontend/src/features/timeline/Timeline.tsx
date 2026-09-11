import { useEffect, useMemo, useRef } from "react";
import type { RTEvent } from "../../types";
import { displayFindingSeverity } from "../../theme";
import { coalesceStreamEvents } from "./coalesce";

const LABEL: Record<string, string> = {
  text: "分析", thought: "思考", tool: "工具", tool_result: "结果", finding: "发现",
  shell: "GETSHELL", steer: "指令", status: "状态", log: "日志", intent: "新意图", turn: "轮次结束", node: "节点", edge: "连接", rce_path: "路径", lateral: "内网横向", drift_alert: "漂移告警", finding_review: "二次验证",
};

function line(ev: RTEvent): string {
  const p = ev.payload || {};
  switch (ev.type) {
    case "text": return p.text?.slice(0, 300) || "";
    case "thought": return "💭 " + (p.message?.slice(0, 800) || "");
    case "tool": return `▶ ${p.tool}` + (p.command ? `: ${p.command}` : p.url ? `: ${p.method || ""} ${p.url}` : p.input ? `: ${p.input}` : "");
    case "tool_result": return p.tool === "run_cmd" ? `exit=${p.exit_code}${p.blocked ? " [已拦截]" : ""} ${(p.stdout_preview || p.reason || "").slice(0, 200)}` : `${p.status ?? ""} ${(p.preview || p.error || "").slice(0, 200)}`;
    case "finding": {
      const sev = displayFindingSeverity(p);
      return `${sev === "critical" ? "★ " : ""}[${sev}] ${p.title} (${p.category})`;
    }
    case "shell": return `🎯 GETSHELL! ${p.access || ""} ${(p.evidence || "").slice(0, 120)}`;
    case "lateral": return `🌐 内网横向已开始${p.hosts_footed ? ` · ${p.hosts_footed} 台主机` : ""}${p.pivot_edges ? ` · ${p.pivot_edges} 条跳板` : ""}`;
    case "finding_review": {
      const n = Number(p.count || (p.titles || []).length || 0);
      if (p.status === "running") return `🔎 专职 Pi 正在二次验证与红队评级 · ${n} 条`;
      return `🔎 本轮二次验证结束${n ? ` · ${n} 条` : ""}`;
    }
    case "drift_alert": return `⚠️ 疑似打偏[${p.category || ""}] ${(p.message || "").slice(0, 220)}`;
    case "steer": return `⚡ ${p.content}`;
    case "status": return `状态: ${p.status}${p.turn ? ` · 第 ${p.turn} 轮` : ""}`;
    case "log": return `${p.level === "error" ? "✖" : p.level === "warn" ? "⚠" : "ℹ"} ${p.message}`;
    case "intent": return `+ 意图: ${p.description}`;
    case "turn": return `— 轮次结束 (${p.num_turns ?? "?"} steps${p.total_cost_usd ? `, $${Number(p.total_cost_usd).toFixed(3)}` : ""})`;
    default: return JSON.stringify(p).slice(0, 160);
  }
}

function labelOf(ev: RTEvent): string {
  if (ev.type === "steer" && ev.payload?.source === "supervisor") return "御主";
  if (ev.type === "steer") return "人工指令";
  return LABEL[ev.type] || ev.type;
}

const CLS: Record<string, string> = { finding: "t-finding", shell: "t-shell", lateral: "t-shell", tool: "t-tool", steer: "t-steer", log: "t-error", drift_alert: "t-error", finding_review: "t-steer" };
const SKIP = new Set(["node", "edge", "rce_path", "supervisor"]);
/** 时间线只渲染最近 N 条，避免长跑项目 DOM 上千节点卡死 */
const MAX_SHOWN = 150;

export function Timeline({ events }: { events: RTEvent[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const shown = useMemo(() => {
    const filtered = coalesceStreamEvents(events).filter((e) => !SKIP.has(e.type) && LABEL[e.type]);
    return filtered.length > MAX_SHOWN ? filtered.slice(-MAX_SHOWN) : filtered;
  }, [events]);

  // 长跑时 shown 被截到 MAX_SHOWN，length 不再变；用末条 id/ts 触发滚到底，避免时间线看起来“卡住”
  const tailKey = shown.length ? (shown[shown.length - 1].id ?? shown[shown.length - 1].ts) : 0;
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [tailKey]);

  return (
    <div className="scroll-y" ref={ref} style={{ maxHeight: 520 }}>
      {shown.length === 0 && <p className="muted" style={{ fontSize: 14 }}>暂无活动。启动项目后，智能体的每一步都会实时显示在这里。</p>}
      {shown.map((ev) => (
        <div key={ev.id ?? `${ev.ts}-${ev.type}`} className={`timeline-item ${ev.type === "log" && ev.payload?.level !== "error" ? "" : CLS[ev.type] || ""}`}>
          <div style={{ fontSize: 11, color: "var(--muted)" }}>{labelOf(ev)}</div>
          <div style={{ fontSize: 13, whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{line(ev)}</div>
        </div>
      ))}
    </div>
  );
}
