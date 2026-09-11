/** 列表/集群筛选：配置了图空转/轮次/时长上限并触顶时进「失败」，不进「未完成」。 */
export const HUNT_FAILED_REASONS = new Set(["graph_idle", "runtime_cap", "turn_cap"]);

export function huntFailedReason(p: { config?: { completion_reason?: string } | null } | null | undefined): string | undefined {
  const r = p?.config?.completion_reason;
  if (r && HUNT_FAILED_REASONS.has(r)) return r;
  return undefined;
}

function formatDur(sec: number): string {
  const n = Math.max(0, Math.floor(sec || 0));
  if (n <= 0) return "0";
  if (n % 3600 === 0) return `${n / 3600} 小时`;
  if (n % 60 === 0) return `${n / 60} 分钟`;
  if (n >= 3600) {
    const h = Math.floor(n / 3600);
    const m = Math.floor((n % 3600) / 60);
    return m ? `${h} 小时 ${m} 分` : `${h} 小时`;
  }
  return `${Math.floor(n / 60)} 分`;
}

/** 项目页/集群页展示硬停条件；运行中附已跑时长。 */
export function hardStopLine(p: {
  hard_stop?: { label?: string; conditions?: string[]; runtime_sec?: number } | null;
  config?: { hunt?: { elapsed_sec?: number } | null } | null;
} | null | undefined): { text: string; title: string; conditions: string[] } | null {
  const hs = p?.hard_stop;
  const label = String(hs?.label || "").trim();
  if (!label) return null;
  const elapsed = Number(p?.config?.hunt?.elapsed_sec || 0);
  const cap = Number(hs?.runtime_sec || 0);
  const ran = cap > 0 && elapsed > 0 ? `已跑 ${formatDur(elapsed)} / ${formatDur(cap)}` : "";
  const conditions = (hs?.conditions || []).map((c) => String(c || "").trim()).filter(Boolean);
  return {
    text: ran ? `${label} ${ran}` : label,
    title: conditions.join("；"),
    conditions,
  };
}

/** 顶栏/列表筛选桶：running / completed / idle / stopped / error */
export function listStatusOf(p: {
  running?: boolean;
  queued?: boolean;
  status?: string;
  config?: { completion_reason?: string } | null;
}): string {
  if (p.queued || p.running || p.status === "running") return "running";
  if (huntFailedReason(p)) return "error";
  if (p.status === "goal_reached" || p.status === "completed") return "completed";
  if (p.status === "error") return "error";
  if (p.status === "stopped") return "stopped";
  return "idle";
}
