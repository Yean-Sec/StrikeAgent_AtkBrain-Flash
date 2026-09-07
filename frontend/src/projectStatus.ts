/** 列表/集群筛选：配置了图空转/轮次/时长上限并触顶时进「失败」，不进「未完成」。 */
export const HUNT_FAILED_REASONS = new Set(["graph_idle", "runtime_cap", "turn_cap"]);

export function huntFailedReason(p: { config?: { completion_reason?: string } | null } | null | undefined): string | undefined {
  const r = p?.config?.completion_reason;
  if (r && HUNT_FAILED_REASONS.has(r)) return r;
  return undefined;
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
