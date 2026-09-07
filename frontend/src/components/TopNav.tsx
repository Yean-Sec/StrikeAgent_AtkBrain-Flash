import { useEffect, useState } from "react";
import { api } from "../api";

interface ClaudeInfo {
  active: number;
  limit: number;
  cap: number;
  per_project: number;
}
interface Health {
  active: number;
  concurrency_limit: number;
  cap: number;
  claude?: ClaudeInfo;
  claude_sdk?: { state: "ready" | "unavailable"; label?: string };
}

export function TopNav() {
  const [h, setH] = useState<Health | null>(null);

  useEffect(() => {
    const load = () => api.health().then((r) => setH(r)).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const changeProjects = async (v: number) => {
    const r = await api.setConcurrency(v).catch(() => null);
    if (r) setH((c) => (c ? { ...c, concurrency_limit: r.concurrency_limit, claude: r.claude ?? c.claude } : c));
  };

  const cl = h?.claude;

  return (
    <div className="topnav">
      <div className="workspace-title">控制台 <span>实时项目与攻击图谱</span></div>
      <div className="nav-meta">
        {h && (
          <div className="row" style={{ gap: 12 }}>
            <div className="row status-control" style={{ gap: 6 }} title="真正占用并发槽、正在渗透的项目数 / 上限。多点的启动会在槽满时排队，不算进左边的 active；把右侧数字调高即可放行排队项目。">
              <span className="pulse-dot" style={{ background: h.active > 0 ? "var(--success)" : "var(--muted-soft)" }} />
              <span>并发项目 {h.active}/{h.concurrency_limit}</span>
              <select
                className="select"
                style={{ width: 56, padding: "4px 6px", fontSize: 12 }}
                value={h.concurrency_limit}
                onChange={(e) => changeProjects(Number(e.target.value))}
              >
                {Array.from({ length: h.cap }).map((_, i) => (
                  <option key={i + 1} value={i + 1}>{i + 1}</option>
                ))}
              </select>
            </div>
            {cl && (
              <div className="row status-control" style={{ gap: 6 }} title="Claude Code：每项目 2 个（主会话 + 自监督）。10 个项目即 20 个。">
                <span className="pulse-dot" style={{ background: h.claude_sdk?.state === "unavailable" ? "var(--error)" : "var(--success)" }} />
                <span>{h.claude_sdk?.label || "Claude Code 连接正常"}</span>
                <span className="muted" style={{ fontSize: 11 }}>· {cl.active}/{cl.limit}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
