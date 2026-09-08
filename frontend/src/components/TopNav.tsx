import { useEffect, useState } from "react";
import { api } from "../api";

interface TrackSlots {
  active: number;
  limit: number;
  cap: number;
}
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
  redteam?: TrackSlots;
  ctf?: TrackSlots;
  claude?: ClaudeInfo;
  claude_sdk?: { state: "ready" | "unavailable"; label?: string };
}

function SlotSelect({
  value,
  cap,
  onChange,
}: {
  value: number;
  cap: number;
  onChange: (n: number) => void;
}) {
  return (
    <select
      className="select"
      style={{ width: 56, padding: "4px 6px", fontSize: 12 }}
      value={value}
      onChange={(e) => onChange(Number(e.target.value))}
    >
      {Array.from({ length: Math.max(1, cap) }).map((_, i) => (
        <option key={i + 1} value={i + 1}>{i + 1}</option>
      ))}
    </select>
  );
}

export function TopNav() {
  const [h, setH] = useState<Health | null>(null);

  useEffect(() => {
    const load = () => api.health().then((r) => setH(r)).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  const applySnap = (r: any) => {
    if (!r) return;
    setH((c) => (c ? {
      ...c,
      concurrency_limit: r.concurrency_limit ?? c.concurrency_limit,
      cap: r.cap ?? c.cap,
      redteam: r.redteam ?? c.redteam,
      ctf: r.ctf ?? c.ctf,
      claude: r.claude ?? c.claude,
    } : c));
  };

  const changeTrack = async (track: "redteam" | "ctf", v: number) => {
    const r = await api.setConcurrency(v, track).catch(() => null);
    applySnap(r);
  };

  const cl = h?.claude;
  const rt = h?.redteam;
  const ctf = h?.ctf;
  const rtActive = rt?.active ?? 0;
  const ctfActive = ctf?.active ?? 0;

  return (
    <div className="topnav">
      <div className="workspace-title">控制台 <span>实时项目与攻击图谱</span></div>
      <div className="nav-meta">
        {h && (
          <div className="row" style={{ gap: 12 }}>
            <div
              className="row status-control"
              style={{ gap: 8 }}
              title="红队与 CTF 各有独立项目槽，互不占用。多点的启动会在本赛道槽满时排队。Claude Code 栏显示两道合计。"
            >
              <span className="pulse-dot" style={{ background: (rtActive + ctfActive) > 0 ? "var(--success)" : "var(--muted-soft)" }} />
              <span>红队 {rtActive}/{rt?.limit ?? "-"}</span>
              {rt && (
                <SlotSelect
                  value={rt.limit}
                  cap={rt.cap}
                  onChange={(n) => changeTrack("redteam", n)}
                />
              )}
              <span>CTF {ctfActive}/{ctf?.limit ?? "-"}</span>
              {ctf && (
                <SlotSelect
                  value={ctf.limit}
                  cap={ctf.cap}
                  onChange={(n) => changeTrack("ctf", n)}
                />
              )}
            </div>
            {cl && (
              <div className="row status-control" style={{ gap: 6 }} title="编排会话合计：红队项目 + CTF 项目，每项目 2 个（从者 + 御主）。子智能体不设上限。">
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
