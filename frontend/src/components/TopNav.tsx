import { useEffect, useState } from "react";
import { api } from "../api";

interface TrackSlots {
  active: number;
  limit: number;
  cap: number;
}
interface PiInfo {
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
  claude?: PiInfo;
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
              title="红队与 SRC 共用项目槽，CTF 另有独立槽，互不占用。多点的启动会在本赛道槽满时排队。已开项目内工人数不因顶栏变化被杀掉。"
            >
              <span className="pulse-dot" style={{ background: (rtActive + ctfActive) > 0 ? "var(--success)" : "var(--muted-soft)" }} />
              <span>红队/SRC {rtActive}/{rt?.limit ?? "-"}</span>
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
            {h.claude_sdk && (
              <div className="row status-control" style={{ gap: 6 }} title="Pi 就绪状态。本机进程数仅展示，项目内工人不设上限。">
                <span className="pulse-dot" style={{ background: h.claude_sdk?.state === "unavailable" ? "var(--error)" : "var(--success)" }} />
                <span>{h.claude_sdk?.label || "Pi 就绪"}</span>
                {(cl?.active ?? 0) > 0 && (
                  <span className="muted" style={{ fontSize: 11 }}>· {cl?.active} 进程</span>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
