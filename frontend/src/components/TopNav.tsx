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

interface ProxyInfo {
  enabled: boolean;
  live: number;
  fetching: boolean;
  exit_ip?: string | null;
  error?: string | null;
}

export function TopNav() {
  const [h, setH] = useState<Health | null>(null);
  const [px, setPx] = useState<ProxyInfo | null>(null);

  useEffect(() => {
    const load = () => api.health().then((r) => setH(r)).catch(() => {});
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const load = () => api.proxyStatus().then((r) => setPx(r)).catch(() => {});
    load();
    const t = setInterval(load, 2000);
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

  const toggleProxy = async () => {
    const next = !(px?.enabled);
    const r = await api.setProxyEnabled(next).catch(() => null);
    if (r) setPx({
      enabled: !!r.enabled,
      live: Number(r.live || 0),
      fetching: !!r.fetching,
      exit_ip: r.exit_ip,
    });
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
        <div className="row" style={{ gap: 12 }}>
        {h && (
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
        )}
            <div
              className="row status-control"
              style={{ gap: 8 }}
              title={px?.error
                ? String(px.error)
                : "红队/SRC 打目标必须走出口代理；关开关才会直连并暴露真实 IP。CTF 始终直连。"}
            >
              <button
                type="button"
                className={`proxy-switch${px?.enabled ? " is-on" : ""}`}
                aria-pressed={!!px?.enabled}
                onClick={() => { void toggleProxy(); }}
              >
                <span className="proxy-switch-knob" />
              </button>
              <span>代理 存活 {px?.live ?? 0}</span>
              <span
                className={`proxy-spin${px?.fetching ? " is-on" : ""}`}
                aria-label={px?.fetching ? "正在持续获取代理" : "代理已关闭"}
              />
            </div>
            {h?.claude_sdk && (
              <div className="row status-control" style={{ gap: 6 }} title="Pi 就绪状态。本机进程数仅展示，项目内工人不设上限。">
                <span className="pulse-dot" style={{ background: h.claude_sdk?.state === "unavailable" ? "var(--error)" : "var(--success)" }} />
                <span>{h.claude_sdk?.label || "Pi 就绪"}</span>
                {(cl?.active ?? 0) > 0 && (
                  <span className="muted" style={{ fontSize: 11 }}>· {cl?.active} 进程</span>
                )}
              </div>
            )}
        </div>
      </div>
    </div>
  );
}
