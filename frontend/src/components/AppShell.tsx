import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { TopNav } from "./TopNav";
import { Spike } from "./Spike";
import { api } from "../api";
import type { AppVersion } from "../types";

type IconName = "projects" | "plus" | "settings" | "collapse";

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (name === "projects") return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 8h10M7 12h10M7 16h6" /></svg>;
  if (name === "plus") return <svg {...common}><path d="M12 5v14M5 12h14" /></svg>;
  if (name === "settings") return <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.12 2.12-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.03 1.56V20h-3v-.08A1.7 1.7 0 0 0 10.68 18.36a1.7 1.7 0 0 0-1.88.34l-.06.06-2.12-2.12.06-.06A1.7 1.7 0 0 0 7.02 14.7 1.7 1.7 0 0 0 5.46 13.7H5v-3h.08a1.7 1.7 0 0 0 1.56-1.03 1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.12-2.12.06.06a1.7 1.7 0 0 0 1.88.34A1.7 1.7 0 0 0 11.3 4.46V4h3v.08a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.88-.34l.06-.06 2.12 2.12-.06.06a1.7 1.7 0 0 0-.34 1.88 1.7 1.7 0 0 0 1.56 1.03H20v3h-.08A1.7 1.7 0 0 0 18.36 14.4Z" /></svg>;
  return <svg {...common}><path d="M15 18l-6-6 6-6" /></svg>;
}

function fmtVer(raw?: string | null): string {
  const s = String(raw || "").trim();
  if (!s) return "";
  return s.toLowerCase().startsWith("v") ? s : `v${s}`;
}

function statusText(v: AppVersion | null, busy: boolean): string {
  if (busy) return "正在检查…";
  if (!v) return "正在检查…";
  if (v.status === "update_available") {
    return v.latest ? `有新版本 ${fmtVer(v.latest)}` : "有新版本";
  }
  return "已是最新";
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("atkbrain_sidebar_collapsed") === "1");
  const [ver, setVer] = useState<AppVersion | null>(null);
  const [busy, setBusy] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => localStorage.setItem("atkbrain_sidebar_collapsed", collapsed ? "1" : "0"), [collapsed]);
  useEffect(() => {
    api.health().then((h: any) => {
      const localVer = String(h?.version || "");
      if (!localVer) return;
      setVer((cur) => cur || { local: localVer, is_latest: true, status: "latest", message: "已是最新" });
    }).catch(() => {});
    const load = () => api.version().then(setVer).catch(() => {});
    load();
    const t = setInterval(load, 10 * 60 * 1000);
    return () => clearInterval(t);
  }, []);
  const create = () => navigate("/?create=1");
  const onProjects = location.pathname === "/";
  const local = fmtVer(ver?.local) || "v—";
  const hasUpdate = ver?.status === "update_available";
  const line = statusText(ver, busy);
  const verTitle = hasUpdate
    ? `${local} · ${line}（本系统不自动更新）`
    : `${local} · ${line}`;

  const refresh = async () => {
    setBusy(true);
    try {
      setVer(await api.version(true));
    } catch {
      /* 检查失败时保持本机版本展示 */
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
      <aside className="app-sidebar">
        <div className="sidebar-brand">
          <Spike />
          {!collapsed && (
            <div>
              <strong>AtkBrain-Flash</strong>
              <small>StrikeAgent</small>
            </div>
          )}
        </div>
        <nav className="sidebar-nav" aria-label="主导航">
          <button className="sidebar-link sidebar-create" onClick={create} title="新建项目">
            <Icon name="plus" /><span>新建项目</span>
          </button>
          <Link to="/" className={`sidebar-link ${onProjects ? "active" : ""}`} title="所有项目">
            <Icon name="projects" /><span>所有项目</span>
          </Link>
          <Link to="/settings" className={`sidebar-link ${location.pathname === "/settings" ? "active" : ""}`} title="设置">
            <Icon name="settings" /><span>设置</span>
          </Link>
        </nav>
        <div className={`sidebar-version${hasUpdate ? " has-update" : ""}`} title={verTitle}>
          <button type="button" className="sidebar-version-hit" onClick={refresh} disabled={busy} title={collapsed ? verTitle : "检查是否有新版本"}>
            <span className="sidebar-version-dot" aria-hidden />
            <span className="sidebar-version-num">{local}</span>
            <span className="sidebar-version-status">{line}</span>
          </button>
          {hasUpdate && ver?.html_url && !collapsed ? (
            <a className="sidebar-version-hint" href={ver.html_url} target="_blank" rel="noreferrer">查看发行说明</a>
          ) : null}
        </div>
        <button className="sidebar-toggle" onClick={() => setCollapsed((v) => !v)} title={collapsed ? "展开菜单" : "收起菜单"} aria-label={collapsed ? "展开菜单" : "收起菜单"}>
          <Icon name="collapse" />
        </button>
      </aside>
      <section className="app-workspace">
        <TopNav />
        <main className="app-main">{children}</main>
      </section>
    </div>
  );
}
