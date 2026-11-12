import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { TopNav } from "./TopNav";
import { Spike } from "./Spike";
import { api } from "../api";
import type { AppVersion } from "../types";
import { useAuth } from "../AuthGate";
import { useT } from "../i18n";
import { consumeShowUpdate, UpdateModal } from "./UpdateModal";
import { HuntViewProvider } from "../features/chat/huntView";
import { ToolExplain } from "../features/chat/ToolExplain";

type IconName = "projects" | "plus" | "settings" | "collapse" | "logout" | "vulns" | "account" | "model" | "hunt" | "review" | "proxy" | "guard";

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  if (name === "projects") return <svg {...common}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 8h10M7 12h10M7 16h6" /></svg>;
  if (name === "vulns") return <svg {...common}><path d="M12 3l8 4v6c0 5-3.4 7.6-8 9-4.6-1.4-8-4-8-9V7z" /><path d="M9 12l2 2 4-4" /></svg>;
  if (name === "plus") return <svg {...common}><path d="M12 5v14M5 12h14" /></svg>;
  if (name === "settings") return <svg {...common}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.12 2.12-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.03 1.56V20h-3v-.08A1.7 1.7 0 0 0 10.68 18.36a1.7 1.7 0 0 0-1.88.34l-.06.06-2.12-2.12.06-.06A1.7 1.7 0 0 0 7.02 14.7 1.7 1.7 0 0 0 5.46 13.7H5v-3h.08a1.7 1.7 0 0 0 1.56-1.03 1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.12-2.12.06.06a1.7 1.7 0 0 0 1.88.34A1.7 1.7 0 0 0 11.3 4.46V4h3v.08a1.7 1.7 0 0 0 1.03 1.56 1.7 1.7 0 0 0 1.88-.34l.06-.06 2.12 2.12-.06.06a1.7 1.7 0 0 0-.34 1.88 1.7 1.7 0 0 0 1.56 1.03H20v3h-.08A1.7 1.7 0 0 0 18.36 14.4Z" /></svg>;
  if (name === "account") return <svg {...common}><circle cx="12" cy="8" r="3" /><path d="M5 19c1.5-3 3.8-4.5 7-4.5S17.5 16 19 19" /></svg>;
  if (name === "model") return <svg {...common}><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M8 9h8M8 13h5" /></svg>;
  if (name === "hunt") return <svg {...common}><circle cx="12" cy="12" r="7" /><circle cx="12" cy="12" r="2" /><path d="M12 3v2M12 19v2M3 12h2M19 12h2" /></svg>;
  if (name === "review") return <svg {...common}><path d="M5 12l4 4 10-10" /><path d="M4 19h16" /></svg>;
  if (name === "proxy") return <svg {...common}><circle cx="12" cy="12" r="8" /><path d="M4 12h16M12 4c2.5 2.8 2.5 13.2 0 16M12 4c-2.5 2.8-2.5 13.2 0 16" /></svg>;
  if (name === "guard") return <svg {...common}><path d="M12 3l7 3v6c0 4.5-3 6.8-7 8-4-1.2-7-3.5-7-8V6z" /></svg>;
  if (name === "logout") return <svg {...common}><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="M16 17l5-5-5-5" /><path d="M21 12H9" /></svg>;
  return <svg {...common}><path d="M15 18l-6-6 6-6" /></svg>;
}

function fmtVer(raw?: string | null): string {
  const s = String(raw || "").trim();
  if (!s) return "";
  return s.toLowerCase().startsWith("v") ? s : `v${s}`;
}

function splitVer(raw?: string | null): { core: string; pre: string } {
  const s = fmtVer(raw) || "v—";
  const cut = s.search(/[-+]/);
  if (cut < 0) return { core: s, pre: "" };
  return { core: s.slice(0, cut), pre: s.slice(cut).replace(/^[-+]/, "") };
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const { t } = useT();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("atkbrain_sidebar_collapsed") === "1");
  const [ver, setVer] = useState<AppVersion | null>(null);
  const [busy, setBusy] = useState(false);
  const [updateOpen, setUpdateOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  const { me, logout } = useAuth();
  useEffect(() => localStorage.setItem("atkbrain_sidebar_collapsed", collapsed ? "1" : "0"), [collapsed]);
  useEffect(() => {
    api.health().then((h: any) => {
      const localVer = String(h?.version || "");
      if (!localVer) return;
      setVer((cur) => cur || { local: localVer, is_latest: false, status: "checking", message: t("shell.checking") });
    }).catch(() => {});
    const applyVer = (v: AppVersion) => {
      setVer(v);
      if (v.status === "update_available" && consumeShowUpdate()) setUpdateOpen(true);
    };
    const load = () => api.version().then(applyVer).catch(() => {});
    load();
    const timer = setInterval(load, 10 * 60 * 1000);
    return () => clearInterval(timer);
  }, [t]);

  const statusText = (v: AppVersion | null, checking: boolean): string => {
    if (checking || !v || v.status === "checking") return t("shell.checking");
    if (v.status === "update_available") return t("shell.updateReady");
    return t("shell.latest");
  };

  const create = () => navigate("/?create=1");
  const onProjects = location.pathname === "/";
  const onVulns = location.pathname === "/vulns";
  const local = fmtVer(ver?.local) || "v—";
  const parts = splitVer(ver?.local);
  const hasUpdate = ver?.status === "update_available";
  const isLatest = !busy && ver?.status === "latest";
  const checking = busy || !ver || ver.status === "checking";
  const line = statusText(ver, busy);
  const latestLabel = fmtVer(ver?.latest || ver?.latest_tag);
  const hint = checking
    ? t("shell.checkingHint")
    : hasUpdate
      ? t("shell.updateHint", { ver: latestLabel || t("shell.latestVersion") })
      : t("shell.latestHint");
  const verTitle = hasUpdate && latestLabel
    ? `${local} · ${t("shell.updateAvailableVer", { ver: latestLabel })}`
    : `${local} · ${line}`;
  const versionClass = [
    "sidebar-version",
    hasUpdate ? "has-update" : "",
    isLatest ? "is-latest" : "",
    checking ? "is-checking" : "",
  ].filter(Boolean).join(" ");

  const refresh = async () => {
    if (hasUpdate && !busy) {
      setUpdateOpen(true);
      return;
    }
    setBusy(true);
    try {
      const v = await api.version(true);
      setVer(v);
      if (v.status === "update_available") setUpdateOpen(true);
    } catch {
      /* keep local version */
    } finally {
      setBusy(false);
    }
  };

  return (
    <HuntViewProvider>
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
        <nav className="sidebar-nav" aria-label={t("shell.nav")}>
          <button className="sidebar-link sidebar-create" onClick={create} title={t("shell.newProject")}>
            <Icon name="plus" /><span>{t("shell.newProject")}</span>
          </button>
          <Link to="/" className={`sidebar-link ${onProjects ? "active" : ""}`} title={t("shell.allProjects")}>
            <Icon name="projects" /><span>{t("shell.allProjects")}</span>
          </Link>
          <Link to="/vulns" className={`sidebar-link ${onVulns ? "active" : ""}`} title={t("shell.vulns")}>
            <Icon name="vulns" /><span>{t("shell.vulns")}</span>
          </Link>
          {([
            ["account", "account", t("settings.navAccount")],
            ["model", "model", t("settings.navModel")],
            ["hunt", "hunt", t("settings.navHunt")],
            ["review", "review", t("settings.navReview")],
            ["proxy", "proxy", t("settings.navProxy")],
            ["guard", "guard", t("settings.navGuard")],
          ] as const).map(([id, icon, label]) => (
            <Link
              key={id}
              to={`/settings/${id}`}
              className={`sidebar-link ${location.pathname === `/settings/${id}` ? "active" : ""}`}
              title={label}
            >
              <Icon name={icon} /><span>{label}</span>
            </Link>
          ))}
          {me?.authenticated ? (
            <button
              className="sidebar-link"
              title={t("shell.logoutTitle")}
              onClick={() => {
                void logout().then(() => navigate("/login", { replace: true }));
              }}
            >
              <Icon name="logout" /><span>{t("shell.logout")}{me.username ? ` · ${me.username}` : ""}</span>
            </button>
          ) : null}
        </nav>
        <div className={versionClass} title={verTitle}>
          <button type="button" className="sidebar-version-hit" onClick={refresh} disabled={busy} title={collapsed ? verTitle : (hasUpdate ? t("shell.releaseNotes") : t("shell.checkVersion"))}>
            <span className="sidebar-version-kicker">
              <span className="sidebar-version-lamp" aria-hidden />
              {t("shell.buildKicker")}
            </span>
            <span className="sidebar-version-num">
              <span className="sidebar-version-core">{parts.core}</span>
              {parts.pre ? <span className="sidebar-version-pre">{parts.pre}</span> : null}
            </span>
            <span className="sidebar-version-pill">
              <span className="sidebar-version-dot" aria-hidden />
              <span className="sidebar-version-status">{line}</span>
            </span>
            {!collapsed ? (
              <span className="sidebar-version-hint">{hint}</span>
            ) : null}
          </button>
        </div>
        <button className="sidebar-toggle" onClick={() => setCollapsed((v) => !v)} title={collapsed ? t("shell.expand") : t("shell.collapse")} aria-label={collapsed ? t("shell.expand") : t("shell.collapse")}>
          <Icon name="collapse" />
        </button>
      </aside>
      <section className="app-workspace">
        <TopNav />
        <main className="app-main">{children}</main>
      </section>
      {updateOpen && ver?.status === "update_available" ? (
        <UpdateModal ver={ver} onClose={() => setUpdateOpen(false)} />
      ) : null}
      <ToolExplain />
    </div>
    </HuntViewProvider>
  );
}
