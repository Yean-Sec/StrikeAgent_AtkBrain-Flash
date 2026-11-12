import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { api } from "../../api";
import { useT } from "../../i18n";
import type { RTEvent } from "../../types";
import { useHuntView } from "./huntView";

type Note = { role: "user" | "assistant" | "error"; text: string };

function openTools(events: RTEvent[]): RTEvent[] {
  const open: RTEvent[] = [];
  for (const ev of events) {
    if (ev.type === "tool") {
      open.push(ev);
      continue;
    }
    if (ev.type !== "tool_result") continue;
    const name = String(ev.payload?.tool || "");
    let idx = -1;
    for (let i = open.length - 1; i >= 0; i -= 1) {
      if (!name || String(open[i].payload?.tool || "") === name) {
        idx = i;
        break;
      }
    }
    if (idx >= 0) open.splice(idx, 1);
  }
  return open;
}

function summary(ev: RTEvent | null): string {
  if (!ev) return "";
  const command = String(ev.payload?.command || "").trim();
  if (command) return command;
  const url = String(ev.payload?.url || "").trim();
  if (url) return `${ev.payload?.method || "GET"} ${url}`.trim();
  return String(ev.payload?.tool || "");
}

function elapsedSec(ts: number | undefined, now: number): number {
  const raw = Number(ts || 0);
  if (!raw) return 0;
  const start = raw > 1e12 ? raw : raw * 1000;
  return Math.max(0, Math.floor((now - start) / 1000));
}

function recentOutput(events: RTEvent[], current: RTEvent | null): string {
  if (!current) return "";
  const start = events.lastIndexOf(current);
  for (let i = events.length - 1; i > start; i -= 1) {
    const ev = events[i];
    if (ev.type !== "tool_result") continue;
    const p = ev.payload || {};
    const text = [p.stdout_preview, p.stderr_preview, p.error, p.reason].filter(Boolean).join("\n");
    if (text.trim()) return text.slice(0, 4000);
  }
  return "";
}

function projectIdFrom(pathname: string): string {
  const match = pathname.match(/^\/project\/([^/]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

function pageName(pathname: string, t: (key: string) => string): string {
  if (pathname === "/" || pathname === "") return t("shell.allProjects");
  if (pathname.startsWith("/vulns")) return t("shell.vulns");
  if (pathname.startsWith("/settings/model")) return t("settings.navModel");
  if (pathname.startsWith("/settings/hunt")) return t("settings.navHunt");
  if (pathname.startsWith("/settings/review")) return t("settings.navReview");
  if (pathname.startsWith("/settings/proxy")) return t("settings.navProxy");
  if (pathname.startsWith("/settings/guard")) return t("settings.navGuard");
  if (pathname.startsWith("/settings")) return t("settings.navAccount");
  if (pathname.startsWith("/project/")) return t("project.toolRail");
  return pathname;
}

export function ToolExplain() {
  const { t } = useT();
  const { pathname } = useLocation();
  const { view } = useHuntView();
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const [question, setQuestion] = useState("");
  const [notes, setNotes] = useState<Note[]>([]);
  const [busy, setBusy] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const projectId = projectIdFrom(pathname);
  const onProject = Boolean(projectId) && view?.projectId === projectId;
  const events = onProject ? view!.events : [];
  const running = onProject ? view!.running : false;
  const tools = useMemo(() => (running ? openTools(events) : []), [events, running]);
  const current = tools.length ? tools[tools.length - 1] : null;
  const currentKey = current ? `${current.id || ""}:${summary(current)}` : "";

  useEffect(() => {
    setNotes([]);
    setQuestion("");
  }, [pathname]);

  useEffect(() => {
    if (open) {
      setShown(true);
      return;
    }
    if (!shown) return;
    const timer = window.setTimeout(() => setShown(false), 240);
    return () => window.clearTimeout(timer);
  }, [open, shown]);

  useEffect(() => {
    if (!currentKey) return;
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [currentKey]);

  useEffect(() => {
    const el = logRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [notes, busy, shown]);

  const ask = async () => {
    const text = question.trim();
    if (!text || busy) return;
    setBusy(true);
    setNotes((prev) => [...prev, { role: "user", text }]);
    setQuestion("");
    try {
      const res = await api.explain({
        question: text,
        command: summary(current),
        output: recentOutput(events, current),
        page: pageName(pathname, t),
        path: pathname,
        project_id: projectId,
      });
      setNotes((prev) => [...prev, { role: "assistant", text: res.reply || "" }]);
    } catch (e) {
      setNotes((prev) => [...prev, { role: "error", text: e instanceof Error ? e.message : String(e) }]);
    } finally {
      setBusy(false);
    }
  };

  const toolName = String(current?.payload?.tool || "");
  const inflight = Number(current?.payload?.cmd_inflight || (current ? 1 : 0));

  return (
    <div className={`tool-bubble ${current && !open ? "is-live" : ""}`}>
      {shown ? (
        <aside className={`tool-rail card-cream ${open ? "is-in" : "is-out"}`}>
          <div className="tool-rail-head">
            <strong>{t("project.toolRail")}</strong>
            <button className="btn btn-ghost btn-sm" type="button" onClick={() => setOpen(false)}>{t("project.toolCollapse")}</button>
          </div>
          {current ? (
            <div className="tool-rail-status">
              <div className="mono">{toolName}</div>
              <div className="tool-rail-cmd">{summary(current)}</div>
              <div className="muted">{elapsedSec(current.ts, now)}s · {inflight}</div>
            </div>
          ) : (
            <p className="muted">{projectId ? (running ? t("project.toolIdleRun") : t("project.toolNone")) : t("project.toolNonePage", { page: pageName(pathname, t) })}</p>
          )}
          <div className="tool-rail-log" ref={logRef}>
            {notes.map((note, i) => (
              <div key={i} className={`tool-chat-row ${note.role}`}>
                <div className={`chat-bubble ${note.role === "user" ? "chat-user" : note.role === "error" ? "chat-sys" : "chat-agent"}`}>{note.text}</div>
              </div>
            ))}
            {busy ? (
              <div className="tool-chat-row assistant">
                <div className="chat-bubble chat-agent tool-chat-thinking" aria-live="polite">
                  <span className="tool-think-dots" aria-hidden>
                    <i /><i /><i />
                  </span>
                  {t("project.toolThinking")}
                </div>
              </div>
            ) : null}
          </div>
          <div className="tool-rail-ask">
            <textarea
              className="input"
              rows={3}
              value={question}
              placeholder={t("project.toolAsk")}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== "Enter" || e.shiftKey || e.nativeEvent.isComposing) return;
                e.preventDefault();
                void ask();
              }}
            />
            <button className="btn btn-primary btn-sm" type="button" disabled={busy} onClick={() => { void ask(); }}>
              {t("project.toolSend")}
            </button>
          </div>
        </aside>
      ) : null}
      <button
        className={`tool-bubble-btn ${open ? "is-away" : ""}`}
        type="button"
        onClick={() => setOpen(true)}
        title={t("project.toolExpand")}
        aria-hidden={open}
        tabIndex={open ? -1 : 0}
      >
        ?
      </button>
    </div>
  );
}
