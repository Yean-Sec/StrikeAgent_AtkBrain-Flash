import { useEffect, useMemo, useRef, useState } from "react";
import type { RTEvent } from "../../types";

interface Msg { role: "user" | "agent" | "sys"; text: string; id: string | number }

function toMessages(events: RTEvent[]): Msg[] {
  const out: Msg[] = [];
  let lastSupervisor = "";
  for (const ev of events) {
    const p = ev.payload || {};
    const id = ev.id ?? `${ev.ts}-${ev.type}-${out.length}`;
    if (ev.type === "text" && p.text?.trim()) out.push({ role: "agent", text: p.text.trim(), id });
    else if (ev.type === "steer" && p.content) {
      if (p.source === "supervisor") {
        const text = `🧭 ${String(p.content)}`;
        if (text === lastSupervisor) continue;
        lastSupervisor = text;
        out.push({ role: "sys", text, id });
        continue;
      }
      if (p.source) continue;
      out.push({ role: "user", text: String(p.content), id });
    }
    else if (ev.type === "shell") out.push({ role: "sys", text: `🎯 GETSHELL 达成！${p.access || ""}`, id });
    else if (ev.type === "lateral") out.push({ role: "sys", text: `🌐 内网横向已开始${p.hosts_footed ? ` · ${p.hosts_footed} 台主机` : ""}`, id });
    else if (ev.type === "log" && (p.level === "warn" || p.level === "error")) out.push({ role: "sys", text: String(p.message || "").slice(0, 400), id });
    else if (ev.type === "status" && ["goal_reached", "completed", "stopped", "error", "running"].includes(p.status) && p.turn === undefined) {
      out.push({ role: "sys", text: `● 状态：${p.status}`, id });
    }
  }
  return out.length > 200 ? out.slice(-200) : out;
}

export function ChatDock({
  events, running, queued, onSend, onStart, onStop, startLabel,
}: { events: RTEvent[]; running: boolean; queued?: boolean; onSend: (m: string) => void; onStart: () => void; onStop: () => void; startLabel?: string }) {
  const [text, setText] = useState("");
  const listRef = useRef<HTMLDivElement>(null);
  const msgs = useMemo(() => toMessages(events), [events]);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [msgs.length]);

  const send = () => {
    const t = text.trim();
    if (!t) return;
    onSend(t);
    setText("");
  };

  return (
    <div className="card-cream" style={{ display: "flex", flexDirection: "column", height: 320 }}>
      <div className="spread" style={{ marginBottom: 10 }}>
        <div className="row" style={{ gap: 8 }}>
          <span className="pulse-dot" style={{ background: queued ? "var(--warning)" : running ? "var(--success)" : "var(--muted-soft)" }} />
          <b style={{ fontSize: 15 }}>协同对话窗口</b>
          <span className="muted" style={{ fontSize: 12 }}>
            {queued
              ? "排队中 · 等待并发槽空出后开跑"
              : running
              ? "自动渗透中 · 指令会在下一个安全节点注入"
              : "已停止"}
          </span>
        </div>
        <div className="row" style={{ gap: 8 }}>
          {running ? (
            <button className="btn btn-sm btn-danger" onClick={onStop}>停止</button>
          ) : (
            <button className="btn btn-sm btn-primary" onClick={onStart}>{startLabel || "启动自动渗透"}</button>
          )}
        </div>
      </div>

      <div ref={listRef} className="scroll-y" style={{ flex: 1, background: "var(--canvas)", borderRadius: 8, padding: 12, border: "1px solid var(--hairline)" }}>
        {msgs.length === 0 && <p className="muted" style={{ fontSize: 13 }}>启动后可全自动运行；也可随时在此发送指令引导（如“重点打上传点”“换用 fscan 扫内网”“先验证这个 SQL 注入”）。</p>}
        {msgs.map((m) => (
          <div
            key={m.id}
            className={`chat-bubble ${
              m.role === "user" ? "chat-user"
                : m.role === "sys" ? "chat-sys"
                : "chat-agent"
            }`}
            style={{ whiteSpace: "pre-wrap" }}
          >{m.text}</div>
        ))}
      </div>

      <div className="row" style={{ marginTop: 10, gap: 8 }}>
        <input
          className="input" placeholder="给从者发送指令…（回车发送）"
          value={text} onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
        />
        <button className="btn btn-primary" onClick={send}>发送</button>
      </div>
    </div>
  );
}
