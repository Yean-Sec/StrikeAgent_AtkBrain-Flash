import type { RTEvent } from "../../types";

const STALL_LABEL: Record<string, string> = {
  none: "有清晰下一步",
  infra: "入口不可达",
  method: "方法空转",
  chain: "应打利用下一跳",
  postex: "应提权/横向",
};

const KIND_LABEL: Record<string, string> = {
  plan: "方案",
  error: "调用失败",
  empty: "空方案",
  hold: "继续",
  runtime_review: "审查",
};

/** 自监督栏只展示失败记录与 Claude Code 生成的内容，不展示 skip/probe 等机械条目。 */
const VISIBLE_KINDS = new Set(["error", "empty", "plan", "hold", "runtime_review"]);

type SupervisorRow = {
  key: string;
  ts: number;
  kind: string;
  title: string;
  diagnosis?: string;
  body?: string;
  stall?: string;
  quality?: string;
  pivot?: number;
  turn?: number;
  rebind?: boolean;
  tags?: { label: string; items: string[] }[];
};

function chips(label: string, items: unknown): { label: string; items: string[] } | null {
  if (!Array.isArray(items) || !items.length) return null;
  const out = items.map((x) => String(x || "").trim()).filter(Boolean);
  return out.length ? { label, items: out } : null;
}

function fromSupervisorEvent(ev: RTEvent): SupervisorRow | null {
  const p = ev.payload || {};
  const kind = String(p.kind || "plan");
  if (!VISIBLE_KINDS.has(kind)) return null;
  const pivot = Number(p.pivot) || 0;
  const turn = Number(p.turn) || 0;
  const title =
    kind === "error"
      ? "监督调用失败，本轮未注入方案"
      : kind === "empty"
      ? "监督返回空方案，本轮未注入"
      : kind === "hold"
      ? (
          String(p.reason || "") === "binding_ignored"
            ? (turn ? `第 ${turn} 轮收紧后重注` : "收紧后重注")
            : (turn ? `第 ${turn} 轮继续当前方案` : "继续当前方案")
        )
      : kind === "runtime_review"
      ? (turn ? `第 ${turn} 轮审查` : "运行时审查")
      : turn
      ? `第 ${turn} 轮方案`
      : pivot
      ? `方案 #${pivot}`
      : "监督方案";
  const tags = [
    chips("必须推进 Intent", p.must_intents),
    chips("只委派", p.subagents),
    chips("只允许战术", p.prefer_tactics),
    chips("禁止策略", p.defer_families),
    chips("禁止重复", p.ban_repeats),
  ].filter(Boolean) as { label: string; items: string[] }[];
  const body = p.next_plan || (kind === "error" ? String(p.error || "") : "") || "";
  const diagnosis = p.diagnosis || (kind === "error" ? p.error : "") || "";
  if (kind !== "error" && kind !== "empty" && !String(body || diagnosis).trim()) return null;
  return {
    key: String(ev.id ?? `sup-${ev.ts}`),
    ts: ev.ts,
    kind,
    title,
    diagnosis,
    body,
    stall: kind === "error" ? "" : p.stall || "",
    quality: kind === "error" ? "" : p.quality || "",
    pivot,
    turn: Number(p.turn) || 0,
    rebind: kind !== "error" && !!p.rebind_entry,
    tags,
  };
}

function fromLegacy(ev: RTEvent): SupervisorRow | null {
  const p = ev.payload || {};
  if (ev.type === "steer") {
    const src = String(p.source || p.from || "");
    const content = String(p.content || "");
    if (/换路兜底|机械模板/.test(content)) return null;
    if (src !== "supervisor" && !content.includes("【AI监督")) return null;
    const m = content.match(/方案\s*#(\d+)/);
    const pivot = m ? Number(m[1]) : 0;
    const diag = (content.match(/判断：([^\n]+)/) || [])[1] || "";
    return {
      key: String(ev.id ?? `steer-${ev.ts}`),
      ts: ev.ts,
      kind: "plan",
      title: pivot ? `方案 #${pivot}` : "监督方案",
      diagnosis: diag,
      body: content,
      pivot,
    };
  }
  if (ev.type !== "log") return null;
  const msg = String(p.message || "");
  if (/换路兜底|机械模板|顾问就绪|未到周期性|本轮不改方向/.test(msg)) return null;
  if (/调用失败/.test(msg) && /AI监督/.test(msg)) {
    return {
      key: String(ev.id ?? `log-${ev.ts}`),
      ts: ev.ts,
      kind: "error",
      title: "监督调用失败，本轮未注入方案",
      body: msg.replace(/^AI监督调用失败（本轮不注入方案）：/, ""),
    };
  }
  if (/空方案/.test(msg) && /AI监督/.test(msg)) {
    return { key: String(ev.id ?? `log-${ev.ts}`), ts: ev.ts, kind: "empty", title: "监督返回空方案，本轮未注入", body: msg };
  }
  return null;
}

/** 有结构化 supervisor 事件时，丢掉同一次方案的 log/steer 摘要，避免三份重复。 */
function collectRows(events: RTEvent[]): SupervisorRow[] {
  const structured = events.filter((e) => e.type === "supervisor");
  const skipLegacy = new Set<string>();
  for (const ev of structured) {
    const p = ev.payload || {};
    const kind = String(p.kind || "plan");
    if (!VISIBLE_KINDS.has(kind)) continue;
    const pivot = Number(p.pivot) || 0;
    if (pivot) skipLegacy.add(`plan:${pivot}`);
    if (kind === "error") skipLegacy.add("error");
    if (kind === "empty") skipLegacy.add("empty");
    if (kind === "hold") skipLegacy.add("hold");
    if (kind === "runtime_review") skipLegacy.add("runtime_review");
  }

  const rows: SupervisorRow[] = [];
  for (const ev of events) {
    if (ev.type === "supervisor") {
      const row = fromSupervisorEvent(ev);
      if (row) rows.push(row);
      continue;
    }
    const row = fromLegacy(ev);
    if (!row) continue;
    if (row.kind === "plan" && row.pivot && skipLegacy.has(`plan:${row.pivot}`)) continue;
    if ((row.kind === "error" || row.kind === "empty" || row.kind === "hold") && skipLegacy.has(row.kind)) continue;
    rows.push(row);
  }
  return rows;
}

export function countSupervisorRecords(events: RTEvent[]): number {
  return collectRows(events).length;
}

export function SupervisorPanel({ events }: { events: RTEvent[] }) {
  const rows = collectRows(events).slice().sort((a, b) => (b.ts || 0) - (a.ts || 0));
  if (!rows.length) {
    return (
      <p className="muted" style={{ padding: 16 }}>
        暂无自监督记录。顾问开口后，这里只显示 Claude Code 给出的方案，以及调用失败。
      </p>
    );
  }
  return (
    <div className="advisor-panel">
      {rows.map((row) => (
        <article key={row.key} className={`advisor-record supervisor-${row.kind}`}>
          <div>
            <span className="badge badge-pill">{KIND_LABEL[row.kind] || "监督"}</span>
            <time>{row.ts ? new Date(row.ts * 1000).toLocaleString() : ""}</time>
          </div>
          <b>{row.title}</b>
          <div className="supervisor-meta">
            {row.turn ? <span>第 {row.turn} 轮</span> : null}
            {row.stall && row.stall !== "none" ? <span>卡点 {STALL_LABEL[row.stall] || row.stall}</span> : null}
            {row.quality && row.quality !== "none" ? <span>进展 {row.quality}</span> : null}
            {row.rebind ? <span>建议重绑入口</span> : null}
          </div>
          {row.diagnosis && row.diagnosis !== row.body ? <p className="supervisor-diag">{row.diagnosis}</p> : null}
          {row.body && <p>{row.body}</p>}
          {row.tags?.map((tag) => (
            <div key={tag.label} className="supervisor-tags">
              <span className="muted">{tag.label}</span>
              {tag.items.map((item) => (
                <span key={`${tag.label}-${item}`} className="badge badge-pill">{item}</span>
              ))}
            </div>
          ))}
        </article>
      ))}
    </div>
  );
}
