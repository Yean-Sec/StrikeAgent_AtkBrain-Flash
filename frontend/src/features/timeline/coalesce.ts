import type { RTEvent } from "../../types";

const STREAM_TYPES = new Set(["text", "thought"]);
const BREAK_TYPES = new Set(["tool", "tool_result", "turn"]);
/** 同一角色相邻 token 超过此时隙视为新一段（毫秒）。 */
const GAP_MS = 8000;

/** 完整段落不再往上一段硬拼；只有 token 级碎片才合并。 */
function looksLikeStreamDelta(s: string): boolean {
  if (s.length <= 64) return true;
  return s.length <= 120 && !/[。．.!?！？\n]/.test(s);
}

/**
 * Pi 曾把每个 text_delta / thinking_delta 落成独立事件。
 * 按 (type, role) 把短间隔碎片拼成完整块，供时间线与协同对话显示。
 */
export function coalesceStreamEvents(events: RTEvent[]): RTEvent[] {
  const out: RTEvent[] = [];
  const open = new Map<string, number>();
  const closeRole = (role: string) => {
    open.delete(`text:${role}`);
    open.delete(`thought:${role}`);
  };

  for (const ev of events) {
    if (STREAM_TYPES.has(ev.type)) {
      const role = String(ev.payload?.role || "");
      const key = `${ev.type}:${role}`;
      const piece = ev.type === "text"
        ? String(ev.payload?.text || "")
        : String(ev.payload?.message || "");
      if (!piece) continue;
      const idx = open.get(key);
      if (idx != null && looksLikeStreamDelta(piece)) {
        const prev = out[idx];
        const dt = Math.abs(Number(ev.ts || 0) - Number(prev.ts || 0));
        if (dt < GAP_MS) {
          if (ev.type === "text") {
            prev.payload = { ...prev.payload, text: String(prev.payload?.text || "") + piece };
          } else {
            prev.payload = { ...prev.payload, message: String(prev.payload?.message || "") + piece };
          }
          prev.ts = ev.ts;
          continue;
        }
      }
      out.push({ ...ev, payload: { ...(ev.payload || {}) } });
      open.set(key, out.length - 1);
      continue;
    }
    if (BREAK_TYPES.has(ev.type)) {
      closeRole(String(ev.payload?.role || ""));
    }
    out.push(ev);
  }
  return out;
}
