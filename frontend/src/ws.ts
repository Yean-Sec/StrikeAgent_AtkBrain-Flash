import { useEffect, useRef } from "react";
import { getApiToken } from "./api";
import type { Graph, RTEvent } from "./types";

type Handlers = {
  onEvent?: (ev: RTEvent) => void;
  onSnapshot?: (graph: Graph, running: boolean, queued?: boolean) => void;
};

/** 高频事件（日志/工具结果）批处理后一次性刷到 React，避免每条事件触发一次重渲染把页面卡死。 */
const BATCH_FLUSH_MS = 120;
/** 关系图/进度类事件必须立刻投递，不能跟 tool/log 一起排队，更不能被 80 条洪峰裁掉。 */
const URGENT_TYPES = new Set([
  "snapshot", "shell", "finding", "status", "steer", "supervisor",
  "node", "edge", "rce_path", "lateral",
]);

export function useProjectSocket(projectId: string | undefined, handlers: Handlers) {
  const wsRef = useRef<WebSocket | null>(null);
  const hRef = useRef<Handlers>(handlers);
  hRef.current = handlers;
  const pendingRef = useRef<RTEvent[]>([]);
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!projectId) return;
    let closed = false;
    let retry: any;
    let pingTimer: ReturnType<typeof setInterval> | null = null;
    let attempts = 0;
    pendingRef.current = [];

    const flush = () => {
      flushTimer.current = null;
      const batch = pendingRef.current;
      pendingRef.current = [];
      if (!batch.length) return;
      // 合并为一条合成事件不够——逐条交给 handler，但同帧内只触发一次 React 更新由外层批处理；
      // 这里仍逐条调用，ProjectPage.onEvent 内部会再做事件列表合并。
      for (const ev of batch) hRef.current.onEvent?.(ev);
    };

    const enqueue = (ev: RTEvent) => {
      // 关系图节点/边与进度类立即投递；log/tool 进批处理队列
      if (URGENT_TYPES.has(ev.type)) {
        hRef.current.onEvent?.(ev);
        return;
      }
      pendingRef.current.push(ev);
      if (pendingRef.current.length > 80) {
        // 洪峰：只保留最近 80 条噪音日志（紧急事件已走立即投递，不会进这里）
        pendingRef.current = pendingRef.current.slice(-80);
      }
      if (flushTimer.current == null) {
        flushTimer.current = setTimeout(flush, BATCH_FLUSH_MS);
      }
    };

    const connect = () => {
      clearTimeout(retry);
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const tok = getApiToken();
      const q = tok ? `?token=${encodeURIComponent(tok)}` : "";
      if (wsRef.current && (wsRef.current.readyState === WebSocket.CONNECTING || wsRef.current.readyState === WebSocket.OPEN)) {
        return;
      }
      const ws = new WebSocket(`${proto}://${location.host}/api/projects/${projectId}/ws${q}`);
      wsRef.current = ws;
      ws.onopen = () => {
        attempts = 0;
        if (pingTimer) clearInterval(pingTimer);
        pingTimer = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: "ping" }));
        }, 10000);
      };
      ws.onmessage = (m) => {
        try {
          const data = JSON.parse(m.data);
          if (data.type === "snapshot") {
            hRef.current.onSnapshot?.(data.payload, data.running, data.queued);
          } else if (data.type !== "pong") {
            enqueue(data as RTEvent);
          }
        } catch {}
      };
      ws.onclose = () => {
        if (pingTimer) {
          clearInterval(pingTimer);
          pingTimer = null;
        }
        if (wsRef.current === ws) wsRef.current = null;
        if (!closed) {
          const delay = Math.min(15000, 300 * 2 ** Math.min(attempts, 5));
          attempts += 1;
          retry = setTimeout(connect, delay);
        }
      };
    };
    const wake = () => {
      if (closed) return;
      const st = wsRef.current?.readyState;
      if (st === WebSocket.OPEN || st === WebSocket.CONNECTING) return;
      connect();
    };
    connect();
    document.addEventListener("visibilitychange", wake);
    window.addEventListener("online", wake);

    return () => {
      closed = true;
      document.removeEventListener("visibilitychange", wake);
      window.removeEventListener("online", wake);
      clearTimeout(retry);
      if (pingTimer) clearInterval(pingTimer);
      if (flushTimer.current) clearTimeout(flushTimer.current);
      pendingRef.current = [];
      wsRef.current?.close();
    };
  }, [projectId]);

  const send = (obj: any) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
  };

  return { send };
}
