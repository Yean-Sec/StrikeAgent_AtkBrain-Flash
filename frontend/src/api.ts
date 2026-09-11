import type { AppVersion, FindingDetail, Graph, Project, RTEvent } from "./types";

export type AssetGroupPreview = {
  primary: string;
  zone?: string;
  vhosts: string[];
  ports: number[];
};

export type AssetPreviewResult = {
  track?: string;
  objective?: string;
  policy?: string;
  group_count: number;
  hosts: number;
  lines_kept: number;
  skipped_dup_count: number;
  skipped_dup?: string[];
  skipped_header: string[];
  groups: AssetGroupPreview[];
  note?: string;
};

const J = { "Content-Type": "application/json" };

/** API Token：优先 localStorage，其次 Vite 环境变量（ATKBRAIN_API_TOKEN 非空时后端强制校验）。 */
export function getApiToken(): string {
  try {
    const fromLs = (localStorage.getItem("atkbrain_api_token") || "").trim();
    if (fromLs) return fromLs;
  } catch {}
  return (import.meta.env.VITE_ATKBRAIN_API_TOKEN || "").trim();
}

function authHeaders(): Record<string, string> {
  const t = getApiToken();
  return t ? { "X-API-Token": t } : {};
}

function isNetworkErr(raw: string) {
  return /failed to fetch|networkerror|load failed|network request failed/i.test(raw);
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function j<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = r.statusText;
    try {
      const b = await r.json();
      msg = b.detail || msg;
    } catch {}
    throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
  }
  return r.json();
}

/** fetch 包装：GET 遇瞬时断连自动重试；把 Failed to fetch 转成可读错误。 */
async function req<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const headers = { ...authHeaders(), ...(init?.headers as Record<string, string> | undefined) };
  const method = String(init?.method || "GET").toUpperCase();
  const retryable = method === "GET" || method === "HEAD";
  let lastRaw = "";
  const attempts = retryable ? 4 : 1;
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(input, { ...init, headers });
      return await j<T>(r);
    } catch (e: any) {
      lastRaw = String(e?.message || e || "");
      if (!isNetworkErr(lastRaw) || i === attempts - 1) {
        if (isNetworkErr(lastRaw)) {
          throw new Error("无法连接后端（Failed to fetch）。请确认 StrikeAgent_AtkBrain-Flash 后端已运行，并刷新页面后重试。");
        }
        throw e instanceof Error ? e : new Error(lastRaw);
      }
      await sleep(400 * 2 ** i);
    }
  }
  throw new Error(lastRaw || "请求失败");
}

export const api = {
  health: () => req<any>("/api/health"),
  settings: () => req<any>("/api/settings"),
  version: (refresh = false) => req<AppVersion>(`/api/version${refresh ? "?refresh=true" : ""}`),
  setConcurrency: (value: number, track: "redteam" | "ctf" = "redteam") =>
    req<any>("/api/settings/concurrency", { method: "POST", headers: J, body: JSON.stringify({ value, track }) }),
  proxyStatus: () => req<any>("/api/proxy/status"),
  setProxyEnabled: (enabled: boolean) =>
    req<any>("/api/proxy/enabled", { method: "POST", headers: J, body: JSON.stringify({ enabled }) }),
  getProxyPool: () => req<any>("/api/proxy/pool"),
  saveProxyPool: (custom_text: string) =>
    req<any>("/api/proxy/pool", { method: "POST", headers: J, body: JSON.stringify({ custom_text }) }),
  verifyProxy: () => req<any>("/api/proxy/verify", { method: "POST" }),

  listProjects: () => req<Project[]>("/api/projects"),
  getProject: (id: string) => req<Project>(`/api/projects/${id}`),
  createProject: (body: any) =>
    req<Project>("/api/projects", { method: "POST", headers: J, body: JSON.stringify(body) }),
  deleteProject: (id: string) => req<any>(`/api/projects/${id}`, { method: "DELETE" }),
  renameProject: (id: string, name: string) =>
    req<Project>(`/api/projects/${id}`, {
      method: "PATCH",
      headers: J,
      body: JSON.stringify({ name }),
    }),
  batchDeleteProjects: (ids: string[]) =>
    req<{ ok: boolean; deleted: string[]; missing: string[]; stopped: string[] }>(
      "/api/projects/batch_delete",
      { method: "POST", headers: J, body: JSON.stringify({ ids }) },
    ),
  batchStartProjects: (ids: string[], confirmRestart = false) =>
    req<any>("/api/projects/batch_start", { method: "POST", headers: J, body: JSON.stringify({ ids, confirm_restart: confirmRestart }) }),
  batchStopProjects: (ids: string[]) =>
    req<any>("/api/projects/batch_stop", { method: "POST", headers: J, body: JSON.stringify({ ids }) }),

  start: (id: string, confirmRestart = false) =>
    req<any>(`/api/projects/${id}/start?confirm_restart=${confirmRestart ? "true" : "false"}`, { method: "POST" }),
  stop: (id: string) => req<any>(`/api/projects/${id}/stop`, { method: "POST" }),
  steer: (id: string, message: string) =>
    req<any>(`/api/projects/${id}/steer`, { method: "POST", headers: J, body: JSON.stringify({ message }) }),

  graph: (id: string) => req<Graph>(`/api/projects/${id}/graph`),
  events: (id: string, after = 0) => req<RTEvent[]>(`/api/projects/${id}/events?after=${after}`),
  runs: (id: string) => req<any[]>(`/api/projects/${id}/runs`),
  projectMemory: (id: string) => req<{ episodes: any[]; playbook?: any[] }>(`/api/projects/${id}/memory`),

  reportUrl: (id: string, format: string) => {
    const t = getApiToken();
    const base = `/api/projects/${id}/report?format=${format}`;
    return t ? `${base}&token=${encodeURIComponent(t)}` : base;
  },
  startReportExport: (id: string, format: string) =>
    req<any>(`/api/projects/${id}/report/export?format=${encodeURIComponent(format)}`, { method: "POST" }),
  reportExportStatus: (id: string, jobId: string) =>
    req<any>(`/api/projects/${id}/report/export/${encodeURIComponent(jobId)}`),
  reportExportFileUrl: (id: string, jobId: string) => {
    const t = getApiToken();
    const base = `/api/projects/${id}/report/export/${encodeURIComponent(jobId)}/file`;
    return t ? `${base}?token=${encodeURIComponent(t)}` : base;
  },
  getFinding: (id: string, fid: string) =>
    req<FindingDetail>(`/api/projects/${id}/findings/${fid}`),
  findingReportUrl: (id: string, fid: string) => {
    const t = getApiToken();
    const base = `/api/projects/${id}/findings/${fid}/report?format=md`;
    return t ? `${base}&token=${encodeURIComponent(t)}` : base;
  },
  poc: (id: string, fid: string) => req<{ curl: string; python: string }>(`/api/projects/${id}/findings/${fid}/poc`),

  // 集群（Phase 2）
  triage: (id: string) => req<any>(`/api/projects/${id}/triage`, { method: "POST" }),
  refoldMachines: (id: string) =>
    req<any>(`/api/projects/${id}/refold_machines`, { method: "POST" }),
  subprojects: (id: string) => req<Project[]>(`/api/projects/${id}/subprojects`),
  addClusterAssets: (id: string, assets: string[], autoStart = true) =>
    req<any>(`/api/projects/${id}/assets`, {
      method: "POST",
      headers: J,
      body: JSON.stringify({ assets, auto_start: autoStart }),
    }),
  previewAssets: (assets: string[], track: string) =>
    req<AssetPreviewResult>("/api/projects/assets/preview", {
      method: "POST",
      headers: J,
      body: JSON.stringify({ assets, track }),
    }),
  importProgress: (id: string) => req<any>(`/api/projects/${id}/import_progress`),
  pauseImport: (id: string) =>
    req<any>(`/api/projects/${id}/import_pause`, { method: "POST" }),
  resumeImport: (id: string) =>
    req<any>(`/api/projects/${id}/import_resume`, { method: "POST" }),
  startAll: (id: string, confirmRestart = false, unfinishedOnly = false) =>
    req<any>(
      `/api/projects/${id}/start_all?confirm_restart=${confirmRestart ? "true" : "false"}&unfinished_only=${unfinishedOnly ? "true" : "false"}`,
      { method: "POST" },
    ),
  stopAll: (id: string) =>
    req<any>(`/api/projects/${id}/stop_all`, { method: "POST" }),

  flags: (id: string) => req<any[]>(`/api/projects/${id}/flags`),

  bmImport: (id: string) => req<any>(`/api/projects/${id}/benchmark/import`, { method: "POST" }),
  scoreboard: (id: string) => req<any>(`/api/projects/${id}/benchmark/scoreboard`),
};
