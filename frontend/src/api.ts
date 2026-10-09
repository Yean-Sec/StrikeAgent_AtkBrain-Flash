import type { AppVersion, FindingDetail, Graph, Project, RTEvent } from "./types";
import { getLocale } from "./i18n/locale";
import { t } from "./i18n/t";
import { appBase, withAppBase } from "./appBase";

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

export type AuthMe = {
  required: boolean;
  authenticated: boolean;
  username: string | null;
  totp_enabled: boolean;
  must_change_password?: boolean;
  show_default_creds?: boolean;
  default_username?: string | null;
};

export type LlmProfile = {
  format: "openai" | "anthropic" | string;
  model: string;
  base_url: string;
  api_key_set: boolean;
  api_key_hint: string;
};

export type LlmProfileInput = {
  format: string;
  model: string;
  base_url: string;
  api_key?: string;
};

export type LlmTestResult = {
  ok: boolean;
  latency_ms?: number;
  model?: string;
  reply?: string;
  error?: string;
};

export type LoginResult = {
  ok: boolean;
  username?: string;
  totp_enabled?: boolean;
  need_totp?: boolean;
  pending_id?: string;
  must_change_password?: boolean;
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
  const tok = getApiToken();
  const headers: Record<string, string> = { "X-Locale": getLocale() };
  if (tok) headers["X-API-Token"] = tok;
  return headers;
}

function isNetworkErr(raw: string) {
  return /failed to fetch|networkerror|load failed|network request failed/i.test(raw);
}

/** HTTP/2 的 statusText 经常是空的，不能只靠 e.message，否则批量操作只剩「失败」。 */
export function formatApiError(e: unknown, fallback: string): string {
  if (e == null) return fallback;
  if (typeof e === "string" && e.trim()) return e;
  const err = e as { message?: unknown; detail?: unknown; status?: number; code?: string };
  let msg: unknown = err.message ?? err.detail;
  if (Array.isArray(msg)) {
    msg = msg.map((x) => (x && typeof x === "object" && "msg" in x ? String((x as { msg?: unknown }).msg || "") : JSON.stringify(x))).filter(Boolean).join("; ");
  } else if (msg && typeof msg !== "string") {
    try {
      msg = JSON.stringify(msg);
    } catch {
      msg = "";
    }
  }
  const text = String(msg || "").trim();
  const status = Number(err.status || 0);
  if (text && text !== "OK") {
    if (status && !/^HTTP\s+\d+/i.test(text)) return `HTTP ${status} ${text}`;
    return text;
  }
  if (status) return `${fallback} (HTTP ${status})`;
  return fallback;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function j<T>(r: Response): Promise<T> {
  if (!r.ok) {
    let msg = r.statusText;
    let retryAfter = 0;
    let code = "";
    try {
      const b = await r.json();
      msg = b.detail || msg;
      retryAfter = Number(b.retry_after || 0);
      code = String(b.code || "");
    } catch {}
    const err = new Error(typeof msg === "string" && msg.trim() ? msg : `HTTP ${r.status}`) as Error & { status?: number; retryAfter?: number; code?: string };
    err.status = r.status;
    if (retryAfter) err.retryAfter = retryAfter;
    if (code) err.code = code;
    throw err;
  }
  return r.json();
}

function maybeLoginRedirect(r: Response, input: RequestInfo | URL) {
  if (r.status !== 401) return;
  if (typeof window === "undefined") return;
  const here = window.location.pathname.replace(appBase(), "") || "/";
  if (here === "/login" || here.endsWith("/login")) return;
  const path = typeof input === "string" ? input : input instanceof URL ? input.pathname : "";
  if (String(path).includes("/api/auth")) return;
  const copy = r.clone();
  copy.json().then((b: any) => {
    if (b?.detail === "login-required") window.location.assign(withAppBase("/login"));
  }).catch(() => {});
}

/** fetch 包装：GET 遇瞬时断连自动重试；把 Failed to fetch 转成可读错误。 */
async function req<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const headers = { ...authHeaders(), ...(init?.headers as Record<string, string> | undefined) };
  const method = String(init?.method || "GET").toUpperCase();
  const retryable = method === "GET" || method === "HEAD";
  let lastRaw = "";
  const attempts = retryable ? 4 : 1;
  const url = typeof input === "string" ? withAppBase(input) : input;
  for (let i = 0; i < attempts; i++) {
    try {
      const r = await fetch(url, { credentials: "include", ...init, headers });
      maybeLoginRedirect(r, url);
      return await j<T>(r);
    } catch (e: any) {
      lastRaw = String(e?.message || e || "");
      if (!isNetworkErr(lastRaw) || i === attempts - 1) {
        if (isNetworkErr(lastRaw)) {
          throw new Error(t("errors.backend"));
        }
        throw e instanceof Error ? e : new Error(lastRaw);
      }
      await sleep(400 * 2 ** i);
    }
  }
  throw new Error(lastRaw || t("errors.request"));
}

export const api = {
  health: () => req<any>("/api/health"),
  authMe: () => req<AuthMe>("/api/auth/me"),
  authPubkey: () => req<{ alg: string; pem: string; ticket?: string }>("/api/auth/pubkey"),
  authLogin: (body: Record<string, unknown>) =>
    req<LoginResult>("/api/auth/login", { method: "POST", headers: J, body: JSON.stringify(body) }),
  authLogout: () => req<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  totpSetup: () => req<{ otpauth_url: string; secret: string; setup_id: string }>("/api/auth/totp/setup"),
  totpConfirm: (setup_id: string, code: string) =>
    req<{ ok: boolean; totp_enabled: boolean }>("/api/auth/totp/confirm", {
      method: "POST",
      headers: J,
      body: JSON.stringify({ setup_id, code }),
    }),
  authPassword: (body: { ticket: string; new_cipher: string; old_cipher?: string }) =>
    req<{ ok: boolean; must_change_password: boolean }>("/api/auth/password", {
      method: "POST",
      headers: J,
      body: JSON.stringify(body),
    }),
  settings: () => req<any>("/api/settings"),
  setReviewFlags: (body: { secondary_verify?: boolean; redteam_rating?: boolean }) =>
    req<{ review: { secondary_verify: boolean; redteam_rating: boolean } }>("/api/settings/review", {
      method: "POST",
      headers: J,
      body: JSON.stringify(body),
    }),
  setHuntClocks: (body: Record<string, number>) =>
    req<{ hunt_clocks: Record<string, number>; hard_stop: Record<string, { label?: string; conditions?: string[] }> }>(
      "/api/settings/hunt-clocks",
      { method: "POST", headers: J, body: JSON.stringify(body) },
    ),
  listFindings: (params?: { q?: string; project?: string; category?: string; severity?: string; track?: string; page?: number; page_size?: number }) => {
    const sp = new URLSearchParams();
    if (params?.q) sp.set("q", params.q);
    if (params?.project) sp.set("project", params.project);
    if (params?.category) sp.set("category", params.category);
    if (params?.severity) sp.set("severity", params.severity);
    if (params?.track) sp.set("track", params.track);
    if (params?.page) sp.set("page", String(params.page));
    if (params?.page_size) sp.set("page_size", String(params.page_size));
    const qs = sp.toString();
    return req<any>(`/api/findings${qs ? `?${qs}` : ""}`);
  },
  reviewFinding: (pid: string, fid: string, mode: "secondary" | "rating") =>
    req<any>(`/api/projects/${pid}/findings/${fid}/review`, {
      method: "POST",
      headers: J,
      body: JSON.stringify({ mode }),
    }),
  reviewJob: (jobId: string) => req<any>(`/api/review-jobs/${encodeURIComponent(jobId)}`),
  version: (refresh = false) => req<AppVersion>(`/api/version${refresh ? "?refresh=true" : ""}`),
  applyVersion: () =>
    req<{
      ok: boolean;
      started?: boolean;
      already_latest?: boolean;
      tag?: string;
      target?: string;
      local?: string;
      latest?: string;
    }>("/api/version/apply", { method: "POST", headers: J }),
  setConcurrency: (value: number, track: "redteam" | "ctf" = "redteam") =>
    req<any>("/api/settings/concurrency", { method: "POST", headers: J, body: JSON.stringify({ value, track }) }),
  proxyStatus: () => req<any>("/api/proxy/status"),
  setProxyEnabled: (enabled: boolean) =>
    req<any>("/api/proxy/enabled", { method: "POST", headers: J, body: JSON.stringify({ enabled }) }),
  getProxyPool: () => req<any>("/api/proxy/pool"),
  saveProxyPool: (custom_text: string) =>
    req<any>("/api/proxy/pool", { method: "POST", headers: J, body: JSON.stringify({ custom_text }) }),
  verifyProxy: () => req<any>("/api/proxy/verify", { method: "POST" }),
  getPiModels: () => req<{ text: string }>("/api/settings/pi-models"),
  savePiModels: (text: string) =>
    req<{ ok: boolean; text: string }>("/api/settings/pi-models", { method: "POST", headers: J, body: JSON.stringify({ text }) }),
  getLlmProfile: () => req<LlmProfile>("/api/settings/llm"),
  saveLlmProfile: (body: LlmProfileInput) =>
    req<LlmProfile & { ok: boolean }>("/api/settings/llm", { method: "POST", headers: J, body: JSON.stringify(body) }),
  testLlmProfile: (body: LlmProfileInput) =>
    req<LlmTestResult>("/api/settings/llm/test", { method: "POST", headers: J, body: JSON.stringify(body) }),

  listProjects: () => req<Project[]>("/api/projects"),
  getProject: (id: string) => req<Project>(`/api/projects/${id}`),
  setOutputLang: (id: string, lang: string) =>
    req<{ ok: boolean; output_lang: string }>(`/api/projects/${id}/output_lang`, {
      method: "PATCH",
      headers: J,
      body: JSON.stringify({ output_lang: lang }),
    }),
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

  reportUrl: (id: string, format: string) => withAppBase(`/api/projects/${id}/report?format=${format}`),
  startReportExport: (id: string, format: string, lang?: string) =>
    req<any>(`/api/projects/${id}/report/export?format=${encodeURIComponent(format)}&lang=${encodeURIComponent(lang || getLocale())}`, { method: "POST" }),
  reportExportStatus: (id: string, jobId: string) =>
    req<any>(`/api/projects/${id}/report/export/${encodeURIComponent(jobId)}`),
  reportExportFileUrl: (id: string, jobId: string) =>
    withAppBase(`/api/projects/${id}/report/export/${encodeURIComponent(jobId)}/file`),
  getFinding: (id: string, fid: string) =>
    req<FindingDetail>(`/api/projects/${id}/findings/${fid}`),
  findingReportUrl: (id: string, fid: string, lang?: string) =>
    withAppBase(`/api/projects/${id}/findings/${fid}/report?format=md&lang=${encodeURIComponent(lang || getLocale())}`),
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
