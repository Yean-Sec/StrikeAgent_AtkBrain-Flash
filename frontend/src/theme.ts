import { t } from "./i18n";

// 设计令牌 —— 来自 DESIGN.md（getdesign claude 模板）。UI 唯一视觉事实来源。
export const colors = {
  primary: "#4c7dff",
  primaryActive: "#3a63d8",
  ink: "#243044",
  body: "#4a5a6e",
  bodyStrong: "#1e2a3a",
  muted: "#8b97a8",
  mutedSoft: "#a8b2c1",
  hairline: "#e6edf5",
  hairlineSoft: "#eef3f8",
  canvas: "#f4f7fc",
  surfaceSoft: "#f7f9fd",
  surfaceCard: "#ffffff",
  surfaceCreamStrong: "#eef4ff",
  surfaceDark: "#ffffff",
  surfaceDarkElevated: "#f3f7ff",
  surfaceDarkSoft: "#eaf1fb",
  onDark: "#243044",
  onDarkSoft: "#7d8b9e",
  accentTeal: "#3ecf8e",
  accentAmber: "#f5b942",
  success: "#22a06b",
  warning: "#d4a017",
  error: "#c64545",
};

export const severityColor: Record<string, string> = {
  critical: "#c64545",
  high: "#cc785c",
  medium: "#d4a017",
  low: "#5db8a6",
  info: "#8e8b82",
};

// 攻击图节点按类型的主色：危险点暖橙 / 漏洞朱红 / GETSHELL 同色相朱红但更鲜艳
export const nodeTypeColor: Record<string, string> = {
  target: "#141413",
  info: "#8e8b82",
  service: "#5db8a6",
  danger: "#f08c2a",
  vuln: "#c64545",
  credential: "#a9583e",
  foothold: "#cc785c",
  honeypot: "#6c6a64",
  goal: "#f23636",
};

const NODE_TYPE_MSG: Record<string, string> = {
  target: "graph.target",
  info: "graph.info",
  service: "graph.service",
  danger: "graph.danger",
  vuln: "graph.vuln",
  credential: "graph.credential",
  foothold: "graph.foothold",
  honeypot: "graph.honeypot",
  goal: "graph.goal",
};

export function nodeTypeLabel(type: string): string {
  const key = NODE_TYPE_MSG[type];
  return key ? t(key) : type;
}

type GraphTypeNode = {
  type?: string;
  key?: string;
  tags?: string[];
  title?: string;
  detail?: unknown;
  severity?: string;
};

function humanizeNodeKey(key: string): string {
  const raw = String(key || "").trim();
  if (!raw.includes(":")) return raw;
  const rest = raw.split(":").slice(1).join(":").trim();
  return rest || raw;
}

function isEmptyNodeDetail(detail: unknown): boolean {
  if (detail == null || detail === "") return true;
  if (typeof detail === "string") return !detail.trim();
  if (Array.isArray(detail)) return detail.length === 0;
  if (typeof detail === "object") return Object.keys(detail as object).length === 0;
  return false;
}

/** 边引用留下的空壳：不是已确认漏洞。 */
export function isPlaceholderGraphNode(n: GraphTypeNode): boolean {
  const tags = (n.tags || []).map((t) => String(t).toLowerCase());
  if (tags.includes("placeholder")) return true;
  const key = String(n.key || "");
  const title = String(n.title || "");
  if (key && isEmptyNodeDetail(n.detail) && (title === key || title === humanizeNodeKey(key))) {
    return true;
  }
  return false;
}

export function graphNodeDisplayType(n: GraphTypeNode): string {
  const t = n.type || "";
  if (isPlaceholderGraphNode(n) && (t === "vuln" || t === "danger")) return "danger";
  return t;
}

export function graphNodeDisplaySeverity(n: GraphTypeNode): string {
  const sev = String(n.severity || "info").toLowerCase();
  if (isPlaceholderGraphNode(n) && (n.type === "vuln" || n.type === "danger") && (sev === "high" || sev === "critical")) {
    return "medium";
  }
  return n.severity || "info";
}

export function isGetshellNode(n: GraphTypeNode): boolean {
  if (n.type !== "goal") return false;
  const key = String(n.key || "");
  const tags = n.tags || [];
  return key.startsWith("goal:shell") || tags.includes("getshell");
}

/** 圆圈内画 ★：仅已拿到命令执行的 GETSHELL / 立足点。漏洞节点不标星。 */
export function showsShellStar(n: GraphTypeNode & { is_rce?: boolean }): boolean {
  if (isGetshellNode(n)) return true;
  const key = String(n.key || "");
  const tags = n.tags || [];
  if (n.type === "goal" && (n.is_rce || tags.includes("getshell"))) return true;
  if (n.type === "foothold" && (n.is_rce || tags.includes("getshell") || tags.includes("shell") || key.startsWith("foothold:shell"))) {
    return true;
  }
  return false;
}

export function isFlagGoalNode(n: GraphTypeNode): boolean {
  if (n.type !== "goal") return false;
  const key = String(n.key || "");
  const tags = n.tags || [];
  return key.startsWith("goal:flag") || tags.includes("flag") || tags.includes("getflag");
}

export function graphNodeTypeLabel(n: GraphTypeNode): string {
  if (isFlagGoalNode(n)) return t("graph.flag");
  // GETSHELL 与 RCE 同属一类
  if (isGetshellNode(n)) return t("graph.goal");
  if (n.type === "goal") return t("graph.goalGeneric");
  const typ = graphNodeDisplayType(n);
  return nodeTypeLabel(typ) || typ || "";
}

const SEVERITY_MSG: Record<string, string> = {
  info: "graph.sevInfo",
  low: "graph.sevLow",
  medium: "graph.sevMedium",
  high: "graph.sevHigh",
  critical: "graph.sevCritical",
};

export function severityLabel(sev: string): string {
  const key = SEVERITY_MSG[sev];
  return key ? t(key) : sev;
}

const RT_RATINGS = new Set(["critical", "high", "medium", "low", "info"]);

/** 漏洞列表/报告展示用评级：红队二次验证评级优先。 */
export function displayFindingSeverity(f: { severity?: string; redteam_rating?: string } | null | undefined): string {
  const rt = String(f?.redteam_rating || "").toLowerCase();
  if (RT_RATINGS.has(rt)) return rt;
  const sev = String(f?.severity || "info").toLowerCase();
  return RT_RATINGS.has(sev) ? sev : "info";
}

export function scrubCandidateRceLabel(text?: string | null): string {
  let s = String(text || "");
  if (!s.includes("候选")) return s;
  s = s.replace(/[（(]\s*候选\s*RCE\s*[)）]/gi, "").replace(/候选\s*RCE/gi, "");
  return s.replace(/\s{2,}/g, " ").replace(/^[\s\-—·/|]+|[\s\-—·/|]+$/g, "");
}

export function formatNodeDetail(detail: unknown): string {
  if (detail == null || detail === "") return "";
  if (typeof detail === "string") return detail;
  try {
    return JSON.stringify(detail, null, 2);
  } catch {
    return String(detail);
  }
}

// 内网横向（PIVOTS_TO / lateral）专用强调色——与 RCE 橙路径明显区分，一眼可辨。
export const lateralColor = "#6d5cf0";

export const radius = { xs: 4, sm: 6, md: 8, lg: 12, xl: 16, pill: 9999 };
export const space = { xxs: 4, xs: 8, sm: 12, md: 16, lg: 24, xl: 32, xxl: 48 };
