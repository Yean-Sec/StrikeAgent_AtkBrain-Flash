// 设计令牌 —— 来自 DESIGN.md（getdesign claude 模板）。UI 唯一视觉事实来源。
export const colors = {
  primary: "#cc785c",
  primaryActive: "#a9583e",
  ink: "#141413",
  body: "#3d3d3a",
  bodyStrong: "#252523",
  muted: "#6c6a64",
  mutedSoft: "#8e8b82",
  hairline: "#e6dfd8",
  hairlineSoft: "#ebe6df",
  canvas: "#faf9f5",
  surfaceSoft: "#f5f0e8",
  surfaceCard: "#efe9de",
  surfaceCreamStrong: "#e8e0d2",
  surfaceDark: "#181715",
  surfaceDarkElevated: "#252320",
  surfaceDarkSoft: "#1f1e1b",
  onDark: "#faf9f5",
  onDarkSoft: "#a09d96",
  accentTeal: "#5db8a6",
  accentAmber: "#e8a55a",
  success: "#5db872",
  warning: "#d4a017",
  error: "#c64545",
};

export const severityColor: Record<string, string> = {
  critical: "#c64545",
  high: "#d4a017",
  medium: "#8e8b82",
  low: "#b8b3a8",
  info: "#a09d96",
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

export const nodeTypeLabel: Record<string, string> = {
  target: "目标",
  info: "信息",
  service: "服务",
  danger: "危险点",
  vuln: "漏洞",
  credential: "凭证",
  foothold: "立足点",
  honeypot: "蜜罐",
  goal: "GETSHELL / RCE",
};

type GraphTypeNode = { type?: string; key?: string; tags?: string[] };

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
  if (isFlagGoalNode(n)) return "夺旗";
  // GETSHELL 与 RCE 同属一类
  if (isGetshellNode(n)) return "GETSHELL / RCE";
  if (n.type === "goal") return "目标成果";
  return nodeTypeLabel[n.type || ""] || n.type || "";
}

export const severityLabel: Record<string, string> = {
  info: "信息",
  low: "低",
  medium: "中",
  high: "高",
  critical: "严重",
};

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
