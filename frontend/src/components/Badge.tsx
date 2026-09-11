export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity.toUpperCase()}</span>;
}

export function VerifyBadge({ status }: { status?: string }) {
  const s = (status || "verified").toLowerCase();
  if (s === "rejected") {
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--error)" }}>已驳回</span>
    );
  }
  if (s === "pending") {
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--muted)" }}>未验证</span>
    );
  }
  if (s === "flaky") {
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--warning, #d4a017)" }}>不稳定</span>
    );
  }
  return (
    <span className="kbd" style={{ fontSize: 11, color: "var(--ok, #2a7)" }}>已验证</span>
  );
}

const RT_RATING_LABEL: Record<string, string> = {
  critical: "红队·严重",
  high: "红队·高危",
  medium: "红队·中危",
  low: "红队·低危",
  info: "红队·信息",
};

export function SecondaryVerifyBadge({ done, reviewing }: { done?: boolean; reviewing?: boolean }) {
  if (done) {
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--ok, #2a7)" }}>已二次验证</span>
    );
  }
  if (reviewing) {
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--warning, #d4a017)" }}>二次验证中</span>
    );
  }
  return (
    <span className="kbd" style={{ fontSize: 11, color: "var(--muted)" }}>未二次验证</span>
  );
}

export function RedteamRatingBadge({ rating, reviewing }: { rating?: string; reviewing?: boolean }) {
  const s = (rating || "").toLowerCase();
  const label = RT_RATING_LABEL[s];
  if (!label) {
    if (reviewing) {
      return (
        <span className="kbd" style={{ fontSize: 11, color: "var(--warning, #d4a017)" }}>红队评级中</span>
      );
    }
    return (
      <span className="kbd" style={{ fontSize: 11, color: "var(--muted)" }}>红队未评级</span>
    );
  }
  const color = s === "critical" || s === "high" ? "var(--error, #c44)" : s === "medium" ? "var(--warning, #d4a017)" : "var(--muted)";
  return (
    <span className="kbd" style={{ fontSize: 11, color }}>{label}</span>
  );
}

export function Badge({ children, coral }: { children: any; coral?: boolean }) {
  return <span className={`badge ${coral ? "badge-coral" : "badge-pill"}`}>{children}</span>;
}
