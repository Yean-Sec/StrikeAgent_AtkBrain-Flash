import { useEffect, useState } from "react";
import { api } from "../api";

export function SettingsPage() {
  const [settings, setSettings] = useState<any>(null);
  const [message, setMessage] = useState("");
  useEffect(() => { api.settings().then(setSettings).catch((e) => setMessage(String(e?.message || e))); }, []);
  const defaults = settings?.defaults || {};
  return (
    <div className="page-container settings-page">
      <header className="page-heading">
        <p className="eyebrow">SYSTEM</p>
        <h1>设置</h1>
        <p>并发上限与模型。</p>
      </header>
      {message && <p className="error-text">{message}</p>}
      <div className="settings-grid">
        <section className="card-cream">
          <h3>运行并发</h3>
          <p className="muted">默认 10 个项目同时跑；每项目 2 个 Claude Code（主会话 + 自监督），共 20 个。</p>
          <dl className="settings-list">
            <dt>当前项目并发</dt><dd>{settings?.concurrency?.projects?.active ?? 0}/{settings?.concurrency?.projects?.limit ?? "-"}</dd>
            <dt>Agent 会话</dt><dd>{settings?.concurrency?.claude?.active ?? 0}/{settings?.concurrency?.claude?.limit ?? "-"}</dd>
            <dt>模型</dt><dd className="mono">{defaults.model || "-"}</dd>
            <dt>监督模型</dt><dd className="mono">{defaults.supervisor_model || defaults.model || "-"}</dd>
            <dt>自进化</dt><dd>{defaults.evolve_ai === false ? "关" : "开"}</dd>
          </dl>
        </section>
      </div>
    </div>
  );
}
