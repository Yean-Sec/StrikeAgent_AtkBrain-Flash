import { useEffect, useState } from "react";
import { api } from "../api";

export function SettingsPage() {
  const [message, setMessage] = useState("");
  const [custom, setCustom] = useState("");
  const [proxy, setProxy] = useState<any>(null);
  useEffect(() => {
    let first = true;
    const load = () => api.getProxyPool().then((r) => {
      setProxy(r);
      if (first) {
        setCustom(String(r?.custom_text || ""));
        first = false;
      }
    }).catch(() => {});
    load();
    const t = setInterval(load, 2000);
    return () => clearInterval(t);
  }, []);

  const savePool = async () => {
    setMessage("");
    try {
      const r = await api.saveProxyPool(custom);
      setProxy(r);
      setMessage("自建代理池已保存");
    } catch (e: any) {
      setMessage(String(e?.message || e));
    }
  };

  return (
    <div className="page-container settings-page">
      <header className="page-heading">
        <p className="eyebrow">SYSTEM</p>
        <h1>设置</h1>
        <p>出口代理池。</p>
      </header>
      {message && <p className={message.includes("已保存") ? "muted" : "error-text"}>{message}</p>}
      <div className="settings-grid">
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
          <h3>出口代理池</h3>
          <p className="muted">红队/SRC 打目标时必须走代理，无存活节点则拒绝出网，不会回落真实 IP。CTF 始终直连。一行一条，支持 <span className="mono">http://ip:port</span>、<span className="mono">socks5://ip:port</span> 或 <span className="mono">ip:port</span>。</p>
          <dl className="settings-list">
            <dt>开关</dt><dd>{proxy?.enabled ? "开" : "关"}（顶栏切换）</dd>
            <dt>存活</dt><dd>{proxy?.live ?? 0}</dd>
            <dt>最近出口 IP</dt><dd className="mono">{proxy?.exit_ip || "-"}</dd>
            {proxy?.error ? <><dt>状态</dt><dd className="error-text">{proxy.error}</dd></> : null}
          </dl>
          <textarea
            className="input"
            style={{ width: "100%", minHeight: 140, marginTop: 14, fontFamily: "var(--font-mono)", fontSize: 12 }}
            placeholder={"http://203.0.113.10:8080\nsocks5://198.51.100.2:1080"}
            value={custom}
            onChange={(e) => setCustom(e.target.value)}
          />
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" onClick={() => { void savePool(); }}>保存自建池</button>
          </div>
        </section>
      </div>
    </div>
  );
}
