import { useEffect, useState } from "react";
import { Navigate, useParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../AuthGate";
import { Modal } from "../components/Modal";
import { PasswordChangeForm } from "../components/PasswordChangeForm";
import { useT } from "../i18n";
import { GuardRules } from "../features/settings/GuardRules";

type HuntClocks = {
  loop_max_turns: number;
  loop_max_turns_agent: number;
  agent_runtime_hard_stop_sec: number;
  runtime_hard_stop_sec: number;
  runtime_hard_stop_pass2_sec: number;
  runtime_hard_stop_pass3_sec: number;
  runtime_hard_stop_pass_step_sec: number;
  graph_idle_empty_plans: number;
  loop_stall_limit_agent: number;
};

const EMPTY_CLOCKS: HuntClocks = {
  loop_max_turns: 0,
  loop_max_turns_agent: 0,
  agent_runtime_hard_stop_sec: 6 * 3600,
  runtime_hard_stop_sec: 40 * 60,
  runtime_hard_stop_pass2_sec: 120 * 60,
  runtime_hard_stop_pass3_sec: 180 * 60,
  runtime_hard_stop_pass_step_sec: 60 * 60,
  graph_idle_empty_plans: 6,
  loop_stall_limit_agent: 10,
};

function secToHours(sec: number) {
  return String(Math.round((Number(sec) || 0) / 3600 * 100) / 100);
}
function secToMin(sec: number) {
  return String(Math.round((Number(sec) || 0) / 60));
}

const SETTINGS_SECTIONS = ["account", "model", "hunt", "review", "proxy", "guard"] as const;
type SettingsSection = (typeof SETTINGS_SECTIONS)[number];

function isSection(value: string | undefined): value is SettingsSection {
  return SETTINGS_SECTIONS.includes(value as SettingsSection);
}

export function SettingsPage() {
  const { t } = useT();
  const { me, refresh } = useAuth();
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [custom, setCustom] = useState("");
  const [proxy, setProxy] = useState<any>(null);
  const [llm, setLlm] = useState({
    model: "",
    base_url: "",
    api_key: "",
    api_key_hint: "",
    api_key_set: false,
  });
  const [llmBusy, setLlmBusy] = useState<"" | "save" | "test">("");
  const [llmTest, setLlmTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [review, setReview] = useState({ secondary_verify: true, redteam_rating: true });
  const [webhook, setWebhook] = useState({ url: "", severities: "", projects: "", assets: "" });
  const [totpUrl, setTotpUrl] = useState("");
  const [totpSecret, setTotpSecret] = useState("");
  const [setupId, setSetupId] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [clocks, setClocks] = useState<HuntClocks>(EMPTY_CLOCKS);
  useEffect(() => {
    let first = true;
    const load = () => {
      api.getProxyPool().then((r) => {
        setProxy(r);
        if (first) {
          setCustom(String(r?.custom_text || ""));
          first = false;
        }
      }).catch(() => {});
    };
    load();
    api.getLlmProfile().then((r) => {
      setLlm({
        model: String(r?.model || ""),
        base_url: String(r?.base_url || ""),
        api_key: "",
        api_key_hint: String(r?.api_key_hint || ""),
        api_key_set: Boolean(r?.api_key_set),
      });
    }).catch(() => {});
    api.settings().then((r) => {
      const rv = r?.review;
      if (rv && typeof rv.secondary_verify === "boolean" && typeof rv.redteam_rating === "boolean") {
        setReview({ secondary_verify: rv.secondary_verify, redteam_rating: rv.redteam_rating });
      }
      const hc = r?.defaults?.hunt_clocks;
      if (hc && typeof hc === "object") setClocks({ ...EMPTY_CLOCKS, ...hc });
      const hook = r?.webhook;
      if (hook && typeof hook === "object") {
        setWebhook({
          url: String(hook.url || ""),
          severities: Array.isArray(hook.severities) ? hook.severities.join(",") : "",
          projects: Array.isArray(hook.projects) ? hook.projects.join(",") : "",
          assets: Array.isArray(hook.assets) ? hook.assets.join(",") : "",
        });
      }
    }).catch(() => {});
    const tmr = setInterval(load, 2000);
    return () => clearInterval(tmr);
  }, []);

  const tell = (ok: boolean, text: string) => {
    setMessage(text);
    setNotice({ ok, text });
  };

  const llmBody = () => ({
    model: llm.model.trim(),
    base_url: llm.base_url.trim(),
    api_key: llm.api_key,
  });

  const applyLlm = (r: { model?: string; base_url?: string; api_key_hint?: string; api_key_set?: boolean }) => {
    setLlm((cur) => ({
      ...cur,
      model: String(r?.model || cur.model),
      base_url: String(r?.base_url || cur.base_url),
      api_key: "",
      api_key_hint: String(r?.api_key_hint || ""),
      api_key_set: Boolean(r?.api_key_set),
    }));
  };

  const saveLlm = async () => {
    if (llmBusy) return;
    setMessage("");
    setLlmBusy("save");
    try {
      const r = await api.saveLlmProfile(llmBody());
      applyLlm(r);
      window.dispatchEvent(new Event("atkbrain-health"));
      tell(true, t("settings.piSaved"));
    } catch (e: any) {
      tell(false, String(e?.message || e));
    } finally {
      setLlmBusy("");
    }
  };

  const testLlm = async () => {
    if (llmBusy) return;
    setLlmTest(null);
    setLlmBusy("test");
    try {
      const r = await api.testLlmProfile(llmBody());
      if (r?.ok) {
        const head = t("settings.testOk", { ms: r.latency_ms ?? 0 });
        const reply = r.reply ? t("settings.testReply", { reply: r.reply }) : "";
        setLlmTest({ ok: true, text: reply ? `${head} · ${reply}` : head });
      } else {
        setLlmTest({ ok: false, text: String(r?.error || t("settings.saveFailedTitle")) });
      }
    } catch (e: any) {
      setLlmTest({ ok: false, text: String(e?.message || e) });
    } finally {
      setLlmBusy("");
    }
  };

  const savePool = async () => {
    setMessage("");
    try {
      const r = await api.saveProxyPool(custom);
      setProxy(r);
      tell(true, t("settings.poolSaved"));
    } catch (e: any) {
      tell(false, String(e?.message || e));
    }
  };

  const saveWebhook = async () => {
    setMessage("");
    try {
      const split = (raw: string) => raw.split(",").map((x) => x.trim()).filter(Boolean);
      const r = await api.setWebhook({
        url: webhook.url.trim(),
        severities: split(webhook.severities),
        projects: split(webhook.projects),
        assets: split(webhook.assets),
      });
      if (r?.webhook) {
        setWebhook({
          url: r.webhook.url || "",
          severities: (r.webhook.severities || []).join(","),
          projects: (r.webhook.projects || []).join(","),
          assets: (r.webhook.assets || []).join(","),
        });
      }
      tell(true, t("settings.webhookSave"));
    } catch (e: any) {
      tell(false, String(e?.message || e));
    }
  };

  const retryWebhook = async () => {
    setMessage("");
    try {
      const r = await api.retryWebhook();
      tell(true, `${t("settings.webhookRetry")} ${r.sent}/${r.sent + r.failed}`);
    } catch (e: any) {
      tell(false, String(e?.message || e));
    }
  };

  const toggleReview = async (key: "secondary_verify" | "redteam_rating") => {
    setMessage("");
    const next = { ...review, [key]: !review[key] };
    setReview(next);
    try {
      const r = await api.setReviewFlags({ [key]: next[key] });
      if (r?.review) setReview(r.review);
    } catch (e: any) {
      setReview(review);
      setMessage(String(e?.message || e));
    }
  };

  const startTotp = async () => {
    setMessage("");
    try {
      const r = await api.totpSetup();
      setTotpUrl(r.otpauth_url);
      setTotpSecret(r.secret);
      setSetupId(r.setup_id);
    } catch (e: any) {
      setMessage(String(e?.message || e));
    }
  };

  const confirmTotp = async () => {
    setMessage("");
    try {
      await api.totpConfirm(setupId, totpCode.trim());
      setTotpUrl("");
      setTotpSecret("");
      setSetupId("");
      setTotpCode("");
      await refresh();
      tell(true, t("settings.totpOk"));
    } catch (e: any) {
      tell(false, String(e?.message || e));
    }
  };

  const saveClocks = async () => {
    setMessage("");
    try {
      const r = await api.setHuntClocks(clocks);
      if (r?.hunt_clocks) setClocks({ ...EMPTY_CLOCKS, ...r.hunt_clocks });
      tell(true, t("settings.clocksSaved"));
    } catch (e: any) {
      tell(false, String(e?.message || e));
    }
  };

  const setClock = (key: keyof HuntClocks, raw: string, unit: "sec" | "min" | "hour" | "int") => {
    const n = Number(raw);
    let sec = 0;
    if (Number.isFinite(n)) {
      if (unit === "hour") sec = Math.round(n * 3600);
      else if (unit === "min") sec = Math.round(n * 60);
      else sec = Math.round(n);
    }
    setClocks((c) => ({ ...c, [key]: sec }));
  };

  const { section: rawSection } = useParams();
  if (rawSection && !isSection(rawSection)) {
    return <Navigate to="/settings/account" replace />;
  }
  const section: SettingsSection = isSection(rawSection) ? rawSection : "account";
  const nav: { id: SettingsSection; label: string }[] = [
    { id: "account", label: t("settings.navAccount") },
    { id: "model", label: t("settings.navModel") },
    { id: "hunt", label: t("settings.navHunt") },
    { id: "review", label: t("settings.navReview") },
    { id: "proxy", label: t("settings.navProxy") },
    { id: "guard", label: t("settings.navGuard") },
  ];

  return (
    <div className="page-container settings-page">
      <header className="page-heading">
        <p className="eyebrow">SYSTEM</p>
        <h1>{nav.find((item) => item.id === section)?.label}</h1>
      </header>
      {message && <p className={/失败|Error|error|already/i.test(message) ? "error-text" : "muted"}>{message}</p>}
      {notice ? (
        <Modal title={notice.ok ? t("settings.savedTitle") : t("settings.saveFailedTitle")} onClose={() => setNotice(null)}>
          <p>{notice.text}</p>
          <div style={{ marginTop: 18, textAlign: "right" }}>
            <button className="btn btn-primary" type="button" onClick={() => setNotice(null)}>{t("common.confirm")}</button>
          </div>
        </Modal>
      ) : null}
      <div className="settings-shell">
        <div className="settings-panel">
        {section === "account" && me?.authenticated ? (
          <section className="card-cream">
            <h3>{t("password.settingsTitle")}</h3>
            <p className="muted">{t("password.settingsHint")}</p>
            <PasswordChangeForm requireOld onDone={() => { void refresh(); }} />
          </section>
        ) : null}
        {section === "hunt" ? (
        <section className="card-cream">
          <h3>{t("settings.clocksTitle")}</h3>
          <p className="muted">{t("settings.clocksHint")}</p>
          <div className="hunt-clock-grid">
            <div>
              <h4>{t("projects.trackAgent")}</h4>
              <label className="login-field">
                <span>{t("settings.clockHours")}</span>
                <input className="input" type="number" min={0} max={72} step={0.5} value={secToHours(clocks.agent_runtime_hard_stop_sec)} onChange={(e) => setClock("agent_runtime_hard_stop_sec", e.target.value, "hour")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockTurns")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_max_turns_agent} onChange={(e) => setClock("loop_max_turns_agent", e.target.value, "int")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockStall")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_stall_limit_agent} onChange={(e) => setClock("loop_stall_limit_agent", e.target.value, "int")} />
              </label>
            </div>
            <div>
              <h4>{t("projects.trackCtfBtn")}</h4>
              <label className="login-field">
                <span>{t("settings.clockCtfPass1")}</span>
                <input className="input" type="number" min={0} max={4320} value={secToMin(clocks.runtime_hard_stop_sec)} onChange={(e) => setClock("runtime_hard_stop_sec", e.target.value, "min")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockCtfPass2")}</span>
                <input className="input" type="number" min={0} max={4320} value={secToMin(clocks.runtime_hard_stop_pass2_sec)} onChange={(e) => setClock("runtime_hard_stop_pass2_sec", e.target.value, "min")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockCtfPass3")}</span>
                <input className="input" type="number" min={0} max={4320} value={secToMin(clocks.runtime_hard_stop_pass3_sec)} onChange={(e) => setClock("runtime_hard_stop_pass3_sec", e.target.value, "min")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockCtfStep")}</span>
                <input className="input" type="number" min={0} max={4320} value={secToMin(clocks.runtime_hard_stop_pass_step_sec)} onChange={(e) => setClock("runtime_hard_stop_pass_step_sec", e.target.value, "min")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockTurns")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_max_turns} onChange={(e) => setClock("loop_max_turns", e.target.value, "int")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockIdlePlans")}</span>
                <input className="input" type="number" min={1} max={100} value={clocks.graph_idle_empty_plans} onChange={(e) => setClock("graph_idle_empty_plans", e.target.value, "int")} />
              </label>
            </div>
          </div>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" onClick={() => { void saveClocks(); }}>{t("settings.saveClocks")}</button>
          </div>
        </section>
        ) : null}
        {section === "review" ? (
        <>
        <section className="card-cream">
          <h3>{t("settings.webhookTitle")}</h3>
          <p className="muted">{t("settings.webhookHint")}</p>
          <label className="login-field">
            <span>{t("settings.webhookUrl")}</span>
            <input className="input" value={webhook.url} onChange={(e) => setWebhook({ ...webhook, url: e.target.value })} placeholder="https://" />
          </label>
          <label className="login-field">
            <span>{t("settings.webhookSeverity")}</span>
            <input className="input" value={webhook.severities} onChange={(e) => setWebhook({ ...webhook, severities: e.target.value })} placeholder="high,critical" />
          </label>
          <label className="login-field">
            <span>{t("settings.webhookProjects")}</span>
            <input className="input" value={webhook.projects} onChange={(e) => setWebhook({ ...webhook, projects: e.target.value })} placeholder="p_..." />
          </label>
          <label className="login-field">
            <span>{t("settings.webhookAssets")}</span>
            <input className="input" value={webhook.assets} onChange={(e) => setWebhook({ ...webhook, assets: e.target.value })} placeholder="app.example.com" />
          </label>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" onClick={() => { void saveWebhook(); }}>{t("settings.webhookSave")}</button>
            <button className="btn btn-secondary btn-sm" type="button" onClick={() => { void retryWebhook(); }}>{t("settings.webhookRetry")}</button>
          </div>
        </section>
        <section className="card-cream">
          <h3>{t("settings.reviewTitle")}</h3>
          <p className="muted">{t("settings.reviewHint")}</p>
          <dl className="settings-list">
            <dt>{t("settings.reviewSecondary")}</dt>
            <dd>
              <button
                type="button"
                className={`proxy-switch${review.secondary_verify ? " is-on" : ""}`}
                aria-pressed={review.secondary_verify}
                onClick={() => { void toggleReview("secondary_verify"); }}
              >
                <span className="proxy-switch-knob" />
              </button>
              <span style={{ marginLeft: 8 }}>{review.secondary_verify ? t("common.on") : t("common.off")}</span>
            </dd>
            <dt>{t("settings.reviewRating")}</dt>
            <dd>
              <button
                type="button"
                className={`proxy-switch${review.redteam_rating ? " is-on" : ""}`}
                aria-pressed={review.redteam_rating}
                onClick={() => { void toggleReview("redteam_rating"); }}
              >
                <span className="proxy-switch-knob" />
              </button>
              <span style={{ marginLeft: 8 }}>{review.redteam_rating ? t("common.on") : t("common.off")}</span>
            </dd>
          </dl>
        </section>
        </>
        ) : null}
        {section === "account" && me?.authenticated ? (
          <section className="card-cream">
            <h3>{t("settings.totpTitle")}</h3>
            <p className="muted">{t("settings.totpHint")}</p>
            <dl className="settings-list">
              <dt>{t("common.status")}</dt>
              <dd>{me.totp_enabled ? t("settings.bound") : t("settings.unbound")}</dd>
              <dt>{t("common.user")}</dt>
              <dd className="mono">{me.username || "-"}</dd>
            </dl>
            {!me.totp_enabled && (
              <div className="row" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
                <button className="btn btn-secondary btn-sm" type="button" onClick={() => { void startTotp(); }}>{t("settings.genTotp")}</button>
                {setupId ? (
                  <>
                    <input
                      className="input"
                      style={{ width: 140 }}
                      placeholder={t("settings.totpPh")}
                      value={totpCode}
                      onChange={(e) => setTotpCode(e.target.value)}
                    />
                    <button className="btn btn-primary btn-sm" type="button" onClick={() => { void confirmTotp(); }}>{t("settings.confirmTotp")}</button>
                  </>
                ) : null}
              </div>
            )}
            {totpSecret ? (
              <p className="mono table-sub" style={{ marginTop: 10, wordBreak: "break-all" }}>
                {totpSecret}
                {totpUrl ? <><br />{totpUrl}</> : null}
              </p>
            ) : null}
          </section>
        ) : null}
        {section === "proxy" ? (
        <section className="card-cream">
          <h3>{t("settings.proxyTitle")}</h3>
          <p className="muted">{t("settings.proxyHint")}</p>
          <dl className="settings-list">
            <dt>{t("settings.switch")}</dt><dd>{proxy?.enabled ? t("common.on") : t("common.off")}{t("settings.switchHint")}</dd>
            <dt>{t("settings.live")}</dt><dd>{proxy?.live ?? 0}</dd>
            <dt>{t("settings.exitIp")}</dt><dd className="mono">{proxy?.exit_ip || "-"}</dd>
            {proxy?.error ? <><dt>{t("common.status")}</dt><dd className="error-text">{proxy.error}</dd></> : null}
          </dl>
          <textarea
            className="input"
            style={{ width: "100%", minHeight: 140, marginTop: 14, fontFamily: "var(--font-mono)", fontSize: 12 }}
            placeholder={"http://203.0.113.10:8080\nsocks5://198.51.100.2:1080"}
            value={custom}
            onChange={(e) => setCustom(e.target.value)}
          />
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" onClick={() => { void savePool(); }}>{t("settings.savePool")}</button>
          </div>
        </section>
        ) : null}
        {section === "model" ? (
        <section className="card-cream">
          <h3>{t("settings.piTitle")}</h3>
          <p className="muted">{t("settings.piHint")}</p>
          <div style={{ display: "grid", gap: 12, marginTop: 14, maxWidth: 640 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.model")}</span>
              <input
                className="input mono"
                value={llm.model}
                placeholder="deepseek-v4-flash"
                onChange={(e) => setLlm((cur) => ({ ...cur, model: e.target.value }))}
                spellCheck={false}
              />
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.baseUrl")}</span>
              <input
                className="input mono"
                value={llm.base_url}
                placeholder="https://api.deepseek.com"
                onChange={(e) => setLlm((cur) => ({ ...cur, base_url: e.target.value }))}
                spellCheck={false}
              />
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.apiKey")}</span>
              <input
                className="input mono"
                type="password"
                value={llm.api_key}
                placeholder={llm.api_key_set ? t("settings.apiKeyKeep", { hint: llm.api_key_hint || "…" }) : "sk-…"}
                onChange={(e) => setLlm((cur) => ({ ...cur, api_key: e.target.value }))}
                autoComplete="off"
                spellCheck={false}
              />
            </label>
          </div>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" disabled={llmBusy !== ""} onClick={() => { void saveLlm(); }}>
              {llmBusy === "save" ? t("common.saving") : t("settings.savePi")}
            </button>
            <button className="btn btn-secondary btn-sm" type="button" disabled={llmBusy !== ""} onClick={() => { void testLlm(); }}>
              {llmBusy === "test" ? t("settings.testing") : t("settings.testLlm")}
            </button>
          </div>
          {llmTest ? <p className={llmTest.ok ? "muted" : "error-text"} style={{ marginTop: 10 }}>{llmTest.text}</p> : null}
        </section>
        ) : null}
        {section === "guard" ? <GuardRules /> : null}
        </div>
      </div>
    </div>
  );
}
