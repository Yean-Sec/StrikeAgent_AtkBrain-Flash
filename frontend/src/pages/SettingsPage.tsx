import { useEffect, useState } from "react";
import { api } from "../api";
import { useAuth } from "../AuthGate";
import { LangToggle } from "../components/LangToggle";
import { Modal } from "../components/Modal";
import { PasswordChangeForm } from "../components/PasswordChangeForm";
import { useT } from "../i18n";

type HuntClocks = {
  loop_max_turns: number;
  loop_max_turns_src: number;
  loop_max_turns_redteam: number;
  src_runtime_hard_stop_sec: number;
  redteam_runtime_hard_stop_sec: number;
  runtime_hard_stop_sec: number;
  runtime_hard_stop_pass2_sec: number;
  runtime_hard_stop_pass3_sec: number;
  runtime_hard_stop_pass_step_sec: number;
  graph_idle_empty_plans: number;
  loop_stall_limit_redteam: number;
  loop_stall_limit_src: number;
};

const EMPTY_CLOCKS: HuntClocks = {
  loop_max_turns: 0,
  loop_max_turns_src: 0,
  loop_max_turns_redteam: 0,
  src_runtime_hard_stop_sec: 12 * 3600,
  redteam_runtime_hard_stop_sec: 12 * 3600,
  runtime_hard_stop_sec: 40 * 60,
  runtime_hard_stop_pass2_sec: 120 * 60,
  runtime_hard_stop_pass3_sec: 180 * 60,
  runtime_hard_stop_pass_step_sec: 60 * 60,
  graph_idle_empty_plans: 6,
  loop_stall_limit_redteam: 10,
  loop_stall_limit_src: 10,
};

function secToHours(sec: number) {
  return String(Math.round((Number(sec) || 0) / 3600 * 100) / 100);
}
function secToMin(sec: number) {
  return String(Math.round((Number(sec) || 0) / 60));
}

export function SettingsPage() {
  const { t, locale } = useT();
  const { me, refresh } = useAuth();
  const [message, setMessage] = useState("");
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const [custom, setCustom] = useState("");
  const [proxy, setProxy] = useState<any>(null);
  const [llm, setLlm] = useState({
    format: "openai" as "openai" | "anthropic",
    model: "",
    base_url: "",
    api_key: "",
    api_key_hint: "",
    api_key_set: false,
  });
  const [llmBusy, setLlmBusy] = useState<"" | "save" | "test">("");
  const [llmTest, setLlmTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [review, setReview] = useState({ secondary_verify: true, redteam_rating: true });
  const [totpUrl, setTotpUrl] = useState("");
  const [totpSecret, setTotpSecret] = useState("");
  const [setupId, setSetupId] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [clocks, setClocks] = useState<HuntClocks>(EMPTY_CLOCKS);
  const [clockPreview, setClockPreview] = useState<Record<string, { label?: string; conditions?: string[] }>>({});
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
        format: r?.format === "anthropic" ? "anthropic" : "openai",
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
      if (r?.defaults?.hard_stop) setClockPreview(r.defaults.hard_stop);
    }).catch(() => {});
    const tmr = setInterval(load, 2000);
    return () => clearInterval(tmr);
  }, []);

  useEffect(() => {
    api.settings().then((r) => {
      if (r?.defaults?.hard_stop) setClockPreview(r.defaults.hard_stop);
    }).catch(() => {});
  }, [locale]);

  const tell = (ok: boolean, text: string) => {
    setMessage(text);
    setNotice({ ok, text });
  };

  const llmBody = () => ({
    format: llm.format,
    model: llm.model.trim(),
    base_url: llm.base_url.trim(),
    api_key: llm.api_key,
  });

  const applyLlm = (r: { format?: string; model?: string; base_url?: string; api_key_hint?: string; api_key_set?: boolean }) => {
    setLlm((cur) => ({
      ...cur,
      format: r?.format === "anthropic" ? "anthropic" : cur.format,
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
      if (r?.hard_stop) setClockPreview(r.hard_stop);
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

  return (
    <div className="page-container settings-page">
      <header className="page-heading">
        <p className="eyebrow">SYSTEM</p>
        <h1>{t("settings.title")}</h1>
        <p>{t("settings.subtitle")}</p>
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
      <div className="settings-grid">
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
          <h3>{t("settings.langCard")}</h3>
          <LangToggle />
          <p className="muted" style={{ marginTop: 10 }}>{t("common.legacyHint")}</p>
        </section>
        {me?.authenticated ? (
          <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
            <h3>{t("password.settingsTitle")}</h3>
            <p className="muted">{t("password.settingsHint")}</p>
            <PasswordChangeForm requireOld onDone={() => { void refresh(); }} />
          </section>
        ) : null}
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
          <h3>{t("settings.clocksTitle")}</h3>
          <p className="muted">{t("settings.clocksHint")}</p>
          <div className="hunt-clock-grid">
            <div>
              <h4>{t("projects.trackRedBtn")}</h4>
              <label className="login-field">
                <span>{t("settings.clockHours")}</span>
                <input className="input" type="number" min={0} max={72} step={0.5} value={secToHours(clocks.redteam_runtime_hard_stop_sec)} onChange={(e) => setClock("redteam_runtime_hard_stop_sec", e.target.value, "hour")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockTurns")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_max_turns_redteam} onChange={(e) => setClock("loop_max_turns_redteam", e.target.value, "int")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockStall")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_stall_limit_redteam} onChange={(e) => setClock("loop_stall_limit_redteam", e.target.value, "int")} />
              </label>
              <p className="muted" style={{ fontSize: 12 }}>{clockPreview.redteam?.label || ""}</p>
            </div>
            <div>
              <h4>{t("projects.trackSrcBtn")}</h4>
              <label className="login-field">
                <span>{t("settings.clockHours")}</span>
                <input className="input" type="number" min={0} max={72} step={0.5} value={secToHours(clocks.src_runtime_hard_stop_sec)} onChange={(e) => setClock("src_runtime_hard_stop_sec", e.target.value, "hour")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockTurns")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_max_turns_src} onChange={(e) => setClock("loop_max_turns_src", e.target.value, "int")} />
              </label>
              <label className="login-field">
                <span>{t("settings.clockStall")}</span>
                <input className="input" type="number" min={0} max={9999} value={clocks.loop_stall_limit_src} onChange={(e) => setClock("loop_stall_limit_src", e.target.value, "int")} />
              </label>
              <p className="muted" style={{ fontSize: 12 }}>{clockPreview.src?.label || ""}</p>
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
              <p className="muted" style={{ fontSize: 12 }}>{clockPreview.flag?.label || ""}</p>
            </div>
          </div>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn btn-primary btn-sm" type="button" onClick={() => { void saveClocks(); }}>{t("settings.saveClocks")}</button>
          </div>
        </section>
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
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
        {me?.authenticated ? (
          <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
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
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
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
        <section className="card-cream" style={{ gridColumn: "1 / -1" }}>
          <h3>{t("settings.piTitle")}</h3>
          <p className="muted">{t("settings.piHint")}</p>
          <div style={{ display: "grid", gap: 12, marginTop: 14, maxWidth: 640 }}>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.format")}</span>
              <select
                className="input"
                value={llm.format}
                onChange={(e) => setLlm((cur) => ({ ...cur, format: e.target.value === "anthropic" ? "anthropic" : "openai" }))}
              >
                <option value="openai">{t("settings.formatOpenai")}</option>
                <option value="anthropic">{t("settings.formatAnthropic")}</option>
              </select>
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.model")}</span>
              <input
                className="input mono"
                value={llm.model}
                placeholder={llm.format === "anthropic" ? "claude-sonnet-4-5" : "gpt-4.1"}
                onChange={(e) => setLlm((cur) => ({ ...cur, model: e.target.value }))}
                spellCheck={false}
              />
            </label>
            <label style={{ display: "grid", gap: 6 }}>
              <span className="muted">{t("settings.baseUrl")}</span>
              <input
                className="input mono"
                value={llm.base_url}
                placeholder={llm.format === "anthropic" ? "https://api.anthropic.com" : "https://api.openai.com/v1"}
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
      </div>
    </div>
  );
}
