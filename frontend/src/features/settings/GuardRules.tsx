import { useEffect, useState } from "react";
import { api } from "../../api";
import { useT } from "../../i18n";

type GuardRule = {
  id: string;
  name: string;
  category?: string;
  pattern: string;
  reason?: string;
  enabled?: boolean;
  builtin?: boolean;
};

const CATEGORY: Record<string, string> = {
  destructive: "破坏性命令",
  scope: "越界主机",
  wordlist: "超大词表",
  quarantine: "隔离区执行",
  custom: "自定义",
};

export function GuardRules() {
  const { t } = useT();
  const [builtin, setBuiltin] = useState<GuardRule[]>([]);
  const [custom, setCustom] = useState<GuardRule[]>([]);
  const [name, setName] = useState("");
  const [pattern, setPattern] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");

  const load = () => {
    api.guardRules().then((r) => {
      setBuiltin(r.builtin || []);
      setCustom(r.custom || []);
      setError("");
    }).catch((e: Error) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const add = async () => {
    setError("");
    try {
      await api.createGuardRule({ name, pattern, reason, enabled: true });
      setName("");
      setPattern("");
      setReason("");
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section className="card-cream" style={{ padding: 18 }}>
      <h2 style={{ marginTop: 0 }}>{t("settings.navGuard")}</h2>
      <p className="muted">{t("settings.guardHint")}</p>
      {error ? <p className="error-text">{error}</p> : null}
      <h3>{t("settings.guardBuiltin")}</h3>
      <div style={{ overflow: "auto" }}>
        <table className="rule-table">
          <thead>
            <tr>
              <th>{t("settings.guardName")}</th>
              <th>类别</th>
              <th>{t("settings.guardPattern")}</th>
            </tr>
          </thead>
          <tbody>
            {builtin.map((row) => (
              <tr key={row.id}>
                <td>{row.name}</td>
                <td>{CATEGORY[row.category || ""] || row.category}</td>
                <td className="mono">{row.pattern}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3>{t("settings.guardCustom")}</h3>
      <div className="guard-create">
        <input className="input" value={name} placeholder={t("settings.guardName")} onChange={(e) => setName(e.target.value)} />
        <input className="input mono" value={pattern} placeholder={t("settings.guardPattern")} onChange={(e) => setPattern(e.target.value)} spellCheck={false} />
        <input className="input" value={reason} placeholder={t("settings.guardReason")} onChange={(e) => setReason(e.target.value)} />
        <button className="btn btn-primary btn-sm" type="button" onClick={() => { void add(); }}>{t("settings.guardAdd")}</button>
      </div>
      {custom.length === 0 ? <p className="muted">{t("settings.guardEmpty")}</p> : (
        <div style={{ overflow: "auto" }}>
          <table className="rule-table">
            <thead>
              <tr>
                <th>{t("settings.guardName")}</th>
                <th>{t("settings.guardPattern")}</th>
                <th>{t("settings.guardReason")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {custom.map((row) => (
                <tr key={row.id} className={row.enabled === false ? "is-off" : undefined}>
                  <td>{row.name}</td>
                  <td className="mono">{row.pattern}</td>
                  <td>{row.reason}</td>
                  <td className="row" style={{ gap: 6 }}>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => {
                        void api.setGuardRuleEnabled(row.id, row.enabled === false).then(load).catch((e: Error) => setError(e.message));
                      }}
                    >
                      {row.enabled === false ? t("settings.guardEnable") : t("settings.guardDisable")}
                    </button>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => {
                        void api.deleteGuardRule(row.id).then(load).catch((e: Error) => setError(e.message));
                      }}
                    >
                      {t("settings.guardDelete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
