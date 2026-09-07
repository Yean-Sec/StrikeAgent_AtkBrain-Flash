import { useEffect, useState } from "react";
import { api } from "../../api";
import { colors } from "../../theme";

type MemoryRow = {
  id: string;
  target_fp?: string;
  version?: number;
  outcome?: string;
  rule?: string;
  chain?: string;
  do?: string[];
  avoid?: string[];
  confidence?: number;
  wins?: number;
  content?: {
    techniques?: string[];
    winning_path?: string;
    approach?: string;
    rule?: string;
    chain?: string;
    do?: string[];
    avoid?: string[];
    confidence?: number;
    wins?: number;
  };
  created_at?: number;
};

export function MemoryPanel({ projectId }: { projectId: string }) {
  const [episodes, setEpisodes] = useState<MemoryRow[]>([]);
  const [playbook, setPlaybook] = useState<MemoryRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError("");
    api.projectMemory(projectId)
      .then((data) => {
        if (!live) return;
        setEpisodes(data.episodes || []);
        setPlaybook(data.playbook || []);
      })
      .catch((e) => live && setError(String(e?.message || e)))
      .finally(() => live && setLoading(false));
    return () => { live = false; };
  }, [projectId]);

  if (loading) return <p className="muted" style={{ padding: 16 }}>正在读取自进化记忆…</p>;
  if (error) return <p style={{ padding: 16, color: colors.error }}>自进化记忆读取失败：{error}</p>;
  if (!episodes.length && !playbook.length) {
    return <p className="muted" style={{ padding: 16 }}>尚无自进化剧本或本局 episode。跑完一局会自动蒸馏；之后的项目会按技术栈取回。</p>;
  }

  return (
    <div style={{ padding: "14px 2px", display: "grid", gap: 16 }}>
      <section>
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <b>自进化剧本</b>
          <span className="badge">{playbook.length} 条</span>
        </div>
        {!playbook.length && (
          <p className="muted" style={{ fontSize: 13 }}>还没有与当前攻击图匹配的跨局手法。</p>
        )}
        {playbook.map((ls) => {
          const c = ls.content || ls;
          const rule = ls.rule || c.rule || c.approach;
          const chain = ls.chain || c.chain;
          const conf = ls.confidence ?? c.confidence;
          return (
            <div key={ls.id} style={{ borderTop: "1px solid var(--hairline)", padding: "10px 0" }}>
              <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
                <span className="badge badge-coral">playbook</span>
                {conf != null && (
                  <span className="muted" style={{ fontSize: 12 }}>置信 {Number(conf).toFixed(2)}</span>
                )}
                <span className="mono muted" style={{ fontSize: 12 }}>{ls.target_fp || "通用"}</span>
              </div>
              {rule && (
                <p style={{ fontSize: 13, margin: "7px 0 0", lineHeight: 1.5 }}>{rule}</p>
              )}
              {!!(ls.do || c.do)?.length && (
                <p className="muted" style={{ fontSize: 12, margin: "6px 0 0" }}>
                  优先：{(ls.do || c.do || []).join(" · ")}
                </p>
              )}
              {!!(ls.avoid || c.avoid)?.length && (
                <p className="muted" style={{ fontSize: 12, margin: "4px 0 0" }}>
                  避免：{(ls.avoid || c.avoid || []).join(" · ")}
                </p>
              )}
              {chain && (
                <p className="mono" style={{ fontSize: 11, lineHeight: 1.5, margin: "7px 0 0", overflowWrap: "anywhere" }}>
                  {chain}
                </p>
              )}
            </div>
          );
        })}
      </section>
      <section>
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <b>本局 episode</b>
          <span className="badge">{episodes.length} 条 episode</span>
        </div>
        {!episodes.length && (
          <p className="muted" style={{ fontSize: 13 }}>本项目尚未生成 episode。</p>
        )}
        {episodes.map((ep) => (
          <div key={ep.id} style={{ borderTop: "1px solid var(--hairline)", padding: "10px 0" }}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <span className="badge badge-coral">{ep.outcome || "unknown"}</span>
              <span className="mono muted" style={{ fontSize: 12 }}>{ep.target_fp || "未分类"}</span>
              <span className="muted" style={{ fontSize: 12 }}>v{ep.version || 1}</span>
            </div>
            {!!ep.content?.techniques?.length && (
              <p className="muted" style={{ fontSize: 12, margin: "7px 0 0" }}>
                技术：{ep.content.techniques.join(" · ")}
              </p>
            )}
            {(ep.content?.approach || ep.content?.winning_path) && (
              <p className="mono" style={{ fontSize: 11, lineHeight: 1.5, margin: "7px 0 0", overflowWrap: "anywhere" }}>
                {ep.content.approach || ep.content.winning_path}
              </p>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}
