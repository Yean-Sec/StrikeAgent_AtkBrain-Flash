import type { AssetPreviewResult } from "../../api";

const PREVIEW_CAP = 12;

export function AssetMergePreview({ data }: { data: AssetPreviewResult }) {
  const groups = data.groups || [];
  const extra = Math.max(0, groups.length - PREVIEW_CAP);
  const shown = groups.slice(0, PREVIEW_CAP);
  const headers = data.skipped_header || [];
  const policy = data.policy === "product_zone" ? "SRC · 产品域" : "红队 · 同机";
  return (
    <div className="card-cream" style={{ margin: "10px 0 12px", padding: 14, fontSize: 13 }}>
      <div className="row" style={{ gap: 16, flexWrap: "wrap", marginBottom: 8 }}>
        <span>策略 <b>{policy}</b></span>
        <span>主机 <b>{data.hosts}</b></span>
        <span>将建子项目 <b>{data.group_count}</b></span>
        {data.skipped_dup_count > 0 && <span>重复行 <b>{data.skipped_dup_count}</b></span>}
        {headers.length > 0 && <span>丢掉表头 <b>{headers.join(", ")}</b></span>}
      </div>
      {data.note && <p className="muted" style={{ fontSize: 12, marginBottom: 8 }}>{data.note}</p>}
      {shown.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 18, maxHeight: 180, overflow: "auto" }}>
          {shown.map((g) => (
            <li key={g.primary} style={{ marginBottom: 4 }}>
              <b>{g.primary}</b>
              {g.zone ? <span className="muted"> · {g.zone}</span> : null}
              {g.vhosts.length > 1 ? ` · ${g.vhosts.length} 域` : ""}
              {g.ports.length ? ` · 端口 ${g.ports.join(",")}` : ""}
            </li>
          ))}
        </ul>
      )}
      {extra > 0 && <p className="muted" style={{ fontSize: 12, marginTop: 6 }}>另有 {extra} 组未展开</p>}
    </div>
  );
}
