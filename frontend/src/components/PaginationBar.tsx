const PAGE_SIZES = [10, 30, 50] as const;
const STORAGE_KEY = "atkbrain.pageSize";

export function readPageSize(): number {
  try {
    const n = Number(localStorage.getItem(STORAGE_KEY));
    if (n === 10 || n === 30 || n === 50) return n;
  } catch {}
  return 30;
}

export function writePageSize(n: number) {
  try {
    localStorage.setItem(STORAGE_KEY, String(n));
  } catch {}
}

export function pageItems<T>(items: T[], page: number, pageSize: number): T[] {
  const start = Math.max(0, (page - 1) * pageSize);
  return items.slice(start, start + pageSize);
}

function pageWindow(cur: number, pages: number): (number | "…")[] {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const out: (number | "…")[] = [1];
  const from = Math.max(2, cur - 1);
  const to = Math.min(pages - 1, cur + 1);
  if (from > 2) out.push("…");
  for (let i = from; i <= to; i++) out.push(i);
  if (to < pages - 1) out.push("…");
  out.push(pages);
  return out;
}

export function PaginationBar({
  total,
  page,
  pageSize,
  onPage,
  onPageSize,
}: {
  total: number;
  page: number;
  pageSize: number;
  onPage: (p: number) => void;
  onPageSize: (n: number) => void;
}) {
  if (total <= 0) return null;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const cur = Math.min(Math.max(1, page), pages);
  const from = (cur - 1) * pageSize + 1;
  const to = Math.min(total, cur * pageSize);
  return (
    <div className="pager">
      <span className="muted pager-count">
        {from}–{to} / {total}
      </span>
      <div className="pager-sizes" role="group" aria-label="每页条数">
        {PAGE_SIZES.map((n) => (
          <button
            key={n}
            type="button"
            className={n === pageSize ? "active" : ""}
            onClick={() => {
              writePageSize(n);
              onPageSize(n);
              onPage(1);
            }}
          >
            {n} / 页
          </button>
        ))}
      </div>
      <div className="pager-pages">
        <button type="button" disabled={cur <= 1} onClick={() => onPage(cur - 1)} aria-label="上一页">
          上一页
        </button>
        {pageWindow(cur, pages).map((item, i) =>
          item === "…" ? (
            <span key={`e${i}`} className="pager-ellipsis">…</span>
          ) : (
            <button
              key={item}
              type="button"
              className={item === cur ? "active" : ""}
              onClick={() => onPage(item)}
            >
              {item}
            </button>
          ),
        )}
        <button type="button" disabled={cur >= pages} onClick={() => onPage(cur + 1)} aria-label="下一页">
          下一页
        </button>
      </div>
    </div>
  );
}
