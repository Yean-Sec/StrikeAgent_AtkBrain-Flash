/** 集群子项目多选操作条。 */

export function BatchSelectionBar({
  count,
  noun = "子项目",
  busy,
  onRun,
  onPause,
  onDelete,
  onClear,
}: {
  count: number;
  noun?: string;
  busy: boolean;
  onRun: () => void;
  onPause: () => void;
  onDelete: () => void;
  onClear: () => void;
}) {
  if (count <= 0) return null;
  return (
    <div className="batch-toolbar">
      <b>已选 {count} 个{noun}</b>
      <button className="btn btn-primary btn-sm" disabled={busy} onClick={onRun}>运行</button>
      <button className="btn btn-secondary btn-sm" disabled={busy} onClick={onPause}>暂停</button>
      <button className="btn btn-danger btn-sm" disabled={busy} onClick={onDelete}>删除</button>
      <button className="btn btn-secondary btn-sm" disabled={busy} onClick={onClear}>取消选择</button>
    </div>
  );
}
