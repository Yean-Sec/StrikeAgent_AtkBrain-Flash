#!/usr/bin/env bash
# StrikeAgent_AtkBrain-Flash 后端常驻管理：经 systemd 拉起，崩溃自动重启。
# 用法: scripts/atkbrain-backend.sh {install|start|stop|restart|status|logs|uninstall}
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$REPO/deploy/systemd/atkbrain-backend.service"
UNIT_DST="/etc/systemd/system/atkbrain-flash-backend.service"
LOG_DIR="$REPO/backend/data/logs"
PY="/usr/bin/python3"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "需要 root（sudo）"; }

wait_health() {
  local i
  for i in $(seq 1 30); do
    if curl -fsS -m 2 http://127.0.0.1:5003/api/health >/tmp/rt-health.json 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# shellcheck source=/dev/null
source "$REPO/scripts/_atkbrain-systemd.sh"

cmd_install() {
  need_root
  [[ -x "$PY" ]] || die "找不到 python3: $PY"
  [[ -f "$UNIT_SRC" ]] || die "找不到 unit: $UNIT_SRC"
  mkdir -p "$LOG_DIR"
  retire_legacy_units
  migrate_legacy_runtime
  snapshot_claude_env
  kill_stray_backend
  sed "s|__REPO__|$REPO|g" "$UNIT_SRC" > "$UNIT_DST"
  chmod 644 "$UNIT_DST"
  systemctl daemon-reload
  systemctl enable atkbrain-flash-backend.service
  systemctl restart atkbrain-flash-backend.service
  wait_health || true
  cmd_status
  echo "[*] 已安装并启动。之后请用本脚本 restart，勿在 Cursor shell 里前台跑 python -m atkbrain.main"
}

cmd_start() {
  need_root
  mkdir -p "$LOG_DIR"
  snapshot_claude_env
  systemctl start atkbrain-flash-backend.service
  wait_health || true
  cmd_status
}

cmd_stop() {
  need_root
  systemctl stop atkbrain-flash-backend.service
  cmd_status
}

cmd_restart() {
  need_root
  mkdir -p "$LOG_DIR"
  if [[ ! -f "$UNIT_DST" ]]; then
    cmd_install
    return
  fi
  # 已在跑新 unit 时只需确保数据已迁；不要再 disable 自己
  migrate_legacy_runtime
  snapshot_claude_env
  sed "s|__REPO__|$REPO|g" "$UNIT_SRC" > "$UNIT_DST"
  chmod 644 "$UNIT_DST"
  systemctl daemon-reload
  systemctl restart atkbrain-flash-backend.service
  wait_health || true
  cmd_status
}

cmd_status() {
  systemctl --no-pager --full status atkbrain-flash-backend.service || true
  echo "---"
  if curl -fsS -m 3 http://127.0.0.1:5003/api/health >/tmp/rt-health.json 2>/dev/null; then
    python3 - <<'PY' || echo "health: $(cat /tmp/rt-health.json)"
import json
d=json.load(open("/tmp/rt-health.json"))
sdk=d.get("claude_sdk") or {}
print(f"health: ok={d.get('ok')} label={sdk.get('label')} running={len(d.get('running') or [])}")
PY
  else
    echo "health: DOWN (5003 无响应)"
  fi
}

cmd_logs() {
  need_root
  journalctl -u atkbrain-flash-backend.service -n "${1:-80}" --no-pager
}

cmd_uninstall() {
  need_root
  systemctl disable --now atkbrain-flash-backend.service 2>/dev/null || true
  rm -f "$UNIT_DST"
  systemctl daemon-reload
  echo "[*] 已卸载 systemd unit（进程已停）"
}

usage() {
  echo "用法: $0 {install|start|stop|restart|status|logs|uninstall}"
}

case "${1:-}" in
  install) cmd_install ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) cmd_logs "${2:-80}" ;;
  uninstall) cmd_uninstall ;;
  *) usage; exit 1 ;;
esac
