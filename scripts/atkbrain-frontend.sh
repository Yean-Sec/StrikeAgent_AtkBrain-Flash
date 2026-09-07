#!/usr/bin/env bash
# StrikeAgent_AtkBrain-Flash 前端常驻管理：经 systemd 拉起 Vite，崩溃自动重启。
# 用法: scripts/atkbrain-frontend.sh {install|start|stop|restart|status|logs|uninstall}
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$REPO/deploy/systemd/atkbrain-frontend.service"
UNIT_DST="/etc/systemd/system/atkbrain-flash-frontend.service"
LOG_DIR="$REPO/backend/data/logs"

die() { echo "error: $*" >&2; exit 1; }
need_root() { [[ "$(id -u)" -eq 0 ]] || die "需要 root（sudo）"; }

# shellcheck source=/dev/null
source "$REPO/scripts/_atkbrain-systemd.sh"

cmd_install() {
  need_root
  command -v npm >/dev/null || die "找不到 npm"
  [[ -f "$UNIT_SRC" ]] || die "找不到 unit: $UNIT_SRC"
  [[ -d "$REPO/frontend/node_modules" ]] || die "先在 frontend/ 执行 npm install"
  mkdir -p "$LOG_DIR"
  retire_legacy_units
  kill_stray_frontend
  sed "s|__REPO__|$REPO|g" "$UNIT_SRC" > "$UNIT_DST"
  chmod 644 "$UNIT_DST"
  systemctl daemon-reload
  systemctl enable atkbrain-flash-frontend.service
  systemctl restart atkbrain-flash-frontend.service
  sleep 1
  cmd_status
  echo "[*] 已安装并启动。之后请用本脚本 restart，勿在 Cursor shell 里前台跑 npm run dev"
}

cmd_start() {
  need_root
  mkdir -p "$LOG_DIR"
  systemctl start atkbrain-flash-frontend.service
  cmd_status
}

cmd_stop() {
  need_root
  systemctl stop atkbrain-flash-frontend.service
  cmd_status
}

cmd_restart() {
  need_root
  mkdir -p "$LOG_DIR"
  if [[ ! -f "$UNIT_DST" ]]; then
    cmd_install
    return
  fi
  sed "s|__REPO__|$REPO|g" "$UNIT_SRC" > "$UNIT_DST"
  chmod 644 "$UNIT_DST"
  systemctl daemon-reload
  systemctl restart atkbrain-flash-frontend.service
  sleep 1
  cmd_status
}

cmd_status() {
  systemctl --no-pager --full status atkbrain-flash-frontend.service || true
  echo "---"
  code="$(curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:5001/ 2>/dev/null || echo 000)"
  echo "vite: HTTP $code (5001)"
}

cmd_logs() {
  need_root
  journalctl -u atkbrain-flash-frontend.service -n "${1:-80}" --no-pager
}

cmd_uninstall() {
  need_root
  systemctl disable --now atkbrain-flash-frontend.service 2>/dev/null || true
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
