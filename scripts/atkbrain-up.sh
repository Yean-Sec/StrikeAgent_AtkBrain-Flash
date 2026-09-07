#!/usr/bin/env bash
# 一键把 StrikeAgent_AtkBrain-Flash 后端+前端交给 systemd（崩溃自动拉起，不依赖 Cursor shell）。
# 用法: scripts/atkbrain-up.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
"$REPO/scripts/atkbrain-backend.sh" install
"$REPO/scripts/atkbrain-frontend.sh" install
echo
echo "[*] 浏览器打开: http://127.0.0.1:5001/"
echo "[*] 之后不要在 Cursor shell 里再跑 python -m atkbrain.main / npm run dev"
