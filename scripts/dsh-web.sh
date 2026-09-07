#!/usr/bin/env bash
# 可选调试侧车：打开 DeepSeek Harness 自带的编码 UI。
# 不是 StrikeAgent_AtkBrain-Flash 主界面（主界面仍是 Vite 控制台）。
# 仅监听 127.0.0.1，不支持 0.0.0.0；不并入 systemd。
set -euo pipefail

PORT="${DSH_WEB_PORT:-3080}"
exec npx --yes @deepseek-ai/dsh web --no-open --port "$PORT"
