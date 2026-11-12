#!/usr/bin/env bash
# 控制台镜像入口：Pi + 前端 :2334。出口代理只走设置页导入的代理池。
# 不是 TSecBench 托管模式，不会自行拉题开打。
set -euo pipefail

export ATKBRAIN_HOSTED="${ATKBRAIN_HOSTED:-0}"
export ATKBRAIN_LLM_GATEWAY="${ATKBRAIN_LLM_GATEWAY:-0}"
export ATKBRAIN_HOST="${ATKBRAIN_HOST:-0.0.0.0}"
export ATKBRAIN_PORT="${ATKBRAIN_PORT:-2333}"
export ATKBRAIN_ADMIN_USER="${ATKBRAIN_ADMIN_USER:-admin}"
export ATKBRAIN_ADMIN_PASSWORD="${ATKBRAIN_ADMIN_PASSWORD:-admin}"
export ATKBRAIN_CORS_ORIGINS="${ATKBRAIN_CORS_ORIGINS:-https://127.0.0.1:2334,https://localhost:2334,http://127.0.0.1:2333,http://localhost:2333}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export HOME="${HOME:-/root}"
export PATH="/opt/atkbrain/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export ATKBRAIN_PI_BIN="${ATKBRAIN_PI_BIN:-pi}"
export ATKBRAIN_PI_PROVIDER="${ATKBRAIN_PI_PROVIDER:-deepseek}"
export ATKBRAIN_PI_MODEL="${ATKBRAIN_PI_MODEL:-deepseek-flash}"
export PI_TELEMETRY="${PI_TELEMETRY:-0}"
export PI_SKIP_VERSION_CHECK="${PI_SKIP_VERSION_CHECK:-1}"
export PI_OFFLINE="${PI_OFFLINE:-1}"

cd /opt/atkbrain/backend
mkdir -p data/workspaces data/loot data/reports data/logs

if [[ -z "${DEEPSEEK_API_KEY:-}" && -n "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  export DEEPSEEK_API_KEY="${ANTHROPIC_AUTH_TOKEN}"
fi
if [[ -z "${ANTHROPIC_AUTH_TOKEN:-}" && -n "${DEEPSEEK_API_KEY:-}" ]]; then
  export ANTHROPIC_AUTH_TOKEN="${DEEPSEEK_API_KEY}"
fi

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "[entrypoint] 警告: 未设置 DEEPSEEK_API_KEY（或 ANTHROPIC_AUTH_TOKEN）。控制台能开，猎面 Pi 不会就绪。" >&2
fi

/opt/atkbrain/venv/bin/python - <<'PY'
from atkbrain.agents.pi_runtime import ensure_pi_agent_dir
p = ensure_pi_agent_dir(hosted=False)
print(f"[entrypoint] Pi 配置已写入 {p}")
PY

# :2334 默认交给 Caddy HTTPS。本机 HTTP 只留 :2333（探活 / 反代上游）。
_tls_sh="/opt/atkbrain/scripts/ensure-console-tls.sh"
if [[ -x "$_tls_sh" ]]; then
  bash "$_tls_sh" /opt/atkbrain/backend/data/tls || echo "[entrypoint] 自签证书生成失败，Caddy 可能起不来" >&2
fi
_skip_socat="$(echo "${ATKBRAIN_SKIP_SOCAT:-true}" | tr '[:upper:]' '[:lower:]')"
if [[ "$_skip_socat" =~ ^(1|true|yes|on)$ ]]; then
  echo "[entrypoint] 不听 HTTP :2334（Caddy TLS → :2333）。浏览器用 https://<主机>:2334/ 加 8 位入口。"
elif command -v socat >/dev/null 2>&1; then
  if socat TCP-LISTEN:2334,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:2333 >/opt/atkbrain/backend/data/logs/console-2334.log 2>&1 & then
echo "[entrypoint] 控制台走 HTTP :2334 → :2333（已关闭 HTTPS）。"
  else
    echo "[entrypoint] 2334 未能监听（可能被占用）" >&2
  fi
else
  echo "[entrypoint] 未安装 socat" >&2
fi

echo "[entrypoint] StrikeAgent_AtkBrain-Flash 控制台启动"
exec /opt/atkbrain/venv/bin/python -m atkbrain.main
