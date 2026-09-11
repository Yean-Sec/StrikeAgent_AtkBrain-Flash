#!/usr/bin/env bash
# 托管镜像入口：容器一启动就跑 Agent，自行拉题开打。
# 密钥只从运行时环境变量读取，镜像内不内置。
set -euo pipefail

export ATKBRAIN_HOSTED="${ATKBRAIN_HOSTED:-1}"
export ATKBRAIN_LLM_GATEWAY="${ATKBRAIN_LLM_GATEWAY:-1}"
export ATKBRAIN_HOST="${ATKBRAIN_HOST:-0.0.0.0}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export HOME="${HOME:-/root}"
export PATH="/opt/atkbrain/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH}"
export PI_TELEMETRY="${PI_TELEMETRY:-0}"
export PI_SKIP_VERSION_CHECK="${PI_SKIP_VERSION_CHECK:-1}"
export PI_OFFLINE="${PI_OFFLINE:-1}"
export ATKBRAIN_PI_BIN="${ATKBRAIN_PI_BIN:-pi}"
export ATKBRAIN_PI_PROVIDER="${ATKBRAIN_PI_PROVIDER:-deepseek}"
export ATKBRAIN_PI_MODEL="${ATKBRAIN_PI_MODEL:-deepseek-flash}"

cd /opt/atkbrain/backend

if [[ -z "${DEEPSEEK_API_KEY:-}" && -n "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  export DEEPSEEK_API_KEY="${ANTHROPIC_AUTH_TOKEN}"
fi
if [[ -z "${ANTHROPIC_AUTH_TOKEN:-}" && -n "${DEEPSEEK_API_KEY:-}" ]]; then
  export ANTHROPIC_AUTH_TOKEN="${DEEPSEEK_API_KEY}"
fi

if [[ -z "${DEEPSEEK_API_KEY:-}" ]]; then
  echo "[entrypoint] 警告: 未设置 DEEPSEEK_API_KEY（或 ANTHROPIC_AUTH_TOKEN）。请在平台「运行时环境变量」中填写大模型 Key。" >&2
fi
if [[ -z "${BENCHMARK_TOKEN:-}" || -z "${BENCHMARK_BASE_URL:-}" ]]; then
  echo "[entrypoint] 提示: 等待平台注入 BENCHMARK_TOKEN / BENCHMARK_BASE_URL。" >&2
fi

/opt/atkbrain/venv/bin/python - <<'PY'
from atkbrain.agents.pi_runtime import ensure_pi_agent_dir
p = ensure_pi_agent_dir(hosted=True)
print(f"[entrypoint] Pi 配置已写入 {p}")
PY

echo "[entrypoint] StrikeAgent_AtkBrain-Flash 托管启动"
exec /opt/atkbrain/venv/bin/python -m atkbrain.main
