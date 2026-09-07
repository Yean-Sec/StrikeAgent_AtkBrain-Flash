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

cd /opt/atkbrain/backend

if [[ -z "${ANTHROPIC_AUTH_TOKEN:-}" && -n "${DEEPSEEK_API_KEY:-}" ]]; then
  export ANTHROPIC_AUTH_TOKEN="${DEEPSEEK_API_KEY}"
fi
if [[ -z "${ANTHROPIC_BASE_URL:-}" ]]; then
  export ANTHROPIC_BASE_URL="http://api.deepseek.com.tsecbench.gw/anthropic"
fi

if [[ -z "${ANTHROPIC_AUTH_TOKEN:-}" ]]; then
  echo "[entrypoint] 警告: 未设置 ANTHROPIC_AUTH_TOKEN（或 DEEPSEEK_API_KEY）。请在平台「运行时环境变量」中填写大模型 Key。" >&2
fi
if [[ -z "${BENCHMARK_TOKEN:-}" || -z "${BENCHMARK_BASE_URL:-}" ]]; then
  echo "[entrypoint] 提示: 等待平台注入 BENCHMARK_TOKEN / BENCHMARK_BASE_URL。" >&2
fi

echo "[entrypoint] StrikeAgent_AtkBrain-Flash 托管启动"
exec /opt/atkbrain/venv/bin/python -m atkbrain.main
