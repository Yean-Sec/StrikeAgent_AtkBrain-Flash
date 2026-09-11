#!/usr/bin/env bash
# 构建托管镜像并导出为平台可上传的 .tar.gz（上限 3GB）。
# 用法: scripts/export-hosted-image.sh [tag] [outfile]
# 未指定 outfile 时优先写到 Downloads（若存在），否则写到仓库根。
# 本地 backend/data（库 / 工作区 / 历史答题）不进镜像；进了就失败。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${1:-strikeagent-atkbrain-flash:latest}"
STAMP="$(date +%Y%m%d-%H%M)"
OUT_DIR=""
for d in "${HOME}/Downloads" "${HOME}/hgfs/Downloads" "/mnt/hgfs/Downloads"; do
  if [[ -d "$d" ]]; then
    OUT_DIR="$d"
    break
  fi
done
if [[ -n "${2:-}" ]]; then
  OUT="$2"
elif [[ -n "$OUT_DIR" ]]; then
  OUT="${OUT_DIR}/StrikeAgent_AtkBrain-Flash-${STAMP}.tar.gz"
else
  OUT="${ROOT}/StrikeAgent_AtkBrain-Flash-${STAMP}.tar.gz"
fi
LIMIT=$((3 * 1024 * 1024 * 1024))

cd "$ROOT"

if grep -E '^[[:space:]]*COPY[[:space:]]+backend/data' Dockerfile; then
  echo "[!] Dockerfile 不能 COPY backend/data（本地库/工作区不准进镜像）" >&2
  exit 1
fi

if [[ "${SKIP_BUILD:-}" == "1" ]]; then
  echo "[*] SKIP_BUILD=1，使用已有镜像 ${TAG}"
else
  echo "[*] docker build -t ${TAG}"
  docker build -t "$TAG" -f Dockerfile .
fi

echo "[*] 检查镜像未带本地库/工作区/对话/题解痕迹"
docker run --rm --entrypoint /bin/bash "$TAG" -lc "$(cat <<'INNER'
set -euo pipefail
hits=$(find /opt/atkbrain -type f \( -name "*.db" -o -name "*.db-wal" -o -name "*.db-shm" -o -name "*.jsonl" \) 2>/dev/null || true)
if [ -n "${hits}" ]; then
  echo "[!] 镜像里出现数据库或对话文件：" >&2
  echo "${hits}" >&2
  exit 1
fi
ws=$(find /opt/atkbrain/backend/data/workspaces -mindepth 1 -maxdepth 1 2>/dev/null || true)
if [ -n "${ws}" ]; then
  echo "[!] 镜像里出现工作区内容：" >&2
  echo "${ws}" >&2
  exit 1
fi
if [ -d /opt/atkbrain/.cursor ] || [ -d /root/.cursor ]; then
  echo "[!] 镜像里出现编辑器对话目录" >&2
  exit 1
fi
if [ ! -f /opt/atkbrain/.claude/skills/recon-fanout/SKILL.md ]; then
  echo "[!] 镜像缺少 CTF skill recon-fanout" >&2
  exit 1
fi
if [ ! -f /opt/atkbrain/pi/extensions/atkbrain-tools.ts ]; then
  echo "[!] 镜像缺少 Pi 扩展 atkbrain-tools.ts" >&2
  exit 1
fi
if ! command -v pi >/dev/null; then
  echo "[!] 镜像缺少 pi" >&2
  exit 1
fi
if command -v claude >/dev/null; then
  echo "[!] 镜像不应再带 claude" >&2
  exit 1
fi
if [ ! -f /opt/atkbrain/backend/atkbrain/memory/evolve.py ]; then
  echo "[!] 镜像缺少自进化模块" >&2
  exit 1
fi
if grep -R -E -n --include="*.py" \
    "Weaver@|submit_fact|commit_step" \
    /opt/atkbrain/backend/atkbrain >/tmp/atkbrain-pack-hits 2>/dev/null; then
  echo "[!] 镜像源码命中赛题/writeup 痕迹：" >&2
  cat /tmp/atkbrain-pack-hits >&2
  exit 1
fi
echo "[*] 镜像数据目录为空，含自进化代码与 skill，无库/对话"
INNER
)"

echo "[*] docker save | gzip > ${OUT}"
mkdir -p "$(dirname "$OUT")"
docker save "$TAG" | gzip > "$OUT"

python3 - "$OUT" "$LIMIT" <<'PY'
import hashlib, os, sys
path, limit = sys.argv[1], int(sys.argv[2])
size = os.path.getsize(path)
mb = size / (1024 * 1024)
h = hashlib.sha256()
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1024 * 1024), b""):
        h.update(chunk)
digest = h.hexdigest()
print(f"[*] 导出完成: {path}")
print(f"[*] 体积: {mb:.1f} MB ({size} bytes)")
print(f"[*] SHA-256 {digest}")
if size > limit:
    print(f"[!] 超过平台 3GB 上限（{size} > {limit}）", file=sys.stderr)
    sys.exit(1)
print("[*] 未超过 3GB 上限")
PY
