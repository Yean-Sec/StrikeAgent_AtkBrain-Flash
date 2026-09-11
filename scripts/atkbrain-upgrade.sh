#!/usr/bin/env bash
# 把本机源码升到指定 GitHub tag，然后重启前后端 systemd。
# 用法: scripts/atkbrain-upgrade.sh <tag>
# 不碰 backend/data、*.env、node_modules。不改 git config、不 force push。
set -euo pipefail

TAG="${1:-}"
[[ "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: 非法 tag: ${TAG}" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SLUG="${ATKBRAIN_GITHUB_REPO:-Yean-Sec/StrikeAgent_AtkBrain-Flash}"
SLUG="${SLUG#https://github.com/}"
SLUG="${SLUG#http://github.com/}"
SLUG="${SLUG%.git}"
LOG_DIR="$REPO/backend/data/logs"
mkdir -p "$LOG_DIR"

echo "[*] $(date -Iseconds) upgrade → $TAG  repo=$REPO slug=$SLUG"

hash_of() {
  if [[ -f "$1" ]]; then sha256sum "$1" | awk '{print $1}'; else echo ""; fi
}

REQ_BEFORE="$(hash_of "$REPO/backend/requirements.txt")"
LOCK_BEFORE="$(hash_of "$REPO/frontend/package-lock.json")"
PKG_BEFORE="$(hash_of "$REPO/frontend/package.json")"

if [[ -d "$REPO/.git" ]]; then
  echo "[*] git fetch --tags"
  git -C "$REPO" fetch --tags origin
  if git -C "$REPO" rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    git -C "$REPO" checkout --detach "tags/$TAG"
  elif git -C "$REPO" rev-parse -q --verify "refs/tags/v$TAG" >/dev/null; then
    git -C "$REPO" checkout --detach "tags/v$TAG"
  else
    git -C "$REPO" checkout --detach "$TAG"
  fi
else
  echo "[*] 无 .git，下载 GitHub source tarball"
  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT
  AUTH=()
  if [[ -n "${ATKBRAIN_GITHUB_TOKEN:-}" ]]; then
    AUTH=(-H "Authorization: Bearer ${ATKBRAIN_GITHUB_TOKEN}")
  fi
  ARCHIVE="$TMP/src.tgz"
  URL="https://api.github.com/repos/${SLUG}/tarball/${TAG}"
  if ! curl -fsSL "${AUTH[@]}" -o "$ARCHIVE" "$URL"; then
    URL="https://github.com/${SLUG}/archive/refs/tags/${TAG}.tar.gz"
    curl -fsSL "${AUTH[@]}" -o "$ARCHIVE" "$URL"
  fi
  mkdir -p "$TMP/unpacked"
  tar -xzf "$ARCHIVE" -C "$TMP/unpacked"
  SRC="$(find "$TMP/unpacked" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [[ -n "$SRC" && -d "$SRC" ]] || { echo "error: tarball 里没有目录" >&2; exit 1; }
  if command -v rsync >/dev/null; then
    rsync -a \
      --exclude '.git/' \
      --exclude 'backend/data/' \
      --exclude 'frontend/node_modules/' \
      --exclude 'frontend/dist/' \
      --exclude '*.env' \
      --exclude 'backend/.env' \
      --exclude 'backend/data/atkbrain-claude.env' \
      "$SRC"/ "$REPO"/
  else
    echo "[*] 无 rsync，用 tar 覆盖（仍跳过 data/node_modules）"
    tar -C "$SRC" --exclude='backend/data' --exclude='frontend/node_modules' --exclude='.git' -cf - . \
      | tar -C "$REPO" --exclude='backend/data' --exclude='frontend/node_modules' -xf -
  fi
fi

REQ_AFTER="$(hash_of "$REPO/backend/requirements.txt")"
LOCK_AFTER="$(hash_of "$REPO/frontend/package-lock.json")"
PKG_AFTER="$(hash_of "$REPO/frontend/package.json")"

if [[ -n "$REQ_AFTER" && "$REQ_AFTER" != "$REQ_BEFORE" ]]; then
  echo "[*] requirements.txt 有变，pip install"
  /usr/bin/python3 -m pip install -r "$REPO/backend/requirements.txt"
fi
if [[ ("$LOCK_AFTER" != "$LOCK_BEFORE" || "$PKG_AFTER" != "$PKG_BEFORE") && -d "$REPO/frontend" ]]; then
  echo "[*] frontend 依赖有变，npm install"
  (cd "$REPO/frontend" && npm install)
fi

echo "[*] 重启 systemd"
systemctl restart atkbrain-flash-backend.service atkbrain-flash-frontend.service
echo "[*] upgrade done $(date -Iseconds)"
