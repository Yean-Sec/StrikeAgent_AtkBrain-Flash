# 被 atkbrain-backend.sh / atkbrain-frontend.sh / atkbrain-up.sh source。
# 不要直接执行。

migrate_legacy_runtime() {
  local data="${REPO}/backend/data"
  DATA_DIR="$data" /usr/bin/python3 - <<'PY'
import os
from pathlib import Path

data = Path(os.environ["DATA_DIR"])
data.mkdir(parents=True, exist_ok=True)
for suffix in ("", "-wal", "-shm", "-journal"):
    old = data / f"redtime.db{suffix}"
    new = data / f"atkbrain.db{suffix}"
    if old.exists() and not new.exists():
        old.rename(new)
        print(f"[*] 已迁移 {old.name} → {new.name}")
old_env = data / "redtime-claude.env"
new_env = data / "atkbrain-claude.env"
if old_env.exists() and not new_env.exists():
    text = old_env.read_text(encoding="utf-8", errors="replace").replace("REDTIME_", "ATKBRAIN_")
    new_env.write_text(text, encoding="utf-8")
    os.chmod(new_env, 0o600)
    print(f"[*] 已迁移 {old_env.name} → {new_env.name}")
PY
}

retire_legacy_units() {
  systemctl disable --now redtime-backend.service 2>/dev/null || true
  systemctl disable --now redtime-frontend.service 2>/dev/null || true
  rm -f /etc/systemd/system/redtime-backend.service /etc/systemd/system/redtime-frontend.service
}

snapshot_claude_env() {
  local dest="${REPO}/backend/data/atkbrain-claude.env"
  DEST="$dest" /usr/bin/python3 - <<'PY'
import os, re
from pathlib import Path

dest = Path(os.environ["DEST"])
dest.parent.mkdir(parents=True, exist_ok=True)

keep_prefixes = ("ANTHROPIC_", "CLAUDE_", "ATKBRAIN_", "DEEPSEEK_", "PI_")
existing: dict[str, str] = {}

def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v

if dest.exists():
    for line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        existing[k.strip()] = unquote(v)

for k, v in os.environ.items():
    if re.search(r"[\n\r]", v or ""):
        continue
    if k.startswith("REDTIME_"):
        nk = "ATKBRAIN_" + k[len("REDTIME_") :]
        if nk != "ATKBRAIN_HOST":
            existing[nk] = v
        continue
    if not k.startswith(keep_prefixes):
        continue
    if k == "ATKBRAIN_HOST":
        continue
    existing[k] = v
existing["ATKBRAIN_HOST"] = "0.0.0.0"

def esc(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

rows = sorted(existing.items())
text = "\n".join(f"{k}={esc(v)}" for k, v in rows) + "\n"
dest.write_text(text, encoding="utf-8")
os.chmod(dest, 0o600)
print(f"[*] 已写入 {len(rows)} 个环境变量到 {dest}（不打印内容）")
PY
}

snapshot_dsh_env() {
  local dest="${REPO}/backend/data/atkbrain-dsh.env"
  DEST="$dest" /usr/bin/python3 - <<'PY'
import os, re
from pathlib import Path

dest = Path(os.environ["DEST"])
dest.parent.mkdir(parents=True, exist_ok=True)
keep_prefixes = ("DEEPSEEK_", "DSH_")
existing: dict[str, str] = {}

def unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] == '"':
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return v

if dest.exists():
    for line in dest.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        existing[k.strip()] = unquote(v)

for k, v in os.environ.items():
    if re.search(r"[\n\r]", v or ""):
        continue
    if not k.startswith(keep_prefixes):
        continue
    existing[k] = v

def esc(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'

rows = sorted(existing.items())
text = "\n".join(f"{k}={esc(v)}" for k, v in rows) + "\n"
dest.write_text(text, encoding="utf-8")
os.chmod(dest, 0o600)
print(f"[*] 已写入 {len(rows)} 个环境变量到 {dest}（不打印内容）")
PY
}

kill_stray_backend() {
  # 只释放 Flash API 口 :5003。禁止 pkill 全部 atkbrain.main——本机还有其它仓库占用 :2233。
  if ss -H -tlnp 2>/dev/null | grep -q ':5003 '; then
    echo "[*] 释放 :5003 上的非 Flash 占用 …"
    fuser -k 5003/tcp 2>/dev/null || true
    sleep 1
  fi
}

kill_stray_frontend() {
  # 只释放 Flash 控制台 :5001，勿杀掉其它仓库的 Vite（:2234）。
  if ss -H -tlnp 2>/dev/null | grep -q ':5001 '; then
    echo "[*] 释放 :5001 上的非 Flash 占用 …"
    fuser -k 5001/tcp 2>/dev/null || true
    sleep 1
  fi
}
