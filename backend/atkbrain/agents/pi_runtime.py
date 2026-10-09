"""Pi RPC 运行时：拉起 `pi --mode rpc`，用 LF JSONL 对话。

从者 / 角色工人带图工具扩展。
无工具一次性会话按 role 分开，互不复用进程：
御主 supervisor、自进化 evolve、漏洞页 finding-page、交付报告 report-export。
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from ..config import REPO_ROOT, settings
from ..engine.turn_close import role_wrote_turn_done

# pid -> (project_id, role)。只在确认进程已死后 pop。
_LIVE: dict[int, tuple[str, str]] = {}
_RESERVED: list[tuple[str, str]] = []
_SPAWN_COND: asyncio.Condition | None = None

# 猎面技能靠 --skill 注入；Pi 0.74+ 已去掉 --exclude-tools / -a，改用 --no-builtin-tools 禁官方 bash/edit。
ONESHOT_ROLES = frozenset({
    "supervisor", "evolve", "finding-page", "report-export", "oneshot",
})
REVIEW_ROLE = "finding-review"

EmitFn = Callable[..., Awaitable[None]]


def _usable_api_key(raw: str | None) -> str:
    """空串和 $ENV 占位不算已配置。"""
    key = str(raw or "").strip().strip('"').strip("'")
    if not key or key.startswith("$"):
        return ""
    if key.lower() in {"changeme", "your-api-key", "your_api_key", "sk-xxx"}:
        return ""
    return key


def _pi_models_api_key() -> str:
    """设置页写进 pi-models.json 的密钥。优先 defaultProvider。"""
    try:
        data = load_pi_models()
    except Exception:
        return ""
    providers = data.get("providers") if isinstance(data.get("providers"), dict) else {}
    name = str(data.get("defaultProvider") or "").strip()
    order: list[str] = []
    if name:
        order.append(name)
    order.extend(str(k) for k in providers if str(k) not in order)
    for pname in order:
        prov = providers.get(pname)
        if not isinstance(prov, dict):
            continue
        key = _usable_api_key(prov.get("apiKey"))
        if key:
            return key
    return ""


def llm_api_key() -> str:
    env = _usable_api_key(os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if env:
        return env
    return _pi_models_api_key()


def llm_api_key_configured() -> bool:
    return bool(llm_api_key())


def llm_key_missing_message() -> str:
    from ..i18n.strings import msg
    return msg("llm_key_missing")


def pi_max_live_limit() -> int:
    try:
        n = int(getattr(settings, "pi_max_live", None) or 32)
    except (TypeError, ValueError):
        n = 32
    try:
        cap = int(getattr(settings, "pi_max_live_cap", None) or 96)
    except (TypeError, ValueError):
        cap = 96
    if n <= 0:
        n = 32
    if cap <= 0:
        cap = 96
    return max(1, min(n, cap))


def pi_per_project_limit() -> int:
    raw = getattr(settings, "pi_per_project", None)
    if raw in (None, 0, "0"):
        raw = getattr(settings, "claude_per_project", None)
    try:
        n = int(raw or 4)
    except (TypeError, ValueError):
        n = 4
    try:
        cap = int(
            getattr(settings, "pi_per_project_cap", None)
            or getattr(settings, "claude_per_project_cap", None)
            or 8
        )
    except (TypeError, ValueError):
        cap = 8
    if n <= 0:
        n = 4
    if cap <= 0:
        cap = 8
    return max(1, min(n, cap))


def cap_hunt_workers(roles: list[str], *, per_project: int | None = None) -> list[str]:
    """从者占 1 槽，工人截断到 per_project-1。"""
    n = (per_project if per_project is not None else pi_per_project_limit()) - 1
    if n <= 0:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for raw in roles:
        name = str(raw or "").strip().lower()
        if not name or name in seen or name in ONESHOT_ROLES or _is_review_role(name):
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= n:
            break
    return out


def _is_review_role(role: str) -> bool:
    r = (role or "").strip().lower()
    return r == REVIEW_ROLE or r.startswith(REVIEW_ROLE + ":")


def _counts_toward_per_project(role: str) -> bool:
    r = (role or "").strip().lower()
    if not r or r in ONESHOT_ROLES or _is_review_role(r):
        return False
    return True


def live_pi_count() -> int:
    _reap_dead()
    return len(_LIVE)


def live_pi_for_project(project_id: str, *, hunt_only: bool = False) -> int:
    want = (project_id or "").strip()
    if not want:
        return 0
    _reap_dead()
    n = 0
    for rec in _LIVE.values():
        if rec[0] != want:
            continue
        if hunt_only and not _counts_toward_per_project(rec[1]):
            continue
        n += 1
    return n


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _reap_dead() -> None:
    dead = [pid for pid in _LIVE if not _pid_alive(pid)]
    for pid in dead:
        _LIVE.pop(pid, None)


def _kill_pid(pid: int, *, sig: int = signal.SIGKILL) -> None:
    try:
        os.killpg(pid, sig)
    except OSError:
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def _proc_env_value(pid: int, key: str) -> str:
    try:
        env = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return ""
    needle = (key + "=").encode("utf-8")
    i = env.find(needle)
    if i < 0:
        return ""
    if i > 0 and env[i - 1] != 0:
        # 避免前缀误匹配
        return ""
    rest = env[i + len(needle):]
    end = rest.find(b"\0")
    return rest[:end if end >= 0 else None].decode("utf-8", "replace").strip()


def _proc_project_ids(pid: int) -> str:
    return _proc_env_value(pid, "ATKBRAIN_PROJECT_ID")


def _proc_role(pid: int) -> str:
    return _proc_env_value(pid, "ATKBRAIN_PI_ROLE")


def _proc_cmdline(pid: int) -> bytes:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return b""


def _proc_ppid(pid: int) -> int:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    for line in text.splitlines():
        if line.startswith("PPid:"):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return 0
    return 0


def _is_backend_cmd(cmd: bytes) -> bool:
    return b"atkbrain.main" in cmd or b"atkbrain-backend" in cmd


def _is_protected_cmd(cmd: bytes) -> bool:
    """停猎扫 /proc 时不能误杀控制台和反代。"""
    if not cmd or _is_backend_cmd(cmd):
        return True
    blob = cmd.replace(b"\0", b" ").lower()
    first = cmd.split(b"\0", 1)[0].rsplit(b"/", 1)[-1].lower()
    if first in (b"caddy", b"caddy.exe", b"uvicorn"):
        return True
    if b"uvicorn" in blob:
        return True
    return False


def _is_pi_cmdline(cmd: bytes) -> bool:
    if not cmd or _is_backend_cmd(cmd):
        return False
    blob = cmd.replace(b"\0", b" ").lower()
    if b"--mode" in blob and b"rpc" in blob:
        return True
    if b"pi-coding-agent" in blob:
        return True
    first = cmd.split(b"\0", 1)[0]
    base = first.rsplit(b"/", 1)[-1].lower()
    return base in (b"pi", b"pi.exe")


def _children_map() -> dict[int, list[int]]:
    out: dict[int, list[int]] = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        ppid = _proc_ppid(pid)
        if ppid <= 0:
            continue
        out.setdefault(ppid, []).append(pid)
    return out


def _descendants(root: int, cmap: dict[int, list[int]] | None = None) -> list[int]:
    cmap = cmap if cmap is not None else _children_map()
    found: list[int] = []
    stack = list(cmap.get(root, []))
    while stack:
        pid = stack.pop()
        found.append(pid)
        stack.extend(cmap.get(pid, []))
    return found


def _kill_tree(root: int, *, sig: int = signal.SIGKILL) -> None:
    kids = _descendants(root)
    for pid in reversed(kids):
        _kill_pid(pid, sig=sig)
    _kill_pid(root, sig=sig)


def _scan_pi_pids(*, project_id: str = "", role: str = "") -> set[int]:
    want_p = (project_id or "").strip()
    want_r = (role or "").strip()
    if not want_p and not want_r:
        return set()
    found: set[int] = set()
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    cmap = _children_map()
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        cmd = _proc_cmdline(pid)
        if _is_protected_cmd(cmd):
            continue
        env_p = _proc_project_ids(pid)
        env_r = _proc_role(pid)
        if want_p and want_r:
            matched = env_p == want_p and env_r == want_r
        elif want_p:
            matched = env_p == want_p
        else:
            matched = env_r == want_r
        if not matched:
            continue
        found.add(pid)
        found.update(_descendants(pid, cmap))
    return found


def _untrack_dead(pid: int | None) -> bool:
    if not pid:
        return True
    if _pid_alive(pid):
        return False
    _LIVE.pop(pid, None)
    return True


def _spawn_cond() -> asyncio.Condition:
    global _SPAWN_COND
    if _SPAWN_COND is None:
        _SPAWN_COND = asyncio.Condition()
    return _SPAWN_COND


def _notify_spawn() -> None:
    cond = _SPAWN_COND
    if cond is None:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return

    async def _wake() -> None:
        async with cond:
            cond.notify_all()

    loop.create_task(_wake())


def _can_spawn(project_id: str, role: str) -> bool:
    _reap_dead()
    if live_pi_count() + len(_RESERVED) >= pi_max_live_limit():
        return False
    if _counts_toward_per_project(role) and (project_id or "").strip():
        n = live_pi_for_project(project_id, hunt_only=True)
        n += sum(
            1 for p, r in _RESERVED
            if p == project_id and _counts_toward_per_project(r)
        )
        if n >= pi_per_project_limit():
            return False
    return True


async def wait_spawn_slot(
    *, project_id: str = "", role: str = "", timeout: float = 180.0,
) -> None:
    """超额排队，不静默再开。"""
    deadline = time.monotonic() + max(1.0, float(timeout or 180.0))
    cond = _spawn_cond()
    async with cond:
        while True:
            if _can_spawn(project_id, role):
                _RESERVED.append(((project_id or "").strip(), (role or "").strip()))
                return
            remain = deadline - time.monotonic()
            if remain <= 0:
                raise RuntimeError(
                    f"Pi 进程闸已满（全局 {pi_max_live_limit()} / "
                    f"项目 {pi_per_project_limit()}），放弃拉起 {role or 'pi'}"
                )
            try:
                await asyncio.wait_for(cond.wait(), timeout=min(1.0, remain))
            except TimeoutError:
                continue


def note_spawned(pid: int, *, project_id: str = "", role: str = "") -> None:
    rec = ((project_id or "").strip(), (role or "").strip())
    try:
        _RESERVED.remove(rec)
    except ValueError:
        if _RESERVED:
            _RESERVED.pop(0)
    _LIVE[int(pid)] = rec
    _notify_spawn()


def note_spawn_failed(*, project_id: str = "", role: str = "") -> None:
    rec = ((project_id or "").strip(), (role or "").strip())
    try:
        _RESERVED.remove(rec)
    except ValueError:
        if _RESERVED:
            _RESERVED.pop(0)
    _notify_spawn()


def kill_live_for_project(
    project_id: str, *, keep_roles: set[str] | frozenset[str] | None = None,
) -> int:
    """停猎后扫掉仍活着的 Pi 进程树。interrupt/close 超时或被取消时会漏。"""
    want = (project_id or "").strip()
    if not want:
        return 0
    keep = {str(x).strip() for x in (keep_roles or ()) if str(x).strip()}

    def _spare(role: str) -> bool:
        if role in keep:
            return True
        return REVIEW_ROLE in keep and _is_review_role(role)

    targets: set[int] = set()
    _reap_dead()
    for proc_pid, rec in list(_LIVE.items()):
        if rec[0] != want:
            continue
        if _spare(rec[1]):
            continue
        targets.add(proc_pid)
        targets.update(_descendants(proc_pid))
    for proc_pid in _scan_pi_pids(project_id=want):
        if keep and _spare(_proc_role(proc_pid)):
            continue
        targets.add(proc_pid)
    n = 0
    for proc_pid in list(targets):
        _kill_tree(proc_pid, sig=signal.SIGKILL)
        n += 1
    time.sleep(0.05)
    for proc_pid in list(targets):
        if not _pid_alive(proc_pid):
            _LIVE.pop(proc_pid, None)
    _notify_spawn()
    try:
        from ..exec.runner import kill_cmds_for_project
        n += kill_cmds_for_project(want)
    except Exception:
        pass
    return n


def extension_path() -> Path:
    p = REPO_ROOT / "pi" / "extensions" / "atkbrain-tools.ts"
    if p.is_file():
        return p
    return Path(__file__).resolve().parents[3] / "pi" / "extensions" / "atkbrain-tools.ts"


def tools_base_url() -> str:
    """Pi 扩展拉工具列表。必须带 8 位入口，否则安全入口中间件会 404。"""
    port = int(getattr(settings, "port", 2333) or 2333)
    try:
        from ..auth.entry import entry_prefix
        prefix = entry_prefix() or ""
    except Exception:
        prefix = ""
    if prefix and not str(prefix).startswith("/"):
        prefix = "/" + str(prefix)
    return f"http://127.0.0.1:{port}{prefix}"


def pi_bin() -> str:
    return (
        (getattr(settings, "pi_bin", None) or "").strip()
        or os.environ.get("ATKBRAIN_PI_BIN")
        or "pi"
    )


_BUILTIN_MODEL = "deepseek-flash"


def _env_pi_model() -> str:
    """还没有 pi-models.json 时的种子。

    ATKBRAIN_PI_MODEL 与历史 ATKBRAIN_CLAUDE_MODEL 同义。
    只改了其中一个、另一个仍是内置 deepseek-flash 时，用改过的那个。
    """
    pi = (getattr(settings, "pi_model", None) or "").strip()
    claude = (getattr(settings, "claude_model", None) or "").strip()
    if pi and pi != _BUILTIN_MODEL:
        return pi
    if claude and claude != _BUILTIN_MODEL:
        return claude
    return pi or claude or _BUILTIN_MODEL


def _env_pi_provider() -> str:
    return (getattr(settings, "pi_provider", None) or "deepseek").strip() or "deepseek"


def pi_models_file() -> Path:
    return Path(settings.data_dir) / "pi-models.json"


def default_pi_models() -> dict:
    return {
        "defaultProvider": _env_pi_provider(),
        "defaultModel": _env_pi_model(),
        "providers": {
            "deepseek": {
                "baseUrl": "https://api.deepseek.com",
                "api": "openai-completions",
                "apiKey": "$DEEPSEEK_API_KEY",
                "models": [
                    {
                        "id": "deepseek-flash",
                        "name": "deepseek-flash",
                        "contextWindow": 1000000,
                        "maxTokens": 384000,
                        "input": ["text"],
                        "reasoning": True,
                        "thinkingLevelMap": {
                            "minimal": None, "low": None, "medium": None,
                            "high": "high", "xhigh": "max",
                        },
                        "cost": {
                            "input": 0.14, "output": 0.28,
                            "cacheRead": 0.028, "cacheWrite": 0,
                        },
                        "compat": {
                            "requiresReasoningContentOnAssistantMessages": True,
                            "thinkingFormat": "deepseek",
                            "reasoningEffortMap": {
                                "minimal": "high", "low": "high", "medium": "high",
                                "high": "high", "xhigh": "max",
                            },
                        },
                    }
                ],
            }
        },
    }


def load_pi_models() -> dict:
    path = pi_models_file()
    data = None
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
        except Exception:
            loaded = None
        if isinstance(loaded, dict) and isinstance(loaded.get("providers"), dict):
            data = loaded
    if data is None:
        data = default_pi_models()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except Exception:
            pass
    data.setdefault("defaultProvider", _env_pi_provider())
    data.setdefault("defaultModel", _env_pi_model())
    return data


def pi_models_text() -> str:
    return json.dumps(load_pi_models(), ensure_ascii=False, indent=2) + "\n"


def save_pi_models_text(text: str) -> dict:
    try:
        data = json.loads(text or "")
    except Exception as e:
        raise ValueError(f"JSON 不合法：{e}") from e
    if not isinstance(data, dict) or not isinstance(data.get("providers"), dict) or not data["providers"]:
        raise ValueError("需要包含非空 providers 对象")
    provider = str(data.get("defaultProvider") or "").strip()
    model = str(data.get("defaultModel") or "").strip()
    if not provider or not model:
        raise ValueError("需要 defaultProvider 和 defaultModel")
    if provider not in data["providers"]:
        raise ValueError("defaultProvider 不在 providers 里")
    path = pi_models_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ensure_pi_agent_dir()
    return data


_OPENAI_API = "openai-completions"
_ANTHROPIC_API = "anthropic-messages"


def _profile_format(api: str, provider: str) -> str:
    blob = f"{api} {provider}".lower()
    return "anthropic" if "anthropic" in blob else "openai"


def _expand_api_key(raw: str | None) -> str:
    text = str(raw or "").strip().strip('"').strip("'")
    if text.startswith("$"):
        name = text[1:].strip()
        if name.startswith("{") and name.endswith("}"):
            name = name[1:-1].strip()
        if not name:
            return ""
        return str(os.environ.get(name) or "")
    return text


def _key_hint(raw: str | None) -> tuple[bool, str]:
    usable = _usable_api_key(_expand_api_key(raw))
    if not usable:
        return False, ""
    tail = usable[-4:] if len(usable) >= 4 else usable
    return True, f"…{tail}"


def llm_profile() -> dict:
    """设置页表单。只暴露格式、模型、地址和密钥是否已填，不回传密钥。"""
    data = load_pi_models()
    providers = data.get("providers") if isinstance(data.get("providers"), dict) else {}
    name = str(data.get("defaultProvider") or "").strip()
    prov = providers.get(name) if isinstance(providers.get(name), dict) else {}
    fmt = _profile_format(str(prov.get("api") or ""), name)
    base = str(prov.get("baseUrl") or "").strip()
    if not base:
        base = "https://api.anthropic.com" if fmt == "anthropic" else "https://api.openai.com/v1"
    set_, hint = _key_hint(prov.get("apiKey"))
    return {
        "format": fmt,
        "model": str(data.get("defaultModel") or "").strip(),
        "base_url": base,
        "api_key_set": set_,
        "api_key_hint": hint,
    }


def save_llm_profile(*, fmt: str, model: str, base_url: str, api_key: str) -> dict:
    """把通用表单写成 Pi 能读的 models.json。密钥留空则保留已保存的值。"""
    kind = (fmt or "").strip().lower()
    if kind not in {"openai", "anthropic"}:
        raise ValueError("格式只能是 openai 或 anthropic")
    model_id = (model or "").strip()
    if not model_id or len(model_id) > 200:
        raise ValueError("需要填写模型")
    base = (base_url or "").strip().rstrip("/")
    if not base.lower().startswith(("http://", "https://")) or " " in base:
        raise ValueError("Base URL 需要以 http:// 或 https:// 开头")
    existing = load_pi_models()
    providers = existing.get("providers") if isinstance(existing.get("providers"), dict) else {}
    current_name = str(existing.get("defaultProvider") or "").strip()
    current = providers.get(current_name) if isinstance(providers.get(current_name), dict) else {}
    key = (api_key or "").strip()
    if not key:
        key = str(current.get("apiKey") or "").strip()
    ctx, mx = 200_000, 16_384
    prev_models = current.get("models") if isinstance(current.get("models"), list) else []
    for item in prev_models:
        if not isinstance(item, dict) or str(item.get("id") or "") != model_id:
            continue
        try:
            ctx = int(item.get("contextWindow") or ctx)
            mx = int(item.get("maxTokens") or mx)
        except (TypeError, ValueError):
            pass
        break
    provider = "anthropic" if kind == "anthropic" else "openai"
    data = {
        "defaultProvider": provider,
        "defaultModel": model_id,
        "providers": {
            provider: {
                "baseUrl": base,
                "api": _ANTHROPIC_API if kind == "anthropic" else _OPENAI_API,
                "apiKey": key,
                "models": [{
                    "id": model_id,
                    "name": model_id,
                    "contextWindow": ctx,
                    "maxTokens": mx,
                    "input": ["text", "image"],
                }],
            }
        },
    }
    save_pi_models_text(json.dumps(data, ensure_ascii=False))
    return llm_profile()


def llm_probe_url(fmt: str, base_url: str) -> str:
    base = (base_url or "").strip().rstrip("/")
    if (fmt or "").strip().lower() == "anthropic":
        if base.endswith("/messages"):
            return base
        if base.endswith("/v1"):
            return base + "/messages"
        return base + "/v1/messages"
    if base.endswith("/chat/completions"):
        return base
    return base + "/chat/completions"


def _probe_reply(fmt: str, body: Any) -> str:
    if not isinstance(body, dict):
        return ""
    if fmt == "anthropic":
        content = body.get("content")
        if isinstance(content, list):
            parts = [
                str(item.get("text") or "").strip()
                for item in content
                if isinstance(item, dict)
            ]
            return " ".join(part for part in parts if part)[:200]
        return ""
    choices = body.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict):
            return str(message.get("content") or "").strip()[:200]
    return ""


def _probe_error(body: Any, text: str) -> str:
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            msg = str(err.get("message") or err.get("type") or "").strip()
            if msg:
                return msg[:400]
        if isinstance(err, str) and err.strip():
            return err.strip()[:400]
    return (text or "").strip()[:400]


def _redact(text: str, key: str) -> str:
    if key and key in text:
        return text.replace(key, "***")
    return text


async def probe_llm(*, fmt: str, model: str, base_url: str, api_key: str) -> dict:
    """发一条最短对话，确认地址、密钥和模型能连通。失败只返回错误文本。"""
    kind = (fmt or "").strip().lower()
    if kind not in {"openai", "anthropic"}:
        return {"ok": False, "error": "格式只能是 openai 或 anthropic"}
    model_id = (model or "").strip()
    base = (base_url or "").strip()
    if not model_id:
        return {"ok": False, "error": "需要填写模型"}
    if not base.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": "Base URL 需要以 http:// 或 https:// 开头"}
    existing = load_pi_models()
    providers = existing.get("providers") if isinstance(existing.get("providers"), dict) else {}
    current_name = str(existing.get("defaultProvider") or "").strip()
    current = providers.get(current_name) if isinstance(providers.get(current_name), dict) else {}
    explicit = (api_key or "").strip()
    key = _usable_api_key(_expand_api_key(explicit or str(current.get("apiKey") or "")))
    if not key:
        return {"ok": False, "error": "未配置 API Key"}
    url = llm_probe_url(kind, base)
    import httpx

    payload: dict[str, Any] = {
        "model": model_id,
        "messages": [{"role": "user", "content": "Reply with the single word OK."}],
    }
    if kind == "anthropic":
        payload["max_tokens"] = 16
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
    else:
        payload["max_tokens"] = 16
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=10.0), follow_redirects=True, trust_env=False) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if (
                kind == "openai"
                and resp.status_code == 400
                and "max_tokens" in (resp.text or "")
                and "max_completion_tokens" not in payload
            ):
                payload.pop("max_tokens", None)
                payload["max_completion_tokens"] = 16
                resp = await client.post(url, headers=headers, json=payload)
    except Exception as e:
        return {"ok": False, "error": _redact(str(e), key)[:400] or "连接失败"}
    latency = int((time.perf_counter() - started) * 1000)
    try:
        body = resp.json()
    except Exception:
        body = None
    if resp.status_code >= 400:
        detail = _redact(_probe_error(body, resp.text), key)
        if not detail:
            detail = f"HTTP {resp.status_code}"
        return {"ok": False, "latency_ms": latency, "error": detail}
    reply = _probe_reply(kind, body)
    return {"ok": True, "latency_ms": latency, "model": model_id, "reply": reply}


def pi_model() -> str:
    try:
        model = str(load_pi_models().get("defaultModel") or "").strip()
        if model:
            return model
    except Exception:
        pass
    return _env_pi_model()


def pi_provider() -> str:
    try:
        provider = str(load_pi_models().get("defaultProvider") or "").strip()
        if provider:
            return provider
    except Exception:
        pass
    return _env_pi_provider()


def _legacy_model_name(name: str) -> bool:
    n = (name or "").strip().lower()
    return (not n) or n in {"sonnet", "haiku", "opus"} or n.startswith("claude")


def console_model() -> str:
    """控制台「设置 → Pi 模型」里的 defaultModel。"""
    return pi_model()


def project_model(explicit: str | None) -> str:
    """项目单独指定的模型优先；没写或仍是旧 Claude 别名时用控制台模型。"""
    raw = (explicit or "").strip()
    if raw and not _legacy_model_name(raw):
        return raw
    return console_model()


def role_model(*candidates: str | None) -> str:
    """御主 / 导出 / 蒸馏。内置 deepseek-flash 不能盖过控制台里保存的模型。"""
    chosen = console_model()
    for item in candidates:
        raw = (item or "").strip()
        if _legacy_model_name(raw):
            continue
        if raw == _BUILTIN_MODEL and chosen and chosen != _BUILTIN_MODEL:
            continue
        return raw
    return chosen


def ensure_pi_agent_dir(*, hosted: bool | None = None) -> Path:
    """保证 ~/.pi/agent 有 models.json / settings.json。托管时改写网关 baseUrl。"""
    from ..llm_gateway import GATEWAY_SUFFIX, hosted_enabled, rewrite_llm_url_for_gateway

    home = Path(os.environ.get("HOME") or "/root")
    agent = home / ".pi" / "agent"
    agent.mkdir(parents=True, exist_ok=True)
    settings_path = agent / "settings.json"
    if not settings_path.is_file():
        settings_path.write_text(
            json.dumps(
                {
                    "enableInstallTelemetry": False,
                    "defaultProjectTrust": "always",
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    else:
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        data.setdefault("enableInstallTelemetry", False)
        data["defaultProjectTrust"] = "always"
        settings_path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    use_gw = hosted if hosted is not None else hosted_enabled()
    models = json.loads(json.dumps(load_pi_models()))
    if use_gw:
        base = rewrite_llm_url_for_gateway("https://api.deepseek.com")
        if GATEWAY_SUFFIX not in base:
            base = "http://api.deepseek.com.tsecbench.gw"
        providers = models.get("providers") if isinstance(models.get("providers"), dict) else {}
        deepseek = providers.get("deepseek") if isinstance(providers.get("deepseek"), dict) else None
        if deepseek is not None:
            deepseek["baseUrl"] = base
    models_path = agent / "models.json"
    models_path.write_text(json.dumps(models, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return agent


def _child_env(*, project_id: str | None, tools: bool, role: str = "") -> dict[str, str]:
    env = dict(os.environ)
    key = llm_api_key()
    if key:
        env["DEEPSEEK_API_KEY"] = key
        env.setdefault("ANTHROPIC_AUTH_TOKEN", key)
    env["PI_TELEMETRY"] = "0"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_OFFLINE"] = "1"
    env.setdefault("PI_CODING_AGENT_DIR", str(Path(env.get("HOME") or "/root") / ".pi" / "agent"))
    if project_id:
        env["ATKBRAIN_PROJECT_ID"] = project_id
        env["ATKBRAIN_TOOLS_BASE"] = tools_base_url()
        env["ATKBRAIN_API"] = tools_base_url()
    if role:
        env["ATKBRAIN_PI_ROLE"] = str(role)
    token = (getattr(settings, "api_token", None) or "").strip()
    if token:
        env["ATKBRAIN_API_TOKEN"] = token
    for k in (
        "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
        "ALL_PROXY", "all_proxy",
    ):
        env.pop(k, None)
    return env


def _assistant_text_from_message(msg: dict | None) -> str:
    """Pi RPC 无流式时，完整助手消息在 message.content[].text。"""
    if not isinstance(msg, dict):
        return ""
    if str(msg.get("role") or "") != "assistant":
        return ""
    content = msg.get("content")
    parts: list[str] = []
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and str(item.get("type") or "") in ("", "text"):
                parts.append(str(item.get("text") or ""))
    return "".join(parts).strip()


class PiSession:
    """一条 Pi RPC 进程。不续接旧对话；猎面角色可保活进程、每轮只换 instruction。"""

    def __init__(
        self,
        *,
        cwd: str,
        system_prompt: str,
        project_id: str = "",
        role: str = "lead",
        tools: bool = True,
        emit: EmitFn | None = None,
        run_id: str | None = None,
        on_activity: Callable[[], None] | None = None,
        model: str = "",
        skill_paths: list[str] | None = None,
    ) -> None:
        self.cwd = cwd
        self.system_prompt = system_prompt or ""
        self.project_id = project_id
        self.role = role
        self.tools = tools
        self.model = (model or "").strip()
        self.skill_paths = [
            str(Path(p).expanduser())
            for p in (skill_paths or [])
            if str(p).strip()
        ]
        self._emit = emit
        self.run_id = run_id
        self.on_activity = on_activity
        self.proc: asyncio.subprocess.Process | None = None
        self._req = 0
        self._closed = False
        self.texts: list[str] = []
        self.tool_uses = 0
        self._reader_task: asyncio.Task | None = None
        self._settled = asyncio.Event()
        self._prompt_ok: asyncio.Future | None = None
        self._buf = b""
        self._last_text = ""
        self._last_thought = ""
        self._text_acc: list[str] = []
        self._thought_acc: list[str] = []
        self._turn_closed = False
        self.last_prompt_at = 0.0
        self.idle_turns = 0

    def _cmd(self) -> list[str]:
        os.makedirs(self.cwd, exist_ok=True)
        prompt_path = os.path.join(self.cwd, f".pi-system-{self.role}.txt")
        Path(prompt_path).write_text(self.system_prompt, encoding="utf-8")
        self._prompt_file = prompt_path
        cmd = [
            pi_bin(),
            "--mode", "rpc",
            "--no-session",
            "--offline",
            "--provider", pi_provider(),
            "--model", self.model or pi_model(),
            "--system-prompt", "StrikeAgent_AtkBrain-Flash",
            "--append-system-prompt", prompt_path,
        ]
        if self.tools:
            ext = extension_path()
            cmd.extend([
                "--no-context-files",
                "--no-extensions", "-e", str(ext),
                "--no-skills",
                "--no-builtin-tools",
            ])
            for raw in self.skill_paths:
                p = Path(raw)
                if not p.is_absolute():
                    p = Path(self.cwd) / p
                if p.is_file() or p.is_dir():
                    cmd.extend(["--skill", str(p.resolve())])
        else:
            cmd.extend([
                "--no-tools", "--no-builtin-tools", "--no-extensions",
                "--no-skills", "--no-context-files",
            ])
        return cmd

    async def start(self) -> None:
        ensure_pi_agent_dir()
        cmd = self._cmd()
        await wait_spawn_slot(project_id=self.project_id, role=self.role)
        try:
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.cwd,
                env=_child_env(project_id=self.project_id or None, tools=self.tools, role=self.role),
                start_new_session=True,
            )
        except Exception:
            note_spawn_failed(project_id=self.project_id, role=self.role)
            raise
        if self.proc and self.proc.pid:
            note_spawned(self.proc.pid, project_id=self.project_id, role=self.role)
        else:
            note_spawn_failed(project_id=self.project_id, role=self.role)
        self._closed = False
        self._reader_task = asyncio.create_task(self._read_loop())
        asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        if not self.proc or not self.proc.stderr:
            return
        err_path = os.path.join(self.cwd, "logs")
        try:
            os.makedirs(err_path, exist_ok=True)
            f = open(os.path.join(err_path, f"pi-{self.role}.err.log"), "ab")
        except OSError:
            f = None
        try:
            while True:
                chunk = await self.proc.stderr.read(4096)
                if not chunk:
                    break
                if f:
                    f.write(chunk)
                    f.flush()
                text = chunk.decode("utf-8", "replace").strip()
                if (
                    "Unknown option" in text
                    or "unknown option" in text.lower()
                    or "Failed to load extension" in text
                ):
                    await self._emit_safe(
                        "log",
                        {"level": "error",
                         "message": f"Pi 启动失败：{text[:300]}"},
                    )
        finally:
            if f:
                f.close()

    async def _read_loop(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            while True:
                chunk = await self.proc.stdout.read(65536)
                if not chunk:
                    break
                self._buf += chunk
                while True:
                    i = self._buf.find(b"\n")
                    if i < 0:
                        break
                    raw = self._buf[:i]
                    self._buf = self._buf[i + 1:]
                    if raw.endswith(b"\r"):
                        raw = raw[:-1]
                    if not raw.strip():
                        continue
                    try:
                        event = json.loads(raw.decode("utf-8", errors="replace"))
                    except Exception:
                        continue
                    if isinstance(event, dict):
                        await self._on_event(event)
        finally:
            self._settled.set()
            if self._prompt_ok and not self._prompt_ok.done():
                self._prompt_ok.set_result(False)

    def _review_beat_for(self, typ: str, event: dict) -> None:
        """复核进程把当前动作写进任务，页面才能看出是不是还活着。不含参数。"""
        jid = str(getattr(self, "review_job_id", "") or "")
        if not jid:
            return
        detail = ""
        if typ == "message_update":
            ev = event.get("assistantMessageEvent") or {}
            et = str(ev.get("type") or "")
            if et in ("text_delta", "text_end", "thinking_delta", "thinking_end"):
                detail = "模型生成中"
            elif et == "toolcall_start":
                name = str(ev.get("toolName") or "").strip()
                detail = f"正在调用 {name}" if name else "正在调用工具"
        elif typ == "tool_execution_start":
            name = str(event.get("toolName") or event.get("name") or "").strip()
            detail = f"正在调用 {name}" if name else "正在调用工具"
        elif typ == "compaction_start":
            detail = "正在压缩上下文"
        if not detail:
            return
        try:
            from ..review.jobs import note_review_beat
            note_review_beat(jid, detail)
        except Exception:
            pass

    async def _on_event(self, event: dict) -> None:
        typ = str(event.get("type") or "")
        if typ == "response":
            fut = self._prompt_ok
            if fut and not fut.done() and str(event.get("command") or "") == "prompt":
                fut.set_result(bool(event.get("success")))
            return
        if self.on_activity:
            try:
                self.on_activity()
            except Exception:
                pass
        self._review_beat_for(typ, event)
        if typ == "agent_settled":
            await self._flush_streams()
            self._settled.set()
            return
        if typ in ("message_end", "turn_end"):
            await self._flush_streams()
            msg = event.get("message") if isinstance(event.get("message"), dict) else {}
            # 用户回显的 message_end 不能当收工，否则会 abort 掉还没生成的助手回复。
            if not self.tools and str(msg.get("role") or "") == "assistant":
                text = _assistant_text_from_message(msg)
                if text and (not self.texts or self.texts[-1] != text):
                    self.texts.append(text)
                stop = str(msg.get("stopReason") or "")
                if stop != "aborted":
                    self._settled.set()
            return
        if typ == "agent_end" and not event.get("willRetry"):
            if not self.tools:
                await self._flush_streams()
                for item in event.get("messages") or []:
                    text = _assistant_text_from_message(item if isinstance(item, dict) else None)
                    if text and (not self.texts or self.texts[-1] != text):
                        self.texts.append(text)
                self._settled.set()
            return
        if typ == "message_update":
            ev = event.get("assistantMessageEvent") or {}
            et = str(ev.get("type") or "")
            if et == "text_delta":
                d = str(ev.get("delta") or "")
                if d:
                    self.texts.append(d)
                    self._text_acc.append(d)
            elif et == "text_end":
                content = str(ev.get("content") or "")
                await self._flush_text(content)
            elif et == "thinking_delta":
                d = str(ev.get("delta") or "")
                if d:
                    self._thought_acc.append(d)
            elif et == "thinking_end":
                content = str(ev.get("content") or "")
                await self._flush_thought(content)
            elif et == "toolcall_start":
                await self._flush_streams()
                name = str(ev.get("toolName") or "")
                if name and name.lower() not in _GRAPH_TOOLS:
                    self.tool_uses += 1
                    await self._emit_safe("tool", {"tool": name, "role": self.role})
            return
        if typ == "tool_execution_start":
            name = str(event.get("toolName") or event.get("name") or "")
            if name.lower() in _GRAPH_TOOLS:
                self.tool_uses += 1
            return
        if typ == "compaction_start":
            await self._emit_safe(
                "log",
                {"level": "info", "message": "Pi 上下文接近上限，正在自动压缩。"},
            )

    async def _flush_text(self, content: str = "") -> None:
        text = (content or "".join(self._text_acc)).strip()
        self._text_acc = []
        if text and text != self._last_text:
            self._last_text = text
            await self._emit_safe("text", {"text": text[:8000], "role": self.role})
            if (
                not getattr(self, "_turn_closed", False)
                and self.role not in ONESHOT_ROLES
                and role_wrote_turn_done(text, role=self.role)
            ):
                self._turn_closed = True
                who = "从者" if self.role == "lead" else f"工人 {self.role}"
                await self._emit_safe(
                    "log",
                    {"level": "info",
                     "message": f"{who}已写本轮收尾，结束该会话以让御主开口。"},
                )
                await self.abort()

    async def _flush_thought(self, content: str = "") -> None:
        text = (content or "".join(self._thought_acc)).strip()
        self._thought_acc = []
        if text and text != self._last_thought:
            self._last_thought = text
            await self._emit_safe(
                "thought",
                {"message": text[:8000], "kind": "reasoning", "role": self.role},
            )

    async def _flush_streams(self) -> None:
        await self._flush_thought()
        await self._flush_text()

    async def _emit_safe(self, kind: str, payload: dict) -> None:
        if not self._emit or not self.project_id:
            return
        try:
            await self._emit(self.project_id, kind, payload, run_id=self.run_id)
        except TypeError:
            try:
                await self._emit(self.project_id, kind, payload)
            except Exception:
                pass
        except Exception:
            pass

    async def _send(self, obj: dict) -> None:
        if not self.proc or not self.proc.stdin or self.proc.stdin.is_closing():
            raise RuntimeError("pi rpc stdin closed")
        self.proc.stdin.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        await self.proc.stdin.drain()

    def alive(self) -> bool:
        if self._closed or not self.proc:
            return False
        return self.proc.returncode is None

    async def prompt(self, message: str, *, timeout: float = 0) -> str:
        self.texts = []
        self._text_acc = []
        self._thought_acc = []
        self._last_text = ""
        self._last_thought = ""
        self._settled = asyncio.Event()
        self._turn_closed = False
        self.last_prompt_at = time.monotonic()
        self.idle_turns = 0
        loop = asyncio.get_running_loop()
        self._prompt_ok = loop.create_future()
        self._req += 1
        await self._send({"id": f"p{self._req}", "type": "prompt", "message": message})
        ack_ok = False
        try:
            ack_ok = bool(await asyncio.wait_for(self._prompt_ok, timeout=30))
        except Exception:
            ack_ok = False
        wait = float(timeout or 0)
        if not self.tools and not ack_ok:
            wait = min(wait, 15.0) if wait > 0 else 15.0
        try:
            await self._wait_settled(wait)
        except TimeoutError:
            text = "".join(self.texts).strip()
            await self.abort()
            if text:
                return text
            raise
        return "".join(self.texts).strip()

    def _pulse_review(self) -> None:
        jid = str(getattr(self, "review_job_id", "") or "")
        if not jid:
            return
        try:
            from ..review.jobs import pulse_review
            pulse_review(jid)
        except Exception:
            pass

    async def _wait_settled(self, wait: float) -> None:
        """等模型时每 8 秒报一次活。进程没了就立刻失败，不把静默当成卡死。"""
        deadline = time.monotonic() + wait if wait > 0 else None
        while not self._settled.is_set():
            self._pulse_review()
            slice_s = 8.0
            if deadline is not None:
                slice_s = min(slice_s, max(0.1, deadline - time.monotonic()))
            try:
                await asyncio.wait_for(self._settled.wait(), timeout=slice_s)
                return
            except TimeoutError:
                if not self.alive():
                    raise RuntimeError("pi process exited")
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError

    async def abort(self) -> None:
        try:
            await self._send({"type": "abort"})
        except Exception:
            pass
        try:
            self._settled.set()
        except Exception:
            pass
        fut = self._prompt_ok
        if fut is not None and not fut.done():
            fut.set_result(False)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await self._flush_streams()
        except Exception:
            pass
        proc = self.proc
        pid = proc.pid if proc else None
        try:
            await self.abort()
        except Exception:
            pass
        if proc and proc.stdin and not proc.stdin.is_closing():
            try:
                proc.stdin.close()
            except Exception:
                pass
        if pid:
            _kill_tree(pid, sig=signal.SIGTERM)
        if proc and proc.returncode is None:
            try:
                await asyncio.wait_for(proc.wait(), timeout=4)
            except Exception:
                if pid:
                    _kill_tree(pid, sig=signal.SIGKILL)
                    for extra in _scan_pi_pids(project_id=self.project_id, role=self.role):
                        _kill_tree(extra, sig=signal.SIGKILL)
                try:
                    if proc:
                        proc.kill()
                except Exception:
                    pass
                try:
                    if proc:
                        await asyncio.wait_for(proc.wait(), timeout=1)
                except Exception:
                    pass
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
        if pid and _pid_alive(pid):
            _kill_tree(pid, sig=signal.SIGKILL)
            await asyncio.sleep(0.08)
        if not _untrack_dead(pid) and pid:
            # 仍活着：留在 _LIVE，计数诚实；再按环境变量扫一轮
            for extra in _scan_pi_pids(project_id=self.project_id, role=self.role):
                _kill_tree(extra, sig=signal.SIGKILL)
            await asyncio.sleep(0.05)
            _untrack_dead(pid)
        self.proc = None
        _notify_spawn()


_GRAPH_TOOLS = frozenset({
    "run_cmd", "http_request", "add_node", "add_edge", "report_finding",
    "report_shell", "report_pivot_capability", "propose_intents",
    "resolve_intent", "mark_honeypot", "note", "report_flag", "request_hint",
    "note_scan_coverage",
})


async def query_text(
    *,
    system_prompt: str,
    user_prompt: str,
    cwd: str | None = None,
    timeout: float = 90,
    tools: bool = False,
    model: str | None = None,
    role: str = "oneshot",
    project_id: str = "",
    emit: EmitFn | None = None,
) -> str:
    """一次性无工具（默认）Pi 查询，返回纯文本。role 区分御主/蒸馏/漏洞页/导出，不混用进程。"""
    work = cwd or str(settings.data_dir)
    os.makedirs(work, exist_ok=True)
    sess = PiSession(
        cwd=work,
        system_prompt=system_prompt,
        tools=tools,
        role=(role or "oneshot").strip() or "oneshot",
        model=(model or "").strip(),
        project_id=project_id or "",
        emit=emit,
    )
    t0 = time.monotonic()
    try:
        await sess.start()
        remain = max(5.0, float(timeout or 90) - (time.monotonic() - t0))
        return await sess.prompt(user_prompt, timeout=remain)
    finally:
        await sess.close()
