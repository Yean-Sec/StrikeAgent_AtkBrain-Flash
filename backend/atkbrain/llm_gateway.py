"""TSecBench 托管网关：把白名单大模型 HTTPS 地址改写成平台 http://*.tsecbench.gw。

平台注入 BENCHMARK_BASE_URL / BENCHMARK_TOKEN（无 ATKBRAIN_ 前缀），
本模块同时把它们别名到 Settings 能读的 ATKBRAIN_BENCHMARK_*。
"""
from __future__ import annotations

import os
from collections.abc import MutableMapping
from urllib.parse import urlparse, urlunparse

GATEWAY_SUFFIX = ".tsecbench.gw"

# 平台《大模型 API 白名单》主机。通配 *.maas.aliyuncs.com 另判。
_EXACT_HOSTS = frozenset({
    "api.hunyuan.cloud.tencent.com",
    "api.lkeap.cloud.tencent.com",
    "tokenhub.tencentmaas.com",
    "api.deepseek.com",
    "dashscope.aliyuncs.com",
    "qianfan.baidubce.com",
    "ark.cn-beijing.volces.com",
    "open.bigmodel.cn",
    "api.moonshot.cn",
    "api.siliconflow.cn",
    "spark-api-open.xf-yun.com",
    "api.minimaxi.com",
    "api.stepfun.com",
    "api.lingyiwanwu.com",
    "api.baichuan-ai.com",
    "api.xiaomimimo.com",
    "api.kimi.com",
    "agent-awd.baidu.com",
})

_TRUTHY = frozenset({"1", "true", "yes", "on"})

_SKIP_ENV_SUBSTR = ("BENCHMARK",)


def _truthy(val: str | None) -> bool:
    return str(val or "").strip().lower() in _TRUTHY


def hosted_enabled(env: MutableMapping[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    return _truthy(e.get("ATKBRAIN_HOSTED"))


def gateway_enabled(env: MutableMapping[str, str] | None = None) -> bool:
    e = os.environ if env is None else env
    if _truthy(e.get("ATKBRAIN_LLM_GATEWAY")):
        return True
    return hosted_enabled(e)


def _host_allowed(host: str) -> bool:
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    if h.endswith(GATEWAY_SUFFIX):
        return True
    if h in _EXACT_HOSTS:
        return True
    if h.endswith(".maas.aliyuncs.com"):
        return True
    return False


def rewrite_llm_url_for_gateway(url: str) -> str:
    """https://api.deepseek.com/v1 → http://api.deepseek.com.tsecbench.gw/v1。幂等。"""
    raw = (url or "").strip()
    if not raw:
        return raw
    u = urlparse(raw)
    host = (u.hostname or "").strip().lower().rstrip(".")
    if not host or not _host_allowed(host):
        return raw
    if host.endswith(GATEWAY_SUFFIX):
        new_host = host
    else:
        new_host = host + GATEWAY_SUFFIX
    user = u.username or ""
    auth = user
    if user and u.password is not None:
        auth = f"{user}:{u.password}"
    if auth:
        auth += "@"
    port = f":{u.port}" if u.port else ""
    netloc = f"{auth}{new_host}{port}"
    return urlunparse(("http", netloc, u.path, u.params, u.query, u.fragment))


def _should_rewrite_key(key: str) -> bool:
    k = (key or "").upper()
    if any(s in k for s in _SKIP_ENV_SUBSTR):
        return False
    if k in ("ANTHROPIC_API_URL", "OPENAI_API_BASE", "OPENAI_BASE_URL"):
        return True
    if "BASE_URL" in k or k.endswith("_URL") or k.endswith("_ENDPOINT"):
        return True
    return False


def apply_llm_gateway(env: MutableMapping[str, str] | None = None) -> dict[str, str]:
    """就地改写环境变量中的白名单大模型 URL。返回被改写的 {key: new_value}。"""
    e = os.environ if env is None else env
    changed: dict[str, str] = {}
    for key in list(e.keys()):
        if not _should_rewrite_key(key):
            continue
        old = e.get(key) or ""
        if not old.strip():
            continue
        new = rewrite_llm_url_for_gateway(old)
        if new != old:
            e[key] = new
            changed[key] = new
    return changed


def apply_platform_env_aliases(env: MutableMapping[str, str] | None = None) -> dict[str, str]:
    """平台注入的 BENCHMARK_* / 常见 Key 名 → 程序实际读取的变量。"""
    e = os.environ if env is None else env
    mapped: dict[str, str] = {}

    def _fill(dst: str, *srcs: str) -> None:
        if (e.get(dst) or "").strip():
            return
        for src in srcs:
            val = (e.get(src) or "").strip()
            if val:
                e[dst] = val
                mapped[dst] = src
                return

    _fill("ATKBRAIN_BENCHMARK_BASE_URL", "BENCHMARK_BASE_URL")
    _fill("ATKBRAIN_BENCHMARK_TOKEN", "BENCHMARK_TOKEN")
    _fill(
        "ATKBRAIN_BENCHMARK_FOCUS_CODES",
        "BENCHMARK_FOCUS_CODES",
        "FOCUS_CODES",
    )
    _fill(
        "ANTHROPIC_AUTH_TOKEN",
        "DEEPSEEK_API_KEY",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
    )
    _fill(
        "DEEPSEEK_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
    )
    return mapped
