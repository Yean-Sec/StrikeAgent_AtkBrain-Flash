# StrikeAgent_AtkBrain-Flash — TSecBench 托管镜像
# 基础：Debian Bookworm + Python 3.12 + Node 22（Pi 要求 Node 较新）。
# 体积远小于 Kali 全量，仍预装常见 Web/Pwn/Crypto 工具。
# 启动后自行拉题开打。密钥不要写进镜像，在平台「运行时环境变量」填写：
#   DEEPSEEK_API_KEY       大模型 Key（必填；也可填 ANTHROPIC_AUTH_TOKEN）
#   BENCHMARK_TOKEN        平台自动注入
#   BENCHMARK_BASE_URL     平台自动注入
ARG PYTHON_IMAGE=docker.m.daocloud.io/library/python:3.12-slim-bookworm

FROM ${PYTHON_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/ \
    PIP_TRUSTED_HOST=mirrors.aliyun.com \
    NPM_CONFIG_REGISTRY=https://registry.npmmirror.com \
    ATKBRAIN_HOSTED=1 \
    ATKBRAIN_LLM_GATEWAY=1 \
    ATKBRAIN_HOST=0.0.0.0 \
    ATKBRAIN_PORT=5003 \
    ATKBRAIN_PI_BIN=pi \
    ATKBRAIN_PI_PROVIDER=deepseek \
    ATKBRAIN_PI_MODEL=deepseek-flash \
    ATKBRAIN_CLAUDE_MODEL=deepseek-flash \
    ATKBRAIN_CLAUDE_FALLBACK_MODEL=deepseek-flash \
    ATKBRAIN_SUPERVISOR_MODEL=deepseek-flash \
    ATKBRAIN_EVOLVE_MODEL=deepseek-flash \
    ATKBRAIN_REPORT_MODEL=deepseek-flash \
    PI_TELEMETRY=0 \
    PI_SKIP_VERSION_CHECK=1 \
    PI_OFFLINE=1 \
    HOME=/root \
    PATH=/opt/atkbrain/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq vim-tiny less procps iproute2 iputils-ping \
      gcc g++ make nasm pkg-config libffi-dev libssl-dev \
      unzip p7zip-full xz-utils file bsdmainutils xxd binutils elfutils \
      strace ltrace tmux openssl \
      nmap \
      socat netcat-traditional \
      gdb \
      php-cli ruby \
      default-mysql-client redis-tools postgresql-client \
      smbclient \
      libimage-exiftool-perl; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*; \
    NODE_VER=22.18.0; \
    curl -fsSL "https://npmmirror.com/mirrors/node/v${NODE_VER}/node-v${NODE_VER}-linux-x64.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1; \
    node --version; \
    npm --version

# 渗透工具：仓库没有的跳过，避免整层失败
RUN set -eux; \
    apt-get update; \
    for p in \
      ncat gdbserver sqlmap nikto gobuster dirb wfuzz hydra john \
      radare2 binwalk sslscan foremost steghide python3-impacket \
      python3-pycryptodome python3-sympy python3-bs4 python3-pil \
      ffuf feroxbuster masscan whatweb wafw00f hashid enum4linux tshark checksec \
    ; do \
      apt-get install -y --no-install-recommends "$p" || echo "[docker] skip $p"; \
    done; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/atkbrain/backend

COPY backend/requirements.txt /opt/atkbrain/backend/requirements.txt

RUN set -eux; \
    python3 -m venv /opt/atkbrain/venv; \
    /opt/atkbrain/venv/bin/pip install --upgrade pip; \
    grep -v -i weasyprint /opt/atkbrain/backend/requirements.txt > /tmp/req.txt; \
    /opt/atkbrain/venv/bin/pip install --no-cache-dir -r /tmp/req.txt; \
    /opt/atkbrain/venv/bin/pip install --no-cache-dir pwntools pycryptodome gmpy2 z3-solver ropper; \
    npm install -g @earendil-works/pi-coding-agent; \
    npm cache clean --force; \
    rm -rf /root/.npm /tmp/req.txt; \
    mkdir -p /opt/atkbrain/backend/data/workspaces \
             /opt/atkbrain/backend/data/loot \
             /opt/atkbrain/backend/data/reports \
             /opt/atkbrain/backend/data/logs; \
    command -v pi >/dev/null; \
    pi --version || true

COPY backend/atkbrain /opt/atkbrain/backend/atkbrain
COPY skills /opt/atkbrain/skills
COPY pi/extensions /opt/atkbrain/pi/extensions
COPY tools /opt/atkbrain/tools
COPY scripts/docker-entrypoint.sh /opt/atkbrain/docker-entrypoint.sh

RUN chmod 0755 /opt/atkbrain/docker-entrypoint.sh \
    && find /opt/atkbrain/backend/atkbrain -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

EXPOSE 5003

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5003/api/health || exit 1

ENTRYPOINT ["/opt/atkbrain/docker-entrypoint.sh"]
