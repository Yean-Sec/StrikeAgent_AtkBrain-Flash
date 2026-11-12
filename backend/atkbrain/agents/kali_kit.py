"""仓库内真实存在的工具路径。

路径写在下面的短纪律里，不要再去读外部 skill 文件。
不要把本模块的目录全文注入系统提示。环境不一定是某一发行版，
正文不写系统词表或扫描器的绝对路径。
"""
from __future__ import annotations

from ..config import REPO_ROOT

KIT_SKILL_HINT = (
    "该环境不一定是某一发行版。禁止假设 /usr/bin 或 /usr/share 下有扫描器或词表，禁止去读这些路径。"
    "仓库里确认存在的只有 JSFinder 和 bypass-403；未列出的文件当不存在。"
    "禁止 which / command -v / type / ls 词表目录 / 猜包名。"
    "路径级 401/403 先用仓库里的 bypass-403；没有这份脚本就停在已确认的状态码上。"
)

KIT_RULES = """# 本机工具纪律
- Pi 用内置 `read` 加载本文件；之后作业只用扩展工具 `run_cmd` / `http_request`，不要用内置 bash。
- 下面只列出仓库里真实存在的文件。禁止 `which` / `command -v` / `type`，禁止 `ls /usr/share`、ls seclists、猜包名。
- 未列出的文件当不存在。不要编造系统路径，也不要因为读不到词表就改去猜别的目录。
- HTTP 优先 `http_request`。没有词表文件时不要开目录爆破。
- 词表超过 10 万行一律不用：端口全表、账号密码、子目录、子域名、host 碰撞、哈希碰撞都算。
- 开局策略在系统提示里。这里只给仓库内真实路径。
"""


def kit_web(repo_root: str) -> str:
    jsfinder = f"{repo_root}/tools/JSFinder/JSFinder.py"
    bypass = f"{repo_root}/tools/bypass-403/bypass-403.sh"
    return f"""# 仓库内工具
- JS 接口：`python3 {jsfinder} -u <url> -ou js_urls.txt -os js_subs.txt`
- 路径级 401/403：已确认后 `bash {bypass} http://<host> <path>`。
- HTTP：用 `http_request`。不要写死 curl、nmap、ffuf、sqlmap、nuclei 的系统路径。本仓库没有这些二进制，也没有系统词表。
- 经开放代理或 SSRF 打内层登录：先读表单 action，把同一方法与 body 转发到认证处理接口。外层打在代理外壳或站点根路径上，不等于内层收到账密。
"""


KIT_EXTRA_WEB = """# 不要假设的系统工具
- 目录、子域、指纹、口令爆破都依赖本机词表和二进制。这里没有列出路径，就不要去读，不要编造 /usr/share 或 /usr/bin。
- 红队禁止 nmap/masscan（原始套接字会漏真实 IP）。没有词表时用 `http_request` 看入口，不要换一个扫描器继续猜路径。
"""

KIT_EXTRA_LATERAL = """# 横向
- 禁止无跳板从本机直连内网，禁止打本机 docker 网桥。
- 立足点上常常没有 ssh 客户端：不要用 curl 的 sftp/libssh2 去讲 SSH。
- 正路：立足点上把 22 或 SOCKS 转到本机（webshell 反连或常驻转发），再用本机已有的 ssh 客户端打已 `report_pivot_capability` 的主机。不要假设 ssh、sshpass、socat、nc 装在固定系统路径。
- 必须是常驻转发（listen+fork 或反连保持）。一次性短超时脚本转发撑不住握手：banner 超时先修通道，不要改字典。
- 口令只用题面或图上已经出现的字面量，不要按厂商名合成。失败不要升字典。
"""

KIT_BIN = """# 逆向
- 不假设 file、strings、objdump、gdb 的安装路径。需要时用仓库或题面已经给出的文件，用 `python3` 处理。
- 不要 which，不要写 /usr/bin。
"""

SKILL_FRONTMATTER = """---
name: kali-kit
description: >
  Repo-local tool paths that actually exist (JSFinder, bypass-403).
  This environment is not assumed to be any one distro. Do not read
  /usr/bin or /usr/share wordlists. Call only after you already decided
  you need a listed file for an unknown surface. Encoding, crypto,
  protocol, or a hinted path is local python3 / openssl / http_request,
  not this skill. Never which / ls wordlists.
  Shared by CTF and red team. Not recon policy — that is recon-fanout /
  recon-spiral.
---
"""


def commander_kit(repo_root: str | None = None, *, objective: str | None = None) -> str:
    """清单正文（无 YAML）。objective 忽略：目录对 CTF/红队共用，策略在 recon skill。"""
    del objective
    root = repo_root if repo_root is not None else str(REPO_ROOT)
    parts = [KIT_RULES, kit_web(root), KIT_EXTRA_WEB, KIT_EXTRA_LATERAL, KIT_BIN]
    return "\n".join(parts).strip() + "\n"


def skill_markdown(repo_root: str | None = None) -> str:
    """仓库 `skills/kali-kit/SKILL.md` / 猎面工作区 `.agents/skills/kali-kit/SKILL.md` 的完整内容。"""
    return SKILL_FRONTMATTER + "\n" + commander_kit(repo_root)


def recon_kit(repo_root: str | None = None, *, objective: str | None = None) -> str:
    del objective
    root = repo_root if repo_root is not None else str(REPO_ROOT)
    return "\n".join([KIT_RULES, kit_web(root), KIT_EXTRA_WEB]).strip() + "\n"


def reverse_kit() -> str:
    return "\n".join([KIT_RULES, KIT_BIN]).strip() + "\n"


def lateral_kit() -> str:
    creds = (
        "# 口令\n"
        "- 只用题面或图上已经出现的口令字面量。不要升到超大词表，不要假设系统词表路径存在。\n"
        "- 转发到本机后再用本机已有的 ssh 客户端。不要写死 /usr/bin。\n"
    )
    return "\n".join([KIT_RULES, KIT_EXTRA_LATERAL, creds]).strip() + "\n"
