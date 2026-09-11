"""本机 Kali 渗透工具清单（绝对路径）。

清单本身是 skill `kali-kit`，由从者/角色工人在需要路径时调用。
不要把本模块的目录全文注入系统提示。
"""
from __future__ import annotations

from ..config import REPO_ROOT

# 词表绝对路径（本机核实存在）。CTF/红队一律禁止超过 10 万行。
WL_DIR_SMALL = "/usr/share/wordlists/dirb/common.txt"  # 4614
WL_DIR_MED = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"  # 87664；目录最大档
WL_DIR_OVER_100K = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # 220560；禁止
WL_DNS = "/usr/share/wordlists/dnsmap.txt"  # 17576；本机唯一现成子域表
WL_USER_SMALL = "/usr/share/metasploit-framework/data/wordlists/unix_users.txt"  # 175
WL_PASS_SMALL = "/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt"  # 1021
WL_HTTP_DEFAULT = "/usr/share/wordlists/metasploit/http_default_userpass.txt"  # 10 对
WL_PASS_MED = "/usr/share/john/password.lst"  # 3559
WL_PASS_LARGE = "/usr/share/wordlists/metasploit/password.lst"  # 88406；未超 10 万
WL_ROCKYOU = "/usr/share/wordlists/rockyou.txt"  # ~1400 万；一律禁止

# 写入从者/子智能体提示的短指针：清单在 skill 里，禁止把目录塞进系统提示。
KIT_SKILL_HINT = (
    "需要本机工具绝对路径、词表或可复制命令时，调用 skill `kali-kit`。"
    "禁止 which / command -v / type / ls /usr/share/wordlists / ls seclists / 猜包名。"
    "未在该 skill 列出的工具当不存在。"
    "利用 payload 被 WAF 或 403/406 拦截页拦住时，调用 skill `waf-bypass-methodology`；"
    "路径级 401/403 先走 kali-kit 的 bypass-403。"
)

KIT_RULES = """# 本机工具纪律
- Pi 用内置 `read` 加载本文件；之后作业只用扩展工具 `run_cmd` / `http_request`，不要用内置 bash。
- 下列路径已存在。禁止 `which` / `command -v` / `type` 探工具；禁止 `ls /usr/share/wordlists`、ls seclists、猜 MCP 名。
- 未列出的工具当不存在。不要编造系统包名去 which。
- 命令一律 `run_cmd`；HTTP 优先 `http_request`。
- CTF 与红队一律禁止超过 10 万行的词表：端口全表、账号密码、子目录、子域名、host 碰撞、哈希碰撞都算。禁止 rockyou（~1400 万）与 dirbuster medium（220560）。目录最大用中档 87664；子域/host 只用 dnsmap（17576）；口令最大 metasploit password.lst（88406）。
- 开局策略（CTF 先看入口 vs 红队三圈）见 skill `recon-fanout` / `recon-spiral`。本 skill 只给路径和可复制命令。
"""


def kit_web(repo_root: str) -> str:
    jsfinder = f"{repo_root}/tools/JSFinder/JSFinder.py"
    bypass = f"{repo_root}/tools/bypass-403/bypass-403.sh"
    return f"""# Web 能力（默认工具 + 一条可复制命令）
- 端口扫描：`timeout 60 /usr/bin/nmap -sV -T4 -Pn --top-ports 100 --open <host>`（`run_cmd` 填 `timeout=60`）。加宽 `--top-ports 1000`（timeout=90）；确认活体后再 `-p-`。备选 `/usr/bin/masscan` 不默认。
- Web 指纹：`/usr/bin/whatweb -a 3 <url>`。
- WAF：`/usr/bin/wafw00f <url>`。
- nuclei：`/usr/bin/nuclei -u <url> -silent -nc`（引擎已装；模板走 nuclei 自己的目录，禁止 which）。
- 域名/子域：`/usr/bin/gobuster dns -d <domain> -w {WL_DNS}`（17576 行，本机唯一子域表）。被动/递归：`/usr/bin/amass`、`/usr/bin/fierce`、`/usr/bin/dnsenum`、`/usr/bin/dnsrecon`。无小中大三档子域表，只钉 dnsmap。
- 目录枚举：只用 `/usr/bin/ffuf`，必须 timeout。没有合法「大档」（medium 220560 超 10 万，禁止）。
  - 小：`/usr/bin/ffuf -u http://<host>/FUZZ -w {WL_DIR_SMALL} -mc 200,204,301,302,307,401,403 -t 40`（4614）
  - 中（最大）：`/usr/bin/ffuf -u http://<host>/FUZZ -w {WL_DIR_MED} -mc 200,204,301,302,307,401,403 -t 40`（87664）
- Host 碰撞：`/usr/bin/gobuster vhost -u http://<ip> --append-domain -w {WL_DNS}`；或 `/usr/bin/ffuf -u http://<ip>/ -H 'Host: FUZZ.<domain>' -w {WL_DNS}`。
- JS 接口：`python3 {jsfinder} -u <url> -ou js_urls.txt -os js_subs.txt`（仓库 tools/，禁止 which jsfinder）。
- 40x 绕过：已确认 401/403 后 `bash {bypass} http://<host> <path>`（iamj0ker/bypass-403；禁止 which bypass-403）。Payload 被 WAF/拦截页拦住时读 skill `waf-bypass-methodology`。
- 账号密码：`/usr/bin/hydra`（用户 `-L` 密码 `-P`）。一律禁止 `{WL_ROCKYOU}` 与 hashcat 全库。
  - 小：`-L {WL_USER_SMALL} -P {WL_PASS_SMALL}`；HTTP 默认对 `{WL_HTTP_DEFAULT}`
  - 中：`-P {WL_PASS_MED}`
  - 大（未超 10 万，红队可用；CTF 不要升到这档）：`-P {WL_PASS_LARGE}`
- HTTP：`http_request` 优先；`/usr/bin/curl` 仅管道/原始报文。
- sqlmap：仅已确认注入点。`/usr/bin/sqlmap -u <url> --batch --risk=1 --level=1`
"""


KIT_EXTRA_WEB = f"""# 已装备选（绝对路径；目录默认仍 ffuf，不要四个扫目录工具轮换）
- 目录备选（同一套小/中词表，禁止超 10 万行；ffuf 失败或缺扩展名规则时才换）：
  `/usr/bin/gobuster dir -u http://<host>/ -w {WL_DIR_MED}`；`/usr/bin/feroxbuster -u http://<host>/ -w {WL_DIR_MED}`；`/usr/bin/dirb http://<host>/ {WL_DIR_SMALL}`；`/usr/bin/wfuzz -c -z file,{WL_DIR_MED} --hc 404 http://<host>/FUZZ`
- Web：`/usr/bin/nikto -h <url>`（仅已确认 HTTP 面）；`/usr/bin/httpx -u <url> -title -status-code -silent`（探活/标题）；nuclei 扫模板；wafw00f 识别 WAF。
- 口令：`/usr/bin/hydra`、`/usr/bin/medusa`、`/usr/bin/ncrack`、`/usr/sbin/john`、`/usr/bin/hashcat`。词表仍走小/中/大（大档 88406，未超 10 万）。禁止 rockyou 与 hashcat 全库。
- 其它 Web 相关：`/usr/bin/dig`、`/usr/bin/amass`、`/usr/bin/theHarvester`、`/usr/bin/cewl`、`/usr/bin/searchsploit`、`/usr/bin/proxychains4`、`/usr/bin/msfconsole`。
"""

KIT_EXTRA_LATERAL = """# 横向 / 服务（何时用 + 一条模板）
- `/usr/bin/masscan`：大网段快速探活，不替代 nmap 服务识别。`masscan <cidr> -p 22,80,443,445 --rate 1000`
- `/usr/bin/nc`：短连 banner / 管道。`nc -nv <host> <port>`
- `/usr/bin/socat`：转发与持久管道。`socat TCP-LISTEN:<lport>,fork TCP:<host>:<port>`
- `/usr/bin/smbclient`：SMB 列共享。`smbclient -L //<host> -N`
- `/usr/bin/enum4linux`：SMB/RPC 枚举。`enum4linux -a <host>`
- `/usr/bin/smbmap`：SMB 权限图。`smbmap -H <host>`
- `/usr/bin/nxc`（同 netexec）：多协议口令喷洒/枚举。`nxc smb <host> -u <user> -p <pass>`
- `/usr/bin/rpcclient`：空会话/用户枚举。`rpcclient -U '' -N <host>`
- `/usr/bin/redis-cli`：已确认 Redis。`redis-cli -h <host> INFO`
- `/usr/bin/mysql`：已确认 MySQL。`mysql -h <host> -u <user> -p`
- `/usr/bin/psql`：已确认 Postgres。`psql -h <host> -U <user>`
- `/usr/bin/ldapsearch`：LDAP。`ldapsearch -x -H ldap://<host> -b '' -s base`
- `/usr/bin/snmpwalk`：SNMP。`snmpwalk -v2c -c public <host>`
- `/usr/bin/onesixtyone`：SNMP community 喷洒。`onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <host>`
- `/usr/sbin/showmount`：NFS。`showmount -e <host>`
- Impacket（均在 `/usr/bin`）：`impacket-smbclient` 列共享；`impacket-secretsdump` 已授权转储；`impacket-psexec` / `impacket-wmiexec` 已有凭证远程执行。
"""

KIT_BIN = """# 二进制 / 逆向（绝对路径）
- 识别：`/usr/bin/file`、`/usr/bin/strings`、`/usr/bin/xxd`、`/usr/bin/exiftool`、`/usr/bin/binwalk`
- 反汇编：`/usr/bin/objdump -d <bin>`、`/usr/bin/readelf -a <bin>`、`/usr/bin/nm <bin>`、`/usr/bin/r2 -A <bin>`、`/usr/bin/gdb`
- OCR：`/usr/bin/tesseract <image> stdout`
- Python 仅这些库可用：`z3`、`Crypto`、`sympy`、`PIL`、`capstone`。本机没有 pwntools / gmpy2，不要 which。
"""

SKILL_FRONTMATTER = """---
name: kali-kit
description: >
  This machine's Kali pentest tools: absolute binary paths, pinned wordlists,
  copy-paste commands (nmap, ffuf, hydra, sqlmap, JSFinder, bypass-403, nxc,
  impacket, binutils). Call only after you already decided you need that
  scanner or wordlist for an unknown surface. Do not call to start a CTF
  puzzle — encoding, crypto, protocol, or a hinted path is local python3 /
  openssl / http_request, not this skill. Never which / ls wordlists.
  Shared by CTF and red team. Not recon policy — that is recon-fanout /
  recon-spiral.
---
"""


def commander_kit(repo_root: str | None = None, *, objective: str | None = None) -> str:
    """清单正文（无 YAML）。objective 忽略：目录对 CTF/红队共用，策略在 recon skill。"""
    del objective
    root = repo_root if repo_root is not None else str(REPO_ROOT)
    return "\n".join([KIT_RULES, kit_web(root), KIT_EXTRA_WEB, KIT_EXTRA_LATERAL, KIT_BIN]).strip() + "\n"


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
        "# 口令档位（hydra/medusa/ncrack/john/hashcat）\n"
        f"- 小：用户 `{WL_USER_SMALL}` + 密码 `{WL_PASS_SMALL}`；HTTP `{WL_HTTP_DEFAULT}`\n"
        f"- 中：`{WL_PASS_MED}`\n"
        f"- 大（未超 10 万，红队可用；CTF 不要升档）：`{WL_PASS_LARGE}`。一律禁止 `{WL_ROCKYOU}` 与 hashcat 全库。\n"
        "- 路径：`/usr/bin/hydra`、`/usr/bin/medusa`、`/usr/bin/ncrack`、`/usr/sbin/john`、`/usr/bin/hashcat`。\n"
    )
    return "\n".join([KIT_RULES, KIT_EXTRA_LATERAL, creds]).strip() + "\n"
