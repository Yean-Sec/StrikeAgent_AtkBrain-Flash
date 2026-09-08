---
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

# 本机工具纪律
- 下列路径已存在。禁止 `which` / `command -v` / `type` 探工具；禁止 `ls /usr/share/wordlists`、ls seclists、猜 MCP 名。
- 未列出的工具当不存在。不要编造系统包名去 which。
- 命令一律 `mcp__atkbrain__run_cmd`；HTTP 优先 `mcp__atkbrain__http_request`。
- CTF 与红队一律禁止超过 10 万行的词表：端口全表、账号密码、子目录、子域名、host 碰撞、哈希碰撞都算。禁止 rockyou（~1400 万）与 dirbuster medium（220560）。目录最大用中档 87664；子域/host 只用 dnsmap（17576）；口令最大 metasploit password.lst（88406）。
- 开局策略（CTF 先看入口 vs 红队三圈）见 skill `recon-fanout` / `recon-spiral`。本 skill 只给路径和可复制命令。

# Web 能力（默认工具 + 一条可复制命令）
- 端口扫描：`timeout 60 /usr/bin/nmap -sV -T4 -Pn --top-ports 100 --open <host>`（`run_cmd` 填 `timeout=60`）。加宽 `--top-ports 1000`（timeout=90）；确认活体后再 `-p-`。备选 `/usr/bin/masscan` 不默认。
- Web 指纹：`/usr/bin/whatweb -a 3 <url>`。
- WAF：`/usr/bin/wafw00f <url>`。
- nuclei：`/usr/bin/nuclei -u <url> -silent -nc`（引擎已装；模板走 nuclei 自己的目录，禁止 which）。
- 域名/子域：`/usr/bin/gobuster dns -d <domain> -w /usr/share/wordlists/dnsmap.txt`（17576 行，本机唯一子域表）。被动/递归：`/usr/bin/amass`、`/usr/bin/fierce`、`/usr/bin/dnsenum`、`/usr/bin/dnsrecon`。无小中大三档子域表，只钉 dnsmap。
- 目录枚举：只用 `/usr/bin/ffuf`，必须 timeout。没有合法「大档」（medium 220560 超 10 万，禁止）。
  - 小：`/usr/bin/ffuf -u http://<host>/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401,403 -t 40`（4614）
  - 中（最大）：`/usr/bin/ffuf -u http://<host>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -mc 200,204,301,302,307,401,403 -t 40`（87664）
- Host 碰撞：`/usr/bin/gobuster vhost -u http://<ip> --append-domain -w /usr/share/wordlists/dnsmap.txt`；或 `/usr/bin/ffuf -u http://<ip>/ -H 'Host: FUZZ.<domain>' -w /usr/share/wordlists/dnsmap.txt`。
- JS 接口：`python3 <REPO>/tools/JSFinder/JSFinder.py -u <url> -ou js_urls.txt -os js_subs.txt`（仓库 tools/，禁止 which jsfinder）。
- 40x 绕过：已确认 401/403 后 `bash <REPO>/tools/bypass-403/bypass-403.sh http://<host> <path>`（iamj0ker/bypass-403；禁止 which bypass-403）。
- 账号密码：`/usr/bin/hydra`（用户 `-L` 密码 `-P`）。一律禁止 `/usr/share/wordlists/rockyou.txt` 与 hashcat 全库。
  - 小：`-L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`；HTTP 默认对 `/usr/share/wordlists/metasploit/http_default_userpass.txt`
  - 中：`-P /usr/share/john/password.lst`
  - 大（未超 10 万，红队可用；CTF 不要升到这档）：`-P /usr/share/wordlists/metasploit/password.lst`
- HTTP：`http_request` 优先；`/usr/bin/curl` 仅管道/原始报文。
- sqlmap：仅已确认注入点。`/usr/bin/sqlmap -u <url> --batch --risk=1 --level=1`

# 已装备选（绝对路径；目录默认仍 ffuf，不要四个扫目录工具轮换）
- 目录备选（同一套小/中词表，禁止超 10 万行；ffuf 失败或缺扩展名规则时才换）：
  `/usr/bin/gobuster dir -u http://<host>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`；`/usr/bin/feroxbuster -u http://<host>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`；`/usr/bin/dirb http://<host>/ /usr/share/wordlists/dirb/common.txt`；`/usr/bin/wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --hc 404 http://<host>/FUZZ`
- Web：`/usr/bin/nikto -h <url>`（仅已确认 HTTP 面）；`/usr/bin/httpx -u <url> -title -status-code -silent`（探活/标题）；nuclei 扫模板；wafw00f 识别 WAF。
- 口令：`/usr/bin/hydra`、`/usr/bin/medusa`、`/usr/bin/ncrack`、`/usr/sbin/john`、`/usr/bin/hashcat`。词表仍走小/中/大（大档 88406，未超 10 万）。禁止 rockyou 与 hashcat 全库。
- 其它 Web 相关：`/usr/bin/dig`、`/usr/bin/amass`、`/usr/bin/theHarvester`、`/usr/bin/cewl`、`/usr/bin/searchsploit`、`/usr/bin/proxychains4`、`/usr/bin/msfconsole`。

# 横向 / 服务（何时用 + 一条模板）
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

# 二进制 / 逆向（绝对路径）
- 识别：`/usr/bin/file`、`/usr/bin/strings`、`/usr/bin/xxd`、`/usr/bin/exiftool`、`/usr/bin/binwalk`
- 反汇编：`/usr/bin/objdump -d <bin>`、`/usr/bin/readelf -a <bin>`、`/usr/bin/nm <bin>`、`/usr/bin/r2 -A <bin>`、`/usr/bin/gdb`
- OCR：`/usr/bin/tesseract <image> stdout`
- Python 仅这些库可用：`z3`、`Crypto`、`sympy`、`PIL`、`capstone`。本机没有 pwntools / gmpy2，不要 which。
