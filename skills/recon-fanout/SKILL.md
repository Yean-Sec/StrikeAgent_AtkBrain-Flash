---
name: recon-fanout
description: >
  CTF recon: look at the live challenge first — source, comments, robots, hinted
  paths — and report_flag if it is already there. If the brief already gives a
  transform, encoding, protocol, or file, write a local python/openssl script;
  do not open nmap/ffuf. Recon only after that, in the background, when the
  attack surface is still unknown. Nested workers forbidden. Not for red team.
---

# 信息收集：CTF 先看题交旗，recon 不得当主线

Pi 用内置 `read` 加载本文件；之后作业只用扩展工具 `run_cmd` / `http_request`。

**唯一目标是尽快 `report_flag`。** getshell / 读文件只是手段。评测邻题始终越界。
不要螺旋升圈、不要扫旁站、不要用题名检索 writeup。已识别组件/版本时用 WebSearch 查 CVE/N-day，公告页用 `http_request` 拉取。

子智能体 **不设上限**。调度并发拉起多个角色会话（`recon` / `web-exploit`）。每个工人只做一面。**禁止再开子进程**。

## 开局（必须先做完，再考虑扫描）

很多题一眼就能交旗。从者或 `web-exploit` **先**对本题入口做活体阅读和题面利用，**不要**先 nmap / ffuf：

1. `http_request` GET 入口（https 与 http）
2. 读 HTML / JS / 注释 / 隐藏字段 / 响应头
3. `/robots.txt`、`/sitemap.xml`、`/.well-known/security.txt`
4. 题面 brief 里的路径、文件、账号、源码链接优先打开
5. 正文或文件里出现 `flag{` / 题面要求的答案形态 → 立刻 `report_flag`

不要等 nmap / ffuf 结束再看源码。不要把整轮只耗在扫描。
开局主线是 `web-exploit`（或从者自己 GET），不是 recon。开局禁止 `request_hint`。

## 看懂之后：脚本优先，扫描器不是默认下一步

## 看懂之后：脚本优先，扫描器不是默认下一步

渗透工具用来找**还不知道在哪**的面。题已经把变换、路径、参数、文件交到手上时，**工作区写短脚本或直接 `http_request` / `python3` / `openssl` / `base64`**，不要调 skill `kali-kit`，不要 nmap / ffuf / sqlmap / hydra：

- 编码、哈希、cookie、JWT、明文算法、自定义协议 → 本地 python3（`z3` / `Crypto` / `sympy` / `PIL` / `capstone`）或 openssl
- 下发的可执行文件 / 固件 / VM → `reverse` / `protocol-model`，先 file/strings 再本地求解
- 题面给出的路径、账号、源码链接 → `http_request` 打开，不要目录爆破找同一条路
- 已看见明确注入/SSTI/反序列化线索 → 先手拼一轮 payload；sqlmap 只在手工确认注入点之后

只有「活体看过、题面路径打过、仍然不知道攻击面在哪」才进入下一节后台 recon，这时才调用 `kali-kit` 取 nmap/ffuf 的绝对路径。一次只用一把扫描器，不要 ffuf/gobuster/feroxbuster 轮换。

## 看完没有旗，再后台 recon

入口已看过、题面路径已打开、仍无 flag 时，才并行派出 recon。每个工人只做一面。recon **不能挡交旗**。

### 有对应资产才开（不是开局必做）

1. **端口**：`timeout 90 /usr/bin/nmap -sV -T4 -Pn --top-ports 1000 --open <host>`（`run_cmd` `timeout=90`）。禁止开局 `-p-`。跳过 top-100 小圈。
2. **子域**（有域名）：`/usr/bin/gobuster dns -d <domain> -w /usr/share/wordlists/dnsmap.txt`。禁止超 10 万行词表；本机只有 dnsmap。
3. **目录**（有 HTTP，且首页/题面路径没有给出攻击面）：中档 ffuf，`timeout=120`，词表 `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`。禁止 dirbuster medium / rockyou。跳过 common.txt 小圈。

### 建议同时开

4. **HTTP 指纹 + WAF**：whatweb、wafw00f。利用 payload 被 403/406 拦截页拦住时读 skill `waf-bypass-methodology`。
5. **DNS 记录**：`dig` A/AAAA/MX/TXT。用 **系统解析器**，不要钉死 `8.8.8.8`
6. **TLS / 证书 SAN**：`httpx`
7. **虚拟主机**（本题 Host 头，不是旁站/邻题）
8. **JS 接口**：调用 skill `kali-kit` 取 `JSFinder.py` 绝对路径
9. **轻量 nuclei**（已确认 HTTP），必须 timeout

## 不要开局并行

- hydra / sqlmap / 全端口 `-p-` / 超 10 万行词表
- 螺旋第 1 圈（top-100、common.txt 升圈）
- 把 nmap / ffuf 当成开局第一面
- 把同一面拆成两个工人
- recon 内部再开子进程
- 评测邻题、旁站当新题打
- `request_hint`（看提示会扣分；活体和题面功能都空转后再用）

## 实在做不出来再看提示

活体看过、题面路径打过、一手利用空转、后台 recon 也没有旗，才允许 `request_hint`。**每次成功调用评测接口都会扣分。** 已看过会缓存，不要重复请求。提示不是 writeup，拿到后立刻按提示打，不要再空转。

回传：活体里是否已有 flag、各面结论、已写图节点。一面失败不要卡住其它面。相同扫描签名不要再跑（简报「已覆盖」）。
