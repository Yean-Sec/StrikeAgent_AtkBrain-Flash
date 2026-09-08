---
name: recon-spiral
description: >
  Red-team spiral recon. 从者 fans out parallel recon Tasks in three rings
  小/中/大 (top-100 + common.txt, then top-1000 + medium dir, then -p- and
  recursive/extension fuzz). Expand after 6 empty 御主方案 with no quality
  growth. Nested Task forbidden. Not for CTF. Goal is getshell.
---

# 信息收集：红队螺旋（从者并行派出）

子智能体 **不设上限**。同一助手回合并行提交多个 `Task`（`subagent_type: recon`，`run_in_background: true`）。每个 Task 只做一面。子智能体 **禁止再 Task**。

升圈看简报 **允许圈**：连续 **6** 个御主方案无高质量增长（已验证洞 / 凭证 / 立足点 / 能力边）才进下一圈。`info` / `service` / `danger` 不算增长。入口挂了（infra）不计数。有增长则留在当前圈。

**进入该圈必须做该圈完整清单**，不要因为小圈做过 top-100 / `common.txt` 就省略。第 1 圈仍禁止抢跑更高档。

**目标是 `report_shell` / getshell。** 本 skill 仅红队。CTF 走 `recon-fanout`（先看题交旗，不升圈）。

## 第 1 圈（小 · 开局，旁站关）

只打 **当前 URL / 当前 host:port**。SAN、兄弟域名只记情报，不当攻击面。

同一回合并行（有对应资产才开）：

1. **端口**：`timeout 60 /usr/bin/nmap -sV -T4 -Pn --top-ports 100 --open <host>`（`run_cmd` `timeout=60`）
2. **目录**：小档 ffuf，`/usr/share/wordlists/dirb/common.txt`，`timeout=90`
3. **HTTP 指纹 + WAF**：whatweb、wafw00f
4. **HTTP 入口面**：https/http、robots、sitemap、security.txt
5. **DNS 记录**：系统解析器，不要钉死 `8.8.8.8`
6. **JS 接口**（已确认 HTTP）：调用 skill `kali-kit` 取 `JSFinder.py` 绝对路径

禁止第 1 圈：中档目录、top-1000、`-p-`、gobuster vhost 当攻击、扫兄弟站、hydra/sqlmap。

入口已确认时 `web-exploit` 与第 1 圈 recon **同时** 开。新端口/路径至少测→证一轮。

## 第 2 圈（中 · 允许圈=2 后做满）

进入后做满本圈，不要因第 1 圈已跑过而跳过：

- 端口：`--top-ports 1000`
- 目录：中档 `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
- 子域：dnsmap 全表
- **旁站开**：同 IP vhost、同证书其它 CN、同备案/兄弟域。每个旁站自己从第 1 圈开，禁止把主站中档表直接浇过去。

## 第 3 圈（大 · 允许圈=3 后做满）

进入后做满本圈：活体后再 `-p-`。目录不再升词表（dirbuster medium 超 10 万，禁止）：对命中目录递归、加扩展名/备份、nikto、加深 nuclei。DNS 可 `amass` / `fierce`，必须 timeout。

## 账本

覆盖账本在工作区 `SPIRAL.json`，每轮简报有「已覆盖 / 允许圈 / 空转 x/6」。账本记扫描只展示当前允许圈，不是禁令。按本圈完整清单做。用 `note_scan_coverage` 补命中列表。一面失败不要卡住其它面。
