---
name: src-hunt-playbook
description: >
  SRC vendor-list vuln hunting. Pick types from the menu by live
  surface (XSS / SQLi / RCE / file / authz / logic / leak / backdoor / n-day);
  do not fan out all 11 every turn. Report low / medium / high / critical
  onto the findings page.
---

# 信息收集与挖洞：SRC 厂商清单（从者并行派出）

子智能体 **不设上限**。同一助手回合并行提交多个 `Task`（`subagent_type: recon` / `web-exploit` / `src-hunt`，`run_in_background: true`）。每个 Task 只做一面或一类。子智能体 **禁止再 Task**。

**本 skill 仅 SRC（track=src）。** CTF 走 `recon-fanout`。红队走 `recon-spiral`（目标 getshell）。不要升圈、不要先看题交旗、不要为拿 shell 停工。

产出 = 尽可能多的独立 `report_finding`（低/中/高危/严重都进漏洞页，各附最小可复现 PoC）。高危/严重必须二次验证且 evidence 含已证实危害。只打到「角色不存在 / 参数不完整 / 空 data」的未授权口仍要报，**不能评高危**。

厂商 11 项是**类型菜单**不是穷尽洞单，也不是每轮必测清单。同一类型下所有变体都要挖，低/中/高危都报。
按图上的入口形态选该派的类：有对应面才开 Task；没有证据就暂缓，不要为凑齐 11 路过代理。

**禁止破坏业务**：不准 DROP/DELETE FROM/TRUNCATE，不准删业务文件/订单；SQLi 只读证明；删除类只动自己上传的测试文件。

不报：phpinfo/指纹/Banner/目录列表、前台弱口令。CSRF、开放重定向按真实危害评级后仍进漏洞页。不夺旗、不以 getshell 收工、**不打内网横向**。

## 评级

**高危**

1. 直接拿服务器权限：任意命令执行、上传 webshell、任意代码执行。
2. 大量个人敏感信息泄露。
3. 支付/改金额等影响盈利的逻辑。
4. 能直接盗取用户身份且影响严重：可拿大量敏感数据或执行命令的 SQLi。
5. 可重置管理员密码并导致大量敏感信息泄露。

**中危 / 低危（也要报进漏洞页，不要抬成高危）**

一般 SQLi 只证库名/用户名、存储 XSS、普通越权、heapdump、短信轰炸、错误页内网 IP。能把影响打到上面高危标准再升评级。

## 决策顺序

```
资产铺开 → 看入口形态，从菜单里选出有面的类型 → 只对这些类型 fan-out
已验证洞提危害 → 新面出现再开新类型 → 下一资产
不要停在第一条；不要为拿 shell 放弃仍有面的类型
不要每轮把 11 类全派一遍
```

| 图上看到 | 才测 | 没有这些就暂缓 |
|---|---|---|
| HTML / 表单 / 反射进 DOM | XSS | JSON-only、OSS XML 错误页 |
| JSON / 查询 / 登录 / 订单参数 | SQLi | 纯静态、无参数的私有桶 |
| ping / exec / cmd / 诊断接口 | 命令执行 | 无命令类参数 |
| 模板报错 / 反序列化 / 表达式 | 代码执行 | 无模板、无序列化字节 |
| include / path= / file= / page= | 文件包含 | 无路径类参数 |
| 下载 / 上传 / 备份 / 附件 | 任意文件 | 无文件面 |
| /user / 对象 ID / token / 未授权 200 | 越权 | — |
| 金额 / 数量 / 优惠 / 积分 / 下单 | 逻辑（改价等） | 非交易面 |
| swagger / .git / 配置 200 / 云钥匙 | 高危泄露 | 仅 Banner/phpinfo |
| /admin / debug / 隐藏登录 / 已知马 | 后门 | 无隐藏入口迹象 |
| 产品+版本（Kong 0.14、nginx/1.x） | N-day | 无版本、不要无产品散弹 |

## 0. 资产铺开（先把面撑大）

同一回合并行（有对应资产才开）。工具绝对路径见 skill `kali-kit`。

1. **端口**：`timeout 90 /usr/bin/nmap -sV -T4 -Pn --top-ports 1000 --open <host>`（`run_cmd` `timeout=90`）。不要立刻 `-p-`。
2. **目录**：中档 ffuf，词表见 `kali-kit`，`timeout=120`
3. **HTTP 入口**：https/http、robots、sitemap、security.txt、swagger、`.git`、备份
4. **JS 接口**：调用 skill `kali-kit` 取 `JSFinder.py` 绝对路径
5. **DNS / 子域**：系统解析器 + dnsmap；不要钉死 `8.8.8.8`

入口已确认时 `web-exploit` / `src-hunt` 与 recon **同一回合 Agent/Task 并行** 开（必须带 `subagent_type`）。禁止先写完 info 再打洞，禁止省略类型的通用 Agent。新端口/路径至少测→证一轮。静态 SPA 不是无攻击面。

源站 nmap 只有 Web、没有 3306/6379/5432 → 疑似库在别的机器。下一刀泄配置/SQLi/未授权读/SSRF，不要为找库再扫库端口，不要把 jdbc/rds/*.internal 当新资产 nmap，不要 `report_pivot_capability`。

禁止：开局全端口、超 10 万行词表、把旁站当跳板打 RFC1918、委派 `lateral` / `privesc` / `flag-hunt`。

## 1. XSS

反射/存储/DOM。存储型默认中危；可直接盗号且影响面大可上调。每处独立报，不要合并。委派 `web-exploit` 或 `src-hunt`。

## 2. SQL 注入

联合/报错/盲注。先证明库名/用户名（中危）；能拖大量敏感数据或叠命令执行 → 高危。时间盲注逐字节是最后手段。只用 SELECT/布尔/报错，禁止 sqlmap `--os-shell` / `--file-del`。

## 3. 命令执行 / 4. 代码执行

参数拼接、反序列化、SSTI、模板、表达式、上传解析。验证后按高危报（canary + proof_url），**不要转后渗收工**，继续挖下一类。RCE 只写无害短 txt canary 并取回，立刻删掉。

## 5. 文件包含 / 6. 任意文件操作

LFI/RFI、任意读/写/删/下载。默认中危；读到大量 PII 或可写 webshell 则上调高危。禁止删业务数据。

## 7. 权限绕过

水平/垂直越权、认证绕过进后台、改他人资料、代操作。默认中危。能进后台拿大量数据再报高危。

## 8. 逻辑漏洞

支付改价=高危；密码重置未大量泄露=中危；短信轰炸/无限流=低危。后台弱口令=中危，前台弱口令不报。支付/改价只证明参数进逻辑，不要提交落地改价。

## 9. 信息泄露

DB 连接密码/源码备份/云钥匙=中危或高危（大量 PII=高危）；版本/路径/phpinfo、错误页回显内网 IP 不报。SSRF 打到内网敏感面再报（报完切下一类，不当跳板扩网）。

## 10. 后门

预留口令、隐藏管理入口、已知 webshell、调试后门。能进系统或大量数据按高危。

## 11. N-day

已识别产品/版本才查已知 CVE（例如 Kong 0.14.x 管理面、组件版本对应的公开洞）。用 WebSearch 查 CVE/N-day/官方公告，再用 `http_request` 拉公告页，短 canary 验证。没有版本不要对着整站喷 N-day 词表。

## 上报与非破坏验证

- 每个可复现漏洞单独 `report_finding`：标题 + 最小 PoC + 影响；**不要合并**。低/中/高危/严重都进漏洞页。
- 高危/严重必须过平台二次验证（evidence + 真实 poc_curl/poc_python）。未过验证仍进漏洞页，标待验证。
- 一类测完立刻切下一类；一个资产测完切下一个。同类型下一实例也要挖。
- **本资产最多 30 轮**；满 30 轮或满 180 分钟硬停都记失败。
- **已验证洞提危害**：**读面铺开、写面克制**。swagger 读全文档；GET/查询类按类型覆盖未授权与敏感字段，不能停在第一条。写接口只证明权限，禁止落库灌垃圾。
- **禁止内网横向**（不扩网打穿）。本机网卡/物机网关是守卫不是目标；SSRF 只走已验证参数打目标内网，不要 Kali 直连办公网。phpinfo、指纹、前台弱口令不报。
- 词表路径与二进制绝对路径见 skill `kali-kit`。
