---
name: waf-bypass-methodology
description: >
  WAF / 403 / 406 payload bypass methodology (encoding, chunked,
  method switch, HPP, mutation, origin IP in-scope). Call when an
  exploit payload is blocked (403/406/intercept page), not to start
  recon. Path-level 401/403 still uses kali-kit bypass-403 first.
  Shared by CTF, red team, and SRC. Nested workers forbidden.
---

# WAF 绕过统一方法论

改编自 [wgpsec/AboutSecurity waf-bypass-methodology](https://github.com/wgpsec/AboutSecurity/blob/master/skills/exploit/web-method/waf-bypass-methodology/SKILL.md)。

Pi 用内置 `read` 加载本文件；需要细则再 `read` `references/`。之后作业只用 `http_request` / `run_cmd`。禁止再开子进程。

**何时用：** 已确认攻击面，payload 被拦（403/406/拦截页/特征头），不是开局扫描。
**路径 401/403（目录/文件被拒）：** 先走 skill `kali-kit` 的 `bypass-403.sh`。本 skill 管 **利用载荷** 被 WAF 拦。
**识别 WAF：** skill `kali-kit` 的 `/usr/bin/wafw00f`。
**范围：** 源站 IP / 旁站须已在本项目 Scope。禁止免费代理池、禁止打码平台、禁止对生产做慢速洪水。SRC 禁止破坏业务；SQLi 只用 SELECT/布尔/报错。

核心：WAF 和后端对同一 HTTP 请求解析不一致——让 WAF 看见「合法」，后端看见恶意 payload。

## 深入参考

- 编码绕过 → [references/encoding-bypass-payloads.md](references/encoding-bypass-payloads.md)
- HTTP 协议层（分块/Content-Type/方法/HTTP2/走私） → [references/http-protocol-bypass.md](references/http-protocol-bypass.md)
- 参数层（HPP/数组/Multipart） → [references/parameter-bypass.md](references/parameter-bypass.md)
- Payload 变形 → [references/payload-mutation.md](references/payload-mutation.md)

---

## Phase 0: WAF 识别

### 0.1 检测是否有 WAF

对照正常请求与明显恶意请求（`http_request`，不要内置 bash）：

- `/?id=1' OR '1'='1`
- `/?id=<script>alert(1)</script>`
- `/?cmd=;id`

拦截特征：403/406、专用拦截页、Server / 特征头与正常请求不同。

### 0.2 指纹

| 特征 | WAF |
|------|-----|
| `Server: cloudflare` / `cf-ray` | Cloudflare |
| `X-Sucuri-ID` | Sucuri |
| 响应含 `ModSecurity` | ModSecurity |
| 响应含 `安全狗` / `safedog` | 安全狗 |
| 响应含 `宝塔` / `bt.cn` | 宝塔 |
| `X-Powered-By-Anquanbao` | 安百 |
| 响应含 `yunsuo` | 云锁 |
| 阿里云 403 页 | 云盾 |
| 腾讯云特定 403 | 腾讯云 WAF |
| `X-Cache: NS`、网宿拦截页 | 网宿 |
| ASM 拦截页 | F5 BIG-IP ASM |

## 通用绕过检查流程

```
Payload 被拦截 → 403/拦截页
├── 1. 编码绕过
│   ├── 双重 URL 编码
│   ├── Unicode 编码
│   └── 混合大小写 + NULL 字节
├── 2. HTTP 层
│   ├── 分块传输（curl 原始报文 / run_cmd）
│   ├── Content-Type 切换
│   ├── HTTP 方法切换
│   └── HTTP/2
├── 3. 参数层
│   ├── 参数污染 (HPP)
│   ├── 数组/JSON 嵌套
│   └── Multipart 包裹
├── 4. Payload 变形
│   ├── 空格替代（注释/Tab/换行）
│   ├── 函数名替代
│   ├── 拼接/编码函数
│   └── 通配符/变量
└── 5. 逻辑层
    ├── 分多次请求（先探测再利用）
    ├── 白名单路径 + 路径穿越
    └── 源站 IP 直连（须已在 Scope；Host 仍用原域名）
```

每个分支的详细 payload 见对应 `references/`。换通道后仍要证明后端处理了参数，不要只看状态码。

## Phase 5: 国产/商业 WAF

| WAF | 指纹 | 绕过思路 |
|-----|------|---------|
| F5 BIG-IP ASM | ASM 拦截页 | 编码混淆、分块、方法切换 |
| 网宿 | `X-Cache: NS` | 参数污染、大小写、Unicode |
| UEWAF | 拦截页 / JS 挑战 | 源站 IP（Scope 内）、绕过 JS 校验 |
| Cloudflare | `cf-ray` | 源站 IP（Scope 内）、编码 |
| 安全狗/宝塔 | 页面特征 | 注释符、等价函数、编码 |

## Phase 6: 验证码 / 风控

1. **逻辑：** 复用 code、置空、删参数、同会话不刷新
2. **识别：** skill `kali-kit` 的 `/usr/bin/tesseract`；不要打码平台
3. **换触发点：** 换接口/换参数，绕过验证码门

## Phase 7: 出口被封

不要免费代理轮换。本机出口就是 Kali。可试：降频、换 `http_request` Header、换已在 Scope 的源站 IP（Host 仍用原域名）、换协议 http/https。禁止对生产做慢速洪水。

## Phase 8: SQL 注入绕过（F5/网宿）

- 注释：`-- ` → `#` → `/*!*/` → `;%00`
- 关键字：大小写、内联注释 `/*!union*/`、等价函数
- 编码：双重 URL、Unicode、hex
- 分块 + HPP 组合

SRC：只用 SELECT/布尔/报错证明，禁止 `--os-shell` / 写业务表。
