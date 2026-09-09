"""监督 AI：读全局简报，产出下一轮方案（无工具、一次性查询）。"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field

from collections.abc import Awaitable, Callable

from ..config import settings
from ..agents.session import _get_spawn_sem, is_retryable_connect_error

SUPERVISOR_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的御主，不是执行层。
每轮从者开打前你先下令；根据简报里的全部信息判断局面，给出本轮可执行任务。

职责
- 只读简报里的攻击图（与控制台图例相同）：目标 / 服务 / 危险点 / 漏洞 / 凭证 / 立足点 / 信息；★GETSHELL 表示已拿到命令执行；RCE 最优路径是橙线；内网横向是紫线（shell→新目标）。再读开放 Intent、否证、flag、局面摘要、「已给过的方案」。不要向执行层要工具流水。
- 「已给过的方案」是你自己每一份方案的完整记录。写第 N 份必须对照第 1…N-1 份：出 C 必须同时看见 A 和 B，不能只看最近一份。违背局面 → 循环收紧禁令，禁止另起同义散文；空转满阈值循环会作废旧绑定并再问你。已执行无收口 → 说明相对前面哪一步改了。不要装作这是第一次开口，也不要把已否证/已忽略的方案换措辞再写一遍。
- 判断：进展是否真实、是否把「一种观测失败」写成「攻击面关闭」、入口是否挂了、是否该武器化/过门/提权/横向/夺旗。
- 给出下一轮可执行方案：当前方案未跑满且有新观测时加深同一面；假钥匙意图、图停滞、已有凭证/活体表面还在入口枚举时必须换方向。
- must_intents / next_plan 是参考假说：循环不会强制从者逐条执行。局面（未消费凭证、未关输入面、已验证洞、跳板/邻题）由循环按攻击图编译，从者必须守。不要把「先打另一个允许 POST 的路由」写成换通道。假说最多 3 条正交，供从者选用。违背局面（入口枚举、离开未关输入面）才会收紧禁令；从者改打正交假说不算违约。空字段由循环按图补全。
- 每轮都开口。简报里本轮认领的 Intent 仍开放 → hold=true 表示继续当前局面（可并行子智能体），禁止另起同义散文或改打目录枚举。
- CTF：唯一目标是正确 flag。题面给出的账号、路径、文件优先于自造字典；交旗优先于把题审完。本题必有解：禁止 rockyou / 超过 10 万行的词表 / hashcat 全库去撞哈希或登录；个位数默认口令失败不要升级字典，回到已验证通道抽数据。RCE / getshell / 橙线高亮都是手段。图上的边权乘积（常见自动补边 0.55）不是夺旗概率，禁止当进度或收工信号。评测 request_hint 会扣分：先打活体；实在卡住（活体、题面路径、一手利用都空转）才允许 next_plan 点名 request_hint；开局禁止。已看过不要再点。平台总分差不是漏旗。
- 红队：最高指令是 GETSHELL（report_shell 即收工）。工作循环是测试→验证→高危/严重 finding→推向命令执行；尚未 GETSHELL 则对下一活体面再来一圈。finding 不单独收工。不要因为已有一条已验证洞就停测其它活体面。CTF 与红队一律禁止超过 10 万行的词表（目录/子域/host/口令/哈希/端口全表）。

决策顺序（必须按简报事实走，禁止写死某题打法）
1. 引用：下一步必须能指到简报中的节点 / Intent / 否证 / 发现。写不出引用就说明没读图。
2. 继续当前方案：方案还没跑满、且本轮有新观测（新节点/边以外的已验证发现或凭证）→ hold=true，加深同一 Intent / 同一输入面（补观测通道）。必须 hold=false：当前方案还是把信息点当钥匙或换凭证（info_to_cred / secret_mount / 枚举进行中 / 爆破失败 / 表单字段清单 / 前端无逻辑）；本轮图不增长且无新观测；已有凭证或活体表面却还在入口 HTTP / 目录枚举 / 登录爆破。已有 ★GETSHELL 而当前方案还在打入口 → 必须 hold=false，转入提权/横向/夺旗。不要因为「尚未否证」就 hold。
3. 通道：同一输入面，状态码 / 正文 / Cookie / 跳转无差异，只否证了这些观测通道，不否证「参数已被后端处理」。恒定延迟、与输入无关的耗时、把节点标成已闭合、同一状态码再采样，都不算通道已做完。换通道 = 同一 URL、同一参数，换观测（耗时/长度/头/副作用）。换 Host/方法但仍以状态码判死，也不算换通道。另一个路由因为允许 POST/JSON，不是换通道，禁止写成主线或「唯一可写面」。未出现耗时差/长度差/其它端点副作用前，禁止结案为「视图未处理输入」，禁止把该面降成其它路线失败后才打。
4. 假穷尽：图上「穷尽 / 闭合 / 全阴 / 已收口」若只覆盖一种通道，把它当未完成。next_plan 主线必须留在该输入面换通道；不要跟着去目录枚举、旁路 IP、会话伪造或认证后的读文件/静态面。
5. 入口：简报里的本题入口地址为准（可有多个 host:port）。邻题入口列表里的 IP/端口不是本题服务，不要 hold 那条链。非 HTTP 交互口优先协议转储与本地建模，不要默认当网站打。已确认的 HTTP JSON/HTML 服务不要把 protocol_model 当主线。HTTP 拦截页换通道，不要结案去枚举目录。403/401 的管理接口是鉴权/过滤，不要写成 file_read_chain。
6. 质量：quality 只是计数差；flag 数为 0 时禁止当夺旗；弱图扩张不是突破。不要被分类绑死。
7. 已否证路径无新证据不要复开。会话 / 工具故障（143、拒绝）不算漏洞失败。
8. 传输层失败不是「换攻击方法」。未验证的高危假设不算已打穿。已有立足点就不要回头刷入口目录。已有 ★GETSHELL 就去提权/横向/夺旗，不要再打入口。
9. 范围：本机网卡和物机网关是守卫，不是目标。邻题入口（同评测其它 unique_code 的入口 IP/端口）禁止当本题主线。本题立足点/已验证 SSRF 看见的容器网 RFC1918 是本题内网，不是邻题——next_plan 必须写 report_pivot_capability 扩容，再经跳板打；SSRF 走载荷，不要 Kali 直连、禁止当邻题换址。从 Kali 扫办公网/入口 /24 邻居不算发现。本题入口端口不通时 rebind_entry=true，不要改打邻题端口。公网文档域名可以访问。CTF/红队/SRC 从者均可 WebSearch：已识别产品/版本时 next_plan 应要求查 CVE/N-day，不要当断网。禁止用 unique_code/题名搜 writeup。
10. 邻题隔离：简报里标了邻题污染的节点，其算法、密钥、flag 候选都不是本题手法。必须从本题入口产物（本题二进制/本题服务）的代码与协议语义求解。当前方案若还在引用邻题地址，hold=false，换回本题产物。
11. 假收口：简报标了假收口 → 否证的是「已经解密出 flag」和已提交的错值，hold=false，不要停猎。next_plan 执行简报里给出的收口手法（若有）；图上标了已否证·假收口的节点不是观测。不要发明题面专用 payload。
12. 收口：图上已有已验证可利用发现（读文件/RCE/注入/跳板/令牌），下一步必须消耗它。进行中、无命令执行的立足点不是 ★GETSHELL。握手、版本探测、可 attach 不等于已经拿到命令执行；一种客户端形态失败不关闭整面。时间差/布尔差已经验证注入 → 先换成回显/联合/报错/状态差分打成控制流或会话，不要把同一耗时通道按位问到底，不要再校准耗时，也不要把库侧文件读原语当默认收口，更不要改去超级大字典撞哈希。前端/JS 字段反复 4xx 或错误正文点名了你没发的键 → 客户端契约过时，换错误正文里的键，禁止对已否证键做编码变体；恒定 4xx 点名缺字段说明通道活着，不要把网关写成存根，也不要从攻击机直连错误正文里的内网地址。过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类。写/反序列化/上传已验证 → 投递执行，不是继续分析 gadget。已持有签名令牌：少数算法或弱密钥变体失败不关闭整类，不要只改前端角色字段。一种证明通道被挡就换抽取面。
12b. 已有可用凭证、尚未立足：下一步必须消费该会话打后认证功能面。下载/附件若是题面下发的可执行文件/固件/字节码，must 格是 reverse_binary，不要写成 file_read_chain。普通文件/路径参数面才是 file_read_chain 或 access_control；403/401 的管理接口不要写成 file_read_chain。不要把这一格让给 html_sink 或回头只打登录表单注入。凭证未消费时 hold=false。未挂载的机器密钥：浅层 404 不关闭密钥，必须在已到达服务上换请求头/Cookie/body/查询参数做有无密钥差分，禁止因此去扫旁路网段。
12c. 正确旗仍为 0：已验证 SSRF 的下一步是消耗跳板与未挂载密钥，不要把「剩余 flag 在别的容器」当主线。占位 stdout（点号/denied/complete）不是诱饵，不等于链已死。本地二进制的开门钥匙（访问码/argv）不是 Web RCE，不要派生 weaponize。
13. 多 flag 未齐且已有 ★GETSHELL/已验证 SSRF：本机已交过的旗不要再挖。入口 webshell/SSRF 是跳板，不要关掉。端口转发/代理映射不等于已经登上邻机。邻机是新身份域：must_intents 三条必须不同 tactic，同一 tactic 只占一格。身份验证与未授权可达并行，一个失败不关闭另一个，也不把「先过门」写成其它面的前置条件。同一身份面没有新秘密、只重复失败 → 该 hop_auth 做完，换其它 tactic。
14. flag 数已齐（正确数 ≥ flag_count）即收工换题。平台总分差是计分/时间衰减，不是还能再交的 flag。

硬约束
- 你没有工具。禁止调用 run_cmd、http_request、Read、Bash 或任何 MCP。只输出 JSON。
- 目标不变：红队以 report_shell 收工；CTF 以正确 flag 数齐收工。不要停题。CTF 不要因为「快 RCE 了」或橙线概率去换路、收工或停猎。
- 禁止破坏性写入；SQLi 只用读证明。
- 不要打本机控制台端口或攻击机网卡 IP。
- 枚举走三圈小/中/大，打过再扩，各面独立升档。第 1 圈（小）只打当前入口：top-100、common.txt。第 2 圈（中）top-1000、中档目录、dnsmap。第 3 圈（大）活体后 -p-；目录不再升词表（禁止 dirbuster medium），改为递归/扩展名/备份/nikto。简报「已覆盖」已跑过的扫描禁止再点名。禁止开局 -p- 或超 10 万行词表。
- must_intents 最多 3 条，必须是不同 tactic、指向不同图节点的正交假说，供从者选用；循环只把它们排到前沿最前，不独占认领。看似一份方案，其实是多条路线。至少一条必须能否证当前主叙事（同一输入面换观测通道 vs 换门/换词表），禁止三条都建立在「该面已闭合」上，禁止把竞争假说写成「仅当其它路线无果」。禁止三条同义复述，禁止把目录枚举+登录爆破+全端口当三条路线。未验证且图上有 web_inject / input_abuse / access_control / file_read_chain 开放：must 至少一格是打洞（注入/越权/文件读均算），subagents 必须含 web-exploit，与 recon 并行。已有可用凭证且图上有文件/路径参数面：must 至少一格是 file_read_chain 或 access_control；题面下发的可执行文件/固件则改占 reverse_binary，不要被 html_sink 或登录表单注入挤掉。禁止三格都是 fingerprint / protocol_model / content_enum。静态 SPA、同源 API=0、JS 外域名单都不是「没有攻击面」：同入口参数/鉴权/路由仍要测→证。已验证可利用发现后：must 至少一格消耗该洞推向 GETSHELL；其余格打其它尚未验证的活体面，继续测→证→高危/严重。禁止三格都回头做目录枚举/指纹，不要把整个猎收成只打一条走廊。
- 简报若有「战术族」计数或「可迁移战术」族名：must 必须覆盖不同族；身份验证（hop_auth）与未授权可达（access_control）同时占格，不要用三格全写 hop_auth。
- 已验证读/包含/注入但尚未 GETSHELL：must 至少一格是利用下一跳（weaponize / impact_escalate / finding_rce_close / finding_sqli_chain），禁止三格都是同一读面加深（file_read_chain / finding_read_loot / filter_bypass）。其余格可打其它活体面继续验证高危/严重。禁止把利用族整族写入 defer_families。禁止把 channel_oracle / api_contract / fingerprint / content_enum 当收口。hold=false。

只输出一个 JSON 对象，不要 markdown 围栏外的解释。字段：
{
  "diagnosis": "一句话局面判断（须引用简报事实）",
  "stall": "none|infra|method|chain|postex",
  "hold": false,
  "rebind_entry": false,
  "next_plan": "参考假说（可执行步骤，指向图上的点；循环不强制逐条执行）",
  "must_intents": ["建议 Intent 的 id，最多 3 个，tactic 必须互异；循环只排序不独占"],
  "prefer_tactics": ["strategy_key 末段战术名，如 weaponize、finding_sqli_chain"],
  "defer_families": ["本轮应避开的策略族，如 content_enum"],
  "ban_repeats": ["不要再打的路径或命令头"],
  "subagents": ["recon|web-exploit|protocol-model|rce-hunt|privesc|lateral|flag-hunt"]
}
stall 取值：none 仍有清晰下一步；infra 入口传输层不可达；method 方法空转需换思路；chain 已有资产应打利用下一跳；postex 有 shell 应提权/横向。
hold=true：继续当前局面（可把步骤写细、并行加深），循环侧不会换成同义新散文。假钥匙、图停滞、已登录还在入口枚举时禁止 hold=true。
rebind_entry 仅在入口地址失效、需要循环侧重绑时为 true。
must_intents 只能引用简报里出现过的 Intent id。
prefer_tactics 优先选简报里已有、尚未做完的战术，不要发明题面专用 payload。
"""

_ENUM_SHARED = (
    "- 枚举走三圈小/中/大，打过再扩，各面独立升档。"
    "第 1 圈（小）只打当前入口：top-100、common.txt。"
    "第 2 圈（中）top-1000、中档目录、dnsmap。"
    "第 3 圈（大）活体后 -p-；目录不再升词表（禁止 dirbuster medium），改为递归/扩展名/备份/nikto。"
    "简报「已覆盖」已跑过的扫描禁止再点名。禁止开局 -p- 或超 10 万行词表。"
)
_ENUM_CTF = (
    "- CTF 不走螺旋升圈。唯一目标是尽快交正确 flag。"
    "先看本题入口活体（源码/注释/robots/题面路径/账号），像 flag 立刻交；立刻 web-exploit 打题面功能，不要先扫完再看。"
    "题面已给出变换/编码/协议/文件时写脚本或直接打，不要把 nmap/ffuf 当下一步。"
    "next_plan / must_intents 开局禁止把 nmap、top-ports、ffuf、common.txt、directory-list、fingerprint、content_enum、request_hint 当主线或占满三格。"
    "三格 must 应是题面利用假说。没有旗才允许一格后台 recon：跳过 small，top-1000 / 中档目录为止，不得挡交旗。"
    "实在卡住才允许 next_plan 点名 request_hint（每次扣分）；不要开局看提示。"
    "评测邻题始终越界。简报「已覆盖」已跑过的扫描不要再点名。禁止开局 -p- 或超 10 万行的表。"
)
_ENUM_REDTEAM = (
    "- 红队螺旋三圈小/中/大。连续 6 个御主方案无高质量增长（已验证洞/凭证/立足点/能力边）才进入下一圈；有增长则留在当前圈。"
    "进入该圈必须做该圈完整清单，不要因为小圈做过就省略。"
    "第 1 圈（小）只打当前入口：top-100、common.txt，旁站关；禁止抢跑 top-1000、-p-、中档目录、旁站当攻击面。"
    "HTTP 活体：must 至少一格 web_inject（或 input_abuse/access_control），subagents 必须含 web-exploit，与第 1 圈 recon 同一回合并行。"
    "禁止三格都是 fingerprint / protocol_model / content_enum。静态 SPA / 同源 API=0 不是没有攻击面。"
    "第 2 圈（中）top-1000、中档目录、dnsmap、旁站（同 IP vhost / 兄弟域，每个旁站自己从第 1 圈开）。"
    "第 3 圈（大）活体后 -p-；目录不再升词表（禁止 dirbuster medium），改为递归/扩展名/备份/nikto。"
    "禁止开局 -p- 或超 10 万行词表。"
)


_RT_GOAL_LINE = (
    "- 红队：最高指令是 GETSHELL（report_shell 即收工）。工作循环是测试→验证→高危/严重 finding→推向命令执行；尚未 GETSHELL 则对下一活体面再来一圈。finding 不单独收工。不要因为已有一条已验证洞就停测其它活体面。CTF 与红队一律禁止超过 10 万行的词表（目录/子域/host/口令/哈希/端口全表）。"
)
_SRC_GOAL_LINE = (
    "- SRC：最高指令是发现尽可能多的独立漏洞（report_finding，低/中/高危/严重都进漏洞页）。厂商 11 类是菜单：按入口形态选该测的类型，不要每轮全开。"
    "有 HTML 才 XSS，有参数才 SQLi，有版本才 N-day（WebSearch 查 CVE）；没有对应面不要硬派 Task。不要停在第一条，不要为拿 shell 停工。"
    "已验证洞提危害后换仍有面、还没测的类型。禁止 GETSHELL/横向/夺旗收工。禁止超过 10 万行词表。"
)
_RT_TARGET_LINE = (
    "- 目标不变：红队以 report_shell 收工；CTF 以正确 flag 数齐收工。不要停题。CTF 不要因为「快 RCE 了」或橙线概率去换路、收工或停猎。"
)
_SRC_TARGET_LINE = (
    "- 目标不变：SRC 以尽可能多的独立高危/严重 report_finding 为目标，不以 report_shell / 夺旗收工。不要停在第一条。"
)
_RT_BIND_CLOSE = (
    "已验证可利用发现后：must 至少一格消耗该洞推向 GETSHELL；其余格打其它尚未验证的活体面，继续测→证→高危/严重。禁止三格都回头做目录枚举/指纹，不要把整个猎收成只打一条走廊。"
)
_SRC_BIND_CLOSE = (
    "已验证洞不收工：must 至多一格提危害（impact_escalate），其余格换简报里「建议测」且还没覆盖的类型，独立 report_finding。"
    "禁止为凑类型去打简报标明暂缓的面。禁止三格都打穿同一条利用链。禁止 lateral / privesc / report_shell 收工。"
)
_RT_CHAIN_MUST = (
    "- 已验证读/包含/注入但尚未 GETSHELL：must 至少一格是利用下一跳（weaponize / impact_escalate / finding_rce_close / finding_sqli_chain），禁止三格都是同一读面加深（file_read_chain / finding_read_loot / filter_bypass）。其余格可打其它活体面继续验证高危/严重。禁止把利用族整族写入 defer_families。禁止把 channel_oracle / api_contract / fingerprint / content_enum 当收口。hold=false。"
)
_SRC_CHAIN_MUST = (
    "- 已验证读/包含/注入：至多一格提危害打到高危标准，其余格换仍有入口形态、还没测的类型并独立 report_finding。"
    "不要把暂缓类型硬塞进 must。禁止三格都加深同一条洞，禁止横向/GETSHELL 收工。hold=false。"
)

_ENUM_SRC = (
    "- SRC 不走螺旋升圈、不夺旗、不 getshell 收工。"
    "目的是发现尽可能多的独立漏洞，不是一条利用链打穿。"
    "厂商类型菜单：XSS、SQL注入、命令执行、代码执行、文件包含、任意文件、越权、逻辑、高危泄露、后门、N-day。"
    "简报会给出本轮建议测/暂缓。must 只钉有对应面的类型，不要 11 路全开。"
    "只报已验证条目；低/中/高危/严重都进漏洞页。已验证洞必须按真实危害评级，不要停在第一条。"
    "HTTP 活体：must 至少一格是建议测里的打洞（web_inject/越权/逻辑/N-day 等），subagents 必须含 web-exploit 与 src-hunt，与 recon 并行。"
    "禁止三格都是 fingerprint / protocol_model / content_enum。静态 SPA 不是没有攻击面。"
    "next_plan / must_intents 禁止横向、提权、report_flag、把本站当跳板打 RFC1918。"
    "禁止开局 -p- 或超 10 万行词表。"
)


def supervisor_system_prompt(objective: str | None = None) -> str:
    from ..objective import objective_allows_flag, objective_is_src
    if objective_allows_flag(objective):
        extra = _ENUM_CTF
    elif objective_is_src(objective):
        extra = _ENUM_SRC
        text = SUPERVISOR_SYSTEM.replace(_ENUM_SHARED, extra)
        return (
            text.replace(_RT_GOAL_LINE, _SRC_GOAL_LINE)
            .replace(_RT_TARGET_LINE, _SRC_TARGET_LINE)
            .replace(_RT_BIND_CLOSE, _SRC_BIND_CLOSE)
            .replace(_RT_CHAIN_MUST, _SRC_CHAIN_MUST)
        )
    else:
        extra = _ENUM_REDTEAM
    return SUPERVISOR_SYSTEM.replace(_ENUM_SHARED, extra)

SUPERVISOR_RUNTIME_SYSTEM = """你是 StrikeAgent_AtkBrain-Flash 的御主，不是执行层。
本轮是运行时审查：CTF 单题已跑过一段时间，由你判断这一猎是否还值得继续。不要写某题 payload。循环不会按轮次硬停，停或续跑只看你的 continue。

必须输出 continue。
continue=false：暂停本猎（idle，不算失败），可人工复盘后再次启动。思路已穷尽，或剩余时限内不可能收口。入口暂时不通不算穷尽。
continue=true：继续打。可附 1～3 条下一步；当前验证还没结束时循环侧会丢掉 next_plan，只裁 continue。
假收口、连续错旗：不是穷尽，continue=true。
flag 数已齐必须 continue=false。
有指向图上节点的清晰下一步则 continue=true。

只输出一个 JSON 对象：
{
  "continue": true,
  "diagnosis": "一句话局面判断（须引用简报事实）",
  "next_plan": "若继续：给从者的下一步（可空，最多三条）"
}
"""

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_JSON_OBJ_RE = re.compile(r"\{[\s\S]*\}")
_STALL_OK = frozenset({"none", "infra", "method", "chain", "postex"})
_UNSTRUCTURED_DIAG = "监督输出未结构化，按全文执行"


def _escape_raw_controls_in_strings(s: str) -> str:
    """把 JSON 字符串字面量里未转义的换行/控制符修成合法转义。"""
    out: list[str] = []
    in_str = False
    escape = False
    for c in s:
        if not in_str:
            if c == '"':
                in_str = True
            out.append(c)
            continue
        if escape:
            out.append(c)
            escape = False
            continue
        if c == "\\":
            out.append(c)
            escape = True
            continue
        if c == '"':
            in_str = False
            out.append(c)
            continue
        if c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif c == "\t":
            out.append("\\t")
        elif ord(c) < 32:
            out.append(f"\\u{ord(c):04x}")
        else:
            out.append(c)
    return "".join(out)


def _loads_json_obj(blob: str) -> dict | None:
    text = (blob or "").strip()
    if not text:
        return None
    if not text.startswith("{"):
        i = text.find("{")
        if i < 0:
            return None
        text = text[i:]
    for candidate in (text, _escape_raw_controls_in_strings(text)):
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        try:
            data, _ = json.JSONDecoder().raw_decode(candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return None


def _as_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v or "").strip().lower()
    return s in ("1", "true", "yes", "y", "hold", "continue")


@dataclass
class SupervisorPlan:
    diagnosis: str = ""
    stall: str = "none"
    hold: bool = False
    rebind_entry: bool = False
    next_plan: str = ""
    must_intents: list[str] = field(default_factory=list)
    prefer_tactics: list[str] = field(default_factory=list)
    defer_families: list[str] = field(default_factory=list)
    ban_repeats: list[str] = field(default_factory=list)
    subagents: list[str] = field(default_factory=list)
    raw_text: str = ""


def _as_str_list(v, *, limit: int = 8) -> list[str]:
    if isinstance(v, str) and v.strip():
        v = [v]
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        s = str(x or "").strip()
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


_FAKE_KEY_PLAN_RE = re.compile(
    r"info_to_cred|secret_mount|当开门钥匙|验证为可用凭证并尝试登录|"
    r"枚举进行中|爆破失败|强随机|无业务逻辑|零业务逻辑|表单结构|模板\s*UI",
    re.I,
)
_ENTRY_ENUM_PLAN_RE = re.compile(
    r"content_enum|目录爆破|目录枚举|登录爆破|auth_surface|fingerprint",
    re.I,
)
_STALL_QUALITY = frozenset({"none", "weak_graph"})


def plan_is_fake_key_loop(plan_text: str) -> bool:
    """方案还在把非资产信息点当钥匙/换凭证。"""
    return bool(_FAKE_KEY_PLAN_RE.search(plan_text or ""))


def plan_is_entry_enum(plan_text: str) -> bool:
    """方案还停在入口枚举/目录爆破/登录爆破。"""
    return bool(_ENTRY_ENUM_PLAN_RE.search(plan_text or ""))


def graph_has_login_or_surface(graph: dict | None) -> bool:
    """图上已有凭证节点或活体 HTTP 表面。"""
    if not graph:
        return False
    for n in graph.get("nodes") or []:
        if isinstance(n, dict) and str(n.get("type") or "").lower() == "credential":
            return True
    try:
        from ..graph.hypothesize import surfaces_from_graph_nodes
        if surfaces_from_graph_nodes(graph):
            return True
    except Exception:
        pass
    return False


def refine_supervisor_plan(
    plan: SupervisorPlan,
    *,
    graph: dict | None = None,
    no_progress: int = 0,
    quality: str = "none",
    extra_plan_text: str = "",
) -> SupervisorPlan:
    """确定性抬 hold：假钥匙、图停滞、已登录还在入口枚举。不依赖模型自觉。"""
    blob = f"{plan.next_plan or ''} {plan.diagnosis or ''} {extra_plan_text or ''}"
    fake = plan_is_fake_key_loop(blob)
    try:
        stalled_n = int(no_progress or 0)
    except (TypeError, ValueError):
        stalled_n = 0
    stalled = stalled_n >= 2 and (quality or "none") in _STALL_QUALITY
    entry_vs_asset = plan_is_entry_enum(blob) and graph_has_login_or_surface(graph)
    if fake or stalled or entry_vs_asset:
        plan.hold = False
        if plan.stall == "none":
            plan.stall = "method"
    try:
        from ..graph.hypothesize import needs_channel_oracle as _needs_oracle
        oracle = bool(_needs_oracle(graph))
    except Exception:
        oracle = False
    if oracle:
        plan.hold = False
        if plan.stall == "chain":
            plan.stall = "method"
        plan.defer_families = [
            t for t in (plan.defer_families or []) if t != "channel_oracle"
        ]
        from .advisor_bind import (
            ORACLE_DIAG, ORACLE_KEEP, strip_premature_timing_bans,
            surface_false_close,
        )
        plan.ban_repeats = strip_premature_timing_bans(plan.ban_repeats)
        blob_plan = f"{plan.next_plan or ''} {plan.diagnosis or ''}"
        if surface_false_close(blob_plan):
            plan.next_plan = ORACLE_KEEP
            plan.diagnosis = ORACLE_DIAG
    return plan


def parse_supervisor_plan(text: str) -> SupervisorPlan:
    """从模型输出里抽出 JSON 方案；解析失败则把全文当 next_plan。"""
    raw = (text or "").strip()
    plan = SupervisorPlan(raw_text=raw)
    blob = ""
    m = _JSON_FENCE_RE.search(raw)
    if m:
        blob = m.group(1)
    else:
        m = _JSON_OBJ_RE.search(raw)
        if m:
            blob = m.group(0)
    data = _loads_json_obj(blob) if blob else None
    if data is None and "{" in raw:
        data = _loads_json_obj(raw[raw.find("{"):])
    if not isinstance(data, dict):
        plan.next_plan = raw
        plan.diagnosis = _UNSTRUCTURED_DIAG
        return plan
    plan.diagnosis = str(data.get("diagnosis") or "").strip()
    stall = str(data.get("stall") or "none").strip().lower()
    plan.stall = stall if stall in _STALL_OK else "none"
    plan.hold = _as_bool(data.get("hold"))
    plan.rebind_entry = bool(data.get("rebind_entry"))
    plan.next_plan = str(data.get("next_plan") or data.get("plan") or "").strip() or raw
    plan.must_intents = _as_str_list(data.get("must_intents"), limit=3)
    plan.prefer_tactics = _as_str_list(data.get("prefer_tactics"), limit=8)
    plan.defer_families = _as_str_list(data.get("defer_families"), limit=6)
    plan.ban_repeats = _as_str_list(data.get("ban_repeats"), limit=12)
    plan.subagents = _as_str_list(data.get("subagents"), limit=4)
    return plan


def format_ai_steer(plan: SupervisorPlan, *, pivots: int, extra_guide: str = "") -> str:
    lines = [f"【御主 · 局面备忘 + 参考假说 · 方案 #{pivots}】"]
    if plan.diagnosis:
        lines.append("判断：" + plan.diagnosis)
    if plan.next_plan:
        lines.append(plan.next_plan.strip())
    lines.append("局面由循环按图编译，必须守住；下面方案是参考假说，可打可丢。真人指令仍覆盖假说。")
    if extra_guide.strip():
        lines.append(extra_guide.strip())
    if plan.must_intents:
        lines.append("建议 Intent：" + "、".join(f"`{x}`" for x in plan.must_intents))
    if plan.subagents:
        lines.append("建议委派：" + "、".join(f"`{x}`" for x in plan.subagents))
    if plan.prefer_tactics:
        lines.append("建议战术：" + "、".join(f"`{x}`" for x in plan.prefer_tactics))
    if plan.ban_repeats:
        lines.append("禁止重复：" + "、".join(f"`{x}`" for x in plan.ban_repeats[:8]))
    if plan.defer_families:
        lines.append("禁止策略族：" + "、".join(f"`{x}`" for x in plan.defer_families))
    return "\n".join(lines)


def parse_runtime_review(raw: str) -> dict:
    """御主运行时审查：解析失败默认续跑，避免误停。"""
    text = (raw or "").strip()
    data = None
    if text:
        m = _JSON_FENCE_RE.search(text)
        blob = m.group(1) if m else None
        if not blob:
            m2 = _JSON_OBJ_RE.search(text)
            blob = m2.group(0) if m2 else None
        data = _loads_json_obj(blob or text)
    if not isinstance(data, dict):
        return {"continue": True, "diagnosis": "", "next_plan": ""}
    cont = data.get("continue")
    if isinstance(cont, str):
        cont = cont.strip().lower() not in ("0", "false", "no", "n", "stop", "halt", "暂停")
    elif cont is None:
        cont = True
    else:
        cont = bool(cont)
    return {
        "continue": cont,
        "diagnosis": str(data.get("diagnosis") or "").strip(),
        "next_plan": str(data.get("next_plan") or data.get("plan") or "").strip(),
    }


def plan_is_usable(plan: SupervisorPlan | None) -> bool:
    """有判断、方案或 hold 即视为顾问开口成功。"""
    if plan is None:
        return False
    return bool((plan.next_plan or "").strip() or (plan.diagnosis or "").strip() or plan.hold)


_ADVISOR_CWD: str | None = None
_BUILTIN_BLOCK = (
    "Bash", "BashOutput", "KillBash", "WebFetch", "Read", "Write", "Edit",
    "Grep", "Glob", "WebSearch", "TodoWrite", "Task", "NotebookEdit",
    "Skill", "SlashCommand",
)


def _advisor_cwd() -> str:
    """空目录：不读 data_dir 里的 CLAUDE.md / .mcp.json。"""
    global _ADVISOR_CWD
    if not _ADVISOR_CWD:
        import tempfile
        _ADVISOR_CWD = tempfile.mkdtemp(prefix="atkbrain-advisor-")
    return _ADVISOR_CWD


def _supervisor_disallowed_tools() -> list[str]:
    from ..agents.tools import tool_names
    return list(_BUILTIN_BLOCK) + list(tool_names(None))


async def _on_supervisor_pre_tool_use(_input, _tool_use_id, _hook_context) -> dict:
    return {
        "continue_": True,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "御主禁止工具，只输出 JSON",
        },
    }


_ONESHOT_CONFIG_ERR = "御主会话配置错误：一次性提问不能挂 can_use_tool，本轮不重试。"


def is_oneshot_prompt_config_error(exc: BaseException | str) -> bool:
    """SDK：can_use_tool 只能配流式 prompt；顾问用字符串一次性提问。"""
    msg = str(exc or "")
    return (
        "can_use_tool callback requires streaming" in msg
        or "一次性提问不能挂 can_use_tool" in msg
    )


def _assert_oneshot_query_options(opts) -> None:
    """顾问 / 一次性 query(字符串) 禁止 can_use_tool，否则 SDK 根本不会去问模型。"""
    if getattr(opts, "can_use_tool", None):
        raise RuntimeError(_ONESHOT_CONFIG_ERR)


def supervisor_query_options(*, system_prompt: str | None = None):
    """顾问会话：无 MCP、无内置工具、不读用户/项目配置。

    不能设 can_use_tool：SDK 会要求 prompt 改成 AsyncIterable，一次性 query(字符串) 会立刻失败。
    """
    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher

    model = (getattr(settings, "supervisor_model", None) or "").strip() or settings.claude_model
    opts = ClaudeAgentOptions(
        tools=[],
        allowed_tools=[],
        disallowed_tools=_supervisor_disallowed_tools(),
        mcp_servers={},
        strict_mcp_config=True,
        plugins=[],
        skills=[],
        can_use_tool=None,
        hooks={"PreToolUse": [HookMatcher(hooks=[_on_supervisor_pre_tool_use])]},
        system_prompt=system_prompt or SUPERVISOR_SYSTEM,
        model=model,
        fallback_model=settings.claude_fallback_model,
        max_turns=1,
        permission_mode="plan",
        setting_sources=[],
        cwd=_advisor_cwd(),
        max_buffer_size=8 * 1024 * 1024,
        load_timeout_ms=30_000,
    )
    _assert_oneshot_query_options(opts)
    return opts


async def _query_text_guarded(prompt: str, opts, timeout: float, *, abandon_sec: float = 3.0) -> str:
    """消费 query()；超时用 wait+cancel，不因子协程吞掉 CancelledError 而假死。"""
    from claude_agent_sdk import AssistantMessage, TextBlock, query

    _assert_oneshot_query_options(opts)
    texts: list[str] = []

    async def _run() -> None:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for b in getattr(msg, "content", []) or []:
                    if isinstance(b, TextBlock) and (b.text or "").strip():
                        texts.append(b.text)

    task = asyncio.create_task(_run())
    done, _ = await asyncio.wait({task}, timeout=max(0.05, float(timeout)))
    if task in done:
        task.result()
        return "\n".join(texts).strip()
    task.cancel()
    await asyncio.wait({task}, timeout=max(0.05, float(abandon_sec)))
    raise TimeoutError(f"超过 {timeout:.0f}s 未返回")


async def consult_supervisor(
    brief: str, *, timeout: float | None = None, system_prompt: str | None = None,
) -> SupervisorPlan:
    """一次性、无工具的 Claude Code 查询。拉起 CLI 与从者共用 spawn 闸。

    initialize / 空回复按从者同一套握手重试；单次生成超时抛给外层用原简报再问。
    """
    wait = float(timeout if timeout is not None else getattr(settings, "supervisor_timeout_sec", 360) or 360)
    opts = supervisor_query_options(system_prompt=system_prompt)
    retries = max(1, int(getattr(settings, "claude_connect_retries", 4) or 4))
    last_exc: BaseException | None = None
    for attempt in range(1, retries + 1):
        try:
            async with _get_spawn_sem():
                blob = await _query_text_guarded(brief, opts, max(0.05, wait))
            if blob:
                return parse_supervisor_plan(blob)
            last_exc = TimeoutError("supervisor_empty_reply")
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            raise
        except asyncio.TimeoutError as e:
            raise TimeoutError(f"超过 {wait:.0f}s 未返回") from e
        except Exception as e:
            if is_oneshot_prompt_config_error(e):
                raise RuntimeError(_ONESHOT_CONFIG_ERR) from e
            last_exc = e
            if not is_retryable_connect_error(e) or attempt >= retries:
                raise
            await asyncio.sleep(min(12.0, 1.5 * attempt))
            continue
        if attempt >= retries:
            break
        await asyncio.sleep(min(12.0, 1.5 * attempt))
    raise last_exc or TimeoutError("supervisor_empty_reply")


async def await_supervisor_plan(
    brief: str,
    *,
    timeout: float | None = None,
    on_wait: Callable[[int, str, float], Awaitable[None]] | None = None,
    consult: Callable[..., Awaitable[SupervisorPlan]] | None = None,
) -> SupervisorPlan:
    """问 Claude Code 给出可用方案。总墙钟内原简报再问，不压短。

    御主是 Claude Code 一次性会话。timeout 是拉起 CLI + 生成 + 重试的总等待，
    到点必须失败，从者按自己的思路继续。supervisor_consult_max_attempts=0
    时只受总墙钟约束。CancelledError 立即中断。
    """
    import time as _time

    ask = consult or consult_supervisor
    total = float(timeout if timeout is not None else getattr(settings, "supervisor_timeout_sec", 360) or 360)
    max_attempts = int(getattr(settings, "supervisor_consult_max_attempts", 0) or 0)
    base = float(getattr(settings, "supervisor_consult_retry_base_sec", 4.0) or 0)
    current = brief
    attempt = 0
    last_err = "监督未返回"
    deadline = _time.monotonic() + max(0.0, total)

    while True:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"{last_err}（简报 {len(current)} 字）。已达 {total:.0f}s 总等待。"
            )
        attempt += 1
        try:
            plan = await ask(current, timeout=remaining)
            if plan_is_usable(plan):
                return plan
            last_err = "监督返回空方案"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if is_oneshot_prompt_config_error(e):
                raise RuntimeError(_ONESHOT_CONFIG_ERR) from e
            last_err = (str(e) or type(e).__name__).strip()
        if max_attempts > 0 and attempt >= max_attempts:
            raise TimeoutError(
                f"{last_err}（简报 {len(current)} 字）。已达重试上限。"
            )
        delay = 0.0 if base <= 0 else min(30.0, base * attempt)
        if _time.monotonic() + delay >= deadline:
            raise TimeoutError(
                f"{last_err}（简报 {len(current)} 字）。已达 {total:.0f}s 总等待。"
            )
        if on_wait is not None:
            await on_wait(attempt, last_err, delay)
        if delay > 0:
            await asyncio.sleep(delay)


async def consult_runtime_review(brief: str, *, timeout: float | None = None) -> dict:
    """CTF 御主运行时审查。失败/空输出默认续跑。"""
    try:
        plan = await consult_supervisor(
            brief, timeout=timeout, system_prompt=SUPERVISOR_RUNTIME_SYSTEM,
        )
        return parse_runtime_review(plan.raw_text or "")
    except Exception:
        return {"continue": True, "diagnosis": "", "next_plan": ""}
