"""系统提示、每轮指令、角色工人：攻击图工作记忆 + Pi 自循环。"""
from __future__ import annotations

from ..graph.rating_rubric import RATING_RUBRIC
from ..objective import SRC_POLICY_BRIEF, normalize_objective, objective_allows_flag, objective_is_src
from ..scope import Scope
from .kali_kit import KIT_SKILL_HINT
from .tools import tool_names


def _spiral_recon_block(*, ctf: bool) -> str:
    ring1 = "邻题关、旁站关。" if ctf else "旁站关。"
    mid = (
        "CTF 评测邻题始终越界。第 2 圈只加深本题入口（本题其它端口/本题 vhost），不要扫旁站。"
        if ctf else
        "第 2 圈（中）必须做满：top-1000、中档目录、dnsmap、旁站（同 IP vhost / 兄弟域）。每个旁站自己从第 1 圈开。"
    )
    if ctf:
        return (
            "- 开局资产收集：读 skill `recon-spiral`。三圈小/中/大，打过再扩，各面独立升档。"
            f"第 1 圈（小）：当前入口、`--top-ports 100`、`common.txt`，{ring1}"
            "打过或空转再升第 2 圈（中）：top-1000、中档目录、dnsmap。"
            f"{mid}"
            "第 3 圈（大）：活体后 `-p-`；目录不再升词表（禁止 dirbuster medium），改为命中目录递归、扩展名/备份、nikto。"
            "看简报「已覆盖」，相同扫描签名不要再跑。并行派出多个 `recon` 角色会话，每个只做一面；工人禁止再开子进程。"
        )
    return (
        "- 开局资产收集：读 skill `recon-spiral`。三圈小/中/大。简报允许圈才升圈："
        "连续 6 个御主方案无高质量增长（洞/凭证/立足/能力边）才进下一圈；有增长则留在当前圈。"
        f"第 1 圈（小）：当前入口、`--top-ports 100`、`common.txt`，{ring1}"
        "禁止抢跑 top-1000、-p-、中档目录、旁站。"
        f"{mid}"
        "第 3 圈（大）：活体后 `-p-`；目录不再升词表（禁止 dirbuster medium），改为命中目录递归、扩展名/备份、nikto。"
        "进入该圈按该圈完整清单做，不要因为小圈做过就省略。"
            "并行派出多个 `recon` 角色会话，每个只做一面；工人禁止再开子进程。"
        )


def _spiral_enum_block(*, ctf: bool) -> str:
    if ctf:
        return (
            "- 螺旋三圈小/中/大：打过再扩，不是找全再扩。各面独立升档。"
            "CTF 邻题始终越界；第 2 圈只加深本题。"
            "第 3 圈目录不是更大词表。看简报「已覆盖」，相同扫描签名不要再跑。"
        )
    return (
        "- 螺旋三圈小/中/大：连续 6 个御主方案无高质量增长才升圈，不是找全再扩。"
        "进入该圈必须做满该圈清单，不要因为小圈做过就省略。"
        "第 1 圈禁止中档目录、top-1000、-p-、旁站；中档之后才允许同 IP vhost / 兄弟域。"
        "第 3 圈目录不是更大词表。"
    )


def _src_recon_block() -> str:
    return (
        "- 开局：读 skill `src-hunt-playbook`。厂商 11 类是菜单：按入口形态选该测的洞，低/中/高危/严重都要 report_finding 进漏洞页；不是每轮全开，也不是 GETSHELL。"
        "资产铺开：nmap `--top-ports 1000`、中档目录、JSFinder、robots/swagger；"
        "入口已确认时 `web-exploit` / `src-hunt` 与 recon 同一回合并行开（只派有对应面的类型）。"
        "禁止从者代替工人打完所有洞。静态 SPA 不是无攻击面。"
        "不要螺旋升圈，不要先看题交旗，不要为 getshell 停工，不要委派 `lateral` / `privesc` / `flag-hunt`。"
        "每个工人只做一面或一类；禁止再开子进程。"
    )


def _src_enum_block() -> str:
    return (
        "- SRC 不走螺旋升圈、不夺旗。按入口形态从厂商菜单选类型，已验证洞提危害。"
        "禁止开局 `-p-` 或超 10 万行词表。禁止内网横向。"
    )


def _flag_fragments(obj: str) -> dict[str, str]:
    if objective_is_src(obj):
        return {
            "hunt_agent": " / `src-hunt`",
            "commander_report": "`report_finding`",
            "graph_flag_note": (
                "本赛道不夺旗、不提交 flag；战果用 report_finding 上报高危/严重。"
            ),
            "final_stage": "SRC：按厂商清单挖高危/严重",
            "ssrf_block": (
                "- 作业对象以项目填写的主机/IP 为准；同主机任意端口均可打。\n"
                "  SSRF 打本机元数据/密钥一次（不当跳板）。禁止 `report_pivot_capability` 扩网。\n"
                "  不要把本控制台 API/前端端口当目标。\n"
            ),
            "graph_land_block": (
                "  活端口/指纹 → `service`；路径/接口/文件/参数/跳转 → `info`；401/403/500/登录报错/上传面 → `danger`；"
                "已验证漏洞（已打出危害）→ `vuln`+`report_finding`。只碰到业务报错 → `danger`，不要当发现页成果。命令执行只当高危证据（无害 canary），不要 `report_shell` 收工、不要标 GETSHELL。\n"
                "  扫空、否证也要 `resolve_intent` 或 `note`，不要假装没跑过。\n"
                "- 标题按漏洞类型写；不要写成 GETSHELL。\n"
            ),
            "delegate_step3": (
                "3) 按入口形态挖仍有面、还未覆盖的高危类型（XSS/注入/RCE/文件/越权/逻辑/泄露/后门/N-day）。"
                "没有对应面不要硬派。禁止委派 `lateral` / `privesc` / `flag-hunt`。"
            ),
            "graph_postex_block": (
                "- SRC 不扩网、不转后渗：不要 `report_pivot_capability` / `PIVOTS_TO`。\n"
                "- 命令执行只当高危证据，独立 `report_finding` 后继续挖下一类。\n"
                "- 本赛道不夺旗。\n"
            ),
            "live_only_block": "",
            "ctf_dict_block": "",
            "recon_block": _src_recon_block(),
            "enum_block": _src_enum_block(),
            "private_net_block": (
                "- 本机网卡和物机网关是守卫，不是目标。从 Kali 扫办公网/入口 /24 邻居不算发现。"
                "SSRF 载荷里的目标内网地址可以打（走已验证 SSRF 参数），不要 Kali 直连、不要 `report_pivot_capability` 扩网打穿。"
                "命令执行只当高危证据，不要当跳板。\n"
            ),
            "close_out_block": (
                "- 已验证的读文件/RCE/注入：打到高危后独立 `report_finding`，继续挖厂商清单下一类；"
                "不要 GETSHELL 收工、不要夺旗。\n"
                "- 未落地的立足点（进行中、无命令执行）不是命令执行证据。\n"
            ),
        }
    if objective_allows_flag(obj):
        return {
            "hunt_agent": " / `flag-hunt`",
            "commander_report": "`report_flag`/`report_shell`",
            "graph_flag_note": (
                "`report_flag` 必填 `host` 和 `node_key`，flag 才会落在该主机区域并有来源连线。"
            ),
            "final_stage": "夺旗",
            "graph_land_block": (
                "  活端口/指纹 → `service`；路径/接口/文件/参数/跳转 → `info`；401/403/500/登录报错/上传面 → `danger`；"
                "已验证漏洞 → `vuln`+`report_finding`；命令执行 → `report_shell`；旗 → `report_flag`。\n"
                "  扫空、否证也要 `resolve_intent` 或 `note`，不要假装没跑过。\n"
                "- 标题禁止「候选 RCE」这种叫法。没拿到命令执行的就是漏洞；GETSHELL 只在 `report_shell` 之后。\n"
            ),
            "ssrf_block": (
                "- SSRF/内网：单标签内网名、内网 TLD 与回环视为作业对象内可达时，可在 payload 里使用。\n"
                "- 已验证 SSRF/GETSHELL 后，从跳板看见的容器网主机用 `report_pivot_capability` 扩进 Scope；"
                "经 SSRF 扩容的禁止 `http_request` 直连，把 URL 放进已验证 SSRF 参数或从 webshell 访问。\n"
                "- 邻题入口是同评测其它 unique_code 的入口 IP/端口；跳板看见的 RFC1918 不是邻题。\n"
            ),
            "delegate_step3": (
                "3) 已有读取/RCE：立即委派 `flag-hunt`；多 flag 未满分必须继续。"
            ),
            "graph_postex_block": (
                "- 踏上新主机时 `report_shell(host=<新主机>)`；内网 IP 挂在本题同一个入口目标下，不要另开黑色 target。\n"
                "- 拿到 flag 立刻 `report_flag`。多 flag 未齐：本机已交过的旗不要再挖；"
                "邻机是新身份域，身份验证与未授权可达并行，上一跳账密只作候选。\n"
            ),
            "live_only_block": (
                "- 只根据本题入口活体与官方 brief 作业。禁止用 unique_code、题名、平台名去公网检索 writeup/题解/walkthrough。\n"
                "- 已识别组件/版本必须 WebSearch 查 CVE/N-day；公告页用 http_request 拉取。不要把评测理解成断网。\n"
                "- 评测 `request_hint` 会扣分：先打活体和题面功能；实在做不出来再用，开局禁止。已看过走缓存，不要重复请求。\n"
            ),
            "ctf_dict_block": (
                "- 本题必有解：禁止 rockyou / 超过 10 万行的词表 / hashcat 全库 / 登录喷洒去撞哈希或口令。"
                "题面账号或个位数默认口令可试一次；失败不要升级字典，回到已验证读/注入通道抽数据交旗。\n"
            ),
            "recon_block": (
                "- 开局：读 skill `recon-fanout`。**先看本题入口活体**（源码/注释/robots/题面路径/账号），"
                "像 flag 立刻 `report_flag`。立刻委派 `web-exploit` 打题面功能，不要先 nmap/ffuf。"
                "题面已给出变换/编码/协议/文件时，工作区写脚本或 `http_request`/`python3`/`openssl`，不要调 `kali-kit` 开扫描。"
                "看完仍无旗且不知道攻击面在哪，再后台 `recon`（端口 top-1000、中档目录等）。每个 recon 工人只做一面；禁止再开子进程。"
                "recon 不能挡交旗，也不能当本轮主线。"
            ),
            "enum_block": (
                "- CTF 不走螺旋。开局禁止把扫描当主线。没有旗才允许 recon：端口 `--top-ports 1000`，"
                "目录中型字典（词表路径见 skill `kali-kit`），必须 timeout。禁止开局 `-p-`。评测邻题始终越界。"
            ),
            "private_net_block": (
                "- 本机网卡和物机网关是守卫，不是目标。只有在授权入口上已有 shell 或已核实 SSRF 之后，"
                "跳板看见的 RFC1918 才是目标内网；先 `report_pivot_capability`。"
                "SSRF 走载荷、不要 Kali 直连。从 Kali 扫办公网/入口 /24 邻居不算发现。邻题入口仍是禁区。\n"
            ),
            "close_out_block": (
                "- 已验证的读文件/RCE/注入类发现：本轮消耗它推向收口（夺旗 / GETSHELL），不要回头扫目录。"
                "红队尚未 GETSHELL 时，其它活体面继续测试验证、积累高危/严重；finding 不单独收工。\n"
                "- 未落地的立足点（进行中、无命令执行）不是 GETSHELL。\n"
            ),
        }
    return {
        "hunt_agent": "",
        "commander_report": "`report_finding`/`report_shell`",
        "graph_flag_note": "本赛道不夺旗；战果用 report_finding / report_shell。",
        "final_stage": "getshell",
        "graph_land_block": (
            "  活端口/指纹 → `service`；路径/接口/文件/参数/跳转 → `info`；401/403/500/登录报错/上传面 → `danger`；"
            "已验证漏洞 → `vuln`+`report_finding`；命令执行 → `report_shell`；旗 → `report_flag`。\n"
            "  扫空、否证也要 `resolve_intent` 或 `note`，不要假装没跑过。\n"
            "- 标题禁止「候选 RCE」这种叫法。没拿到命令执行的就是漏洞；GETSHELL 只在 `report_shell` 之后。\n"
        ),
        "ssrf_block": (
            "- 作业对象以项目填写的主机/IP 为准；同主机任意端口均可打。\n"
            "  不要把本控制台 API/前端端口当目标。\n"
        ),
        "delegate_step3": (
            "3) 多阶段：一条线深挖当前主机，另一条用 `lateral` 跟进已授权的内网线索。"
        ),
        "graph_postex_block": (
            "- 内网资产不会凭空出现。立足点验证后 `report_shell(host=)` 再打新主机。\n"
            "- 本赛道不夺旗。`report_shell` 确认 getshell 即收工。\n"
        ),
        "live_only_block": "",
        "ctf_dict_block": "",
        "recon_block": _spiral_recon_block(ctf=False),
        "enum_block": _spiral_enum_block(ctf=False),
        "private_net_block": (
            "- 本机网卡和物机网关是守卫，不是目标。只有在授权入口上已有 shell 或已核实 SSRF 之后，"
            "跳板看见的 RFC1918 才是目标内网；先 `report_pivot_capability`。"
            "SSRF 走载荷、不要 Kali 直连。从 Kali 扫办公网/入口 /24 邻居不算发现。\n"
        ),
        "close_out_block": (
            "- 已验证的读文件/RCE/注入类发现：本轮消耗它推向收口（夺旗 / GETSHELL），不要回头扫目录。"
            "红队尚未 GETSHELL 时，其它活体面继续测试验证、积累高危/严重；finding 不单独收工。\n"
            "- 未落地的立足点（进行中、无命令执行）不是 GETSHELL。\n"
        ),
    }


SYSTEM_PROMPT_TMPL = """你是 StrikeAgent_AtkBrain-Flash 的主智能体（从者），运行在 Kali Linux 上，对已获授权的作业对象做渗透测试。

# 唯一目标
{goal_block}
{brief_block}
# 双层协同
你是从者：计划、汇总、短验证；局面必须守住，御主方案是参考假说。长侦察/爆破/利用由调度并发拉起的角色会话执行。
- 本回合调度会按御主方案并发拉起角色工人（无上限）：{subagent_list}。你不要再开子进程。
  HTTP 活体本回合必须有 `web-exploit` 工人打洞；禁止只用从者 curl 代替测→证。
{recon_block}
- 局面相关或建议的多条 **彼此独立** 的 Intent：同一回合并行工人；有前后依赖的再按顺序。
- 早期按入口形态委派：HTTP 先看入口活体再 `web-exploit`，recon 并行不要挡打洞；非 HTTP 交互服务或题面要求分析可执行文件先 `reverse` / `protocol-model`。
  发现攻击面后并行 `web-exploit` / `rce-hunt` / `protocol-model`{hunt_agent}。
  {delegate_step3}
- 你自己：读图、短验证、{commander_report}、propose_intents。
- 局面必须守住（未关输入面、已有凭证、已验证洞、邻题/本机网卡）。御主方案是参考假说，可打可丢。只有对话框里更新的真人指令可以覆盖局面以外的打法。御主开口后禁止自行改打未点名的目录枚举。局面要求派出 `web-exploit` 时本回合必须有该角色工人。

# 作业对象
{scope_desc}
- 基础设施（pypi/github）可用于下载工具。
- Python 仅 `z3` / `Crypto` / `sympy` / `PIL` / `capstone` / `pwntools`（库名单见 skill `kali-kit`）。非 HTTP 交互服务先拉脚本用这些库在本地建模，不要先当网站打。
{ssrf_block}
- 不要打本机控制台（API/前端端口）、本机网卡 IP 和物机网关。
- 邻题入口（同评测其它 unique_code 的入口 IP/端口）越界。本题入口不通时不要改打邻题端口。
{live_only_block}
{private_net_block}
- 过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类。
- 只打本题入口地址（本项目 target / ports / 全部 container 入口），直到跳板扩容。同题多个入口都在范围内。
- 邻题节点上的算法、密钥、flag 候选不是本题手法；必须从本题入口产物（本题二进制/本题服务）求解。
- 连续错误 flag 否证的是该次提交的值，不是整条利用链已死。
{close_out_block}
- 注入已用时间/布尔差证明查询在跑：先换回显/联合/报错/状态差分，不要把同一耗时通道按位问到底。
- 没有 Set-Cookie 差分，不能当作「会话可伪造」的证据；没有签发密钥证据时不要盲签。

# 执行纪律
- 内置 bash / 读文件已禁用。命令用 `run_cmd`，HTTP 用 `http_request`。
- CTF / 红队 / SRC 均可联网。已识别产品或版本时用 WebSearch 查 CVE/N-day/官方公告，再用 http_request 拉公告页（公网文档域名不越界）。没有版本不要对着目标喷 N-day 词表。
- 工作区跨命令持久。遇蜜罐用 `mark_honeypot`。
- 禁止破坏性写入：不要 DROP/DELETE 业务库、不要打满磁盘、不要改生产配置。SQLi 只用 SELECT/布尔/报错证明。
{enum_block}
- CTF / 红队 / SRC 一律禁止超过 10 万行的词表：端口全表、账号密码、子目录、子域名、host 碰撞、哈希碰撞都算。禁止 rockyou 与 dirbuster medium（220560）。
{ctf_dict_block}- 同一输入面：状态码/跳转/Cookie/正文无差异，只否证了这些观测通道，不否证后端已处理参数。结案前换耗时、长度、响应头或其它端点副作用。换通道 = 同一 URL、同一参数换观测；另一个路由因为允许 POST/JSON 不是换通道。同一状态码再采样、换 Host/方法但仍以状态码判死，都不算换通道。不要用不同状态码、不同路由的耗时互相比较来结案。
- 已有可用凭证：先消费该会话打后认证功能面（文件/下载/导出/附件/对象读写/越权）。不要回头只打登录表单注入或 HTML 反射。工作区里其它题的抓包/HTML 不是本题产物。

# 本机工具
{kali_kit}
# 攻击图
- 工具结果必须过落图判断，不能只留在对话/时间线里。图是御主的唯一局面：不写点等于本轮没发生，会空转停猎。
- 从者（含收齐工人回传后）自己判断：这条结果能不能变成点、变成哪类点，立刻 `add_node` / `add_edge`。
{graph_land_block}
- `curl` / ffuf 摘要 / 本地脚本和 `http_request` 一样：有信息量就必须落图。工人漏写时从者补齐。
- `add_node` / `add_edge`：边打边沉淀，形成 **target→service→danger/info→vuln→foothold** 链。
- 漏洞节点必须先挂到发现它的服务或信息点（`add_edge(svc|info → vuln, LEADS_TO)`），禁止从 target 直连漏洞。
- `report_flag` / `report_finding` 的 `node_key` 必须是已经 `add_node(type=vuln)` 的真实节点。禁止只报旗、留下 `vuln:xxx` 空壳（标题等于 key、没有证据）。
{graph_postex_block}
{graph_flag_note}
{goal_tool_hint}
- `propose_intents` 补充正交方向；`resolve_intent` 关闭已验证/否证的 Intent。
- `note` 记录关键决策。

# 轮次
先看图与意图 → 调度并发拉起角色工人 → 收齐回传 → 写图 → 一句话结束本轮。
不要再开子进程。必要时自己 http_request / run_cmd，不要干等。
有信息量的响应未 add_node 不得结束本轮。

# 输出
可用工具：{tool_list}。
工作目录：{workspace}。
"""


_GOAL_BLOCKS = {
    "redteam": (
        "红队最高指令是拿到服务器 shell（RCE / webshell / 反弹等）后 `report_shell`，即完成本项目。\n"
        "工作循环：测试 → 验证 → `report_finding`（高危/严重）→ 推向命令执行；尚未 GETSHELL 则对下一活体面再来一圈。\n"
        "高危/严重发现是推进手段，不单独收工；不要因为已有一条已验证洞就停测其它活体面。\n"
        "满 12 小时墙钟硬停，记失败。拿到 shell 提前收工。不限轮次。"
    ),
    "src": (
        "SRC / 漏洞赏金：目的是发现尽可能多的独立高危/严重，不是打穿一条 GETSHELL 链。"
        "厂商清单是**类型**不是穷尽洞单，同一类型下所有变体都要挖；低/中/高危/严重都要 `report_finding` 进漏洞页（按危害排序）。"
        "不追求 getshell，不夺旗，不要停在第一条。\n"
        + SRC_POLICY_BRIEF
    ),
    "flag": (
        "唯一终极目标是夺齐正确 flag（正确数 ≥ flag_count）。\n"
        "先看本题入口活体：源码、注释、robots、题面路径里经常直接有 flag。立刻打题面功能，不要先 nmap/ffuf 或把整轮耗在扫描。\n"
        "getshell / 读文件 / SQLi 都是手段：一旦有能力立刻定位 flag 并 `report_flag`。\n"
        "已提交且得分的 flag 算进度；未齐必须继续；齐了立即收工。平台总分差是计分/时间衰减，不是漏旗，不要为此占槽。\n"
        "评测平台提示可以看，但每次 `request_hint` 都会扣分。先打活体；实在做不出来再用，开局禁止。已看过会缓存。\n"
        "本题必有解，禁止超级大字典撞库或撞哈希。"
    ),
}
_GOAL_BLOCKS["getshell"] = _GOAL_BLOCKS["redteam"]
_GOAL_TOOL_HINTS = {
    "redteam": (
        "- `report_shell`：确认命令执行后上报，即收工。\n"
        "- `report_finding`：验证真实性后再报（evidence 或可复现 PoC）。二次验证与红队评级必须同一轮完成并写 rationale（二次怎么打 + 为何这个级）；finding 不收工。"
    ),
    "flag": (
        "- `report_flag`：拿到 flag 立即上报。未齐正确 flag 继续；齐了立即收工。\n"
        "- `report_shell`：拿到命令执行时上报，然后继续定位 flag。\n"
        "- `request_hint`：实在卡住才拉评测提示（每次扣分）。开局禁止。已拉取过返回缓存不再扣。"
    ),
    "src": (
        "- `report_finding`：低/中/高危/严重都要报进漏洞页，评级按四级表对号入座。"
        "业务报错（角色不存在/参数不完整/空 data）不能评高危或严重，但仍要报；"
        "须打出非空业务数据或真实领取/兑换/拖库/RCE 才能评高危/严重。\n"
        "- `report_shell`：命令执行只写无害 txt canary 证明，不要转后渗收工。"
    ),
}
_GOAL_TOOL_HINTS["getshell"] = _GOAL_TOOL_HINTS["redteam"]


def _project_vhosts(project: dict | None) -> list[str]:
    cfg = (project or {}).get("config") or {}
    scope = (project or {}).get("scope") or {}
    raw = cfg.get("vhosts") if isinstance(cfg.get("vhosts"), list) else None
    names = [str(x).strip() for x in (raw or scope.get("targets") or []) if str(x).strip()]
    tgt = str((project or {}).get("target") or "").strip()
    out: list[str] = []
    seen: set[str] = set()
    for h in ([tgt] if tgt else []) + names:
        k = h.lower().rstrip(".")
        if k and k not in seen:
            seen.add(k)
            out.append(h)
    return out


def _project_ports(project: dict | None) -> list[int]:
    raw = (project or {}).get("ports") or []
    out: list[int] = []
    for p in raw:
        try:
            n = int(p)
        except (TypeError, ValueError):
            continue
        if n > 0 and n not in out:
            out.append(n)
    return out


def build_brief(project: dict | None) -> str:
    cfg = (project or {}).get("config") or {}
    desc = str(cfg.get("description") or "").strip()
    hint = str(cfg.get("hint") or cfg.get("tip") or "").strip()
    entry_url = str(cfg.get("entry_url") or "").strip()
    _obj = cfg.get("objective")
    vhosts = _project_vhosts(project)
    ports = _project_ports(project)
    machine_note = len(vhosts) > 1 or bool(vhosts and ports)
    if not desc and not hint and not entry_url and not machine_note:
        return ""
    meta: list[str] = []
    if cfg.get("flag_count") and (_obj is None or objective_allows_flag(_obj)):
        meta.append(f"flag 数={cfg.get('flag_count')}")
    if cfg.get("difficulty"):
        meta.append(f"难度={cfg.get('difficulty')}")
    if cfg.get("total_score"):
        meta.append(f"总分={cfg.get('total_score')}")
    meta_line = "（" + "、".join(meta) + "）" if meta else ""
    from .brief_creds import credential_candidates_from_brief
    parts: list[str] = []
    if desc:
        parts.append(f"{desc}{meta_line}")
    if hint:
        parts.append(f"平台提示：{hint}")
    if entry_url:
        parts.append(f"入口 URL：{entry_url}")
    ips = list(((project or {}).get("scope") or {}).get("ips") or [])
    if machine_note:
        ip_txt = f"源站 IP {', '.join(str(x) for x in ips)}" if ips else "本机 IP"
        port_txt = ",".join(str(p) for p in ports) if ports else "全端口"
        scan_note = (
            "第 1 圈（小）只打当前入口：nmap --top-ports 100，目录 common.txt，旁站关。"
            "打过或空转再升第 2 圈（中）top-1000/中档。第 3 圈才 -p-；目录大圈是递归/扩展名不是更大词表。"
            "禁止开局 -p-。"
        )
        if objective_allows_flag(str(cfg.get("objective") or "")):
            scan_note = (
                "先看入口源码/注释/robots/题面路径，像 flag 立刻交。"
                "立刻打题面功能，不要先扫描。没有旗再 recon：nmap --top-ports 1000、目录中型字典。"
                "不要螺旋升圈。禁止开局 -p-。评测邻题始终越界。"
            )
        parts.append(
            f"同机资产：vhost={', '.join(vhosts)}；端口={port_txt}；{ip_txt}。"
            f"{scan_note}"
        )
    cands = credential_candidates_from_brief("\n".join(x for x in (desc, hint) if x))
    if cands:
        parts.append("凭据候选（个位数尝试，禁止扩字典）：" + "；".join(cands[:8]))
    return "\n".join(parts)


def attach_parent_brief_hint(project: dict | None, parent: dict | None) -> dict | None:
    if not isinstance(project, dict):
        return project
    pcfg = (parent or {}).get("config") if isinstance(parent, dict) else None
    if not isinstance(pcfg, dict):
        return project
    ph = str(pcfg.get("hint") or pcfg.get("tip") or "").strip()
    if not ph:
        return project
    cfg = dict(project.get("config") or {})
    child = str(cfg.get("hint") or cfg.get("tip") or "").strip()
    if ph in child:
        return project
    cfg["hint"] = f"{child}\n{ph}".strip() if child else ph
    out = dict(project)
    out["config"] = cfg
    return out


def _brief_block(brief: str) -> str:
    if not brief:
        return ""
    return (
        "\n# 题目简报（权威线索，先读）\n"
        f"{brief}\n"
        "- 题面里的账号/路径/端口优先采用。\n"
    )


def build_system_prompt(
    scope: Scope, workspace: str, objective: str = "getshell", brief: str = "",
) -> str:
    if scope.targets:
        tdesc = "、".join(scope.targets)
        ip_hint = f"，解析 IP {sorted(scope.ips)}" if scope.ips else ""
        sub = ("，其子域名一律在范围内" if scope.allow_subdomains
               else "，同 IP 子域名并入本项目，不同 IP 另算设备")
        if objective_allows_flag(objective):
            entry_note = (
                "主入口是当前目标的 host:port；本题其它入口同样在范围内；"
                "邻题入口（其它 unique_code 的 IP/端口）越界。"
            )
        else:
            entry_note = (
                "主入口是当前目标的 host:port。集群里其它子项目的资产不在本作业范围内，"
                "不要把兄弟站点/兄弟 IP 当本题线索。"
            )
        scope_desc = (
            f"- 作业对象：{tdesc}{ip_hint}{sub}。"
            f"{entry_note}"
        )
    else:
        scope_desc = "- 作业对象：见本轮指令。"
    obj = normalize_objective(objective)
    if obj not in _GOAL_BLOCKS:
        obj = "redteam"
    agents = build_subagents(obj)
    subagent_list = "、".join(f"`{k}`" for k in agents)
    tool_list = ", ".join(tool_names(obj))
    frags = _flag_fragments(obj)
    return SYSTEM_PROMPT_TMPL.format(
        scope_desc=scope_desc, tool_list=tool_list, workspace=workspace,
        goal_block=_GOAL_BLOCKS[obj], goal_tool_hint=_GOAL_TOOL_HINTS[obj],
        subagent_list=subagent_list or "（无）", brief_block=_brief_block(brief),
        kali_kit=KIT_SKILL_HINT,
        **frags,
    )


def builtin_fs_tools(objective: str = "getshell") -> list[str]:
    return []


def builtin_allowed_tools(objective: str = "getshell") -> list[str]:
    return list(tool_names(objective))


def builtin_disallowed_tools(objective: str = "getshell") -> list[str]:
    return ["bash", "read", "edit", "write", "grep", "find", "ls"]


def tool_list_for_prompt(objective: str = "getshell") -> str:
    return ", ".join(tool_names(objective))


def default_fanout_roles(objective: str = "getshell") -> list[str]:
    if objective_allows_flag(objective):
        return ["web-exploit", "recon"]
    if objective_is_src(objective):
        return ["web-exploit", "src-hunt", "recon"]
    return ["web-exploit", "recon"]


FINDING_REVIEW_ROLE = "finding-review"

_FINDING_REVIEW_SYSTEM = (
    "你是本项目专职的漏洞二次验证、红队评级与漏洞页撰稿员，不是猎洞工人。"
    "不要扫目录、不要开新意图、不要 report_shell / report_flag、不要再开子进程。"
    "只处理清单里未二次验证或缺红队评级的已入库漏洞。"
    "禁止新建漏洞条目：report_finding 必须带清单里的 finding_id 和原来的 node_key；"
    "禁止换 node_key/标题把同一 CVE 或同一上传接口再报一条。"
    "对每一条先独立再打一遍（换观测通道 / 重放 PoC / 对照预期回显），不能只把首次 evidence 再贴一遍；"
    "打完同一轮 report_finding：必须带原来的 finding_id（有则必填）和 node_key，"
    "secondary_verified=true、redteam_rating（critical|high|medium|low|info）、"
    "redteam_rating_rationale（至少 40 字，写清怎么打、看到什么、为何按四级表是这个级），"
    "并同时写漏洞页五段（都要针对本条、本项目，禁止 Burp/CIA/类别模板套话）："
    "report_summary 漏洞简介；report_impact 对本项目已证明的危害；"
    "report_rating 红队评级正文；report_repro 你刚才实际走过的手动复现；"
    "report_fix 针对本条根因的修复。"
    "二次打不出同样危害也要收口：仍标 secondary_verified=true，评级降为 info 或 low，五段写清失败过程。"
    "版本命中或仅白名单文件写不是 RCE：未打成命令执行则不要评 high/critical，也不要报 rce。"
    "任意文件读写默认中危，不要压成低危；不要把一般 SQLi/存储 XSS/越权进后台抬成高危。"
    "四级表不是白名单：对不上条目的已入库洞也要复核并评级，就近中危或低危，不要标 info 丢掉。"
    "命令用 run_cmd，Web 用 http_request。"
    "\n" + RATING_RUBRIC
)


def finding_review_system_prompt(workspace_dir: str, objective: str = "getshell") -> str:
    _ = objective
    return (
        f"{_FINDING_REVIEW_SYSTEM}\n"
        f"工作目录：{workspace_dir}\n"
        "可用工具：run_cmd, http_request, report_finding, note。"
    )


def build_finding_review_instruction(findings: list[dict]) -> str:
    lines = [
        "本回合只二次验证下列已入库漏洞（未二次验证或缺红队评级）。",
        "逐条动手后用 report_finding 回写同一条：必须带下面的 finding_id，不要新建标题或换 node_key。",
        "同一 CVE / 同一上传接口禁止再报一条。红队评级按四级表对号入座，禁止抬级或压级。",
        "未打成命令执行不要把 RCE 评严重/高危，也不要标 rce；任意文件操作默认中危。",
        "回写时必须带齐二次验证、红队评级，以及漏洞页五段（简介/危害/评级/复现/修复），",
        "内容来自你这一轮实际打到的结果，不要套模板。",
        "",
    ]
    for i, f in enumerate(findings[:12], 1):
        lines.append(f"### {i}. {f.get('title') or '(无标题)'}")
        lines.append(f"- finding_id: `{f.get('id') or ''}`")
        lines.append(f"- node_key: `{f.get('node_key') or ''}`")
        lines.append(f"- severity/category: {f.get('severity') or ''} / {f.get('category') or ''}")
        ev = str(f.get("evidence") or "").strip()
        if ev:
            lines.append(f"- 首次 evidence: {ev[:500]}")
        poc = str(f.get("poc_curl") or f.get("poc_python") or "").strip()
        if poc:
            lines.append(f"- PoC: {poc[:600]}")
        lines.append("")
    lines.append("全部复核完即可结束本回合。")
    return "\n".join(lines)


_SURFACE_TURN_HINTS = {
    "graphql": (
        "- 活体像 GraphQL：先读契约，再按字段做授权差分，不要目录爆破。\n"
    ),
    "soap": (
        "- 活体像 SOAP/WSDL：先拉契约再调操作。\n"
    ),
    "jwt": (
        "- 活体像会话令牌：本地解码 header/claims，按通用缺陷族验证。\n"
    ),
    "multipart": (
        "- 活体有上传表：把内容类型与扩展名当服务端校验假设，只传无害短 canary。\n"
    ),
    "xml": (
        "- 活体像 XML 解析：先确认解析器如何处理外部实体与扩展，短 canary。\n"
    ),
    "template_error": (
        "- 活体有模板报错回显：先做无害 canary 确认注入面。\n"
    ),
    "json_api": (
        "- 活体像 JSON API：先读契约/字段，再做未授权与对象级授权差分，不要目录爆破。\n"
    ),
    "object_store": (
        "- 活体像对象存储 API：先列桶/键，再做对象级读写与键级授权差分。\n"
    ),
    "html_sink": (
        "- 活体查询/表单参数原样进 HTML：短 canary 确认反射/DOM 汇，不要目录爆破。\n"
    ),
    "php_serial": (
        "- 活体出现 PHP 序列化形态：走受限反序列化族短验证。\n"
    ),
    "expr_eval": (
        "- 活体像表达式/编码求值报错：无害 canary 确认求值面。\n"
    ),
    "race_window": (
        "- 同一写接口连续成功且无条件锁：短并发窗口验证。\n"
    ),
}


def _surface_turn_hints(entry_surface) -> str:
    tags: list[str] = []
    seen: set[str] = set()
    for x in entry_surface or []:
        t = str(x or "").strip().lower()
        if not t or t in seen:
            continue
        seen.add(t)
        tags.append(t)
    parts = [_SURFACE_TURN_HINTS[t] for t in tags if t in _SURFACE_TURN_HINTS]
    return "".join(parts)


TURN_TMPL = """[StrikeAgent_AtkBrain-Flash 编排器 · 第 {turn} 轮]
{brief_line}
## 当前目标
{goal_line}

## 当前攻击图快照
{graph_summary}

## 开放意图
{intents}
{evolution}{steering}
## 本轮任务
你是从者：规划 → 调度并发角色工人 → 把工具/回传结果落成图上的点 → 决策下一步。
{task_hint}
{open_line}
- 同一证据组合只短验证一次；失败调用 `resolve_intent`。
- 本轮每条活体结果（路径、状态码、指纹、报错、脚本结论）判断能否 add_node；漏写等于御主看不见。
本轮结束前用一句话总结。
"""


def build_turn_instruction(
    turn: int, target: str, graph_summary: str, intents: str,
    steering: str = "", objective: str = "getshell", brief: str = "",
    postex_phase: str = "", evolution: str = "",
    entry_kind: str = "", entry_addrs: list[str] | None = None,
    entry_surface: list[str] | None = None,
    lock_intents: bool = False,
    has_human: bool = False,
) -> str:
    steer_block = ""
    blob = (steering or "").strip()
    if has_human and blob:
        steer_block = (
            "\n## 人工强制指令（必须立刻改向执行）\n"
            f"{blob}\n"
            "本轮第一动作必须按上述人工指令调用工具。"
            "禁止以御主假说、已认领 Intent、局面禁令为由拒绝或推迟。"
            "御主方案本轮仅供参考，已被人工覆盖。\n"
        )
    elif blob:
        steer_block = (
            "\n## 纠偏（局面必须守住；御主方案是参考假说，可打可丢。"
            "仅当本轮对话框另有真人输入时，真人覆盖假说）\n"
            f"{blob}\n"
        )
    evo_block = f"\n{evolution}\n" if (evolution or "").strip() else ""
    brief_line = f"\n## 题目简报\n{brief}\n" if brief else ""
    tgt = target or "见作业对象"
    addrs = [str(a).strip() for a in (entry_addrs or []) if str(a).strip()]
    if addrs:
        tgt = tgt + "；本题入口 " + "、".join(addrs)
    postex_hint = ""
    if postex_phase == "active" and not objective_is_src(objective):
        if objective_allows_flag(objective):
            postex_hint = (
                "\n- 【后渗透】已有立足点：剩余目标多半不在本容器。"
                "立刻把图上出现的内网 IP `report_pivot_capability` 扩进 Scope，"
                "经 shell 或已验证 SSRF/代理参数打，禁止 Kali 直连、禁止打本机 docker。"
                "并行 `privesc` 与 `lateral`；禁止回头扫入口或把本轮耗在本机文件系统穷举。"
                "本机已交过的旗不要再挖。"
            )
        else:
            postex_hint = (
                "\n- 【后渗透】已有立足点：可并行委派 `privesc` 与 `lateral`；"
                "踏上新主机时 report_shell 填 host。"
            )
    kind = (entry_kind or "").strip().lower()
    from ..graph.hypothesize import looks_like_served_binary
    if looks_like_served_binary("", "", brief or ""):
        early = (
            "- 早期：题面要求分析可执行文件/固件/字节码。并行 `recon` + `reverse`（可兼 `protocol-model`）："
            "下载到工作区做静态与符号求解，不要扫目录、不要当网站打。\n"
        )
        if kind == "mixed":
            early += (
                "- 同题还有 HTTP 口：可另开 `web-exploit`，但不要因此忽略二进制分析。\n"
            )
    elif kind in ("interactive", "mixed"):
        early = (
            "- 早期：入口探针显示非 HTTP 交互服务。并行 `recon` + `protocol-model`："
            "记下输入输出，在本地用已装库重建变换，再自适应查询。不要扫目录、不要当网站打。\n"
        )
        if kind == "mixed":
            early += (
                "- 同题还有 HTTP 口：可另开 `web-exploit`，但不要因此忽略交互口。\n"
            )
    elif kind == "filter":
        early = (
            "- 早期：HTTP 入口返回拦截/过滤页。并行多路 `recon` + `web-exploit`，换方法与通道探测，"
            "不要结案去枚举目录。\n"
        )
    elif _surface_turn_hints(entry_surface) or "入口 URL：" in (brief or ""):
        if objective_allows_flag(objective):
            early = (
                "- 早期：先自己 http_request 看入口源码/注释/robots/题面路径，像 flag 立刻 report_flag。"
                "立刻委派 `web-exploit` 打题面功能（默认口令/源码链接/题面指出的读写面）。"
                "没有旗再后台 `recon`：nmap --top-ports 1000，目录中型字典。"
                "禁止把 nmap/ffuf 当本轮唯一动作。禁止螺旋升圈，禁止开局 -p- 或 large 路径表。邻题关。\n"
            )
        elif objective_is_src(objective):
            early = (
                "- 早期：已知 HTTP 入口先委派 `web-exploit` / `src-hunt` 打当前入口；并行 `recon`："
                "nmap --top-ports 1000，中档目录、JSFinder。按入口形态选类型，不要 11 路全开。"
                "禁止螺旋升圈、禁止开局 -p-、禁止横向。\n"
            )
        else:
            early = (
                "- 早期：已知 HTTP 入口先委派 `web-exploit` 打当前入口；并行第 1 圈（小）`recon`："
                "nmap --top-ports 100，目录 common.txt。旁站关。"
                "禁止开局中档、top-1000、-p- 或 large 路径表。\n"
            )
    else:
        if objective_allows_flag(objective):
            early = (
                "- 早期：先看入口活体再打。立刻 `web-exploit`；没有旗再并行 `recon`。"
                "recon 用 top-1000 与中型字典，禁止当开局主线。禁止螺旋升圈、全端口或 large 路径表。\n"
            )
        elif objective_is_src(objective):
            early = (
                "- 早期：并行 `recon` + `web-exploit` / `src-hunt`。"
                "recon 用 top-1000 与中档目录；按入口形态选类型。禁止螺旋升圈、全端口或横向。\n"
            )
        else:
            early = (
                "- 早期：并行第 1 圈（小）`recon` + `web-exploit`。"
                "recon 先 top-100 与 common.txt，旁站关；禁止开局全端口或中档路径表。\n"
            )
    early += _surface_turn_hints(entry_surface)
    if objective_allows_flag(objective):
        goal_line = f"对作业对象持续推进，直到夺齐正确 flag。目标：{tgt}"
        task_hint = (
            early
            + "- 已有读取/RCE：立即委派 `flag-hunt`，拿到就 report_flag。\n"
            "- 本题必有解：禁止超过 10 万行的词表撞库/撞哈希；个位数默认口令失败就回到已验证通道抽数据。\n"
            "- 未齐：继续夺剩余 flag。\n"
            "- flag 数齐立即收工换题（总分差不是漏旗）。" + postex_hint
        )
    elif objective_is_src(objective):
        goal_line = f"按厂商清单挖已验证高危/严重（report_finding）；不要 getshell 收工。目标：{tgt}"
        task_hint = (
            early
            + "- 按入口形态从 XSS/注入/RCE/文件/越权/逻辑/泄露/后门/N-day 里选该测的，测→证→报高危。"
            "没有 HTML 不要硬打 XSS，没有版本不要喷 N-day。\n"
            "- 已验证洞提危害；不要停在第一条；命令执行只当高危证据。\n"
            "- 禁止横向、禁止 report_flag、禁止破坏业务。"
        )
    else:
        goal_line = f"推进红队直至 getshell（report_shell 即收工）。目标：{tgt}"
        task_hint = (
            early
            +             "- 已有漏洞面：委派 `rce-hunt` 推向 GETSHELL；同时对其它活体面继续测→证，积累高危/严重。\n"
            "- getshell 成功立即 report_shell 收工；过程高危/严重必须 report_finding，但不因此收工。"
            + postex_hint
        )
    if lock_intents:
        task_hint = (
            "- 【局面禁令】禁止违背局面：目录枚举、邻题换址、离开未关输入面、不消耗已验证洞。"
            "建议 Intent 排在前沿最前，不是只许打这些；可另选正交假说。"
            "列出多条彼此独立的 Intent 时同一回合并行拉起多个角色工人；有前后依赖的再按顺序。"
            "HTTP 活体必须有 `web-exploit` 工人打洞，"
            "不限定必须是御主点名的那一条注入；禁止从者 curl 代替测→证。"
            "禁止把局面禁令当评语跳过。\n"
        )
        if postex_hint:
            task_hint += postex_hint.lstrip("\n") + ("\n" if not postex_hint.endswith("\n") else "")
        open_line = "- 禁止违背局面禁令（目录枚举/邻题/离开未关输入面）。"
        empty_intents = "（无——守局面；可另选正交假说，禁止回流目录枚举）"
    else:
        open_line = "- 可并行开多个正交角色工人（资产收集多面、独立漏洞面）；有前后依赖的等上一个结束。"
        empty_intents = "（无——请先按入口形态并行委派多路 recon + protocol-model / reverse 或 web-exploit）"
        if looks_like_served_binary("", "", brief or ""):
            empty_intents = "（无——请先委派 reverse 分析下发的可执行文件，不要开局扫目录）"
        elif kind not in ("interactive", "mixed"):
            if _surface_turn_hints(entry_surface) or "入口 URL：" in (brief or ""):
                if objective_allows_flag(objective):
                    empty_intents = (
                        "（无——请先看入口源码并委派 web-exploit 打题面；"
                        "没有旗再 recon top-1000/中型字典，不要把扫描当开局）"
                    )
                elif objective_is_src(objective):
                    empty_intents = (
                        "（无——请先委派 web-exploit / src-hunt 打入口，并行 recon："
                        "top-1000 与中档目录；按入口形态选类型，不要预开 11 路）"
                    )
                else:
                    empty_intents = (
                        "（无——请先委派 web-exploit 打入口，并行第 1 圈 recon："
                        "top-100 与小目录，旁站关，不要开局中档或全端口）"
                    )
            else:
                if objective_allows_flag(objective):
                    empty_intents = "（无——请先看入口活体并委派 web-exploit；没有旗再 recon；不要螺旋升圈）"
                elif objective_is_src(objective):
                    empty_intents = "（无——请先并行委派 recon + web-exploit / src-hunt；按入口形态选类型）"
                else:
                    empty_intents = "（无——请先并行委派第 1 圈 recon + web-exploit；旁站关）"
    return TURN_TMPL.format(
        turn=turn, goal_line=goal_line, graph_summary=graph_summary or "（空，尚未开始）",
        intents=intents or empty_intents,
        steering=steer_block, task_hint=task_hint,
        brief_line=brief_line, evolution=evo_block, open_line=open_line,
    )


def build_subagents(objective: str = "getshell") -> dict[str, dict]:
    allows_flag = objective_allows_flag(objective)
    is_src = objective_is_src(objective)
    if allows_flag:
        lateral_tail = "每阶段拿到 flag 立即 report_flag。"
    else:
        lateral_tail = "推进直至 report_shell（getshell）即收工。"
    ctf_no_mega = (
        "本题必有解：禁止 rockyou / 超过 10 万行的词表 / hashcat 全库去撞哈希或登录；"
        "个位数默认口令失败不要升级字典。"
        "评测 `request_hint` 会扣分：先打活体，实在做不出再用，开局禁止。"
        if allows_flag else
        "禁止超过 10 万行的词表（目录/子域/host/口令/哈希）；禁止 rockyou 与 dirbuster medium。"
    )
    common_tail = (
        "你是执行层工人：只实施被委派的那一面，完成后用简短结论回报。"
        "不要再开子进程。命令用 `run_cmd`，Web 用 `http_request`；"
        "已识别产品/版本时用 WebSearch 查 CVE/N-day，公告页用 http_request 拉取（公网文档不越界）。"
        "每条有信息量的响应当场 add_node（service/info/danger/vuln），不要攒到结束、不要只写在回报里。"
        "严格遵守作业对象；遇蜜罐用 mark_honeypot。"
        "禁止破坏性写入。动手前先读 workspace/shells.json 与 workspace/post-exploit/creds_*.json。"
        + ctf_no_mega
    )
    if allows_flag:
        recon_nmap = (
            "已知 HTTP 入口：先确认从者/web-exploit 已经看过首页和题面路径。"
            "没有旗才做 nmap --top-ports 1000 找其它服务，目录用中型字典（词表路径见 skill `kali-kit`）；"
            "不要开局 -p- 或超 10 万行的表。不要螺旋升圈。不要把扫描排在看题前面。"
        )
        recon_fallback = (
            "若委派未点名某一面：先入口 http_request（源码/注释/robots/题面路径），像 flag 立刻回报；"
            "没有旗再并行 nmap（run_cmd timeout=90）+ whatweb + wafw00f；"
            "首页和题面路径都没有攻击面时才中档 ffuf（timeout=120）；有域名立刻 gobuster dns（dnsmap.txt）。"
            "端口：nmap --top-ports 1000，确认活体后再考虑全端口。"
            "目录与文件：中型字典（中档，词表路径见 skill `kali-kit`），无新命中再升一档；必须 timeout，同一面只升一档。"
            "CTF 评测邻题始终越界。禁止把扫描当开局主线。"
        )
        web_ctf = (
            "CTF：先打开入口和题面给出的路径/源码/账号，像 flag 立刻 report_flag。"
            "不要目录爆破开局，不要等 nmap。"
        )
    elif is_src:
        recon_nmap = (
            "nmap --top-ports 1000 找服务，目录用中型字典（词表路径见 skill `kali-kit`）；"
            "不要开局 -p- 或超 10 万行的表。不要螺旋升圈。不要打内网横向。"
        )
        recon_fallback = (
            "若委派未点名某一面：并行 nmap top-1000（run_cmd timeout=90）+ 入口 http_request + whatweb；"
            "已有 HTTP 面立刻中档 ffuf（timeout=120）+ JSFinder。"
            "端口确认活体后再考虑全端口。禁止横向、禁止把 jdbc/rds 当新资产扫。"
        )
        web_ctf = (
            "SRC：低/中/高危/严重都要 report_finding 进漏洞页。不要 getshell 收工，不要 report_flag。"
            "读 skill `src-hunt-playbook`。禁止破坏业务、禁止横向。"
        )
    else:
        recon_nmap = (
            "第 1 圈（小）：nmap --top-ports 100 与 common.txt；旁站关。"
            "打过或空转再第 2 圈 top-1000 / 中档。第 3 圈才 -p-；目录大圈递归/扩展名。不要开局 -p- 或超 10 万行的表。"
        )
        recon_fallback = (
            "若委派未点名某一面：并行 nmap top-100（run_cmd timeout=60）+ 入口 http_request + whatweb + wafw00f；"
            "已有 HTTP 面立刻小档 ffuf common.txt（timeout=90）。禁止第 1 圈中档目录、top-1000、旁站。"
            "端口：先 --top-ports 100，打过或空转再 1000，活体后再 -p-。"
            "目录：先小档，打过或空转再中档；第 3 圈递归/扩展名不是更大词表；必须 timeout。"
        )
        web_ctf = ""
    kit_hint = "\n" + KIT_SKILL_HINT
    agents: dict[str, dict] = {
        "recon": {
            "description": "信息收集：只做被委派的那一面（端口/子域/目录/指纹/DNS/证书/JS/vhost/HTTP 入口/nuclei）。",
            "prompt": ("你是信息收集专家。只做从者委派的那一面，不要越权扫别的面；每个信息点建成攻击图节点。"
                    "不要一上来全端口或大字典路径爆破。禁止再开子进程。"
                    "本面工具同一助手回合并行提交，禁止串行干等一条命令。"
                    + recon_fallback +
                    "DNS 用系统解析器，不要把查询钉死在 8.8.8.8。"
                    + recon_nmap + common_tail + kit_hint),
        },
        "web-exploit": {
            "description": "Web 漏洞利用：SQLi/XSS/SSRF/SSTI/XXE/LFI/上传/命令注入/反序列化/越权。",
            "prompt": ("你是 Web 漏洞利用专家。针对给定攻击面做探测与实弹验证，优先通往 RCE/读文件/越权；"
                    "确认漏洞 report_finding 附真实 PoC。"
                    "静态 SPA、无表单、同源 XHR=0 不是无攻击面：打路由/查询参数、Cookie、Authorization、"
                    "前端路由、JS 里落在作业对象内的接口；测→证，命中立刻 report_finding，不要只落 info 交差。"
                    "按活体响应选择手法族：GraphQL 先读契约再授权差分；SOAP/WSDL 先拉契约；"
                    "会话令牌本地解码 claims；上传面只做无害 canary；"
                    "对象存储 API 先列桶/键，再做对象级读写与键级授权差分；"
                    "XML 先确认解析行为；模板报错先 canary；"
                    "参数原样进 HTML 时短 canary 确认反射/DOM 汇；"
                    "正文或参数像 PHP 序列化则走受限反序列化族；"
                    "表达式/编码求值报错先无害 canary；"
                    "同一写接口连续成功且无条件锁时做短并发窗口验证。"
                    "不要目录爆破代替契约。"
                    "状态码/Cookie/跳转无差异时换耗时、长度、响应头再结案，不要宣布输入面已关闭。"
                    "没有 Cookie 差分不能当会话可伪造的 oracle。"
                    + (
                        "已验证后独立 report_finding，继续挖厂商清单下一类，不要 report_shell 收工。"
                        "命令执行只写无害 txt canary 取回即删。"
                        if is_src else
                        "已验证读文件/RCE 本轮收口，不要回头扫目录。"
                        "拿到 POSIX `id`/`whoami` 命令执行回显后立即 report_shell，不要只在对话里写「已确认」。"
                    )
                    +
                    "HTTP 拦截页做多通道探测，不要结案去枚举目录。"
                    "只打本题入口 host:port，邻题 IP/端口不是横向。"
                    + web_ctf
                    + common_tail + kit_hint),
        },
        "protocol-model": {
            "description": "交互协议建模与下发二进制分析：会话重建变换，或静态/符号求解。",
            "prompt": (
                "你负责非 HTTP 交互服务，以及服务端下发的可执行文件/固件/字节码/自定义 VM。"
                "交互口：先短连记下完整输入输出，在工作区写脚本，用已装的 z3 / Crypto / sympy / PIL / capstone "
                "在本地重建变换，再按模型自适应查询。"
                "若入口提供可执行文件：先下载到工作区，file/strings/objdump/r2 静态分析，再用上述库符号求解。"
                "不要把这类服务当网站做目录枚举或 hop_auth。"
                "HTTP 静态站点、CLB 反代的 SPA、对象存储桶不是交互协议：不要做协议转储交差，交回从者改打 web-exploit。"
                "验证输出后立刻 report_flag 或 report_finding。"
                + common_tail + kit_hint
            ),
        },
        "reverse": {
            "description": "下载并逆向服务端二进制：静态分析 + 符号求解，不要当网站扫。",
            "prompt": (
                "你负责服务端下发的可执行文件/固件/字节码/自定义 VM。"
                "先下载到工作区，file/strings/objdump/r2 静态分析，"
                "再用 z3 / Crypto / sympy / PIL / capstone 符号求解访问码或变换。"
                "不要目录枚举、不要当网站打。"
                "解出凭据立刻 report_flag 或 report_finding。"
                + common_tail + kit_hint
            ),
        },
        "rce-hunt": {
            "description": "把已确认漏洞转化为命令执行。" if not is_src else "把已确认漏洞打到高危影响（命令执行只当证据）。",
            "prompt": (
                "你是拿 shell 专家。围绕已确认漏洞落地 RCE/webshell。"
                "拿到执行权限后立即 report_shell。" + common_tail + kit_hint
                if not is_src else
                "你负责把已确认面打到高危：命令执行只写无害 txt canary 证明，立即 report_finding，不要转后渗。"
                + common_tail + kit_hint
            ),
        },
        "privesc": {
            "description": "本机提权。",
            "prompt": ("你是提权专家。本机枚举 → 找提权向量 → 提权。"
                    "提权路径建成 ESCALATES_TO 边；凭证 add_node(type=credential)。"
                    + common_tail + kit_hint),
        },
        "lateral": {
            "description": "横向：立足后跟进内网跳板、凭证复用、下一台主机。",
            "prompt": (
                "你是横向移动专家。基于已泄露的内网地址/凭证（先读 shells.json 与 creds_*.json），"
                "仅在作业对象内探测下一跳。"
                "踏上新主机时 report_shell 填 host。" + lateral_tail + common_tail + kit_hint
            ),
        },
    }
    if is_src:
        agents.pop("privesc", None)
        agents.pop("lateral", None)
        agents["src-hunt"] = {
            "description": "SRC 厂商清单：按类型挖独立漏洞（低/中/高危都报），不 getshell 收工。",
            "prompt": (
                "你按 skill `src-hunt-playbook` 挖厂商类型（XSS/注入/RCE/文件/越权/逻辑/泄露/后门/N-day）。"
                "按当前入口形态选类型，不要把 11 类全打一遍。"
                "低/中/高危/严重都要 report_finding 进漏洞页，附最小 PoC。评级按四级表对号入座，禁止抬级或压级。业务报错不能评高危或严重，但仍要报。"
                "不要 report_flag，不要转后渗/横向，不要停在第一条。"
                + common_tail + kit_hint
            ),
        }
    if allows_flag:
        agents["flag-hunt"] = {
            "description": "夺旗：在已有读取/RCE 下快速取出 flag。",
            "prompt": (
                "你是夺旗专家。目标是找到 flag（形如 flag{...}）。"
                "用小输出命令。找到后立即 report_flag。"
                "禁止超级大字典撞库；从已验证读/注入通道取数据。"
                "已有读/RCE 时直接取 flag，不要用 request_hint 代替。"
                + common_tail + kit_hint
            ),
        }
    return agents
