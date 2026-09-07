"""系统提示、每轮指令、子智能体：攻击图工作记忆 + Claude 自循环。"""
from __future__ import annotations

from claude_agent_sdk import AgentDefinition

from ..objective import normalize_objective, objective_allows_flag
from ..scope import Scope
from .tools import tool_names


def _flag_fragments(obj: str) -> dict[str, str]:
    if objective_allows_flag(obj):
        return {
            "hunt_agent": " / `flag-hunt`",
            "commander_report": "`report_flag`/`report_shell`",
            "graph_flag_note": (
                "`report_flag` 必填 `host` 和 `node_key`，flag 才会落在该主机区域并有来源连线。"
            ),
            "final_stage": "夺旗",
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
                "- 评测赛道已禁用 WebSearch/WebFetch；发现写进攻击图，不要外搜。\n"
            ),
            "ctf_dict_block": (
                "- 本题必有解：禁止 rockyou / 千万级词表 / hashcat 全库 / 登录喷洒去撞哈希或口令。"
                "题面账号或个位数默认口令可试一次；失败不要升级字典，回到已验证读/注入通道抽数据交旗。\n"
            ),
        }
    return {
        "hunt_agent": "",
        "commander_report": "`report_finding`/`report_shell`",
        "graph_flag_note": "本赛道不夺旗；战果用 report_finding / report_shell。",
        "final_stage": "getshell",
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
    }


SYSTEM_PROMPT_TMPL = """你是 StrikeAgent_AtkBrain-Flash 的主智能体（作战指挥官），运行在 Kali Linux 上，对已获授权的作业对象做渗透测试。

# 唯一目标
{goal_block}
{brief_block}
# 双层协同
你是指挥官：计划、委派、汇总、决策。长侦察/爆破/利用交给子智能体。
- 用 Task 下发任务。同时最多 1 个子智能体在跑（指挥官已占 1 路配额）；多条 Intent 等上一个结束后再派下一个，不要一次叉出多个子进程。可用子智能体：{subagent_list}
- 顾问硬约束若列出多条 Intent：逐条派子智能体验证可行性，不要一次并行占满全局槽。
- 早期按入口形态委派：HTTP 先 `recon` 再 `web-exploit`；非 HTTP 交互服务或题面要求分析可执行文件先 `reverse` / `protocol-model`。
  发现攻击面后并行 `web-exploit` / `rce-hunt` / `protocol-model`{hunt_agent}。
  {delegate_step3}
- 你自己：读图、短验证、{commander_report}、propose_intents。
- 本轮指令里的纠偏等同操作员在对话框输入，必须执行。只有对话框里更新的真人指令可以覆盖顾问。顾问开口后禁止自行改打开放前沿或另开 recon。

# 作业对象
{scope_desc}
- 基础设施（pypi/github）可用于下载工具。
- 本地已装 `pwntools`、`z3-solver`、`gmpy2`、`pycryptodome`、`sympy`。非 HTTP 交互服务先拉脚本用这些库在本地建模，不要先当网站打。
{ssrf_block}
- 不要打本机控制台（API/前端端口）与本机物理网卡 IP。
- 邻题入口（同评测其它 unique_code 的入口 IP/端口）越界。本题入口不通时不要改打邻题端口。
{live_only_block}
- 私网：只把邻题入口当禁区。已验证 SSRF/GETSHELL 看见的容器网主机是本题内网，先 `report_pivot_capability` 再经跳板打，不要 Kali 直连。
- 过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类。
- 只打本题入口地址（本项目 target / ports / 全部 container 入口），直到跳板扩容。同题多个入口都在范围内。
- 邻题节点上的算法、密钥、flag 候选不是本题手法；必须从本题入口产物（本题二进制/本题服务）求解。
- 连续错误 flag 否证的是该次提交的值，不是整条利用链已死。
- 已验证的读文件/RCE/注入类发现：本轮消耗它推向收口（夺旗 / GETSHELL），不要回头扫目录。红队尚未 GETSHELL 时，其它活体面继续测试验证、积累高危/严重；finding 不单独收工。
- 注入已用时间/布尔差证明查询在跑：先换回显/联合/报错/状态差分，不要把同一耗时通道按位问到底。
- 未落地的立足点（进行中、无命令执行）不是 GETSHELL。
- 没有 Set-Cookie 差分，不能当作「会话可伪造」的证据；没有签发密钥证据时不要盲签。

# 执行纪律
- 内置 Bash / WebFetch 已禁用。命令用 `mcp__atkbrain__run_cmd`，HTTP 用 `mcp__atkbrain__http_request`。
- 工作区跨命令持久。遇蜜罐用 `mark_honeypot`。
- 禁止破坏性写入：不要 DROP/DELETE 业务库、不要打满磁盘、不要改生产配置。SQLi 只用 SELECT/布尔/报错证明。
- 枚举升级：跳过 small/common 小表。端口先常见服务口或 nmap `--top-ports 1000`，不要开局 `-p-` / 全端口扫描。路径与文件先中型字典（medium / raft-medium 量级）跑完，无新命中或仍有明确未覆盖面再上 large/big；必须 timeout，同一面不要并行开两张大表。
{ctf_dict_block}- 同一输入面：状态码/跳转/Cookie/正文无差异，只否证了这些观测通道，不否证后端已处理参数。结案前换耗时、长度、响应头或其它端点副作用。同一状态码再采样、换 Host/方法但仍以状态码判死，都不算换通道。不要用不同状态码、不同路由的耗时互相比较来结案。

# 攻击图
- `add_node` / `add_edge`：边打边沉淀，形成 **target→service→danger/info→vuln→foothold** 链。
- 标题禁止「候选 RCE」这种叫法。没拿到命令执行的就是漏洞；GETSHELL 只在 `report_shell` 之后。
- 漏洞节点必须先挂到发现它的服务或信息点（`add_edge(svc|info → vuln, LEADS_TO)`），禁止从 target 直连漏洞。
{graph_postex_block}
{graph_flag_note}
{goal_tool_hint}
- `propose_intents` 补充正交方向；`resolve_intent` 关闭已验证/否证的 Intent。
- `note` 记录关键决策。

# 轮次
先看图与意图 → 同一时刻最多 1 个 Task → 等它结束并读回结果 → 写图 → 一句话结束本轮。
禁止只派后台任务就收工；没有子任务回传就不要结束本轮。必要时自己 http_request / run_cmd，不要干等。

# 输出
可用工具：{tool_list}；另有 Task / TodoWrite / Read/Write/Grep/Glob。
工作目录：{workspace}。
"""


_GOAL_BLOCKS = {
    "redteam": (
        "红队最高指令是拿到服务器 shell（RCE / webshell / 反弹等）后 `report_shell`，即完成本项目。\n"
        "工作循环：测试 → 验证 → `report_finding`（高危/严重）→ 推向命令执行；尚未 GETSHELL 则对下一活体面再来一圈。\n"
        "高危/严重发现是推进手段，不单独收工；不要因为已有一条已验证洞就停测其它活体面。"
    ),
    "flag": (
        "唯一终极目标是夺齐正确 flag（正确数 ≥ flag_count）。\n"
        "getshell / 读文件 / SQLi 都是手段：一旦有能力立刻定位 flag 并 `report_flag`。\n"
        "已提交且得分的 flag 算进度；未齐必须继续；齐了立即收工。平台扣分/总分差不是漏旗，不要为此占槽。\n"
        "本题必有解，禁止超级大字典撞库或撞哈希。"
    ),
}
_GOAL_BLOCKS["getshell"] = _GOAL_BLOCKS["redteam"]
_GOAL_TOOL_HINTS = {
    "redteam": (
        "- `report_shell`：确认命令执行后上报，即收工。\n"
        "- `report_finding`：验证真实性后再报（evidence 或可复现 PoC）；标二次验证；给红队评级及理由。finding 不收工。"
    ),
    "flag": (
        "- `report_flag`：拿到 flag 立即上报。未齐正确 flag 继续；齐了立即收工。\n"
        "- `report_shell`：拿到命令执行时上报，然后继续定位 flag。"
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
            "已知 HTTP 入口先打；同时 nmap --top-ports 1000 找其它服务，"
            "目录先中型字典。禁止开局 -p- 或 large 路径表。"
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
        scope_desc = (
            f"- 作业对象：{tdesc}{ip_hint}{sub}。"
            f"主入口是当前目标的 host:port；本题其它入口同样在范围内；邻题入口（其它 unique_code 的 IP/端口）越界。"
        )
    else:
        scope_desc = "- 作业对象：见本轮指令。"
    obj = objective if objective in _GOAL_BLOCKS else "redteam"
    if obj == "getshell":
        obj = "redteam"
    agents = build_subagents(obj)
    subagent_list = "、".join(f"`{k}`" for k in agents)
    tool_list = ", ".join(tool_names(obj))
    frags = _flag_fragments(obj)
    return SYSTEM_PROMPT_TMPL.format(
        scope_desc=scope_desc, tool_list=tool_list, workspace=workspace,
        goal_block=_GOAL_BLOCKS[obj], goal_tool_hint=_GOAL_TOOL_HINTS[obj],
        subagent_list=subagent_list or "（无）", brief_block=_brief_block(brief),
        **frags,
    )


def builtin_fs_tools(objective: str = "getshell") -> list[str]:
    """子智能体/指挥官共用的本地文件工具。flag 赛道不含 WebSearch。"""
    tools = ["Read", "Write", "Edit", "Grep", "Glob", "TodoWrite"]
    if not objective_allows_flag(objective):
        tools.append("WebSearch")
    return tools


def builtin_allowed_tools(objective: str = "getshell") -> list[str]:
    return builtin_fs_tools(objective) + ["Task"]


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
你是指挥官：规划 → Task 并行委派 → 写图 → 决策下一步。
{task_hint}
{open_line}
- 同一证据组合只短验证一次；失败调用 `resolve_intent`。
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
    if steering:
        if has_human:
            steer_head = (
                "纠偏与硬约束（本轮对话框有真人输入：真人覆盖顾问；"
                "其余顾问指令仍须执行，不是评语）"
            )
        else:
            steer_head = (
                "纠偏与硬约束（顾问=人工指令，必须执行，不是评语。"
                "仅当本轮对话框另有真人输入时，真人覆盖顾问）"
            )
        steer_block = f"\n## {steer_head}\n{steering}\n"
    evo_block = f"\n{evolution}\n" if (evolution or "").strip() else ""
    brief_line = f"\n## 题目简报\n{brief}\n" if brief else ""
    tgt = target or "见作业对象"
    addrs = [str(a).strip() for a in (entry_addrs or []) if str(a).strip()]
    if addrs:
        tgt = tgt + "；本题入口 " + "、".join(addrs)
    postex_hint = ""
    if postex_phase == "active":
        if objective_allows_flag(objective):
            postex_hint = (
                "\n- 【后渗透】已有立足点：剩余目标多半不在本容器。"
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
            "- 早期：HTTP 入口返回拦截/过滤页。并行 `recon` + `web-exploit`，换方法与通道探测，"
            "不要结案去枚举目录。\n"
        )
    elif _surface_turn_hints(entry_surface) or "入口 URL：" in (brief or ""):
        early = (
            "- 早期：已知 HTTP 入口先委派 `web-exploit` 打活体面；并行 `recon`："
            "nmap --top-ports 1000 找其它服务，目录先中型字典（medium / raft-medium）。"
            "禁止开局 -p- 或 large/big 路径表，禁止把整轮只耗在扫描。\n"
        )
    else:
        early = (
            "- 早期：并行 `recon` + `web-exploit`。"
            "recon 先常见口/中型字典，禁止开局全端口或 large 路径表。\n"
        )
    early += _surface_turn_hints(entry_surface)
    if objective_allows_flag(objective):
        goal_line = f"对作业对象持续推进，直到夺齐正确 flag。目标：{tgt}"
        task_hint = (
            early
            + "- 已有读取/RCE：立即委派 `flag-hunt`，拿到就 report_flag。\n"
            "- 本题必有解：禁止超级大字典撞库/撞哈希；个位数默认口令失败就回到已验证通道抽数据。\n"
            "- 未齐：继续夺剩余 flag。\n"
            "- flag 数齐立即收工换题（总分差不是漏旗）。" + postex_hint
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
            "- 【强制执行】顾问指令等同对话框人工输入。"
            "本轮只推进「本轮必须推进」列出的 Intent，只委派硬约束允许的子智能体与战术。"
            "列出多条 Intent 时同一时刻只派 1 个 Task，上一个结束后再派下一条；不要一次叉出多个子进程。"
            "禁止另开目录枚举、其它开放前沿、或硬约束未点名的 Task。"
            "禁止把顾问方案当评语跳过。\n"
        )
        if postex_hint:
            task_hint += postex_hint.lstrip("\n") + ("\n" if not postex_hint.endswith("\n") else "")
        open_line = "- 【强制】不要另开与硬约束无关的 Task。"
        empty_intents = "（无——执行硬约束允许的战术；禁止自行改打开放前沿）"
    else:
        open_line = "- 优先开 1 个正交 Task；结束再开下一个。"
        empty_intents = "（无——请先按入口形态委派 recon + protocol-model / reverse 或 web-exploit）"
        if looks_like_served_binary("", "", brief or ""):
            empty_intents = "（无——请先委派 reverse 分析下发的可执行文件，不要开局扫目录）"
        elif kind not in ("interactive", "mixed"):
            if _surface_turn_hints(entry_surface) or "入口 URL：" in (brief or ""):
                empty_intents = (
                    "（无——请先委派 web-exploit 打入口，并行 recon："
                    "top-1000 端口 + 中型目录，不要开局全端口或大字典）"
                )
            else:
                empty_intents = "（无——请先并行委派 recon + web-exploit）"
    return TURN_TMPL.format(
        turn=turn, goal_line=goal_line, graph_summary=graph_summary or "（空，尚未开始）",
        intents=intents or empty_intents,
        steering=steer_block, task_hint=task_hint,
        brief_line=brief_line, evolution=evo_block, open_line=open_line,
    )


def build_subagents(objective: str = "getshell") -> dict[str, AgentDefinition]:
    sub_tools = tool_names(objective) + builtin_fs_tools(objective)
    allows_flag = objective_allows_flag(objective)
    if allows_flag:
        lateral_tail = "每阶段拿到 flag 立即 report_flag。"
    else:
        lateral_tail = "推进直至 report_shell（getshell）即收工。"
    ctf_no_mega = (
        "本题必有解：禁止 rockyou / 千万级词表 / hashcat 全库去撞哈希或登录；"
        "个位数默认口令失败不要升级字典。"
        if allows_flag else ""
    )
    common_tail = (
        "你是执行层子智能体：只实施被委派的任务，完成后用简短结论回报。"
        "不要再使用 Task。命令用 mcp__atkbrain__run_cmd，Web 用 mcp__atkbrain__http_request；"
        "发现写入攻击图；严格遵守作业对象；遇蜜罐用 mark_honeypot。"
        "禁止破坏性写入。动手前先读 workspace/shells.json 与 workspace/post-exploit/creds_*.json。"
        + ctf_no_mega
    )
    recon_nmap = (
        "已知 HTTP 入口仍要做一次 nmap --top-ports 1000 找其它服务，"
        "目录先中型字典；不要开局 -p- 或 large 表。"
    )
    agents: dict[str, AgentDefinition] = {
        "recon": AgentDefinition(
            description="信息收集：端口/服务/指纹/目录/子域/JS 接口/参数。",
            prompt=("你是信息收集专家。系统化收集端口、服务、Web 指纹、目录、JS 接口；每个信息点建成攻击图节点。"
                    "不要一上来全端口或大字典路径爆破。"
                    "端口：先常见口 / nmap --top-ports 1000，确认活体后再考虑全端口。"
                    "目录与文件：跳过 small/common，先中型字典（medium / raft-medium），"
                    "中型无新命中或仍有明确未覆盖面再上 large/big；必须 timeout，同一面只升一档。"
                    + recon_nmap + common_tail),
            tools=sub_tools, model="inherit",
        ),
        "web-exploit": AgentDefinition(
            description="Web 漏洞利用：SQLi/XSS/SSRF/SSTI/XXE/LFI/上传/命令注入/反序列化/越权。",
            prompt=("你是 Web 漏洞利用专家。针对给定攻击面做探测与实弹验证，优先通往 RCE/读文件/越权；"
                    "确认漏洞 report_finding 附真实 PoC。"
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
                    "已验证读文件/RCE 本轮收口，不要回头扫目录。"
                    "拿到 POSIX `id`/`whoami` 命令执行回显后立即 report_shell，不要只在对话里写「已确认」。"
                    "HTTP 拦截页做多通道探测，不要结案去枚举目录。"
                    "只打本题入口 host:port，邻题 IP/端口不是横向。"
                    + common_tail),
            tools=sub_tools, model="inherit",
        ),
        "protocol-model": AgentDefinition(
            description="交互协议建模与下发二进制分析：会话重建变换，或静态/符号求解。",
            prompt=(
                "你负责非 HTTP 交互服务，以及服务端下发的可执行文件/固件/字节码/自定义 VM。"
                "交互口：先短连记下完整输入输出，在工作区写脚本，用已装的 pwntools / z3 / gmpy2 / pycryptodome / sympy "
                "在本地重建变换，再按模型自适应查询。"
                "若入口提供可执行文件：先下载到工作区，file/strings/objdump/radare2 静态分析，再用上述库符号求解。"
                "不要把这类服务当网站做目录枚举或 hop_auth。"
                "验证输出后立刻 report_flag 或 report_finding。"
                + common_tail
            ),
            tools=sub_tools, model="inherit",
        ),
        "reverse": AgentDefinition(
            description="下载并逆向服务端二进制：静态分析 + 符号求解，不要当网站扫。",
            prompt=(
                "你负责服务端下发的可执行文件/固件/字节码/自定义 VM。"
                "先下载到工作区，file/strings/objdump/radare2 静态分析，"
                "再用 pwntools / z3 / gmpy2 / pycryptodome / sympy 符号求解访问码或变换。"
                "不要目录枚举、不要当网站打。"
                "解出凭据立刻 report_flag 或 report_finding。"
                + common_tail
            ),
            tools=sub_tools, model="inherit",
        ),
        "rce-hunt": AgentDefinition(
            description="把已确认漏洞转化为命令执行。",
            prompt=("你是拿 shell 专家。围绕已确认漏洞落地 RCE/webshell。"
                    "拿到执行权限后立即 report_shell。" + common_tail),
            tools=sub_tools, model="inherit",
        ),
        "privesc": AgentDefinition(
            description="本机提权。",
            prompt=("你是提权专家。本机枚举 → 找提权向量 → 提权。"
                    "提权路径建成 ESCALATES_TO 边；凭证 add_node(type=credential)。" + common_tail),
            tools=sub_tools, model="inherit",
        ),
        "lateral": AgentDefinition(
            description="横向：立足后跟进内网跳板、凭证复用、下一台主机。",
            prompt=(
                "你是横向移动专家。基于已泄露的内网地址/凭证（先读 shells.json 与 creds_*.json），"
                "仅在作业对象内探测下一跳。"
                "踏上新主机时 report_shell 填 host。" + lateral_tail + common_tail
            ),
            tools=sub_tools, model="inherit",
        ),
    }
    if allows_flag:
        agents["flag-hunt"] = AgentDefinition(
            description="夺旗：在已有读取/RCE 下快速取出 flag。",
            prompt=(
                "你是夺旗专家。目标是找到 flag（形如 flag{...}）。"
                "用小输出命令。找到后立即 mcp__atkbrain__report_flag。"
                "禁止超级大字典撞库；从已验证读/注入通道取数据。" + common_tail
            ),
            tools=sub_tools, model="inherit",
        )
    return agents
