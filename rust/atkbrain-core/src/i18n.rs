//! 界面语言、接口文案和报告标签。只区分 zh 与 en。

use std::cell::Cell;
use std::collections::HashMap;

thread_local! {
    static LOCALE: Cell<&'static str> = Cell::new("zh");
    static REPORT_LANG: Cell<&'static str> = Cell::new("zh");
}

/// `en` / `en-US` / `en_GB` 都是 en，其余（含空）是 zh。
pub fn normalize_locale(raw: Option<&str>) -> &'static str {
    let folded = raw.unwrap_or("").trim().to_lowercase().replace('_', "-");
    if folded.starts_with("en") {
        "en"
    } else {
        "zh"
    }
}

pub fn set_locale(raw: Option<&str>) -> &'static str {
    let lang = normalize_locale(raw);
    LOCALE.with(|slot| slot.set(lang));
    lang
}

pub fn get_locale() -> &'static str {
    normalize_locale(Some(LOCALE.with(|slot| slot.get())))
}

pub fn set_report_lang(raw: Option<&str>) -> &'static str {
    let lang = normalize_locale(raw);
    REPORT_LANG.with(|slot| slot.set(lang));
    lang
}

pub fn get_report_lang() -> &'static str {
    normalize_locale(Some(REPORT_LANG.with(|slot| slot.get())))
}

/// 猎面输出锁定中文。传入的配置不再生效。
pub fn config_output_lang<T>(_cfg: T) -> &'static str {
    "zh"
}

/// 界面语言锁定中文，不读 Accept-Language 或 X-Locale。
pub fn locale_from_request<T>(_request: T) -> &'static str {
    "zh"
}

fn choose_lang(explicit: Option<&str>, current: &str) -> &'static str {
    match explicit {
        Some(value) if !value.is_empty() => normalize_locale(Some(value)),
        _ => normalize_locale(Some(current)),
    }
}

fn is_ident(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {
            chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        }
        _ => false,
    }
}

fn lookup_var<'a>(vars: &[(&str, &'a str)], name: &str) -> Option<&'a str> {
    vars.iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

/// Python `str.format` 的命名占位符。失败返回 None，调用方保留原文。
fn fill_named(text: &str, vars: &[(&str, &str)]) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                if bytes.get(i + 1) == Some(&b'{') {
                    out.push('{');
                    i += 2;
                    continue;
                }
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'}' && bytes[j] != b'{' {
                    j += 1;
                }
                if bytes.get(j) != Some(&b'}') {
                    return None;
                }
                let name = text.get(start..j)?;
                if !is_ident(name) {
                    return None;
                }
                out.push_str(lookup_var(vars, name)?);
                i = j + 1;
            }
            b'}' => {
                if bytes.get(i + 1) == Some(&b'}') {
                    out.push('}');
                    i += 2;
                    continue;
                }
                return None;
            }
            _ => {
                let ch = text.get(i..)?.chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Some(out)
}

fn apply_vars(text: &str, vars: &[(&str, &str)]) -> String {
    if vars.is_empty() {
        return text.to_string();
    }
    fill_named(text, vars).unwrap_or_else(|| text.to_string())
}

fn row(
    table: &'static [(&'static str, &'static str, &'static str)],
    key: &str,
) -> Option<(&'static str, &'static str)> {
    table
        .iter()
        .find(|item| item.0 == key)
        .map(|item| (item.1, item.2))
}

fn pick<'a>(loc: &str, zh: &'a str, en: &'a str, key: &'a str) -> &'a str {
    let primary = if loc == "en" { en } else { zh };
    if !primary.is_empty() {
        primary
    } else if !zh.is_empty() {
        zh
    } else {
        key
    }
}

const MESSAGES: &[(&str, &str, &str)] = &[
    ("project_missing", "项目不存在", "Project not found"),
    ("export_missing", "导出任务不存在", "Export job not found"),
    ("export_file_missing", "报告文件不存在", "Report file not found"),
    ("export_not_ready", "报告尚未生成完成", "Report is not ready yet"),
    ("finding_missing", "发现不存在", "Finding not found"),
    ("finding_rejected", "已驳回的漏洞不提供完整报告", "Rejected findings have no full report"),
    ("md_gone", "项目总报告请改用 HTML 或 PDF 导出", "Project reports are HTML or PDF only"),
    ("format_html_pdf", "format 仅支持 html|pdf", "format must be html or pdf"),
    ("format_md", "format 仅支持 md", "format must be md"),
    ("job_queued", "专职导出 Pi 排队中…", "Export Pi queued…"),
    ("job_facts", "收集项目事实与漏洞页…", "Collecting project facts…"),
    ("job_cache", "命中缓存，跳过专职导出 Pi…", "Cache hit; skipping export Pi…"),
    ("job_writing", "专职导出 Pi 正在撰写封面与漏洞卡片…", "Export Pi is writing cover and finding cards…"),
    ("job_slots", "专职导出 Pi 正在撰写槽位…", "Export Pi is filling slots…"),
    ("job_bad_json", "专职导出 Pi 未返回可用槽位 JSON", "Export Pi did not return usable slot JSON"),
    ("job_pi_fail", "专职导出 Pi 撰写失败：{err}", "Export Pi failed: {err}"),
    ("job_shell", "套入母版槽位…", "Assembling the shell…"),
    ("job_write", "写入报告…", "Writing the report…"),
    ("job_pdf", "渲染 PDF…", "Rendering PDF…"),
    ("job_done", "报告已生成", "Report ready"),
    ("job_done_pi", "报告已生成（专职导出 Pi 已撰写）", "Report ready (export Pi wrote the slots)"),
    ("job_done_cache", "报告已生成（命中缓存）", "Report ready (cache)"),
    ("job_fail", "失败：{err}", "Failed: {err}"),
    ("missing", "未采集", "Not collected"),
    ("auth_fail", "验证失败", "Verification failed"),
    ("llm_key_missing", "未配置大模型密钥。在设置 → 模型里填写 API Key 并保存，或在项目目录 .env 填写 DEEPSEEK_API_KEY 后执行 docker compose up -d。", "No model API key. Fill in the API key under Settings → Model and save, or set DEEPSEEK_API_KEY in the project .env and run docker compose up -d."),
    ("password_wrong", "口令错误", "Wrong password"),
    ("review_busy", "该漏洞这项复核正在进行", "This finding already has that review running"),
    ("review_mode", "mode 须为 secondary 或 rating", "mode must be secondary or rating"),
    ("review_job_missing", "复核任务不存在", "Review job not found"),
    ("hs.unlimited", "不限", "unlimited"),
    ("hs.retry", "回合内 {hang}无思考/工具/命令 → 打断本回合；连续 2 次卡死或连续 5 个空回合 → 结束本 run 并自动重开新会话（项目不记失败）", "{hang} with no thought, tool, or command in a turn → interrupt that turn; two hangs or five empty turns in a row → end this run and open a new session (the project is not marked failed)"),
    ("hs.wall_fail", "墙钟满 {cap} → 记失败", "Wall clock hits {cap} → mark failed"),
    ("hs.src_stall", "连续 {n} 轮无高质量进展 → 暂停，可再开", "{n} rounds with no high-quality progress in a row → pause, can resume"),
    ("hs.entry_down", "入口连续 {dur} TCP 不可达（探 80/443/登记端口，超时/拒绝/DNS）→ 暂停，站点恢复后可再开", "Entry TCP unreachable for {dur} (probe 80/443/registered port; timeout/refuse/DNS) → pause, resume when the site is back"),
    ("hs.turns_fail", "满 {turns} 轮 → 记失败", "{turns} rounds → mark failed"),
    ("hs.src_label_turns", "硬停：满 {turns} 轮或墙钟满 {cap}，记失败。已验证高危/严重不停工。", "Hard stop: {turns} rounds or a {cap} wall clock marks failure. Verified high/critical does not stop the hunt."),
    ("hs.empty_rounds", "连续 {n} 轮没有新节点也没有新漏洞 → 记失败", "{n} rounds in a row with no new node and no new finding → mark failed"),
    ("hs.manual", "手动停止", "Manual stop"),
    ("hs.src_label", "硬停：墙钟满 {cap}，或连续 {n} 轮没有新节点也没有新漏洞。其余只接受手动停止。", "Hard stop: {cap} wall clock, or {n} rounds with no new node and no new finding. Otherwise only a manual stop."),
    ("hs.ctf_wall", "本遍墙钟满 {cap} → 记失败", "This pass’s wall clock hits {cap} → mark failed"),
    ("hs.ctf_idle", "连续 {n} 个御主方案无图增长（无新节点/交旗/本地长计算）→ 记失败", "{n} master plans in a row with no graph growth (no new node / flag / local long compute) → mark failed"),
    ("hs.ctf_entry", "入口连续 {dur} 不可达且已尝试重绑 → 暂停让槽，可再开", "Entry unreachable for {dur} after rebind attempts → pause and yield the slot, can resume"),
    ("hs.ctf_env", "评测环境到期或平台不可达 → 停止（不把整场标失败）", "Bench expired or platform unreachable → stop (do not mark the whole run failed)"),
    ("hs.ctf_label", "硬停：本遍墙钟 {cap}；连续 {n} 个御主方案无增长记失败。不限轮次。", "Hard stop: this pass’s wall clock is {cap}; {n} idle master plans mark failure. No turn cap."),
    ("hs.red_stall", "已升到第 3 圈后，连续 {n} 轮无高质量进展 → 暂停，可再开", "After ring 3, {n} rounds with no high-quality progress in a row → pause, can resume"),
    ("hs.red_label", "硬停：墙钟满 {cap}，或连续 {n} 轮没有新节点也没有新漏洞。拿到 shell 提前收工。其余只接受手动停止。", "Hard stop: {cap} wall clock, or {n} rounds with no new node and no new finding. A shell finishes early. Otherwise only a manual stop."),
];

/// 接口与任务文案。`lang` 为 None 或空串时用当前线程语言。占位符对不上就保持原文。
pub fn msg(key: &str, lang: Option<&str>, vars: &[(&str, &str)]) -> String {
    let loc = choose_lang(lang, get_locale());
    let text = match row(MESSAGES, key) {
        Some((zh, en)) => pick(loc, zh, en, key),
        None => key,
    };
    apply_vars(text, vars)
}

const CONTRACT_ZH: &str = r#"
# 输出语言
人可见文本必须用中文：对话、时间线思考、report_finding 的 title/description/report_summary/report_impact/report_rating/report_repro/report_fix、御主方案、记忆蒸馏。
本系统提示仍是中文，照做即可。
证据、命令、URL、payload、CVE、目标站回显必须原文保留。不要把英文套话写进人可见字段（引用目标站原文除外）。
"#;

const CONTRACT_EN: &str = r#"
# Output language
All human-visible text MUST be in English: chat replies, timeline thoughts, report_finding title/description/report_summary/report_impact/report_rating/report_repro/report_fix, supervisor plans, and distilled memory.
This system prompt remains Chinese — follow it, but emit English.
Keep evidence, commands, URLs, payloads, CVEs, and target-site output verbatim. Do not mix Chinese into human-visible fields except when quoting the target.
"#;

pub fn output_lang_contract(lang: Option<&str>) -> &'static str {
    if normalize_locale(lang) == "en" {
        CONTRACT_EN
    } else {
        CONTRACT_ZH
    }
}

pub fn with_output_lang(prompt: Option<&str>, lang: Option<&str>) -> String {
    let body = prompt.unwrap_or("").trim_end();
    let contract = output_lang_contract(lang);
    let mut out = String::with_capacity(body.len() + 1 + contract.len());
    out.push_str(body);
    out.push('\n');
    out.push_str(contract);
    out
}

/// 与 backend/atkbrain/report/slots.py 的 PROMPT_REV 相同。
const PROMPT_REV: &str = "2026.09.02.1";

const EXPORT_SYSTEM_EN: &str = r#"You are StrikeAgent_AtkBrain-Flash's dedicated deliverable writer Pi (role=report-export).
You are not the hunter, not the finding re-verifier, and not the evolve editor. You only turn confirmed facts into report slots.
Prompt revision {rev}. The shell is fixed: cover tag/h1/meta, executive summary grid, 8 KPIs, bar chart + verification ring, path-board, asset cards, index table, vf cards (1 summary/root cause, 2 exploitation, 3 fix now/root). Fill text only. Do not emit a full HTML page, <style>, or layout changes.

Output JSON only:
{{
  "title_line": "cover main title (org or project name)",
  "title_accent": "domain or target, may be empty",
  "sub": "one or two cover sentences; may mention entry and whether access was obtained",
  "goal_text": "if access was obtained write \"Access obtained\", else empty string",
  "goal_detail": "one-sentence access footnote, may be empty",
  "summary_overview": "left executive-summary HTML (p/ul/li/b/code/span); write the attack chain, no product name",
  "summary_conclusions": "right executive-summary HTML, prefer <ul class=\"concl\"><li><span class=\"tag-sev crit|high|med\">severity</span><span>conclusion</span></li></ul>",
  "verify_note": "verification note as plain text",
  "path_note": "one sentence for the attack-path section intro and caption",
  "findings": {{
    "vuln-01": {{
      "intro": "1 summary / technical root cause (paragraphs separated by newlines)",
      "impact": "impact (appended after intro)",
      "steps": ["2 exploitation steps"],
      "prerequisites": "one-sentence prerequisites",
      "fixes_now": ["immediate mitigations"],
      "fixes_root": ["root fixes"],
      "fixes": ["if now/root are not split, this list is ok"],
      "verify": "one-sentence fix verification"
    }}
  }}
}}

Hard rules
- Use the facts pack only. If missing, write "Not collected". Do not invent URLs / payloads / CVEs.
- Prefer rewriting report_summary / report_impact / report_rating / report_repro / report_fix from the facts pack into English. Do not invent a second story. If those five fields are absent, write from evidence and mark the intro as not yet re-verified.
- No internal engine fields, timeline, appendix, or product names.
- Critical/high must fully cover intro, exploitation, and fix.
- Finding keys must be the facts-pack slot_id (vuln-01 …).
- All prose in the JSON values MUST be English. Keep evidence, URLs, payloads, commands, and CVE IDs verbatim.
"#;

pub fn export_system_prompt(lang: Option<&str>, chinese_system: &str) -> String {
    if normalize_locale(lang) == "en" {
        apply_vars(EXPORT_SYSTEM_EN, &[("rev", PROMPT_REV)])
    } else {
        chinese_system.to_string()
    }
}

const CATALOG: &[(&str, &str, &str)] = &[
    ("html_lang", "zh-CN", "en"),
    ("brand", "授权渗透测试交付报告", "Authorized Penetration Test Report"),
    ("doc_suffix", "授权渗透测试交付报告", "Authorized Penetration Test Report"),
    ("authorized", "授权项目", "Authorized project"),
    ("cluster_target", "（集群 / 多资产）", "(cluster / multi-asset)"),
    ("missing", "未采集", "Not collected"),
    ("missing_p", "<p>未采集。</p>", "<p>Not collected.</p>"),
    ("uncat", "未分类", "Uncategorized"),
    ("untitled", "未命名漏洞", "Untitled finding"),
    ("intel", "情报记录", "Intel note"),
    ("sev.critical", "严重", "Critical"),
    ("sev.high", "高危", "High"),
    ("sev.medium", "中危", "Medium"),
    ("sev.low", "低危", "Low"),
    ("sev.info", "信息", "Info"),
    ("verify.verified", "已验证", "Verified"),
    ("verify.pending", "待复验", "Pending"),
    ("verify.flaky", "待复验", "Pending"),
    ("kind.target", "目标", "Target"),
    ("kind.service", "服务", "Service"),
    ("kind.host", "主机", "Host"),
    ("kind.endpoint", "入口", "Entry"),
    ("kind.info", "资产", "Asset"),
    ("pn.target", "入口", "Entry"),
    ("pn.service", "服务", "Service"),
    ("pn.danger", "缺陷", "Flaw"),
    ("pn.vuln", "漏洞", "Finding"),
    ("pn.foothold", "立足点", "Foothold"),
    ("pn.goal", "权限", "Access"),
    ("pn.info", "节点", "Node"),
    ("pn.host", "主机", "Host"),
    ("pn.endpoint", "入口", "Entry"),
    ("sec01", "执行摘要", "Executive Summary"),
    ("sec01en", "Executive Summary", ""),
    ("sec02", "漏洞统计分布", "Severity & Verification"),
    ("sec02en", "Severity & Verification", ""),
    ("sec03", "关键攻击路径", "Attack Path"),
    ("sec03en", "Attack Path", ""),
    ("sec04", "资产画像", "Assets in Scope"),
    ("sec04en", "Assets in Scope", ""),
    ("sec05", "漏洞清单总表", "Findings Index"),
    ("sec05en", "Findings Index", ""),
    ("sec06", "严重漏洞", "Critical Findings"),
    ("sec06en", "Critical Findings", ""),
    ("sec07", "高危漏洞", "High Findings"),
    ("sec07en", "High Findings", ""),
    ("sec08", "中危漏洞", "Medium Findings"),
    ("sec08en", "Medium Findings", ""),
    ("sec09", "低危漏洞", "Low Findings"),
    ("sec09en", "Low Findings", ""),
    ("second_yes", "已二次验证", "Re-verified"),
    ("second_no", "未二次验证", "Not re-verified"),
    ("count_items", "{n} 项", "{n} items"),
    ("bar.critical", "严重 critical", "Critical"),
    ("bar.high", "高危 high", "High"),
    ("bar.medium", "中危 medium", "Medium"),
    ("bar.low", "低危 low", "Low"),
    ("chart.sev_aria", "漏洞严重度分布", "Severity distribution"),
    ("chart.verify_aria", "验证状态分布", "Verification status"),
    ("chart.total", "漏洞总数", "Findings"),
    ("chart.sev_title", "严重度分布（{n} 项发现）", "Severity ({n} findings)"),
    ("chart.sev_note", "严重/高危合计 {hot} 项，占 {pct}%。", "Critical/high together: {hot} ({pct}%)."),
    ("chart.verify_title", "验证状态分布", "Verification status"),
    ("chart.node_records", "节点级记录", "Node-level notes"),
    ("n_items", "{n} 条", "{n}"),
    ("auth_target", "授权目标", "Authorized target"),
    ("path.next", "进入下一跳", "Next hop"),
    ("path.expand", "扩展", "Expand"),
    ("path.enter", "进入", "Enter"),
    ("path.exploit", "利用", "Exploit"),
    ("path.lateral", "横向", "Lateral"),
    ("path.privesc", "提权", "Privilege"),
    ("path.land", "落地", "Land"),
    ("path.note", "路径由授权范围内已验证环节串联，不含推测跳步。", "Path links verified in-scope steps only; no guessed hops."),
    ("path.leg_crit", "关键缺陷节点", "Critical flaw nodes"),
    ("path.leg_warn", "过渡 / 扩展节点", "Transition / expand nodes"),
    ("path.leg_info", "情报与服务节点", "Intel and service nodes"),
    ("path.leg_goal", "权限落地目标", "Access objective"),
    ("asset", "资产", "Asset"),
    ("asset.main", "授权主目标", "Primary authorized target"),
    ("asset.map", "资产关系图", "Asset map"),
    ("asset.map_sub", "授权范围内主要测绘对象，共 <b>{n}</b> 条。", "Main in-scope objects, <b>{n}</b> total."),
    ("asset.scope", "授权范围内识别 {n} 项资产 / 服务。", "{n} in-scope assets / services identified."),
    ("asset.rest", "其余资产：", "Other assets:"),
    ("idx.jump", "跳转", "Go"),
    ("idx.sev", "严重度", "Severity"),
    ("idx.title", "漏洞 / 发现", "Finding"),
    ("idx.cat", "类型", "Type"),
    ("idx.status", "状态", "Status"),
    ("idx.anchor", "锚点", "Anchor"),
    ("missing_steps", "未采集可执行复现步骤；请结合证据区原始请求复核。", "No executable reproduction steps collected; review the raw request in evidence."),
    ("fix.now", "立即缓解", "Immediate mitigation"),
    ("fix.root", "根治", "Root cause"),
    ("fix.default1", "关闭不必要的暴露面。", "Close unnecessary exposure."),
    ("fix.default2", "对相关接口实施鉴权与最小权限。", "Enforce authentication and least privilege on related interfaces."),
    ("fix.verify", "修复后按「②利用」逐步复测，关键请求应失败或不再回显敏感数据。", "After the fix, re-run the exploitation steps; the key request should fail or no longer leak sensitive data."),
    ("fix.baseline", "纳入基线：复杂度策略、最小权限与暴露面收敛。", "Baseline: complexity policy, least privilege, and reduced exposure."),
    ("precond", "攻击前置条件见验证证据、PoC 与关联节点。", "Prerequisites are in the evidence, PoC, and related nodes."),
    ("impact_default", "影响以已验证证据为准；应结合关联资产与权限边界进行复核。", "Impact is limited to verified evidence; re-check asset and privilege boundaries."),
    ("label.precond", "前置条件：", "Prerequisites:"),
    ("label.impact", "影响：", "Impact:"),
    ("ev.evidence", "证据", "Evidence"),
    ("ev.detail", "验证细节", "Verification detail"),
    ("ev.url", "证明 URL", "Proof URL"),
    ("ev.curl", "PoC curl", "PoC curl"),
    ("ev.http", "原始 HTTP", "Raw HTTP"),
    ("ev.steps", "复现步骤", "Reproduction steps"),
    ("ev.missing", "未采集可展示证据。", "No displayable evidence collected."),
    ("ev.summary", "证据 / PoC 复现（点击展开）", "Evidence / PoC (click to expand)"),
    ("vf.type", "类型", "Type"),
    ("vf.status", "状态", "Status"),
    ("vf.intro", "简介 / 技术成因", "Summary / root cause"),
    ("vf.exploit", "利用方式（编号分步复现）", "Exploitation (numbered steps)"),
    ("vf.fix", "修复方式", "Remediation"),
    ("kpi.got_access", "已获取权限", "Access obtained"),
    ("kpi.no_access", "尚未获取权限", "Access not obtained"),
    ("kpi.total", "漏洞发现总数", "Findings"),
    ("kpi.crit", "严重 Critical", "Critical"),
    ("kpi.high", "高危 High", "High"),
    ("kpi.medlow", "中危 / 低危", "Medium / Low"),
    ("kpi.svc", "服务节点", "Service nodes"),
    ("kpi.fixnow", "建议立即整改项", "Fix now"),
    ("sum.left", "测试概况与结论", "Overview and conclusions"),
    ("sum.right", "关键结论", "Key conclusions"),
    ("sum.verify", "验证说明：", "Verification note:"),
    ("sum.overview", "对授权目标 <code>{target}</code> 开展授权渗透测试。共登记 {total} 项风险，其中严重 {crit} 项、高危 {high} 项。{shell}</p>", "Authorized test of <code>{target}</code>. {total} issues recorded, including {crit} critical and {high} high. {shell}</p>"),
    ("sum.shell_yes", "测试过程中已证实可获取目标服务器权限。", "Server access was demonstrated during the test."),
    ("sum.shell_no", "测试过程中尚未证实服务器权限落地。", "Server access was not demonstrated."),
    ("sum.note", "全部验证以最小影响方式执行，未改动业务数据。漏洞分级：严重 = 可直接导致权限失陷或平台接管；高危 = 可直接导致数据泄露或构成命令执行前置面；中低危 = 信息泄露与配置类风险。", "All checks used minimal impact and did not change business data. Severity: Critical = direct access loss or platform takeover; High = data leak or a command-execution precursor; Medium/Low = disclosure and configuration issues."),
    ("sum.empty", "未发现严重或高危项；仍建议复核中低危暴露面。", "No critical or high findings; still review medium/low exposure."),
    ("sum.grade", "整体风险评级：", "Overall risk:"),
    ("sum.grade_mid", "中低", "Medium/Low"),
    ("cover.sub", "{name}授权范围内公开服务面渗透测试。", "Authorized testing of public services in scope for {name}."),
    ("cover.goal", "已获取目标服务器权限", "Target server access obtained"),
    ("cover.goal_extra", "授权验证已证实", "Confirmed by authorized verification"),
    ("cover.entry", "入口目标", "Entry"),
    ("cover.nature", "测试性质", "Engagement"),
    ("cover.nature_v", "授权渗透测试（仅限授权环境）", "Authorized penetration test (in-scope only)"),
    ("cover.verify", "验证结论", "Verification"),
    ("cover.verify_v", "{n} 项已验证", "{n} verified"),
    ("cover.graph", "攻击图", "Attack graph"),
    ("cover.graph_v", "{nodes} 节点 / {edges} 边", "{nodes} nodes / {edges} edges"),
    ("footer.src", "数据来源：授权测试取证记录 · {date}", "Source: authorized test evidence · {date}"),
    ("findings.sub", "{label}项共 {n} 项，每一项均附证据与复现路径。", "{n} {label} items, each with evidence and a reproduction path."),
    ("vf.fix_auth", "对受影响入口实施鉴权、参数校验与最小权限。", "Enforce authentication, input checks, and least privilege on the affected entry."),
    ("vf.fix_pwd", "关闭默认口令与不必要的管理面暴露。", "Disable default passwords and unnecessary admin surfaces."),
    ("vf.fix_iso", "移除或隔离相关危险功能。", "Remove or isolate the dangerous capability."),
];

/// 报告标签。`lang` 为 None 或空串时用当前报告语言。英文空串回落到中文，再没有就返回 key。
pub fn lab(key: &str, lang: Option<&str>, vars: &[(&str, &str)]) -> String {
    let loc = choose_lang(lang, get_report_lang());
    let text = match row(CATALOG, key) {
        Some((zh, en)) => pick(loc, zh, en, key),
        None => key,
    };
    apply_vars(text, vars)
}

pub fn sev_map(lang: Option<&str>) -> HashMap<&'static str, String> {
    HashMap::from([
        ("critical", lab("sev.critical", lang, &[])),
        ("high", lab("sev.high", lang, &[])),
        ("medium", lab("sev.medium", lang, &[])),
        ("low", lab("sev.low", lang, &[])),
        ("info", lab("sev.info", lang, &[])),
    ])
}

pub fn verify_map(lang: Option<&str>) -> HashMap<&'static str, String> {
    HashMap::from([
        ("verified", lab("verify.verified", lang, &[])),
        ("pending", lab("verify.pending", lang, &[])),
        ("flaky", lab("verify.flaky", lang, &[])),
    ])
}

pub fn kind_map(lang: Option<&str>) -> HashMap<&'static str, String> {
    HashMap::from([
        ("target", lab("kind.target", lang, &[])),
        ("service", lab("kind.service", lang, &[])),
        ("host", lab("kind.host", lang, &[])),
        ("endpoint", lab("kind.endpoint", lang, &[])),
        ("info", lab("kind.info", lang, &[])),
    ])
}

pub fn pn_map(lang: Option<&str>) -> HashMap<&'static str, String> {
    HashMap::from([
        ("target", lab("pn.target", lang, &[])),
        ("service", lab("pn.service", lang, &[])),
        ("danger", lab("pn.danger", lang, &[])),
        ("vuln", lab("pn.vuln", lang, &[])),
        ("foothold", lab("pn.foothold", lang, &[])),
        ("goal", lab("pn.goal", lang, &[])),
        ("info", lab("pn.info", lang, &[])),
        ("host", lab("pn.host", lang, &[])),
        ("endpoint", lab("pn.endpoint", lang, &[])),
    ])
}

const SHELL_PAIRS: &[(&str, &str, &str, &str)] = &[
    ("执行摘要", "sec01", "Executive Summary", "sec01en"),
    (
        "漏洞统计分布",
        "sec02",
        "Severity &amp; Verification",
        "sec02en",
    ),
    ("关键攻击路径", "sec03", "Attack Path", "sec03en"),
    ("资产画像", "sec04", "Assets in Scope", "sec04en"),
    ("漏洞清单总表", "sec05", "Findings Index", "sec05en"),
    ("严重漏洞", "sec06", "Critical Findings", "sec06en"),
    ("高危漏洞", "sec07", "High Findings", "sec07en"),
    ("中危漏洞", "sec08", "Medium Findings", "sec08en"),
    ("低危漏洞", "sec09", "Low Findings", "sec09en"),
];

/// `lang` 为空时固定中文，不读报告语言。只替换第一处 `lang="zh-CN"`。
pub fn apply_shell_chrome(html: &str, lang: Option<&str>) -> String {
    let loc = normalize_locale(lang);
    let html_lang = lab("html_lang", Some(loc), &[]);
    let mut out = html.replacen("lang=\"zh-CN\"", &format!("lang=\"{}\"", html_lang), 1);
    let brand = lab("brand", Some(loc), &[]);
    out = out.replace("授权渗透测试交付报告", &brand);
    for &(zh, zk, en_html, ek) in SHELL_PAIRS {
        let heading = lab(zk, Some(loc), &[]);
        out = out.replace(
            &format!("<h2>{}</h2>", zh),
            &format!("<h2>{}</h2>", heading),
        );
        let en_lab = lab(ek, Some(loc), &[]);
        let span = format!("<span class=\"en\">{}</span>", en_html);
        if loc == "en" {
            out = out.replace(&span, "");
            let plain = en_html.replace("&amp;", "&");
            out = out.replace(&format!("<span class=\"en\">{}</span>", plain), "");
        } else if !en_lab.is_empty() {
            out = out.replace(&span, &format!("<span class=\"en\">{}</span>", en_lab));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPECT_EXPORT: &str = r#"You are StrikeAgent_AtkBrain-Flash's dedicated deliverable writer Pi (role=report-export).
You are not the hunter, not the finding re-verifier, and not the evolve editor. You only turn confirmed facts into report slots.
Prompt revision 2026.09.02.1. The shell is fixed: cover tag/h1/meta, executive summary grid, 8 KPIs, bar chart + verification ring, path-board, asset cards, index table, vf cards (1 summary/root cause, 2 exploitation, 3 fix now/root). Fill text only. Do not emit a full HTML page, <style>, or layout changes.

Output JSON only:
{
  "title_line": "cover main title (org or project name)",
  "title_accent": "domain or target, may be empty",
  "sub": "one or two cover sentences; may mention entry and whether access was obtained",
  "goal_text": "if access was obtained write \"Access obtained\", else empty string",
  "goal_detail": "one-sentence access footnote, may be empty",
  "summary_overview": "left executive-summary HTML (p/ul/li/b/code/span); write the attack chain, no product name",
  "summary_conclusions": "right executive-summary HTML, prefer <ul class=\"concl\"><li><span class=\"tag-sev crit|high|med\">severity</span><span>conclusion</span></li></ul>",
  "verify_note": "verification note as plain text",
  "path_note": "one sentence for the attack-path section intro and caption",
  "findings": {
    "vuln-01": {
      "intro": "1 summary / technical root cause (paragraphs separated by newlines)",
      "impact": "impact (appended after intro)",
      "steps": ["2 exploitation steps"],
      "prerequisites": "one-sentence prerequisites",
      "fixes_now": ["immediate mitigations"],
      "fixes_root": ["root fixes"],
      "fixes": ["if now/root are not split, this list is ok"],
      "verify": "one-sentence fix verification"
    }
  }
}

Hard rules
- Use the facts pack only. If missing, write "Not collected". Do not invent URLs / payloads / CVEs.
- Prefer rewriting report_summary / report_impact / report_rating / report_repro / report_fix from the facts pack into English. Do not invent a second story. If those five fields are absent, write from evidence and mark the intro as not yet re-verified.
- No internal engine fields, timeline, appendix, or product names.
- Critical/high must fully cover intro, exploitation, and fix.
- Finding keys must be the facts-pack slot_id (vuln-01 …).
- All prose in the JSON values MUST be English. Keep evidence, URLs, payloads, commands, and CVE IDs verbatim.
"#;

    struct LangGuard {
        locale: &'static str,
        report: &'static str,
    }

    impl LangGuard {
        fn take() -> Self {
            Self {
                locale: get_locale(),
                report: get_report_lang(),
            }
        }
    }

    impl Drop for LangGuard {
        fn drop(&mut self) {
            set_locale(Some(self.locale));
            set_report_lang(Some(self.report));
        }
    }

    fn placeholder_names(text: &str) -> Vec<String> {
        let mut names = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find('{') {
            rest = &rest[start + 1..];
            if rest.starts_with('{') {
                rest = &rest[1..];
                continue;
            }
            let Some(end) = rest.find('}') else { break };
            let name = &rest[..end];
            if !name.is_empty() && !names.iter().any(|have| have == name) {
                names.push(name.to_string());
            }
            rest = &rest[end + 1..];
        }
        names
    }

    fn check_table(
        table: &[(&str, &str, &str)],
        mut render: impl FnMut(&str, Option<&str>, &[(&str, &str)]) -> String,
    ) {
        let mut seen = std::collections::HashSet::new();
        for &(key, zh, en) in table {
            assert!(seen.insert(key), "duplicate {}", key);
            assert!(!zh.is_empty(), "{}", key);
            for &(loc, raw) in &[("zh", zh), ("en", en)] {
                let shown = render(key, Some(loc), &[]);
                let expect = if raw.is_empty() { zh } else { raw };
                assert_eq!(shown, expect, "{}/{}", key, loc);
                let names = placeholder_names(expect);
                if names.is_empty() {
                    continue;
                }
                let values: Vec<String> = (0..names.len()).map(|i| format!("V{}", i)).collect();
                let vars: Vec<(&str, &str)> = names
                    .iter()
                    .zip(&values)
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect();
                let filled = render(key, Some(loc), &vars);
                for (i, name) in names.iter().enumerate() {
                    assert!(
                        filled.contains(&format!("V{}", i)),
                        "{} {} {}",
                        key,
                        loc,
                        name
                    );
                    assert!(
                        !filled.contains(&format!("{{{}}}", name)),
                        "{} {} leftover {}",
                        key,
                        loc,
                        name
                    );
                }
                if vars.len() >= 2 {
                    assert_eq!(
                        render(key, Some(loc), &vars[..1]),
                        expect,
                        "{} {} partial",
                        key,
                        loc
                    );
                }
            }
        }
    }

    #[test]
    fn normalize_locale_aliases() {
        assert_eq!(normalize_locale(Some("en-US")), "en");
        assert_eq!(normalize_locale(Some("EN")), "en");
        assert_eq!(normalize_locale(Some("zh-CN")), "zh");
        assert_eq!(normalize_locale(Some("")), "zh");
        assert_eq!(normalize_locale(None), "zh");
        assert_eq!(normalize_locale(Some("en_GB")), "en");
        assert_eq!(normalize_locale(Some("  EN  ")), "en");
        assert_eq!(normalize_locale(Some("english")), "en");
        assert_eq!(normalize_locale(Some("fr")), "zh");
        assert_eq!(normalize_locale(Some("zh_TW")), "zh");
    }

    #[test]
    fn config_output_lang_locked_zh() {
        assert_eq!(config_output_lang("{\"output_lang\":\"en\"}"), "zh");
        assert_eq!(config_output_lang("{\"output_lang\":\"en-GB\"}"), "zh");
        assert_eq!(config_output_lang(()), "zh");
        assert_eq!(locale_from_request("en"), "zh");
        assert_eq!(locale_from_request(1_u8), "zh");
    }

    #[test]
    fn locale_and_report_lang_are_independent() {
        let _guard = LangGuard::take();
        assert_eq!(set_locale(Some("EN")), "en");
        assert_eq!(get_locale(), "en");
        assert_eq!(set_locale(Some("")), "zh");
        assert_eq!(get_locale(), "zh");
        assert_eq!(set_locale(None), "zh");
        assert_eq!(set_report_lang(Some("en-US")), "en");
        assert_eq!(get_report_lang(), "en");
        assert_eq!(get_locale(), "zh");

        set_locale(Some("en"));
        set_report_lang(Some("zh"));
        assert_eq!(msg("password_wrong", None, &[]), "Wrong password");
        assert_eq!(msg("password_wrong", Some(""), &[]), "Wrong password");
        assert_eq!(msg("password_wrong", Some("zh"), &[]), "口令错误");
        assert_eq!(lab("brand", None, &[]), "授权渗透测试交付报告");
        set_report_lang(Some("en"));
        assert_eq!(
            lab("brand", None, &[]),
            "Authorized Penetration Test Report"
        );
        assert_eq!(
            lab("brand", Some(""), &[]),
            "Authorized Penetration Test Report"
        );
        assert_eq!(lab("brand", Some("zh"), &[]), "授权渗透测试交付报告");
        assert_eq!(msg("password_wrong", None, &[]), "Wrong password");
    }

    #[test]
    fn english_contract_on_prompt() {
        let en = output_lang_contract(Some("en"));
        assert!(en.contains("All human-visible text MUST be in English"));
        assert!(en.contains("This system prompt remains Chinese"));
        assert!(en.contains("report_finding"));
        assert_eq!(output_lang_contract(Some("en-US")), CONTRACT_EN);
        assert_eq!(output_lang_contract(Some("EN")), CONTRACT_EN);
        let wrapped = with_output_lang(Some("SYS  \n"), Some("en"));
        assert!(wrapped.contains("All human-visible text MUST be in English"));
        assert!(wrapped.contains("This system prompt remains Chinese"));
        assert!(wrapped.contains("report_finding"));
        assert_eq!(wrapped, format!("SYS\n{}", CONTRACT_EN));
        assert!(wrapped.starts_with("SYS\n\n# Output language\n"));
    }

    #[test]
    fn chinese_contract_default() {
        let zh = output_lang_contract(None);
        assert!(zh.contains("人可见文本必须用中文"));
        assert_eq!(zh, CONTRACT_ZH);
        assert_eq!(output_lang_contract(Some("zh-CN")), CONTRACT_ZH);
        assert_eq!(output_lang_contract(Some("fr")), CONTRACT_ZH);
        assert_eq!(
            with_output_lang(None, Some("zh")),
            format!("\n{}", CONTRACT_ZH)
        );
        assert_eq!(
            with_output_lang(Some(""), None),
            format!("\n{}", CONTRACT_ZH)
        );
        let wrapped = with_output_lang(Some("提示"), None);
        assert!(wrapped.contains("人可见文本必须用中文"));
        assert!(!wrapped.contains("All human-visible text MUST be in English"));
    }

    #[test]
    fn export_system_english() {
        let en = export_system_prompt(Some("en"), "CHINESE_SYSTEM");
        assert!(en.contains("Not collected"));
        assert!(en.contains("All prose in the JSON values MUST be English"));
        assert!(en.contains("Prompt revision 2026.09.02.1."));
        assert!(!en.contains("{rev}"));
        assert!(!en.contains("{{"));
        assert!(en.contains("write \\\"Access obtained\\\""));
        assert_eq!(en, EXPECT_EXPORT);
        assert_eq!(
            export_system_prompt(Some("en-GB"), "CHINESE_SYSTEM"),
            EXPECT_EXPORT
        );
        assert_eq!(
            export_system_prompt(Some("zh"), "CHINESE_SYSTEM"),
            "CHINESE_SYSTEM"
        );
        assert_eq!(
            export_system_prompt(None, "CHINESE_SYSTEM"),
            "CHINESE_SYSTEM"
        );
        assert_eq!(export_system_prompt(Some(""), "  ZH  "), "  ZH  ");
        assert_eq!(export_system_prompt(Some("fr"), ""), "");
    }

    #[test]
    fn message_and_label_tables() {
        check_table(MESSAGES, |key, lang, vars| msg(key, lang, vars));
        check_table(CATALOG, |key, lang, vars| lab(key, lang, vars));
        assert_eq!(msg("project_missing", Some("zh"), &[]), "项目不存在");
        assert_eq!(msg("project_missing", Some("en"), &[]), "Project not found");
        assert_eq!(msg("no-such-key", Some("en"), &[]), "no-such-key");
        assert_eq!(msg("job_fail", Some("en"), &[("err", "x")]), "Failed: x");
        assert_eq!(
            msg("job_fail", Some("en"), &[("nope", "x")]),
            "Failed: {err}"
        );
        assert_eq!(msg("job_fail", Some("en"), &[]), "Failed: {err}");
        assert_eq!(
            msg("job_fail", Some("en"), &[("err", "{nope}")]),
            "Failed: {nope}"
        );
        assert_eq!(
            msg("job_pi_fail", Some("en"), &[("err", "")]),
            "Export Pi failed: "
        );
        assert_eq!(msg("job_queued", Some("zh"), &[]), "专职导出 Pi 排队中…");
        assert_eq!(msg("job_queued", Some("en"), &[]), "Export Pi queued…");
        assert!(msg("llm_key_missing", Some("zh"), &[]).contains("DEEPSEEK_API_KEY"));
        assert!(msg("llm_key_missing", Some("en"), &[]).contains("DEEPSEEK_API_KEY"));
        assert_eq!(msg("missing", Some("en"), &[]), "Not collected");
        assert_eq!(lab("missing", Some("en"), &[]), "Not collected");
        assert_eq!(lab("sec01en", Some("en"), &[]), "Executive Summary");
        assert_eq!(lab("no-such", Some("zh"), &[("n", "1")]), "no-such");
        assert_eq!(lab("count_items", Some("zh"), &[("n", "3")]), "3 项");
        assert_eq!(lab("count_items", Some("en"), &[("n", "3")]), "3 items");
        assert_eq!(
            lab(
                "sum.overview",
                Some("en"),
                &[("target", "T"), ("total", "1"), ("crit", "2"), ("high", "3"), ("shell", "S")]
            ),
            "Authorized test of <code>T</code>. 1 issues recorded, including 2 critical and 3 high. S</p>"
        );
        assert_eq!(
            lab("findings.sub", Some("zh"), &[("label", "严重"), ("n", "2")]),
            "严重项共 2 项，每一项均附证据与复现路径。"
        );
        assert_eq!(
            lab(
                "findings.sub",
                Some("en"),
                &[("n", "2"), ("label", "Critical")]
            ),
            "2 Critical items, each with evidence and a reproduction path."
        );
        assert_eq!(
            lab("fix.verify", Some("zh"), &[]),
            "修复后按「②利用」逐步复测，关键请求应失败或不再回显敏感数据。"
        );
    }

    #[test]
    fn maps_match_labels() {
        let en = sev_map(Some("en"));
        assert_eq!(en.get("critical").map(String::as_str), Some("Critical"));
        assert_eq!(en.get("high").map(String::as_str), Some("High"));
        assert_eq!(en.get("medium").map(String::as_str), Some("Medium"));
        assert_eq!(en.get("low").map(String::as_str), Some("Low"));
        assert_eq!(en.get("info").map(String::as_str), Some("Info"));
        let zh = sev_map(Some("zh"));
        assert_eq!(zh.get("critical").map(String::as_str), Some("严重"));
        assert_eq!(zh.get("high").map(String::as_str), Some("高危"));
        assert_eq!(zh.get("medium").map(String::as_str), Some("中危"));
        assert_eq!(zh.get("low").map(String::as_str), Some("低危"));
        assert_eq!(zh.get("info").map(String::as_str), Some("信息"));

        let verify_en = verify_map(Some("en"));
        assert_eq!(
            verify_en.get("verified").map(String::as_str),
            Some("Verified")
        );
        assert_eq!(
            verify_en.get("pending").map(String::as_str),
            Some("Pending")
        );
        assert_eq!(verify_en.get("flaky").map(String::as_str), Some("Pending"));
        let verify_zh = verify_map(Some("zh"));
        assert_eq!(
            verify_zh.get("verified").map(String::as_str),
            Some("已验证")
        );
        assert_eq!(verify_zh.get("pending").map(String::as_str), Some("待复验"));
        assert_eq!(verify_zh.get("flaky"), verify_zh.get("pending"));

        assert_eq!(
            kind_map(Some("zh")).get("target").map(String::as_str),
            Some("目标")
        );
        assert_eq!(
            kind_map(Some("en")).get("info").map(String::as_str),
            Some("Asset")
        );
        assert_eq!(kind_map(Some("en")).len(), 5);
        assert_eq!(
            pn_map(Some("zh")).get("danger").map(String::as_str),
            Some("缺陷")
        );
        assert_eq!(
            pn_map(Some("en")).get("goal").map(String::as_str),
            Some("Access")
        );
        assert_eq!(
            pn_map(Some("zh")).get("foothold").map(String::as_str),
            Some("立足点")
        );
        assert_eq!(pn_map(None).len(), 9);
    }

    #[test]
    fn shell_chrome_lang_en() {
        let html = "<html lang=\"zh-CN\"><div>授权渗透测试交付报告</div><h2>执行摘要</h2><span class=\"en\">Executive Summary</span><h2>漏洞统计分布</h2><span class=\"en\">Severity &amp; Verification</span><span class=\"en\">Severity & Verification</span>";
        let en = apply_shell_chrome(html, Some("en"));
        assert!(en.contains("lang=\"en\""));
        assert!(en.contains("Executive Summary"));
        assert!(en.contains("Authorized Penetration Test Report"));
        assert!(!en.contains("<h2>执行摘要</h2>"));
        assert_eq!(
            en,
            "<html lang=\"en\"><div>Authorized Penetration Test Report</div><h2>Executive Summary</h2><h2>Severity & Verification</h2>"
        );
        let zh = apply_shell_chrome(html, Some("zh"));
        assert_eq!(
            zh,
            "<html lang=\"zh-CN\"><div>授权渗透测试交付报告</div><h2>执行摘要</h2><span class=\"en\">Executive Summary</span><h2>漏洞统计分布</h2><span class=\"en\">Severity & Verification</span><span class=\"en\">Severity & Verification</span>"
        );
        let _guard = LangGuard::take();
        set_report_lang(Some("en"));
        let untouched = apply_shell_chrome(html, None);
        assert_eq!(untouched, zh);
        let once = apply_shell_chrome(
            "<html lang=\"zh-CN\"><iframe lang=\"zh-CN\"></iframe>",
            Some("en"),
        );
        assert!(once.starts_with("<html lang=\"en\">"));
        assert!(once.contains("<iframe lang=\"zh-CN\">"));
    }

    #[test]
    fn shell_chrome_all_sections_en() {
        let zh_heads = [
            "执行摘要",
            "漏洞统计分布",
            "关键攻击路径",
            "资产画像",
            "漏洞清单总表",
            "严重漏洞",
            "高危漏洞",
            "中危漏洞",
            "低危漏洞",
        ];
        let en_spans = [
            "Executive Summary",
            "Severity &amp; Verification",
            "Attack Path",
            "Assets in Scope",
            "Findings Index",
            "Critical Findings",
            "High Findings",
            "Medium Findings",
            "Low Findings",
        ];
        let mut html = String::from("<html lang=\"zh-CN\">授权渗透测试交付报告");
        for (zh, en) in zh_heads.iter().zip(en_spans) {
            html.push_str(&format!("<h2>{}</h2><span class=\"en\">{}</span>", zh, en));
        }
        let out = apply_shell_chrome(&html, Some("en"));
        assert!(out.contains("lang=\"en\""));
        assert!(out.contains("Authorized Penetration Test Report"));
        assert!(!out.contains("授权渗透测试交付报告"));
        assert!(!out.contains("<span class=\"en\">"));
        for zh in zh_heads {
            assert!(!out.contains(&format!("<h2>{}</h2>", zh)), "{}", zh);
        }
        for heading in [
            "Executive Summary",
            "Severity & Verification",
            "Attack Path",
            "Assets in Scope",
            "Findings Index",
            "Critical Findings",
            "High Findings",
            "Medium Findings",
            "Low Findings",
        ] {
            assert!(
                out.contains(&format!("<h2>{}</h2>", heading)),
                "{}",
                heading
            );
        }
    }

    #[test]
    fn hard_stop_string_lookups() {
        assert_eq!(msg("hs.unlimited", Some("en"), &[]), "unlimited");
        assert_eq!(msg("hs.unlimited", Some("zh"), &[]), "不限");
        let wall = msg("hs.wall_fail", Some("en"), &[("cap", "12 hours")]);
        assert_eq!(wall, "Wall clock hits 12 hours → mark failed");
        assert!(wall.contains("Wall clock"));
        let red_en = msg(
            "hs.red_label",
            Some("en"),
            &[("cap", "12 hours"), ("n", "6")],
        );
        assert!(red_en.contains("Hard stop"));
        assert!(!red_en.contains("硬停"));
        assert!(red_en.contains("wall clock"));
        let red_zh = msg(
            "hs.red_label",
            Some("zh"),
            &[("cap", "12 小时"), ("n", "6")],
        );
        assert!(red_zh.contains("硬停"));
        assert!(red_zh.contains("墙钟"));
        let src_en = msg(
            "hs.src_label",
            Some("en"),
            &[("cap", "6 hours"), ("n", "30")],
        );
        assert!(src_en.contains("Hard stop"));
        assert!(!src_en.contains("硬停"));
        assert_eq!(
            src_en,
            "Hard stop: 6 hours wall clock, or 30 rounds with no new node and no new finding. Otherwise only a manual stop."
        );
        let src_zh = msg(
            "hs.src_label",
            Some("zh"),
            &[("cap", "6 小时"), ("n", "30")],
        );
        assert!(src_zh.contains("硬停"));
        assert!(src_zh.contains("墙钟"));
        let turns = msg(
            "hs.src_label_turns",
            Some("en"),
            &[("turns", "40"), ("cap", "6 hours")],
        );
        assert!(turns.contains("Hard stop"));
        assert!(!turns.contains("硬停"));
        assert_eq!(
            msg("hs.ctf_wall", Some("en"), &[("cap", "40 minutes")]),
            "This pass’s wall clock hits 40 minutes → mark failed"
        );
        assert!(msg("hs.manual", Some("en"), &[]).contains("Manual stop"));
        assert_eq!(msg("hs.manual", Some("zh"), &[]), "手动停止");
    }
}
