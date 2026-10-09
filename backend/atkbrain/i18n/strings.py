"""Request-facing API / job strings. Report chrome lives in report_labels."""
from __future__ import annotations

from .locale import get_locale, normalize_locale

_MSG = {
    "project_missing": {"zh": "项目不存在", "en": "Project not found"},
    "export_missing": {"zh": "导出任务不存在", "en": "Export job not found"},
    "export_file_missing": {"zh": "报告文件不存在", "en": "Report file not found"},
    "export_not_ready": {"zh": "报告尚未生成完成", "en": "Report is not ready yet"},
    "finding_missing": {"zh": "发现不存在", "en": "Finding not found"},
    "finding_rejected": {"zh": "已驳回的漏洞不提供完整报告", "en": "Rejected findings have no full report"},
    "md_gone": {"zh": "项目总报告请改用 HTML 或 PDF 导出", "en": "Project reports are HTML or PDF only"},
    "format_html_pdf": {"zh": "format 仅支持 html|pdf", "en": "format must be html or pdf"},
    "format_md": {"zh": "format 仅支持 md", "en": "format must be md"},
    "job_queued": {"zh": "专职导出 Pi 排队中…", "en": "Export Pi queued…"},
    "job_facts": {"zh": "收集项目事实与漏洞页…", "en": "Collecting project facts…"},
    "job_cache": {"zh": "命中缓存，跳过专职导出 Pi…", "en": "Cache hit; skipping export Pi…"},
    "job_writing": {"zh": "专职导出 Pi 正在撰写封面与漏洞卡片…", "en": "Export Pi is writing cover and finding cards…"},
    "job_slots": {"zh": "专职导出 Pi 正在撰写槽位…", "en": "Export Pi is filling slots…"},
    "job_bad_json": {"zh": "专职导出 Pi 未返回可用槽位 JSON", "en": "Export Pi did not return usable slot JSON"},
    "job_pi_fail": {"zh": "专职导出 Pi 撰写失败：{err}", "en": "Export Pi failed: {err}"},
    "job_shell": {"zh": "套入母版槽位…", "en": "Assembling the shell…"},
    "job_write": {"zh": "写入报告…", "en": "Writing the report…"},
    "job_pdf": {"zh": "渲染 PDF…", "en": "Rendering PDF…"},
    "job_done": {"zh": "报告已生成", "en": "Report ready"},
    "job_done_pi": {"zh": "报告已生成（专职导出 Pi 已撰写）", "en": "Report ready (export Pi wrote the slots)"},
    "job_done_cache": {"zh": "报告已生成（命中缓存）", "en": "Report ready (cache)"},
    "job_fail": {"zh": "失败：{err}", "en": "Failed: {err}"},
    "missing": {"zh": "未采集", "en": "Not collected"},
    "auth_fail": {"zh": "验证失败", "en": "Verification failed"},
    "llm_key_missing": {
        "zh": "未配置大模型密钥。在设置 → 模型里填写 API Key 并保存，或在项目目录 .env 填写 DEEPSEEK_API_KEY 后执行 docker compose up -d。",
        "en": "No model API key. Fill in the API key under Settings → Model and save, or set DEEPSEEK_API_KEY in the project .env and run docker compose up -d.",
    },
    "password_wrong": {"zh": "口令错误", "en": "Wrong password"},
    "review_busy": {"zh": "该漏洞这项复核正在进行", "en": "This finding already has that review running"},
    "review_mode": {"zh": "mode 须为 secondary 或 rating", "en": "mode must be secondary or rating"},
    "review_job_missing": {"zh": "复核任务不存在", "en": "Review job not found"},
    "hs.unlimited": {"zh": "不限", "en": "unlimited"},
    "hs.retry": {
        "zh": "回合内 {hang}无思考/工具/命令 → 打断本回合；连续 2 次卡死或连续 5 个空回合 → 结束本 run 并自动重开新会话（项目不记失败）",
        "en": "{hang} with no thought, tool, or command in a turn → interrupt that turn; two hangs or five empty turns in a row → end this run and open a new session (the project is not marked failed)",
    },
    "hs.wall_fail": {"zh": "墙钟满 {cap} → 记失败", "en": "Wall clock hits {cap} → mark failed"},
    "hs.src_stall": {"zh": "连续 {n} 轮无高质量进展 → 暂停，可再开", "en": "{n} rounds with no high-quality progress in a row → pause, can resume"},
    "hs.entry_down": {
        "zh": "入口连续 {dur} TCP 不可达（探 80/443/登记端口，超时/拒绝/DNS）→ 暂停，站点恢复后可再开",
        "en": "Entry TCP unreachable for {dur} (probe 80/443/registered port; timeout/refuse/DNS) → pause, resume when the site is back",
    },
    "hs.turns_fail": {"zh": "满 {turns} 轮 → 记失败", "en": "{turns} rounds → mark failed"},
    "hs.src_label_turns": {
        "zh": "硬停：满 {turns} 轮或墙钟满 {cap}，记失败。已验证高危/严重不停工。",
        "en": "Hard stop: {turns} rounds or a {cap} wall clock marks failure. Verified high/critical does not stop the hunt.",
    },
    "hs.empty_rounds": {
        "zh": "连续 {n} 轮没有新节点也没有新漏洞 → 记失败",
        "en": "{n} rounds in a row with no new node and no new finding → mark failed",
    },
    "hs.manual": {"zh": "手动停止", "en": "Manual stop"},
    "hs.src_label": {
        "zh": "硬停：墙钟满 {cap}，或连续 {n} 轮没有新节点也没有新漏洞。其余只接受手动停止。",
        "en": "Hard stop: {cap} wall clock, or {n} rounds with no new node and no new finding. Otherwise only a manual stop.",
    },
    "hs.ctf_wall": {"zh": "本遍墙钟满 {cap} → 记失败", "en": "This pass’s wall clock hits {cap} → mark failed"},
    "hs.ctf_idle": {
        "zh": "连续 {n} 个御主方案无图增长（无新节点/交旗/本地长计算）→ 记失败",
        "en": "{n} master plans in a row with no graph growth (no new node / flag / local long compute) → mark failed",
    },
    "hs.ctf_entry": {
        "zh": "入口连续 {dur} 不可达且已尝试重绑 → 暂停让槽，可再开",
        "en": "Entry unreachable for {dur} after rebind attempts → pause and yield the slot, can resume",
    },
    "hs.ctf_env": {
        "zh": "评测环境到期或平台不可达 → 停止（不把整场标失败）",
        "en": "Bench expired or platform unreachable → stop (do not mark the whole run failed)",
    },
    "hs.ctf_label": {
        "zh": "硬停：本遍墙钟 {cap}；连续 {n} 个御主方案无增长记失败。不限轮次。",
        "en": "Hard stop: this pass’s wall clock is {cap}; {n} idle master plans mark failure. No turn cap.",
    },
    "hs.red_stall": {
        "zh": "已升到第 3 圈后，连续 {n} 轮无高质量进展 → 暂停，可再开",
        "en": "After ring 3, {n} rounds with no high-quality progress in a row → pause, can resume",
    },
    "hs.red_label": {
        "zh": "硬停：墙钟满 {cap}，或连续 {n} 轮没有新节点也没有新漏洞。拿到 shell 提前收工。其余只接受手动停止。",
        "en": "Hard stop: {cap} wall clock, or {n} rounds with no new node and no new finding. A shell finishes early. Otherwise only a manual stop.",
    },
}


def msg(key: str, lang: str | None = None, **vars) -> str:
    row = _MSG.get(key) or {}
    loc = normalize_locale(lang or get_locale())
    text = row.get(loc) or row.get("zh") or key
    if vars:
        try:
            text = text.format(**vars)
        except Exception:
            pass
    return text
