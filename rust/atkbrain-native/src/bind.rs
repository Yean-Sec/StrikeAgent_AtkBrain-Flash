//! 御主局面绑定。横幅是否送达仍问 hop_auth_gate。

use std::collections::BTreeSet;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PySet};
use regex::Regex;
use std::sync::LazyLock;

const CLOSEOUT_OVERRIDE: &str = "【收口覆盖·消耗已验证能力】禁止再证明同一面。一种键名或算法失败不等于整面关闭。过滤器拒绝的是这一次提交的形态：不要给同一形态加包装；同一绕过族已否证就换正交表示类，不要用同族变体占下一步。一种观测类已证明可利用：先换成回显/联合/报错/状态差分等更快证明类，打成控制流或会话；同一耗时通道按位抽取只是退路，不要把它问到底。下一步抽取、过门或投递执行。客户端字段名不是后端契约；错误正文点名缺字段说明通道还活着。已验证跳板不要改成从本机打内网。少数令牌变体失败不关闭密码学或鉴权类。浅层路径 404 不关闭未挂载密钥；换查询参数/请求头/Cookie/body，不要转去旁路网段。握手/版本/可 attach 不是命令执行：已验证调试或注入能力必须消耗到一次执行证据。一种客户端形态失败不关闭整面，不要改回协议转储。";
const GADGET_KEEP: &str = "【跳板仍活】一种 4xx 或否证笔记不等于跳板已死。禁止从本机打内网面。按错误正文换键。过滤器拒绝的是这一次提交的形态，不要给同一形态加包装。";
const ORACLE_KEEP: &str = "【硬约束·输入面未关】状态码/正文无差异只否证这一类观测，不关闭输入面。换通道 = 同一 URL、同一参数，换观测（耗时/长度/响应头/副作用）。另一个路由因为允许 POST/JSON，不是换通道，禁止写成主线或「唯一可写面」。路线包必须并行：同一输入面换耗时/长度/响应头/副作用通道，加上该面的可控输入；至多再留一条其它正交面，且不能挤掉未关闭的输入面。禁止把该面写成已闭合/dos，禁止仅当其它路线无果才回来打。同一状态码再采样、换 Host/方法但仍以状态码判死，都不算换通道；必须对同一输入的两次提交比对耗时差/长度差/头差/副作用。";
const ORACLE_DIAG: &str = "一种观测失败不等于输入面关闭。恒定状态码/正文只否证这一类通道；输入面仍开放。必须在同一 URL、同一参数上换耗时/长度/响应头/副作用通道。禁止把另一个允许 POST 的路由当成换通道或唯一可写面。禁止把该面写成已闭合/dos，禁止把其它面当主线。";
const CYCLE_NOTE: &str = "挖洞循环：发现更多漏洞，并把已证实危害做到 getshell。路径是侦察→找攻击面→深入利用。命令执行后 report_shell 收工。不要把整猎收成一条利用链，也不要只扫不打。";
const HUNT_NOTE: &str = "局面：HTTP 活体本轮必须并发拉起 `web-exploit` 工人测→证；禁止从者 curl/http_request 代替。不限定必须是御主点名的那一条注入。静态 SPA、同源 API=0、只有 JS 外域名单，都不是无攻击面：打同入口参数/路由/Cookie/鉴权。info 节点不是战果。";
const SURFACE_SIT: &str = "页面和 JS 里的接口不是服务端入口全集。本轮先打开入口 HTML 里的同站内容页，把图片、文件、下载地址建成节点；和首页相同的只当阴性对照。第一个 500 或登录页不能代替这些内容页。然后再用中档词表列出和首页状态或长度不同的路径，文件名、路径、上传参数单独建成节点。静态目录或 WEB-INF 穿不过，只否定这次穿越，不能写成文件面已关闭。";

static FALSE_CLOSE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)已收口|已闭合|输入无关(?:崩溃|延迟|耗时)?|无条件崩溃|通道级否证|确定性\s*500|死面|离开.{0,16}(?:登录|/login)|零翻面.{0,12}收口|视图未处理|该面(?:已死|关闭)|面已关|(?:登录|口令|认证|输入|表单|参数|注入)面.{0,16}(?:关闭|已死|已闭合|穷尽)|仅当.{0,24}无果|主线无果|失败后才(?:回来|再打)|唯一可写|唯一允许\s*POST|优先打.{0,40}唯一|另一(?:个|条).{0,16}(?:可写|POST)|优先打.{0,32}(?:其它|其他|另一).{0,20}(?:路由|路径|接口|功能面)").unwrap());
static TIMING_BAN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"耗时|校准").unwrap());
static ENTRY_REFLUX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)目录枚举|目录爆破|content_enum|扫(?:一遍)?目录|回头打入口|再打入口").unwrap());

const ENTRY_ENUM: &[&str] = &["fingerprint", "auth_surface", "content_enum"];
const CHAIN_RESERVE: &[&str] = &["weaponize", "impact_escalate", "finding_rce_close", "ssrf_as_gateway", "finding_sqli_chain"];
const LOOT: &[&str] = &["file_read_chain", "finding_read_loot", "filter_bypass"];
const CLOSE_SIDE: &[&str] = &["channel_oracle", "fingerprint", "api_contract", "graphql_contract", "content_enum", "protocol_model"];
const CYCLE_VERIFY: &[&str] = &["web_inject", "auth_surface", "access_control", "upload_bypass", "restricted_deserialize", "input_abuse", "business_logic", "nday"];
const HUNT_LIVE: &[&str] = &["web_inject", "input_abuse", "access_control", "upload_bypass", "file_read_chain", "html_sink", "restricted_deserialize", "info_to_danger", "business_logic", "nday"];
const CONSUME: &[&str] = &["secret_mount", "file_read_chain", "auth_reuse", "access_control", "priv_enum"];
const POSTEX: &[&str] = &["access_control", "file_read_chain", "svc_auth_bruteforce", "ssrf_as_gateway", "privesc_lateral", "weaponize", "auth_reuse", "hop_auth", "protocol_model", "reverse_binary"];
const POSTEX_RESERVE: &[&str] = &["ssrf_as_gateway", "hop_auth", "access_control", "file_read_chain", "svc_auth_bruteforce"];
const GADGET_SIDE: &[&str] = &["file_read_chain", "access_control", "api_contract", "graphql_contract", "fingerprint", "content_enum", "protocol_model", "reverse_binary", "channel_oracle", "auth_surface"];
const SQLI: &[&str] = &["sqli", "db_access", "sql_injection", "sql-injection"];
const SSRF: &[&str] = &["ssrf", "ssrf_internal"];
const EXEC: &[&str] = &["rce", "command_injection", "deserialization", "ssti", "file_upload", "file_write"];
const READ: &[&str] = &["file_read", "lfi", "arbitrary_file_read"];
const TOKEN: &[&str] = &["token", "jwt", "signed_token", "jws", "jwe"];
const AUTH: &[&str] = &["auth_bypass", "authz", "unauth", "idor"];
const PROTECT: &[&str] = &["channel_oracle", "weaponize", "impact_escalate", "finding_rce_close", "finding_sqli_chain", "ssrf_as_gateway", "secret_mount", "reverse_binary"];

#[pyclass]
struct AdvisorBinding {
    #[pyo3(get, set)]
    diagnosis: String,
    #[pyo3(get, set)]
    next_plan: String,
    #[pyo3(get, set)]
    situation: String,
    must_intents: Py<PyList>,
    prefer_tactics: Py<PyList>,
    deny_tactics: Py<PyList>,
    ban_repeats: Py<PyList>,
    subagents: Py<PyList>,
    #[pyo3(get, set)]
    stall: String,
    #[pyo3(get, set)]
    misses: i64,
    #[pyo3(get, set)]
    tightened: bool,
    #[pyo3(get, set)]
    cycle_hunt: bool,
    #[pyo3(get, set)]
    keep_path_enum: bool,
    situation_intent_ids: Py<PyList>,
}

#[pymethods]
impl AdvisorBinding {
    #[new]
    #[pyo3(signature = (*, diagnosis="", next_plan="", situation="", must_intents=None, prefer_tactics=None, deny_tactics=None, ban_repeats=None, subagents=None, stall="none", misses=0, tightened=false, cycle_hunt=false, keep_path_enum=false, situation_intent_ids=None))]
    fn new(py: Python<'_>, diagnosis: &str, next_plan: &str, situation: &str, must_intents: Option<&Bound<PyAny>>, prefer_tactics: Option<&Bound<PyAny>>, deny_tactics: Option<&Bound<PyAny>>, ban_repeats: Option<&Bound<PyAny>>, subagents: Option<&Bound<PyAny>>, stall: &str, misses: i64, tightened: bool, cycle_hunt: bool, keep_path_enum: bool, situation_intent_ids: Option<&Bound<PyAny>>) -> PyResult<Self> {
        Ok(Self {
            diagnosis: diagnosis.into(), next_plan: next_plan.into(), situation: situation.into(),
            must_intents: as_list(py, must_intents)?, prefer_tactics: as_list(py, prefer_tactics)?,
            deny_tactics: as_list(py, deny_tactics)?, ban_repeats: as_list(py, ban_repeats)?,
            subagents: as_list(py, subagents)?, stall: stall.into(), misses, tightened, cycle_hunt, keep_path_enum,
            situation_intent_ids: as_list(py, situation_intent_ids)?,
        })
    }
    #[getter]
    fn must_intents<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.must_intents.bind(py).clone() }
    #[setter]
    fn set_must_intents(&mut self, v: Py<PyList>) { self.must_intents = v; }
    #[getter]
    fn prefer_tactics<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.prefer_tactics.bind(py).clone() }
    #[setter]
    fn set_prefer_tactics(&mut self, v: Py<PyList>) { self.prefer_tactics = v; }
    #[getter]
    fn deny_tactics<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.deny_tactics.bind(py).clone() }
    #[setter]
    fn set_deny_tactics(&mut self, v: Py<PyList>) { self.deny_tactics = v; }
    #[getter]
    fn ban_repeats<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.ban_repeats.bind(py).clone() }
    #[setter]
    fn set_ban_repeats(&mut self, v: Py<PyList>) { self.ban_repeats = v; }
    #[getter]
    fn subagents<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.subagents.bind(py).clone() }
    #[setter]
    fn set_subagents(&mut self, v: Py<PyList>) { self.subagents = v; }
    #[getter]
    fn situation_intent_ids<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> { self.situation_intent_ids.bind(py).clone() }
    #[getter]
    fn fingerprint(&self, py: Python<'_>) -> String {
        let must = strs(&self.must_intents.bind(py));
        let prefer = strs(&self.prefer_tactics.bind(py));
        let deny = strs(&self.deny_tactics.bind(py));
        let mut m = must.clone(); m.sort(); m.truncate(3);
        let mut p = prefer.clone(); p.sort(); p.truncate(6);
        let mut d = deny.clone(); d.sort(); d.truncate(8);
        format!("{}|{}|{}|{}", self.stall, m.join(","), p.join(","), d.join(","))
    }
}

fn as_list(py: Python<'_>, value: Option<&Bound<PyAny>>) -> PyResult<Py<PyList>> {
    let out = PyList::empty(py);
    if let Some(value) = value {
        if let Ok(it) = value.try_iter() {
            for v in it.flatten() { out.append(v)?; }
        }
    }
    Ok(out.unbind())
}
fn strs(list: &Bound<PyList>) -> Vec<String> {
    list.iter().filter_map(|v| v.extract::<String>().ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}
fn text(v: &Bound<PyAny>) -> String { v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default() }
fn intent_ids(obj: Option<&Bound<PyAny>>) -> Vec<String> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(iter) = obj.try_iter() else { return Vec::new() };
    let mut out = Vec::new();
    for item in iter.flatten() {
        let id = if let Ok(row) = item.downcast::<PyDict>() {
            row.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default()
        } else {
            text(&item)
        };
        let id = id.trim().to_string();
        if !id.is_empty() { out.push(id); }
    }
    out
}
fn attr(obj: &Bound<PyAny>, name: &str) -> String {
    obj.getattr(name).ok().filter(|v| !v.is_none()).map(|v| text(&v)).unwrap_or_default()
}
fn attr_list(py: Python<'_>, obj: &Bound<PyAny>, name: &str) -> Vec<String> {
    obj.getattr(name).ok().and_then(|v| if v.is_none() { None } else { Some(v) }).and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| text(&x)).collect()).unwrap_or_default()
}
fn uniq(seq: &[String], limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    for s in seq {
        let s = s.trim();
        if !s.is_empty() && !out.iter().any(|x: &String| x == s) { out.push(s.to_string()); }
        if out.len() >= limit { break; }
    }
    out
}
fn contains(list: &[String], name: &str) -> bool { list.iter().any(|x| x == name) }
fn without<'a>(list: &'a [String], ban: &[&str]) -> Vec<String> { list.iter().filter(|x| !ban.contains(&x.as_str())).cloned().collect() }

#[pyfunction]
fn intent_tactic(intent: Option<&Bound<PyDict>>) -> String {
    let Some(intent) = intent else { return String::new() };
    let sk = intent.get_item("strategy_key").ok().flatten().map(|v| text(&v)).unwrap_or_default();
    if let Some((_, t)) = sk.rsplit_once("::") { t.to_string() } else { sk }
}

fn cats_of(value: Option<&Bound<PyAny>>) -> BTreeSet<String> {
    let Some(value) = value else { return BTreeSet::new() };
    value.try_iter().map(|it| it.flatten().map(|v| text(&v).trim().to_ascii_lowercase()).filter(|s| !s.is_empty()).collect()).unwrap_or_default()
}
fn hit(set: &BTreeSet<String>, names: &[&str]) -> bool { names.iter().any(|n| set.contains(*n)) }

#[pyfunction]
#[pyo3(signature = (verified_categories=None))]
fn closeout_sidetrack_tactics(py: Python<'_>, verified_categories: Option<&Bound<PyAny>>) -> PyResult<Py<PySet>> {
    let cats = cats_of(verified_categories);
    let mut out: BTreeSet<String> = CLOSE_SIDE.iter().map(|s| (*s).to_string()).collect();
    if hit(&cats, SQLI) && !hit(&cats, READ) {
        out.extend(["file_read_chain".into(), "flag_or_privesc".into(), "input_abuse".into(), "access_control".into()]);
    }
    if hit(&cats, SSRF) && !hit(&cats, READ) {
        out.extend(["file_read_chain".into(), "access_control".into(), "filter_bypass".into()]);
    }
    if (hit(&cats, TOKEN) || hit(&cats, AUTH)) && !hit(&cats, READ) {
        out.extend(["file_read_chain".into(), "html_sink".into(), "flag_hunt".into()]);
    }
    if hit(&cats, EXEC) { out.extend(["protocol_model".into(), "fingerprint".into()]); }
    Ok(PySet::new(py, out)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (*, has_foothold=false, remaining_goals=false, has_verified_asset=false, verified_categories=None, has_live_gadget=false, invert_ops=false))]
fn binding_reserve_tactics(has_foothold: bool, remaining_goals: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>, has_live_gadget: bool, invert_ops: bool) -> Vec<String> {
    let cats = cats_of(verified_categories);
    if invert_ops && !hit(&cats, EXEC) { return vec!["reverse_binary".into()]; }
    if has_foothold && remaining_goals { return POSTEX_RESERVE.iter().map(|s| (*s).into()).collect(); }
    if has_verified_asset && !has_foothold {
        if hit(&cats, TOKEN) { return vec!["weaponize".into(), "finding_authz_expand".into(), "secret_mount".into()]; }
        if hit(&cats, SQLI) { return vec!["finding_sqli_chain".into(), "weaponize".into()]; }
        if hit(&cats, EXEC) { return vec!["finding_rce_close".into(), "weaponize".into(), "impact_escalate".into()]; }
        if hit(&cats, SSRF) { return vec!["ssrf_as_gateway".into(), "hop_auth".into(), "secret_mount".into()]; }
        if hit(&cats, AUTH) { return vec!["weaponize".into(), "finding_authz_expand".into()]; }
        return CHAIN_RESERVE.iter().map(|s| (*s).into()).collect();
    }
    if has_live_gadget && !has_foothold { return vec!["ssrf_as_gateway".into(), "hop_auth".into(), "upload_bypass".into()]; }
    Vec::new()
}

#[pyfunction]
#[pyo3(signature = (*, has_foothold, remaining_goals, has_verified_asset=false, verified_categories=None, has_live_gadget=false))]
fn postex_reserve_tactics(has_foothold: bool, remaining_goals: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>, has_live_gadget: bool) -> Vec<String> {
    binding_reserve_tactics(has_foothold, remaining_goals, has_verified_asset, verified_categories, has_live_gadget, false)
}

#[pyfunction]
#[pyo3(signature = (*, has_foothold=false, remaining_goals=false, has_verified_asset=false, verified_categories=None, has_live_gadget=false))]
fn protected_tactics(py: Python<'_>, has_foothold: bool, remaining_goals: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>, has_live_gadget: bool) -> PyResult<Py<PySet>> {
    Ok(PySet::new(py, binding_reserve_tactics(has_foothold, remaining_goals, has_verified_asset, verified_categories, has_live_gadget, false))?.unbind())
}

#[pyfunction]
fn surface_false_close(text: &str) -> bool { FALSE_CLOSE.is_match(text) }

#[pyfunction]
fn strip_premature_timing_bans(bans: Option<&Bound<PyAny>>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(bans) = bans {
        if let Ok(it) = bans.try_iter() {
            for v in it.flatten() {
                let s = text(&v).trim().to_string();
                if s.is_empty() || TIMING_BAN.is_match(&s) { continue; }
                out.push(s);
            }
        }
    }
    out
}

#[pyfunction]
#[pyo3(signature = (binding=None, *, misses_limit=3))]
fn should_refresh_stale_binding(py: Python<'_>, binding: Option<&Bound<PyAny>>, misses_limit: i64) -> bool {
    let Some(binding) = binding else { return false };
    let limit = misses_limit.max(1);
    let bans = attr_list(py, binding, "ban_repeats");
    let disproven = bans.iter().any(|b| b.contains("已否证"));
    let stall = attr(binding, "stall").trim().to_ascii_lowercase();
    if (stall == "chain" || stall == "postex") && !disproven { return false; }
    attr(binding, "misses").parse::<i64>().unwrap_or(0) >= limit
}

#[pyfunction]
#[pyo3(signature = (*, chain_live, has_plan, assigned_tactics=None, verified_categories=None))]
fn should_force_chain_close_review(chain_live: bool, has_plan: bool, assigned_tactics: Option<&Bound<PyAny>>, verified_categories: Option<&Bound<PyAny>>) -> bool {
    if !chain_live { return false; }
    if !has_plan { return true; }
    assigned_is_entry_sidetrack(assigned_tactics, verified_categories)
}

#[pyfunction]
#[pyo3(signature = (assigned_tactics=None, verified_categories=None))]
fn assigned_is_entry_sidetrack(assigned_tactics: Option<&Bound<PyAny>>, verified_categories: Option<&Bound<PyAny>>) -> bool {
    let tacs = cats_of(assigned_tactics);
    if tacs.is_empty() { return true; }
    let mut side: BTreeSet<String> = CLOSE_SIDE.iter().map(|s| (*s).into()).chain(ENTRY_ENUM.iter().map(|s| (*s).into())).collect();
    let cats = cats_of(verified_categories);
    if !hit(&cats, TOKEN) { side.insert("secret_mount".into()); }
    tacs.iter().all(|t| side.contains(t))
}

#[pyfunction]
#[pyo3(signature = (*, needs_oracle, has_plan, assigned_tactics=None))]
fn should_force_oracle_review(needs_oracle: bool, has_plan: bool, assigned_tactics: Option<&Bound<PyAny>>) -> bool {
    if !needs_oracle { return false; }
    if !has_plan { return true; }
    !cats_of(assigned_tactics).contains("channel_oracle")
}

#[pyfunction]
fn graph_has_http_service(graph: Option<&Bound<PyDict>>) -> bool {
    let Some(graph) = graph else { return false };
    let Ok(Some(ns)) = graph.get_item("nodes") else { return false };
    let Ok(list) = ns.downcast::<PyList>() else { return false };
    for n in list.iter() {
        let Ok(d) = n.downcast::<PyDict>() else { continue };
        if d.get_item("type").ok().flatten().map(|v| text(&v)).unwrap_or_default() != "service" { continue; }
        let key = d.get_item("key").ok().flatten().map(|v| text(&v)).unwrap_or_default().to_ascii_lowercase();
        let title = d.get_item("title").ok().flatten().map(|v| text(&v)).unwrap_or_default();
        let detail = d.get_item("detail").ok().flatten().map(|v| text(&v)).unwrap_or_default();
        let tags = d.get_item("tags").ok().flatten().map(|v| cats_of(Some(&v))).unwrap_or_default();
        let blob = format!("{key} {title} {detail}").to_ascii_lowercase();
        if key.contains("http") || tags.contains("http") || blob.contains("https") || key.contains("/http") { return true; }
    }
    false
}

fn tactic_of_any(it: &Bound<PyAny>) -> String {
    it.downcast::<PyDict>().ok().map(|d| intent_tactic(Some(&d))).unwrap_or_default()
}

#[pyfunction]
#[pyo3(signature = (open_intents=None, graph=None, workspace_dir=""))]
fn preferred_hop_auth_id(py: Python<'_>, open_intents: Option<&Bound<PyAny>>, graph: Option<&Bound<PyDict>>, workspace_dir: &str) -> String {
    let Some(open_intents) = open_intents else { return String::new() };
    let Ok(it) = open_intents.try_iter() else { return String::new() };
    let hops: Vec<Bound<PyDict>> = it.flatten().filter_map(|v| v.downcast::<PyDict>().ok().map(|d| d.clone())).filter(|d| {
        let id = d.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default();
        let st = d.get_item("status").ok().flatten().map(|v| text(&v)).unwrap_or_else(|| "open".into());
        !id.is_empty() && intent_tactic(Some(d)) == "hop_auth" && st != "deferred" && st != "disproved"
    }).collect();
    if hops.is_empty() { return String::new(); }
    let set = |name: &str| -> BTreeSet<String> {
        py.import("atkbrain_native").ok().and_then(|m| m.getattr(name).ok()).and_then(|f| f.call1((graph,)).ok()).and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| text(&x)).collect()).unwrap_or_default()
    };
    let live = set("live_surface_hosts");
    let ident = set("identity_service_hosts");
    let svc = set("all_service_hosts");
    let cred = set("cred_named_hosts");
    let owned = set("foothold_hosts");
    let loot = set("unauth_loot_hosts");
    let clue = set("clue_only_hosts");
    let done = py.import("atkbrain_native").ok().and_then(|m| m.getattr("verified_hop_auth_hosts").ok()).and_then(|f| f.call1((graph, open_intents)).ok()).and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| text(&x)).collect::<BTreeSet<String>>()).unwrap_or_default();
    let has_live = !live.is_empty() || !ident.is_empty();
    let mut best = (i64::MIN, String::new());
    for hop in &hops {
        let hosts = py.import("atkbrain_native").ok().and_then(|m| m.getattr("intent_private_hosts").ok()).and_then(|f| f.call1((hop,)).ok()).and_then(|v| v.extract::<Vec<String>>().ok()).unwrap_or_default();
        let mut score = if hosts.is_empty() { -20 } else { 0 };
        let mut delivered = false;
        for h in &hosts {
            let bcast = py.import("atkbrain_native").ok().and_then(|m| m.getattr("is_broadcast_or_net").ok()).and_then(|f| f.call1((h,)).ok()).and_then(|v| v.extract::<bool>().ok()).unwrap_or(false);
            if bcast { score -= 100; continue; }
            if live.contains(h) { score += 100; }
            if ident.contains(h) { score += 80; } else if svc.contains(h) { score += 40; }
            if cred.contains(h) { score += 30; }
            if owned.contains(h) { score -= 80; }
            if done.contains(h) { score -= 50; }
            if (clue.contains(h) || !live.contains(h)) && has_live && !ident.contains(h) && !cred.contains(h) { score -= 40; }
            if loot.contains(h) { score -= 70; }
            if atkbrain_core::hop::hop_delivered(workspace_dir, h) {
                delivered = true;
            }
        }
        let id = hop.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default();
        let rank = score * 10 - if delivered { 1 } else { 0 };
        if rank > best.0 { best = (rank, id); }
    }
    best.1
}

#[pyfunction]
fn hop_auth_switch_plan(py: Python<'_>, hops: Option<&Bound<PyAny>>, preferred_id: &str) -> PyResult<Py<PyDict>> {
    let preferred = preferred_id.to_string();
    let mut active = Vec::new();
    if let Some(hops) = hops {
        if let Ok(it) = hops.try_iter() {
            for v in it.flatten() {
                let Ok(d) = v.downcast::<PyDict>() else { continue };
                let id = d.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default();
                let st = d.get_item("status").ok().flatten().map(|v| text(&v)).unwrap_or_default();
                if st == "active" && !id.is_empty() { active.push(id); }
            }
        }
    }
    let out = PyDict::new(py);
    if preferred.is_empty() {
        out.set_item("claim", "")?;
        out.set_item("reopen", PyList::empty(py))?;
    } else if active.iter().any(|i| i == &preferred) {
        out.set_item("claim", "")?;
        out.set_item("reopen", PyList::new(py, active.into_iter().filter(|i| i != &preferred).collect::<Vec<_>>())?)?;
    } else {
        out.set_item("claim", &preferred)?;
        out.set_item("reopen", PyList::new(py, active)?)?;
    }
    Ok(out.unbind())
}

#[pyfunction]
#[pyo3(signature = (plan, *, open_intents=None, repeats=None, has_foothold=false, remaining_goals=false, has_verified_asset=false, has_internal_hops=false, verified_categories=None, has_live_gadget=false, needs_channel_oracle=false, cycle_hunt=false, extra_subagents=None, has_http_service=false, invert_ops=false, graph=None))]
fn compile_binding(
    py: Python<'_>,
    plan: &Bound<PyAny>,
    open_intents: Option<&Bound<PyAny>>,
    repeats: Option<&Bound<PyAny>>,
    has_foothold: bool,
    remaining_goals: bool,
    has_verified_asset: bool,
    has_internal_hops: bool,
    verified_categories: Option<&Bound<PyAny>>,
    has_live_gadget: bool,
    needs_channel_oracle: bool,
    cycle_hunt: bool,
    extra_subagents: Option<&Bound<PyAny>>,
    has_http_service: bool,
    invert_ops: bool,
    graph: Option<&Bound<PyDict>>,
) -> PyResult<Py<AdvisorBinding>> {
    let _ = (has_internal_hops, extra_subagents);
    let open_tacs = open_intents.and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| tactic_of_any(&x)).filter(|s| !s.is_empty()).collect::<BTreeSet<_>>()).unwrap_or_default();
    let cats = cats_of(verified_categories);
    let exploit = {
        let non = py.import("atkbrain_native").ok().and_then(|m| m.getattr("NON_EXPLOIT_FINDING_CATS").ok()).and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| text(&x)).collect::<BTreeSet<_>>()).unwrap_or_default();
        cats.iter().any(|c| !non.contains(c))
    };
    let listed = verified_categories.and_then(|v| v.try_iter().ok()).map(|it| it.flatten().any(|x| !text(&x).trim().is_empty())).unwrap_or(false);
    let block_oracle = needs_channel_oracle && !exploit && !(has_verified_asset && !listed);
    let mut chain_close = has_verified_asset && !has_foothold && !block_oracle;
    let mut live_gadget = has_live_gadget && !has_foothold;
    if cycle_hunt || (invert_ops && !hit(&cats, EXEC)) { chain_close = false; live_gadget = false; }
    let mut prefer = uniq(&attr_list(py, plan, "prefer_tactics"), 8);
    let mut deny = uniq(&attr_list(py, plan, "defer_families"), 12);
    let mut bans = attr_list(py, plan, "ban_repeats");
    if let Some(repeats) = repeats { if let Ok(it) = repeats.try_iter() { bans.extend(it.flatten().map(|v| text(&v))); } }
    bans = uniq(&bans, 12);
    let allow = format!("{} {}", attr(plan, "next_plan"), attr(plan, "diagnosis"));
    bans.retain(|b| !b.trim().is_empty() && !allow.contains(b.trim()));
    let mut subs = uniq(&attr_list(py, plan, "subagents"), 4);
    let mut stall = attr(plan, "stall").trim().to_ascii_lowercase();
    if stall.is_empty() { stall = "none".into(); }
    if block_oracle { bans = strip_plain(&bans); deny.retain(|t| t != "channel_oracle"); }
    let reserve = binding_reserve_tactics(has_foothold, remaining_goals, has_verified_asset, verified_categories, has_live_gadget, invert_ops);
    let postex = has_foothold && remaining_goals && !cycle_hunt;
    if postex {
        for t in ENTRY_ENUM { if !contains(&deny, t) { deny.push((*t).into()); } }
        deny.retain(|t| !POSTEX_RESERVE.contains(&t.as_str()));
        for t in POSTEX { if !contains(&prefer, t) && !contains(&deny, t) { prefer.push((*t).into()); } }
        if !contains(&subs, "lateral") { subs.push("lateral".into()); }
        if !contains(&subs, "privesc") { subs.push("privesc".into()); }
        if stall == "none" { stall = "postex".into(); }
    } else if chain_close {
        let keep = crate::hypo::action_surface_incomplete(graph, has_http_service);
        if keep { deny.retain(|t| t != "content_enum"); }
        else if !contains(&deny, "content_enum") { deny.push("content_enum".into()); }
        let side = closeout_sidetrack_tactics(py, verified_categories)?;
        for t in side.bind(py).iter() { let s = text(&t); if !contains(&deny, &s) { deny.push(s); } }
        for t in LOOT { if !contains(&deny, t) && !contains(&reserve, t) { deny.push((*t).into()); } }
        deny.retain(|t| !reserve.iter().any(|r| r == t));
        let head: Vec<String> = reserve.iter().filter(|t| open_tacs.contains(*t) && !contains(&deny, t)).cloned().collect();
        let extra: Vec<String> = prefer.iter().filter(|t| !contains(&deny, t)).cloned().collect();
        let cycle: Vec<String> = CYCLE_VERIFY.iter().filter(|t| open_tacs.contains(**t) && !contains(&deny, *t)).map(|s| (*s).into()).collect();
        prefer = uniq(&{ let mut v = head; v.extend(extra); v.extend(cycle); v }, 8);
        if stall == "none" || stall == "method" { stall = "chain".into(); }
    } else if live_gadget {
        for t in GADGET_SIDE { if !contains(&deny, t) && !contains(&reserve, t) { deny.push((*t).into()); } }
        deny.retain(|t| !reserve.iter().any(|r| r == t));
        if stall == "none" || stall == "method" { stall = "chain".into(); }
    }
    if cycle_hunt {
        for t in ["hop_auth", "privesc_lateral", "ssrf_as_gateway", "flag_hunt"] { if !contains(&deny, t) { deny.push(t.into()); } }
        let keep_enum = crate::hypo::action_surface_incomplete(graph, has_http_service);
        if has_verified_asset && !contains(&deny, "content_enum") && !keep_enum { deny.push("content_enum".into()); }
        else if keep_enum { deny.retain(|t| t != "content_enum"); }
    }
    prefer.retain(|t| !contains(&deny, t));
    prefer.truncate(8);
    if block_oracle {
        deny.retain(|t| t != "channel_oracle");
        if !contains(&deny, "content_enum") { deny.push("content_enum".into()); }
        for t in ["channel_oracle", "input_abuse"] {
            if !contains(&prefer, t) && !contains(&deny, t) { prefer.insert(0, t.into()); }
        }
        prefer.retain(|t| !contains(&deny, t) && !LOOT.contains(&t.as_str()));
        prefer.truncate(8);
    }
    let surface_open = crate::hypo::action_surface_incomplete(graph, has_http_service);
    let gaps = crate::hypo::request_form_gaps(py, graph)?;
    if surface_open { deny.retain(|t| t != "content_enum"); prefer = uniq(&{
        let mut v = vec!["content_enum".to_string()]; v.extend(prefer); v
    }, 8); }
    let mut situation = Vec::new();
    if surface_open { situation.push(SURFACE_SIT.to_string()); }
    let gap_list = gaps.bind(py);
    if gap_list.len() > 0 {
        let mut pairs = Vec::new();
        for gap in gap_list.iter().take(4) {
            let Ok(d) = gap.downcast::<PyDict>() else { continue };
            let stem = d.get_item("stem").ok().flatten().map(|v| text(&v)).unwrap_or_default();
            let sibs = d.get_item("siblings").ok().flatten().and_then(|v| v.extract::<Vec<String>>().ok()).unwrap_or_default();
            let sibs = sibs.into_iter().take(2).collect::<Vec<_>>().join("、");
            pairs.push(format!("{stem}（对照 {sibs}）"));
        }
        situation.push(format!("这些入口已经确认存在，调用形式比同站其他入口少：{}。把对照入口上多出来的、且改变了响应的形式套过来。方法名和参数名只用本站已经出现过的，不要新造路径。堆栈里的方法名和重写路径返回 404，不能算这个入口已经测完。", pairs.join("、")));
    }
    let mut next_plan = attr(plan, "next_plan");
    if (chain_close || live_gadget) && next_plan.trim().is_empty() {
        next_plan = if chain_close { CLOSEOUT_OVERRIDE.into() } else { GADGET_KEEP.into() };
    }
    Py::new(py, AdvisorBinding {
        diagnosis: attr(plan, "diagnosis"),
        next_plan,
        situation: situation.join("\n"),
        must_intents: PyList::new(py, uniq(&attr_list(py, plan, "must_intents"), 3))?.unbind(),
        prefer_tactics: PyList::new(py, prefer)?.unbind(),
        deny_tactics: PyList::new(py, uniq(&deny, 12))?.unbind(),
        ban_repeats: PyList::new(py, bans)?.unbind(),
        subagents: PyList::new(py, subs)?.unbind(),
        stall,
        misses: 0,
        tightened: false,
        cycle_hunt,
        keep_path_enum: surface_open,
        situation_intent_ids: PyList::empty(py).unbind(),
    })
}

fn strip_plain(bans: &[String]) -> Vec<String> { bans.iter().filter(|s| !TIMING_BAN.is_match(s)).cloned().collect() }

fn binding_strs(py: Python<'_>, binding: &Bound<PyAny>, name: &str) -> Vec<String> { attr_list(py, binding, name) }

#[pyfunction]
fn tighten_binding(py: Python<'_>, binding: &Bound<PyAny>) -> PyResult<Py<AdvisorBinding>> {
    let mut deny = binding_strs(py, binding, "deny_tactics");
    let prefer0 = binding_strs(py, binding, "prefer_tactics");
    for t in ENTRY_ENUM { if !contains(&deny, t) && !contains(&prefer0, t) { deny.push((*t).into()); } }
    let mut prefer: Vec<String> = prefer0.into_iter().filter(|t| !contains(&deny, t)).collect();
    let stall = attr(binding, "stall");
    if stall == "postex" || (contains(&prefer, "hop_auth") && stall != "chain") {
        let head: Vec<String> = POSTEX_RESERVE.iter().filter(|t| !contains(&deny, t)).map(|s| (*s).into()).collect();
        prefer = uniq(&{ let mut v = head; v.extend(prefer); v }, 8);
    }
    let misses = attr(binding, "misses").parse::<i64>().unwrap_or(0) + 1;
    let mut sit = attr(binding, "situation");
    if !sit.contains("局面收紧") {
        let note = "【局面收紧·上一步违背局面】禁止入口枚举与本机回流。参考假说仍可另选，但不能再违局面。";
        sit = if sit.trim().is_empty() { note.into() } else { format!("{note}\n{sit}") };
    }
    Py::new(py, AdvisorBinding {
        diagnosis: attr(binding, "diagnosis"), next_plan: attr(binding, "next_plan"), situation: sit,
        must_intents: as_list(py, binding.getattr("must_intents").ok().as_ref())?,
        prefer_tactics: PyList::new(py, prefer)?.unbind(),
        deny_tactics: PyList::new(py, uniq(&deny, 12))?.unbind(),
        ban_repeats: as_list(py, binding.getattr("ban_repeats").ok().as_ref())?,
        subagents: as_list(py, binding.getattr("subagents").ok().as_ref())?,
        stall, misses, tightened: true, cycle_hunt: binding.getattr("cycle_hunt").ok().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false),
        keep_path_enum: binding.getattr("keep_path_enum").ok().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false),
        situation_intent_ids: as_list(py, binding.getattr("situation_intent_ids").ok().as_ref())?,
    })
}

#[pyfunction]
#[pyo3(signature = (binding=None, *, assigned=None, open_intents=None, last_turn_text="", last_tool_uses=0, quality="none", task_subagents=None))]
fn binding_compliance(py: Python<'_>, binding: Option<&Bound<PyAny>>, assigned: Option<&Bound<PyAny>>, open_intents: Option<&Bound<PyAny>>, last_turn_text: &str, last_tool_uses: i64, quality: &str, task_subagents: Option<&Bound<PyAny>>) -> String {
    let _ = (assigned, open_intents);
    let Some(binding) = binding else { return "executed".into() };
    if ["flag", "finding", "capability_edge"].contains(&quality) { return "oracle".into(); }
    if last_turn_text.contains("让出给顾问") || last_turn_text.to_ascii_lowercase().contains("turn yield") { return "executed".into(); }
    if last_tool_uses <= 0 { return "empty".into(); }
    let subs = binding_strs(py, binding, "subagents");
    let prefer = binding_strs(py, binding, "prefer_tactics");
    let needs = attr(binding, "cycle_hunt") == "True" || binding.getattr("cycle_hunt").ok().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false) || subs.iter().any(|s| s == "web-exploit" || s == "src-hunt") || prefer.iter().any(|t| HUNT_LIVE.contains(&t.as_str()));
    let did = cats_of(task_subagents).iter().any(|s| s == "web-exploit" || s == "src-hunt");
    if needs && !did { return "ignored".into(); }
    let deny = binding_strs(py, binding, "deny_tactics");
    let low = last_turn_text.to_ascii_lowercase();
    if deny.iter().any(|t| low.contains(&t.to_ascii_lowercase())) || (deny.iter().any(|t| ENTRY_ENUM.contains(&t.as_str())) && ENTRY_REFLUX.is_match(last_turn_text)) {
        return "ignored".into();
    }
    "executed".into()
}

#[pyfunction]
fn format_binding_block(py: Python<'_>, binding: Option<&Bound<PyAny>>) -> String {
    let Some(binding) = binding else { return String::new() };
    let keep = binding.getattr("keep_path_enum").ok().map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false);
    let mut lines = vec![
        "【局面·必须守住】".to_string(),
        if keep { "循环按攻击图编译本段。先打开入口 HTML 里的内容页并记下图片和文件地址，再列出和首页状态或长度不同的路径。不得回流邻题/本机内网。".into() } else { "循环按攻击图编译本段。必须消费已有凭证、不得回流目录枚举/邻题/本机内网。".into() },
        "同一身份域：过门与未授权可达并行，不是互为前置。经跳板打内层登录时，未确认认证接口收到请求体，不算口令否证。".into(),
    ];
    let bans = binding_strs(py, binding, "ban_repeats");
    let disproven: Vec<String> = bans.iter().filter(|b| b.contains("已否证")).cloned().collect();
    if disproven.is_empty() { lines.push("未关的输入面不要丢掉；已经否证的写法必须离开。".into()); }
    else { lines.push(format!("这些路径已经否证，下一轮必须换节点，禁止同一 URL 再换通道：{}", disproven.into_iter().take(4).collect::<Vec<_>>().join("、"))); }
    let sit = attr(binding, "situation");
    if !sit.trim().is_empty() { lines.push(sit.trim().to_string()); }
    let deny = binding_strs(py, binding, "deny_tactics");
    if !deny.is_empty() { lines.push(format!("禁止战术：{}", deny.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join("、"))); }
    lines.push("【参考假说·可打可丢】".into());
    lines.join("\n")
}

#[pyfunction]
#[pyo3(signature = (binding=None, open_intents=None, *, has_foothold=false, remaining_goals=false, has_verified_asset=false, verified_categories=None, has_live_gadget=false))]
fn starves_chain_close(py: Python<'_>, binding: Option<&Bound<PyAny>>, open_intents: Option<&Bound<PyAny>>, has_foothold: bool, remaining_goals: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>, has_live_gadget: bool) -> bool {
    let reserve = binding_reserve_tactics(has_foothold, remaining_goals, has_verified_asset, verified_categories, has_live_gadget, false);
    let Some(binding) = binding else { return false };
    if reserve.is_empty() { return false; }
    let deny = binding_strs(py, binding, "deny_tactics");
    deny.iter().any(|t| reserve.iter().any(|r| r == t))
}

#[pyfunction]
#[pyo3(signature = (assigned=None, open_intents=None, *, has_verified_asset=false, verified_categories=None))]
fn in_flight_blocks_new_direction(py: Python<'_>, assigned: Option<&Bound<PyAny>>, open_intents: Option<&Bound<PyAny>>, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>) -> bool {
    let _ = verified_categories;
    let still = atkbrain_core::advisor::assigned_still_open(&intent_ids(assigned), &intent_ids(open_intents));
    if !still { return false; }
    !has_verified_asset
}

#[pyfunction]
#[pyo3(signature = (binding=None, open_intents=None))]
fn situation_protected_intent_ids(py: Python<'_>, binding: Option<&Bound<PyAny>>, open_intents: Option<&Bound<PyAny>>) -> PyResult<Py<PySet>> {
    let Some(binding) = binding else { return Ok(PySet::empty(py)?.unbind()); };
    let mut by = std::collections::BTreeMap::new();
    if let Some(open_intents) = open_intents {
        if let Ok(it) = open_intents.try_iter() {
            for v in it.flatten() {
                let Ok(d) = v.downcast::<PyDict>() else { continue };
                let id = d.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default();
                if !id.is_empty() { by.insert(id, d.clone()); }
            }
        }
    }
    let mut out = Vec::new();
    for iid in binding_strs(py, binding, "must_intents") {
        let tac = by.get(&iid).map(|d| intent_tactic(Some(d))).unwrap_or_default();
        if PROTECT.contains(&tac.as_str()) { out.push(iid); }
    }
    out.extend(binding_strs(py, binding, "situation_intent_ids"));
    Ok(PySet::new(py, out)?.unbind())
}

#[pyfunction]
#[pyo3(signature = (*, open_intents=None, want_ids=None, extras=None, prefer=None, deny=None, lock=false, reserve=None, exclusive=false, limit=3, graph=None))]
fn pick_bound_assigned(py: Python<'_>, open_intents: Option<&Bound<PyAny>>, want_ids: Option<&Bound<PyAny>>, extras: Option<&Bound<PyAny>>, prefer: Option<&Bound<PyAny>>, deny: Option<&Bound<PyAny>>, lock: bool, reserve: Option<&Bound<PyAny>>, exclusive: bool, limit: usize, graph: Option<&Bound<PyDict>>) -> PyResult<Py<PyList>> {
    let _ = (prefer, reserve, exclusive, graph);
    let deny = cats_of(deny);
    let mut by = std::collections::BTreeMap::new();
    if let Some(open_intents) = open_intents {
        if let Ok(it) = open_intents.try_iter() {
            for v in it.flatten() {
                let Ok(d) = v.downcast::<PyDict>() else { continue };
                let id = d.get_item("id").ok().flatten().map(|x| text(&x)).unwrap_or_default();
                if !id.is_empty() { by.insert(id, d.clone()); }
            }
        }
    }
    let out = PyList::empty(py);
    let mut seen = BTreeSet::new();
    let mut push = |it: &Bound<PyDict>| -> PyResult<bool> {
        let id = it.get_item("id").ok().flatten().map(|v| text(&v)).unwrap_or_default();
        if id.is_empty() || seen.contains(&id) { return Ok(false); }
        let tac = intent_tactic(Some(it));
        if deny.contains(&tac) { return Ok(false); }
        out.append(it)?;
        seen.insert(id);
        Ok(out.len() >= limit)
    };
    if let Some(want_ids) = want_ids {
        if let Ok(it) = want_ids.try_iter() {
            for v in it.flatten() {
                let id = text(&v);
                if let Some(row) = by.get(&id) { if push(row)? { return Ok(out.unbind()); } }
            }
        }
    }
    if !lock {
        if let Some(extras) = extras {
            if let Ok(it) = extras.try_iter() {
                for v in it.flatten() {
                    let Ok(d) = v.downcast::<PyDict>() else { continue };
                    if push(&d)? { break; }
                }
            }
        }
    }
    Ok(out.unbind())
}

#[pyfunction]
#[pyo3(signature = (binding=None, open_intents=None, *, has_foothold=false, remaining_goals=false, has_verified_asset=false, verified_categories=None, has_live_gadget=false))]
fn ensure_postex_orthogonal(py: Python<'_>, binding: Option<&Bound<PyAny>>, open_intents: Option<&Bound<PyAny>>, has_foothold: bool, remaining_goals: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>, has_live_gadget: bool) -> PyResult<Py<PyAny>> {
    let _ = (open_intents, has_foothold, remaining_goals, has_verified_asset, verified_categories, has_live_gadget);
    match binding {
        Some(b) => Ok(b.clone().unbind()),
        None => Ok(py.None()),
    }
}

#[pyfunction]
#[pyo3(signature = (*, needs_channel_oracle=false, has_verified_asset=false, verified_categories=None))]
fn oracle_blocks_closeout(py: Python<'_>, needs_channel_oracle: bool, has_verified_asset: bool, verified_categories: Option<&Bound<PyAny>>) -> bool {
    if !needs_channel_oracle { return false; }
    let cats = cats_of(verified_categories);
    let non = py.import("atkbrain_native").ok().and_then(|m| m.getattr("NON_EXPLOIT_FINDING_CATS").ok()).and_then(|v| v.try_iter().ok()).map(|it| it.flatten().map(|x| text(&x)).collect::<BTreeSet<_>>()).unwrap_or_default();
    if cats.iter().any(|c| !non.contains(c)) { return false; }
    let listed = verified_categories.and_then(|v| v.try_iter().ok()).map(|it| it.flatten().any(|x| !text(&x).trim().is_empty())).unwrap_or(false);
    if has_verified_asset && !listed { return false; }
    true
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<AdvisorBinding>()?;
    m.add("CLOSEOUT_OVERRIDE", CLOSEOUT_OVERRIDE)?;
    m.add("GADGET_KEEP", GADGET_KEEP)?;
    m.add("ORACLE_KEEP", ORACLE_KEEP)?;
    m.add("ORACLE_DIAG", ORACLE_DIAG)?;
    m.add("CYCLE_HUNT_NOTE", CYCLE_NOTE)?;
    m.add("HUNT_TASK_NOTE", HUNT_NOTE)?;
    m.add("EXPLORE_REFRESH_TACTICS", PyList::new(m.py(), ["channel_oracle", "input_abuse", "web_inject", "access_control", "file_read_chain", "info_to_danger", "fingerprint", "filter_bypass", "web_inject"])?)?;
    m.add("ENTRY_ENUM_TACTICS", PySet::new(m.py(), ENTRY_ENUM)?)?;
    m.add_function(wrap_pyfunction!(intent_tactic, m)?)?;
    m.add_function(wrap_pyfunction!(closeout_sidetrack_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(binding_reserve_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(postex_reserve_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(protected_tactics, m)?)?;
    m.add_function(wrap_pyfunction!(surface_false_close, m)?)?;
    m.add_function(wrap_pyfunction!(strip_premature_timing_bans, m)?)?;
    m.add_function(wrap_pyfunction!(should_refresh_stale_binding, m)?)?;
    m.add_function(wrap_pyfunction!(should_force_chain_close_review, m)?)?;
    m.add_function(wrap_pyfunction!(should_force_oracle_review, m)?)?;
    m.add_function(wrap_pyfunction!(assigned_is_entry_sidetrack, m)?)?;
    m.add_function(wrap_pyfunction!(graph_has_http_service, m)?)?;
    m.add_function(wrap_pyfunction!(preferred_hop_auth_id, m)?)?;
    m.add_function(wrap_pyfunction!(hop_auth_switch_plan, m)?)?;
    m.add_function(wrap_pyfunction!(compile_binding, m)?)?;
    m.add_function(wrap_pyfunction!(tighten_binding, m)?)?;
    m.add_function(wrap_pyfunction!(binding_compliance, m)?)?;
    m.add_function(wrap_pyfunction!(format_binding_block, m)?)?;
    m.add_function(wrap_pyfunction!(starves_chain_close, m)?)?;
    m.add_function(wrap_pyfunction!(in_flight_blocks_new_direction, m)?)?;
    m.add_function(wrap_pyfunction!(situation_protected_intent_ids, m)?)?;
    m.add_function(wrap_pyfunction!(pick_bound_assigned, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_postex_orthogonal, m)?)?;
    m.add_function(wrap_pyfunction!(oracle_blocks_closeout, m)?)?;
    Ok(())
}
