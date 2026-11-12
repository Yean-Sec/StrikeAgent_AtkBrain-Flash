//! 项目展示状态、CTF 遍数墙钟和时长文案。设置数值由 Python 传入。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use crate::objective::normalize_objective;

fn dur(sec: i64, loc: &str) -> String {
    let n = sec.max(0);
    if n <= 0 {
        return if loc == "en" { "unlimited".into() } else { "不限".into() };
    }
    if loc == "en" {
        if n % 3600 == 0 {
            let h = n / 3600;
            return if h == 1 { "1 hour".into() } else { format!("{h} hours") };
        }
        if n % 60 == 0 {
            let m = n / 60;
            return if m == 1 { "1 minute".into() } else { format!("{m} minutes") };
        }
        return if n == 1 { "1 second".into() } else { format!("{n} seconds") };
    }
    if n % 3600 == 0 {
        return format!("{} 小时", n / 3600);
    }
    if n % 60 == 0 {
        return format!("{} 分钟", n / 60);
    }
    format!("{n} 秒")
}

fn as_i64(v: &Bound<PyAny>, default: i64) -> i64 {
    if v.is_none() {
        return default;
    }
    if let Ok(i) = v.extract::<i64>() {
        return i;
    }
    if let Ok(f) = v.extract::<f64>() {
        if f.is_finite() {
            return f as i64;
        }
    }
    default
}

fn setting(raw: &Bound<PyDict>, key: &str, default: i64) -> i64 {
    match raw.get_item(key).ok().flatten() {
        Some(v) => as_i64(&v, default).max(0),
        None => default.max(0),
    }
}

#[pyfunction]
pub fn status_uses_ctf(objective: Option<&str>) -> bool {
    normalize_objective(objective) == "flag"
}

#[pyfunction]
pub fn status_ctf_pass_sec(pass_n: Option<i64>, clocks: &Bound<PyDict>) -> i64 {
    let n = match pass_n {
        Some(v) if v >= 1 => v,
        Some(_) => 1,
        None => 1,
    };
    let p1 = setting(clocks, "runtime_hard_stop_sec", 40 * 60);
    let p2 = setting(clocks, "runtime_hard_stop_pass2_sec", 120 * 60);
    let p3 = setting(clocks, "runtime_hard_stop_pass3_sec", 180 * 60);
    let step = setting(clocks, "runtime_hard_stop_pass_step_sec", 60 * 60);
    if n <= 1 {
        p1
    } else if n == 2 {
        p2
    } else if n == 3 {
        p3
    } else {
        p3 + (n - 3) * step
    }
}

#[pyfunction]
pub fn status_ctf_pass_index(ended_real_attempts: i64) -> i64 {
    ended_real_attempts.max(0) + 1
}

#[pyfunction]
pub fn status_runtime_hard_stop(objective: Option<&str>, pass_n: Option<i64>, clocks: &Bound<PyDict>) -> i64 {
    if status_uses_ctf(objective) {
        status_ctf_pass_sec(pass_n, clocks)
    } else {
        setting(clocks, "agent_runtime_hard_stop_sec", 6 * 60 * 60)
    }
}

#[pyfunction]
pub fn status_format_duration(sec: f64, lang: &str) -> String {
    let n = if sec.is_finite() { sec as i64 } else { 0 };
    dur(n.max(0), if lang == "en" { "en" } else { "zh" })
}

#[pyfunction]
pub fn status_max_turns(objective: Option<&str>, clocks: &Bound<PyDict>) -> i64 {
    if status_uses_ctf(objective) {
        setting(clocks, "loop_max_turns", 0)
    } else {
        setting(clocks, "loop_max_turns_agent", 0)
    }
}

#[pyfunction]
pub fn status_displayed(db_status: Option<&str>, running: bool, queued: bool) -> String {
    if queued {
        return "queued".into();
    }
    if running {
        return "running".into();
    }
    let st = db_status.unwrap_or("idle").trim().to_ascii_lowercase();
    if st == "running" {
        return "idle".into();
    }
    if st == "goal_reached" {
        return "completed".into();
    }
    if st.is_empty() { "idle".into() } else { st }
}

#[pyfunction]
pub fn status_final(goal: bool, exhausted: bool, pause_reason: Option<&str>) -> String {
    if goal {
        return "completed".into();
    }
    let failed = matches!(
        pause_reason.unwrap_or(""),
        "graph_idle" | "runtime_cap" | "turn_cap" | "empty_rounds"
    );
    if exhausted || failed {
        "error".into()
    } else {
        "idle".into()
    }
}

#[pyfunction]
pub fn status_anchor_elapsed(
    py: Python<'_>,
    hunt: Option<&Bound<PyDict>>,
    running: bool,
    run_started_at: Option<f64>,
    now_ts: f64,
) -> PyResult<Py<PyDict>> {
    let out = PyDict::new(py);
    if let Some(h) = hunt {
        for (k, v) in h.iter() {
            out.set_item(k, v)?;
        }
    }
    let elapsed = out
        .get_item("elapsed_sec")?
        .map(|v| as_i64_f(&v))
        .unwrap_or(0.0)
        .max(0.0);
    if !running {
        out.set_item("elapsed_sec", elapsed)?;
        if out.contains("elapsed_as_of")? {
            out.del_item("elapsed_as_of")?;
        }
        return Ok(out.unbind());
    }
    let as_of = out.get_item("elapsed_as_of")?.map(|v| as_i64_f(&v)).unwrap_or(0.0);
    let elapsed = if as_of > 0.0 {
        elapsed + (now_ts - as_of).max(0.0)
    } else if run_started_at.unwrap_or(0.0) > 0.0 {
        elapsed.max(now_ts - run_started_at.unwrap_or(0.0))
    } else {
        elapsed
    };
    out.set_item("elapsed_sec", elapsed)?;
    out.set_item("elapsed_as_of", now_ts)?;
    Ok(out.unbind())
}

fn as_i64_f(v: &Bound<PyAny>) -> f64 {
    if let Ok(f) = v.extract::<f64>() {
        if f.is_finite() { return f; }
    }
    if let Ok(i) = v.extract::<i64>() {
        return i as f64;
    }
    0.0
}

fn msg_retry(loc: &str, hang: &str) -> String {
    if loc == "en" {
        format!("{hang} with no thought, tool, or command in a turn → interrupt that turn; two hangs or five empty turns in a row → end this run and open a new session (the project is not marked failed)")
    } else {
        format!("回合内 {hang}无思考/工具/命令 → 打断本回合；连续 2 次卡死或连续 5 个空回合 → 结束本 run 并自动重开新会话（项目不记失败）")
    }
}

#[pyfunction]
pub fn status_hard_stop_info(
    py: Python<'_>,
    objective: Option<&str>,
    pass_n: Option<i64>,
    lang: &str,
    clocks: &Bound<PyDict>,
) -> PyResult<Py<PyDict>> {
    let loc = if lang == "en" { "en" } else { "zh" };
    let runtime = status_runtime_hard_stop(objective, pass_n, clocks);
    let turns = status_max_turns(objective, clocks);
    let cap = dur(runtime, loc);
    let hang = dur(setting(clocks, "turn_hang_sec", 8 * 60), loc);
    let ctf_entry_sec = setting(clocks, "benchmark_entry_down_yield_sec", 8 * 60);
    let o = normalize_objective(objective);
    let retry = msg_retry(loc, &hang);
    let idle_n = setting(clocks, "graph_idle_empty_plans", 6).max(1);
    let (conditions, label): (Vec<String>, String) = if o == "flag" {
        let mut conds = vec![
            if loc == "en" {
                format!("This pass’s wall clock hits {cap} → mark failed")
            } else {
                format!("本遍墙钟满 {cap} → 记失败")
            },
            if loc == "en" {
                format!("{idle_n} master plans in a row with no graph growth (no new node / flag / local long compute) → mark failed")
            } else {
                format!("连续 {idle_n} 个御主方案无图增长（无新节点/交旗/本地长计算）→ 记失败")
            },
        ];
        if ctf_entry_sec > 0 {
            let d = dur(ctf_entry_sec, loc);
            conds.push(if loc == "en" {
                format!("Entry unreachable for {d} after rebind attempts → pause and yield the slot, can resume")
            } else {
                format!("入口连续 {d} 不可达且已尝试重绑 → 暂停让槽，可再开")
            });
        }
        conds.push(if loc == "en" {
            "Bench expired or platform unreachable → stop (do not mark the whole run failed)".into()
        } else {
            "评测环境到期或平台不可达 → 停止（不把整场标失败）".into()
        });
        conds.push(retry);
        // Python inserts entry at index 2 and env at -1, which is before retry.
        // Rebuild to match: wall, idle, [entry], env, retry.
        let label = if loc == "en" {
            format!("Hard stop: this pass’s wall clock is {cap}; {idle_n} idle master plans mark failure. No turn cap.")
        } else {
            format!("硬停：本遍墙钟 {cap}；连续 {idle_n} 个御主方案无增长记失败。不限轮次。")
        };
        (conds, label)
    } else {
        let conds = vec![
            if loc == "en" {
                format!("Wall clock hits {cap} → mark failed")
            } else {
                format!("墙钟满 {cap} → 记失败")
            },
            if loc == "en" {
                "30 rounds in a row with no new node and no new finding → mark failed".into()
            } else {
                "连续 30 轮没有新节点也没有新漏洞 → 记失败".into()
            },
            if loc == "en" { "Manual stop".into() } else { "手动停止".into() },
        ];
        let label = if loc == "en" {
            format!("Hard stop: {cap} wall clock, or 30 rounds with no new node and no new finding. Otherwise only a manual stop.")
        } else {
            format!("硬停：墙钟满 {cap}，或连续 30 轮没有新节点也没有新漏洞。其余只接受手动停止。")
        };
        (conds, label)
    };
    let d = PyDict::new(py);
    d.set_item("track", o)?;
    d.set_item("runtime_sec", runtime)?;
    d.set_item("max_turns", turns)?;
    let plist = PyList::new(py, conditions)?;
    d.set_item("conditions", plist)?;
    d.set_item("label", label)?;
    Ok(d.unbind())
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(status_uses_ctf, m)?)?;
    m.add_function(wrap_pyfunction!(status_ctf_pass_sec, m)?)?;
    m.add_function(wrap_pyfunction!(status_ctf_pass_index, m)?)?;
    m.add_function(wrap_pyfunction!(status_runtime_hard_stop, m)?)?;
    m.add_function(wrap_pyfunction!(status_format_duration, m)?)?;
    m.add_function(wrap_pyfunction!(status_max_turns, m)?)?;
    m.add_function(wrap_pyfunction!(status_displayed, m)?)?;
    m.add_function(wrap_pyfunction!(status_final, m)?)?;
    m.add_function(wrap_pyfunction!(status_anchor_elapsed, m)?)?;
    m.add_function(wrap_pyfunction!(status_hard_stop_info, m)?)?;
    Ok(())
}
