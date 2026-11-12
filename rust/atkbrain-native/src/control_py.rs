//! 御主门闩和 CTF 题型提示的 Python 入口。

use atkbrain_core::{advisor, ctf_prompts, surface};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

fn text_of(obj: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(String::new()) };
    Ok(obj.str()?.to_string_lossy().into_owned())
}

fn string_list(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<String>> {
    let Some(obj) = obj.filter(|v| !v.is_none()) else { return Ok(Vec::new()) };
    if let Ok(iter) = obj.try_iter() {
        let mut out = Vec::new();
        for item in iter {
            let item = item?;
            if item.is_none() { continue; }
            out.push(item.str()?.to_string_lossy().into_owned());
        }
        return Ok(out);
    }
    Ok(vec![obj.str()?.to_string_lossy().into_owned()])
}

#[pyfunction]
#[pyo3(signature = (*, turn, interval, stall_class="none", no_progress=0, last_steer_turn=None, hold_turns=0, in_flight=false, hard_turns=10, pivots=0, first_turns=2))]
fn should_review_advisor(
    turn: i64,
    interval: i64,
    stall_class: &str,
    no_progress: i64,
    last_steer_turn: Option<i64>,
    hold_turns: i64,
    in_flight: bool,
    hard_turns: i64,
    pivots: i64,
    first_turns: i64,
) -> (bool, String) {
    let (ask, why) = advisor::should_review_advisor(
        turn, interval, stall_class, no_progress, last_steer_turn, hold_turns, in_flight, hard_turns, pivots, first_turns,
    );
    (ask, why.to_string())
}

#[pyfunction]
fn stall_pause_due(no_progress: i64, limit: i64) -> bool {
    advisor::stall_pause_due(no_progress, limit)
}

#[pyfunction]
#[pyo3(signature = (*, in_flight=false, hold_course=false))]
fn hold_note_text(in_flight: bool, hold_course: bool) -> &'static str {
    advisor::hold_note_text(in_flight, hold_course)
}

#[pyfunction]
#[pyo3(signature = (raw=None))]
fn normalize_ctf_category(raw: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    Ok(ctf_prompts::normalize_ctf_category(&text_of(raw)?).to_string())
}

#[pyfunction]
#[pyo3(signature = (category=None))]
fn ctf_category_prompt(category: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    Ok(ctf_prompts::ctf_category_prompt(&text_of(category)?).to_string())
}

#[pyfunction]
#[pyo3(signature = (category=None, *, attachments=None, offline=false))]
fn brief_for_category(category: Option<&Bound<'_, PyAny>>, attachments: Option<&Bound<'_, PyAny>>, offline: bool) -> PyResult<String> {
    let names = string_list(attachments)?;
    Ok(ctf_prompts::brief_for_category(&text_of(category)?, &names, offline))
}

fn surface_hay(graph: Option<&Bound<'_, PyAny>>) -> String {
    let Some(graph) = graph.filter(|v| !v.is_none()) else { return String::new() };
    let Ok(row) = graph.downcast::<PyDict>() else { return String::new() };
    let Ok(Some(nodes)) = row.get_item("nodes") else { return String::new() };
    let Ok(list) = nodes.downcast::<PyList>() else { return String::new() };
    let mut parts = Vec::new();
    for item in list.iter() {
        let Ok(node) = item.downcast::<PyDict>() else { continue };
        for key in ["key", "type", "title", "detail"] {
            if let Ok(Some(value)) = node.get_item(key) {
                if !value.is_none() { parts.push(value.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()); }
            }
        }
        if let Ok(Some(tags)) = node.get_item("tags") {
            if let Ok(iter) = tags.try_iter() {
                for tag in iter.flatten() { parts.push(tag.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()); }
            }
        }
    }
    parts.join(" ").to_lowercase()
}

#[pyfunction]
#[pyo3(signature = (graph=None))]
fn format_src_surface_brief(graph: Option<&Bound<'_, PyAny>>) -> String {
    surface::format_src_surface_brief(&surface_hay(graph))
}

fn dict_text(row: &Bound<'_, PyDict>, key: &str) -> String {
    row.get_item(key).ok().flatten().filter(|v| !v.is_none()).and_then(|v| v.str().ok()).map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
}

fn stack_rows(graph: Option<&Bound<'_, PyAny>>) -> Vec<(String, String, String, String)> {
    let Some(graph) = graph.filter(|v| !v.is_none()) else { return Vec::new() };
    let Ok(row) = graph.downcast::<PyDict>() else { return Vec::new() };
    let Ok(Some(nodes)) = row.get_item("nodes") else { return Vec::new() };
    let Ok(list) = nodes.downcast::<PyList>() else { return Vec::new() };
    list.iter().filter_map(|item| item.downcast::<PyDict>().ok().cloned()).map(|node| {
        let tags = node.get_item("tags").ok().flatten().and_then(|v| v.try_iter().ok()).map(|it| it.flatten().filter_map(|t| t.str().ok().map(|s| s.to_string_lossy().into_owned())).collect::<Vec<_>>().join(" ")).unwrap_or_default();
        (dict_text(&node, "key"), dict_text(&node, "title"), dict_text(&node, "type"), tags)
    }).collect()
}

fn live_stack(live: Option<&Bound<'_, PyAny>>) -> String {
    let Some(live) = live.filter(|v| !v.is_none()) else { return String::new() };
    let Ok(row) = live.downcast::<PyDict>() else { return String::new() };
    let mut hdr = Vec::new();
    if let Ok(Some(headers)) = row.get_item("headers") {
        if let Ok(headers) = headers.downcast::<PyDict>() {
            for (k, v) in headers.iter() {
                hdr.push(format!("{}: {}", k.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default(), v.str().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()));
            }
        }
    }
    let body = dict_text(row, "body");
    format!("{} {} {} {}", hdr.join(" "), dict_text(row, "server"), dict_text(row, "title"), body.chars().take(4000).collect::<String>())
}

#[pyfunction]
#[pyo3(signature = (*, brief="", graph=None, live=None))]
fn classify_entry_identity<'py>(py: Python<'py>, brief: &str, graph: Option<&Bound<'_, PyAny>>, live: Option<&Bound<'_, PyAny>>) -> PyResult<Bound<'py, PyAny>> {
    let (expected, live_fams, mismatch) = surface::classify_entry_identity(brief, &surface::graph_stack_text(&stack_rows(graph), 24000), &live_stack(live));
    let (title, server, status) = if let Some(row) = live.filter(|v| !v.is_none()).and_then(|v| v.downcast::<PyDict>().ok()) {
        (dict_text(row, "title"), dict_text(row, "server"), row.get_item("status").ok().flatten())
    } else {
        (String::new(), String::new(), None)
    };
    let out = PyDict::new(py);
    out.set_item("expected", expected)?;
    out.set_item("live", live_fams)?;
    out.set_item("mismatch", mismatch)?;
    out.set_item("title", title.chars().take(120).collect::<String>())?;
    out.set_item("server", server.chars().take(80).collect::<String>())?;
    if let Some(status) = status { out.set_item("status", status)?; }
    Ok(out.into_any())
}

#[pyfunction]
#[pyo3(signature = (roles, objective=None, *, http=false, keep_rce=false))]
fn ensure_live_page_reader(roles: Vec<String>, objective: Option<&str>, http: bool, keep_rce: bool) -> Vec<String> {
    surface::ensure_live_page_reader(&roles, objective.unwrap_or(""), http, keep_rce)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    let cats = PyTuple::new(m.py(), ctf_prompts::CTF_CATEGORIES.iter().copied())?;
    m.add("CTF_CATEGORIES", cats)?;
    m.add_function(wrap_pyfunction!(should_review_advisor, m)?)?;
    m.add_function(wrap_pyfunction!(stall_pause_due, m)?)?;
    m.add_function(wrap_pyfunction!(hold_note_text, m)?)?;
    m.add_function(wrap_pyfunction!(normalize_ctf_category, m)?)?;
    m.add_function(wrap_pyfunction!(ctf_category_prompt, m)?)?;
    m.add_function(wrap_pyfunction!(brief_for_category, m)?)?;
    m.add_function(wrap_pyfunction!(format_src_surface_brief, m)?)?;
    m.add_function(wrap_pyfunction!(classify_entry_identity, m)?)?;
    m.add_function(wrap_pyfunction!(ensure_live_page_reader, m)?)?;
    Ok(())
}
