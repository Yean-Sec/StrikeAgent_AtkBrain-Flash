//! 回合收口标记。

use pyo3::prelude::*;

const MARKS: &[&str] = &[
    "本轮完成",
    "已完成本轮",
    "本轮小结",
    "本轮从者已完成",
    "收尾如下",
    "收尾结论",
    "本轮结束",
    "结束本轮",
    "round complete",
    "finished this turn",
    "wrapping up this turn",
];

#[pyfunction]
#[pyo3(signature = (text, *, role=""))]
pub fn role_wrote_turn_done(text: &str, role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    if r == "finding-review" || r.starts_with("finding-review:") {
        return false;
    }
    if text.trim().is_empty() {
        return false;
    }
    let low = text.to_ascii_lowercase();
    for mark in MARKS {
        if mark.is_empty() {
            continue;
        }
        if mark.is_ascii() {
            if low.contains(&mark.to_ascii_lowercase()) {
                return true;
            }
        } else if text.contains(mark) {
            return true;
        }
    }
    false
}

#[pyfunction]
pub fn turn_must_close(elapsed_sec: f64, cap_sec: f64) -> bool {
    cap_sec > 0.0 && elapsed_sec >= cap_sec
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add("WORKER_ABORT_GRACE_SEC", 15.0)?;
    m.add_function(wrap_pyfunction!(role_wrote_turn_done, m)?)?;
    m.add_function(wrap_pyfunction!(turn_must_close, m)?)?;
    Ok(())
}
