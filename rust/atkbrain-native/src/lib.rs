//! Python 控制台调用的判断内核。读网卡、密钥文件、SQLite 和猎面循环仍在 Python。

use pyo3::prelude::*;

mod auth;
mod bind;
mod clocks;
mod control_py;
mod creds_py;
mod cvss;
mod engine_py;
mod extras;
mod findings;
mod gateway_py;
mod graph_py;
mod guard;
mod http_log_py;
mod hop_py;
mod hypo;
mod i18n_py;
mod guard_obj;
mod intranet;
mod net;
mod nodes;
mod objective;
mod osnet;
mod pi_py;
mod projects_py;
mod pyface;
mod reach;
mod scope;
mod scope_obj;
mod spiral_py;
mod status;
mod turn_close;
mod verify;

#[pymodule]
fn atkbrain_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    cvss::register(m)?;
    clocks::register(m)?;
    objective::register(m)?;
    status::register(m)?;
    auth::register(m)?;
    findings::register(m)?;
    nodes::register(m)?;
    verify::register(m)?;
    intranet::register(m)?;
    scope::register(m)?;
    scope_obj::register(m)?;
    gateway_py::register(m)?;
    graph_py::register(m)?;
    guard::register(m)?;
    guard_obj::register(m)?;
    http_log_py::register(m)?;
    i18n_py::register(m)?;
    turn_close::register(m)?;
    pyface::register(m)?;
    projects_py::register(m)?;
    pi_py::register(m)?;
    engine_py::register(m)?;
    control_py::register(m)?;
    creds_py::register(m)?;
    hop_py::register(m)?;
    spiral_py::register(m)?;
    reach::register(m)?;
    extras::register(m)?;
    hypo::register(m)?;
    bind::register(m)?;
    Ok(())
}
