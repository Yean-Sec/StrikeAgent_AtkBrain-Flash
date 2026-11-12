//! 把网关改写交给 Rust。未传入环境表时，读写进程里的 os.environ。

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::PyDict;

fn snapshot(py: Python<'_>) -> PyResult<HashMap<String, String>> {
    let os = py.import("os")?;
    let env = os.getattr("environ")?;
    let mut map = HashMap::new();
    for item in env.call_method0("items")?.try_iter()? {
        let pair = item?;
        let key = pair.get_item(0)?.str()?.to_string_lossy().into_owned();
        let value = pair.get_item(1)?.str()?.to_string_lossy().into_owned();
        if !key.is_empty() {
            map.insert(key, value);
        }
    }
    Ok(map)
}

fn write_diff(py: Python<'_>, before: &HashMap<String, String>, after: &HashMap<String, String>) -> PyResult<()> {
    let os = py.import("os")?;
    let env = os.getattr("environ")?;
    for (key, value) in after {
        if before.get(key).map(String::as_str) != Some(value.as_str()) {
            env.set_item(key, value)?;
        }
    }
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (env=None))]
fn hosted_enabled(py: Python<'_>, env: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
    let map = match env {
        Some(given) => given.extract()?,
        None => snapshot(py)?,
    };
    Ok(atkbrain_core::gateway::hosted_enabled(&map))
}

#[pyfunction]
#[pyo3(signature = (env=None))]
fn gateway_enabled(py: Python<'_>, env: Option<&Bound<'_, PyDict>>) -> PyResult<bool> {
    let map = match env {
        Some(given) => given.extract()?,
        None => snapshot(py)?,
    };
    Ok(atkbrain_core::gateway::gateway_enabled(&map))
}

#[pyfunction]
fn rewrite_llm_url_for_gateway(url: &str) -> String {
    atkbrain_core::gateway::rewrite_llm_url_for_gateway(url)
}

#[pyfunction]
#[pyo3(signature = (env=None))]
fn apply_platform_env_aliases<'py>(py: Python<'py>, env: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyDict>> {
    let mut map = match env {
        Some(given) => given.extract()?,
        None => snapshot(py)?,
    };
    let before = map.clone();
    let mapped = atkbrain_core::gateway::apply_platform_env_aliases(&mut map);
    if env.is_none() {
        write_diff(py, &before, &map)?;
    } else if let Some(given) = env {
        for (key, value) in &map {
            if before.get(key).map(String::as_str) != Some(value.as_str()) {
                given.set_item(key, value)?;
            }
        }
    }
    let out = PyDict::new(py);
    for (dst, src) in mapped {
        out.set_item(dst, src)?;
    }
    Ok(out)
}

#[pyfunction]
#[pyo3(signature = (env=None))]
fn apply_llm_gateway<'py>(py: Python<'py>, env: Option<&Bound<'py, PyDict>>) -> PyResult<Bound<'py, PyDict>> {
    let mut map = match env {
        Some(given) => given.extract()?,
        None => snapshot(py)?,
    };
    let before = map.clone();
    let changed = atkbrain_core::gateway::apply_llm_gateway(&mut map);
    if env.is_none() {
        write_diff(py, &before, &map)?;
    } else if let Some(given) = env {
        for (key, value) in &changed {
            given.set_item(key, value)?;
        }
    }
    let out = PyDict::new(py);
    for (key, value) in changed {
        out.set_item(key, value)?;
    }
    Ok(out)
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add("GATEWAY_SUFFIX", ".tsecbench.gw")?;
    m.add_function(wrap_pyfunction!(hosted_enabled, m)?)?;
    m.add_function(wrap_pyfunction!(gateway_enabled, m)?)?;
    m.add_function(wrap_pyfunction!(rewrite_llm_url_for_gateway, m)?)?;
    m.add_function(wrap_pyfunction!(apply_platform_env_aliases, m)?)?;
    m.add_function(wrap_pyfunction!(apply_llm_gateway, m)?)?;
    Ok(())
}
