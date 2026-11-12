//! `Scope` 类型。字段是可变的 Python 列表，判断在 Rust。

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyType};

use crate::net::norm_host;
use crate::osnet::{attacker_hosts, local_networks, local_self_hosts, on_docker_bridge};
use crate::scope::{is_attacker, scope_host_in_scope};

fn list_of(py: Python<'_>, items: &[String]) -> PyResult<Py<PyList>> {
    Ok(PyList::new(py, items)?.unbind())
}

fn strings(list: &Bound<PyList>) -> Vec<String> {
    list.iter().filter_map(|x| x.extract::<String>().ok()).collect()
}

#[pyclass]
pub struct Scope {
    targets: Py<PyList>,
    ips: Py<PyList>,
    cidrs: Py<PyList>,
    ports: Py<PyAny>,
    #[pyo3(get, set)]
    pub allow_subdomains: bool,
    #[pyo3(get, set)]
    pub mode: String,
}

#[pymethods]
impl Scope {
    #[new]
    #[pyo3(signature = (targets=None, ips=None, cidrs=None, ports=None, allow_subdomains=false, mode="strict"))]
    fn new(
        py: Python<'_>,
        targets: Option<&Bound<PyAny>>,
        ips: Option<&Bound<PyAny>>,
        cidrs: Option<&Bound<PyAny>>,
        ports: Option<&Bound<PyAny>>,
        allow_subdomains: bool,
        mode: &str,
    ) -> PyResult<Self> {
        Ok(Scope {
            targets: as_list(py, targets)?,
            ips: as_list(py, ips)?,
            cidrs: as_list(py, cidrs)?,
            ports: ports.map(|p| p.clone().unbind()).unwrap_or_else(|| py.None()),
            allow_subdomains,
            mode: mode.to_string(),
        })
    }

    #[getter]
    pub fn targets<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        self.targets.bind(py).clone()
    }
    #[setter]
    fn set_targets(&mut self, py: Python<'_>, value: &Bound<PyAny>) -> PyResult<()> {
        self.targets = as_list(py, Some(value))?;
        Ok(())
    }
    #[getter]
    pub fn ips<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        self.ips.bind(py).clone()
    }
    #[setter]
    fn set_ips(&mut self, py: Python<'_>, value: &Bound<PyAny>) -> PyResult<()> {
        self.ips = as_list(py, Some(value))?;
        Ok(())
    }
    #[getter]
    fn cidrs<'py>(&self, py: Python<'py>) -> Bound<'py, PyList> {
        self.cidrs.bind(py).clone()
    }
    #[setter]
    fn set_cidrs(&mut self, py: Python<'_>, value: &Bound<PyAny>) -> PyResult<()> {
        self.cidrs = as_list(py, Some(value))?;
        Ok(())
    }
    #[getter]
    fn ports<'py>(&self, py: Python<'py>) -> Bound<'py, PyAny> {
        self.ports.bind(py).clone()
    }
    #[setter]
    fn set_ports(&mut self, value: Py<PyAny>) {
        self.ports = value;
    }

    fn identity_hosts(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let mut out = Vec::new();
        for raw in strings(self.targets.bind(py)).into_iter().chain(strings(self.ips.bind(py))) {
            let h = norm_host(&raw);
            if !h.is_empty() && !out.contains(&h) {
                out.push(h);
            }
        }
        Ok(PyList::new(py, out)?.into_any().unbind())
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let d = PyDict::new(py);
        d.set_item("targets", self.targets.bind(py))?;
        d.set_item("ips", self.ips.bind(py))?;
        d.set_item("cidrs", self.cidrs.bind(py))?;
        d.set_item("ports", self.ports.bind(py))?;
        d.set_item("allow_subdomains", self.allow_subdomains)?;
        d.set_item("mode", &self.mode)?;
        Ok(d.unbind())
    }

    #[classmethod]
    fn from_dict(_cls: &Bound<PyType>, py: Python<'_>, d: Option<&Bound<PyDict>>) -> PyResult<Self> {
        let empty = PyDict::new(py);
        let d = d.unwrap_or(&empty);
        let get = |k: &str| d.get_item(k).ok().flatten();
        Scope::new(
            py,
            get("targets").as_ref(),
            get("ips").as_ref(),
            get("cidrs").as_ref(),
            get("ports").as_ref(),
            get("allow_subdomains").map(|v| v.is_truthy().unwrap_or(false)).unwrap_or(false),
            &get("mode").map(|v| v.extract::<String>().unwrap_or_else(|_| "strict".into())).unwrap_or_else(|| "strict".into()),
        )
    }

    #[pyo3(signature = (host, *, objective=None, allow_internal=false))]
    fn host_in_scope(&self, py: Python<'_>, host: &str, objective: Option<&str>, allow_internal: bool) -> PyResult<bool> {
        let _ = (objective, allow_internal);
        let dict = self.to_dict(py)?;
        let attackers = attacker_hosts(&[]);
        Ok(scope_host_in_scope(host, &dict.bind(py), attackers))
    }
}

fn as_list(py: Python<'_>, value: Option<&Bound<PyAny>>) -> PyResult<Py<PyList>> {
    let Some(value) = value else {
        return Ok(PyList::empty(py).unbind());
    };
    if value.is_none() {
        return Ok(PyList::empty(py).unbind());
    }
    if let Ok(list) = value.downcast::<PyList>() {
        return Ok(list.clone().unbind());
    }
    if let Ok(iter) = value.try_iter() {
        let list = PyList::empty(py);
        for item in iter {
            list.append(item?)?;
        }
        return Ok(list.unbind());
    }
    Ok(PyList::empty(py).unbind())
}

#[pyfunction]
pub fn local_self_hosts_py() -> Vec<String> {
    local_self_hosts()
}

#[pyfunction]
pub fn enumerate_local_ipv4s_py() -> Vec<String> {
    local_self_hosts()
}

#[pyfunction]
pub fn enumerate_local_gateways_py() -> Vec<String> {
    crate::osnet::gateways()
}

#[pyfunction]
#[pyo3(signature = (extra=None))]
pub fn attacker_identity_hosts_py(extra: Option<&Bound<PyAny>>) -> Vec<String> {
    let extra = extra.map(any_strings).unwrap_or_default();
    attacker_hosts(&extra)
}

#[pyfunction]
#[pyo3(signature = (host, extra=None))]
pub fn is_attacker_identity_py(host: &str, extra: Option<&Bound<PyAny>>) -> bool {
    let extra = extra.map(any_strings).unwrap_or_default();
    is_attacker(host, &attacker_hosts(&extra))
}

fn any_strings(value: &Bound<PyAny>) -> Vec<String> {
    value.try_iter().map(|it| it.filter_map(|x| x.ok().and_then(|v| v.extract::<String>().ok())).collect()).unwrap_or_default()
}

#[pyfunction]
#[pyo3(signature = (host, *, allow=None))]
pub fn on_local_docker_bridge_py(host: &str, allow: Option<&Bound<PyAny>>) -> Option<String> {
    let allow = allow.map(any_strings).unwrap_or_default();
    on_docker_bridge(host, &allow)
}

#[pyfunction]
pub fn local_self_networks_py() -> Vec<String> {
    local_networks()
}

pub fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Scope>()?;
    m.add_function(wrap_pyfunction!(local_self_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(enumerate_local_ipv4s_py, m)?)?;
    m.add_function(wrap_pyfunction!(enumerate_local_gateways_py, m)?)?;
    m.add_function(wrap_pyfunction!(attacker_identity_hosts_py, m)?)?;
    m.add_function(wrap_pyfunction!(is_attacker_identity_py, m)?)?;
    m.add_function(wrap_pyfunction!(on_local_docker_bridge_py, m)?)?;
    m.add_function(wrap_pyfunction!(local_self_networks_py, m)?)?;
    Ok(())
}
