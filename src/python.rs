use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_async_runtimes::tokio::future_into_py;
use serde_json;

use crate::{
    collateral::get_collateral_for_fmspc,
    quote::Quote,
    verify::{verify, VerifiedReport},
    QuoteCollateralV3,
};

#[pyclass]
#[derive(Clone)]
pub struct PyQuoteCollateralV3 {
    inner: QuoteCollateralV3,
}

#[pymethods]
impl PyQuoteCollateralV3 {
    #[new]
    fn new(
        pck_crl_issuer_chain: String,
        root_ca_crl: Vec<u8>,
        pck_crl: Vec<u8>,
        tcb_info_issuer_chain: String,
        tcb_info: String,
        tcb_info_signature: Vec<u8>,
        qe_identity_issuer_chain: String,
        qe_identity: String,
        qe_identity_signature: Vec<u8>,
    ) -> Self {
        Self {
            inner: QuoteCollateralV3 {
                pck_crl_issuer_chain,
                root_ca_crl,
                pck_crl,
                tcb_info_issuer_chain,
                tcb_info,
                tcb_info_signature,
                qe_identity_issuer_chain,
                qe_identity,
                qe_identity_signature,
            },
        }
    }

    #[getter]
    fn pck_crl_issuer_chain(&self) -> &str {
        &self.inner.pck_crl_issuer_chain
    }

    #[getter]
    fn root_ca_crl(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.root_ca_crl).into()
    }

    #[getter]
    fn pck_crl(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.pck_crl).into()
    }

    #[getter]
    fn tcb_info_issuer_chain(&self) -> &str {
        &self.inner.tcb_info_issuer_chain
    }

    #[getter]
    fn tcb_info(&self) -> &str {
        &self.inner.tcb_info
    }

    #[getter]
    fn tcb_info_signature(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.tcb_info_signature).into()
    }

    #[getter]
    fn qe_identity_issuer_chain(&self) -> &str {
        &self.inner.qe_identity_issuer_chain
    }

    #[getter]
    fn qe_identity(&self) -> &str {
        &self.inner.qe_identity
    }

    #[getter]
    fn qe_identity_signature(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.qe_identity_signature).into()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize to JSON: {}", e)))
    }

    #[staticmethod]
    fn from_json(json_str: &str) -> PyResult<Self> {
        let inner: QuoteCollateralV3 = serde_json::from_str(json_str)
            .map_err(|e| PyValueError::new_err(format!("Failed to parse JSON: {}", e)))?;
        Ok(Self { inner })
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyVerifiedReport {
    inner: VerifiedReport,
}

#[pymethods]
impl PyVerifiedReport {
    #[getter]
    fn status(&self) -> &str {
        &self.inner.status
    }

    #[getter]
    fn advisory_ids(&self) -> Vec<String> {
        self.inner.advisory_ids.clone()
    }

    #[getter]
    fn ppid(&self) -> Vec<u8> {
        self.inner.ppid.clone()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize to JSON: {}", e)))
    }
}

#[pyclass]
pub struct PyQuote {
    inner: Quote,
}

#[pymethods]
impl PyQuote {
    #[staticmethod]
    fn parse(raw_quote: &Bound<'_, PyBytes>) -> PyResult<Self> {
        let quote_bytes = raw_quote.as_bytes();
        match Quote::parse(quote_bytes) {
            Ok(quote) => Ok(PyQuote { inner: quote }),
            Err(e) => Err(PyValueError::new_err(format!(
                "Failed to parse quote: {}",
                e
            ))),
        }
    }

    fn fmspc(&self) -> PyResult<String> {
        match self.inner.fmspc() {
            Ok(fmspc) => Ok(hex::encode_upper(fmspc)),
            Err(e) => Err(PyValueError::new_err(format!("Failed to get FMSPC: {}", e))),
        }
    }

    fn ca(&self) -> PyResult<String> {
        match self.inner.ca() {
            Ok(ca) => Ok(ca.to_string()),
            Err(e) => Err(PyValueError::new_err(format!("Failed to get CA: {}", e))),
        }
    }

    fn is_tdx(&self) -> bool {
        !self.is_sgx()
    }

    fn is_sgx(&self) -> bool {
        self.inner.header.is_sgx()
    }

    fn quote_type(&self) -> String {
        if self.inner.header.is_sgx() {
            "SGX".to_string()
        } else {
            "TDX".to_string()
        }
    }
}

#[pyfunction]
fn py_verify(
    raw_quote: &Bound<'_, PyBytes>,
    collateral: &PyQuoteCollateralV3,
    now_secs: u64,
) -> PyResult<PyVerifiedReport> {
    let quote_bytes = raw_quote.as_bytes();

    match verify(quote_bytes, &collateral.inner, now_secs) {
        Ok(verified_report) => Ok(PyVerifiedReport {
            inner: verified_report,
        }),
        Err(e) => Err(PyValueError::new_err(format!("Verification failed: {e:?}"))),
    }
}

#[pyfunction]
fn py_verify_with_root_ca(
    raw_quote: &Bound<'_, PyBytes>,
    collateral: &PyQuoteCollateralV3,
    root_ca_der: &Bound<'_, PyBytes>,
    now_secs: u64,
) -> PyResult<PyVerifiedReport> {
    let quote_bytes = raw_quote.as_bytes();
    let root_ca = root_ca_der.as_bytes();

    let verifier = crate::verify::QuoteVerifier::new_with_root_ca(root_ca.to_vec());
    match verifier.verify(quote_bytes, &collateral.inner, now_secs) {
        Ok(verified_report) => Ok(PyVerifiedReport {
            inner: verified_report,
        }),
        Err(e) => Err(PyValueError::new_err(format!("Verification failed: {e:?}"))),
    }
}

#[pyfunction]
fn parse_quote(raw_quote: &Bound<'_, PyBytes>) -> PyResult<PyQuote> {
    PyQuote::parse(raw_quote)
}

#[pyfunction(name = "get_collateral_for_fmspc")]
fn get_collateral_for_fmspc_py<'py>(
    py: Python<'py>,
    pccs_url: String,
    fmspc: String,
    ca: String,
    for_sgx: bool,
) -> PyResult<Bound<'py, PyAny>> {
    future_into_py(py, async move {
        // Convert ca String to &'static str by leaking it
        // This is necessary because the Rust function expects &'static str
        let ca_static: &'static str = Box::leak(ca.into_boxed_str());

        match get_collateral_for_fmspc(&pccs_url, fmspc, ca_static, for_sgx).await {
            Ok(collateral) => Ok(PyQuoteCollateralV3 { inner: collateral }),
            Err(e) => Err(PyValueError::new_err(format!(
                "Failed to get collateral for FMSPC: {}",
                e
            ))),
        }
    })
}

pub fn register_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyQuoteCollateralV3>()?;
    m.add_class::<PyVerifiedReport>()?;
    m.add_class::<PyQuote>()?;
    m.add_function(wrap_pyfunction!(py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_with_root_ca, m)?)?;
    m.add_function(wrap_pyfunction!(parse_quote, m)?)?;
    m.add_function(wrap_pyfunction!(get_collateral_for_fmspc_py, m)?)?;

    Ok(())
}
