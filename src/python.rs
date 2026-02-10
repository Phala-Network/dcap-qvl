use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3_async_runtimes::tokio::future_into_py;
use serde_json;

use crate::{
    collateral::get_collateral_for_fmspc,
    intel,
    quote::{EnclaveReport, Header, Quote, Report, TDReport10, TDReport15},
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
                pck_certificate_chain: None,
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
    fn ppid(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.ppid).into()
    }

    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize to JSON: {}", e)))
    }
}

/// Quote header parsed from raw quote.
#[pyclass]
#[derive(Clone, Copy)]
pub struct PyQuoteHeader {
    inner: Header,
}

#[pymethods]
impl PyQuoteHeader {
    #[getter]
    fn version(&self) -> u16 {
        self.inner.version
    }

    #[getter]
    fn attestation_key_type(&self) -> u16 {
        self.inner.attestation_key_type
    }

    #[getter]
    fn tee_type(&self) -> u32 {
        self.inner.tee_type
    }

    #[getter]
    fn qe_svn(&self) -> u16 {
        self.inner.qe_svn
    }

    #[getter]
    fn pce_svn(&self) -> u16 {
        self.inner.pce_svn
    }

    #[getter]
    fn qe_vendor_id(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.qe_vendor_id).into()
    }

    #[getter]
    fn user_data(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.user_data).into()
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct PyTdReport10 {
    inner: TDReport10,
}

#[pymethods]
impl PyTdReport10 {
    #[getter]
    fn tee_tcb_svn(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.tee_tcb_svn).into()
    }
    #[getter]
    fn mr_seam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_seam).into()
    }
    #[getter]
    fn mr_signer_seam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_signer_seam).into()
    }
    #[getter]
    fn seam_attributes(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.seam_attributes).into()
    }
    #[getter]
    fn td_attributes(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.td_attributes).into()
    }
    #[getter]
    fn xfam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.xfam).into()
    }
    #[getter]
    fn mr_td(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_td).into()
    }
    #[getter]
    fn mr_config_id(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_config_id).into()
    }
    #[getter]
    fn mr_owner(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_owner).into()
    }
    #[getter]
    fn mr_owner_config(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_owner_config).into()
    }
    #[getter]
    fn rt_mr0(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.rt_mr0).into()
    }
    #[getter]
    fn rt_mr1(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.rt_mr1).into()
    }
    #[getter]
    fn rt_mr2(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.rt_mr2).into()
    }
    #[getter]
    fn rt_mr3(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.rt_mr3).into()
    }
    #[getter]
    fn report_data(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.report_data).into()
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct PyTdReport15 {
    inner: TDReport15,
}

#[pymethods]
impl PyTdReport15 {
    // Flatten fields from base TDReport10
    #[getter]
    fn tee_tcb_svn(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.tee_tcb_svn).into()
    }
    #[getter]
    fn mr_seam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_seam).into()
    }
    #[getter]
    fn mr_signer_seam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_signer_seam).into()
    }
    #[getter]
    fn seam_attributes(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.seam_attributes).into()
    }
    #[getter]
    fn td_attributes(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.td_attributes).into()
    }
    #[getter]
    fn xfam(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.xfam).into()
    }
    #[getter]
    fn mr_td(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_td).into()
    }
    #[getter]
    fn mr_config_id(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_config_id).into()
    }
    #[getter]
    fn mr_owner(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_owner).into()
    }
    #[getter]
    fn mr_owner_config(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.mr_owner_config).into()
    }
    #[getter]
    fn rt_mr0(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.rt_mr0).into()
    }
    #[getter]
    fn rt_mr1(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.rt_mr1).into()
    }
    #[getter]
    fn rt_mr2(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.rt_mr2).into()
    }
    #[getter]
    fn rt_mr3(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.rt_mr3).into()
    }
    #[getter]
    fn report_data(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.base.report_data).into()
    }

    // TD15 extra fields
    #[getter]
    fn tee_tcb_svn2(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.tee_tcb_svn2).into()
    }

    #[getter]
    fn mr_service_td(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_service_td).into()
    }
}

#[pyclass]
#[derive(Clone, Copy)]
pub struct PySgxEnclaveReport {
    inner: EnclaveReport,
}

#[pymethods]
impl PySgxEnclaveReport {
    #[getter]
    fn cpu_svn(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.cpu_svn).into()
    }

    #[getter]
    fn attributes(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.attributes).into()
    }

    #[getter]
    fn mr_enclave(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_enclave).into()
    }

    #[getter]
    fn mr_signer(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.mr_signer).into()
    }

    #[getter]
    fn report_data(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.report_data).into()
    }
}

#[pyclass]
#[derive(Clone)]
pub struct PyPckExtension {
    inner: intel::PckExtension,
}

#[pymethods]
impl PyPckExtension {
    #[getter]
    fn ppid(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.ppid).into()
    }

    #[getter]
    fn cpu_svn(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.cpu_svn).into()
    }

    #[getter]
    fn pce_svn(&self) -> u16 {
        self.inner.pce_svn
    }

    #[getter]
    fn pce_id(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.pce_id).into()
    }

    #[getter]
    fn fmspc(&self, py: Python<'_>) -> PyObject {
        PyBytes::new(py, &self.inner.fmspc).into()
    }

    #[getter]
    fn sgx_type(&self) -> u64 {
        self.inner.sgx_type
    }

    #[getter]
    fn platform_instance_id(&self, py: Python<'_>) -> Option<PyObject> {
        self.inner
            .platform_instance_id
            .as_ref()
            .map(|v| PyBytes::new(py, v).into())
    }

    /// Look up an arbitrary OID inside the raw Intel SGX extension.
    fn get_value(&self, oid: &str, py: Python<'_>) -> PyResult<Option<PyObject>> {
        let parsed_oid = const_oid::ObjectIdentifier::new(oid)
            .map_err(|e| PyValueError::new_err(format!("Invalid OID '{}': {}", oid, e)))?;
        match self.inner.get_value(&parsed_oid) {
            Ok(Some(bytes)) => Ok(Some(PyBytes::new(py, &bytes).into())),
            Ok(None) => Ok(None),
            Err(e) => Err(PyValueError::new_err(format!(
                "Failed to look up OID: {}",
                e
            ))),
        }
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

    /// Parsed quote header.
    #[getter]
    fn header(&self) -> PyQuoteHeader {
        PyQuoteHeader {
            inner: self.inner.header,
        }
    }

    /// Parsed quote report (TDX TDREPORT10/15 or SGX enclave report).
    #[getter]
    fn report<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.inner.report {
            Report::SgxEnclave(r) => Ok(Py::new(py, PySgxEnclaveReport { inner: *r })?
                .into_pyobject(py)
                .unwrap()
                .into_any()),
            Report::TD10(r) => Ok(Py::new(py, PyTdReport10 { inner: *r })?
                .into_pyobject(py)
                .unwrap()
                .into_any()),
            Report::TD15(r) => Ok(Py::new(py, PyTdReport15 { inner: *r })?
                .into_pyobject(py)
                .unwrap()
                .into_any()),
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

    /// Get the embedded PCK certificate chain in PEM form, if present.
    ///
    /// Returns bytes instead of str to avoid implicit decoding/copying.
    fn cert_chain_pem_bytes(&self, py: Python<'_>) -> PyResult<Option<PyObject>> {
        let raw = match self.inner.raw_cert_chain() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let mut end = raw.len();
        while end > 0 && raw[end - 1] == 0 {
            end -= 1;
        }
        Ok(Some(PyBytes::new(py, &raw[..end]).into()))
    }

    /// Parse the Intel SGX extension from the leaf PCK certificate.
    ///
    /// Returns None if the quote does not contain a parseable leaf certificate.
    fn pck_extension(&self) -> PyResult<Option<PyPckExtension>> {
        let certs = match intel::extract_cert_chain(&self.inner) {
            Ok(certs) => certs,
            Err(_) => return Ok(None),
        };
        let leaf = match certs.first() {
            Some(c) => c,
            None => return Ok(None),
        };
        match intel::parse_pck_extension(leaf) {
            Ok(ext) => Ok(Some(PyPckExtension { inner: ext })),
            Err(_) => Ok(None),
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

    let verifier = crate::verify::QuoteVerifier::new(
        root_ca.to_vec(),
        crate::verify::default_crypto::backend(),
    );
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

#[pyfunction]
fn parse_pck_extension_from_pem(pem_bytes: &Bound<'_, PyBytes>) -> PyResult<PyPckExtension> {
    let pem_data = pem_bytes.as_bytes();
    match intel::parse_pck_extension_from_pem(pem_data) {
        Ok(ext) => Ok(PyPckExtension { inner: ext }),
        Err(e) => Err(PyValueError::new_err(format!(
            "Failed to parse PCK extension: {}",
            e
        ))),
    }
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
    m.add_class::<PyQuoteHeader>()?;
    m.add_class::<PyTdReport10>()?;
    m.add_class::<PyTdReport15>()?;
    m.add_class::<PySgxEnclaveReport>()?;
    m.add_class::<PyPckExtension>()?;
    m.add_class::<PyQuote>()?;
    m.add_function(wrap_pyfunction!(py_verify, m)?)?;
    m.add_function(wrap_pyfunction!(py_verify_with_root_ca, m)?)?;
    m.add_function(wrap_pyfunction!(parse_quote, m)?)?;
    m.add_function(wrap_pyfunction!(parse_pck_extension_from_pem, m)?)?;
    m.add_function(wrap_pyfunction!(get_collateral_for_fmspc_py, m)?)?;

    Ok(())
}
