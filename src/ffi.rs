use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::slice;

use scale::Decode;
use serde::Serialize;

use crate::intel;
use crate::quote::{EnclaveReport, Header, Quote, Report, TDReport10, TDReport15};
use crate::verify::{self, VerifiedReport};
use crate::QuoteCollateralV3;

// ---------------------------------------------------------------------------
// FFI-specific serialization structs (flattened for Go consumption)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct FfiQuote {
    header: Header,
    report: FfiReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert_chain_pem: Option<String>,
    fmspc: String,
    ca: String,
    quote_type: &'static str,
}

#[derive(Serialize)]
struct FfiReport {
    r#type: &'static str,
    #[serde(with = "serde_bytes")]
    report_data: Vec<u8>,
    // TDX fields
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    tee_tcb_svn: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_seam: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_signer_seam: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    seam_attributes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    td_attributes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    xfam: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_td: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_config_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_owner: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_owner_config: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    rt_mr0: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    rt_mr1: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    rt_mr2: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    rt_mr3: Option<Vec<u8>>,
    // TD15 extra
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    tee_tcb_svn2: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_service_td: Option<Vec<u8>>,
    // SGX fields
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    cpu_svn: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    misc_select: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    attributes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_enclave: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", with = "crate::ffi::opt_hex")]
    mr_signer: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    isv_prod_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    isv_svn: Option<u16>,
}

/// serde helper for Option<Vec<u8>> serialized as hex via serde_bytes when Some
mod opt_hex {
    use serde::Serializer;

    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(v) => serde_bytes::serialize(v, serializer),
            None => serializer.serialize_none(),
        }
    }
}

impl FfiReport {
    fn from_td10(r: &TDReport10) -> Self {
        Self {
            r#type: "TD10",
            report_data: r.report_data.to_vec(),
            tee_tcb_svn: Some(r.tee_tcb_svn.to_vec()),
            mr_seam: Some(r.mr_seam.to_vec()),
            mr_signer_seam: Some(r.mr_signer_seam.to_vec()),
            seam_attributes: Some(r.seam_attributes.to_vec()),
            td_attributes: Some(r.td_attributes.to_vec()),
            xfam: Some(r.xfam.to_vec()),
            mr_td: Some(r.mr_td.to_vec()),
            mr_config_id: Some(r.mr_config_id.to_vec()),
            mr_owner: Some(r.mr_owner.to_vec()),
            mr_owner_config: Some(r.mr_owner_config.to_vec()),
            rt_mr0: Some(r.rt_mr0.to_vec()),
            rt_mr1: Some(r.rt_mr1.to_vec()),
            rt_mr2: Some(r.rt_mr2.to_vec()),
            rt_mr3: Some(r.rt_mr3.to_vec()),
            tee_tcb_svn2: None,
            mr_service_td: None,
            cpu_svn: None,
            misc_select: None,
            attributes: None,
            mr_enclave: None,
            mr_signer: None,
            isv_prod_id: None,
            isv_svn: None,
        }
    }

    fn from_td15(r: &TDReport15) -> Self {
        let mut ffi = Self::from_td10(&r.base);
        ffi.r#type = "TD15";
        ffi.tee_tcb_svn2 = Some(r.tee_tcb_svn2.to_vec());
        ffi.mr_service_td = Some(r.mr_service_td.to_vec());
        ffi
    }

    fn from_sgx(r: &EnclaveReport) -> Self {
        Self {
            r#type: "SGX",
            report_data: r.report_data.to_vec(),
            cpu_svn: Some(r.cpu_svn.to_vec()),
            misc_select: Some(r.misc_select),
            attributes: Some(r.attributes.to_vec()),
            mr_enclave: Some(r.mr_enclave.to_vec()),
            mr_signer: Some(r.mr_signer.to_vec()),
            isv_prod_id: Some(r.isv_prod_id),
            isv_svn: Some(r.isv_svn),
            tee_tcb_svn: None,
            mr_seam: None,
            mr_signer_seam: None,
            seam_attributes: None,
            td_attributes: None,
            xfam: None,
            mr_td: None,
            mr_config_id: None,
            mr_owner: None,
            mr_owner_config: None,
            rt_mr0: None,
            rt_mr1: None,
            rt_mr2: None,
            rt_mr3: None,
            tee_tcb_svn2: None,
            mr_service_td: None,
        }
    }

    fn from_report(report: &Report) -> Self {
        match report {
            Report::SgxEnclave(r) => Self::from_sgx(r),
            Report::TD10(r) => Self::from_td10(r),
            Report::TD15(r) => Self::from_td15(r),
        }
    }
}

#[derive(Serialize)]
struct FfiVerifiedReport {
    status: String,
    advisory_ids: Vec<String>,
    report: FfiReport,
    #[serde(with = "serde_bytes")]
    ppid: Vec<u8>,
    qe_status: crate::tcb_info::TcbStatusWithAdvisory,
    platform_status: crate::tcb_info::TcbStatusWithAdvisory,
}

impl FfiVerifiedReport {
    fn from(vr: VerifiedReport) -> Self {
        Self {
            status: vr.status,
            advisory_ids: vr.advisory_ids,
            report: FfiReport::from_report(&vr.report),
            ppid: vr.ppid,
            qe_status: vr.qe_status,
            platform_status: vr.platform_status,
        }
    }
}

#[derive(Serialize)]
struct FfiPckExtension {
    #[serde(with = "serde_bytes")]
    ppid: Vec<u8>,
    #[serde(with = "serde_bytes")]
    cpu_svn: Vec<u8>,
    pce_svn: u16,
    #[serde(with = "serde_bytes")]
    pce_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    fmspc: Vec<u8>,
    sgx_type: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_instance_id: Option<serde_bytes::ByteBuf>,
    #[serde(with = "serde_bytes")]
    raw_extension: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a JSON string into a Rust-allocated buffer and return it through FFI pointers.
/// Returns 0 on success.
unsafe fn write_output(json: String, out_json: *mut *mut u8, out_len: *mut usize) {
    let bytes = json.into_bytes();
    let len = bytes.len();
    let ptr = bytes.as_ptr();
    let leaked = alloc::boxed::Box::leak(bytes.into_boxed_slice());
    *out_json = leaked.as_mut_ptr();
    *out_len = len;
    let _ = ptr; // suppress unused
}

unsafe fn write_error(msg: String, out_json: *mut *mut u8, out_len: *mut usize) -> i32 {
    write_output(msg, out_json, out_len);
    1
}

fn format_error(e: &anyhow::Error) -> String {
    let mut msg = e.to_string();
    let mut source = e.source();
    while let Some(err) = source {
        msg.push_str(": ");
        msg.push_str(&err.to_string());
        source = err.source();
    }
    msg
}

// ---------------------------------------------------------------------------
// extern "C" functions
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn dcap_parse_quote(
    quote: *const u8,
    quote_len: usize,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let quote_slice = slice::from_raw_parts(quote, quote_len);
    let parsed = match Quote::decode(&mut &quote_slice[..]) {
        Ok(q) => q,
        Err(e) => return write_error(format!("Failed to parse quote: {e}"), out_json, out_len),
    };

    let cert_chain_pem = parsed.raw_cert_chain().ok().map(|raw| {
        let mut end = raw.len();
        while end > 0 && raw[end.saturating_sub(1)] == 0 {
            end = end.saturating_sub(1);
        }
        String::from_utf8_lossy(&raw[..end]).into_owned()
    });

    let fmspc = match parsed.fmspc() {
        Ok(f) => hex::encode_upper(f),
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let ca = match parsed.ca() {
        Ok(c) => c.to_string(),
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let quote_type = if parsed.header.is_sgx() { "SGX" } else { "TDX" };

    let ffi_quote = FfiQuote {
        header: parsed.header,
        report: FfiReport::from_report(&parsed.report),
        cert_chain_pem,
        fmspc,
        ca,
        quote_type,
    };

    let json = match serde_json::to_string(&ffi_quote) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_verify(
    quote: *const u8,
    quote_len: usize,
    collateral_json: *const u8,
    coll_len: usize,
    now_secs: u64,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let quote_slice = slice::from_raw_parts(quote, quote_len);
    let coll_slice = slice::from_raw_parts(collateral_json, coll_len);

    let collateral: QuoteCollateralV3 = match serde_json::from_slice(coll_slice) {
        Ok(c) => c,
        Err(e) => {
            return write_error(
                format!("Failed to parse collateral JSON: {e}"),
                out_json,
                out_len,
            )
        }
    };

    let report = match verify::verify(quote_slice, &collateral, now_secs) {
        Ok(r) => r,
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let ffi_report = FfiVerifiedReport::from(report);
    let json = match serde_json::to_string(&ffi_report) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_verify_with_root_ca(
    quote: *const u8,
    quote_len: usize,
    collateral_json: *const u8,
    coll_len: usize,
    root_ca_der: *const u8,
    root_ca_len: usize,
    now_secs: u64,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let quote_slice = slice::from_raw_parts(quote, quote_len);
    let coll_slice = slice::from_raw_parts(collateral_json, coll_len);
    let root_ca = slice::from_raw_parts(root_ca_der, root_ca_len);

    let collateral: QuoteCollateralV3 = match serde_json::from_slice(coll_slice) {
        Ok(c) => c,
        Err(e) => {
            return write_error(
                format!("Failed to parse collateral JSON: {e}"),
                out_json,
                out_len,
            )
        }
    };

    let verifier = verify::QuoteVerifier::new(
        root_ca.to_vec(),
        verify::default_crypto::backend(),
    );

    let report = match verifier.verify(quote_slice, &collateral, now_secs) {
        Ok(r) => r,
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let ffi_report = FfiVerifiedReport::from(report);
    let json = match serde_json::to_string(&ffi_report) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_get_collateral(
    pccs_url: *const u8,
    url_len: usize,
    quote: *const u8,
    quote_len: usize,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let url_slice = slice::from_raw_parts(pccs_url, url_len);
    let url = match core::str::from_utf8(url_slice) {
        Ok(s) => s,
        Err(e) => return write_error(format!("Invalid URL: {e}"), out_json, out_len),
    };
    let quote_slice = slice::from_raw_parts(quote, quote_len);

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return write_error(format!("Failed to create runtime: {e}"), out_json, out_len),
    };

    let collateral = match rt.block_on(crate::collateral::get_collateral(url, quote_slice)) {
        Ok(c) => c,
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let json = match serde_json::to_string(&collateral) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_get_collateral_for_fmspc(
    pccs_url: *const u8,
    url_len: usize,
    fmspc: *const u8,
    fmspc_len: usize,
    ca: *const u8,
    ca_len: usize,
    is_sgx: i32,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let url_str = match core::str::from_utf8(slice::from_raw_parts(pccs_url, url_len)) {
        Ok(s) => s,
        Err(e) => return write_error(format!("Invalid URL: {e}"), out_json, out_len),
    };
    let fmspc_str = match core::str::from_utf8(slice::from_raw_parts(fmspc, fmspc_len)) {
        Ok(s) => s,
        Err(e) => return write_error(format!("Invalid FMSPC: {e}"), out_json, out_len),
    };
    let ca_str = match core::str::from_utf8(slice::from_raw_parts(ca, ca_len)) {
        Ok(s) => s,
        Err(e) => return write_error(format!("Invalid CA: {e}"), out_json, out_len),
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return write_error(format!("Failed to create runtime: {e}"), out_json, out_len),
    };

    let collateral = match rt.block_on(crate::collateral::get_collateral_for_fmspc(
        url_str,
        fmspc_str.to_string(),
        ca_str,
        is_sgx != 0,
    )) {
        Ok(c) => c,
        Err(e) => return write_error(format_error(&e), out_json, out_len),
    };

    let json = match serde_json::to_string(&collateral) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_parse_pck_extension_from_pem(
    pem: *const u8,
    pem_len: usize,
    out_json: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let pem_slice = slice::from_raw_parts(pem, pem_len);

    let ext = match intel::parse_pck_extension_from_pem(pem_slice) {
        Ok(e) => e,
        Err(e) => {
            return write_error(
                format!("Failed to parse PCK extension: {e}"),
                out_json,
                out_len,
            )
        }
    };

    let ffi_ext = FfiPckExtension {
        ppid: ext.ppid,
        cpu_svn: ext.cpu_svn.to_vec(),
        pce_svn: ext.pce_svn,
        pce_id: ext.pce_id.to_vec(),
        fmspc: ext.fmspc.to_vec(),
        sgx_type: ext.sgx_type,
        platform_instance_id: ext
            .platform_instance_id
            .map(|v| serde_bytes::ByteBuf::from(v)),
        raw_extension: ext.raw_extension,
    };

    let json = match serde_json::to_string(&ffi_ext) {
        Ok(j) => j,
        Err(e) => return write_error(format!("JSON serialization failed: {e}"), out_json, out_len),
    };

    write_output(json, out_json, out_len);
    0
}

#[no_mangle]
pub unsafe extern "C" fn dcap_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(alloc::boxed::Box::from_raw(slice::from_raw_parts_mut(
            ptr, len,
        )));
    }
}
