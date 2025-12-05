use core::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use scale::Decode;
use webpki::types::UnixTime;

use {
    crate::constants::*, crate::intel, crate::tcb_info::TcbInfo, alloc::borrow::ToOwned,
    alloc::string::String, alloc::vec::Vec,
};

pub use crate::quote::{AuthData, EnclaveReport, Quote};
use crate::{
    quote::{Report, TDAttributes},
    utils::{self, encode_as_der, extract_certs, verify_certificate_chain},
};
use crate::{
    quote::{TDReport10, TDReport15},
    QuoteCollateralV3,
};
use serde::{Deserialize, Serialize};
use webpki::types::CertificateDer;

#[cfg(feature = "js")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "js")]
fn format_error_chain(e: &anyhow::Error) -> String {
    use alloc::format;
    let mut msg = format!("{}", e);
    let mut source = e.source();
    while let Some(err) = source {
        msg.push_str(&format!("\n  Caused by: {}", err));
        source = err.source();
    }
    msg
}

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
}

/// Quote verifier with configurable root certificate
///
/// This allows using custom root certificates for testing or private deployments.
#[derive(Clone)]
pub struct QuoteVerifier {
    root_ca_der: Vec<u8>,
}

impl QuoteVerifier {
    /// Create a new verifier using Intel's production root certificate
    pub fn new_prod() -> Self {
        Self::new_with_root_ca(TRUSTED_ROOT_CA_DER.to_vec())
    }

    /// Create a new verifier with a custom root certificate
    ///
    /// # Arguments
    /// * `root_ca_der` - DER-encoded root certificate
    pub fn new_with_root_ca(root_ca_der: Vec<u8>) -> Self {
        Self { root_ca_der }
    }

    /// Verify a quote with the configured root certificate
    ///
    /// # Arguments
    /// * `raw_quote` - The raw quote bytes
    /// * `collateral` - The quote collateral
    /// * `now_secs` - Current time in seconds since UNIX epoch
    ///
    /// # Returns
    /// * `Ok(VerifiedReport)` - The verified report
    /// * `Err(Error)` - The error
    pub fn verify(
        &self,
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        verify_impl(raw_quote, collateral, now_secs, &self.root_ca_der)
    }
}

#[cfg(feature = "js")]
#[wasm_bindgen]
pub fn js_verify(
    raw_quote: JsValue,
    quote_collateral: JsValue,
    now: u64,
) -> Result<JsValue, JsValue> {
    let raw_quote: Vec<u8> = serde_wasm_bindgen::from_value(raw_quote)
        .map_err(|_| JsValue::from_str("Failed to decode raw_quote"))?;
    let quote_collateral = serde_wasm_bindgen::from_value::<QuoteCollateralV3>(quote_collateral)?;

    let verified_report = verify(&raw_quote, &quote_collateral, now).map_err(|e| {
        let error_msg = format_error_chain(&e);
        serde_wasm_bindgen::to_value(&error_msg)
            .unwrap_or_else(|_| JsValue::from_str("Failed to encode Error"))
    })?;

    serde_wasm_bindgen::to_value(&verified_report)
        .map_err(|_| JsValue::from_str("Failed to encode verified_report"))
}

#[cfg(feature = "js")]
#[wasm_bindgen]
pub fn js_verify_with_root_ca(
    raw_quote: JsValue,
    quote_collateral: JsValue,
    root_ca_der: JsValue,
    now: u64,
) -> Result<JsValue, JsValue> {
    let raw_quote: Vec<u8> = serde_wasm_bindgen::from_value(raw_quote)
        .map_err(|_| JsValue::from_str("Failed to decode raw_quote"))?;
    let quote_collateral = serde_wasm_bindgen::from_value::<QuoteCollateralV3>(quote_collateral)?;
    let root_ca_der: Vec<u8> = serde_wasm_bindgen::from_value(root_ca_der)
        .map_err(|_| JsValue::from_str("Failed to decode root_ca_der"))?;

    let verifier = QuoteVerifier::new_with_root_ca(root_ca_der);
    let verified_report = verifier
        .verify(&raw_quote, &quote_collateral, now)
        .map_err(|e| {
            let error_msg = format_error_chain(&e);
            serde_wasm_bindgen::to_value(&error_msg)
                .unwrap_or_else(|_| JsValue::from_str("Failed to encode Error"))
        })?;

    serde_wasm_bindgen::to_value(&verified_report)
        .map_err(|_| JsValue::from_str("Failed to encode verified_report"))
}

#[cfg(feature = "js")]
#[wasm_bindgen]
pub async fn js_get_collateral(pccs_url: JsValue, raw_quote: JsValue) -> Result<JsValue, JsValue> {
    let pccs_url: String = serde_wasm_bindgen::from_value(pccs_url)
        .map_err(|_| JsValue::from_str("Failed to decode pccs_url"))?;
    let raw_quote: Vec<u8> = serde_wasm_bindgen::from_value(raw_quote)
        .map_err(|_| JsValue::from_str("Failed to decode raw_quote"))?;

    let collateral: QuoteCollateralV3 = crate::collateral::get_collateral(&pccs_url, &raw_quote)
        .await
        .map_err(|e| JsValue::from_str(&format_error_chain(&e)))?;
    serde_wasm_bindgen::to_value(&collateral)
        .map_err(|_| JsValue::from_str("Failed to encode collateral"))
}

// Internal implementation that uses QuoteVerifier
fn verify_impl(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    root_ca_der: &[u8],
) -> Result<VerifiedReport> {
    let root_ca = CertificateDer::from_slice(root_ca_der);
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_ca).context("Failed to load root ca")?;
    // Parse data
    let mut quote = raw_quote;
    let quote = Quote::decode(&mut quote).context("Failed to decode quote")?;
    let signed_quote_len = quote.signed_length();

    let tcb_info = serde_json::from_str::<TcbInfo>(&collateral.tcb_info)
        .context("Failed to decode TcbInfo")?;

    let next_update = chrono::DateTime::parse_from_rfc3339(&tcb_info.next_update)
        .ok()
        .context("Failed to parse next update")?;
    if now_secs > next_update.timestamp() as u64 {
        bail!("TCBInfo expired");
    }

    let crls = [&collateral.root_ca_crl[..], &collateral.pck_crl];
    // Because the original rustls-webpki doesn't check the ROOT CA against the CRL, we use our forked webpki to check it
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
    dcap_qvl_webpki::check_single_cert_crl(root_ca_der, &crls, now)?;

    // Verify enclave

    // Seems we verify MR_ENCLAVE and MR_SIGNER is enough
    // skip verify_misc_select_field
    // skip verify_attributes_field

    // Verify integrity

    // Check TCB info cert chain and signature
    let tcb_leaf_certs = extract_certs(collateral.tcb_info_issuer_chain.as_bytes())?;
    if tcb_leaf_certs.len() < 2 {
        bail!("Certificate chain is too short in quote_collateral");
    }
    let tcb_leaf_cert = webpki::EndEntityCert::try_from(&tcb_leaf_certs[0])
        .context("Failed to parse leaf certificate in quote_collateral")?;
    verify_certificate_chain(
        &tcb_leaf_cert,
        &tcb_leaf_certs[1..],
        now,
        &crls,
        trust_anchor.clone(),
    )?;
    let asn1_signature = encode_as_der(&collateral.tcb_info_signature)?;
    if tcb_leaf_cert
        .verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            collateral.tcb_info.as_bytes(),
            &asn1_signature,
        )
        .is_err()
    {
        return Err(anyhow!(
            "Signature is invalid for tcb_info in quote_collateral"
        ));
    }

    // Check quote fields
    if ![3, 4, 5].contains(&quote.header.version) {
        return Err(anyhow!("Unsupported DCAP quote version"));
    }
    // We only support ECDSA256 with P256 curve
    if quote.header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE {
        bail!("Unsupported DCAP attestation key type");
    }

    // Extract Auth data from quote
    let auth_data = quote.auth_data.into_v3();
    let certification_data = auth_data.certification_data;

    // We only support 5 -Concatenated PCK Cert Chain (PEM formatted).
    if certification_data.cert_type != PCK_CERT_CHAIN {
        bail!("Unsupported DCAP PCK cert format");
    }

    // Extract PCK certificate chain from certification data in the quote
    let qe_certification_certs = extract_certs(&certification_data.body.data)
        .context("Failed to extract PCK certificates")?;

    if qe_certification_certs.len() < 2 {
        bail!("Certificate chain is too short in quote");
    }

    let qe_leaf_cert = webpki::EndEntityCert::try_from(&qe_certification_certs[0])
        .context("Failed to parse PCK certificate")?;
    // Then verify the certificate chain
    verify_certificate_chain(
        &qe_leaf_cert,
        &qe_certification_certs[1..],
        now,
        &crls,
        trust_anchor.clone(),
    )?;

    let ppid = intel::parse_pck_extension(qe_certification_certs[0].as_ref())
        .ok()
        .map(|ext| ext.ppid.clone())
        .unwrap_or_default();

    // Check QE signature
    let asn1_signature = encode_as_der(&auth_data.qe_report_signature)?;
    if qe_leaf_cert
        .verify_signature(
            webpki::ring::ECDSA_P256_SHA256,
            &auth_data.qe_report,
            &asn1_signature,
        )
        .is_err()
    {
        return Err(anyhow!("Signature is invalid for qe_report in quote"));
    }

    // Extract QE report from quote
    let mut qe_report = auth_data.qe_report.as_slice();
    let qe_report = EnclaveReport::decode(&mut qe_report).context("Failed to decode QE report")?;

    // Check QE hash
    let mut qe_hash_data = [0u8; QE_HASH_DATA_BYTE_LEN];
    qe_hash_data[0..ATTESTATION_KEY_LEN].copy_from_slice(&auth_data.ecdsa_attestation_key);
    qe_hash_data[ATTESTATION_KEY_LEN..].copy_from_slice(&auth_data.qe_auth_data.data);
    let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
    if qe_hash.as_ref() != &qe_report.report_data[0..32] {
        bail!("QE report hash mismatch");
    }

    // Check signature from auth data
    let mut pub_key = [0x04u8; 65]; //Prepend 0x04 to specify uncompressed format
    pub_key[1..].copy_from_slice(&auth_data.ecdsa_attestation_key);
    let peer_public_key =
        ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pub_key);
    peer_public_key
        .verify(
            raw_quote
                .get(..signed_quote_len)
                .ok_or(anyhow!("Failed to get signed quote"))?,
            &auth_data.ecdsa_signature,
        )
        .map_err(|_| anyhow!("Isv enclave report signature is invalid"))?;

    // Extract information from the quote

    let extension_section = utils::get_intel_extension(&qe_certification_certs[0])?;
    let cpu_svn = utils::get_cpu_svn(&extension_section)?;
    let pce_svn = utils::get_pce_svn(&extension_section)?;
    let fmspc = utils::get_fmspc(&extension_section)?;

    let tcb_fmspc = hex::decode(&tcb_info.fmspc)
        .ok()
        .context("Failed to decode TCB FMSPC")?;
    if fmspc != tcb_fmspc[..] {
        bail!("Fmspc mismatch");
    }

    if quote.header.tee_type == TEE_TYPE_TDX && (tcb_info.version < 3 || tcb_info.id != "TDX") {
        bail!("TDX quote with non-TDX TCB info in the collateral");
    }

    // TCB status and advisory ids
    let mut tcb_status = "Unknown".to_owned();
    let mut advisory_ids = Vec::<String>::new();
    for tcb_level in &tcb_info.tcb_levels {
        if pce_svn < tcb_level.tcb.pce_svn {
            continue;
        }
        let sgx_components = tcb_level
            .tcb
            .sgx_components
            .iter()
            .map(|c| c.svn)
            .collect::<Vec<_>>();
        if sgx_components.is_empty() {
            bail!("No SGX components in the TCB info");
        }
        if cpu_svn[..] < sgx_components[..] {
            continue;
        }
        if quote.header.tee_type == TEE_TYPE_TDX {
            let td_report = quote
                .report
                .as_td10()
                .context("Failed to get TD10 report")?;
            let tdx_components = tcb_level
                .tcb
                .tdx_components
                .iter()
                .map(|c| c.svn)
                .collect::<Vec<_>>();
            if tdx_components.is_empty() {
                bail!("No TDX components in the TCB info");
            }
            if td_report.tee_tcb_svn[..] < tdx_components[..] {
                continue;
            }
        }

        tcb_status = tcb_level.tcb_status.clone();
        tcb_level
            .advisory_ids
            .iter()
            .for_each(|id| advisory_ids.push(id.clone()));
        break;
    }
    validate_attrs(&quote.report)?;
    Ok(VerifiedReport {
        status: tcb_status,
        advisory_ids,
        report: quote.report,
        ppid,
    })
}

fn validate_attrs(report: &Report) -> Result<()> {
    fn validate_td10(report: &TDReport10) -> Result<()> {
        let td_attrs =
            TDAttributes::parse(report.td_attributes).context("Failed to parse TD attributes")?;
        if td_attrs.tud != 0 {
            bail!("Debug mode is enabled");
        }
        if td_attrs.sec.reserved_lower != 0
            || td_attrs.sec.reserved_bit29
            || td_attrs.other.reserved != 0
        {
            bail!("Reserved bits in TD attributes are set");
        }
        if !td_attrs.sec.sept_ve_disable {
            bail!("SEPT_VE_DISABLE is not enabled");
        }
        Ok(())
    }
    fn validate_td15(report: &TDReport15) -> Result<()> {
        if report.mr_service_td != [0u8; 48] {
            bail!("Invalid mr service td");
        }
        validate_td10(&report.base)
    }
    fn validate_sgx(report: &EnclaveReport) -> Result<()> {
        let is_debug = report.attributes[0] & 0x02 != 0;
        if is_debug {
            bail!("Debug mode is enabled");
        }
        Ok(())
    }
    match &report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx(report),
    }
}

/// Verify a quote using Intel's trusted root CA
///
/// # Arguments
///
/// * `raw_quote` - The raw quote to verify. Supported SGX and TDX quotes.
/// * `quote_collateral` - The quote collateral to verify. Can be obtained from PCCS by `get_collateral`.
/// * `now` - The current time in seconds since the Unix epoch
///
/// # Returns
///
/// * `Ok(VerifiedReport)` - The verified report
/// * `Err(Error)` - The error
pub fn verify(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
) -> Result<VerifiedReport> {
    QuoteVerifier::new_prod().verify(raw_quote, collateral, now_secs)
}
