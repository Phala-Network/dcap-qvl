//! UniFFI-driven Kotlin/Swift bindings for `dcap-qvl`.
//!
//! Exposed surface mirrors the existing C FFI in `dcap-qvl/src/ffi.rs`:
//!
//! - [`parse_quote`] — decode an SGX/TDX quote into a structured [`Quote`].
//! - [`verify`] — verify a quote against collateral, using Intel's production
//!   root CA and the `ring` crypto backend.
//! - [`verify_with_root_ca`] — same, with a caller-supplied root CA.
//! - [`parse_pck_extension_from_pem`] — parse the Intel SGX extension from
//!   a PEM PCK certificate chain.
//!
//! Collateral is accepted as raw PCCS JSON bytes (the same shape PCCS returns
//! over HTTP). Mobile apps download the JSON via OkHttp / URLSession and pass
//! the bytes straight in — no field-by-field marshalling required.

use dcap_qvl::{
    intel as core_intel, quote::Quote as CoreQuote, verify::QuoteVerifier, QuoteCollateralV3,
};

uniffi::setup_scaffolding!();

mod errors;
mod types;

pub use errors::DcapError;
pub use types::*;

fn parse_collateral(bytes: &[u8]) -> Result<QuoteCollateralV3, DcapError> {
    serde_json::from_slice(bytes)
        .map_err(|e| DcapError::Parse(format!("Failed to parse collateral JSON: {e}")))
}

/// Parse an SGX/TDX quote binary into a structured [`Quote`].
#[uniffi::export]
pub fn parse_quote(raw_quote: Vec<u8>) -> Result<Quote, DcapError> {
    use scale::Decode;
    let parsed = CoreQuote::decode(&mut &raw_quote[..])
        .map_err(|e| DcapError::Parse(format!("Failed to parse quote: {e}")))?;
    Ok(Quote::from_core(&parsed))
}

/// Verify a quote against PCCS collateral JSON, using Intel's production
/// root CA and the `ring` crypto backend.
///
/// `collateral_json` is the raw response body returned by a PCCS — the same
/// shape produced by `dcap_qvl::collateral::CollateralClient`.
#[uniffi::export]
pub fn verify(
    raw_quote: Vec<u8>,
    collateral_json: Vec<u8>,
    now_secs: u64,
) -> Result<VerifiedReport, DcapError> {
    let collateral = parse_collateral(&collateral_json)?;
    let verifier = QuoteVerifier::new_prod();
    let report = verifier
        .verify(&raw_quote, &collateral, now_secs)
        .map_err(DcapError::from_anyhow)?;
    Ok(VerifiedReport::from_core(report))
}

/// Verify a quote against PCCS collateral JSON, with a custom DER-encoded
/// root CA.
#[uniffi::export]
pub fn verify_with_root_ca(
    raw_quote: Vec<u8>,
    collateral_json: Vec<u8>,
    root_ca_der: Vec<u8>,
    now_secs: u64,
) -> Result<VerifiedReport, DcapError> {
    let collateral = parse_collateral(&collateral_json)?;
    let verifier = QuoteVerifier::new(root_ca_der);
    let report = verifier
        .verify(&raw_quote, &collateral, now_secs)
        .map_err(DcapError::from_anyhow)?;
    Ok(VerifiedReport::from_core(report))
}

/// Parse the Intel SGX extension from a PEM-encoded PCK certificate chain.
#[uniffi::export]
pub fn parse_pck_extension_from_pem(pem: Vec<u8>) -> Result<PckExtension, DcapError> {
    let ext = core_intel::parse_pck_extension_from_pem(&pem)
        .map_err(|e| DcapError::Parse(format!("Failed to parse PCK extension: {e}")))?;
    Ok(PckExtension::from_core(ext))
}
