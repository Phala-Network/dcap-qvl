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
//! Collateral fetching is intentionally out of scope: mobile apps fetch JSON
//! from a PCCS over native HTTP (OkHttp / URLSession) and pass it in.

use dcap_qvl::{intel as core_intel, quote::Quote as CoreQuote, verify::QuoteVerifier};

uniffi::setup_scaffolding!();

mod errors;
mod types;

pub use errors::DcapError;
pub use types::*;

/// Parse an SGX/TDX quote binary into a structured [`Quote`].
#[uniffi::export]
pub fn parse_quote(raw_quote: Vec<u8>) -> Result<Quote, DcapError> {
    use scale::Decode;
    let parsed = CoreQuote::decode(&mut &raw_quote[..])
        .map_err(|e| DcapError::Parse(format!("Failed to parse quote: {e}")))?;
    Ok(Quote::from_core(&parsed))
}

/// Verify a quote with collateral, using Intel's production root CA and the
/// `ring` crypto backend.
#[uniffi::export]
pub fn verify(
    raw_quote: Vec<u8>,
    collateral: QuoteCollateral,
    now_secs: u64,
) -> Result<VerifiedReport, DcapError> {
    let verifier = QuoteVerifier::new_prod();
    let report = verifier
        .verify(&raw_quote, &collateral.into(), now_secs)
        .map_err(DcapError::from_anyhow)?;
    Ok(VerifiedReport::from_core(report))
}

/// Verify a quote with collateral and a custom DER-encoded root CA.
#[uniffi::export]
pub fn verify_with_root_ca(
    raw_quote: Vec<u8>,
    collateral: QuoteCollateral,
    root_ca_der: Vec<u8>,
    now_secs: u64,
) -> Result<VerifiedReport, DcapError> {
    let verifier = QuoteVerifier::new(root_ca_der);
    let report = verifier
        .verify(&raw_quote, &collateral.into(), now_secs)
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
