use core::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use rustls_pki_types::UnixTime;
use scale::Decode;

use {
    crate::constants::*,
    crate::intel,
    crate::qe_identity::QeIdentity,
    crate::tcb_info::{TcbInfo, TcbStatusWithAdvisory},
    alloc::string::String,
    alloc::vec::Vec,
};

pub use crate::quote::{AuthData, EnclaveReport, Quote};
use crate::{
    quote::{Report, TDAttributes},
    utils::{encode_as_der, extract_certs, parse_crls, verify_certificate_chain},
};
use crate::{
    quote::{TDReport10, TDReport15},
    QuoteCollateralV3,
};
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

#[cfg(feature = "ring")]
pub(crate) use self::ring as default_crypto;
#[cfg(all(not(feature = "ring"), feature = "rustcrypto"))]
pub(crate) use self::rustcrypto as default_crypto;
#[cfg(all(not(feature = "ring"), not(feature = "rustcrypto"), feature = "sp1"))]
pub(crate) use self::sp1 as default_crypto;
#[cfg(all(
    not(feature = "ring"),
    not(feature = "rustcrypto"),
    not(feature = "sp1"),
    feature = "cosmwasm"
))]
pub(crate) use self::cosmwasm as default_crypto;

/// Crypto backend configuration for quote verification.
///
/// Holds the signature verification algorithm and SHA-256 implementation
/// needed by the verification logic. Use [`ring::backend()`] or
/// [`rustcrypto::backend()`] to obtain a pre-configured instance.
pub struct CryptoBackend {
    /// ECDSA P-256 SHA-256 algorithm for certificate and raw signature verification
    pub sig_algo: &'static dyn rustls_pki_types::SignatureVerificationAlgorithm,
    /// SHA-256 hash function
    pub sha256: fn(&[u8]) -> [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TeeType {
    Sgx,
    Tdx,
}

impl TeeType {
    fn from_u32(value: u32) -> Result<Self> {
        match value {
            TEE_TYPE_SGX => Ok(TeeType::Sgx),
            TEE_TYPE_TDX => Ok(TeeType::Tdx),
            _ => bail!("Unsupported TEE type: {value}"),
        }
    }

    fn is_tdx(&self) -> bool {
        matches!(self, TeeType::Tdx)
    }
}

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
    pub qe_status: TcbStatusWithAdvisory,
    pub platform_status: TcbStatusWithAdvisory,
}

/// Quote verifier with configurable root certificate and crypto backend.
///
/// This allows using custom root certificates for testing or private deployments,
/// and selecting between different cryptographic backends (ring or rustcrypto).
pub struct QuoteVerifier {
    root_ca_der: Vec<u8>,
    backend: CryptoBackend,
}

impl QuoteVerifier {
    /// Create a new verifier with a custom root certificate and crypto backend.
    pub fn new(root_ca_der: Vec<u8>, backend: CryptoBackend) -> Self {
        Self {
            root_ca_der,
            backend,
        }
    }

    /// Create a new verifier using Intel's production root certificate with ring backend.
    pub fn new_prod(backend: CryptoBackend) -> Self {
        Self::new(TRUSTED_ROOT_CA_DER.to_vec(), backend)
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
        verify_impl(
            raw_quote,
            collateral,
            now_secs,
            &self.root_ca_der,
            &self.backend,
        )
    }
}

#[cfg(all(feature = "js", feature = "_anycrypto"))]
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

#[cfg(all(feature = "js", feature = "_anycrypto"))]
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

    let verifier = QuoteVerifier::new(root_ca_der, default_crypto::backend());
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

// =============================================================================
// Step 1: Verify TCB Info signature (Intel Root -> TCB Signing Cert -> TCB Info JSON)
// =============================================================================

/// Verify TCB Info collateral: certificate chain, signature, parsing, and expiration check
fn verify_tcb_info_signature(
    collateral: &QuoteCollateralV3,
    now: UnixTime,
    crls: &[webpki::CertRevocationList<'_>],
    trust_anchor: rustls_pki_types::TrustAnchor,
    backend: &CryptoBackend,
) -> Result<TcbInfo> {
    // Parse TCB Info
    let tcb_info = serde_json::from_str::<TcbInfo>(&collateral.tcb_info)
        .context("Failed to decode TcbInfo")?;

    // Check validity window
    let issue_date = chrono::DateTime::parse_from_rfc3339(&tcb_info.issue_date)
        .ok()
        .context("Failed to parse TCB Info issue date")?;
    let next_update = chrono::DateTime::parse_from_rfc3339(&tcb_info.next_update)
        .ok()
        .context("Failed to parse TCB Info next update")?;
    if now.as_secs() < issue_date.timestamp() as u64 {
        bail!("TCBInfo issue date is in the future");
    }
    if now.as_secs() > next_update.timestamp() as u64 {
        bail!("TCBInfo expired");
    }

    // Verify certificate chain
    let tcb_certs = extract_certs(collateral.tcb_info_issuer_chain.as_bytes())?;
    let [tcb_leaf, tcb_chain @ ..] = &tcb_certs[..] else {
        bail!("Certificate chain is too short for TCB Info");
    };
    let tcb_leaf_cert = webpki::EndEntityCert::try_from(tcb_leaf)
        .context("Failed to parse TCB Info leaf certificate")?;
    verify_certificate_chain(&tcb_leaf_cert, tcb_chain, now, crls, trust_anchor, &[backend.sig_algo])?;

    // Verify signature
    let asn1_signature = encode_as_der(&collateral.tcb_info_signature)?;
    if tcb_leaf_cert
        .verify_signature(
            backend.sig_algo,
            collateral.tcb_info.as_bytes(),
            &asn1_signature,
        )
        .is_err()
    {
        bail!("Signature is invalid for tcb_info in quote_collateral");
    }

    Ok(tcb_info)
}

// =============================================================================
// Step 2: Verify QE Identity signature (Intel Root -> QE Identity Signing Cert -> QE Identity JSON)
// =============================================================================

/// Verify QE Identity collateral: certificate chain, signature, parsing, and expiration check
fn verify_qe_identity_signature(
    collateral: &QuoteCollateralV3,
    now: UnixTime,
    crls: &[webpki::CertRevocationList<'_>],
    trust_anchor: rustls_pki_types::TrustAnchor,
    backend: &CryptoBackend,
) -> Result<QeIdentity> {
    // Parse QE Identity
    let qe_identity = serde_json::from_str::<QeIdentity>(&collateral.qe_identity)
        .context("Failed to decode QeIdentity")?;

    // Check validity window
    let issue_date = chrono::DateTime::parse_from_rfc3339(&qe_identity.issue_date)
        .ok()
        .context("Failed to parse QE Identity issue date")?;
    let next_update = chrono::DateTime::parse_from_rfc3339(&qe_identity.next_update)
        .ok()
        .context("Failed to parse QE Identity next update")?;
    if now.as_secs() < issue_date.timestamp() as u64 {
        bail!("QE Identity issue date is in the future");
    }
    if now.as_secs() > next_update.timestamp() as u64 {
        bail!("QE Identity expired");
    }

    // Verify certificate chain
    let qe_id_certs = extract_certs(collateral.qe_identity_issuer_chain.as_bytes())?;
    let [qe_id_leaf, qe_id_chain @ ..] = &qe_id_certs[..] else {
        bail!("Certificate chain is too short for QE Identity");
    };
    let qe_id_leaf_cert = webpki::EndEntityCert::try_from(qe_id_leaf)
        .context("Failed to parse QE Identity leaf certificate")?;
    verify_certificate_chain(&qe_id_leaf_cert, qe_id_chain, now, crls, trust_anchor, &[backend.sig_algo])?;

    // Verify signature
    let qe_id_asn1_signature = encode_as_der(&collateral.qe_identity_signature)?;
    if qe_id_leaf_cert
        .verify_signature(
            backend.sig_algo,
            collateral.qe_identity.as_bytes(),
            &qe_id_asn1_signature,
        )
        .is_err()
    {
        bail!("Signature is invalid for qe_identity in quote_collateral");
    }

    Ok(qe_identity)
}

// =============================================================================
// Step 3: Verify PCK certificate chain (Intel Root -> PCK CA -> PCK Cert)
// =============================================================================

/// Verify PCK certificate chain and extract platform data
///
/// Verifies the PCK certificate chain against the trusted root and CRLs.
/// Extracts cpu_svn, pce_svn, fmspc, and ppid from the certificate.
fn verify_pck_cert_chain(
    collateral: &QuoteCollateralV3,
    certification_data: &crate::quote::CertificationData,
    now: UnixTime,
    crls: &[webpki::CertRevocationList<'_>],
    trust_anchor: rustls_pki_types::TrustAnchor,
    sig_algs: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm],
) -> Result<PckCertChainResult> {
    // Extract PCK certificate chain - prefer collateral, fall back to quote
    let certification_certs = if let Some(pem_chain) = &collateral.pck_certificate_chain {
        extract_certs(pem_chain.as_bytes())
            .context("Failed to extract PCK certificates from collateral")?
    } else {
        if certification_data.cert_type != PCK_CERT_CHAIN {
            bail!("Unsupported DCAP PCK cert format: {}. Use get_collateral() to fetch PCK certificate.", certification_data.cert_type);
        }
        extract_certs(&certification_data.body.data)
            .context("Failed to extract PCK certificates from quote")?
    };

    let [pck_leaf, pck_chain @ ..] = &certification_certs[..] else {
        bail!("Certificate chain is too short in quote");
    };

    // Verify PCK certificate chain
    let pck_leaf_cert =
        webpki::EndEntityCert::try_from(pck_leaf).context("Failed to parse PCK certificate")?;
    verify_certificate_chain(&pck_leaf_cert, pck_chain, now, crls, trust_anchor, sig_algs)?;

    // Extract Intel extension data from PCK cert (parsed once)
    let pck_ext = intel::parse_pck_extension(pck_leaf)?;

    Ok(PckCertChainResult {
        pck_leaf_der: pck_leaf.as_ref().to_vec(),
        ppid: pck_ext.ppid,
        cpu_svn: pck_ext.cpu_svn,
        pce_svn: pck_ext.pce_svn,
        fmspc: pck_ext.fmspc,
    })
}

/// Result from PCK certificate chain verification
struct PckCertChainResult {
    pck_leaf_der: Vec<u8>,
    ppid: Vec<u8>,
    cpu_svn: [u8; 16],
    pce_svn: u16,
    fmspc: [u8; 6],
}

/// Pre-verified outputs from certificate chain validation (steps 1-3).
///
/// Extracted on the host (where cert chain validation is cheap) and passed to
/// the zkVM guest, which only runs steps 4-10.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreVerifiedInputs {
    pub tcb_info: TcbInfo,
    pub qe_identity: QeIdentity,
    #[serde(with = "serde_bytes")]
    pub pck_leaf_der: Vec<u8>,
    pub cpu_svn: [u8; 16],
    pub pce_svn: u16,
    pub fmspc: [u8; 6],
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
}

/// Pre-parsed collateral for efficient full verification in zkVM.
///
/// Replaces `QuoteCollateralV3` for the full guest path. All PEM cert chains are
/// pre-extracted to DER bytes (skipping base64/PEM parsing in guest), and TCB Info /
/// QE Identity JSON are pre-parsed to structs (skipping serde_json in guest).
/// Raw JSON bytes are retained for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedCollateral {
    // CRL bytes (DER, unchanged)
    #[serde(with = "serde_bytes")]
    pub root_ca_crl: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pck_crl: Vec<u8>,

    // TCB Info: pre-parsed struct + raw JSON bytes for sig verification
    pub tcb_info: TcbInfo,
    #[serde(with = "serde_bytes")]
    pub tcb_info_raw: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub tcb_info_signature: Vec<u8>,
    /// TCB Info issuer chain as DER cert bytes (leaf first)
    pub tcb_info_certs_der: Vec<Vec<u8>>,

    // QE Identity: pre-parsed struct + raw JSON bytes for sig verification
    pub qe_identity: QeIdentity,
    #[serde(with = "serde_bytes")]
    pub qe_identity_raw: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub qe_identity_signature: Vec<u8>,
    /// QE Identity issuer chain as DER cert bytes (leaf first)
    pub qe_identity_certs_der: Vec<Vec<u8>>,

    /// PCK certificate chain as DER cert bytes (leaf first)
    pub pck_certs_der: Vec<Vec<u8>>,
}

/// Run certificate chain validation (steps 1-3) and return pre-verified inputs.
///
/// Call this on the host, then pass the result to [`verify_quote_lite()`] in the zkVM guest.
pub fn extract_pre_verified_inputs(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    backend: &CryptoBackend,
) -> Result<PreVerifiedInputs> {
    let root_ca_der = TRUSTED_ROOT_CA_DER;
    let root_ca = CertificateDer::from_slice(root_ca_der);
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_ca).context("Failed to load root ca")?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
    let raw_crls = [&collateral.root_ca_crl[..], &collateral.pck_crl];

    webpki::check_single_cert_crl(root_ca_der, &raw_crls, now)?;
    let crls = parse_crls(&raw_crls)?;

    // Parse quote to get certification_data for step 3
    let mut quote_slice = raw_quote;
    let quote = Quote::decode(&mut quote_slice).context("Failed to decode quote")?;
    let auth_data = quote.auth_data.clone().into_v3();

    // Step 1: Verify TCB Info signature
    let tcb_info =
        verify_tcb_info_signature(collateral, now, &crls, trust_anchor.clone(), backend)?;

    // Step 2: Verify QE Identity signature
    let qe_identity =
        verify_qe_identity_signature(collateral, now, &crls, trust_anchor.clone(), backend)?;

    // Step 3: Verify PCK certificate chain
    let pck_result = verify_pck_cert_chain(
        collateral,
        &auth_data.certification_data,
        now,
        &crls,
        trust_anchor,
        &[backend.sig_algo],
    )?;

    Ok(PreVerifiedInputs {
        tcb_info,
        qe_identity,
        pck_leaf_der: pck_result.pck_leaf_der,
        cpu_svn: pck_result.cpu_svn,
        pce_svn: pck_result.pce_svn,
        fmspc: pck_result.fmspc,
        ppid: pck_result.ppid,
    })
}

/// Prepare collateral for efficient zkVM full verification.
///
/// Pre-extracts PEM cert chains to DER bytes and pre-parses TCB Info / QE Identity
/// JSON to structs. The result can be serialized with bincode for SP1 stdin, avoiding
/// PEM/base64 and JSON parsing overhead inside the zkVM guest.
pub fn prepare_collateral(
    collateral: &QuoteCollateralV3,
    raw_quote: &[u8],
) -> Result<PreparedCollateral> {
    use crate::utils::extract_raw_certs;

    // Pre-parse JSON
    let tcb_info = serde_json::from_str::<TcbInfo>(&collateral.tcb_info)
        .context("Failed to decode TcbInfo")?;
    let qe_identity = serde_json::from_str::<QeIdentity>(&collateral.qe_identity)
        .context("Failed to decode QeIdentity")?;

    // Pre-extract PEM to DER
    let tcb_info_certs_der = extract_raw_certs(collateral.tcb_info_issuer_chain.as_bytes())?;
    let qe_identity_certs_der =
        extract_raw_certs(collateral.qe_identity_issuer_chain.as_bytes())?;

    // PCK certs: prefer collateral, fall back to quote cert data
    let pck_certs_der = if let Some(ref pem_chain) = collateral.pck_certificate_chain {
        extract_raw_certs(pem_chain.as_bytes())?
    } else {
        let mut slice = raw_quote;
        let quote = Quote::decode(&mut slice).context("Failed to decode quote")?;
        let auth_data = quote.auth_data.clone().into_v3();
        extract_raw_certs(&auth_data.certification_data.body.data)?
    };

    Ok(PreparedCollateral {
        root_ca_crl: collateral.root_ca_crl.clone(),
        pck_crl: collateral.pck_crl.clone(),
        tcb_info,
        tcb_info_raw: collateral.tcb_info.as_bytes().to_vec(),
        tcb_info_signature: collateral.tcb_info_signature.clone(),
        tcb_info_certs_der,
        qe_identity,
        qe_identity_raw: collateral.qe_identity.as_bytes().to_vec(),
        qe_identity_signature: collateral.qe_identity_signature.clone(),
        qe_identity_certs_der,
        pck_certs_der,
    })
}

/// Full DCAP verification using pre-parsed collateral (steps 1-10).
///
/// Like [`verify_impl`] but skips PEM parsing and JSON deserialization by using
/// pre-extracted DER certs and pre-parsed structs from [`PreparedCollateral`].
pub fn verify_with_prepared(
    raw_quote: &[u8],
    prepared: &PreparedCollateral,
    now_secs: u64,
    root_ca_der: &[u8],
    backend: &CryptoBackend,
) -> Result<VerifiedReport> {
    let root_ca = CertificateDer::from_slice(root_ca_der);
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_ca).context("Failed to load root ca")?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
    let raw_crls = [&prepared.root_ca_crl[..], &prepared.pck_crl];

    webpki::check_single_cert_crl(root_ca_der, &raw_crls, now)?;
    let crls = parse_crls(&raw_crls)?;

    // Parse quote
    let mut quote_slice = raw_quote;
    let quote = Quote::decode(&mut quote_slice).context("Failed to decode quote")?;
    if !ALLOWED_QUOTE_VERSIONS.contains(&quote.header.version) {
        bail!("Unsupported DCAP quote version");
    }
    let tee_type = TeeType::from_u32(quote.header.tee_type)?;
    match tee_type {
        TeeType::Sgx => {
            if quote.header.version != 3 {
                bail!("SGX TEE quote must have version 3");
            }
        }
        TeeType::Tdx => {
            if ![4, 5].contains(&quote.header.version) {
                bail!("TDX TEE quote must have version 4 or 5");
            }
        }
    }
    if quote.header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE {
        bail!("Unsupported DCAP attestation key type");
    }
    let auth_data = quote.auth_data.clone().into_v3();

    // Step 1: Verify TCB Info signature (using pre-parsed struct + pre-extracted DER certs)
    {
        let issue_date = chrono::DateTime::parse_from_rfc3339(&prepared.tcb_info.issue_date)
            .ok()
            .context("Failed to parse TCB Info issue date")?;
        let next_update = chrono::DateTime::parse_from_rfc3339(&prepared.tcb_info.next_update)
            .ok()
            .context("Failed to parse TCB Info next update")?;
        if now.as_secs() < issue_date.timestamp() as u64 {
            bail!("TCBInfo issue date is in the future");
        }
        if now.as_secs() > next_update.timestamp() as u64 {
            bail!("TCBInfo expired");
        }

        let tcb_certs: Vec<CertificateDer> = prepared
            .tcb_info_certs_der
            .iter()
            .map(|d| CertificateDer::from(d.as_slice()))
            .collect();
        let [tcb_leaf, tcb_chain @ ..] = &tcb_certs[..] else {
            bail!("Certificate chain is too short for TCB Info");
        };
        let tcb_leaf_cert = webpki::EndEntityCert::try_from(tcb_leaf)
            .context("Failed to parse TCB Info leaf certificate")?;
        verify_certificate_chain(
            &tcb_leaf_cert,
            tcb_chain,
            now,
            &crls,
            trust_anchor.clone(),
            &[backend.sig_algo],
        )?;

        let asn1_signature = encode_as_der(&prepared.tcb_info_signature)?;
        if tcb_leaf_cert
            .verify_signature(backend.sig_algo, &prepared.tcb_info_raw, &asn1_signature)
            .is_err()
        {
            bail!("Signature is invalid for tcb_info");
        }
    }

    // Step 2: Verify QE Identity signature (using pre-parsed struct + pre-extracted DER certs)
    {
        let issue_date = chrono::DateTime::parse_from_rfc3339(&prepared.qe_identity.issue_date)
            .ok()
            .context("Failed to parse QE Identity issue date")?;
        let next_update = chrono::DateTime::parse_from_rfc3339(&prepared.qe_identity.next_update)
            .ok()
            .context("Failed to parse QE Identity next update")?;
        if now.as_secs() < issue_date.timestamp() as u64 {
            bail!("QE Identity issue date is in the future");
        }
        if now.as_secs() > next_update.timestamp() as u64 {
            bail!("QE Identity expired");
        }

        let qe_certs: Vec<CertificateDer> = prepared
            .qe_identity_certs_der
            .iter()
            .map(|d| CertificateDer::from(d.as_slice()))
            .collect();
        let [qe_leaf, qe_chain @ ..] = &qe_certs[..] else {
            bail!("Certificate chain is too short for QE Identity");
        };
        let qe_leaf_cert = webpki::EndEntityCert::try_from(qe_leaf)
            .context("Failed to parse QE Identity leaf certificate")?;
        verify_certificate_chain(
            &qe_leaf_cert,
            qe_chain,
            now,
            &crls,
            trust_anchor.clone(),
            &[backend.sig_algo],
        )?;

        let asn1_signature = encode_as_der(&prepared.qe_identity_signature)?;
        if qe_leaf_cert
            .verify_signature(
                backend.sig_algo,
                &prepared.qe_identity_raw,
                &asn1_signature,
            )
            .is_err()
        {
            bail!("Signature is invalid for qe_identity");
        }
    }

    let (expected_qe_id, allowed_qe_versions): (&str, &[u8]) = match tee_type {
        TeeType::Sgx => ("QE", &[2]),
        TeeType::Tdx => ("TD_QE", &[2, 3]),
    };
    if prepared.qe_identity.id != expected_qe_id
        || !allowed_qe_versions.contains(&prepared.qe_identity.version)
    {
        bail!("Unsupported QE Identity id/version");
    }

    // Step 3: Verify PCK certificate chain (using pre-extracted DER certs)
    let pck_certs: Vec<CertificateDer> = prepared
        .pck_certs_der
        .iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect();
    let [pck_leaf, pck_chain @ ..] = &pck_certs[..] else {
        bail!("Certificate chain is too short for PCK");
    };
    let pck_leaf_cert =
        webpki::EndEntityCert::try_from(pck_leaf).context("Failed to parse PCK certificate")?;
    verify_certificate_chain(
        &pck_leaf_cert,
        pck_chain,
        now,
        &crls,
        trust_anchor,
        &[backend.sig_algo],
    )?;
    let pck_ext = intel::parse_pck_extension(pck_leaf)?;

    // Steps 4-10: same as verify_impl
    let qe_report = verify_qe_report_signature(pck_leaf, &auth_data, backend)?;
    verify_qe_report_data(&qe_report, &auth_data, backend)?;
    let qe_status = verify_qe_identity_policy(&qe_report, &prepared.qe_identity)?;
    verify_isv_report_signature(raw_quote, &quote, &auth_data, backend)?;

    let platform_status = match_platform_tcb(
        &prepared.tcb_info,
        &quote,
        tee_type,
        &pck_ext.cpu_svn,
        pck_ext.pce_svn,
        &pck_ext.fmspc,
    )?;

    let final_status = platform_status.clone().merge(&qe_status);
    if !final_status.status.is_valid() {
        bail!("TCB status is invalid: {:?}", final_status.status);
    }

    validate_attrs(&quote.report)?;

    Ok(VerifiedReport {
        status: final_status.status.to_string(),
        advisory_ids: final_status.advisory_ids,
        report: quote.report,
        ppid: pck_ext.ppid,
        qe_status,
        platform_status,
    })
}

/// Verify a quote using pre-verified certificate chain results (steps 4-10 only).
///
/// Skips certificate chain validation (steps 1-3), which must have been done
/// previously via [`extract_pre_verified_inputs()`]. Use this in zkVM guests where
/// cert chain validation is prohibitively expensive.
pub fn verify_quote_lite(
    raw_quote: &[u8],
    pre: &PreVerifiedInputs,
    backend: &CryptoBackend,
) -> Result<VerifiedReport> {
    // Parse quote and validate header
    let mut quote_slice = raw_quote;
    let quote = Quote::decode(&mut quote_slice).context("Failed to decode quote")?;
    if !ALLOWED_QUOTE_VERSIONS.contains(&quote.header.version) {
        bail!("Unsupported DCAP quote version");
    }
    let tee_type = TeeType::from_u32(quote.header.tee_type)?;
    match tee_type {
        TeeType::Sgx => {
            if quote.header.version != 3 {
                bail!("SGX TEE quote must have version 3");
            }
        }
        TeeType::Tdx => {
            if ![4, 5].contains(&quote.header.version) {
                bail!("TDX TEE quote must have version 4 or 5");
            }
        }
    }
    if quote.header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE {
        bail!("Unsupported DCAP attestation key type");
    }
    let auth_data = quote.auth_data.clone().into_v3();

    // Validate QE Identity id/version
    let (expected_qe_id, allowed_qe_versions): (&str, &[u8]) = match tee_type {
        TeeType::Sgx => ("QE", &[2]),
        TeeType::Tdx => ("TD_QE", &[2, 3]),
    };
    if pre.qe_identity.id != expected_qe_id
        || !allowed_qe_versions.contains(&pre.qe_identity.version)
    {
        bail!("Unsupported QE Identity id/version");
    }

    let pck_leaf = CertificateDer::from(pre.pck_leaf_der.as_slice());

    // Step 4: Verify QE Report signature
    let qe_report = verify_qe_report_signature(&pck_leaf, &auth_data, backend)?;

    // Step 5: Verify QE Report content (hash check)
    verify_qe_report_data(&qe_report, &auth_data, backend)?;

    // Step 6: Verify QE Report policy
    let qe_status = verify_qe_identity_policy(&qe_report, &pre.qe_identity)?;

    // Step 7: Verify ISV Report signature
    verify_isv_report_signature(raw_quote, &quote, &auth_data, backend)?;

    // Step 8: Match Platform TCB
    let platform_status = match_platform_tcb(
        &pre.tcb_info,
        &quote,
        tee_type,
        &pre.cpu_svn,
        pre.pce_svn,
        &pre.fmspc,
    )?;

    // Step 9 & 10: Merge TCB statuses
    let final_status = platform_status.clone().merge(&qe_status);
    if !final_status.status.is_valid() {
        bail!("TCB status is invalid: {:?}", final_status.status);
    }

    validate_attrs(&quote.report)?;

    Ok(VerifiedReport {
        status: final_status.status.to_string(),
        advisory_ids: final_status.advisory_ids,
        report: quote.report,
        ppid: pre.ppid.clone(),
        qe_status,
        platform_status,
    })
}

// =============================================================================
// Step 4: Verify QE Report signature (PCK Cert signs QE Report)
// =============================================================================

/// Verify QE report signature using PCK certificate
fn verify_qe_report_signature(
    pck_leaf: &CertificateDer,
    auth_data: &crate::quote::AuthDataV3,
    backend: &CryptoBackend,
) -> Result<EnclaveReport> {
    let pck_leaf_cert =
        webpki::EndEntityCert::try_from(pck_leaf).context("Failed to parse PCK certificate")?;

    // Verify QE report signature (signed by PCK)
    let qe_report_signature = encode_as_der(&auth_data.qe_report_signature)?;
    if pck_leaf_cert
        .verify_signature(backend.sig_algo, &auth_data.qe_report, &qe_report_signature)
        .is_err()
    {
        bail!("Signature is invalid for qe_report in quote");
    }

    // Decode QE report
    let mut qe_report_slice = auth_data.qe_report.as_slice();
    let qe_report =
        EnclaveReport::decode(&mut qe_report_slice).context("Failed to decode QE report")?;

    Ok(qe_report)
}

// =============================================================================
// Step 5: Verify QE Report content (QE Hash = hash(attestation_key + auth_data))
// =============================================================================

/// Verify QE report hash matches attestation key and auth data (panic-free)
fn verify_qe_report_data(
    qe_report: &EnclaveReport,
    auth_data: &crate::quote::AuthDataV3,
    backend: &CryptoBackend,
) -> Result<()> {
    use crate::constants::{ATTESTATION_KEY_LEN, AUTHENTICATION_DATA_LEN};

    ensure!(
        auth_data.qe_auth_data.data.len() == AUTHENTICATION_DATA_LEN,
        "Invalid QE auth data length"
    );
    // Build hash data: attestation_key || qe_auth_data
    let mut qe_hash_data = [0u8; ATTESTATION_KEY_LEN + AUTHENTICATION_DATA_LEN];
    qe_hash_data[..ATTESTATION_KEY_LEN].copy_from_slice(&auth_data.ecdsa_attestation_key);
    qe_hash_data[ATTESTATION_KEY_LEN..].copy_from_slice(&auth_data.qe_auth_data.data);
    let qe_hash = (backend.sha256)(&qe_hash_data);
    if qe_hash[..] != qe_report.report_data[..32] {
        bail!("QE report hash mismatch");
    }
    Ok(())
}

// =============================================================================
// Step 6: Verify QE Report policy (QE Report fields match QE Identity policy)
// =============================================================================

// verify_qe_identity_policy is defined below (after verify_impl)

// =============================================================================
// Step 7: Verify ISV Report signature (Attestation Key signs ISV Report)
// =============================================================================

/// Verify ISV enclave report signature using attestation key
fn verify_isv_report_signature(
    raw_quote: &[u8],
    quote: &Quote,
    auth_data: &crate::quote::AuthDataV3,
    backend: &CryptoBackend,
) -> Result<()> {
    // Prepend 0x04 to raw public key for SEC1 uncompressed format
    let mut pub_key = [0x04u8; 65];
    pub_key[1..].copy_from_slice(&auth_data.ecdsa_attestation_key);

    // DER-encode the raw r||s signature for SignatureVerificationAlgorithm
    let der_sig = encode_as_der(&auth_data.ecdsa_signature)?;

    let signed_data = raw_quote
        .get(..quote.signed_length())
        .context("Failed to get signed quote scope")?;

    backend
        .sig_algo
        .verify_signature(&pub_key, signed_data, &der_sig)
        .map_err(|_| anyhow::anyhow!("ISV enclave report signature is invalid"))
}

// =============================================================================
// Step 8: Match Platform TCB (PCK Cert's CPU_SVN/PCE_SVN/FMSPC vs TCB Info)
// =============================================================================

/// Match platform TCB level and return status with advisory IDs
fn match_platform_tcb(
    tcb_info: &TcbInfo,
    quote: &Quote,
    tee_type: TeeType,
    cpu_svn: &[u8],
    pce_svn: u16,
    fmspc: &[u8],
) -> Result<TcbStatusWithAdvisory> {
    // Verify FMSPC matches
    let tcb_fmspc = hex::decode(&tcb_info.fmspc)
        .ok()
        .context("Failed to decode TCB FMSPC")?;
    if fmspc[..] != tcb_fmspc[..] {
        bail!("Fmspc mismatch");
    }

    // Verify TCB Info type matches quote TEE type
    match tee_type {
        TeeType::Tdx => {
            if tcb_info.version < 3 || tcb_info.id != "TDX" {
                bail!("TDX quote with non-TDX TCB info in the collateral");
            }
        }
        TeeType::Sgx => {
            if tcb_info.version < 2 || tcb_info.id != "SGX" {
                bail!("SGX quote with non-SGX TCB info in the collateral");
            }
        }
    }

    // Find matching TCB level
    for tcb_level in &tcb_info.tcb_levels {
        if pce_svn < tcb_level.tcb.pce_svn {
            continue;
        }

        let sgx_components: Vec<u8> = tcb_level.tcb.sgx_components.iter().map(|c| c.svn).collect();
        if sgx_components.is_empty() {
            bail!("No SGX components in the TCB info");
        }
        // Component-wise comparison: every cpu_svn[i] must be >= sgx_components[i]
        if cpu_svn.iter().zip(&sgx_components).any(|(a, b)| a < b) {
            continue;
        }

        // For TDX, also check TDX components
        if tee_type.is_tdx() {
            let td_report = quote
                .report
                .as_td10()
                .context("Failed to get TD10 report")?;
            let tdx_components: Vec<u8> =
                tcb_level.tcb.tdx_components.iter().map(|c| c.svn).collect();
            if tdx_components.is_empty() {
                bail!("No TDX components in the TCB info");
            }
            // Component-wise comparison: every tee_tcb_svn[i] must be >= tdx_components[i]
            if td_report
                .tee_tcb_svn
                .iter()
                .zip(&tdx_components)
                .any(|(a, b)| a < b)
            {
                continue;
            }
        }

        // Found matching level
        return Ok(TcbStatusWithAdvisory::new(
            tcb_level.tcb_status,
            tcb_level.advisory_ids.clone(),
        ));
    }

    bail!("No matching TCB level found");
}

// =============================================================================
// Main verification flow following the trust chain
// =============================================================================

/// Internal implementation that uses QuoteVerifier
///
/// Trust chain verification order:
/// 1. Verify TCB Info signature (Intel Root -> TCB Signing Cert -> TCB Info JSON)
/// 2. Verify QE Identity signature (Intel Root -> QE Identity Signing Cert -> QE Identity JSON)
/// 3. Verify PCK certificate chain (Intel Root -> PCK CA -> PCK Cert)
/// 4. Verify QE Report signature (PCK Cert signs QE Report)
/// 5. Verify QE Report content (QE Hash = hash(attestation_key + auth_data))
/// 6. Verify QE Report policy (QE Report fields match QE Identity policy)
/// 7. Verify ISV Report signature (Attestation Key signs ISV Report)
/// 8. Match Platform TCB (PCK Cert's CPU_SVN/PCE_SVN/FMSPC vs TCB Info)
/// 9. Match QE TCB (QE Report's ISVSVN vs QE Identity tcb_levels)
/// 10. Merge TCB statuses
fn verify_impl(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    root_ca_der: &[u8],
    backend: &CryptoBackend,
) -> Result<VerifiedReport> {
    // Setup trust anchor and time
    let root_ca = CertificateDer::from_slice(root_ca_der);
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_ca).context("Failed to load root ca")?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
    let raw_crls = [&collateral.root_ca_crl[..], &collateral.pck_crl];

    // Check root CA against CRL
    webpki::check_single_cert_crl(root_ca_der, &raw_crls, now)?;

    // Parse CRLs once for reuse across all certificate chain verifications
    let crls = parse_crls(&raw_crls)?;

    // Parse quote and validate header
    let mut quote_slice = raw_quote;
    let quote = Quote::decode(&mut quote_slice).context("Failed to decode quote")?;
    if !ALLOWED_QUOTE_VERSIONS.contains(&quote.header.version) {
        bail!("Unsupported DCAP quote version");
    }
    let tee_type = TeeType::from_u32(quote.header.tee_type)?;
    match tee_type {
        TeeType::Sgx => {
            if quote.header.version != 3 {
                bail!("SGX TEE quote must have version 3");
            }
        }
        TeeType::Tdx => {
            if ![4, 5].contains(&quote.header.version) {
                bail!("TDX TEE quote must have version 4 or 5");
            }
        }
    }
    if quote.header.attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE {
        bail!("Unsupported DCAP attestation key type");
    }
    let auth_data = quote.auth_data.clone().into_v3();

    // Step 1: Verify TCB Info signature
    let tcb_info =
        verify_tcb_info_signature(collateral, now, &crls, trust_anchor.clone(), backend)?;

    // Step 2: Verify QE Identity signature
    let qe_identity =
        verify_qe_identity_signature(collateral, now, &crls, trust_anchor.clone(), backend)?;
    let (expected_qe_id, allowed_qe_versions): (&str, &[u8]) = match tee_type {
        TeeType::Sgx => ("QE", &[2]),
        TeeType::Tdx => ("TD_QE", &[2, 3]),
    };
    if qe_identity.id != expected_qe_id || !allowed_qe_versions.contains(&qe_identity.version) {
        bail!(
            "Unsupported QE Identity id/version for the quote TEE type: {} version {} (expected {} version {:?})",
            qe_identity.id,
            qe_identity.version,
            expected_qe_id,
            allowed_qe_versions
        );
    }

    // Step 3: Verify PCK certificate chain
    let pck_result = verify_pck_cert_chain(
        collateral,
        &auth_data.certification_data,
        now,
        &crls,
        trust_anchor,
        &[backend.sig_algo],
    )?;
    let pck_leaf = CertificateDer::from(pck_result.pck_leaf_der.as_slice());

    // Step 4: Verify QE Report signature
    let qe_report = verify_qe_report_signature(&pck_leaf, &auth_data, backend)?;

    // Step 5: Verify QE Report content (hash check)
    verify_qe_report_data(&qe_report, &auth_data, backend)?;

    // Step 6: Verify QE Report policy
    let qe_status = verify_qe_identity_policy(&qe_report, &qe_identity)?;

    // Step 7: Verify ISV Report signature
    verify_isv_report_signature(raw_quote, &quote, &auth_data, backend)?;

    // Step 8: Match Platform TCB
    let platform_status = match_platform_tcb(
        &tcb_info,
        &quote,
        tee_type,
        &pck_result.cpu_svn,
        pck_result.pce_svn,
        &pck_result.fmspc,
    )?;

    // Step 9 & 10: QE TCB matching is done in verify_qe_identity_policy, merge statuses
    let final_status = platform_status.clone().merge(&qe_status);
    if !final_status.status.is_valid() {
        bail!("TCB status is invalid: {:?}", final_status.status);
    }

    // Validate report attributes (debug mode check, etc.)
    validate_attrs(&quote.report)?;

    Ok(VerifiedReport {
        status: final_status.status.to_string(),
        advisory_ids: final_status.advisory_ids,
        report: quote.report,
        ppid: pck_result.ppid,
        qe_status,
        platform_status,
    })
}

fn validate_sgx_attrs(report: &EnclaveReport) -> Result<()> {
    let is_debug = report.attributes[0] & 0x02 != 0;
    if is_debug {
        bail!("Debug mode is enabled");
    }
    Ok(())
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
            bail!("Invalid MR service TD");
        }
        validate_td10(&report.base)
    }
    match &report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx_attrs(report),
    }
}

/// Ring crypto backend module.
///
/// Provides a pre-configured [`CryptoBackend`] using ring for ECDSA P-256 and SHA-256.
#[cfg(feature = "ring")]
pub mod ring {
    use super::*;

    fn ring_sha256(data: &[u8]) -> [u8; 32] {
        let digest = ::ring::digest::digest(&::ring::digest::SHA256, data);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// Returns a [`CryptoBackend`] backed by ring.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: webpki::ring::ECDSA_P256_SHA256,
            sha256: ring_sha256,
        }
    }

    /// Verify a quote using Intel's trusted root CA and ring backend.
    pub fn verify(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        QuoteVerifier::new(TRUSTED_ROOT_CA_DER.to_vec(), backend())
            .verify(raw_quote, collateral, now_secs)
    }

    /// Extract pre-verified inputs (steps 1-3) using ring backend.
    pub fn extract_pre_verified(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<PreVerifiedInputs> {
        extract_pre_verified_inputs(raw_quote, collateral, now_secs, &backend())
    }

    /// Verify a quote using pre-verified inputs (steps 4-10 only, ring backend).
    pub fn verify_lite(
        raw_quote: &[u8],
        pre: &PreVerifiedInputs,
    ) -> Result<VerifiedReport> {
        verify_quote_lite(raw_quote, pre, &backend())
    }
}

/// RustCrypto backend module.
///
/// Provides a pre-configured [`CryptoBackend`] using RustCrypto (sha2 + p256) for ECDSA P-256 and SHA-256.
#[cfg(feature = "rustcrypto")]
pub mod rustcrypto {
    use super::*;

    fn rustcrypto_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }

    /// Returns a [`CryptoBackend`] backed by RustCrypto.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: webpki::rustcrypto::ECDSA_P256_SHA256,
            sha256: rustcrypto_sha256,
        }
    }

    /// Verify a quote using Intel's trusted root CA and RustCrypto backend.
    pub fn verify(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        QuoteVerifier::new(TRUSTED_ROOT_CA_DER.to_vec(), backend())
            .verify(raw_quote, collateral, now_secs)
    }

    /// Extract pre-verified inputs (steps 1-3) using RustCrypto backend.
    pub fn extract_pre_verified(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<PreVerifiedInputs> {
        extract_pre_verified_inputs(raw_quote, collateral, now_secs, &backend())
    }

    /// Verify a quote using pre-verified inputs (steps 4-10 only, RustCrypto backend).
    pub fn verify_lite(
        raw_quote: &[u8],
        pre: &PreVerifiedInputs,
    ) -> Result<VerifiedReport> {
        verify_quote_lite(raw_quote, pre, &backend())
    }

    /// Prepare collateral for efficient full verification (pre-parse JSON, pre-extract PEM→DER).
    pub fn prepare(
        collateral: &QuoteCollateralV3,
        raw_quote: &[u8],
    ) -> Result<PreparedCollateral> {
        prepare_collateral(collateral, raw_quote)
    }

    /// Full verification using pre-parsed collateral (steps 1-10, RustCrypto backend).
    pub fn verify_prepared(
        raw_quote: &[u8],
        prepared: &PreparedCollateral,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        verify_with_prepared(raw_quote, prepared, now_secs, TRUSTED_ROOT_CA_DER, &backend())
    }
}

/// CosmWasm native crypto backend module.
///
/// Uses the CosmWasm host's native `secp256r1_verify` for ECDSA P-256 verification.
/// Requires wasmd v0.51+ / CosmWasm 2.1+.
#[cfg(feature = "cosmwasm")]
pub mod cosmwasm {
    use super::*;

    fn cosmwasm_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }

    /// Returns a [`CryptoBackend`] using the CosmWasm native host function.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: crate::cosmwasm_backend::ECDSA_P256_SHA256,
            sha256: cosmwasm_sha256,
        }
    }

    /// Verify a quote using Intel's trusted root CA and CosmWasm native backend.
    pub fn verify(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        QuoteVerifier::new(TRUSTED_ROOT_CA_DER.to_vec(), backend())
            .verify(raw_quote, collateral, now_secs)
    }
}

/// SP1 zkVM crypto backend module.
///
/// Uses SP1's native secp256r1 precompiles for accelerated ECDSA P-256 verification.
/// Falls back to software implementation when not running inside SP1 zkVM.
#[cfg(feature = "sp1")]
pub mod sp1 {
    use super::*;

    fn sp1_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }

    /// Returns a [`CryptoBackend`] using SP1's secp256r1 precompiles.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: crate::sp1_backend::ECDSA_P256_SHA256,
            sha256: sp1_sha256,
        }
    }

    /// Verify a quote using Intel's trusted root CA and SP1 backend.
    pub fn verify(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        QuoteVerifier::new(TRUSTED_ROOT_CA_DER.to_vec(), backend())
            .verify(raw_quote, collateral, now_secs)
    }

    /// Extract pre-verified inputs (steps 1-3) using SP1 backend.
    pub fn extract_pre_verified(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<PreVerifiedInputs> {
        extract_pre_verified_inputs(raw_quote, collateral, now_secs, &backend())
    }

    /// Verify a quote using pre-verified inputs (steps 4-10 only, SP1 backend).
    pub fn verify_lite(
        raw_quote: &[u8],
        pre: &PreVerifiedInputs,
    ) -> Result<VerifiedReport> {
        verify_quote_lite(raw_quote, pre, &backend())
    }

    /// Prepare collateral for efficient full verification (pre-parse JSON, pre-extract PEM→DER).
    pub fn prepare(
        collateral: &QuoteCollateralV3,
        raw_quote: &[u8],
    ) -> Result<PreparedCollateral> {
        prepare_collateral(collateral, raw_quote)
    }

    /// Full verification using pre-parsed collateral (steps 1-10, SP1 backend).
    pub fn verify_prepared(
        raw_quote: &[u8],
        prepared: &PreparedCollateral,
        now_secs: u64,
    ) -> Result<VerifiedReport> {
        verify_with_prepared(raw_quote, prepared, now_secs, TRUSTED_ROOT_CA_DER, &backend())
    }
}

/// Verify a quote using Intel's trusted root CA (ring backend).
///
/// This is a backwards-compatible convenience function that uses the ring backend.
/// For rustcrypto, use [`rustcrypto::verify()`].
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
#[cfg(feature = "_anycrypto")]
pub use self::default_crypto::verify;

// =============================================================================
// Step 6 & 9: Verify QE Report policy and match QE TCB
// =============================================================================

/// Verify QE report fields against QE Identity policy constraints.
///
/// This enforces Intel's QE Identity policy by checking:
/// - MRSIGNER matches the expected value from QE Identity
/// - ISVPRODID matches the expected value
/// - MISCSELECT matches after applying the mask
/// - ATTRIBUTES match after applying the mask
/// - ISVSVN meets minimum requirement from QE Identity TCB levels (Step 9)
///
/// Returns the QE TCB status and advisory IDs based on the QE's ISVSVN.
fn verify_qe_identity_policy(
    qe_report: &EnclaveReport,
    qe_identity: &QeIdentity,
) -> Result<TcbStatusWithAdvisory> {
    // Verify MRSIGNER
    if qe_report.mr_signer != qe_identity.mrsigner {
        bail!(
            "QE MRSIGNER mismatch: expected {}, got {}",
            hex::encode_upper(qe_identity.mrsigner),
            hex::encode_upper(qe_report.mr_signer)
        );
    }

    validate_sgx_attrs(qe_report).context("QE report validation failed")?;

    // Verify ISVPRODID
    if qe_report.isv_prod_id != qe_identity.isvprodid {
        bail!(
            "QE ISVPRODID mismatch: expected {}, got {}",
            qe_identity.isvprodid,
            qe_report.isv_prod_id
        );
    }

    // Verify MISCSELECT with mask
    let expected_miscselect_u32 = u32::from_le_bytes(qe_identity.miscselect);
    let miscselect_mask_u32 = u32::from_le_bytes(qe_identity.miscselect_mask);
    let qe_miscselect_masked = qe_report.misc_select & miscselect_mask_u32;
    let expected_miscselect_masked = expected_miscselect_u32 & miscselect_mask_u32;

    if qe_miscselect_masked != expected_miscselect_masked {
        bail!(
            "QE MISCSELECT mismatch: expected {:08X} (masked), got {:08X} (masked)",
            expected_miscselect_masked,
            qe_miscselect_masked
        );
    }

    // Verify ATTRIBUTES with mask
    // Apply mask and compare byte-by-byte using iterators
    for (i, ((expected, mask), qe_attr)) in qe_identity
        .attributes
        .iter()
        .zip(qe_identity.attributes_mask.iter())
        .zip(qe_report.attributes.iter())
        .enumerate()
    {
        let expected_masked = expected & mask;
        let qe_masked = qe_attr & mask;
        if expected_masked != qe_masked {
            bail!(
                "QE ATTRIBUTES mismatch at byte {}: expected {:02X} (masked), got {:02X} (masked)",
                i,
                expected_masked,
                qe_masked
            );
        }
    }

    // Match QE TCB level based on ISVSVN
    match_qe_tcb_level(qe_report.isv_svn, &qe_identity.tcb_levels)
}

/// Match QE ISVSVN against QE Identity TCB levels
///
/// TCB levels are expected to be sorted from highest to lowest ISVSVN.
/// Returns the status and advisory IDs for the matching level.
fn match_qe_tcb_level(
    isv_svn: u16,
    tcb_levels: &[crate::qe_identity::QeTcbLevel],
) -> Result<TcbStatusWithAdvisory> {
    for tcb_level in tcb_levels {
        if isv_svn >= tcb_level.tcb.isvsvn {
            return Ok(TcbStatusWithAdvisory::new(
                tcb_level.tcb_status,
                tcb_level.advisory_ids.clone(),
            ));
        }
    }

    match tcb_levels.last().map(|l| l.tcb.isvsvn) {
        Some(min_required) => {
            bail!("QE ISVSVN {isv_svn} is below minimum required {min_required} from QE Identity");
        }
        None => {
            bail!("No TCB levels found in QE Identity");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tcb_info::TcbStatus::*;
    use hex_literal::hex;

    fn make_test_qe_report() -> EnclaveReport {
        EnclaveReport {
            cpu_svn: [0u8; 16],
            misc_select: 0x00000000,
            reserved1: [0u8; 28],
            attributes: [
                0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            mr_enclave: [0u8; 32],
            reserved2: [0u8; 32],
            mr_signer: hex::decode(
                "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF",
            )
            .unwrap()
            .try_into()
            .unwrap(),
            reserved3: [0u8; 96],
            isv_prod_id: 1,
            isv_svn: 8,
            reserved4: [0u8; 60],
            report_data: [0u8; 64],
        }
    }

    fn make_test_qe_identity() -> QeIdentity {
        use crate::qe_identity::{QeTcb, QeTcbLevel};

        QeIdentity {
            id: "QE".to_string(),
            version: 2,
            issue_date: "2025-06-19T10:01:18Z".to_string(),
            next_update: "2025-07-19T10:01:18Z".to_string(),
            tcb_evaluation_data_number: 17,
            miscselect: hex!("00000000"),
            miscselect_mask: hex!("FFFFFFFF"),
            attributes: hex!("11000000000000000000000000000000"),
            attributes_mask: hex!("FBFFFFFFFFFFFFFF0000000000000000"),
            mrsigner: hex!("8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF"),
            isvprodid: 1,
            tcb_levels: vec![
                QeTcbLevel {
                    tcb: QeTcb { isvsvn: 8 },
                    tcb_date: "2024-03-13T00:00:00Z".to_string(),
                    tcb_status: UpToDate,
                    advisory_ids: vec![],
                },
                QeTcbLevel {
                    tcb: QeTcb { isvsvn: 6 },
                    tcb_date: "2021-11-10T00:00:00Z".to_string(),
                    tcb_status: OutOfDate,
                    advisory_ids: vec!["INTEL-SA-00615".to_string()],
                },
                QeTcbLevel {
                    tcb: QeTcb { isvsvn: 5 },
                    tcb_date: "2020-11-11T00:00:00Z".to_string(),
                    tcb_status: OutOfDate,
                    advisory_ids: vec!["INTEL-SA-00477".to_string(), "INTEL-SA-00615".to_string()],
                },
            ],
        }
    }

    #[test]
    fn test_qe_identity_policy_valid() {
        let qe_report = make_test_qe_report();
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok(), "Expected success, got: {:?}", result);
    }

    #[test]
    fn test_qe_identity_policy_mrsigner_mismatch() {
        let qe_report = make_test_qe_report();
        let mut qe_identity = make_test_qe_identity();
        // Change expected MRSIGNER to something different
        qe_identity.mrsigner =
            hex!("0000000000000000000000000000000000000000000000000000000000000000");

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("MRSIGNER mismatch"),
            "Expected MRSIGNER mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_qe_identity_policy_isvprodid_mismatch() {
        let qe_report = make_test_qe_report();
        let mut qe_identity = make_test_qe_identity();
        qe_identity.isvprodid = 999; // Different product ID

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ISVPRODID mismatch"),
            "Expected ISVPRODID mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_qe_identity_policy_miscselect_mismatch() {
        let mut qe_report = make_test_qe_report();
        qe_report.misc_select = 0x00000001; // Set a bit
        let mut qe_identity = make_test_qe_identity();
        qe_identity.miscselect = hex!("00000000");
        qe_identity.miscselect_mask = hex!("FFFFFFFF"); // All bits checked

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("MISCSELECT mismatch"),
            "Expected MISCSELECT mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_qe_identity_policy_miscselect_masked() {
        let mut qe_report = make_test_qe_report();
        qe_report.misc_select = 0x000000FF; // Set some bits
        let mut qe_identity = make_test_qe_identity();
        qe_identity.miscselect = hex!("00000000");
        qe_identity.miscselect_mask = hex!("00000000"); // No bits checked (mask all zeros)

        // Should pass because mask is all zeros - no bits are checked
        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(
            result.is_ok(),
            "Expected success with zero mask, got: {:?}",
            result
        );
    }

    #[test]
    fn test_qe_identity_policy_attributes_mismatch() {
        let mut qe_report = make_test_qe_report();
        qe_report.attributes[0] = 0;
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ATTRIBUTES mismatch"),
            "Expected ATTRIBUTES mismatch error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_qe_identity_policy_attributes_masked() {
        let mut qe_report = make_test_qe_report();
        // Set bits in the second half (bytes 8-15) which are masked out
        qe_report.attributes[8] = 0xFF;
        qe_report.attributes[15] = 0xFF;
        let qe_identity = make_test_qe_identity();
        // Mask is "FBFFFFFFFFFFFFFF0000000000000000" - second half is all zeros

        // Should pass because those bytes are masked out
        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(
            result.is_ok(),
            "Expected success with masked attributes, got: {:?}",
            result
        );
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_up_to_date() {
        let qe_report = make_test_qe_report(); // isv_svn = 8
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.status, UpToDate);
        assert!(status.advisory_ids.is_empty());
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_out_of_date() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 6; // Lower than 8, matches second TCB level
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.status, OutOfDate);
        assert_eq!(status.advisory_ids, vec!["INTEL-SA-00615"]);
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_higher_than_required() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 10; // Higher than highest TCB level (8)
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let status = result.unwrap();
        assert_eq!(status.status, UpToDate); // Matches first level (isvsvn >= 8)
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_too_low() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 4; // Lower than all TCB levels (min is 5)
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("ISVSVN") && err_msg.contains("below minimum"),
            "Expected ISVSVN below minimum error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_between_levels() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 7; // Between level 8 and 6
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let status = result.unwrap();
        // Should match level with isvsvn=6 (7 >= 6)
        assert_eq!(status.status, OutOfDate);
        assert_eq!(status.advisory_ids, vec!["INTEL-SA-00615"]);
    }
}
