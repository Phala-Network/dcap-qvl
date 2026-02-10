use core::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use rustls_pki_types::UnixTime;
use scale::Decode;

use {
    crate::constants::*,
    crate::intel,
    crate::policy::{PckCertFlag, Policy, SupplementalData},
    crate::qe_identity::{QeIdentity, QeTcbLevel},
    crate::tcb_info::{TcbInfo, TcbLevel, TcbStatusWithAdvisory},
    alloc::string::String,
    alloc::vec::Vec,
};

pub use crate::quote::{AuthData, EnclaveReport, Quote};

#[cfg(feature = "ring")]
pub(crate) use self::ring as default_crypto;
#[cfg(all(not(feature = "ring"), feature = "rustcrypto"))]
pub(crate) use self::rustcrypto as default_crypto;
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
    /// SHA-384 hash function (used for root_key_id computation)
    pub sha384: fn(&[u8]) -> [u8; 48],
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

/// Result of cryptographic quote verification, before policy validation.
///
/// The enclave report is private — it can only be obtained by passing a [`Policy`]
/// via [`validate()`](Self::validate).
/// The [`supplemental`](Self::supplemental) field is public for inspection.
///
/// ```ignore
/// let result = verifier.verify(&quote, &collateral, now)?;
/// // Inspect supplemental data before committing
/// println!("TCB status: {:?}", result.supplemental.tcb_status);
/// // Apply policy to get the report
/// let report = result.validate(&QuotePolicy::strict(now))?;
/// ```
pub struct QuoteVerificationResult {
    report: Report,
    /// Supplemental data for policy decisions (publicly accessible).
    pub supplemental: SupplementalData,
}

impl QuoteVerificationResult {
    /// Validate against a policy, consuming self into [`VerifiedReport`] on success.
    pub fn validate<P: Policy + ?Sized>(self, policy: &P) -> Result<VerifiedReport> {
        policy.validate(&self.supplemental)?;
        Ok(self.into_verified_report())
    }

    /// Convert directly into [`VerifiedReport`] without applying any policy.
    ///
    /// Use this only when you have already performed your own validation
    /// or intentionally want to skip policy checks.
    pub fn into_report(self) -> VerifiedReport {
        self.into_verified_report()
    }

    fn into_verified_report(self) -> VerifiedReport {
        VerifiedReport {
            status: self.supplemental.tcb_status.to_string(),
            advisory_ids: self.supplemental.advisory_ids,
            report: self.report,
            ppid: self.supplemental.ppid,
            platform_tcb_level: self.supplemental.platform_tcb_level,
            qe_tcb_level: self.supplemental.qe_tcb_level,
        }
    }
}

#[cfg(feature = "rego")]
impl QuoteVerificationResult {
    /// Generate Intel-format `qvl_result` array for Rego appraisal.
    ///
    /// SGX quotes produce 2 entries (platform + enclave).
    /// TDX quotes produce 3 entries (platform + QE identity + TD).
    pub fn to_rego_qvl_result(&self) -> Vec<serde_json::Value> {
        use crate::policy::rego_policy::{platform_class_id, tenant_class_id, tenant_measurement};

        let mut result = Vec::new();

        // 1. Platform TCB measurement
        let platform_cid = platform_class_id(&self.report, self.supplemental.tee_type);
        result.push(serde_json::json!({
            "environment": { "class_id": platform_cid },
            "measurement": self.supplemental.to_platform_rego_measurement(),
        }));

        // 2. QE Identity measurement (TDX only)
        if matches!(self.report, Report::TD10(_) | Report::TD15(_)) {
            result.push(serde_json::json!({
                "environment": { "class_id": "3769258c-75e6-4bc7-8d72-d2b0e224cad2" },
                "measurement": self.supplemental.to_qe_rego_measurement(),
            }));
        }

        // 3. Tenant measurement (enclave or TD report)
        let tenant_cid = tenant_class_id(&self.report);
        result.push(serde_json::json!({
            "environment": { "class_id": tenant_cid },
            "measurement": tenant_measurement(&self.report),
        }));

        result
    }

    /// Validate against a [`RegoPolicySet`], consuming self into [`VerifiedReport`] on success.
    ///
    /// This is the multi-measurement equivalent of [`validate()`](Self::validate).
    pub fn validate_rego(self, policies: &crate::policy::RegoPolicySet) -> Result<VerifiedReport> {
        let qvl_result = self.to_rego_qvl_result();
        policies.eval_rego(qvl_result)?;
        Ok(self.into_verified_report())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct VerifiedReport {
    pub status: String,
    pub advisory_ids: Vec<String>,
    pub report: Report,
    #[serde(with = "serde_bytes")]
    pub ppid: Vec<u8>,
    pub platform_tcb_level: TcbLevel,
    pub qe_tcb_level: QeTcbLevel,
}

/// Quote verifier with configurable root certificate and crypto backend.
///
/// Returns [`QuoteVerificationResult`] from cryptographic verification.
/// The caller applies a [`Policy`] via [`QuoteVerificationResult::validate()`].
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

    /// Create a new verifier using Intel's production root certificate.
    pub fn new_prod(backend: CryptoBackend) -> Self {
        Self::new(TRUSTED_ROOT_CA_DER.to_vec(), backend)
    }

    #[cfg(feature = "_anycrypto")]
    pub fn new_prod_default_crypto() -> Self {
        Self::new_prod(default_crypto::backend())
    }

    /// Perform cryptographic verification, returning [`QuoteVerificationResult`].
    ///
    /// This does NOT apply any policy. Use [`QuoteVerificationResult::validate()`]
    /// to apply a policy and obtain a [`VerifiedReport`].
    pub fn verify(
        &self,
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> Result<QuoteVerificationResult> {
        verify_impl(
            raw_quote,
            collateral,
            now_secs,
            &self.root_ca_der,
            &self.backend,
        )
    }
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
    verify_certificate_chain(&tcb_leaf_cert, tcb_chain, now, crls, trust_anchor)?;

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
    verify_certificate_chain(&qe_id_leaf_cert, qe_id_chain, now, crls, trust_anchor)?;

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
    verify_certificate_chain(&pck_leaf_cert, pck_chain, now, crls, trust_anchor)?;

    // Extract Intel extension data from PCK cert (parsed once)
    let pck_ext = intel::parse_pck_extension(pck_leaf)?;

    // Convert pce_id bytes to u16 (big-endian)
    let pce_id = match pck_ext.pce_id.as_slice() {
        [hi, lo] => u16::from_be_bytes([*hi, *lo]),
        [lo] => u16::from(*lo),
        _ => 0,
    };

    // Convert platform_instance_id to fixed-size array
    let platform_instance_id = pck_ext.platform_instance_id.as_ref().and_then(|v| {
        let arr: [u8; 16] = v.as_slice().try_into().ok()?;
        Some(arr)
    });

    Ok(PckCertChainResult {
        pck_leaf_der: pck_leaf.as_ref().to_vec(),
        ppid: pck_ext.ppid,
        cpu_svn: pck_ext.cpu_svn,
        pce_svn: pck_ext.pce_svn,
        fmspc: pck_ext.fmspc,
        pce_id,
        sgx_type: pck_ext.sgx_type as u8,
        platform_instance_id,
        dynamic_platform: pck_ext.dynamic_platform.into(),
        cached_keys: pck_ext.cached_keys.into(),
        smt_enabled: pck_ext.smt_enabled.into(),
    })
}

/// Result from PCK certificate chain verification
struct PckCertChainResult {
    pck_leaf_der: Vec<u8>,
    ppid: Vec<u8>,
    cpu_svn: [u8; 16],
    pce_svn: u16,
    fmspc: [u8; 6],
    pce_id: u16,
    sgx_type: u8,
    platform_instance_id: Option<[u8; 16]>,
    dynamic_platform: PckCertFlag,
    cached_keys: PckCertFlag,
    smt_enabled: PckCertFlag,
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

/// Match platform TCB level and return the matched TcbLevel
fn match_platform_tcb(
    tcb_info: &TcbInfo,
    quote: &Quote,
    tee_type: TeeType,
    cpu_svn: &[u8],
    pce_svn: u16,
    fmspc: &[u8],
) -> Result<TcbLevel> {
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

        // Found matching level - return the full TcbLevel
        return Ok(tcb_level.clone());
    }

    bail!("No matching TCB level found");
}

// =============================================================================
// Main verification flow following the trust chain
// =============================================================================

/// Cryptographic verification of a quote. Returns [`SupplementalData`] without
/// applying any policy — the caller decides acceptance via [`SupplementalData::validate()`].
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
) -> Result<QuoteVerificationResult> {
    // Setup trust anchor and time
    let root_ca = CertificateDer::from_slice(root_ca_der);
    let trust_anchor =
        webpki::anchor_from_trusted_cert(&root_ca).context("Failed to load root ca")?;
    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));
    let raw_crls = [&collateral.root_ca_crl[..], &collateral.pck_crl];

    // Compute root_key_id: SHA-384 of root CA's raw public key bytes
    // (the BIT STRING content from SubjectPublicKeyInfo, excluding algorithm OID).
    // Matches Intel QVL's use of X509_get0_pubkey_bitstr().
    let root_key_id = {
        let root_cert: x509_cert::Certificate =
            der::Decode::from_der(root_ca_der).context("Failed to parse root CA for SPKI")?;
        let raw_key = root_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        (backend.sha384)(raw_key)
    };

    // Check root CA against CRL
    webpki::check_single_cert_crl(root_ca_der, &raw_crls, now)?;

    // Extract CRL numbers before parsing into webpki types
    let root_ca_crl_num = crate::utils::extract_crl_number(&collateral.root_ca_crl).unwrap_or(0);
    let pck_crl_num = crate::utils::extract_crl_number(&collateral.pck_crl).unwrap_or(0);

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
    )?;
    let pck_leaf = CertificateDer::from(pck_result.pck_leaf_der.as_slice());

    // Step 4: Verify QE Report signature
    let qe_report = verify_qe_report_signature(&pck_leaf, &auth_data, backend)?;

    // Step 5: Verify QE Report content (hash check)
    verify_qe_report_data(&qe_report, &auth_data, backend)?;

    // Step 6: Verify QE Report policy (returns matched QeTcbLevel)
    let qe_tcb_level = verify_qe_identity_policy(&qe_report, &qe_identity)?;

    // Step 7: Verify ISV Report signature
    verify_isv_report_signature(raw_quote, &quote, &auth_data, backend)?;

    // Step 8: Match Platform TCB (returns matched TcbLevel)
    let platform_tcb_level = match_platform_tcb(
        &tcb_info,
        &quote,
        tee_type,
        &pck_result.cpu_svn,
        pck_result.pce_svn,
        &pck_result.fmspc,
    )?;

    // Step 9 & 10: Merge statuses (take worst)
    let platform_status = TcbStatusWithAdvisory::new(
        platform_tcb_level.tcb_status,
        platform_tcb_level.advisory_ids.clone(),
    );
    let qe_status =
        TcbStatusWithAdvisory::new(qe_tcb_level.tcb_status, qe_tcb_level.advisory_ids.clone());
    let final_status = platform_status.merge(&qe_status);

    // Validate report attributes (debug mode check, etc.)
    validate_attrs(&quote.report)?;

    // Compute collateral time window fields
    // Re-extract PCK cert chain for date computation (already verified in step 3)
    let pck_certs_for_dates = if let Some(pem_chain) = &collateral.pck_certificate_chain {
        extract_certs(pem_chain.as_bytes()).unwrap_or_default()
    } else if auth_data.certification_data.cert_type == PCK_CERT_CHAIN {
        extract_certs(&auth_data.certification_data.body.data).unwrap_or_default()
    } else {
        Vec::new()
    };
    let (earliest_issue_date, latest_issue_date, earliest_expiration_date) =
        compute_collateral_time_window(collateral, &pck_certs_for_dates, &tcb_info, &qe_identity)?;

    // tcb_level_date_tag: parse the matched platform TCB level's tcb_date
    let tcb_level_date_tag = chrono::DateTime::parse_from_rfc3339(&platform_tcb_level.tcb_date)
        .ok()
        .map(|dt| dt.timestamp() as u64)
        .unwrap_or(0);

    // tcb_eval_data_number: lower of TCBInfo and QEIdentity values
    let tcb_eval_data_number = tcb_info
        .tcb_evaluation_data_number
        .min(qe_identity.tcb_evaluation_data_number);

    Ok(QuoteVerificationResult {
        report: quote.report,
        supplemental: SupplementalData {
            tcb_status: final_status.status,
            advisory_ids: final_status.advisory_ids,
            earliest_issue_date,
            latest_issue_date,
            earliest_expiration_date,
            tcb_level_date_tag,
            pck_crl_num,
            root_ca_crl_num,
            tcb_eval_data_number,
            root_key_id,
            ppid: pck_result.ppid,
            cpu_svn: pck_result.cpu_svn,
            pce_svn: pck_result.pce_svn,
            pce_id: pck_result.pce_id,
            fmspc: pck_result.fmspc,
            tee_type: quote.header.tee_type,
            sgx_type: pck_result.sgx_type,
            platform_instance_id: pck_result.platform_instance_id,
            dynamic_platform: pck_result.dynamic_platform,
            cached_keys: pck_result.cached_keys,
            smt_enabled: pck_result.smt_enabled,
            platform_tcb_level,
            qe_tcb_level,
            qe_report,
            qe_tcb_eval_data_number: qe_identity.tcb_evaluation_data_number,
        },
    })
}

/// Compute the collateral time window: earliest issue, latest issue, earliest expiration.
///
/// Matches Intel QVL's `qve_get_collateral_dates()` which considers **8 date sources**:
/// 1. Root CA CRL thisUpdate/nextUpdate
/// 2. PCK CRL thisUpdate/nextUpdate
/// 3. PCK CRL issuer certificate chain notBefore/notAfter
/// 4. PCK certificate chain notBefore/notAfter
/// 5. TCBInfo issuer certificate chain notBefore/notAfter
/// 6. QEIdentity issuer certificate chain notBefore/notAfter
/// 7. TCBInfo JSON issueDate/nextUpdate
/// 8. QEIdentity JSON issueDate/nextUpdate
fn compute_collateral_time_window(
    collateral: &QuoteCollateralV3,
    pck_cert_chain: &[CertificateDer<'_>],
    tcb_info: &TcbInfo,
    qe_identity: &QeIdentity,
) -> Result<(u64, u64, u64)> {
    fn parse_rfc3339_ts(s: &str) -> Option<u64> {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp() as u64)
    }

    fn parse_crl_dates(crl_der: &[u8]) -> Result<(u64, Option<u64>)> {
        use der::Decode as _;
        let crl = x509_cert::crl::CertificateList::from_der(crl_der)
            .context("Failed to parse CRL for time window")?;
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next_update = crl
            .tbs_cert_list
            .next_update
            .map(|t| t.to_unix_duration().as_secs());
        Ok((this_update, next_update))
    }

    /// Extract notBefore/notAfter from a PEM certificate chain and fold into min/max accumulators.
    fn fold_cert_chain_dates(
        pem_chain: &[u8],
        earliest_issue: &mut u64,
        latest_issue: &mut u64,
        earliest_expiration: &mut u64,
    ) -> Result<()> {
        let certs = extract_certs(pem_chain)?;
        fold_der_cert_dates(&certs, earliest_issue, latest_issue, earliest_expiration)
    }

    fn fold_der_cert_dates(
        certs: &[CertificateDer<'_>],
        earliest_issue: &mut u64,
        latest_issue: &mut u64,
        earliest_expiration: &mut u64,
    ) -> Result<()> {
        use der::Decode as _;
        for cert_der in certs {
            let cert = x509_cert::Certificate::from_der(cert_der)
                .context("Failed to parse certificate for time window")?;
            let not_before = cert
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs();
            let not_after = cert
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs();
            *earliest_issue = (*earliest_issue).min(not_before);
            *latest_issue = (*latest_issue).max(not_before);
            *earliest_expiration = (*earliest_expiration).min(not_after);
        }
        Ok(())
    }

    // TCBInfo dates (already parsed upstream)
    let tcb_issue = parse_rfc3339_ts(&tcb_info.issue_date).context("TCBInfo issueDate")?;
    let tcb_next = parse_rfc3339_ts(&tcb_info.next_update).context("TCBInfo nextUpdate")?;

    // QEIdentity dates (already parsed upstream)
    let qe_issue = parse_rfc3339_ts(&qe_identity.issue_date).context("QEIdentity issueDate")?;
    let qe_next = parse_rfc3339_ts(&qe_identity.next_update).context("QEIdentity nextUpdate")?;

    let mut earliest_issue = tcb_issue.min(qe_issue);
    let mut latest_issue = tcb_issue.max(qe_issue);
    let mut earliest_expiration = tcb_next.min(qe_next);

    // Include CRL dates (sources 1 & 2)
    for crl_der in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
        let (this_update, next_update) = parse_crl_dates(crl_der)?;
        earliest_issue = earliest_issue.min(this_update);
        latest_issue = latest_issue.max(this_update);
        if let Some(next) = next_update {
            earliest_expiration = earliest_expiration.min(next);
        }
    }

    // Include certificate chain dates (sources 3-6)
    // PCK CRL issuer chain (same PEM as pck_crl_issuer_chain)
    fold_cert_chain_dates(
        collateral.pck_crl_issuer_chain.as_bytes(),
        &mut earliest_issue,
        &mut latest_issue,
        &mut earliest_expiration,
    )?;
    // PCK certificate chain
    fold_der_cert_dates(
        pck_cert_chain,
        &mut earliest_issue,
        &mut latest_issue,
        &mut earliest_expiration,
    )?;
    // TCBInfo issuer chain
    fold_cert_chain_dates(
        collateral.tcb_info_issuer_chain.as_bytes(),
        &mut earliest_issue,
        &mut latest_issue,
        &mut earliest_expiration,
    )?;
    // QEIdentity issuer chain
    fold_cert_chain_dates(
        collateral.qe_identity_issuer_chain.as_bytes(),
        &mut earliest_issue,
        &mut latest_issue,
        &mut earliest_expiration,
    )?;

    Ok((earliest_issue, latest_issue, earliest_expiration))
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

    fn ring_sha384(data: &[u8]) -> [u8; 48] {
        let digest = ::ring::digest::digest(&::ring::digest::SHA384, data);
        let mut out = [0u8; 48];
        out.copy_from_slice(digest.as_ref());
        out
    }

    /// Returns a [`CryptoBackend`] backed by ring.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: webpki::ring::ECDSA_P256_SHA256,
            sha256: ring_sha256,
            sha384: ring_sha384,
        }
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

    fn rustcrypto_sha384(data: &[u8]) -> [u8; 48] {
        use sha2::Digest;
        sha2::Sha384::digest(data).into()
    }

    /// Returns a [`CryptoBackend`] backed by RustCrypto.
    pub fn backend() -> CryptoBackend {
        CryptoBackend {
            sig_algo: webpki::rustcrypto::ECDSA_P256_SHA256,
            sha256: rustcrypto_sha256,
            sha384: rustcrypto_sha384,
        }
    }
}

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
/// Returns the matched QeTcbLevel based on the QE's ISVSVN.
fn verify_qe_identity_policy(
    qe_report: &EnclaveReport,
    qe_identity: &QeIdentity,
) -> Result<QeTcbLevel> {
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
/// Returns the matched QeTcbLevel.
fn match_qe_tcb_level(
    isv_svn: u16,
    tcb_levels: &[crate::qe_identity::QeTcbLevel],
) -> Result<QeTcbLevel> {
    for tcb_level in tcb_levels {
        if isv_svn >= tcb_level.tcb.isvsvn {
            return Ok(tcb_level.clone());
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
        let tcb_level = result.unwrap();
        assert_eq!(tcb_level.tcb_status, UpToDate);
        assert!(tcb_level.advisory_ids.is_empty());
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_out_of_date() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 6; // Lower than 8, matches second TCB level
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let tcb_level = result.unwrap();
        assert_eq!(tcb_level.tcb_status, OutOfDate);
        assert_eq!(tcb_level.advisory_ids, vec!["INTEL-SA-00615"]);
    }

    #[test]
    fn test_qe_identity_policy_isvsvn_higher_than_required() {
        let mut qe_report = make_test_qe_report();
        qe_report.isv_svn = 10; // Higher than highest TCB level (8)
        let qe_identity = make_test_qe_identity();

        let result = verify_qe_identity_policy(&qe_report, &qe_identity);
        assert!(result.is_ok());
        let tcb_level = result.unwrap();
        assert_eq!(tcb_level.tcb_status, UpToDate); // Matches first level (isvsvn >= 8)
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
        let tcb_level = result.unwrap();
        // Should match level with isvsvn=6 (7 >= 6)
        assert_eq!(tcb_level.tcb_status, OutOfDate);
        assert_eq!(tcb_level.advisory_ids, vec!["INTEL-SA-00615"]);
    }
}
