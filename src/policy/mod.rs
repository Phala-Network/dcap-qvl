use anyhow::Result;

use {
    crate::constants::*,
    crate::qe_identity::QeTcbLevel,
    crate::quote::{EnclaveReport, Report},
    crate::tcb_info::{TcbLevel, TcbStatus},
    alloc::string::String,
    alloc::vec::Vec,
};

mod simple;
pub use simple::{SimplePolicy, SimplePolicyConfig};

#[cfg(feature = "rego")]
pub(crate) mod rego;
#[cfg(feature = "rego")]
pub use rego::RegoPolicy;
#[cfg(feature = "rego")]
pub use rego::RegoPolicySet;

/// Policy trait for customizing quote verification behavior.
///
/// Implement this trait to define custom validation logic for [`SupplementalData`].
/// The library provides [`SimplePolicy`] as a comprehensive built-in implementation
/// that covers all common checks from Intel's Appraisal framework.
///
/// For most use cases, [`SimplePolicy`] with its builder methods is sufficient:
/// ```ignore
/// use dcap_qvl::SimplePolicy;
/// use dcap_qvl::TcbStatus;
///
/// use core::time::Duration;
///
/// let policy = SimplePolicy::strict(now_unix_secs)
///     .allow_status(TcbStatus::SWHardeningNeeded)
///     .collateral_grace_period(Duration::from_secs(90 * 24 * 3600))
///     .accept_advisory("INTEL-SA-00334");
/// ```
///
/// Implement this trait directly only for logic that [`SimplePolicy`] cannot express.
pub trait Policy {
    /// Validate supplemental data against this policy.
    ///
    /// Return `Ok(())` to accept, or `Err(...)` to reject.
    fn validate(&self, data: &SupplementalData) -> Result<()>;
}

/// PCK certificate flag, matching Intel's `pck_cert_flag_enum_t`.
///
/// These flags are only present in PCK certificates issued by the **Platform CA**.
/// For Processor CA certificates, the value is [`Undefined`](PckCertFlag::Undefined).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PckCertFlag {
    /// The flag is explicitly false (ASN.1 BOOLEAN FALSE).
    False = 0,
    /// The flag is explicitly true (ASN.1 BOOLEAN TRUE).
    True = 1,
    /// The flag is not present in the certificate (Processor CA certs).
    Undefined = 2,
}

impl From<Option<bool>> for PckCertFlag {
    fn from(v: Option<bool>) -> Self {
        match v {
            Some(true) => PckCertFlag::True,
            Some(false) => PckCertFlag::False,
            None => PckCertFlag::Undefined,
        }
    }
}

/// Supplemental data from quote verification.
///
/// Organized into structured sub-groups:
/// - [`tcb`](Self::tcb): Merged TCB verdict
/// - [`platform`](Self::platform): Platform-level details from PCK certificate and TCB matching
/// - [`qe`](Self::qe): QE (Quoting Enclave) verification results
///
/// Also includes the collateral time window (8 sources: TCBInfo, QEIdentity, 2 CRLs,
/// 4 certificate chains) and the quote report body.
pub struct SupplementalData {
    /// TEE type: `0x00000000` for SGX, `0x00000081` for TDX.
    pub tee_type: u32,
    /// Merged TCB verdict (worst of platform + QE).
    pub tcb: TcbVerdict,
    /// Platform verification details.
    pub platform: PlatformInfo,
    /// QE verification details.
    pub qe: QeInfo,
    /// `min(issueDate / thisUpdate / notBefore)` across all 8 collateral sources.
    pub earliest_issue_date: u64,
    /// `max(issueDate / thisUpdate / notBefore)` across all 8 collateral sources.
    pub latest_issue_date: u64,
    /// `min(nextUpdate / notAfter)` across all 8 collateral sources (the "weakest link").
    pub earliest_expiration_date: u64,
    /// Quote report body (SGX enclave report, TDX TD10/TD15).
    pub report: Report,
}

/// Merged TCB verdict from platform and QE status convergence.
///
/// Uses Intel's `convergeTcbStatusWithQeTcbStatus` logic to produce the
/// worst-case status and union of advisory IDs.
pub struct TcbVerdict {
    /// Merged TCB status (worst of platform TCB + QE TCB).
    pub status: TcbStatus,
    /// Merged advisory IDs (union of platform + QE advisories).
    pub advisory_ids: Vec<String>,
    /// Lower of TCBInfo and QEIdentity `tcbEvaluationDataNumber` values.
    pub eval_data_number: u32,
}

/// Platform-level verification results.
pub struct PlatformInfo {
    /// The matched platform TCB level (unmerged).
    pub tcb_level: TcbLevel,
    /// Platform TCB level date as unix timestamp (precomputed from `tcb_level.tcb_date`).
    pub tcb_date_tag: u64,
    /// PCK certificate identity fields.
    pub pck: PckIdentity,
    /// SHA-384 of root CA's raw public key bytes, matching Intel's `root_key_id`.
    pub root_key_id: [u8; 48],
    /// CRL number from PCK Certificate Revocation List.
    pub pck_crl_num: u32,
    /// CRL number from Root CA Certificate Revocation List.
    pub root_ca_crl_num: u32,
}

/// QE (Quoting Enclave) verification results.
pub struct QeInfo {
    /// The matched QE TCB level (unmerged).
    pub tcb_level: QeTcbLevel,
    /// The QE's enclave report.
    pub report: EnclaveReport,
    /// TCB evaluation data number from QE Identity (unmerged).
    pub tcb_eval_data_number: u32,
}

/// PCK certificate identity fields.
pub struct PckIdentity {
    /// Platform Provisioning ID (PPID).
    pub ppid: Vec<u8>,
    /// CPU Security Version Number (16 bytes).
    pub cpu_svn: CpuSvn,
    /// PCE ISV Security Version Number.
    pub pce_svn: Svn,
    /// PCE ID.
    pub pce_id: u16,
    /// FMSPC (6 bytes).
    pub fmspc: Fmspc,
    /// SGX type: 0=Standard, 1=Scalable, 2=ScalableWithIntegrity.
    pub sgx_type: u8,
    /// Platform Instance ID (16 bytes, Platform CA only).
    pub platform_instance_id: Option<[u8; 16]>,
    /// Dynamic platform flag.
    pub dynamic_platform: PckCertFlag,
    /// Cached keys flag.
    pub cached_keys: PckCertFlag,
    /// SMT (hyperthreading) flag.
    pub smt_enabled: PckCertFlag,
    /// Platform Provider ID (Platform CA only, for Rego).
    pub platform_provider_id: Option<String>,
}
