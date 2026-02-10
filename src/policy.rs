use core::time::Duration;

use anyhow::{bail, Result};

use {
    crate::constants::*,
    crate::qe_identity::QeTcbLevel,
    crate::quote::EnclaveReport,
    crate::tcb_info::{TcbLevel, TcbStatus},
    alloc::string::String,
    alloc::vec::Vec,
};


/// Policy trait for customizing quote verification behavior.
///
/// Implement this trait to define custom validation logic for [`SupplementalData`].
/// The library provides [`QuotePolicy`] as a comprehensive built-in implementation
/// that covers all common checks from Intel's Appraisal framework.
///
/// For most use cases, [`QuotePolicy`] with its builder methods is sufficient:
/// ```ignore
/// use dcap_qvl::QuotePolicy;
/// use dcap_qvl::TcbStatus;
///
/// use core::time::Duration;
///
/// let policy = QuotePolicy::strict(now_unix_secs)
///     .allow_status(TcbStatus::SWHardeningNeeded)
///     .collateral_grace_period(Duration::from_secs(90 * 24 * 3600))
///     .accept_advisory("INTEL-SA-00334");
/// ```
///
/// Implement this trait directly only for logic that [`QuotePolicy`] cannot express.
pub trait Policy {
    /// Validate supplemental data against this policy.
    ///
    /// Return `Ok(())` to accept, or `Err(...)` to reject.
    fn validate(&self, data: &SupplementalData) -> Result<()>;
}

/// Status-based verification policy.
///
/// By default, the policy is strict: only `UpToDate` status is accepted.
/// Comprehensive verification policy with builder pattern.
///
/// Covers all checks from Intel's Appraisal framework (`qal_script.rego`).
/// Strict by default: only `UpToDate`, no grace period, no advisory tolerance.
///
/// # Example
/// ```ignore
/// use dcap_qvl::QuotePolicy;
/// use dcap_qvl::TcbStatus;
///
/// // Strict: only UpToDate, collateral must not be expired
/// let policy = QuotePolicy::strict(now);
///
/// // With 90-day collateral grace period
/// use core::time::Duration;
/// let policy = QuotePolicy::strict(now)
///     .allow_status(TcbStatus::SWHardeningNeeded)
///     .collateral_grace_period(Duration::from_secs(90 * 24 * 3600))
///     .accept_advisory("INTEL-SA-00334");
/// ```
#[derive(Clone, Debug)]
pub struct QuotePolicy {
    acceptable_statuses: u8,

    // Current time + grace periods (mutually exclusive, default 0 = no tolerance)
    now: u64,
    collateral_grace_period: u64,
    platform_grace_period: u64,

    // TCB evaluation
    min_tcb_eval_data_number: Option<u32>,

    // Advisory whitelist (all advisories in quote must be in this set)
    accepted_advisory_ids: Vec<String>,

    // Platform flags (default false = reject if True)
    allow_dynamic_platform: bool,
    allow_cached_keys: bool,
    allow_smt: bool,

    // SGX type whitelist (None = skip check)
    accepted_sgx_types: Option<Vec<u8>>,
}

impl QuotePolicy {
    const UP_TO_DATE: u8 = 1 << 0;
    const SW_HARDENING_NEEDED: u8 = 1 << 1;
    const CONFIGURATION_NEEDED: u8 = 1 << 2;
    const CONFIGURATION_AND_SW_HARDENING_NEEDED: u8 = 1 << 3;
    const OUT_OF_DATE: u8 = 1 << 4;
    const OUT_OF_DATE_CONFIGURATION_NEEDED: u8 = 1 << 5;

    fn status_to_flag(status: TcbStatus) -> u8 {
        match status {
            TcbStatus::UpToDate => Self::UP_TO_DATE,
            TcbStatus::SWHardeningNeeded => Self::SW_HARDENING_NEEDED,
            TcbStatus::ConfigurationNeeded => Self::CONFIGURATION_NEEDED,
            TcbStatus::ConfigurationAndSWHardeningNeeded => {
                Self::CONFIGURATION_AND_SW_HARDENING_NEEDED
            }
            TcbStatus::OutOfDate => Self::OUT_OF_DATE,
            TcbStatus::OutOfDateConfigurationNeeded => Self::OUT_OF_DATE_CONFIGURATION_NEEDED,
            TcbStatus::Revoked => 0,
        }
    }

    fn new_with_statuses(now: u64, acceptable_statuses: u8) -> Self {
        Self {
            acceptable_statuses,
            now,
            collateral_grace_period: 0,
            platform_grace_period: 0,
            min_tcb_eval_data_number: None,
            accepted_advisory_ids: Vec::new(),
            allow_dynamic_platform: false,
            allow_cached_keys: false,
            allow_smt: false,
            accepted_sgx_types: None,
        }
    }

    /// Create a strict policy: only `UpToDate` status is accepted,
    /// no grace period, no advisory tolerance.
    pub fn strict(now_secs: u64) -> Self {
        Self::new_with_statuses(now_secs, Self::UP_TO_DATE)
    }

    /// Allow an additional TCB status.
    pub fn allow_status(mut self, status: TcbStatus) -> Self {
        self.acceptable_statuses |= Self::status_to_flag(status);
        self
    }

    /// Set collateral grace period (default: zero). Accepts quotes where
    /// `earliest_expiration_date + grace_period >= now`.
    ///
    /// Must be zero if [`platform_grace_period`](Self::platform_grace_period) is non-zero.
    pub fn collateral_grace_period(mut self, duration: Duration) -> Self {
        self.collateral_grace_period = duration.as_secs();
        self
    }

    /// Set platform grace period (default: zero). When TCB status is
    /// OutOfDate or OutOfDateConfigurationNeeded, accepts quotes where
    /// `tcb_level_date_tag + grace_period >= now`. Skipped for UpToDate/ConfigNeeded/SWHardening.
    ///
    /// Must be zero if [`collateral_grace_period`](Self::collateral_grace_period) is non-zero.
    pub fn platform_grace_period(mut self, duration: Duration) -> Self {
        self.platform_grace_period = duration.as_secs();
        self
    }

    /// Set minimum TCB evaluation data number. Rejects quotes with
    /// `tcb_eval_data_number` below this threshold.
    pub fn min_tcb_eval_data_number(mut self, min: u32) -> Self {
        self.min_tcb_eval_data_number = Some(min);
        self
    }

    /// Accept a specific advisory ID. All advisories in the quote must be in
    /// the accepted set or validation fails. By default the set is empty,
    /// rejecting any quote with advisories.
    pub fn accept_advisory(mut self, id: impl Into<String>) -> Self {
        self.accepted_advisory_ids.push(id.into());
        self
    }

    /// Set whether dynamic platforms are allowed. If `false` (default), rejects
    /// quotes where `dynamic_platform` is `True`.
    pub fn allow_dynamic_platform(mut self, allow: bool) -> Self {
        self.allow_dynamic_platform = allow;
        self
    }

    /// Set whether cached keys are allowed. If `false` (default), rejects
    /// quotes where `cached_keys` is `True`.
    pub fn allow_cached_keys(mut self, allow: bool) -> Self {
        self.allow_cached_keys = allow;
        self
    }

    /// Set whether SMT (simultaneous multithreading / hyperthreading) is allowed.
    /// If `false` (default), rejects quotes where `smt_enabled` is `True`.
    pub fn allow_smt(mut self, allow: bool) -> Self {
        self.allow_smt = allow;
        self
    }

    /// Set accepted SGX types (0=Standard, 1=Scalable, 2=ScalableWithIntegrity).
    /// Rejects quotes with `sgx_type` not in this list. Default: skip check.
    pub fn accepted_sgx_types(mut self, types: &[u8]) -> Self {
        self.accepted_sgx_types = Some(types.to_vec());
        self
    }

    /// Check if a TCB status is acceptable according to this policy.
    pub fn is_status_acceptable(&self, status: TcbStatus) -> bool {
        let flag = Self::status_to_flag(status);
        (self.acceptable_statuses & flag) != 0
    }
}

impl Policy for QuotePolicy {
    fn validate(&self, data: &SupplementalData) -> Result<()> {
        // 1. TCB status whitelist
        if !self.is_status_acceptable(data.tcb_status) {
            bail!(
                "TCB status {:?} is not acceptable by policy",
                data.tcb_status
            );
        }

        // 2. Advisory ID whitelist
        for id in &data.advisory_ids {
            if !self
                .accepted_advisory_ids
                .iter()
                .any(|a| a.eq_ignore_ascii_case(id))
            {
                bail!("Advisory ID {id} is not in the accepted set");
            }
        }

        // 3 & 4. Grace periods (mutually exclusive)
        if self.collateral_grace_period > 0 && self.platform_grace_period > 0 {
            bail!("collateral_grace_period and platform_grace_period are mutually exclusive");
        }

        // 3. Collateral expiration: earliest_expiration_date + grace >= now
        // Always checked. With grace=0, this only rejects if collateral is already expired
        // (which verify() already enforces, so this catches offline/delayed validation).
        if data
            .earliest_expiration_date
            .saturating_add(self.collateral_grace_period)
            < self.now
        {
            bail!(
                "Collateral expired: earliest_expiration_date {} + grace {} < now {}",
                data.earliest_expiration_date,
                self.collateral_grace_period,
                self.now
            );
        }

        // 4. Platform TCB freshness: tcb_level_date_tag + grace >= now
        // Only checked when TCB status indicates the platform is out-of-date.
        // For "good" statuses (UpToDate, ConfigurationNeeded, SWHardeningNeeded),
        // tcb_level_date_tag is always in the past and irrelevant.
        // Matches Intel Rego: skip for UpToDate/ConfigNeeded/SWHardening.
        {
            let is_out_of_date = matches!(
                data.tcb_status,
                TcbStatus::OutOfDate | TcbStatus::OutOfDateConfigurationNeeded
            );
            if is_out_of_date
                && data
                    .tcb_level_date_tag
                    .saturating_add(self.platform_grace_period)
                    < self.now
            {
                bail!(
                    "Platform TCB too old: tcb_level_date_tag {} + grace {} < now {}",
                    data.tcb_level_date_tag,
                    self.platform_grace_period,
                    self.now
                );
            }
        }

        // 5. Minimum TCB evaluation data number
        if let Some(min) = self.min_tcb_eval_data_number {
            if data.tcb_eval_data_number < min {
                bail!(
                    "TCB eval data number {} is below minimum {}",
                    data.tcb_eval_data_number,
                    min
                );
            }
        }

        // 6. Dynamic platform flag
        if !self.allow_dynamic_platform && data.dynamic_platform == PckCertFlag::True {
            bail!("Dynamic platform is not allowed by policy");
        }

        // 7. Cached keys flag
        if !self.allow_cached_keys && data.cached_keys == PckCertFlag::True {
            bail!("Cached keys are not allowed by policy");
        }

        // 8. SMT flag
        if !self.allow_smt && data.smt_enabled == PckCertFlag::True {
            bail!("SMT (hyperthreading) is not allowed by policy");
        }

        // 9. SGX type whitelist
        if let Some(ref types) = self.accepted_sgx_types {
            if !types.contains(&data.sgx_type) {
                bail!(
                    "SGX type {} is not in accepted types {:?}",
                    data.sgx_type,
                    types
                );
            }
        }

        Ok(())
    }
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

/// Supplemental data from quote verification, analogous to Intel's `sgx_ql_qv_supplemental_t`.
///
/// Contains all information needed for policy decisions. This data is publicly
/// accessible for inspection, but the enclave report is only released after
/// passing a [`Policy`] via [`QuoteVerificationResult::validate()`].
///
/// Field names and semantics follow Intel's official QVL supplemental data structure.
pub struct SupplementalData {
    // ── Merged TCB result ───────────────────────────────────────────────
    /// Merged TCB status (worst of platform TCB + QE TCB).
    pub tcb_status: TcbStatus,

    /// Merged advisory IDs (union of platform + QE advisories).
    /// Comma-separated list in Intel's struct (`sa_list`).
    pub advisory_ids: Vec<String>,

    // ── Collateral time window ──────────────────────────────────────────
    /// Earliest issue date across **all** collateral pieces (UTC, unix seconds).
    /// Corresponds to Intel's `earliest_issue_date`.
    pub earliest_issue_date: u64,

    /// Latest issue date across **all** collateral pieces (UTC, unix seconds).
    /// Corresponds to Intel's `latest_issue_date`.
    pub latest_issue_date: u64,

    /// Earliest expiration date across **all** collateral pieces (UTC, unix seconds).
    /// Corresponds to Intel's `earliest_expiration_date`.
    pub earliest_expiration_date: u64,

    /// The SGX platform's TCB level date tag (UTC, unix seconds).
    /// The platform is not vulnerable to any Security Advisories with an SGX TCB
    /// impact released on or before this date.
    /// Corresponds to Intel's `tcb_level_date_tag`.
    pub tcb_level_date_tag: u64,

    // ── CRL information ─────────────────────────────────────────────────
    /// CRL number from the PCK Certificate Revocation List.
    /// Corresponds to Intel's `pck_crl_num`.
    pub pck_crl_num: u32,

    /// CRL number from the Root CA Certificate Revocation List.
    /// Corresponds to Intel's `root_ca_crl_num`.
    pub root_ca_crl_num: u32,

    // ── TCB evaluation ──────────────────────────────────────────────────
    /// Lower of the TCBInfo and QEIdentity `tcbEvaluationDataNumber` values.
    /// Corresponds to Intel's `tcb_eval_ref_num`.
    pub tcb_eval_data_number: u32,

    // ── Root of trust ───────────────────────────────────────────────────
    /// ID of the collateral's root signer: SHA-384 hash of the Root CA's
    /// raw public key bytes (BIT STRING content from SubjectPublicKeyInfo).
    /// Corresponds to Intel's `root_key_id`.
    pub root_key_id: [u8; 48],

    // ── Platform identity from PCK certificate ──────────────────────────
    /// Platform Provisioning ID (PPID) from the PCK certificate.
    /// Can be used for platform ownership checks.
    /// Corresponds to Intel's `pck_ppid`.
    pub ppid: Vec<u8>,

    /// CPU Security Version Number from the PCK certificate (16 bytes).
    /// Corresponds to Intel's `tcb_cpusvn`.
    pub cpu_svn: CpuSvn,

    /// PCE ISV Security Version Number from the PCK certificate.
    /// Corresponds to Intel's `tcb_pce_isvsvn`.
    pub pce_svn: Svn,

    /// PCE ID of the remote platform.
    /// Corresponds to Intel's `pce_id`.
    pub pce_id: u16,

    /// FMSPC — Firmware Security Version & Package Configuration (6 bytes)
    /// from the PCK certificate. Not directly in Intel's supplemental struct
    /// but essential for TCB level matching.
    pub fmspc: Fmspc,

    // ── TEE and SGX type ────────────────────────────────────────────────
    /// TEE type: `0x00000000` for SGX, `0x00000081` for TDX.
    /// Corresponds to Intel's `tee_type`.
    pub tee_type: u32,

    /// SGX memory protection type from the PCK certificate:
    /// - 0 = Standard
    /// - 1 = Scalable
    /// - 2 = Scalable with Integrity
    ///
    /// Corresponds to Intel's `sgx_type`.
    pub sgx_type: u8,

    // ── Platform instance (Platform CA certs only) ──────────────────────
    /// Platform Instance ID (16 bytes). Only present for Multi-Package
    /// platforms (PCK certificates issued by Platform CA).
    /// Corresponds to Intel's `platform_instance_id`.
    pub platform_instance_id: Option<[u8; 16]>,

    /// Whether the platform can be extended with additional packages
    /// via Package Add calls to SGX Registration Backend.
    /// Only relevant to PCK certificates issued by Platform CA.
    /// Corresponds to Intel's `dynamic_platform`.
    pub dynamic_platform: PckCertFlag,

    /// Whether platform root keys are cached by SGX Registration Backend.
    /// Only relevant to PCK certificates issued by Platform CA.
    /// Corresponds to Intel's `cached_keys`.
    pub cached_keys: PckCertFlag,

    /// Whether the platform has SMT (simultaneous multithreading / hyperthreading)
    /// enabled. Only relevant to PCK certificates issued by Platform CA.
    /// Corresponds to Intel's `smt_enabled`.
    pub smt_enabled: PckCertFlag,

    // ── Full TCB level details ──────────────────────────────────────────
    /// The matched platform TCB level (includes `tcb_date`, `tcb_status`, `advisory_ids`).
    pub platform_tcb_level: TcbLevel,

    /// The matched QE TCB level (includes `tcb_date`, `tcb_status`, `advisory_ids`).
    pub qe_tcb_level: QeTcbLevel,

    // ── QE report (for multi-measurement Rego) ────────────────────────────
    /// The QE's enclave report. Needed for QE Identity Rego measurement (TDX)
    /// and available for inspection.
    pub qe_report: EnclaveReport,

    /// TCB evaluation data number from QE Identity (unmerged).
    /// `tcb_eval_data_number` is min(TCBInfo, QEIdentity); this is the QE-specific value.
    pub qe_tcb_eval_data_number: u32,
}

// =============================================================================
// RegoPolicy — Intel QAL-compatible policy evaluation via regorus
// =============================================================================

#[cfg(feature = "rego")]
pub(crate) mod rego_policy {
    use super::*;
    use serde_json::json;

    /// Convert a unix timestamp (seconds) to an RFC3339 string.
    /// Returns an empty string for timestamp 0 (matching Intel's behavior of omitting the field).
    fn unix_to_rfc3339(secs: u64) -> String {
        chrono::DateTime::from_timestamp(secs as i64, 0)
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default()
    }

    /// Convert `TcbStatus` to the JSON string array that Intel's Rego expects.
    ///
    /// This matches Intel's `qv_result_tcb_status_map` in qve.cpp.
    fn tcb_status_to_rego_array(status: TcbStatus) -> serde_json::Value {
        match status {
            TcbStatus::UpToDate => json!(["UpToDate"]),
            TcbStatus::SWHardeningNeeded => json!(["UpToDate", "SWHardeningNeeded"]),
            TcbStatus::ConfigurationNeeded => json!(["UpToDate", "ConfigurationNeeded"]),
            TcbStatus::ConfigurationAndSWHardeningNeeded => {
                json!(["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded"])
            }
            TcbStatus::OutOfDate => json!(["OutOfDate"]),
            TcbStatus::OutOfDateConfigurationNeeded => {
                json!(["OutOfDate", "ConfigurationNeeded"])
            }
            TcbStatus::Revoked => json!(["Revoked"]),
        }
    }

    impl SupplementalData {
        /// Convert to the JSON `measurement` object that Intel's `qal_script.rego` expects.
        ///
        /// This matches the JSON construction in Intel's `qve.cpp` (lines 2135-2216).
        pub fn to_rego_measurement(&self) -> serde_json::Value {
            let mut m = serde_json::Map::new();

            // tcb_status: array of strings
            m.insert(
                "tcb_status".into(),
                tcb_status_to_rego_array(self.tcb_status),
            );

            // Time fields as RFC3339 strings
            let earliest_issue = unix_to_rfc3339(self.earliest_issue_date);
            if !earliest_issue.is_empty() {
                m.insert("earliest_issue_date".into(), json!(earliest_issue));
            }
            let latest_issue = unix_to_rfc3339(self.latest_issue_date);
            if !latest_issue.is_empty() {
                m.insert("latest_issue_date".into(), json!(latest_issue));
            }
            let earliest_exp = unix_to_rfc3339(self.earliest_expiration_date);
            if !earliest_exp.is_empty() {
                m.insert("earliest_expiration_date".into(), json!(earliest_exp));
            }
            let tcb_date = unix_to_rfc3339(self.tcb_level_date_tag);
            if !tcb_date.is_empty() {
                m.insert("tcb_level_date_tag".into(), json!(tcb_date));
            }

            // CRL numbers
            m.insert("pck_crl_num".into(), json!(self.pck_crl_num));
            m.insert("root_ca_crl_num".into(), json!(self.root_ca_crl_num));

            // TCB eval number
            m.insert("tcb_eval_num".into(), json!(self.tcb_eval_data_number));

            // SGX type (note: Rego reads "sgx_type", Intel C++ writes "sgx_types")
            m.insert("sgx_type".into(), json!(self.sgx_type));

            // Platform flags: only emit if not Undefined (matching Intel C++)
            if self.dynamic_platform != PckCertFlag::Undefined {
                m.insert(
                    "is_dynamic_platform".into(),
                    json!(self.dynamic_platform == PckCertFlag::True),
                );
            }
            if self.cached_keys != PckCertFlag::Undefined {
                m.insert(
                    "cached_keys".into(),
                    json!(self.cached_keys == PckCertFlag::True),
                );
            }
            if self.smt_enabled != PckCertFlag::Undefined {
                m.insert(
                    "smt_enabled".into(),
                    json!(self.smt_enabled == PckCertFlag::True),
                );
            }

            // Advisory IDs
            if !self.advisory_ids.is_empty() {
                m.insert("advisory_ids".into(), json!(self.advisory_ids));
            }

            // FMSPC as hex uppercase string
            m.insert("fmspc".into(), json!(hex::encode_upper(self.fmspc)));

            // Root key ID as hex uppercase string
            m.insert(
                "root_key_id".into(),
                json!(hex::encode_upper(self.root_key_id)),
            );

            serde_json::Value::Object(m)
        }

        /// Generate platform TCB measurement JSON using **unmerged** platform status.
        ///
        /// Unlike [`to_rego_measurement()`] which uses the merged `tcb_status`,
        /// this uses `platform_tcb_level.tcb_status` and `platform_tcb_level.advisory_ids`,
        /// suitable for multi-measurement Rego input alongside QE and tenant measurements.
        pub fn to_platform_rego_measurement(&self) -> serde_json::Value {
            let mut m = serde_json::Map::new();

            // tcb_status from platform (unmerged)
            m.insert(
                "tcb_status".into(),
                tcb_status_to_rego_array(self.platform_tcb_level.tcb_status),
            );

            // Time fields as RFC3339 strings
            let earliest_issue = unix_to_rfc3339(self.earliest_issue_date);
            if !earliest_issue.is_empty() {
                m.insert("earliest_issue_date".into(), json!(earliest_issue));
            }
            let latest_issue = unix_to_rfc3339(self.latest_issue_date);
            if !latest_issue.is_empty() {
                m.insert("latest_issue_date".into(), json!(latest_issue));
            }
            let earliest_exp = unix_to_rfc3339(self.earliest_expiration_date);
            if !earliest_exp.is_empty() {
                m.insert("earliest_expiration_date".into(), json!(earliest_exp));
            }
            let tcb_date = unix_to_rfc3339(self.tcb_level_date_tag);
            if !tcb_date.is_empty() {
                m.insert("tcb_level_date_tag".into(), json!(tcb_date));
            }

            m.insert("pck_crl_num".into(), json!(self.pck_crl_num));
            m.insert("root_ca_crl_num".into(), json!(self.root_ca_crl_num));
            m.insert("tcb_eval_num".into(), json!(self.tcb_eval_data_number));
            m.insert("sgx_type".into(), json!(self.sgx_type));

            if self.dynamic_platform != PckCertFlag::Undefined {
                m.insert(
                    "is_dynamic_platform".into(),
                    json!(self.dynamic_platform == PckCertFlag::True),
                );
            }
            if self.cached_keys != PckCertFlag::Undefined {
                m.insert(
                    "cached_keys".into(),
                    json!(self.cached_keys == PckCertFlag::True),
                );
            }
            if self.smt_enabled != PckCertFlag::Undefined {
                m.insert(
                    "smt_enabled".into(),
                    json!(self.smt_enabled == PckCertFlag::True),
                );
            }

            // Advisory IDs from platform (unmerged)
            if !self.platform_tcb_level.advisory_ids.is_empty() {
                m.insert(
                    "advisory_ids".into(),
                    json!(self.platform_tcb_level.advisory_ids),
                );
            }

            m.insert("fmspc".into(), json!(hex::encode_upper(self.fmspc)));
            m.insert(
                "root_key_id".into(),
                json!(hex::encode_upper(self.root_key_id)),
            );

            serde_json::Value::Object(m)
        }

        /// Generate QE Identity measurement JSON for Rego appraisal.
        ///
        /// Uses the unmerged QE TCB level data. Only meaningful for TDX quotes
        /// (SGX does not have a QE Identity qvl_result in Intel's format).
        pub fn to_qe_rego_measurement(&self) -> serde_json::Value {
            let mut m = serde_json::Map::new();

            // tcb_status from QE (unmerged)
            m.insert(
                "tcb_status".into(),
                tcb_status_to_rego_array(self.qe_tcb_level.tcb_status),
            );

            // tcb_level_date_tag from QE TCB level's tcb_date
            let qe_tcb_date = chrono::DateTime::parse_from_rfc3339(&self.qe_tcb_level.tcb_date)
                .ok()
                .map(|dt| dt.timestamp() as u64)
                .unwrap_or(0);
            let qe_date_str = unix_to_rfc3339(qe_tcb_date);
            if !qe_date_str.is_empty() {
                m.insert("tcb_level_date_tag".into(), json!(qe_date_str));
            }

            // Time window fields (collateral-wide, same as platform)
            let earliest_issue = unix_to_rfc3339(self.earliest_issue_date);
            if !earliest_issue.is_empty() {
                m.insert("earliest_issue_date".into(), json!(earliest_issue));
            }
            let latest_issue = unix_to_rfc3339(self.latest_issue_date);
            if !latest_issue.is_empty() {
                m.insert("latest_issue_date".into(), json!(latest_issue));
            }
            let earliest_exp = unix_to_rfc3339(self.earliest_expiration_date);
            if !earliest_exp.is_empty() {
                m.insert("earliest_expiration_date".into(), json!(earliest_exp));
            }

            // QE-specific tcb_eval_num
            m.insert("tcb_eval_num".into(), json!(self.qe_tcb_eval_data_number));

            m.insert(
                "root_key_id".into(),
                json!(hex::encode_upper(self.root_key_id)),
            );

            serde_json::Value::Object(m)
        }
    }

    // ── Tenant measurement helpers ─────────────────────────────────────────

    use crate::quote::{Report, TDReport10, TDReport15};

    /// Generate SGX enclave measurement JSON from an `EnclaveReport`.
    ///
    /// KSS fields are extracted from reserved areas matching Intel's `sgx_report_body_t` layout:
    /// - `isv_ext_prod_id`: reserved1\[12..28\] (16B at offset 32)
    /// - `config_id`: reserved3\[32..96\] (64B at offset 192)
    /// - `config_svn`: reserved4\[0..2\] (u16 LE at offset 260)
    /// - `isv_family_id`: reserved4\[44..60\] (16B at offset 304)
    pub(crate) fn sgx_enclave_measurement(report: &EnclaveReport) -> serde_json::Value {
        let mut m = serde_json::Map::new();

        m.insert(
            "sgx_miscselect".into(),
            json!(hex::encode_upper(report.misc_select.to_le_bytes())),
        );
        m.insert(
            "sgx_attributes".into(),
            json!(hex::encode_upper(report.attributes)),
        );
        m.insert(
            "sgx_mrenclave".into(),
            json!(hex::encode_upper(report.mr_enclave)),
        );
        m.insert(
            "sgx_mrsigner".into(),
            json!(hex::encode_upper(report.mr_signer)),
        );
        m.insert("sgx_isvprodid".into(), json!(report.isv_prod_id));
        m.insert("sgx_isvsvn".into(), json!(report.isv_svn));
        m.insert(
            "sgx_reportdata".into(),
            json!(hex::encode_upper(report.report_data)),
        );

        // KSS fields from reserved areas (Intel sgx_report_body_t layout)
        if let Some(ext_prod_id) = report.reserved1.get(12..28) {
            m.insert(
                "sgx_isvextprodid".into(),
                json!(hex::encode_upper(ext_prod_id)),
            );
        }
        if let Some(config_id) = report.reserved3.get(32..96) {
            m.insert(
                "sgx_configid".into(),
                json!(hex::encode_upper(config_id)),
            );
        }
        if let Some(config_svn_bytes) = report.reserved4.get(0..2).and_then(|s| <[u8; 2]>::try_from(s).ok()) {
            let config_svn = u16::from_le_bytes(config_svn_bytes);
            m.insert("sgx_configsvn".into(), json!(config_svn));
        }
        if let Some(family_id) = report.reserved4.get(44..60) {
            m.insert(
                "sgx_isvfamilyid".into(),
                json!(hex::encode_upper(family_id)),
            );
        }

        serde_json::Value::Object(m)
    }

    /// Generate TDX TD 1.0 measurement JSON from a `TDReport10`.
    fn td10_measurement(report: &TDReport10) -> serde_json::Value {
        let mut m = serde_json::Map::new();

        m.insert(
            "tdx_attributes".into(),
            json!(hex::encode_upper(report.td_attributes)),
        );
        m.insert(
            "tdx_xfam".into(),
            json!(hex::encode_upper(report.xfam)),
        );
        m.insert(
            "tdx_mrtd".into(),
            json!(hex::encode_upper(report.mr_td)),
        );
        m.insert(
            "tdx_mrconfigid".into(),
            json!(hex::encode_upper(report.mr_config_id)),
        );
        m.insert(
            "tdx_mrowner".into(),
            json!(hex::encode_upper(report.mr_owner)),
        );
        m.insert(
            "tdx_mrownerconfig".into(),
            json!(hex::encode_upper(report.mr_owner_config)),
        );
        m.insert(
            "tdx_rtmr0".into(),
            json!(hex::encode_upper(report.rt_mr0)),
        );
        m.insert(
            "tdx_rtmr1".into(),
            json!(hex::encode_upper(report.rt_mr1)),
        );
        m.insert(
            "tdx_rtmr2".into(),
            json!(hex::encode_upper(report.rt_mr2)),
        );
        m.insert(
            "tdx_rtmr3".into(),
            json!(hex::encode_upper(report.rt_mr3)),
        );
        m.insert(
            "tdx_reportdata".into(),
            json!(hex::encode_upper(report.report_data)),
        );

        serde_json::Value::Object(m)
    }

    /// Generate TDX TD 1.5 measurement JSON from a `TDReport15`.
    fn td15_measurement(report: &TDReport15) -> serde_json::Value {
        let mut m = td10_measurement(&report.base);
        if let Some(obj) = m.as_object_mut() {
            obj.insert(
                "tdx_mrservicetd".into(),
                json!(hex::encode_upper(report.mr_service_td)),
            );
        }
        m
    }

    /// Generate tenant measurement JSON from a `Report`.
    pub(crate) fn tenant_measurement(report: &Report) -> serde_json::Value {
        match report {
            Report::SgxEnclave(er) => sgx_enclave_measurement(er),
            Report::TD10(td) => td10_measurement(td),
            Report::TD15(td) => td15_measurement(td),
        }
    }

    /// Returns the tenant class_id for the given report type.
    pub(crate) fn tenant_class_id(report: &Report) -> &'static str {
        match report {
            Report::SgxEnclave(_) => "bef7cb8c-31aa-42c1-854c-10db005d5c41",
            Report::TD10(_) => "a1e4ee9c-a12e-48ac-bed0-e3f89297f687",
            Report::TD15(_) => "45b734fc-aa4e-4c3d-ad28-e43d08880e68",
        }
    }

    /// Returns the platform class_id for the given report type and tee_type.
    pub(crate) fn platform_class_id(report: &Report, tee_type: u32) -> &'static str {
        match (report, tee_type) {
            (Report::TD10(_), _) => "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f",
            (Report::TD15(_), _) => "f708b97f-0fb2-4e6b-8b03-8a5bcd1221d3",
            _ => "3123ec35-8d38-4ea5-87a5-d6c48b567570", // SGX
        }
    }

    // ── RegoPolicySet ──────────────────────────────────────────────────────

    /// A set of Rego policies for multi-measurement appraisal.
    ///
    /// Accepts multiple policy JSON objects (one per class_id). The Rego engine
    /// matches each `qvl_result` entry to its corresponding policy by `class_id`.
    ///
    /// This provides full Intel QAL compatibility with separate evaluation of
    /// platform TCB, QE identity, and tenant measurements.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dcap_qvl::RegoPolicySet;
    ///
    /// let platform_policy = r#"{
    ///     "environment": { "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570" },
    ///     "reference": { "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }
    /// }"#;
    /// let enclave_policy = r#"{
    ///     "environment": { "class_id": "bef7cb8c-31aa-42c1-854c-10db005d5c41" },
    ///     "reference": { "sgx_mrenclave": "ABCD..." }
    /// }"#;
    /// let policies = RegoPolicySet::new(&[platform_policy, enclave_policy]).unwrap();
    /// ```
    pub struct RegoPolicySet {
        engine: regorus::Engine,
        policies: Vec<serde_json::Value>,
    }

    impl RegoPolicySet {
        /// Create a `RegoPolicySet` from multiple Intel JSON policy strings.
        ///
        /// Uses the bundled `qal_script.rego`. Each JSON must have `environment.class_id`.
        pub fn new(policy_jsons: &[&str]) -> Result<Self> {
            Self::with_rego(policy_jsons, include_str!("../rego/qal_script.rego"))
        }

        /// Create a `RegoPolicySet` with a custom Rego script.
        pub fn with_rego(policy_jsons: &[&str], rego_source: &str) -> Result<Self> {
            let mut engine = regorus::Engine::new();
            engine
                .add_policy("qal_script.rego".into(), rego_source.into())
                .map_err(|e| anyhow::anyhow!("Failed to load Rego policy: {e}"))?;

            let mut policies = Vec::new();
            for json_str in policy_jsons {
                let policy: serde_json::Value = serde_json::from_str(json_str)
                    .map_err(|e| anyhow::anyhow!("Failed to parse policy JSON: {e}"))?;
                // Validate that class_id exists
                policy
                    .get("environment")
                    .and_then(|e| e.get("class_id"))
                    .and_then(|c| c.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Policy JSON missing environment.class_id"))?;
                policies.push(policy);
            }

            Ok(Self { engine, policies })
        }

        /// Evaluate the Rego engine with the given qvl_result entries.
        pub(crate) fn eval_rego(&self, qvl_result: Vec<serde_json::Value>) -> Result<()> {
            let mut engine = self.engine.clone();

            let input = json!({
                "qvl_result": qvl_result,
                "policies": {
                    "policy_array": &self.policies,
                }
            });

            let input_str = serde_json::to_string(&input)
                .map_err(|e| anyhow::anyhow!("Failed to serialize Rego input: {e}"))?;
            engine
                .set_input_json(&input_str)
                .map_err(|e| anyhow::anyhow!("Failed to set Rego input: {e}"))?;

            let result = engine
                .eval_rule("data.dcap.quote.appraisal.final_ret".into())
                .map_err(|e| anyhow::anyhow!("Rego evaluation failed: {e}"))?;

            let result_json = result
                .to_json_str()
                .map_err(|e| anyhow::anyhow!("Failed to convert Rego result: {e}"))?;

            match result_json.trim() {
                "1" => Ok(()),
                "0" => {
                    let detail = engine
                        .eval_rule("data.dcap.quote.appraisal.appraisal_result".into())
                        .ok()
                        .and_then(|v| v.to_json_str().ok());
                    if let Some(detail) = detail {
                        bail!("Rego appraisal failed: {detail}");
                    }
                    bail!("Rego appraisal failed (result = 0)");
                }
                "-1" => bail!("No policy matched the report class_id"),
                other => bail!("Unexpected Rego appraisal result: {other}"),
            }
        }
    }

    /// Policy implementation that evaluates Intel's `qal_script.rego` via the
    /// [regorus](https://github.com/microsoft/regorus) Rego interpreter.
    ///
    /// This provides bit-exact compatibility with Intel's Quote Appraisal Library (QAL).
    /// Users provide a JSON policy in Intel's format (the `reference` object from a
    /// Quote Appraisal Policy), and the Rego script evaluates it against the
    /// [`SupplementalData`] converted to Intel's measurement JSON format.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use dcap_qvl::RegoPolicy;
    ///
    /// let policy_json = r#"{
    ///     "environment": {
    ///         "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
    ///         "description": "Strict SGX platform TCB policy"
    ///     },
    ///     "reference": {
    ///         "accepted_tcb_status": ["UpToDate"],
    ///         "collateral_grace_period": 0
    ///     }
    /// }"#;
    /// let policy = RegoPolicy::new(policy_json).expect("invalid policy");
    /// ```
    pub struct RegoPolicy {
        engine: regorus::Engine,
        policy_json: serde_json::Value,
        class_id: String,
    }

    impl RegoPolicy {
        /// Create a `RegoPolicy` from an Intel JSON policy string.
        ///
        /// Uses the bundled `qal_script.rego` (from Intel's DCAP source).
        /// The JSON must contain `environment.class_id` to identify the policy type.
        pub fn new(policy_json: &str) -> Result<Self> {
            Self::with_rego(policy_json, include_str!("../rego/qal_script.rego"))
        }

        /// Create a `RegoPolicy` with a custom Rego script.
        ///
        /// Use this to provide an updated or modified version of `qal_script.rego`.
        pub fn with_rego(policy_json: &str, rego_source: &str) -> Result<Self> {
            let mut engine = regorus::Engine::new();
            engine
                .add_policy("qal_script.rego".into(), rego_source.into())
                .map_err(|e| anyhow::anyhow!("Failed to load Rego policy: {e}"))?;

            let policy: serde_json::Value = serde_json::from_str(policy_json)
                .map_err(|e| anyhow::anyhow!("Failed to parse policy JSON: {e}"))?;

            let class_id = policy
                .get("environment")
                .and_then(|e| e.get("class_id"))
                .and_then(|c| c.as_str())
                .ok_or_else(|| anyhow::anyhow!("Policy JSON missing environment.class_id"))?
                .to_string();

            Ok(Self {
                engine,
                policy_json: policy,
                class_id,
            })
        }
    }

    impl Policy for RegoPolicy {
        fn validate(&self, data: &SupplementalData) -> Result<()> {
            let mut engine = self.engine.clone();

            // Build the Rego input matching Intel's QAL format
            let measurement = data.to_rego_measurement();
            let input = json!({
                "qvl_result": [{
                    "environment": { "class_id": &self.class_id },
                    "measurement": measurement,
                }],
                "policies": {
                    "policy_array": [&self.policy_json]
                }
            });

            let input_str = serde_json::to_string(&input)
                .map_err(|e| anyhow::anyhow!("Failed to serialize Rego input: {e}"))?;
            engine
                .set_input_json(&input_str)
                .map_err(|e| anyhow::anyhow!("Failed to set Rego input: {e}"))?;

            // Evaluate `final_ret` directly (1=pass, 0=fail, -1=no policy).
            // We avoid `final_appraisal_result` which uses `rand.intn` (not available
            // in regorus) and `time.now_ns` for nonce/timestamp decorating.
            let result = engine
                .eval_rule("data.dcap.quote.appraisal.final_ret".into())
                .map_err(|e| anyhow::anyhow!("Rego evaluation failed: {e}"))?;

            let result_json = result
                .to_json_str()
                .map_err(|e| anyhow::anyhow!("Failed to convert Rego result: {e}"))?;

            match result_json.trim() {
                "1" => Ok(()),
                "0" => {
                    // Try to get detailed sub-check results for the error message
                    let detail = engine
                        .eval_rule("data.dcap.quote.appraisal.appraisal_result".into())
                        .ok()
                        .and_then(|v| v.to_json_str().ok());
                    if let Some(detail) = detail {
                        bail!("Rego appraisal failed: {detail}");
                    }
                    bail!("Rego appraisal failed (result = 0)");
                }
                "-1" => bail!("No policy matched the report class_id"),
                other => bail!("Unexpected Rego appraisal result: {other}"),
            }
        }
    }
}

#[cfg(feature = "rego")]
pub use rego_policy::RegoPolicy;
#[cfg(feature = "rego")]
pub use rego_policy::RegoPolicySet;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::tcb_info::TcbStatus::*;

    // ═══════════════════════════════════════════════════════════════════
    // QuotePolicy tests
    // ═══════════════════════════════════════════════════════════════════

    fn make_test_supplemental(tcb_status: TcbStatus) -> SupplementalData {
        use crate::qe_identity::{QeTcb, QeTcbLevel};
        use crate::tcb_info::{Tcb, TcbComponents, TcbLevel};

        SupplementalData {
            tcb_status,
            advisory_ids: vec![],
            earliest_issue_date: 1_700_000_000,
            latest_issue_date: 1_700_100_000,
            earliest_expiration_date: 1_703_000_000, // ~2023-12-19
            tcb_level_date_tag: 1_690_000_000,       // ~2023-07-22
            pck_crl_num: 1,
            root_ca_crl_num: 1,
            tcb_eval_data_number: 17,
            root_key_id: [0u8; 48],
            ppid: vec![0u8; 16],
            cpu_svn: [0u8; 16],
            pce_svn: 13,
            pce_id: 0,
            fmspc: [0u8; 6],
            tee_type: 0,
            sgx_type: 0,
            platform_instance_id: None,
            dynamic_platform: PckCertFlag::Undefined,
            cached_keys: PckCertFlag::Undefined,
            smt_enabled: PckCertFlag::Undefined,
            platform_tcb_level: TcbLevel {
                tcb: Tcb {
                    sgx_components: vec![TcbComponents { svn: 0 }; 16],
                    tdx_components: vec![],
                    pce_svn: 13,
                },
                tcb_date: "2023-07-22T00:00:00Z".to_string(),
                tcb_status: tcb_status,
                advisory_ids: vec![],
            },
            qe_tcb_level: QeTcbLevel {
                tcb: QeTcb { isvsvn: 8 },
                tcb_date: "2024-03-13T00:00:00Z".to_string(),
                tcb_status: UpToDate,
                advisory_ids: vec![],
            },
            qe_report: crate::quote::EnclaveReport {
                cpu_svn: [0u8; 16],
                misc_select: 0,
                reserved1: [0u8; 28],
                attributes: [0u8; 16],
                mr_enclave: [0u8; 32],
                reserved2: [0u8; 32],
                mr_signer: [0u8; 32],
                reserved3: [0u8; 96],
                isv_prod_id: 1,
                isv_svn: 8,
                reserved4: [0u8; 60],
                report_data: [0u8; 64],
            },
            qe_tcb_eval_data_number: 17,
        }
    }

    // -- TCB status checks --

    #[test]
    fn policy_strict_accepts_up_to_date() {
        let data = make_test_supplemental(UpToDate);
        let policy = QuotePolicy::strict(1_702_000_000); // within collateral window
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_strict_rejects_sw_hardening() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = QuotePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("TCB status"), "{err}");
    }

    #[test]
    fn policy_out_of_date_with_fresh_tcb_date_accepts() {
        let mut data = make_test_supplemental(OutOfDate);
        data.tcb_level_date_tag = 1_702_000_000;
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(OutOfDate);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_allow_status_builder() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(SWHardeningNeeded);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Advisory ID whitelist --

    #[test]
    fn policy_rejects_unknown_advisory() {
        let mut data = make_test_supplemental(UpToDate);
        data.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = QuotePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("INTEL-SA-00615"), "{err}");
    }

    #[test]
    fn policy_accepts_whitelisted_advisory() {
        let mut data = make_test_supplemental(UpToDate);
        data.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = QuotePolicy::strict(1_702_000_000).accept_advisory("INTEL-SA-00615");
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_advisory_case_insensitive() {
        let mut data = make_test_supplemental(UpToDate);
        data.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = QuotePolicy::strict(1_702_000_000).accept_advisory("intel-sa-00615");
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_empty_advisories_passes() {
        let data = make_test_supplemental(UpToDate);
        assert!(data.advisory_ids.is_empty());
        let policy = QuotePolicy::strict(1_702_000_000);
        // Empty advisory list in quote → nothing to check against whitelist → passes
        assert!(policy.validate(&data).is_ok());
    }

    // -- Collateral grace period --

    #[test]
    fn policy_collateral_expired_no_grace_rejects() {
        let data = make_test_supplemental(UpToDate);
        // earliest_expiration_date = 1_703_000_000, now = 1_704_000_000 → expired
        let policy = QuotePolicy::strict(1_704_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Collateral expired"), "{err}");
    }

    #[test]
    fn policy_collateral_expired_with_grace_accepts() {
        let data = make_test_supplemental(UpToDate);
        // earliest_expiration_date = 1_703_000_000, now = 1_704_000_000
        // grace = 2_000_000 → 1_703M + 2M = 1_705M >= 1_704M → ok
        let policy = QuotePolicy::strict(1_704_000_000)
            .collateral_grace_period(Duration::from_secs(2_000_000));
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_collateral_expired_grace_too_short_rejects() {
        let data = make_test_supplemental(UpToDate);
        // earliest_expiration_date = 1_703_000_000, now = 1_704_000_000
        // grace = 500_000 → 1_703M + 0.5M = 1_703_500_000 < 1_704M → reject
        let policy = QuotePolicy::strict(1_704_000_000)
            .collateral_grace_period(Duration::from_secs(500_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Collateral expired"), "{err}");
    }

    #[test]
    fn policy_collateral_not_expired_zero_grace_passes() {
        let data = make_test_supplemental(UpToDate);
        // earliest_expiration_date = 1_703_000_000, now = 1_702_000_000 → not expired
        let policy = QuotePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Platform grace period --

    #[test]
    fn policy_platform_grace_skipped_for_up_to_date() {
        let data = make_test_supplemental(UpToDate);
        // tcb_level_date_tag = 1_690_000_000, now = 1_702_000_000
        // grace = 0, but check is skipped because status is UpToDate
        let policy = QuotePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_skipped_for_sw_hardening() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(SWHardeningNeeded);
        // SWHardeningNeeded is a "good" status → platform grace skipped
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_skipped_for_config_needed() {
        let data = make_test_supplemental(ConfigurationNeeded);
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(ConfigurationNeeded);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_rejects() {
        let data = make_test_supplemental(OutOfDate);
        // tcb_level_date_tag = 1_690_000_000, now = 1_702_000_000, grace = 0
        // 1_690M + 0 < 1_702M → reject
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(OutOfDate);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_accepts_with_grace() {
        let data = make_test_supplemental(OutOfDate);
        // tcb_level_date_tag = 1_690_000_000, now = 1_702_000_000
        // grace = 13_000_000 → 1_690M + 13M = 1_703M >= 1_702M → ok
        let policy = QuotePolicy::strict(1_702_000_000)
            .allow_status(OutOfDate)
            .platform_grace_period(Duration::from_secs(13_000_000));
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_too_short_rejects() {
        let data = make_test_supplemental(OutOfDate);
        // tcb_level_date_tag = 1_690_000_000, now = 1_702_000_000
        // grace = 11_000_000 → 1_690M + 11M = 1_701M < 1_702M → reject
        let policy = QuotePolicy::strict(1_702_000_000)
            .allow_status(OutOfDate)
            .platform_grace_period(Duration::from_secs(11_000_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_config_needed() {
        let data = make_test_supplemental(OutOfDateConfigurationNeeded);
        // grace = 0 → reject
        let policy = QuotePolicy::strict(1_702_000_000).allow_status(OutOfDateConfigurationNeeded);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_grace_periods_mutually_exclusive() {
        let data = make_test_supplemental(UpToDate);
        let policy = QuotePolicy::strict(1_702_000_000)
            .collateral_grace_period(Duration::from_secs(100))
            .platform_grace_period(Duration::from_secs(100));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    // -- min_tcb_eval_data_number --

    #[test]
    fn policy_min_eval_num_rejects_below() {
        let data = make_test_supplemental(UpToDate);
        assert_eq!(data.tcb_eval_data_number, 17);
        let policy = QuotePolicy::strict(1_702_000_000).min_tcb_eval_data_number(20);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("below minimum"), "{err}");
    }

    #[test]
    fn policy_min_eval_num_accepts_equal() {
        let data = make_test_supplemental(UpToDate);
        let policy = QuotePolicy::strict(1_702_000_000).min_tcb_eval_data_number(17);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Platform flags --

    #[test]
    fn policy_rejects_dynamic_platform_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.dynamic_platform = PckCertFlag::True;
        let policy = QuotePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Dynamic platform"), "{err}");
    }

    #[test]
    fn policy_allows_dynamic_platform_when_configured() {
        let mut data = make_test_supplemental(UpToDate);
        data.dynamic_platform = PckCertFlag::True;
        let policy = QuotePolicy::strict(1_702_000_000).allow_dynamic_platform(true);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_undefined_platform_flags_pass() {
        // Processor CA certs have Undefined flags — should never be rejected
        let data = make_test_supplemental(UpToDate);
        assert_eq!(data.dynamic_platform, PckCertFlag::Undefined);
        assert_eq!(data.cached_keys, PckCertFlag::Undefined);
        assert_eq!(data.smt_enabled, PckCertFlag::Undefined);
        let policy = QuotePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_rejects_smt_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.smt_enabled = PckCertFlag::True;
        let policy = QuotePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("SMT"), "{err}");
    }

    #[test]
    fn policy_rejects_cached_keys_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.cached_keys = PckCertFlag::True;
        let policy = QuotePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Cached keys"), "{err}");
    }

    // -- SGX type whitelist --

    #[test]
    fn policy_sgx_type_not_configured_passes() {
        let data = make_test_supplemental(UpToDate);
        let policy = QuotePolicy::strict(1_702_000_000);
        // No accepted_sgx_types set → skip check
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_sgx_type_whitelist_rejects() {
        let mut data = make_test_supplemental(UpToDate);
        data.sgx_type = 1; // Scalable
        let policy = QuotePolicy::strict(1_702_000_000).accepted_sgx_types(&[0]); // Only Standard
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("SGX type"), "{err}");
    }

    #[test]
    fn policy_sgx_type_whitelist_accepts() {
        let mut data = make_test_supplemental(UpToDate);
        data.sgx_type = 1; // Scalable
        let policy = QuotePolicy::strict(1_702_000_000).accepted_sgx_types(&[0, 1, 2]);
        assert!(policy.validate(&data).is_ok());
    }

    // -- RegoPolicy tests (require "rego" feature) --

    #[cfg(feature = "rego")]
    mod rego_tests {
        use super::*;

        const SGX_PLATFORM_CLASS_ID: &str = "3123ec35-8d38-4ea5-87a5-d6c48b567570";

        /// Create test supplemental data with future expiration dates.
        ///
        /// The Rego engine uses `time.now_ns()` (real wall clock) for expiration
        /// checks, so test data must have dates in the future to pass.
        fn make_rego_supplemental(status: TcbStatus) -> SupplementalData {
            let mut data = make_test_supplemental(status);
            // Set dates far in the future so expiration_date_check passes
            data.earliest_expiration_date = 2_000_000_000; // 2033-05-18
            data.earliest_issue_date = 1_900_000_000; // 2030-03-17
            data.latest_issue_date = 1_900_100_000;
            data
        }

        fn policy_json(reference: &str) -> String {
            format!(
                r#"{{
                    "environment": {{
                        "class_id": "{SGX_PLATFORM_CLASS_ID}",
                        "description": "Test policy"
                    }},
                    "reference": {reference}
                }}"#
            )
        }

        #[test]
        fn rego_strict_accepts_up_to_date() {
            let data = make_rego_supplemental(UpToDate);
            let json = policy_json(
                r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let result = policy.validate(&data);
            assert!(
                result.is_ok(),
                "expected Ok, got: {:?}",
                result.unwrap_err()
            );
        }

        #[test]
        fn rego_strict_rejects_out_of_date() {
            let data = make_rego_supplemental(OutOfDate);
            let json = policy_json(
                r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let err = policy.validate(&data).unwrap_err().to_string();
            assert!(
                err.contains("appraisal failed"),
                "expected appraisal failure, got: {err}"
            );
        }

        #[test]
        fn rego_permissive_accepts_out_of_date() {
            let data = make_rego_supplemental(OutOfDate);
            let json = policy_json(
                r#"{"accepted_tcb_status": ["UpToDate", "OutOfDate"], "collateral_grace_period": 0}"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let result = policy.validate(&data);
            assert!(
                result.is_ok(),
                "expected Ok, got: {:?}",
                result.unwrap_err()
            );
        }

        #[test]
        fn rego_rejects_advisory() {
            let mut data = make_rego_supplemental(UpToDate);
            data.advisory_ids = vec!["INTEL-SA-00334".into()];
            let json = policy_json(
                r#"{
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                    "rejected_advisory_ids": ["INTEL-SA-00334"]
                }"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let err = policy.validate(&data).unwrap_err().to_string();
            assert!(
                err.contains("appraisal failed"),
                "expected advisory rejection, got: {err}"
            );
        }

        #[test]
        fn rego_platform_grace_period_accepts() {
            let mut data = make_rego_supplemental(OutOfDate);
            // tcb_level_date_tag in the past, but huge grace period covers it
            data.tcb_level_date_tag = 1_690_000_000; // 2023-07-22
            let json = policy_json(
                r#"{
                    "accepted_tcb_status": ["UpToDate", "OutOfDate"],
                    "collateral_grace_period": 0,
                    "platform_grace_period": 999999999
                }"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let result = policy.validate(&data);
            assert!(
                result.is_ok(),
                "expected Ok, got: {:?}",
                result.unwrap_err()
            );
        }

        #[test]
        fn rego_expiration_check_rejects_expired_collateral() {
            let mut data = make_rego_supplemental(UpToDate);
            // Set expiration in the past
            data.earliest_expiration_date = 1_703_000_000; // 2023-12-19
            let json = policy_json(
                r#"{"accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0}"#,
            );
            let policy = RegoPolicy::new(&json).unwrap();
            let err = policy.validate(&data).unwrap_err().to_string();
            assert!(
                err.contains("appraisal failed"),
                "expected expiration failure, got: {err}"
            );
        }

        #[test]
        fn rego_no_collateral_grace_skips_expiration_check() {
            let mut data = make_rego_supplemental(UpToDate);
            // Expired collateral, but no collateral_grace_period in policy → skip check
            data.earliest_expiration_date = 1_703_000_000; // 2023-12-19
            let json = policy_json(r#"{"accepted_tcb_status": ["UpToDate"]}"#);
            let policy = RegoPolicy::new(&json).unwrap();
            let result = policy.validate(&data);
            assert!(
                result.is_ok(),
                "expected Ok (no expiration check), got: {:?}",
                result.unwrap_err()
            );
        }

        #[test]
        fn rego_missing_class_id_errors() {
            let json = r#"{"reference": {"accepted_tcb_status": ["UpToDate"]}}"#;
            assert!(RegoPolicy::new(json).is_err());
        }

        #[test]
        fn rego_to_measurement_tcb_status_mapping() {
            let data = make_test_supplemental(ConfigurationAndSWHardeningNeeded);
            let m = data.to_rego_measurement();
            let statuses = m.get("tcb_status").unwrap().as_array().unwrap();
            assert_eq!(statuses.len(), 3);
            assert_eq!(statuses[0], "UpToDate");
            assert_eq!(statuses[1], "SWHardeningNeeded");
            assert_eq!(statuses[2], "ConfigurationNeeded");
        }

        #[test]
        fn rego_to_measurement_omits_undefined_flags() {
            let data = make_test_supplemental(UpToDate);
            assert_eq!(data.dynamic_platform, PckCertFlag::Undefined);
            let m = data.to_rego_measurement();
            assert!(m.get("is_dynamic_platform").is_none());
            assert!(m.get("cached_keys").is_none());
            assert!(m.get("smt_enabled").is_none());
        }

        #[test]
        fn rego_to_measurement_includes_true_flags() {
            let mut data = make_test_supplemental(UpToDate);
            data.dynamic_platform = PckCertFlag::True;
            data.cached_keys = PckCertFlag::False;
            data.smt_enabled = PckCertFlag::True;
            let m = data.to_rego_measurement();
            assert_eq!(m.get("is_dynamic_platform").unwrap(), true);
            assert_eq!(m.get("cached_keys").unwrap(), false);
            assert_eq!(m.get("smt_enabled").unwrap(), true);
        }

        // ═══════════════════════════════════════════════════════════════════
        // Multi-measurement tests
        // ═══════════════════════════════════════════════════════════════════

        #[test]
        fn rego_platform_measurement_uses_unmerged_status() {
            let mut data = make_test_supplemental(UpToDate);
            // Merged status is UpToDate, but platform-specific is OutOfDate
            data.platform_tcb_level.tcb_status = OutOfDate;
            data.platform_tcb_level.advisory_ids = vec!["INTEL-SA-00001".into()];
            let m = data.to_platform_rego_measurement();
            let statuses = m.get("tcb_status").unwrap().as_array().unwrap();
            // OutOfDate maps to ["UpToDate", "OutOfDate"]
            assert!(statuses.contains(&serde_json::json!("OutOfDate")));
            // Advisory from platform, not merged
            let advisories = m.get("advisory_ids").unwrap().as_array().unwrap();
            assert_eq!(advisories, &[serde_json::json!("INTEL-SA-00001")]);
        }

        #[test]
        fn rego_qe_measurement_fields() {
            let data = make_rego_supplemental(UpToDate);
            let m = data.to_qe_rego_measurement();
            // QE measurement should have tcb_status from qe_tcb_level
            assert!(m.get("tcb_status").is_some());
            // Should have tcb_eval_num from qe_tcb_eval_data_number
            assert_eq!(m.get("tcb_eval_num").unwrap(), 17);
            // Should have root_key_id
            assert!(m.get("root_key_id").is_some());
            // Should have time fields
            assert!(m.get("earliest_issue_date").is_some());
            assert!(m.get("latest_issue_date").is_some());
            assert!(m.get("earliest_expiration_date").is_some());
            assert!(m.get("tcb_level_date_tag").is_some());
        }

        #[test]
        fn rego_sgx_enclave_measurement_fields() {
            use crate::quote::EnclaveReport;

            let mut report = EnclaveReport {
                cpu_svn: [0u8; 16],
                misc_select: 0x12345678,
                reserved1: [0u8; 28],
                attributes: [0xAA; 16],
                mr_enclave: [0xBB; 32],
                reserved2: [0u8; 32],
                mr_signer: [0xCC; 32],
                reserved3: [0u8; 96],
                isv_prod_id: 42,
                isv_svn: 7,
                reserved4: [0u8; 60],
                report_data: [0xDD; 64],
            };
            // Set KSS fields in reserved areas
            // isv_ext_prod_id at reserved1[12..28]
            report.reserved1[12..28].copy_from_slice(&[0x11; 16]);
            // config_id at reserved3[32..96]
            report.reserved3[32..96].copy_from_slice(&[0x22; 64]);
            // config_svn at reserved4[0..2]
            report.reserved4[0..2].copy_from_slice(&42u16.to_le_bytes());
            // isv_family_id at reserved4[44..60]
            report.reserved4[44..60].copy_from_slice(&[0x33; 16]);

            let m = rego_policy::sgx_enclave_measurement(&report);
            assert!(m.get("sgx_mrenclave").is_some());
            assert!(m.get("sgx_mrsigner").is_some());
            assert_eq!(m.get("sgx_isvprodid").unwrap(), 42);
            assert_eq!(m.get("sgx_isvsvn").unwrap(), 7);
            assert!(m.get("sgx_reportdata").is_some());
            assert!(m.get("sgx_configid").is_some());
            assert_eq!(m.get("sgx_configsvn").unwrap(), 42);
            assert!(m.get("sgx_isvextprodid").is_some());
            assert!(m.get("sgx_isvfamilyid").is_some());
        }

        #[test]
        fn rego_policy_set_sgx_platform_accepts() {
            let data = make_rego_supplemental(UpToDate);
            let platform_json = format!(
                r#"{{
                    "environment": {{ "class_id": "{SGX_PLATFORM_CLASS_ID}" }},
                    "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
                }}"#
            );
            let policies = RegoPolicySet::new(&[&platform_json]).unwrap();
            let qvl_result = vec![serde_json::json!({
                "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
                "measurement": data.to_platform_rego_measurement(),
            })];
            assert!(
                policies.eval_rego(qvl_result).is_ok(),
                "expected Ok, got: {:?}",
                {
                    let qvl_result2 = vec![serde_json::json!({
                        "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
                        "measurement": data.to_platform_rego_measurement(),
                    })];
                    policies.eval_rego(qvl_result2).unwrap_err()
                }
            );
        }

        #[test]
        fn rego_policy_set_class_id_mismatch_fails() {
            let data = make_rego_supplemental(UpToDate);
            // Policy expects TDX platform class_id, but measurement is SGX
            let tdx_class_id = "9eec018b-7481-4b1c-8e1a-9f7c0c8c777f";
            let policy_json = format!(
                r#"{{
                    "environment": {{ "class_id": "{tdx_class_id}" }},
                    "reference": {{ "accepted_tcb_status": ["UpToDate"], "collateral_grace_period": 0 }}
                }}"#
            );
            let policies = RegoPolicySet::new(&[&policy_json]).unwrap();
            let qvl_result = vec![serde_json::json!({
                "environment": { "class_id": SGX_PLATFORM_CLASS_ID },
                "measurement": data.to_platform_rego_measurement(),
            })];
            // Mismatched class_ids → no bundle matched → empty appraisal → fail
            let err = policies.eval_rego(qvl_result).unwrap_err().to_string();
            assert!(
                err.contains("appraisal failed"),
                "expected appraisal failure on class_id mismatch, got: {err}"
            );
        }
    }
}
