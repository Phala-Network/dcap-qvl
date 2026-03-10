use core::time::Duration;

use anyhow::{bail, Result};

use {
    super::{PckCertFlag, Policy, SupplementalData},
    crate::tcb_info::TcbStatus,
    alloc::string::String,
    alloc::vec::Vec,
};

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
/// use dcap_qvl::SimplePolicy;
/// use dcap_qvl::TcbStatus;
///
/// // Strict: only UpToDate, collateral must not be expired
/// let policy = SimplePolicy::strict(now);
///
/// // With 90-day collateral grace period
/// use core::time::Duration;
/// let policy = SimplePolicy::strict(now)
///     .allow_status(TcbStatus::SWHardeningNeeded)
///     .collateral_grace_period(Duration::from_secs(90 * 24 * 3600))
///     .accept_advisory("INTEL-SA-00334");
/// ```
#[derive(Clone, Debug)]
pub struct SimplePolicy {
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

impl SimplePolicy {
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

impl Policy for SimplePolicy {
    fn validate(&self, data: &SupplementalData) -> Result<()> {
        // 1. TCB status whitelist
        if !self.is_status_acceptable(data.tcb.status) {
            bail!(
                "TCB status {:?} is not acceptable by policy",
                data.tcb.status
            );
        }

        // 3 & 4. Grace periods (mutually exclusive)
        if self.collateral_grace_period > 0 && self.platform_grace_period > 0 {
            bail!("collateral_grace_period and platform_grace_period are mutually exclusive");
        }

        // 3. Collateral expiration: earliest_expiration + grace >= now
        if data
            .tcb
            .earliest_expiration
            .saturating_add(self.collateral_grace_period)
            < self.now
        {
            bail!(
                "Collateral expired: earliest_expiration {} + grace {} < now {}",
                data.tcb.earliest_expiration,
                self.collateral_grace_period,
                self.now
            );
        }

        // 4. Platform TCB freshness: tcb_date_tag + grace >= now
        // Only checked when TCB status indicates the platform is out-of-date.
        let is_out_of_date = matches!(
            data.tcb.status,
            TcbStatus::OutOfDate | TcbStatus::OutOfDateConfigurationNeeded
        );
        if is_out_of_date
            && data
                .platform
                .tcb_date_tag
                .saturating_add(self.platform_grace_period)
                < self.now
        {
            bail!(
                "Platform TCB too old: tcb_date_tag {} + grace {} < now {}",
                data.platform.tcb_date_tag,
                self.platform_grace_period,
                self.now
            );
        }

        // Determine if we're within a platform grace window — advisory checks are skipped
        // only for pure OutOfDate during platform grace. Collateral grace does NOT skip
        // advisories (stale collateral doesn't invalidate advisory data).
        // OutOfDateConfigurationNeeded does NOT skip either (Configuration advisories
        // are unrelated to the OutOfDate grace window).
        let in_platform_grace =
            self.platform_grace_period > 0 && data.tcb.status == TcbStatus::OutOfDate;

        // 2. Advisory ID whitelist (skipped only during platform grace for pure OutOfDate)
        if !in_platform_grace {
            for id in &data.tcb.advisory_ids {
                if !self
                    .accepted_advisory_ids
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(id))
                {
                    bail!("Advisory ID {id} is not in the accepted set");
                }
            }
        }

        // 5. Minimum TCB evaluation data number
        if let Some(min) = self.min_tcb_eval_data_number {
            if data.tcb.eval_data_number < min {
                bail!(
                    "TCB eval data number {} is below minimum {}",
                    data.tcb.eval_data_number,
                    min
                );
            }
        }

        // 6. Dynamic platform flag
        if !self.allow_dynamic_platform && data.platform.pck.dynamic_platform == PckCertFlag::True {
            bail!("Dynamic platform is not allowed by policy");
        }

        // 7. Cached keys flag
        if !self.allow_cached_keys && data.platform.pck.cached_keys == PckCertFlag::True {
            bail!("Cached keys are not allowed by policy");
        }

        // 8. SMT flag
        if !self.allow_smt && data.platform.pck.smt_enabled == PckCertFlag::True {
            bail!("SMT (hyperthreading) is not allowed by policy");
        }

        // 9. SGX type whitelist
        if let Some(ref types) = self.accepted_sgx_types {
            if !types.contains(&data.platform.pck.sgx_type) {
                bail!(
                    "SGX type {} is not in accepted types {:?}",
                    data.platform.pck.sgx_type,
                    types
                );
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::policy::{PckIdentity, PlatformInfo, QeInfo, TcbVerdict};
    use crate::tcb_info::TcbStatus::*;

    fn make_test_supplemental(tcb_status: TcbStatus) -> SupplementalData {
        use crate::qe_identity::{QeTcb, QeTcbLevel};
        use crate::tcb_info::{Tcb, TcbComponents, TcbLevel};

        SupplementalData {
            tee_type: 0,
            tcb: TcbVerdict {
                status: tcb_status,
                advisory_ids: vec![],
                eval_data_number: 17,
                earliest_expiration: 1_703_000_000, // ~2023-12-19
            },
            platform: PlatformInfo {
                tcb_level: TcbLevel {
                    tcb: Tcb {
                        sgx_components: vec![TcbComponents { svn: 0 }; 16],
                        tdx_components: vec![],
                        pce_svn: 13,
                    },
                    tcb_date: "2023-07-22T00:00:00Z".to_string(),
                    tcb_status,
                    advisory_ids: vec![],
                },
                tcb_date_tag: 1_690_000_000, // ~2023-07-22
                pck: PckIdentity {
                    ppid: vec![0u8; 16],
                    cpu_svn: [0u8; 16],
                    pce_svn: 13,
                    pce_id: 0,
                    fmspc: [0u8; 6],
                    sgx_type: 0,
                    platform_instance_id: None,
                    dynamic_platform: PckCertFlag::Undefined,
                    cached_keys: PckCertFlag::Undefined,
                    smt_enabled: PckCertFlag::Undefined,
                    platform_provider_id: None,
                },
                root_key_id: [0u8; 48],
                pck_crl_num: 1,
                root_ca_crl_num: 1,
            },
            qe: QeInfo {
                tcb_level: QeTcbLevel {
                    tcb: QeTcb { isvsvn: 8 },
                    tcb_date: "2024-03-13T00:00:00Z".to_string(),
                    tcb_status: UpToDate,
                    advisory_ids: vec![],
                },
                report: crate::quote::EnclaveReport {
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
                tcb_eval_data_number: 17,
            },
        }
    }

    // -- TCB status checks --

    #[test]
    fn policy_strict_accepts_up_to_date() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000); // within collateral window
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_strict_rejects_sw_hardening() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("TCB status"), "{err}");
    }

    #[test]
    fn policy_out_of_date_with_fresh_tcb_date_accepts() {
        let mut data = make_test_supplemental(OutOfDate);
        data.platform.tcb_date_tag = 1_702_000_000;
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(OutOfDate);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_allow_status_builder() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(SWHardeningNeeded);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Advisory ID whitelist --

    #[test]
    fn policy_rejects_unknown_advisory() {
        let mut data = make_test_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("INTEL-SA-00615"), "{err}");
    }

    #[test]
    fn policy_accepts_whitelisted_advisory() {
        let mut data = make_test_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = SimplePolicy::strict(1_702_000_000).accept_advisory("INTEL-SA-00615");
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_advisory_case_insensitive() {
        let mut data = make_test_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = SimplePolicy::strict(1_702_000_000).accept_advisory("intel-sa-00615");
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_empty_advisories_passes() {
        let data = make_test_supplemental(UpToDate);
        assert!(data.tcb.advisory_ids.is_empty());
        let policy = SimplePolicy::strict(1_702_000_000);
        // Empty advisory list in quote → nothing to check against whitelist → passes
        assert!(policy.validate(&data).is_ok());
    }

    // -- Collateral grace period --

    #[test]
    fn policy_collateral_expired_no_grace_rejects() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_704_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Collateral expired"), "{err}");
    }

    #[test]
    fn policy_collateral_expired_with_grace_accepts() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_704_000_000)
            .collateral_grace_period(Duration::from_secs(2_000_000));
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_collateral_expired_grace_too_short_rejects() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_704_000_000)
            .collateral_grace_period(Duration::from_secs(500_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Collateral expired"), "{err}");
    }

    #[test]
    fn policy_collateral_not_expired_zero_grace_passes() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Platform grace period --

    #[test]
    fn policy_platform_grace_skipped_for_up_to_date() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_skipped_for_sw_hardening() {
        let data = make_test_supplemental(SWHardeningNeeded);
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(SWHardeningNeeded);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_skipped_for_config_needed() {
        let data = make_test_supplemental(ConfigurationNeeded);
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(ConfigurationNeeded);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_rejects() {
        let data = make_test_supplemental(OutOfDate);
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(OutOfDate);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_accepts_with_grace() {
        let data = make_test_supplemental(OutOfDate);
        let policy = SimplePolicy::strict(1_702_000_000)
            .allow_status(OutOfDate)
            .platform_grace_period(Duration::from_secs(13_000_000));
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_platform_grace_too_short_rejects() {
        let data = make_test_supplemental(OutOfDate);
        let policy = SimplePolicy::strict(1_702_000_000)
            .allow_status(OutOfDate)
            .platform_grace_period(Duration::from_secs(11_000_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_platform_grace_checked_for_out_of_date_config_needed() {
        let data = make_test_supplemental(OutOfDateConfigurationNeeded);
        let policy = SimplePolicy::strict(1_702_000_000).allow_status(OutOfDateConfigurationNeeded);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Platform TCB too old"), "{err}");
    }

    #[test]
    fn policy_grace_periods_mutually_exclusive() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000)
            .collateral_grace_period(Duration::from_secs(100))
            .platform_grace_period(Duration::from_secs(100));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "{err}");
    }

    // -- min_tcb_eval_data_number --

    #[test]
    fn policy_min_eval_num_rejects_below() {
        let data = make_test_supplemental(UpToDate);
        assert_eq!(data.tcb.eval_data_number, 17);
        let policy = SimplePolicy::strict(1_702_000_000).min_tcb_eval_data_number(20);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("below minimum"), "{err}");
    }

    #[test]
    fn policy_min_eval_num_accepts_equal() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000).min_tcb_eval_data_number(17);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Platform flags --

    #[test]
    fn policy_rejects_dynamic_platform_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.dynamic_platform = PckCertFlag::True;
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Dynamic platform"), "{err}");
    }

    #[test]
    fn policy_allows_dynamic_platform_when_configured() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.dynamic_platform = PckCertFlag::True;
        let policy = SimplePolicy::strict(1_702_000_000).allow_dynamic_platform(true);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_undefined_platform_flags_pass() {
        let data = make_test_supplemental(UpToDate);
        assert_eq!(data.platform.pck.dynamic_platform, PckCertFlag::Undefined);
        assert_eq!(data.platform.pck.cached_keys, PckCertFlag::Undefined);
        assert_eq!(data.platform.pck.smt_enabled, PckCertFlag::Undefined);
        let policy = SimplePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_rejects_smt_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.smt_enabled = PckCertFlag::True;
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("SMT"), "{err}");
    }

    #[test]
    fn policy_rejects_cached_keys_true() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.cached_keys = PckCertFlag::True;
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("Cached keys"), "{err}");
    }

    // -- SGX type whitelist --

    #[test]
    fn policy_sgx_type_not_configured_passes() {
        let data = make_test_supplemental(UpToDate);
        let policy = SimplePolicy::strict(1_702_000_000);
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_sgx_type_whitelist_rejects() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.sgx_type = 1;
        let policy = SimplePolicy::strict(1_702_000_000).accepted_sgx_types(&[0]);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("SGX type"), "{err}");
    }

    #[test]
    fn policy_sgx_type_whitelist_accepts() {
        let mut data = make_test_supplemental(UpToDate);
        data.platform.pck.sgx_type = 1;
        let policy = SimplePolicy::strict(1_702_000_000).accepted_sgx_types(&[0, 1, 2]);
        assert!(policy.validate(&data).is_ok());
    }

    // -- Advisory skipped during grace --

    #[test]
    fn policy_advisory_checked_during_collateral_grace() {
        let mut data = make_test_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        // Collateral grace doesn't skip advisory checks — stale collateral
        // doesn't invalidate advisory data.
        let policy = SimplePolicy::strict(1_704_000_000)
            .collateral_grace_period(Duration::from_secs(2_000_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("INTEL-SA-00615"), "{err}");
    }

    #[test]
    fn policy_advisory_skipped_during_platform_grace() {
        let mut data = make_test_supplemental(OutOfDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        // now=1_702_000_000, tcb_date_tag=1_690_000_000 (old),
        // grace=13_000_000 → within grace → advisories skipped
        let policy = SimplePolicy::strict(1_702_000_000)
            .allow_status(OutOfDate)
            .platform_grace_period(Duration::from_secs(13_000_000));
        assert!(policy.validate(&data).is_ok());
    }

    #[test]
    fn policy_advisory_not_skipped_for_out_of_date_config_needed() {
        // OutOfDateConfigurationNeeded should NOT skip advisory checks during grace,
        // because the Configuration advisories are unrelated to the OutOfDate grace.
        let mut data = make_test_supplemental(OutOfDateConfigurationNeeded);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        let policy = SimplePolicy::strict(1_702_000_000)
            .allow_status(OutOfDateConfigurationNeeded)
            .platform_grace_period(Duration::from_secs(13_000_000));
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("INTEL-SA-00615"), "{err}");
    }

    #[test]
    fn policy_advisory_checked_without_grace() {
        let mut data = make_test_supplemental(UpToDate);
        data.tcb.advisory_ids = vec!["INTEL-SA-00615".to_string()];
        // No grace period → advisories checked normally
        let policy = SimplePolicy::strict(1_702_000_000);
        let err = policy.validate(&data).unwrap_err().to_string();
        assert!(err.contains("INTEL-SA-00615"), "{err}");
    }
}
