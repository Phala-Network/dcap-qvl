use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TcbInfo {
    pub id: String,
    pub version: u8,
    pub issue_date: String,
    pub next_update: String,
    pub fmspc: String,
    pub pce_id: String,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TcbLevel>,
    #[serde(default)]
    pub tdx_module: Option<TdxModule>,
    #[serde(rename = "tdxModuleIdentities", default)]
    pub tdx_module_identities: Vec<TdxModuleIdentity>,
}

impl TcbInfo {
    /// Canonicalize `tcb_levels` ordering to match Intel QVL.
    ///
    /// Intel's QVL does not rely on the JSON order of `tcbLevels`. Instead, it
    /// inserts levels into a sorted container using a custom comparator:
    ///
    /// - First by SGX CPU SVN components (lexicographically, highest first)
    /// - Then by PCE SVN (highest first)
    /// - For TDX TCB Info (version >= 3, id == "TDX"), by TDX TCB components
    ///   as a final tiebreaker (lexicographically, highest first)
    ///
    /// This function mirrors that behavior so that matching logic operates on a
    /// stable, implementation-defined order rather than whatever the PCS JSON
    /// happens to contain.
    pub(crate) fn canonicalize_tcb_levels(&mut self) {
        let is_tdx = self.version >= 3 && self.id == "TDX";
        self.tcb_levels
            .sort_by(|a, b| compare_tcb_levels(a, b, is_tdx));
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

fn compare_tcb_levels(a: &TcbLevel, b: &TcbLevel, is_tdx: bool) -> Ordering {
    // Primary key: SGX CPU SVN components (lexicographically, highest first)
    b.tcb
        .sgx_components
        .cmp(&a.tcb.sgx_components)
        // Then by PCE SVN (highest first)
        .then_with(|| b.tcb.pce_svn.cmp(&a.tcb.pce_svn))
        // For TDX, refine by TDX TCB components as final tiebreaker
        .then_with(|| {
            if is_tdx {
                b.tcb.tdx_components.cmp(&a.tcb.tdx_components)
            } else {
                Ordering::Equal
            }
        })
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct Tcb {
    #[serde(rename = "sgxtcbcomponents")]
    pub sgx_components: Vec<TcbComponents>,
    #[serde(rename = "tdxtcbcomponents", default)]
    pub tdx_components: Vec<TcbComponents>,
    #[serde(rename = "pcesvn")]
    pub pce_svn: u16,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TcbComponents {
    pub svn: u8,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TdxModule {
    /// Expected TDX module MRSIGNER as hex string
    pub mrsigner: String,
    /// Expected SEAMATTRIBUTES value as hex string
    pub attributes: String,
    /// Mask to apply when comparing SEAMATTRIBUTES, as hex string
    pub attributes_mask: String,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TdxModuleIdentity {
    pub id: String,
    pub mrsigner: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub tcb_levels: Vec<TdxModuleTcbLevel>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TdxModuleTcbLevel {
    pub tcb: TdxModuleTcb,
    pub tcb_date: String,
    pub tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TdxModuleTcb {
    pub isvsvn: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Display)]
#[display("{_variant}")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub enum TcbStatus {
    UpToDate,
    OutOfDateConfigurationNeeded,
    OutOfDate,
    ConfigurationAndSWHardeningNeeded,
    ConfigurationNeeded,
    SWHardeningNeeded,
    Revoked,
    /// TD 1.5 only: the TD launched with an out-of-date TCB, but its current
    /// TCB (after a TD-preserving module update) is not out of date.
    TDRelaunchAdvised,
    /// [`TDRelaunchAdvised`](Self::TDRelaunchAdvised) where the launch or
    /// current TCB also needs platform configuration.
    TDRelaunchAdvisedConfigurationNeeded,
}

impl TcbStatus {
    /// Converge a platform status with a QE or TDX module status like Intel
    /// QVL's `convergeTcbStatuses`: only an `OutOfDate` or `Revoked` component
    /// affects the platform status.
    pub(crate) fn converge_with_component(self, component: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        match (component, self) {
            (Revoked, _) => Revoked,
            (OutOfDate, UpToDate | SWHardeningNeeded) => OutOfDate,
            (OutOfDate, ConfigurationNeeded | ConfigurationAndSWHardeningNeeded) => {
                OutOfDateConfigurationNeeded
            }
            _ => self,
        }
    }

    /// Combine the launch and current statuses of a TD 1.5 like Intel QVL's
    /// `checkForRelaunch`.
    pub(crate) fn check_for_relaunch(self, current: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        let configuration_needed = |status| {
            matches!(
                status,
                ConfigurationNeeded
                    | OutOfDateConfigurationNeeded
                    | ConfigurationAndSWHardeningNeeded
                    | TDRelaunchAdvisedConfigurationNeeded
            )
        };
        match (self, current) {
            (
                OutOfDate | OutOfDateConfigurationNeeded,
                UpToDate
                | SWHardeningNeeded
                | ConfigurationNeeded
                | ConfigurationAndSWHardeningNeeded,
            ) => {
                if configuration_needed(self) || configuration_needed(current) {
                    TDRelaunchAdvisedConfigurationNeeded
                } else {
                    TDRelaunchAdvised
                }
            }
            _ => self,
        }
    }
}

/// TCB status with advisory IDs
///
/// This is the result of matching a TCB level, used by both
/// platform TCB matching and QE Identity verification.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TcbStatusWithAdvisory {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

impl TcbStatusWithAdvisory {
    /// Create a new TcbStatus with the given status and advisory IDs
    pub fn new(status: TcbStatus, advisory_ids: Vec<String>) -> Self {
        Self {
            status,
            advisory_ids,
        }
    }

    /// Merge a platform status with a QE status using Intel QVL convergence rules.
    pub fn merge(self, other: &TcbStatusWithAdvisory) -> Self {
        let final_status = self.status.converge_with_component(other.status);

        let mut advisory_ids = self.advisory_ids;
        for id in &other.advisory_ids {
            if !advisory_ids.contains(id) {
                advisory_ids.push(id.clone());
            }
        }

        Self {
            status: final_status,
            advisory_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TcbStatus::*;

    #[test]
    fn test_tcb_status_merge_both_up_to_date() {
        let a = TcbStatusWithAdvisory::new(UpToDate, vec![]);
        let b = TcbStatusWithAdvisory::new(UpToDate, vec![]);
        let result = a.merge(&b);
        assert_eq!(result.status, UpToDate);
        assert!(result.advisory_ids.is_empty());
    }

    #[test]
    fn test_tcb_status_merge_out_of_date_component() {
        let a = TcbStatusWithAdvisory::new(UpToDate, vec![]);
        let b = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.status, OutOfDate);
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
    }

    #[test]
    fn qe_out_of_date_converges_configuration_status() {
        let platform = TcbStatusWithAdvisory::new(TcbStatus::ConfigurationNeeded, vec![]);
        let qe = TcbStatusWithAdvisory::new(TcbStatus::OutOfDate, vec![]);
        assert_eq!(
            platform.merge(&qe).status,
            TcbStatus::OutOfDateConfigurationNeeded
        );
    }

    #[test]
    fn test_converge_with_component_matches_intel() {
        for (platform, component, expected) in [
            (UpToDate, OutOfDate, OutOfDate),
            (SWHardeningNeeded, OutOfDate, OutOfDate),
            (
                ConfigurationAndSWHardeningNeeded,
                OutOfDate,
                OutOfDateConfigurationNeeded,
            ),
            (
                OutOfDateConfigurationNeeded,
                OutOfDate,
                OutOfDateConfigurationNeeded,
            ),
            (ConfigurationNeeded, Revoked, Revoked),
            // Only OutOfDate and Revoked components affect the platform status.
            (UpToDate, ConfigurationNeeded, UpToDate),
            (UpToDate, OutOfDateConfigurationNeeded, UpToDate),
            (SWHardeningNeeded, UpToDate, SWHardeningNeeded),
        ] {
            assert_eq!(platform.converge_with_component(component), expected);
        }
    }

    #[test]
    fn test_check_for_relaunch_matches_intel() {
        for (launch, current, expected) in [
            (OutOfDate, UpToDate, TDRelaunchAdvised),
            (OutOfDate, SWHardeningNeeded, TDRelaunchAdvised),
            (
                OutOfDate,
                ConfigurationNeeded,
                TDRelaunchAdvisedConfigurationNeeded,
            ),
            (
                OutOfDateConfigurationNeeded,
                UpToDate,
                TDRelaunchAdvisedConfigurationNeeded,
            ),
            (OutOfDate, OutOfDate, OutOfDate),
            (OutOfDate, Revoked, OutOfDate),
            (UpToDate, UpToDate, UpToDate),
            (ConfigurationNeeded, UpToDate, ConfigurationNeeded),
        ] {
            assert_eq!(launch.check_for_relaunch(current), expected);
        }
    }

    #[test]
    fn test_tcb_status_merge_combines_advisories() {
        let a = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let b = TcbStatusWithAdvisory::new(SWHardeningNeeded, vec!["INTEL-SA-00002".into()]);
        let result = a.merge(&b);
        assert_eq!(result.status, OutOfDate);
        assert_eq!(
            result.advisory_ids,
            vec!["INTEL-SA-00001", "INTEL-SA-00002"]
        );
    }

    #[test]
    fn test_tcb_status_merge_deduplicates_advisories() {
        let a = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let b = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
    }

    fn make_tcb_level(sgx: &[u8], pce_svn: u16, tdx: &[u8], status: TcbStatus) -> TcbLevel {
        TcbLevel {
            tcb: Tcb {
                sgx_components: sgx.iter().map(|&svn| TcbComponents { svn }).collect(),
                tdx_components: tdx.iter().map(|&svn| TcbComponents { svn }).collect(),
                pce_svn,
            },
            tcb_date: String::new(),
            tcb_status: status,
            advisory_ids: vec![],
        }
    }

    fn make_tcb_info(id: &str, tcb_levels: Vec<TcbLevel>) -> TcbInfo {
        TcbInfo {
            id: id.into(),
            version: 3,
            issue_date: String::new(),
            next_update: String::new(),
            fmspc: String::new(),
            pce_id: String::new(),
            tcb_type: 0,
            tcb_evaluation_data_number: 0,
            tcb_levels,
            tdx_module: None,
            tdx_module_identities: vec![],
        }
    }

    #[allow(clippy::expect_used)]
    fn first_component_svn(components: &[TcbComponents]) -> u8 {
        components
            .first()
            .expect("expected at least one TCB component")
            .svn
    }

    #[test]
    fn test_canonicalize_sgx_sorts_by_cpu_svn_desc() {
        let mut info = make_tcb_info(
            "SGX",
            vec![
                make_tcb_level(&[2, 0], 10, &[], UpToDate),
                make_tcb_level(&[5, 0], 10, &[], UpToDate),
                make_tcb_level(&[3, 0], 10, &[], UpToDate),
            ],
        );
        info.canonicalize_tcb_levels();
        let svns: Vec<u8> = info
            .tcb_levels
            .iter()
            .map(|l| first_component_svn(&l.tcb.sgx_components))
            .collect();
        assert_eq!(svns, vec![5, 3, 2]);
    }

    #[test]
    fn test_canonicalize_sgx_pce_svn_tiebreaker() {
        let mut info = make_tcb_info(
            "SGX",
            vec![
                make_tcb_level(&[5], 7, &[], UpToDate),
                make_tcb_level(&[5], 12, &[], UpToDate),
                make_tcb_level(&[5], 9, &[], UpToDate),
            ],
        );
        info.canonicalize_tcb_levels();
        let pce_svns: Vec<u16> = info.tcb_levels.iter().map(|l| l.tcb.pce_svn).collect();
        assert_eq!(pce_svns, vec![12, 9, 7]);
    }

    #[test]
    fn test_canonicalize_tdx_components_tiebreaker() {
        let mut info = make_tcb_info(
            "TDX",
            vec![
                make_tcb_level(&[5], 10, &[1, 0], UpToDate),
                make_tcb_level(&[5], 10, &[3, 0], UpToDate),
                make_tcb_level(&[5], 10, &[2, 0], UpToDate),
            ],
        );
        info.canonicalize_tcb_levels();
        let tdx_svns: Vec<u8> = info
            .tcb_levels
            .iter()
            .map(|l| first_component_svn(&l.tcb.tdx_components))
            .collect();
        assert_eq!(tdx_svns, vec![3, 2, 1]);
    }

    #[test]
    fn test_canonicalize_sgx_ignores_tdx_components() {
        let mut info = make_tcb_info(
            "SGX",
            vec![
                make_tcb_level(&[5], 10, &[1], UpToDate),
                make_tcb_level(&[5], 10, &[9], UpToDate),
            ],
        );
        info.canonicalize_tcb_levels();
        // For SGX, tdx_components should NOT break the tie — order is stable
        let tdx_svns: Vec<u8> = info
            .tcb_levels
            .iter()
            .map(|l| first_component_svn(&l.tcb.tdx_components))
            .collect();
        assert_eq!(tdx_svns, vec![1, 9]);
    }
}
