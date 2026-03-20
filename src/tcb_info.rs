use std::cmp::Ordering;

use alloc::string::String;
use alloc::vec::Vec;
use derive_more::Display;
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
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
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, Display)]
#[display("{_variant}")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub enum TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl Ord for TcbStatus {
    fn cmp(&self, other: &Self) -> Ordering {
        self.severity().cmp(&other.severity())
    }
}

impl PartialOrd for TcbStatus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TcbStatus {
    fn severity(&self) -> u8 {
        match self {
            Self::UpToDate => 0,
            Self::SWHardeningNeeded => 1,
            Self::ConfigurationNeeded => 2,
            Self::ConfigurationAndSWHardeningNeeded => 3,
            Self::OutOfDate => 4,
            Self::OutOfDateConfigurationNeeded => 5,
            Self::Revoked => 6,
        }
    }

    /// Converge platform TCB status with QE TCB status.
    ///
    /// Matches Intel QVL's `convergeTcbStatusWithQeTcbStatus()` from
    /// `TcbLevelCheck.cpp`. The QE status can only be UpToDate, OutOfDate,
    /// or Revoked (from QE Identity verification).
    fn converge_with_qe(self, qe: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        match (qe, self) {
            // QE is OutOfDate: escalate platform status
            (OutOfDate, ConfigurationNeeded | ConfigurationAndSWHardeningNeeded) => {
                OutOfDateConfigurationNeeded
            }
            _ => qe.max(self),
        }
    }
}

/// TCB status with advisory IDs
///
/// This is the result of matching a TCB level, used by both
/// platform TCB matching and QE Identity verification.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
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

    /// Merge platform TCB status with QE TCB status, following Intel QVL's
    /// `convergeTcbStatusWithQeTcbStatus()` logic. `self` is the platform
    /// status, `other` is the QE status.
    pub fn merge(self, other: &TcbStatusWithAdvisory) -> Self {
        let final_status = self.status.converge_with_qe(other.status);

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

    fn merge(platform: TcbStatus, qe: TcbStatus) -> TcbStatus {
        TcbStatusWithAdvisory::new(platform, vec![])
            .merge(&TcbStatusWithAdvisory::new(qe, vec![]))
            .status
    }

    // ── QE UpToDate: pass through platform status ──────────────────────
    #[test]
    fn qe_uptodate_passes_through() {
        assert_eq!(merge(UpToDate, UpToDate), UpToDate);
        assert_eq!(merge(SWHardeningNeeded, UpToDate), SWHardeningNeeded);
        assert_eq!(merge(ConfigurationNeeded, UpToDate), ConfigurationNeeded);
        assert_eq!(
            merge(ConfigurationAndSWHardeningNeeded, UpToDate),
            ConfigurationAndSWHardeningNeeded
        );
        assert_eq!(merge(OutOfDate, UpToDate), OutOfDate);
        assert_eq!(
            merge(OutOfDateConfigurationNeeded, UpToDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(merge(Revoked, UpToDate), Revoked);
    }

    // ── QE OutOfDate: escalate platform status ─────────────────────────
    #[test]
    fn qe_outofdate_escalates() {
        assert_eq!(merge(UpToDate, OutOfDate), OutOfDate);
        assert_eq!(merge(SWHardeningNeeded, OutOfDate), OutOfDate);
        assert_eq!(
            merge(ConfigurationNeeded, OutOfDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(
            merge(ConfigurationAndSWHardeningNeeded, OutOfDate),
            OutOfDateConfigurationNeeded
        );
    }

    #[test]
    fn qe_outofdate_already_worse_keeps() {
        assert_eq!(merge(OutOfDate, OutOfDate), OutOfDate);
        assert_eq!(
            merge(OutOfDateConfigurationNeeded, OutOfDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(merge(Revoked, OutOfDate), Revoked);
    }

    // ── QE Revoked: always revoked ─────────────────────────────────────
    #[test]
    fn qe_revoked_always_revoked() {
        assert_eq!(merge(UpToDate, Revoked), Revoked);
        assert_eq!(merge(SWHardeningNeeded, Revoked), Revoked);
        assert_eq!(merge(OutOfDate, Revoked), Revoked);
        assert_eq!(merge(ConfigurationNeeded, Revoked), Revoked);
    }

    // ── Advisory ID merging ────────────────────────────────────────────
    #[test]
    fn merge_combines_advisories() {
        let a = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let b = TcbStatusWithAdvisory::new(UpToDate, vec!["INTEL-SA-00002".into()]);
        let result = a.merge(&b);
        assert_eq!(
            result.advisory_ids,
            vec!["INTEL-SA-00001", "INTEL-SA-00002"]
        );
    }

    #[test]
    fn merge_deduplicates_advisories() {
        let a = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let b = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
    }
}
