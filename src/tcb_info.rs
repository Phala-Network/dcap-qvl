use alloc::string::String;
use alloc::vec::Vec;
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
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

    pub fn is_valid(&self) -> bool {
        match self {
            Self::UpToDate => true,
            Self::SWHardeningNeeded => true,
            Self::ConfigurationNeeded => true,
            Self::ConfigurationAndSWHardeningNeeded => true,
            Self::OutOfDate => true,
            Self::OutOfDateConfigurationNeeded => true,
            Self::Revoked => false,
        }
    }
}

/// TCB status with advisory IDs
///
/// This is the result of matching a TCB level, used by both
/// platform TCB matching and QE Identity verification.
#[derive(Clone, Debug)]
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

    /// Merge two TCB statuses, taking the worse status and combining advisory IDs
    pub fn merge(self, other: &TcbStatusWithAdvisory) -> Self {
        let final_status = if other.status.severity() > self.status.severity() {
            other.status
        } else {
            self.status
        };

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
    fn test_tcb_status_merge_takes_worse() {
        let a = TcbStatusWithAdvisory::new(UpToDate, vec![]);
        let b = TcbStatusWithAdvisory::new(OutOfDate, vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.status, OutOfDate);
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
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
}
