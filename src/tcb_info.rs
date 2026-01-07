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
    pub tcb_status: String,
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

/// TCB status with advisory IDs
///
/// This is the result of matching a TCB level, used by both
/// platform TCB matching and QE Identity verification.
#[derive(Clone, Debug, Default)]
pub struct TcbStatus {
    pub status: String,
    pub advisory_ids: Vec<String>,
}

impl TcbStatus {
    /// Create a new TcbStatus with the given status and advisory IDs
    pub fn new(status: impl Into<String>, advisory_ids: Vec<String>) -> Self {
        Self {
            status: status.into(),
            advisory_ids,
        }
    }

    /// Create an unknown status (no matching TCB level found)
    pub fn unknown() -> Self {
        Self {
            status: "Unknown".into(),
            advisory_ids: vec![],
        }
    }

    /// Check if the TCB status is unknown
    pub fn is_unknown(&self) -> bool {
        self.status == "Unknown"
    }

    /// Merge two TCB statuses, taking the worse status and combining advisory IDs
    pub fn merge(self, other: &TcbStatus) -> Self {
        let final_status = if tcb_status_severity(&other.status) > tcb_status_severity(&self.status)
        {
            other.status.clone()
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

/// TCB status severity ordering (higher number = worse status)
fn tcb_status_severity(status: &str) -> u8 {
    match status {
        "UpToDate" => 0,
        "SWHardeningNeeded" => 1,
        "ConfigurationNeeded" => 2,
        "ConfigurationAndSWHardeningNeeded" => 3,
        "OutOfDate" => 4,
        "OutOfDateConfigurationNeeded" => 5,
        "Revoked" => 6,
        _ => 100, // Unknown status treated as worst
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcb_status_merge_both_up_to_date() {
        let a = TcbStatus::new("UpToDate", vec![]);
        let b = TcbStatus::new("UpToDate", vec![]);
        let result = a.merge(&b);
        assert_eq!(result.status, "UpToDate");
        assert!(result.advisory_ids.is_empty());
    }

    #[test]
    fn test_tcb_status_merge_takes_worse() {
        let a = TcbStatus::new("UpToDate", vec![]);
        let b = TcbStatus::new("OutOfDate", vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.status, "OutOfDate");
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
    }

    #[test]
    fn test_tcb_status_merge_combines_advisories() {
        let a = TcbStatus::new("OutOfDate", vec!["INTEL-SA-00001".into()]);
        let b = TcbStatus::new("SWHardeningNeeded", vec!["INTEL-SA-00002".into()]);
        let result = a.merge(&b);
        assert_eq!(result.status, "OutOfDate");
        assert_eq!(
            result.advisory_ids,
            vec!["INTEL-SA-00001", "INTEL-SA-00002"]
        );
    }

    #[test]
    fn test_tcb_status_merge_deduplicates_advisories() {
        let a = TcbStatus::new("OutOfDate", vec!["INTEL-SA-00001".into()]);
        let b = TcbStatus::new("OutOfDate", vec!["INTEL-SA-00001".into()]);
        let result = a.merge(&b);
        assert_eq!(result.advisory_ids, vec!["INTEL-SA-00001"]);
    }

    #[test]
    fn test_tcb_status_severity_ordering() {
        assert!(tcb_status_severity("UpToDate") < tcb_status_severity("SWHardeningNeeded"));
        assert!(
            tcb_status_severity("SWHardeningNeeded") < tcb_status_severity("ConfigurationNeeded")
        );
        assert!(
            tcb_status_severity("ConfigurationNeeded")
                < tcb_status_severity("ConfigurationAndSWHardeningNeeded")
        );
        assert!(
            tcb_status_severity("ConfigurationAndSWHardeningNeeded")
                < tcb_status_severity("OutOfDate")
        );
        assert!(
            tcb_status_severity("OutOfDate") < tcb_status_severity("OutOfDateConfigurationNeeded")
        );
        assert!(
            tcb_status_severity("OutOfDateConfigurationNeeded") < tcb_status_severity("Revoked")
        );
    }
}
