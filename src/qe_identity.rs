use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

/// QE Identity structure as returned by Intel's PCCS
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct QeIdentity {
    pub id: String,
    pub version: u8,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    /// Hex-encoded MISCSELECT value (4 bytes, 8 hex chars)
    pub miscselect: String,
    /// Hex-encoded MISCSELECT mask (4 bytes, 8 hex chars)
    #[serde(rename = "miscselectMask")]
    pub miscselect_mask: String,
    /// Hex-encoded ATTRIBUTES value (16 bytes, 32 hex chars)
    pub attributes: String,
    /// Hex-encoded ATTRIBUTES mask (16 bytes, 32 hex chars)
    #[serde(rename = "attributesMask")]
    pub attributes_mask: String,
    /// Hex-encoded MRSIGNER (32 bytes, 64 hex chars)
    pub mrsigner: String,
    /// ISV Product ID
    pub isvprodid: u16,
    /// TCB levels for the QE
    pub tcb_levels: Vec<QeTcbLevel>,
}

/// TCB level for QE Identity
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct QeTcbLevel {
    pub tcb: QeTcb,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs", default)]
    pub advisory_ids: Vec<String>,
}

/// TCB component for QE Identity
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct QeTcb {
    pub isvsvn: u16,
}
