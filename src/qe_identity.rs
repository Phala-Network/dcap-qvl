use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode_upper(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;

        // Reject non-ASCII before any further processing
        if !s.is_ascii() {
            return Err(D::Error::custom("hex string must be ASCII"));
        }

        // Fast reject: exact length before decode
        if s.len() != N * 2 {
            return Err(D::Error::custom(format!(
                "expected {} hex chars, got {}",
                N * 2,
                s.len()
            )));
        }

        // hex::decode is case-insensitive — no extra handling needed
        hex::decode(s)
            .map_err(|e| D::Error::custom(format!("invalid hex: {e}")))?
            .try_into()
            .map_err(|_| D::Error::custom("hex decode length mismatch"))
    }
}

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

use crate::tcb_info::TcbStatus;

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
    #[serde(with = "hex_array")]
    pub miscselect: [u8; 4],
    #[serde(rename = "miscselectMask")]
    #[serde(with = "hex_array")]
    pub miscselect_mask: [u8; 4],
    #[serde(with = "hex_array")]
    pub attributes: [u8; 16],
    #[serde(rename = "attributesMask")]
    #[serde(with = "hex_array")]
    pub attributes_mask: [u8; 16],
    #[serde(with = "hex_array")]
    pub mrsigner: [u8; 32],
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
    pub tcb_status: TcbStatus,
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
