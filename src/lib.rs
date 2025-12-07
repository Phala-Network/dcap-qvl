//! # dcap-qvl
//!
//! This crate implements the quote verification logic for DCAP (Data Center Attestation Primitives) in pure Rust. It supports both SGX (Software Guard Extensions) and TDX (Trust Domain Extensions) quotes.
//!
//! # Features
//! - Verify SGX and TDX quotes
//! - Get collateral from PCCS
//! - Extract information from quotes
//!
//! # Usage
//! Add the following dependency to your `Cargo.toml` file to use this crate:
//! ```toml
//! [dependencies]
//! dcap-qvl = "0.1.0"
//! ```
//!
//! # Example
//!
//! ```no_run
//! use dcap_qvl::collateral::get_collateral;
//! use dcap_qvl::verify::verify;
//! use dcap_qvl::PHALA_PCCS_URL;
//!
//! #[tokio::main]
//! async fn main() {
//!     let quote = std::fs::read("quote").expect("quote file not found");
//!
//!     // Use default Phala PCCS, or override with custom URL
//!     let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
//!     let collateral = get_collateral(&pccs_url, &quote).await.expect("failed to get collateral");
//!
//!     let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
//!     let report = verify(&quote, &collateral, now).expect("failed to verify quote");
//!     println!("{:?}", report);
//! }
//! ```

#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

#[macro_use]
extern crate alloc;

use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct QuoteCollateralV3 {
    pub pck_crl_issuer_chain: String,
    #[serde(with = "serde_bytes")]
    pub root_ca_crl: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    #[serde(with = "serde_bytes")]
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    #[serde(with = "serde_bytes")]
    pub qe_identity_signature: Vec<u8>,
}

#[cfg(feature = "report")]
pub mod collateral;

#[cfg(feature = "report")]
pub use collateral::PHALA_PCCS_URL;

pub mod oids;

mod constants;
pub mod intel;
mod tcb_info;
mod utils;

pub mod quote;
pub mod verify;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn _dcap_qvl(m: &Bound<'_, PyModule>) -> PyResult<()> {
    python::register_module(m)
}
