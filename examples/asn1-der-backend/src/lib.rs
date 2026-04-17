//! Downstream `Config` example: smaller-footprint X.509 / DER backend
//! built on `asn1_der`.
//!
//! This crate is **not part of the audited `dcap-qvl` codebase.** It is a
//! reference implementation showing how a downstream consumer can swap the
//! pluggable components defined in [`dcap_qvl::config`] without forking
//! `dcap-qvl`.
//!
//! ## Goal
//!
//! `dcap-qvl`'s default backends ([`dcap_qvl::x509::X509CertBackend`] and
//! [`dcap_qvl::signature::DerSigEncoder`]) pull in `x509-cert` + `der`
//! (~37 KiB on `wasm32-unknown-unknown` with `lto="fat"` + `wasm-opt -O`).
//! For binary-size-sensitive deployments — WASM smart contracts being the
//! motivating case — that overhead is significant.
//!
//! [`Asn1DerCertBackend`] and [`Asn1DerSigEncoder`] reimplement the same
//! surface using the `asn1_der` crate, which is already a transitive
//! dependency of `dcap-qvl`. Once `dcap-qvl` makes `der` / `x509-cert`
//! optional behind a feature flag (follow-up to PR #144), a downstream
//! consumer can drop the audited backends entirely and ship only this
//! `asn1_der`-based path:
//!
//! ```ignore
//! use asn1_der_backend_example::Asn1DerConfig;
//! let report = dcap_qvl::verify::verify_with::<Asn1DerConfig>(
//!     &raw_quote,
//!     &collateral,
//!     now_secs,
//! )?;
//! ```
//!
//! ## Conformance
//!
//! Custom backends are the implementer's responsibility (see
//! `dcap_qvl::config` module docs). This crate's `tests/conformance.rs`
//! exercises [`Asn1DerConfig`] against the bundled SGX/TDX sample quotes
//! and asserts byte-for-byte equivalence with [`dcap_qvl::configs::DefaultConfig`]
//! on cert parsing, issuer DN extraction, and ECDSA signature DER encoding.
//! Any downstream consumer adopting this code SHOULD run the same test
//! suite (or stronger) on a corpus that matches their production traffic.

#![deny(clippy::unwrap_used, clippy::expect_used)]

extern crate alloc;

mod sig;
mod x509;

pub use sig::Asn1DerSigEncoder;
pub use x509::{Asn1DerCertBackend, Asn1DerParsedCert};

use dcap_qvl::config::Config;

/// `Config` bundle pairing the `asn1_der`-based backends with `dcap-qvl`'s
/// `ring` crypto provider. Drop-in replacement for
/// [`dcap_qvl::configs::RingConfig`].
///
/// To use a different crypto provider, write your own `Config` impl that
/// names [`Asn1DerCertBackend`] and [`Asn1DerSigEncoder`] for the X.509 and
/// signature components.
pub struct Asn1DerConfig;

impl Config for Asn1DerConfig {
    type X509 = Asn1DerCertBackend;
    type SigEncoder = Asn1DerSigEncoder;
    type Crypto = dcap_qvl::crypto::RingCrypto;
}
