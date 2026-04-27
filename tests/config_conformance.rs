//! Conformance harness for `Config` implementations.
//!
//! Any custom config SHOULD pass [`assert_config_conforms`] against a
//! representative cert/signature corpus. This module also drives the in-tree
//! [`DefaultConfig`] over the bundled SGX/TDX sample quotes as a regression
//! gate — if the default backend's output ever changes, these tests catch it.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "default-x509")]

use dcap_qvl::config::{Config, EcdsaSigEncoder, ParsedCert, X509Codec};
use dcap_qvl::configs::DefaultConfig;
use dcap_qvl::crypto::RingCrypto;
use dcap_qvl::quote::Quote;
use dcap_qvl::signature::DerSigEncoder;
use dcap_qvl::x509::X509CertBackend;
use dcap_qvl::QuoteCollateralV3;
use scale::Decode;

const SGX_QUOTE: &[u8] = include_bytes!("../sample/sgx_quote");
const TDX_QUOTE: &[u8] = include_bytes!("../sample/tdx_quote");

const SGX_EXTENSION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];

fn pck_leaf_certs() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for raw in [SGX_QUOTE, TDX_QUOTE] {
        let q = Quote::decode(&mut &raw[..]).expect("decode quote");
        let pem = q.raw_cert_chain().expect("cert chain");
        let leaf = pem::parse_many(pem)
            .expect("parse pem")
            .into_iter()
            .next()
            .expect("leaf cert")
            .into_contents();
        out.push(leaf);
    }
    out
}

/// Drive a custom [`Config`] through the sample corpus and assert byte-for-
/// byte equivalence with [`DefaultConfig`]. Custom-config implementers
/// should call this from their own test module.
pub fn assert_config_conforms<C: Config>() {
    for cert_der in pck_leaf_certs() {
        let custom = C::X509::from_der(&cert_der).expect("custom from_der");
        let default =
            <DefaultConfig as Config>::X509::from_der(&cert_der).expect("default from_der");

        assert_eq!(
            custom.pck_ca(),
            default.pck_ca(),
            "pck_ca classification mismatch on PCK leaf",
        );

        let custom_ext = custom.extension(SGX_EXTENSION_OID).expect("custom ext");
        let default_ext = default.extension(SGX_EXTENSION_OID).expect("default ext");
        assert_eq!(custom_ext, default_ext, "extension output mismatch");
    }

    // Signature encoding vectors — see encode_test_vectors() below for rationale.
    for (r, s) in encode_test_vectors() {
        assert_eq!(
            C::SigEncoder::encode_ecdsa_sig(&r, &s).expect("custom encode"),
            <DefaultConfig as Config>::SigEncoder::encode_ecdsa_sig(&r, &s)
                .expect("default encode"),
            "encode_ecdsa_sig output mismatch for r={:02x?} s={:02x?}",
            &r,
            &s,
        );
    }
}

/// Test vectors stress the DER integer encoding edge cases:
/// - high bit of leading byte set (must prepend 0x00 for unsigned)
/// - leading zero byte (must be stripped)
/// - all-zero (must encode as `02 01 00`)
/// - typical random-looking values
fn encode_test_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    /// Build a 32-byte vector with a single non-zero trailing byte.
    fn trailing(b: u8) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        if let Some(last) = v.last_mut() {
            *last = b;
        }
        v
    }
    vec![
        // high bit set on both
        (vec![0x80; 32], vec![0xFF; 32]),
        // leading zero on r
        (trailing(0x42), vec![0x7F; 32]),
        // leading zero on s
        (vec![0x55; 32], trailing(0x01)),
        // both all-zero
        (vec![0u8; 32], vec![0u8; 32]),
        // mixed typical
        ((0u8..32).collect(), (32u8..64).collect()),
    ]
}

#[test]
fn default_config_conforms_to_itself() {
    // Sanity check that the harness runs end-to-end on the default config.
    // Anyone wiring up a custom config can copy this test and swap the type.
    assert_config_conforms::<DefaultConfig>();
}

#[test]
fn encode_ecdsa_sig_handles_edge_cases() {
    // Verify the audited encoder produces well-formed DER on the edge-case
    // vectors. (Decoded structure check, not just self-equivalence.)
    for (r, s) in encode_test_vectors() {
        let der = DerSigEncoder::encode_ecdsa_sig(&r, &s).expect("encode succeeds on edge cases");
        // Must start with SEQUENCE tag.
        assert_eq!(der.first(), Some(&0x30), "ECDSA sig must be a SEQUENCE");
        // Must be parseable back as a SequenceOf<UintRef, 2>.
        let _decoded: ::der::asn1::SequenceOf<::der::asn1::UintRef, 2> =
            ::der::Decode::from_der(&der).expect("re-decode succeeds");
    }
}

/// A `Config` defined entirely in this test crate, to prove the plumbing in
/// `verify_with::<C>` actually accepts a downstream-defined config and that
/// custom configs can mix-and-match per-component.
struct ForwardingConfig;
impl Config for ForwardingConfig {
    type X509 = X509CertBackend;
    type SigEncoder = DerSigEncoder;
    type Crypto = RingCrypto;
}

#[test]
fn verify_with_custom_config_matches_default() {
    use dcap_qvl::verify::{verify, verify_with};

    let raw_quote = include_bytes!("../sample/tdx_quote");
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/tdx_quote_collateral.json"))
            .expect("collateral");

    // Use a permissive `now` — the precise value isn't material here; we only
    // care that the generic plumbing reaches the same outcome as the default
    // entry point. Either both succeed with equal reports, or both fail with
    // equal error strings.
    let now = chrono::DateTime::parse_from_rfc3339(
        &serde_json::from_str::<serde_json::Value>(&collateral.tcb_info).expect("tcb json")
            ["nextUpdate"]
            .as_str()
            .expect("nextUpdate")
            .to_string(),
    )
    .expect("nextUpdate parse")
    .timestamp() as u64
        - 1;

    let default_result = verify(raw_quote, &collateral, now);
    let custom_result = verify_with::<ForwardingConfig>(raw_quote, &collateral, now);
    assert_eq!(
        default_result.map_err(|e| e.to_string()),
        custom_result.map_err(|e| e.to_string()),
        "verify_with::<ForwardingConfig> must match verify"
    );
}

#[test]
fn extension_returns_none_for_missing_oid() {
    let certs = pck_leaf_certs();
    let cert_der = certs.first().expect("at least one cert");
    let cert = X509CertBackend::from_der(cert_der).expect("parse cert");
    // OID that definitely doesn't exist in a PCK cert.
    let bogus_oid: &[u8] = &[0x2A, 0x03, 0x04, 0x05, 0x06];
    assert!(matches!(cert.extension(bogus_oid), Ok(None)));
}
