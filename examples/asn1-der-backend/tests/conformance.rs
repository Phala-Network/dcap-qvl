//! Conformance harness: prove [`Asn1DerConfig`] is a drop-in equivalent
//! of [`DefaultConfig`] on the bundled corpus.
//!
//! Mirrors `dcap-qvl/tests/config_conformance.rs`. A downstream consumer
//! adopting the `asn1_der` backend should run something like this against
//! a representative cert/signature corpus from their own deployment.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use asn1_der_backend_example::{Asn1DerCertBackend, Asn1DerConfig, Asn1DerSigEncoder};
use dcap_qvl::config::{Config, EcdsaSigEncoder, ParsedCert, X509Codec};
use dcap_qvl::configs::DefaultConfig;
use dcap_qvl::quote::Quote;
use dcap_qvl::QuoteCollateralV3;
use scale::Decode;

const SGX_QUOTE: &[u8] = include_bytes!("../../../sample/sgx_quote");
const TDX_QUOTE: &[u8] = include_bytes!("../../../sample/tdx_quote");
const TDX_COLLATERAL: &[u8] = include_bytes!("../../../sample/tdx_quote_collateral.json");

/// DER-encoded body of the Intel SGX OID (1.2.840.113741.1.13.1) — same
/// constant used by the in-tree `dcap-qvl` test harness.
const SGX_EXTENSION_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01];

fn pck_leaf_certs() -> Vec<Vec<u8>> {
    [SGX_QUOTE, TDX_QUOTE]
        .into_iter()
        .map(|raw| {
            let q = Quote::decode(&mut &raw[..]).expect("decode quote");
            let pem = q.raw_cert_chain().expect("cert chain");
            pem::parse_many(pem)
                .expect("parse pem")
                .into_iter()
                .next()
                .expect("leaf cert")
                .into_contents()
        })
        .collect()
}

#[test]
fn parsed_cert_matches_default_on_sample_corpus() {
    for cert_der in pck_leaf_certs() {
        let custom = Asn1DerCertBackend::from_der(&cert_der).expect("custom from_der");
        let default =
            <DefaultConfig as Config>::X509::from_der(&cert_der).expect("default from_der");

        // The default `issuer_dn` returns RFC 4514 form; the asn1_der
        // backend returns a comma-joined sequence of printable RDN
        // values. They are not byte-identical, but they MUST agree on
        // the substrings `pck_ca_with` checks for.
        let custom_issuer = custom.issuer_dn().expect("custom issuer_dn");
        let default_issuer = default.issuer_dn().expect("default issuer_dn");
        // Same substrings `dcap_qvl::intel::pck_ca_with` looks for to
        // classify the issuing CA. Hardcoded here because the underlying
        // constants live in a private module.
        for needle in ["Processor", "Platform"] {
            assert_eq!(
                custom_issuer.contains(needle),
                default_issuer.contains(needle),
                "issuer DN substring match diverged for {needle:?}: \
                 custom={custom_issuer:?} default={default_issuer:?}",
            );
        }

        // The SGX extension OCTET STRING contents MUST be byte-identical
        // — downstream code parses these bytes with `find_extension` and
        // any divergence would break TCB matching.
        assert_eq!(
            custom.extension(SGX_EXTENSION_OID).expect("custom ext"),
            default.extension(SGX_EXTENSION_OID).expect("default ext"),
            "Intel SGX extension bytes diverged",
        );

        // Missing extensions: both must agree on `None`.
        let bogus_oid: &[u8] = &[0x2A, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(
            custom.extension(bogus_oid).expect("custom missing"),
            default.extension(bogus_oid).expect("default missing"),
            "missing-extension behavior diverged",
        );
    }
}

/// Edge cases for DER INTEGER encoding: high bit set (must prepend `0x00`),
/// leading zeros (must be stripped), all-zero (must encode as `02 01 00`),
/// and mixed values.
fn encode_test_vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
    fn trailing(b: u8) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        if let Some(last) = v.last_mut() {
            *last = b;
        }
        v
    }
    vec![
        (vec![0x80; 32], vec![0xFF; 32]),
        (trailing(0x42), vec![0x7F; 32]),
        (vec![0x55; 32], trailing(0x01)),
        (vec![0u8; 32], vec![0u8; 32]),
        ((0u8..32).collect(), (32u8..64).collect()),
    ]
}

#[test]
fn encode_ecdsa_sig_matches_default() {
    for (r, s) in encode_test_vectors() {
        let custom = Asn1DerSigEncoder::encode_ecdsa_sig(&r, &s).expect("custom encode");
        let default = <DefaultConfig as Config>::SigEncoder::encode_ecdsa_sig(&r, &s)
            .expect("default encode");
        assert_eq!(
            custom, default,
            "encode_ecdsa_sig diverged for r={:02x?} s={:02x?}",
            &r, &s,
        );
    }
}

#[test]
fn verify_with_asn1_der_config_matches_default() {
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(TDX_COLLATERAL).expect("collateral");
    let now: u64 = chrono::DateTime::parse_from_rfc3339(
        serde_json::from_str::<serde_json::Value>(&collateral.tcb_info)
            .expect("tcb json")
            .get("nextUpdate")
            .expect("nextUpdate field")
            .as_str()
            .expect("nextUpdate str"),
    )
    .expect("nextUpdate parse")
    .timestamp() as u64
        - 1;

    let default_result = dcap_qvl::verify::verify(TDX_QUOTE, &collateral, now);
    let custom_result =
        dcap_qvl::verify::verify_with::<Asn1DerConfig>(TDX_QUOTE, &collateral, now);

    assert_eq!(
        default_result.map_err(|e| e.to_string()),
        custom_result.map_err(|e| e.to_string()),
        "verify_with::<Asn1DerConfig> diverged from verify (DefaultConfig)",
    );
}
