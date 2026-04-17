#![allow(clippy::unwrap_used, clippy::expect_used)]

use dcap_qvl::{
    intel,
    quote::{Data, Quote, Report},
};
use scale::Decode as ScaleDecode;

#[cfg(feature = "default-x509")]
#[test]
fn tdx_quote_parsing_exports_cert_chain_and_extension() {
    let raw_quote = include_bytes!("../sample/tdx_quote");
    let quote = Quote::decode(&mut &raw_quote[..]).expect("quote parse");

    // Ensure report kind is TDX
    assert!(!quote.header.is_sgx());
    assert!(matches!(quote.report, Report::TD10(_) | Report::TD15(_)));

    // Cert chain extraction must work for teehouse's cert parsing needs.
    let pem = quote.raw_cert_chain().expect("cert chain pem bytes");
    assert!(!pem.is_empty());

    // Extension parsing from leaf PCK cert.
    let certs_der = intel::extract_cert_chain(&quote).expect("extract cert chain der");
    let leaf = certs_der.first().expect("leaf cert");
    let ext = intel::parse_pck_extension(leaf).expect("parse pck extension");

    // FMSPC from quote should match extension.
    assert_eq!(intel::quote_fmspc(&quote).unwrap(), ext.fmspc);
    assert!(!ext.ppid.is_empty());
}

#[cfg(feature = "default-x509")]
#[test]
fn sgx_quote_parsing_exports_cert_chain_and_extension() {
    let raw_quote = include_bytes!("../sample/sgx_quote");
    let quote = Quote::decode(&mut &raw_quote[..]).expect("quote parse");

    assert!(quote.header.is_sgx());
    assert!(matches!(quote.report, Report::SgxEnclave(_)));

    let pem = quote.raw_cert_chain().expect("cert chain pem bytes");
    assert!(!pem.is_empty());

    let certs_der = intel::extract_cert_chain(&quote).expect("extract cert chain der");
    let leaf = certs_der.first().expect("leaf cert");
    let ext = intel::parse_pck_extension(leaf).expect("parse pck extension");

    assert_eq!(intel::quote_fmspc(&quote).unwrap(), ext.fmspc);
    assert!(!ext.ppid.is_empty());
}

#[test]
fn data_decode_rejects_overlong_length() {
    use scale::Encode as ScaleEncode;

    // Length slightly above the 1 MiB bound used in Data::<u32>::decode.
    let len: u32 = 1_048_576 + 1;
    let encoded = len.encode();

    let result = Data::<u32>::decode(&mut &encoded[..]);
    assert!(result.is_err());
}
