#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use dcap_qvl::{
    intel,
    quote::{Data, Quote, Report, TDReport15, TDReport15Ex},
};
use scale::{Decode as ScaleDecode, Encode};

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

/// Builds a quote v5 with a TD report 1.5ex body (body type 4) from the sample TDX quote: the
/// sample's TD 1.0 report, zeroed TD 1.5 fields, distinctive 1.5ex fields, and its own auth data.
/// No real 1.5ex quote is public yet (upstream KVM does not enable TD ID reporting), so this
/// checks the layout against Intel's sgx_quote_5.h offsets, not a signature.
fn synthetic_td15_ex_quote() -> (Vec<u8>, TDReport15Ex) {
    let raw_quote = include_bytes!("../sample/tdx_quote");
    let mut quote = Quote::decode(&mut &raw_quote[..]).expect("quote parse");
    let td10 = *quote.report.as_td10().expect("sample is a TDX quote");
    let mut td_id = [0u8; 32];
    for (i, b) in td_id.iter_mut().enumerate() {
        *b = 0xA0 ^ i as u8;
    }
    let report = TDReport15Ex {
        base: TDReport15 {
            base: td10,
            tee_tcb_svn2: [0; 16],
            mr_service_td: [0; 48],
        },
        vmid: 2,
        td_id,
        dev_info: [0xD1; 48],
        init_service_td_hash: [0x11; 48],
        init_service_td_attributes: [0x12; 8],
        init_cpu_svn: [0x13; 16],
        init_tee_tcb_svn: [0x14; 16],
        init_tee_fmspc: [0x15; 12],
        cur_service_td_hash: [0x16; 48],
        cur_service_td_attributes: [0x17; 8],
    };
    quote.header.version = 5;
    quote.report = Report::TD15Ex(report);
    (quote.encode(), report)
}

#[test]
fn td15_ex_body_type_4_round_trips_with_intel_offsets() {
    let (bytes, report) = synthetic_td15_ex_quote();

    // Quote v5 framing per sgx_quote_5.h: body type at 48, body size at 50, body at 54.
    assert_eq!(u16::from_le_bytes([bytes[48], bytes[49]]), 4);
    assert_eq!(u32::from_le_bytes(bytes[50..54].try_into().unwrap()), 885);
    // sgx_report2_body_v1_5_ex_t: vmid at 648, td_id at 649..681, devinfo at 681.
    assert_eq!(bytes[54 + 648], 2);
    assert_eq!(&bytes[54 + 649..54 + 681], &report.td_id[..]);
    assert_eq!(&bytes[54 + 681..54 + 729], &[0xD1; 48][..]);
    // The last field, curr_server_td_attr, ends the 885-byte body.
    assert_eq!(&bytes[54 + 877..54 + 885], &[0x17; 8][..]);

    let parsed = Quote::parse(&bytes).expect("a body type 4 quote must parse");
    assert_eq!(parsed.report, Report::TD15Ex(report));
    assert_eq!(parsed.report.as_td15_ex().unwrap().td_id, report.td_id);
    assert_eq!(parsed.report.as_td15(), Some(&report.base));
    assert_eq!(parsed.report.as_td10(), Some(&report.base.base));
    assert_eq!(parsed.signed_length(), 48 + 6 + 885);
    assert_eq!(parsed.encode(), bytes);
}
