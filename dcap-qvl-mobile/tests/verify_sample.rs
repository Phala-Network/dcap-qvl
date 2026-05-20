//! Sanity tests for the mobile binding surface. Mirrors the offline
//! verification covered by `tests/verify_quote.rs`, but goes through the
//! UniFFI-exported functions instead of the core API.

use dcap_qvl_mobile::{parse_quote, verify, QuoteCollateral, QuoteKind, TcbStatus};
use serde_json::Value;

fn load_collateral(json: &[u8]) -> QuoteCollateral {
    let parsed: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_slice(json).expect("collateral JSON parses");
    parsed.into()
}

fn timestamp_within_collateral(json: &[u8]) -> u64 {
    let parsed: dcap_qvl::QuoteCollateralV3 =
        serde_json::from_slice(json).expect("collateral JSON parses");
    let pick = |s: &str| {
        let v: Value = serde_json::from_str(s).expect("JSON");
        let issue = v["issueDate"].as_str().expect("issueDate");
        let next = v["nextUpdate"].as_str().expect("nextUpdate");
        (
            chrono::DateTime::parse_from_rfc3339(issue).unwrap().timestamp() as u64,
            chrono::DateTime::parse_from_rfc3339(next).unwrap().timestamp() as u64,
        )
    };
    let (ti, tn) = pick(&parsed.tcb_info);
    let (qi, qn) = pick(&parsed.qe_identity);
    let not_before = ti.max(qi);
    let not_after = tn.min(qn);
    not_before + (not_after - not_before) / 2
}

#[test]
fn parse_sgx_sample() {
    let raw = include_bytes!("../../sample/sgx_quote").to_vec();
    let q = parse_quote(raw).expect("parse_quote");
    assert!(matches!(q.kind, QuoteKind::Sgx));
    assert_eq!(q.header.version, 3);
}

#[test]
fn parse_tdx_sample() {
    let raw = include_bytes!("../../sample/tdx_quote").to_vec();
    let q = parse_quote(raw).expect("parse_quote");
    assert!(matches!(q.kind, QuoteKind::Tdx));
}

#[test]
fn verify_sgx_sample() {
    let raw = include_bytes!("../../sample/sgx_quote").to_vec();
    let coll_json = include_bytes!("../../sample/sgx_quote_collateral.json");
    let now = timestamp_within_collateral(coll_json);
    let report = verify(raw, load_collateral(coll_json), now).expect("verify");
    assert_eq!(report.status, "ConfigurationAndSWHardeningNeeded");
    assert!(matches!(
        report.platform_status.status,
        TcbStatus::ConfigurationAndSwHardeningNeeded
    ));
}

#[test]
fn verify_tdx_sample() {
    let raw = include_bytes!("../../sample/tdx_quote").to_vec();
    let coll_json = include_bytes!("../../sample/tdx_quote_collateral.json");
    let now = timestamp_within_collateral(coll_json);
    let report = verify(raw, load_collateral(coll_json), now).expect("verify");
    assert!(!report.status.is_empty());
}
