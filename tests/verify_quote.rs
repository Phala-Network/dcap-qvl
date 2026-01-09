#![allow(clippy::unwrap_used, clippy::expect_used)]

use dcap_qvl::tcb_info::TcbStatus;
use dcap_qvl::{quote::Quote, verify::verify, QuoteCollateralV3};
use der::Decode as DerDecode;
use scale::Decode as ScaleDecode;
use serde_json::Value;
use x509_cert::crl::CertificateList;

fn now_from_collateral(collateral: &QuoteCollateralV3) -> u64 {
    fn parse_issue_next(json_str: &str) -> (u64, u64) {
        let value: Value = serde_json::from_str(json_str).expect("valid JSON");
        let issue = value["issueDate"].as_str().expect("issueDate string");
        let next = value["nextUpdate"].as_str().expect("nextUpdate string");
        let issue_ts = chrono::DateTime::parse_from_rfc3339(issue)
            .expect("issueDate parse")
            .timestamp() as u64;
        let next_ts = chrono::DateTime::parse_from_rfc3339(next)
            .expect("nextUpdate parse")
            .timestamp() as u64;
        (issue_ts, next_ts)
    }

    fn parse_crl_bounds(crl_der: &[u8]) -> (u64, Option<u64>) {
        let crl = CertificateList::from_der(crl_der).expect("CRL parse");
        let this_update = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next_update = crl
            .tbs_cert_list
            .next_update
            .map(|t| t.to_unix_duration().as_secs());
        (this_update, next_update)
    }

    let (tcb_issue, tcb_next) = parse_issue_next(&collateral.tcb_info);
    let (qe_issue, qe_next) = parse_issue_next(&collateral.qe_identity);
    let mut not_before = tcb_issue.max(qe_issue);
    let mut not_after = tcb_next.min(qe_next);

    for crl_der in [&collateral.root_ca_crl[..], &collateral.pck_crl[..]] {
        let (this_update, next_update) = parse_crl_bounds(crl_der);
        not_before = not_before.max(this_update);
        if let Some(next) = next_update {
            not_after = not_after.min(next);
        }
    }

    assert!(
        not_before <= not_after,
        "collateral validity window invalid"
    );
    if not_after > not_before {
        not_after - 1
    } else {
        not_after
    }
}

#[test]
fn could_parse_sgx_quote() {
    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let raw_quote_collateral = include_bytes!("../sample/sgx_quote_collateral.json");
    let quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    insta::assert_debug_snapshot!(quote);

    let quote_collateral: QuoteCollateralV3 =
        serde_json::from_slice(raw_quote_collateral).expect("decodable");
    let now = now_from_collateral(&quote_collateral);
    let tcb_status = verify(&raw_quote, &quote_collateral, now).expect("verify");

    assert_eq!(
        tcb_status.status,
        TcbStatus::ConfigurationAndSWHardeningNeeded
    );
    assert_eq!(
        tcb_status.advisory_ids,
        ["INTEL-SA-00289", "INTEL-SA-00615"]
    );
}

#[test]
fn could_parse_tdx_quote() {
    let raw_quote = include_bytes!("../sample/tdx_quote");
    let raw_quote_collateral = include_bytes!("../sample/tdx_quote_collateral.json");
    let quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    insta::assert_debug_snapshot!(quote);

    let quote_collateral: QuoteCollateralV3 = serde_json::from_slice(raw_quote_collateral).unwrap();
    let now = now_from_collateral(&quote_collateral);
    let tcb_status = verify(raw_quote, &quote_collateral, now).unwrap();
    assert_eq!(tcb_status.status, TcbStatus::UpToDate);
    assert!(tcb_status.advisory_ids.is_empty());
}
