#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "danger-allow-tcb-override")]
mod tests {
    use dcap_qvl::{
        tcb_info::{Tcb, TcbComponents, TcbInfo, TcbLevel, TcbStatus},
        verify::VerifiedReport,
        QuoteCollateralV3,
    };
    use der::Decode as DerDecode;
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use x509_cert::crl::CertificateList;

    fn verify(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
    ) -> anyhow::Result<VerifiedReport> {
        use dcap_qvl::verify::{ring, rustcrypto};
        let ring_result = ring::verify(raw_quote, collateral, now_secs);
        let rustcrypto_result = rustcrypto::verify(raw_quote, collateral, now_secs);
        assert_eq!(
            ring_result.map_err(|e| e.to_string()),
            rustcrypto_result.map_err(|e| e.to_string())
        );
        ring::verify(raw_quote, collateral, now_secs)
    }

    fn verify_with_tcb_override<F>(
        raw_quote: &[u8],
        collateral: &QuoteCollateralV3,
        now_secs: u64,
        override_tcb_info: F,
    ) -> anyhow::Result<VerifiedReport>
    where
        F: FnOnce(TcbInfo) -> TcbInfo + Copy,
    {
        use dcap_qvl::verify::{ring, rustcrypto};
        let ring_result =
            ring::verify_with_tcb_override(raw_quote, collateral, now_secs, override_tcb_info);
        let rustcrypto_result = rustcrypto::verify_with_tcb_override(
            raw_quote,
            collateral,
            now_secs,
            override_tcb_info,
        );
        assert_eq!(
            ring_result.map_err(|e| e.to_string()),
            rustcrypto_result.map_err(|e| e.to_string())
        );
        ring::verify_with_tcb_override(raw_quote, collateral, now_secs, override_tcb_info)
    }

    fn force_out_of_date(mut tcb_info: TcbInfo) -> TcbInfo {
        for level in &mut tcb_info.tcb_levels {
            level.tcb_status = TcbStatus::OutOfDate;
        }
        tcb_info
    }

    fn force_up_to_date(mut tcb_info: TcbInfo) -> TcbInfo {
        for level in &mut tcb_info.tcb_levels {
            level.tcb_status = TcbStatus::UpToDate;
        }
        tcb_info
    }

    fn force_up_to_date_with_matching_level(mut tcb_info: TcbInfo) -> TcbInfo {
        let permissive_level = TcbLevel {
            tcb: Tcb {
                sgx_components: vec![TcbComponents { svn: 0 }; 16],
                tdx_components: vec![TcbComponents { svn: 0 }; 16],
                pce_svn: 0,
            },
            tcb_date: tcb_info.issue_date.clone(),
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: vec![],
        };
        tcb_info.tcb_levels.insert(0, permissive_level);
        force_up_to_date(tcb_info)
    }

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
    fn override_can_change_tcb_result_and_runs_once() {
        use dcap_qvl::verify::ring;

        let raw_quote = include_bytes!("../sample/tdx_quote");
        let raw_quote_collateral = include_bytes!("../sample/tdx_quote_collateral.json");
        let quote_collateral: QuoteCollateralV3 =
            serde_json::from_slice(raw_quote_collateral).unwrap();
        let now = now_from_collateral(&quote_collateral);

        let baseline = verify(raw_quote, &quote_collateral, now).expect("baseline verify");
        assert_eq!(baseline.status, "UpToDate");

        static OVERRIDE_CALLS: AtomicUsize = AtomicUsize::new(0);
        OVERRIDE_CALLS.store(0, Ordering::SeqCst);
        let ring_overridden =
            ring::verify_with_tcb_override(raw_quote, &quote_collateral, now, |mut tcb_info| {
                OVERRIDE_CALLS.fetch_add(1, Ordering::SeqCst);
                for level in &mut tcb_info.tcb_levels {
                    level.tcb_status = TcbStatus::OutOfDate;
                }
                tcb_info
            })
            .expect("verify with override");
        assert_eq!(OVERRIDE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(ring_overridden.status, "OutOfDate");

        let parity_overridden =
            verify_with_tcb_override(raw_quote, &quote_collateral, now, force_out_of_date)
                .expect("verify parity with override");
        assert_eq!(parity_overridden.status, "OutOfDate");
    }

    #[test]
    fn outdated_fixture_with_override_matches_expected_status() {
        let raw_quote = include_bytes!("../sample/tdx_quote_outdated");
        let raw_quote_collateral = include_bytes!("../sample/tdx_quote_outdated_collateral.json");
        let quote_collateral: QuoteCollateralV3 =
            serde_json::from_slice(raw_quote_collateral).unwrap();
        let now = now_from_collateral(&quote_collateral);

        let overridden = verify_with_tcb_override(
            raw_quote,
            &quote_collateral,
            now,
            force_up_to_date_with_matching_level,
        )
        .expect("verify with override");
        assert_eq!(overridden.status, "UpToDate");
    }
}
