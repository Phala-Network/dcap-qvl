#![allow(clippy::unwrap_used, clippy::expect_used)]

use dcap_qvl::{quote::Quote, verify::VerifiedReport, QuoteCollateralV3};
use der::Decode as DerDecode;
use scale::Decode as ScaleDecode;
use serde_json::Value;
use x509_cert::crl::CertificateList;

pub fn verify(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
) -> anyhow::Result<VerifiedReport> {
    use dcap_qvl::verify::{ring, rustcrypto, QuoteVerifier};

    let ring_verifier = QuoteVerifier::new_prod(ring::backend());
    let rustcrypto_verifier = QuoteVerifier::new_prod(rustcrypto::backend());

    let ring_result = ring_verifier
        .verify(raw_quote, collateral.clone(), now_secs)
        .map(|s| s.into_report_unchecked());
    let rustcrypto_result = rustcrypto_verifier
        .verify(raw_quote, collateral.clone(), now_secs)
        .map(|s| s.into_report_unchecked());

    assert_eq!(
        ring_result.map_err(|e| e.to_string()),
        rustcrypto_result.map_err(|e| e.to_string())
    );
    ring_verifier
        .verify(raw_quote, collateral.clone(), now_secs)
        .map(|s| s.into_report_unchecked())
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
fn could_parse_sgx_quote() {
    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let raw_quote_collateral = include_bytes!("../sample/sgx_quote_collateral.json");
    let quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    insta::assert_debug_snapshot!(quote);

    let quote_collateral: QuoteCollateralV3 =
        serde_json::from_slice(raw_quote_collateral).expect("decodable");
    let now = now_from_collateral(&quote_collateral);
    let tcb_status = verify(&raw_quote, &quote_collateral, now).expect("verify");

    assert_eq!(tcb_status.status, "ConfigurationAndSWHardeningNeeded");
    assert_eq!(
        tcb_status.advisory_ids,
        ["INTEL-SA-00289", "INTEL-SA-00615"]
    );
}

/// Cross-validate all SupplementalData fields against independently computed values.
#[test]
fn sgx_supplemental_data_cross_validation() {
    use dcap_qvl::verify::{ring, QuoteVerifier};
    use dcap_qvl::PckCertFlag;

    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/sgx_quote_collateral.json")).unwrap();
    let now = now_from_collateral(&collateral);

    let verifier = QuoteVerifier::new_prod(ring::backend());
    let result = verifier.verify(&raw_quote, collateral.clone(), now).unwrap();
    let s = &result.supplemental().unwrap();

    // Parse quote for later use
    let parsed_quote = Quote::decode(&mut &raw_quote[..]).unwrap();

    // ── TCB status ──────────────────────────────────────────────────────
    assert_eq!(
        s.tcb.status.to_string(),
        "ConfigurationAndSWHardeningNeeded"
    );
    assert_eq!(s.tcb.advisory_ids, ["INTEL-SA-00289", "INTEL-SA-00615"]);

    // earliest_expiration is computed lazily in supplemental()
    assert!(s.tcb.earliest_expiration > 0);

    // ── tcb_date_tag ────────────────────────────────────────────────────
    let expected_tcb_date = chrono::DateTime::parse_from_rfc3339(&s.platform.tcb_level.tcb_date)
        .unwrap()
        .timestamp() as u64;
    assert_eq!(s.platform.tcb_date_tag, expected_tcb_date);

    // ── CRL numbers ─────────────────────────────────────────────────────
    fn extract_crl_num(crl_der: &[u8]) -> u32 {
        let crl = CertificateList::from_der(crl_der).unwrap();
        if let Some(exts) = &crl.tbs_cert_list.crl_extensions {
            for ext in exts.iter() {
                if ext.extn_id.to_string() == "2.5.29.20" {
                    let num =
                        <der::asn1::UintRef as DerDecode>::from_der(ext.extn_value.as_bytes())
                            .unwrap();
                    let bytes = num.as_bytes();
                    let mut val: u32 = 0;
                    for &b in bytes {
                        val = (val << 8) | u32::from(b);
                    }
                    return val;
                }
            }
        }
        0
    }
    assert_eq!(s.platform.root_ca_crl_num, extract_crl_num(&collateral.root_ca_crl));
    assert_eq!(s.platform.pck_crl_num, extract_crl_num(&collateral.pck_crl));

    // ── tcb_eval_data_number ────────────────────────────────────────────
    let tcb_info_parsed: dcap_qvl::TcbInfo = serde_json::from_str(&collateral.tcb_info).unwrap();
    let qe_id_parsed: dcap_qvl::QeIdentity = serde_json::from_str(&collateral.qe_identity).unwrap();
    let expected_eval_num = tcb_info_parsed
        .tcb_evaluation_data_number
        .min(qe_id_parsed.tcb_evaluation_data_number);
    assert_eq!(s.tcb.eval_data_number, expected_eval_num);

    // ── root_key_id ─────────────────────────────────────────────────────
    let root_ca_der = include_bytes!("../src/TrustedRootCA.der");
    let root_cert: x509_cert::Certificate = DerDecode::from_der(root_ca_der).unwrap();
    let raw_pub_key = root_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let expected_root_key_id: [u8; 48] = {
        use sha2::Digest;
        sha2::Sha384::digest(raw_pub_key).into()
    };
    assert_eq!(s.platform.root_key_id, expected_root_key_id);

    // ── PCK certificate fields ──────────────────────────────────────────
    let pck_chain_der = dcap_qvl::intel::extract_cert_chain(&parsed_quote).unwrap();
    let pck_ext = dcap_qvl::intel::parse_pck_extension(&pck_chain_der[0]).unwrap();

    assert_eq!(s.platform.pck.cpu_svn, pck_ext.cpu_svn);
    assert_eq!(s.platform.pck.pce_svn, pck_ext.pce_svn);
    assert_eq!(s.platform.pck.fmspc, pck_ext.fmspc);
    assert_eq!(s.platform.pck.ppid, pck_ext.ppid);
    assert_eq!(s.platform.pck.sgx_type, pck_ext.sgx_type as u8);

    let expected_pce_id = match pck_ext.pce_id.len() {
        2 => u16::from_be_bytes([pck_ext.pce_id[0], pck_ext.pce_id[1]]),
        1 => u16::from(pck_ext.pce_id[0]),
        _ => 0,
    };
    assert_eq!(s.platform.pck.pce_id, expected_pce_id);

    // ── TEE type ────────────────────────────────────────────────────────
    assert_eq!(s.tee_type, 0x00000000); // SGX

    // ── Platform instance (Processor CA → should be Undefined) ──────────
    assert_eq!(s.platform.pck.dynamic_platform, PckCertFlag::Undefined);
    assert_eq!(s.platform.pck.cached_keys, PckCertFlag::Undefined);
    assert_eq!(s.platform.pck.smt_enabled, PckCertFlag::Undefined);

    // ── TCB levels ──────────────────────────────────────────────────────
    assert!(!s.platform.tcb_level.tcb_date.is_empty());
    assert!(!s.qe.tcb_level.tcb_date.is_empty());

    // Verify ring and rustcrypto produce identical supplemental data
    let rustcrypto_verifier = QuoteVerifier::new_prod(dcap_qvl::verify::rustcrypto::backend());
    let rc_result = rustcrypto_verifier
        .verify(&raw_quote, collateral.clone(), now)
        .unwrap();
    let rc = &rc_result.supplemental().unwrap();
    assert_eq!(s.tcb.status, rc.tcb.status);
    assert_eq!(s.tcb.advisory_ids, rc.tcb.advisory_ids);
    assert_eq!(s.tcb.earliest_expiration, rc.tcb.earliest_expiration);
    assert_eq!(s.platform.tcb_date_tag, rc.platform.tcb_date_tag);
    assert_eq!(s.platform.pck_crl_num, rc.platform.pck_crl_num);
    assert_eq!(s.platform.root_ca_crl_num, rc.platform.root_ca_crl_num);
    assert_eq!(s.tcb.eval_data_number, rc.tcb.eval_data_number);
    assert_eq!(s.platform.root_key_id, rc.platform.root_key_id);
    assert_eq!(s.platform.pck.ppid, rc.platform.pck.ppid);
    assert_eq!(s.platform.pck.cpu_svn, rc.platform.pck.cpu_svn);
    assert_eq!(s.platform.pck.pce_svn, rc.platform.pck.pce_svn);
    assert_eq!(s.platform.pck.pce_id, rc.platform.pck.pce_id);
    assert_eq!(s.platform.pck.fmspc, rc.platform.pck.fmspc);
    assert_eq!(s.tee_type, rc.tee_type);
    assert_eq!(s.platform.pck.sgx_type, rc.platform.pck.sgx_type);
    assert_eq!(s.platform.pck.platform_instance_id, rc.platform.pck.platform_instance_id);
    assert_eq!(s.platform.pck.dynamic_platform, rc.platform.pck.dynamic_platform);
    assert_eq!(s.platform.pck.cached_keys, rc.platform.pck.cached_keys);
    assert_eq!(s.platform.pck.smt_enabled, rc.platform.pck.smt_enabled);
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
    assert_eq!(tcb_status.status, "UpToDate");
    assert!(tcb_status.advisory_ids.is_empty());
}

/// Print key SupplementalData fields for both SGX and TDX quotes.
#[test]
fn print_supplemental_data_comparison() {
    use dcap_qvl::verify::{ring, QuoteVerifier};

    fn ts_to_utc(ts: u64) -> String {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| format!("{ts}"))
    }

    let verifier = QuoteVerifier::new_prod(ring::backend());

    // ═══════════════════════════════════════════════════════════════════
    // SGX Quote
    // ═══════════════════════════════════════════════════════════════════
    println!("\n{:=<80}", "");
    println!("SGX Quote — SupplementalData");
    println!("{:=<80}", "");

    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/sgx_quote_collateral.json")).unwrap();
    let now = now_from_collateral(&collateral);

    let result = verifier.verify(&raw_quote, collateral.clone(), now).unwrap();
    let s = &result.supplemental().unwrap();

    println!("{:<40} {:?}", "tcb.status", s.tcb.status);
    println!("{:<40} {:?}", "tcb.advisory_ids", s.tcb.advisory_ids);
    println!("{:<40} {} ({})", "tcb.earliest_expiration", s.tcb.earliest_expiration, ts_to_utc(s.tcb.earliest_expiration));
    println!("{:<40} {}", "tcb.eval_data_number", s.tcb.eval_data_number);
    println!("{:<40} {} ({})", "platform.tcb_date_tag", s.platform.tcb_date_tag, ts_to_utc(s.platform.tcb_date_tag));
    println!("{:<40} {}", "platform.pck_crl_num", s.platform.pck_crl_num);
    println!("{:<40} {}", "platform.root_ca_crl_num", s.platform.root_ca_crl_num);
    println!("{:<40} {}...", "platform.root_key_id", hex::encode(&s.platform.root_key_id[..24]));
    println!("{:<40} {}", "platform.pck.fmspc", hex::encode(s.platform.pck.fmspc));
    println!("{:<40} {}", "platform.pck.sgx_type", s.platform.pck.sgx_type);
    println!("{:<40} {:?}", "platform.pck.dynamic_platform", s.platform.pck.dynamic_platform);
    println!("{:<40} {:?}", "platform.pck.cached_keys", s.platform.pck.cached_keys);
    println!("{:<40} {:?}", "platform.pck.smt_enabled", s.platform.pck.smt_enabled);
    println!("{:<40} 0x{:08X}", "tee_type", s.tee_type);
    println!("{:<40} {:?}", "platform.tcb_level.tcb_status", s.platform.tcb_level.tcb_status);
    println!("{:<40} {:?}", "qe.tcb_level.tcb_status", s.qe.tcb_level.tcb_status);

    // ═══════════════════════════════════════════════════════════════════
    // TDX Quote
    // ═══════════════════════════════════════════════════════════════════
    println!("\n{:=<80}", "");
    println!("TDX Quote — SupplementalData");
    println!("{:=<80}", "");

    let raw_quote_tdx = include_bytes!("../sample/tdx_quote");
    let collateral_tdx: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/tdx_quote_collateral.json")).unwrap();
    let now_tdx = now_from_collateral(&collateral_tdx);

    let result_tdx = verifier.verify(raw_quote_tdx, collateral_tdx.clone(), now_tdx).unwrap();
    let t = &result_tdx.supplemental().unwrap();

    println!("{:<40} {:?}", "tcb.status", t.tcb.status);
    println!("{:<40} {:?}", "tcb.advisory_ids", t.tcb.advisory_ids);
    println!("{:<40} {} ({})", "tcb.earliest_expiration", t.tcb.earliest_expiration, ts_to_utc(t.tcb.earliest_expiration));
    println!("{:<40} {}", "tcb.eval_data_number", t.tcb.eval_data_number);
    println!("{:<40} {} ({})", "platform.tcb_date_tag", t.platform.tcb_date_tag, ts_to_utc(t.platform.tcb_date_tag));
    println!("{:<40} {}", "platform.pck_crl_num", t.platform.pck_crl_num);
    println!("{:<40} {}", "platform.root_ca_crl_num", t.platform.root_ca_crl_num);
    println!("{:<40} {}...", "platform.root_key_id", hex::encode(&t.platform.root_key_id[..24]));
    println!("{:<40} {}", "platform.pck.fmspc", hex::encode(t.platform.pck.fmspc));
    println!("{:<40} {}", "platform.pck.sgx_type", t.platform.pck.sgx_type);
    println!("{:<40} {:?}", "platform.pck.dynamic_platform", t.platform.pck.dynamic_platform);
    println!("{:<40} {:?}", "platform.pck.cached_keys", t.platform.pck.cached_keys);
    println!("{:<40} {:?}", "platform.pck.smt_enabled", t.platform.pck.smt_enabled);
    println!("{:<40} 0x{:08X}", "tee_type", t.tee_type);
    println!("{:<40} {:?}", "platform.tcb_level.tcb_status", t.platform.tcb_level.tcb_status);
    println!("{:<40} {:?}", "qe.tcb_level.tcb_status", t.qe.tcb_level.tcb_status);
}

/// Cross-validate TDX supplemental data fields.
#[test]
fn tdx_supplemental_data_cross_validation() {
    use dcap_qvl::verify::{ring, QuoteVerifier};

    let raw_quote = include_bytes!("../sample/tdx_quote");
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/tdx_quote_collateral.json")).unwrap();
    let now = now_from_collateral(&collateral);

    let verifier = QuoteVerifier::new_prod(ring::backend());
    let result = verifier.verify(raw_quote, collateral.clone(), now).unwrap();
    let s = &result.supplemental().unwrap();

    // TDX quote should have tee_type = 0x81
    assert_eq!(s.tee_type, 0x00000081);
    assert_eq!(s.tcb.status.to_string(), "UpToDate");
    assert!(s.tcb.advisory_ids.is_empty());

    // Fields should be populated (computed lazily in supplemental())
    assert!(s.tcb.earliest_expiration > 0);
    assert!(s.platform.tcb_date_tag > 0);

    // root_key_id should match SHA-384 of Intel root CA raw public key bytes
    let root_ca_der = include_bytes!("../src/TrustedRootCA.der");
    let root_cert: x509_cert::Certificate = DerDecode::from_der(root_ca_der).unwrap();
    let raw_pub_key = root_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let expected_root_key_id: [u8; 48] = {
        use sha2::Digest;
        sha2::Sha384::digest(raw_pub_key).into()
    };
    assert_eq!(s.platform.root_key_id, expected_root_key_id);

    // Verify ring == rustcrypto for all fields
    let rc_verifier = QuoteVerifier::new_prod(dcap_qvl::verify::rustcrypto::backend());
    let rc_result = rc_verifier.verify(raw_quote, collateral.clone(), now).unwrap();
    let rc = &rc_result.supplemental().unwrap();
    assert_eq!(s.tee_type, rc.tee_type);
    assert_eq!(s.tcb.status, rc.tcb.status);
    assert_eq!(s.platform.root_key_id, rc.platform.root_key_id);
    assert_eq!(s.tcb.earliest_expiration, rc.tcb.earliest_expiration);
    assert_eq!(s.tcb.eval_data_number, rc.tcb.eval_data_number);
}
