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
        .verify(raw_quote, collateral, now_secs)
        .map(|s| s.into_report());
    let rustcrypto_result = rustcrypto_verifier
        .verify(raw_quote, collateral, now_secs)
        .map(|s| s.into_report());

    assert_eq!(
        ring_result.map_err(|e| e.to_string()),
        rustcrypto_result.map_err(|e| e.to_string())
    );
    ring_verifier
        .verify(raw_quote, collateral, now_secs)
        .map(|s| s.into_report())
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
    let result = verifier.verify(&raw_quote, &collateral, now).unwrap();
    let s = &result.supplemental;

    // Parse quote for later use
    let parsed_quote = Quote::decode(&mut &raw_quote[..]).unwrap();

    // ── TCB status ──────────────────────────────────────────────────────
    assert_eq!(
        s.tcb_status.to_string(),
        "ConfigurationAndSWHardeningNeeded"
    );
    assert_eq!(s.advisory_ids, ["INTEL-SA-00289", "INTEL-SA-00615"]);

    // ── Collateral time window ──────────────────────────────────────────
    // Independently compute using all 8 sources matching Intel QVL:
    // TCBInfo, QEIdentity, 2 CRLs, 4 certificate chains
    fn parse_ts(json: &str, field: &str) -> u64 {
        let v: Value = serde_json::from_str(json).unwrap();
        chrono::DateTime::parse_from_rfc3339(v[field].as_str().unwrap())
            .unwrap()
            .timestamp() as u64
    }
    fn crl_dates(der: &[u8]) -> (u64, u64) {
        let crl = CertificateList::from_der(der).unwrap();
        let this = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next = crl
            .tbs_cert_list
            .next_update
            .unwrap()
            .to_unix_duration()
            .as_secs();
        (this, next)
    }
    fn cert_chain_dates(pem: &[u8]) -> Vec<(u64, u64)> {
        let certs = pem::parse_many(pem).unwrap();
        certs
            .iter()
            .map(|c| {
                let cert: x509_cert::Certificate = DerDecode::from_der(c.contents()).unwrap();
                let nb = cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs();
                let na = cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs();
                (nb, na)
            })
            .collect()
    }

    let tcb_issue = parse_ts(&collateral.tcb_info, "issueDate");
    let tcb_next = parse_ts(&collateral.tcb_info, "nextUpdate");
    let qe_issue = parse_ts(&collateral.qe_identity, "issueDate");
    let qe_next = parse_ts(&collateral.qe_identity, "nextUpdate");
    let (root_crl_this, root_crl_next) = crl_dates(&collateral.root_ca_crl);
    let (pck_crl_this, pck_crl_next) = crl_dates(&collateral.pck_crl);

    let mut expected_earliest_issue = tcb_issue.min(qe_issue).min(root_crl_this).min(pck_crl_this);
    let mut expected_latest_issue = tcb_issue.max(qe_issue).max(root_crl_this).max(pck_crl_this);
    let mut expected_earliest_expiration =
        tcb_next.min(qe_next).min(root_crl_next).min(pck_crl_next);

    // Include certificate chain dates (4 chains)
    let pck_chain = dcap_qvl::intel::extract_cert_chain(&parsed_quote).unwrap();
    for cert_der in &pck_chain {
        let cert: x509_cert::Certificate = DerDecode::from_der(cert_der).unwrap();
        let nb = cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let na = cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();
        expected_earliest_issue = expected_earliest_issue.min(nb);
        expected_latest_issue = expected_latest_issue.max(nb);
        expected_earliest_expiration = expected_earliest_expiration.min(na);
    }
    for pem_chain in [
        collateral.pck_crl_issuer_chain.as_bytes(),
        collateral.tcb_info_issuer_chain.as_bytes(),
        collateral.qe_identity_issuer_chain.as_bytes(),
    ] {
        for (nb, na) in cert_chain_dates(pem_chain) {
            expected_earliest_issue = expected_earliest_issue.min(nb);
            expected_latest_issue = expected_latest_issue.max(nb);
            expected_earliest_expiration = expected_earliest_expiration.min(na);
        }
    }

    assert_eq!(s.earliest_issue_date, expected_earliest_issue);
    assert_eq!(s.latest_issue_date, expected_latest_issue);
    assert_eq!(s.earliest_expiration_date, expected_earliest_expiration);

    // ── tcb_level_date_tag ──────────────────────────────────────────────
    let expected_tcb_date = chrono::DateTime::parse_from_rfc3339(&s.platform_tcb_level.tcb_date)
        .unwrap()
        .timestamp() as u64;
    assert_eq!(s.tcb_level_date_tag, expected_tcb_date);

    // ── CRL numbers ─────────────────────────────────────────────────────
    // Parse CRL numbers independently
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
    assert_eq!(s.root_ca_crl_num, extract_crl_num(&collateral.root_ca_crl));
    assert_eq!(s.pck_crl_num, extract_crl_num(&collateral.pck_crl));

    // ── tcb_eval_data_number ────────────────────────────────────────────
    let tcb_info_parsed: dcap_qvl::TcbInfo = serde_json::from_str(&collateral.tcb_info).unwrap();
    let qe_id_parsed: dcap_qvl::QeIdentity = serde_json::from_str(&collateral.qe_identity).unwrap();
    let expected_eval_num = tcb_info_parsed
        .tcb_evaluation_data_number
        .min(qe_id_parsed.tcb_evaluation_data_number);
    assert_eq!(s.tcb_eval_data_number, expected_eval_num);

    // ── root_key_id ─────────────────────────────────────────────────────
    // SHA-384 of root CA raw public key bytes (BIT STRING content),
    // matching Intel QVL's X509_get0_pubkey_bitstr()
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
    assert_eq!(s.root_key_id, expected_root_key_id);

    // ── PCK certificate fields ──────────────────────────────────────────
    // Parse PCK cert extension independently from the quote's embedded chain
    let pck_chain_der = dcap_qvl::intel::extract_cert_chain(&parsed_quote).unwrap();
    let pck_ext = dcap_qvl::intel::parse_pck_extension(&pck_chain_der[0]).unwrap();

    assert_eq!(s.cpu_svn, pck_ext.cpu_svn);
    assert_eq!(s.pce_svn, pck_ext.pce_svn);
    assert_eq!(s.fmspc, pck_ext.fmspc);
    assert_eq!(s.ppid, pck_ext.ppid);
    assert_eq!(s.sgx_type, pck_ext.sgx_type as u8);

    // pce_id: from raw extension bytes
    let expected_pce_id = match pck_ext.pce_id.len() {
        2 => u16::from_be_bytes([pck_ext.pce_id[0], pck_ext.pce_id[1]]),
        1 => u16::from(pck_ext.pce_id[0]),
        _ => 0,
    };
    assert_eq!(s.pce_id, expected_pce_id);

    // ── TEE type ────────────────────────────────────────────────────────
    assert_eq!(s.tee_type, 0x00000000); // SGX

    // ── Platform instance (Processor CA → should be None/Undefined) ─────
    // Sample quote uses Processor CA, so platform_instance_id should be None
    // and config flags should be Undefined
    assert_eq!(s.dynamic_platform, PckCertFlag::Undefined);
    assert_eq!(s.cached_keys, PckCertFlag::Undefined);
    assert_eq!(s.smt_enabled, PckCertFlag::Undefined);

    // ── TCB levels ──────────────────────────────────────────────────────
    assert!(!s.platform_tcb_level.tcb_date.is_empty());
    assert!(!s.qe_tcb_level.tcb_date.is_empty());

    // Verify ring and rustcrypto produce identical supplemental data
    let rustcrypto_verifier = QuoteVerifier::new_prod(dcap_qvl::verify::rustcrypto::backend());
    let rc_result = rustcrypto_verifier
        .verify(&raw_quote, &collateral, now)
        .unwrap();
    let rc = &rc_result.supplemental;
    assert_eq!(s.tcb_status, rc.tcb_status);
    assert_eq!(s.advisory_ids, rc.advisory_ids);
    assert_eq!(s.earliest_issue_date, rc.earliest_issue_date);
    assert_eq!(s.latest_issue_date, rc.latest_issue_date);
    assert_eq!(s.earliest_expiration_date, rc.earliest_expiration_date);
    assert_eq!(s.tcb_level_date_tag, rc.tcb_level_date_tag);
    assert_eq!(s.pck_crl_num, rc.pck_crl_num);
    assert_eq!(s.root_ca_crl_num, rc.root_ca_crl_num);
    assert_eq!(s.tcb_eval_data_number, rc.tcb_eval_data_number);
    assert_eq!(s.root_key_id, rc.root_key_id);
    assert_eq!(s.ppid, rc.ppid);
    assert_eq!(s.cpu_svn, rc.cpu_svn);
    assert_eq!(s.pce_svn, rc.pce_svn);
    assert_eq!(s.pce_id, rc.pce_id);
    assert_eq!(s.fmspc, rc.fmspc);
    assert_eq!(s.tee_type, rc.tee_type);
    assert_eq!(s.sgx_type, rc.sgx_type);
    assert_eq!(s.platform_instance_id, rc.platform_instance_id);
    assert_eq!(s.dynamic_platform, rc.dynamic_platform);
    assert_eq!(s.cached_keys, rc.cached_keys);
    assert_eq!(s.smt_enabled, rc.smt_enabled);
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

/// Print all SupplementalData fields side-by-side: our result vs independently computed.
#[test]
fn print_supplemental_data_comparison() {
    use dcap_qvl::verify::{ring, QuoteVerifier};

    fn ts_to_utc(ts: u64) -> String {
        chrono::DateTime::from_timestamp(ts as i64, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_else(|| format!("{ts}"))
    }

    fn parse_ts(json: &str, field: &str) -> u64 {
        let v: Value = serde_json::from_str(json).unwrap();
        chrono::DateTime::parse_from_rfc3339(v[field].as_str().unwrap())
            .unwrap()
            .timestamp() as u64
    }

    fn crl_dates(der: &[u8]) -> (u64, u64) {
        let crl = CertificateList::from_der(der).unwrap();
        let this = crl.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let next = crl
            .tbs_cert_list
            .next_update
            .unwrap()
            .to_unix_duration()
            .as_secs();
        (this, next)
    }

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

    fn cert_chain_dates_pem(pem: &[u8]) -> Vec<(u64, u64)> {
        pem::parse_many(pem)
            .unwrap()
            .iter()
            .map(|c| {
                let cert: x509_cert::Certificate = DerDecode::from_der(c.contents()).unwrap();
                let nb = cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs();
                let na = cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs();
                (nb, na)
            })
            .collect()
    }

    fn cert_chain_dates_der(chain: &[Vec<u8>]) -> Vec<(u64, u64)> {
        chain
            .iter()
            .map(|der| {
                let cert: x509_cert::Certificate = DerDecode::from_der(der).unwrap();
                let nb = cert
                    .tbs_certificate
                    .validity
                    .not_before
                    .to_unix_duration()
                    .as_secs();
                let na = cert
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_unix_duration()
                    .as_secs();
                (nb, na)
            })
            .collect()
    }

    // Compute expected time window from 8 sources
    fn compute_time_window(
        collateral: &QuoteCollateralV3,
        pck_chain: &[Vec<u8>],
    ) -> (u64, u64, u64) {
        let tcb_issue = parse_ts(&collateral.tcb_info, "issueDate");
        let tcb_next = parse_ts(&collateral.tcb_info, "nextUpdate");
        let qe_issue = parse_ts(&collateral.qe_identity, "issueDate");
        let qe_next = parse_ts(&collateral.qe_identity, "nextUpdate");
        let (root_crl_this, root_crl_next) = crl_dates(&collateral.root_ca_crl);
        let (pck_crl_this, pck_crl_next) = crl_dates(&collateral.pck_crl);

        let mut ei = tcb_issue.min(qe_issue).min(root_crl_this).min(pck_crl_this);
        let mut li = tcb_issue.max(qe_issue).max(root_crl_this).max(pck_crl_this);
        let mut ee = tcb_next.min(qe_next).min(root_crl_next).min(pck_crl_next);

        for (nb, na) in cert_chain_dates_der(pck_chain) {
            ei = ei.min(nb);
            li = li.max(nb);
            ee = ee.min(na);
        }
        for pem in [
            collateral.pck_crl_issuer_chain.as_bytes(),
            collateral.tcb_info_issuer_chain.as_bytes(),
            collateral.qe_identity_issuer_chain.as_bytes(),
        ] {
            for (nb, na) in cert_chain_dates_pem(pem) {
                ei = ei.min(nb);
                li = li.max(nb);
                ee = ee.min(na);
            }
        }
        (ei, li, ee)
    }

    fn compute_root_key_id() -> [u8; 48] {
        let root_ca_der = include_bytes!("../src/TrustedRootCA.der");
        let root_cert: x509_cert::Certificate = DerDecode::from_der(root_ca_der).unwrap();
        let raw_pub_key = root_cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        use sha2::Digest;
        sha2::Sha384::digest(raw_pub_key).into()
    }

    // ═══════════════════════════════════════════════════════════════════
    // SGX Quote
    // ═══════════════════════════════════════════════════════════════════
    println!("\n{:=<80}", "");
    println!("SGX Quote — SupplementalData (ours vs independently computed)");
    println!("{:=<80}", "");

    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/sgx_quote_collateral.json")).unwrap();
    let now = now_from_collateral(&collateral);
    let parsed_quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    let pck_chain = dcap_qvl::intel::extract_cert_chain(&parsed_quote).unwrap();
    let pck_ext = dcap_qvl::intel::parse_pck_extension(&pck_chain[0]).unwrap();

    let verifier = QuoteVerifier::new_prod(ring::backend());
    let result = verifier.verify(&raw_quote, &collateral, now).unwrap();
    let s = &result.supplemental;

    let tcb_info: dcap_qvl::TcbInfo = serde_json::from_str(&collateral.tcb_info).unwrap();
    let qe_id: dcap_qvl::QeIdentity = serde_json::from_str(&collateral.qe_identity).unwrap();
    let (exp_ei, exp_li, exp_ee) = compute_time_window(&collateral, &pck_chain);
    let exp_tcb_date = chrono::DateTime::parse_from_rfc3339(&s.platform_tcb_level.tcb_date)
        .unwrap()
        .timestamp() as u64;
    let exp_eval_num = tcb_info
        .tcb_evaluation_data_number
        .min(qe_id.tcb_evaluation_data_number);
    let exp_root_key_id = compute_root_key_id();
    let exp_pce_id = match pck_ext.pce_id.len() {
        2 => u16::from_be_bytes([pck_ext.pce_id[0], pck_ext.pce_id[1]]),
        1 => u16::from(pck_ext.pce_id[0]),
        _ => 0,
    };

    println!(
        "{:<40} {:<40} {:<40}",
        "Field", "Our Value", "Expected (independent)"
    );
    println!("{:-<40} {:-<40} {:-<40}", "", "", "");
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_status",
        format!("{:?}", s.tcb_status),
        "ConfigurationAndSWHardeningNeeded"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "advisory_ids",
        format!("{:?}", s.advisory_ids),
        "[INTEL-SA-00289, INTEL-SA-00615]"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "earliest_issue_date",
        format!(
            "{} ({})",
            s.earliest_issue_date,
            ts_to_utc(s.earliest_issue_date)
        ),
        format!("{} ({})", exp_ei, ts_to_utc(exp_ei))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "latest_issue_date",
        format!(
            "{} ({})",
            s.latest_issue_date,
            ts_to_utc(s.latest_issue_date)
        ),
        format!("{} ({})", exp_li, ts_to_utc(exp_li))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "earliest_expiration_date",
        format!(
            "{} ({})",
            s.earliest_expiration_date,
            ts_to_utc(s.earliest_expiration_date)
        ),
        format!("{} ({})", exp_ee, ts_to_utc(exp_ee))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_level_date_tag",
        format!(
            "{} ({})",
            s.tcb_level_date_tag,
            ts_to_utc(s.tcb_level_date_tag)
        ),
        format!("{} ({})", exp_tcb_date, ts_to_utc(exp_tcb_date))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pck_crl_num",
        format!("{}", s.pck_crl_num),
        format!("{}", extract_crl_num(&collateral.pck_crl))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "root_ca_crl_num",
        format!("{}", s.root_ca_crl_num),
        format!("{}", extract_crl_num(&collateral.root_ca_crl))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_eval_data_number",
        format!("{}", s.tcb_eval_data_number),
        format!(
            "{} (min of {} and {})",
            exp_eval_num, tcb_info.tcb_evaluation_data_number, qe_id.tcb_evaluation_data_number
        )
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "root_key_id",
        hex::encode(&s.root_key_id[..24]) + "...",
        hex::encode(&exp_root_key_id[..24]) + "..."
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "ppid",
        hex::encode(&s.ppid),
        hex::encode(&pck_ext.ppid)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "cpu_svn",
        hex::encode(s.cpu_svn),
        hex::encode(pck_ext.cpu_svn)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pce_svn",
        format!("{}", s.pce_svn),
        format!("{}", pck_ext.pce_svn)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pce_id",
        format!("{}", s.pce_id),
        format!("{}", exp_pce_id)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "fmspc",
        hex::encode(s.fmspc),
        hex::encode(pck_ext.fmspc)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tee_type",
        format!("0x{:08X}", s.tee_type),
        "0x00000000 (SGX)"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "sgx_type",
        format!("{}", s.sgx_type),
        format!("{}", pck_ext.sgx_type)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "platform_instance_id",
        format!("{:?}", s.platform_instance_id),
        format!("{:?}", pck_ext.platform_instance_id)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "dynamic_platform",
        format!("{:?}", s.dynamic_platform),
        format!("{:?}", pck_ext.dynamic_platform)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "cached_keys",
        format!("{:?}", s.cached_keys),
        format!("{:?}", pck_ext.cached_keys)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "smt_enabled",
        format!("{:?}", s.smt_enabled),
        format!("{:?}", pck_ext.smt_enabled)
    );
    println!(
        "{:<40} {:<40}",
        "platform_tcb_level.tcb_date", &s.platform_tcb_level.tcb_date
    );
    println!(
        "{:<40} {:<40}",
        "platform_tcb_level.tcb_status",
        format!("{:?}", s.platform_tcb_level.tcb_status)
    );
    println!(
        "{:<40} {:<40}",
        "qe_tcb_level.tcb_date", &s.qe_tcb_level.tcb_date
    );
    println!(
        "{:<40} {:<40}",
        "qe_tcb_level.tcb_status",
        format!("{:?}", s.qe_tcb_level.tcb_status)
    );

    // ═══════════════════════════════════════════════════════════════════
    // TDX Quote
    // ═══════════════════════════════════════════════════════════════════
    println!("\n{:=<80}", "");
    println!("TDX Quote — SupplementalData (ours vs independently computed)");
    println!("{:=<80}", "");

    let raw_quote_tdx = include_bytes!("../sample/tdx_quote");
    let collateral_tdx: QuoteCollateralV3 =
        serde_json::from_slice(include_bytes!("../sample/tdx_quote_collateral.json")).unwrap();
    let now_tdx = now_from_collateral(&collateral_tdx);
    let parsed_quote_tdx = Quote::decode(&mut &raw_quote_tdx[..]).unwrap();
    let pck_chain_tdx = dcap_qvl::intel::extract_cert_chain(&parsed_quote_tdx).unwrap();
    let pck_ext_tdx = dcap_qvl::intel::parse_pck_extension(&pck_chain_tdx[0]).unwrap();

    let result_tdx = verifier
        .verify(raw_quote_tdx, &collateral_tdx, now_tdx)
        .unwrap();
    let t = &result_tdx.supplemental;

    let tcb_info_tdx: dcap_qvl::TcbInfo = serde_json::from_str(&collateral_tdx.tcb_info).unwrap();
    let qe_id_tdx: dcap_qvl::QeIdentity =
        serde_json::from_str(&collateral_tdx.qe_identity).unwrap();
    let (exp_ei_t, exp_li_t, exp_ee_t) = compute_time_window(&collateral_tdx, &pck_chain_tdx);
    let exp_tcb_date_t = chrono::DateTime::parse_from_rfc3339(&t.platform_tcb_level.tcb_date)
        .unwrap()
        .timestamp() as u64;
    let exp_eval_num_t = tcb_info_tdx
        .tcb_evaluation_data_number
        .min(qe_id_tdx.tcb_evaluation_data_number);
    let exp_pce_id_t = match pck_ext_tdx.pce_id.len() {
        2 => u16::from_be_bytes([pck_ext_tdx.pce_id[0], pck_ext_tdx.pce_id[1]]),
        1 => u16::from(pck_ext_tdx.pce_id[0]),
        _ => 0,
    };

    println!(
        "{:<40} {:<40} {:<40}",
        "Field", "Our Value", "Expected (independent)"
    );
    println!("{:-<40} {:-<40} {:-<40}", "", "", "");
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_status",
        format!("{:?}", t.tcb_status),
        "UpToDate"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "advisory_ids",
        format!("{:?}", t.advisory_ids),
        "[]"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "earliest_issue_date",
        format!(
            "{} ({})",
            t.earliest_issue_date,
            ts_to_utc(t.earliest_issue_date)
        ),
        format!("{} ({})", exp_ei_t, ts_to_utc(exp_ei_t))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "latest_issue_date",
        format!(
            "{} ({})",
            t.latest_issue_date,
            ts_to_utc(t.latest_issue_date)
        ),
        format!("{} ({})", exp_li_t, ts_to_utc(exp_li_t))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "earliest_expiration_date",
        format!(
            "{} ({})",
            t.earliest_expiration_date,
            ts_to_utc(t.earliest_expiration_date)
        ),
        format!("{} ({})", exp_ee_t, ts_to_utc(exp_ee_t))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_level_date_tag",
        format!(
            "{} ({})",
            t.tcb_level_date_tag,
            ts_to_utc(t.tcb_level_date_tag)
        ),
        format!("{} ({})", exp_tcb_date_t, ts_to_utc(exp_tcb_date_t))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pck_crl_num",
        format!("{}", t.pck_crl_num),
        format!("{}", extract_crl_num(&collateral_tdx.pck_crl))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "root_ca_crl_num",
        format!("{}", t.root_ca_crl_num),
        format!("{}", extract_crl_num(&collateral_tdx.root_ca_crl))
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tcb_eval_data_number",
        format!("{}", t.tcb_eval_data_number),
        format!(
            "{} (min of {} and {})",
            exp_eval_num_t,
            tcb_info_tdx.tcb_evaluation_data_number,
            qe_id_tdx.tcb_evaluation_data_number
        )
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "root_key_id",
        hex::encode(&t.root_key_id[..24]) + "...",
        hex::encode(&exp_root_key_id[..24]) + "..."
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "ppid",
        hex::encode(&t.ppid),
        hex::encode(&pck_ext_tdx.ppid)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "cpu_svn",
        hex::encode(t.cpu_svn),
        hex::encode(pck_ext_tdx.cpu_svn)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pce_svn",
        format!("{}", t.pce_svn),
        format!("{}", pck_ext_tdx.pce_svn)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "pce_id",
        format!("{}", t.pce_id),
        format!("{}", exp_pce_id_t)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "fmspc",
        hex::encode(t.fmspc),
        hex::encode(pck_ext_tdx.fmspc)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "tee_type",
        format!("0x{:08X}", t.tee_type),
        "0x00000081 (TDX)"
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "sgx_type",
        format!("{}", t.sgx_type),
        format!("{}", pck_ext_tdx.sgx_type)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "platform_instance_id",
        format!("{:?}", t.platform_instance_id),
        format!("{:?}", pck_ext_tdx.platform_instance_id)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "dynamic_platform",
        format!("{:?}", t.dynamic_platform),
        format!("{:?}", pck_ext_tdx.dynamic_platform)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "cached_keys",
        format!("{:?}", t.cached_keys),
        format!("{:?}", pck_ext_tdx.cached_keys)
    );
    println!(
        "{:<40} {:<40} {:<40}",
        "smt_enabled",
        format!("{:?}", t.smt_enabled),
        format!("{:?}", pck_ext_tdx.smt_enabled)
    );
    println!(
        "{:<40} {:<40}",
        "platform_tcb_level.tcb_date", &t.platform_tcb_level.tcb_date
    );
    println!(
        "{:<40} {:<40}",
        "platform_tcb_level.tcb_status",
        format!("{:?}", t.platform_tcb_level.tcb_status)
    );
    println!(
        "{:<40} {:<40}",
        "qe_tcb_level.tcb_date", &t.qe_tcb_level.tcb_date
    );
    println!(
        "{:<40} {:<40}",
        "qe_tcb_level.tcb_status",
        format!("{:?}", t.qe_tcb_level.tcb_status)
    );
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
    let result = verifier.verify(raw_quote, &collateral, now).unwrap();
    let s = &result.supplemental;

    // TDX quote should have tee_type = 0x81
    assert_eq!(s.tee_type, 0x00000081);
    assert_eq!(s.tcb_status.to_string(), "UpToDate");
    assert!(s.advisory_ids.is_empty());

    // Time window fields should be populated
    assert!(s.earliest_issue_date > 0);
    assert!(s.latest_issue_date >= s.earliest_issue_date);
    assert!(s.earliest_expiration_date > s.latest_issue_date);
    assert!(s.tcb_level_date_tag > 0);

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
    assert_eq!(s.root_key_id, expected_root_key_id);

    // Verify ring == rustcrypto for all fields
    let rc_verifier = QuoteVerifier::new_prod(dcap_qvl::verify::rustcrypto::backend());
    let rc_result = rc_verifier.verify(raw_quote, &collateral, now).unwrap();
    let rc = &rc_result.supplemental;
    assert_eq!(s.tee_type, rc.tee_type);
    assert_eq!(s.tcb_status, rc.tcb_status);
    assert_eq!(s.root_key_id, rc.root_key_id);
    assert_eq!(s.earliest_issue_date, rc.earliest_issue_date);
    assert_eq!(s.tcb_eval_data_number, rc.tcb_eval_data_number);
}
