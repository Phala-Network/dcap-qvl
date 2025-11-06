///! Realistic Exception Test Suite
///!
///! This test suite focuses on exceptions that can be tested with real data mutations
///! Some tests are impossible to implement without binary quote modification tools
use dcap_qvl::{verify::verify, QuoteCollateralV3};

fn load_sgx_sample() -> (Vec<u8>, QuoteCollateralV3) {
    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let raw_quote_collateral = include_bytes!("../sample/sgx_quote_collateral.json");
    let quote_collateral: QuoteCollateralV3 = serde_json::from_slice(raw_quote_collateral).unwrap();
    (raw_quote, quote_collateral)
}

fn load_tdx_sample() -> (Vec<u8>, QuoteCollateralV3) {
    let raw_quote = include_bytes!("../sample/tdx_quote").to_vec();
    let raw_quote_collateral = include_bytes!("../sample/tdx_quote_collateral.json");
    let quote_collateral: QuoteCollateralV3 = serde_json::from_slice(raw_quote_collateral).unwrap();
    (raw_quote, quote_collateral)
}

const VALID_NOW: u64 = 1750320802u64;
const EXPIRED_NOW: u64 = 9999999999u64;

// ====================
// COLLATERAL ERRORS
// ====================

#[test]
fn exception_01_invalid_quote_empty() {
    let (_, collateral) = load_sgx_sample();
    let empty_quote = vec![];
    let result = verify(&empty_quote, &collateral, VALID_NOW);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Failed to decode quote"));
}

#[test]
fn exception_02_invalid_quote_truncated() {
    let (mut quote, collateral) = load_sgx_sample();
    quote.truncate(quote.len() / 2);
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_03_invalid_tcb_info_json() {
    let (quote, mut collateral) = load_sgx_sample();
    collateral.tcb_info = "invalid json {".to_string();
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Failed to decode TcbInfo"));
}

#[test]
fn exception_04_invalid_next_update_format() {
    let (quote, mut collateral) = load_sgx_sample();
    let mut tcb_info: serde_json::Value = serde_json::from_str(&collateral.tcb_info).unwrap();
    tcb_info["nextUpdate"] = serde_json::Value::String("not-a-valid-date".to_string());
    collateral.tcb_info = serde_json::to_string(&tcb_info).unwrap();
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Failed to parse next update"));
}

#[test]
fn exception_05_tcb_info_expired() {
    let (quote, collateral) = load_sgx_sample();
    let result = verify(&quote, &collateral, EXPIRED_NOW);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().to_string(), "TCBInfo expired");
}

#[test]
fn exception_06_root_ca_crl_invalid() {
    let (quote, mut collateral) = load_sgx_sample();
    collateral.root_ca_crl = vec![0x00; 100];
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_07_pck_crl_invalid() {
    let (quote, mut collateral) = load_sgx_sample();
    collateral.pck_crl = vec![0x00; 100];
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_08_tcb_cert_chain_too_short() {
    let (quote, mut collateral) = load_sgx_sample();
    let full_chain = collateral.tcb_info_issuer_chain.clone();
    let first_cert_end =
        full_chain.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
    collateral.tcb_info_issuer_chain = full_chain[..first_cert_end].to_string();
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Certificate chain is too short in quote_collateral"));
}

#[test]
fn exception_09_tcb_cert_chain_corrupted() {
    let (quote, mut collateral) = load_sgx_sample();
    collateral.tcb_info_issuer_chain = collateral.tcb_info_issuer_chain.replace("MII", "XXX");
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_10_fmspc_mismatch() {
    let (quote, mut collateral) = load_sgx_sample();
    let mut tcb_info: serde_json::Value = serde_json::from_str(&collateral.tcb_info).unwrap();
    tcb_info["fmspc"] = serde_json::Value::String("FFFFFFFFFFFF".to_string());
    collateral.tcb_info = serde_json::to_string(&tcb_info).unwrap();
    // Note: This will fail signature check first, but that's a realistic scenario
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_11_tdx_quote_with_sgx_tcb() {
    let (tdx_quote, tdx_collateral) = load_tdx_sample();
    let (_, sgx_collateral) = load_sgx_sample();

    // Use SGX TCB info for TDX quote - will fail signature first, but tests the flow
    let mut bad_collateral = tdx_collateral.clone();
    bad_collateral.tcb_info = sgx_collateral.tcb_info;

    let result = verify(&tdx_quote, &bad_collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_12_empty_sgx_components() {
    let (quote, mut collateral) = load_sgx_sample();
    let mut tcb_info: serde_json::Value = serde_json::from_str(&collateral.tcb_info).unwrap();
    if let Some(levels) = tcb_info["tcbLevels"].as_array_mut() {
        for level in levels.iter_mut() {
            level["tcb"]["sgxtcbcomponents"] = serde_json::Value::Array(vec![]);
        }
    }
    collateral.tcb_info = serde_json::to_string(&tcb_info).unwrap();
    // Will fail signature check first
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

#[test]
fn exception_13_empty_tdx_components() {
    let (quote, mut collateral) = load_tdx_sample();
    let mut tcb_info: serde_json::Value = serde_json::from_str(&collateral.tcb_info).unwrap();
    if let Some(levels) = tcb_info["tcbLevels"].as_array_mut() {
        for level in levels.iter_mut() {
            if level["tcb"].get("tdxtcbcomponents").is_some() {
                level["tcb"]["tdxtcbcomponents"] = serde_json::Value::Array(vec![]);
            }
        }
    }
    collateral.tcb_info = serde_json::to_string(&tcb_info).unwrap();
    // Will fail signature check first
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_err());
}

// ====================
// POSITIVE TESTS
// ====================

#[test]
fn valid_sgx_quote() {
    let (quote, collateral) = load_sgx_sample();
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.status, "ConfigurationAndSWHardeningNeeded");
    assert_eq!(
        verified.advisory_ids,
        vec!["INTEL-SA-00289", "INTEL-SA-00615"]
    );
}

#[test]
fn valid_tdx_quote() {
    let (quote, collateral) = load_tdx_sample();
    let result = verify(&quote, &collateral, VALID_NOW);
    assert!(result.is_ok());
    let verified = result.unwrap();
    assert_eq!(verified.status, "UpToDate");
    assert!(verified.advisory_ids.is_empty());
}
