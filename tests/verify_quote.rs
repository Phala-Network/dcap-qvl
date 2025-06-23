use dcap_qvl::{quote::Quote, verify::verify, QuoteCollateralV3};
use scale::Decode;

#[test]
fn could_parse_sgx_quote() {
    let raw_quote = include_bytes!("../sample/sgx_quote").to_vec();
    let raw_quote_collateral = include_bytes!("../sample/sgx_quote_collateral.json");
    let now = 1750320802u64;

    let quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    insta::assert_debug_snapshot!(quote);

    let quote_collateral: QuoteCollateralV3 =
        serde_json::from_slice(raw_quote_collateral).expect("decodable");
    let tcb_status = verify(&raw_quote, &quote_collateral, now).expect("verify");

    assert_eq!(tcb_status.status, "ConfigurationAndSWHardeningNeeded");
    assert_eq!(
        tcb_status.advisory_ids,
        ["INTEL-SA-00289", "INTEL-SA-00615"]
    );
}

#[test]
fn could_parse_tdx_quote() {
    let raw_quote = include_bytes!("../sample/tdx_quote");
    let raw_quote_collateral = include_bytes!("../sample/tdx_quote_collateral.json");
    let now = 1750320802u64;

    let quote = Quote::decode(&mut &raw_quote[..]).unwrap();
    insta::assert_debug_snapshot!(quote);

    let quote_collateral: QuoteCollateralV3 = serde_json::from_slice(raw_quote_collateral).unwrap();
    let tcb_status = verify(raw_quote, &quote_collateral, now).unwrap();
    assert_eq!(tcb_status.status, "UpToDate");
    assert!(tcb_status.advisory_ids.is_empty());
}
