extern crate alloc;

use dcap_qvl::{verify::QuoteVerifier, QuoteCollateralV3, QuotePolicy};
use near_sdk::{env, near};

/// Returns the current block timestamp in seconds.
/// When the `test` feature is enabled, returns a fixed timestamp
#[must_use]
pub fn get_block_timestamp_secs() -> u64 {
    #[cfg(feature = "test")]
    {
        // The quotes for testing under tests/samples are retrieved from TEE on Sep 2, 2025
        // To make the verification pass in test, we use a fixed timestamp Sep 10, 2025 00:00:00 UTC
        1_757_462_400
    }
    #[cfg(not(feature = "test"))]
    {
        env::block_timestamp_ms() / 1_000
    }
}

fn decode_args(quote_hex: &str, collateral: &str) -> (Vec<u8>, QuoteCollateralV3) {
    let quote = hex::decode(quote_hex).unwrap_or_else(|_| env::panic_str("Invalid quote hex"));
    let collateral = near_sdk::serde_json::from_str(collateral)
        .unwrap_or_else(|_| env::panic_str("Invalid collateral format"));
    (quote, collateral)
}

#[near(contract_state)]
#[derive(Default)]
pub struct Contract;

#[near]
impl Contract {
    /// Verifies a quote with `QuoteVerifier::verify`.
    pub fn verify(&self, quote_hex: String, collateral: String) {
        let (quote, collateral) = decode_args(&quote_hex, &collateral);
        QuoteVerifier::new_prod()
            .verify(&quote, &collateral, get_block_timestamp_secs())
            .unwrap_or_else(|e| env::panic_str(&format!("{e:?}")));
    }

    /// Verifies a quote with `QuoteVerifier::verify_with_policy` and a pass-through policy.
    pub fn verify_with_policy(&self, quote_hex: String, collateral: String) {
        let (quote, collateral) = decode_args(&quote_hex, &collateral);
        let now = get_block_timestamp_secs();
        QuoteVerifier::new_prod()
            .verify_with_policy(&quote, collateral, now, &QuotePolicy::claims_only(now))
            .unwrap_or_else(|e| env::panic_str(&format!("{e:?}")));
    }
}
