extern crate alloc;

use dcap_qvl::{verify::{QuoteVerifier, ring}, QuoteCollateralV3};
use hex::decode;
use near_sdk::{env, log, near};

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

#[near(contract_state)]
#[derive(Default)]
pub struct Contract;

#[near]
impl Contract {
    /// Verifies a TEE attestation using dcap-qvl::verify::verify().
    ///
    /// # Parameters
    /// - `quote_hex`: Hex-encoded quote bytes
    /// - `collateral`: JSON string containing quote collateral data (QuoteCollateralV3 format)
    ///
    /// # Returns
    /// `true` if verification succeeds, `false` otherwise.
    #[must_use]
    pub fn verify_attestation(&self, quote_hex: String, collateral: String) -> bool {
        // Decode quote bytes from hex
        let quote_bytes = match decode(&quote_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                log!("Invalid quote hex: {} (error: {:?})", quote_hex, e);
                env::panic_str("Invalid quote hex");
            }
        };

        // Parse collateral JSON
        let collateral_data: QuoteCollateralV3 = match near_sdk::serde_json::from_str(&collateral) {
            Ok(c) => c,
            Err(e) => {
                log!("Invalid collateral format: {} (error: {:?})", collateral, e);
                env::panic_str("Invalid collateral format");
            }
        };

        // Get current timestamp in seconds
        let timestamp_s = get_block_timestamp_secs();

        // Call dcap-qvl verify
        let verifier = QuoteVerifier::new_prod(ring::backend());
        match verifier.verify(&quote_bytes, &collateral_data, timestamp_s) {
            Ok(_supplemental) => {
                log!("Verification result: Success");
                true
            }
            Err(e) => {
                log!("Verification failed: {:?}", e);
                false
            }
        }
    }
}
