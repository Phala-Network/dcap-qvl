// Test data constants
pub const TEST_SECRET_KEY: &str = "ed25519:3uHrtHQ6422oAj7WhvDgf9KdewGZLvCLbY6AyDdfkctRkUgyai1yMFn7TGnY2a4zQ8o2a1xQpaPPuaTcjRNaxTqP";
pub const TEST_QUOTE_HEX: &str = include_str!("quote/quote_hex.txt");
pub const TEST_QUOTE_COLLATERAL: &str = include_str!("quote/quote_collateral.json");

// Gas regression ceilings. Adjust them together with any intentional change in gas usage.
// Measured with ring: verify 124.2 TGas, verify_with_policy 125.6 TGas.
#[cfg(feature = "ring")]
pub const MAX_VERIFY_GAS: near_gas::NearGas = near_gas::NearGas::from_tgas(126);
// Measured with rustcrypto: verify 98.2 TGas, verify_with_policy 99.5 TGas.
#[cfg(not(feature = "ring"))]
pub const MAX_VERIFY_GAS: near_gas::NearGas = near_gas::NearGas::from_tgas(100);
/// Extra gas `verify_with_policy` may spend on building claims on top of `verify`.
pub const MAX_CLAIMS_OVERHEAD_GAS: near_gas::NearGas = near_gas::NearGas::from_tgas(2);
