# NEAR Gas Tests for DCAP-QVL

This directory contains NEAR smart contract integration tests for measuring gas consumption of dcap-qvl verification operations.

## Overview

The `dcap-qvl-gas-test` contract is a minimal NEAR contract that tests gas consumption of `dcap-qvl::verify::verify()`. It directly calls the core verification function with quote bytes and collateral data.

## Prerequisites

- Rust and Cargo (latest stable version)
- [cargo-near](https://github.com/near/cargo-near) - NEAR smart contract development toolkit
- `near-sandbox` and `near-api` (automatically included as dev dependencies)

## Building and Testing

### Build the Contract

From the `dcap-qvl` project root:

```bash
make build_near_gas_test
```

Or manually:

```bash
cd tests/near/contracts/dcap-qvl-gas-test
cargo near build non-reproducible-wasm --features test --locked
```

### Run the Tests

From the `dcap-qvl` project root:

```bash
make test_near_gas
```

Or manually:

```bash
cd tests/near/contracts/dcap-qvl-gas-test
cargo test --features test -- --nocapture
```

### Build and Test Together

```bash
make near_gas_test
```

## Test Output

The tests will output detailed gas consumption statistics:

```
=== Starting Gas Consumption Test ===

Deploying contract...
Testing with Alice's attestation data...
Using public key: ed25519:...

--- Gas Consumption Test: dcap-qvl::verify::verify() ---
Gas burnt: ... gas units
Result: Success
Gas consumed: ... TGas
Gas consumed: ... gas units

=== Gas Consumption Test Complete ===
```

## Notes

- The contract uses `dcap-qvl` from the parent project (via relative path dependency)
- Tests use `near-sandbox` for local blockchain testing
- The contract directly calls `dcap-qvl::verify::verify()` with quote bytes and collateral
- Sample attestation data is included in `tests/samples/` for testing
- The contract is simplified to only test the core `dcap-qvl::verify::verify()` function

## Troubleshooting

### Rust Version Issues

**Important**: NEAR sandbox requires Rust 1.86.0. Rust 1.87.0 or higher are **not supported** by NEAR's VM.

The contract uses Rust 1.86.0 (specified in `rust-toolchain.toml`). Some dependencies may try to pull in newer versions that require Rust 1.88.0+ (like `darling@0.23.0`). The `Cargo.toml` includes explicit version constraints to force compatible versions:

```toml
darling = "=0.21.3"
darling_core = "=0.21.3"
darling_macro = "=0.21.3"
```

If you encounter version conflicts, run:
```bash
cargo update -p darling@0.23.0 --precise 0.21.3
```

### WASM Path Issues

If the test fails to find the WASM file, ensure the contract has been built first using `make build_near_gas_test` or `cargo near build`.

### Sandbox Platform Compatibility

**Important**: `near-sandbox` currently only supports:
- Linux x86_64
- macOS ARM64 (Apple Silicon)

If you see `UnsupportedPlatformError("only linux-x86 and darwin-arm are supported")`, you're on an unsupported platform (e.g., macOS Intel/x86_64). 

**Workarounds**:
1. Use a Linux x86_64 machine or VM
2. Use an Apple Silicon Mac (M1/M2/M3)
3. Run tests in a Docker container with Linux x86_64

### Sandbox Issues

If `near-sandbox` fails to start, ensure you have the necessary system dependencies. On Linux, you may need to configure kernel parameters (see `near-sandbox` documentation).

### Build vs Check

Note: `cargo check` may fail with `near-sdk` errors because NEAR contracts must be built with `cargo near build`, not regular `cargo build`. This is expected behavior.

