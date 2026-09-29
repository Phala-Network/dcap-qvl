# NEAR Gas Tests for DCAP-QVL

This directory contains NEAR smart contract integration tests for measuring gas consumption of dcap-qvl verification operations.

## Overview

The `dcap-qvl-gas-test` contract exposes `verify` and `verify_with_policy`, which call
`QuoteVerifier::verify` and `QuoteVerifier::verify_with_policy` on the sample quote in
`contracts/gas-test/tests/quote/`. The test measures the gas burnt by each call and fails if
`verify` exceeds `MAX_VERIFY_GAS` or if `verify_with_policy` costs more than
`MAX_CLAIMS_OVERHEAD_GAS` on top of `verify` (see `tests/constants.rs`). CI runs it on every PR
with both crypto backends.

## Prerequisites

- [cargo-near](https://github.com/near/cargo-near)
- Linux x86_64 or macOS ARM64 (required by `near-sandbox`)

## Running

From the `dcap-qvl` project root:

```bash
make test_near_gas                          # rustcrypto backend
make test_near_gas NEAR_GAS_BACKEND=ring     # ring backend
```

Sample output:

```
verify: 98.2 TGas (98162610346450 gas)
verify_with_policy: 99.5 TGas (99520700012074 gas)
```

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

If the test fails to find the WASM file, ensure the contract has been built first using `make test_near_gas` or `cargo near build non-reproducible-wasm --features test`.

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

