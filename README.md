
<!-- cargo-rdme start -->

# dcap-qvl

This crate implements the quote verification logic for DCAP (Data Center Attestation Primitives) in pure Rust. It supports both SGX (Software Guard Extensions) and TDX (Trust Domain Extensions) quotes.

# Features
- Verify SGX and TDX quotes
- Get collateral from PCCS or Intel PCS
- Extract information from quotes
- Default PCCS: Phala Network (`https://pccs.phala.network`) - recommended for better availability and lower rate limits

# Usage
Add the following dependency to your `Cargo.toml` file to use this crate:
```toml
[dependencies]
dcap-qvl = "0.1.0"
```

# Crypto Backend Selection

This crate supports two crypto backends: **ring** (optimized, uses assembly) and **rustcrypto** (pure Rust).

## Gas/Performance Comparison (NEAR Contract)

| Backend | Gas Consumption |
|---------|-----------------|
| ring | ~175 Tgas |
| rustcrypto | ~288 Tgas |

Ring saves ~113 Tgas (~39%) compared to rustcrypto.

## Feature Flags

```toml
# Default: both backends enabled, ring takes priority
dcap-qvl = "0.3.11"

# For WASM/NEAR (recommended for gas efficiency):
dcap-qvl = { version = "0.3.11", default-features = false, features = ["std", "ring"] }

# For pure Rust / no-assembly environments:
dcap-qvl = { version = "0.3.11", default-features = false, features = ["std", "rustcrypto"] }
```

## Backend Selection Rules for `verify()`

The top-level `verify()` function selects backend based on enabled features:

| `ring` enabled | `rustcrypto` enabled | `verify()` uses |
|----------------|----------------------|-----------------|
| ✓ | ✓ | ring |
| ✓ | ✗ | ring |
| ✗ | ✓ | rustcrypto |
| ✗ | ✗ | compile error |

⚠️ **Important**: Due to Cargo's additive feature model, if **any** crate in your dependency tree enables the `ring` feature, the top-level `verify()` will use ring. This can lead to unexpected behavior in complex projects.

## Explicit Backend Selection (Recommended)

For predictable behavior, especially in complex projects, use explicit backend modules:

```rust
// Explicitly use ring backend
use dcap_qvl::verify::ring::verify;

// Explicitly use rustcrypto backend
use dcap_qvl::verify::rustcrypto::verify;
```

# Example

```rust
use dcap_qvl::collateral::get_collateral;
// Use explicit backend for predictable behavior
use dcap_qvl::verify::ring::verify;
use dcap_qvl::PHALA_PCCS_URL;

#[tokio::main]
async fn main() {
    let quote = std::fs::read("quote").expect("quote file not found");

    // Use default Phala PCCS, or override with custom URL
    let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
    let collateral = get_collateral(&pccs_url, &quote).await.expect("failed to get collateral");

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let report = verify(&quote, &collateral, now).expect("failed to verify quote");
    println!("{:?}", report);
}
```

<!-- cargo-rdme end -->

# Python Bindings

Python bindings are available for this crate, providing a Pythonic interface to the DCAP quote verification functionality.

## Quick Start

```bash
# Build and test Python bindings
make build_python
make test_python

# Test across Python versions (3.8-3.13)
make test_python_versions
```

## Usage

```python
import asyncio
import dcap_qvl

async def main():
    quote_data = open("quote.bin", "rb").read()

    # Get collateral and verify in one step (defaults to Phala PCCS)
    result = await dcap_qvl.get_collateral_and_verify(quote_data)
    print(f"Status: {result.status}")

asyncio.run(main())
```

See [python-bindings/](python-bindings/) for complete documentation, examples, and testing information.

# Android (Kotlin / Java) Bindings

Native Android bindings, generated from the same Rust core via [UniFFI](https://mozilla.github.io/uniffi-rs/)
and published to Maven Central as `com.phala:dcap-qvl-android`.

## Quick Start

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.phala:dcap-qvl-android:0.5.2")
}
```

## Usage

```kotlin
import com.phala.dcapqvl.*

// `collateralJson` is the raw PCCS response body — fetch it with your own
// HTTP stack (OkHttp / Ktor) and pass the bytes straight in.
val collateralJson: ByteArray = httpClient.get(pccsUrl).body()
val quote = parseQuote(rawQuote)
val report = verify(rawQuote, collateralJson, (System.currentTimeMillis() / 1000).toULong())
println("status=${report.status} advisories=${report.advisoryIds}")
```

Java callers use the same package via the generated types. Verification is
synchronous; wrap in `withContext(Dispatchers.IO)` off the main thread.

See [dcap-qvl-mobile/android/](dcap-qvl-mobile/android/) for complete documentation.

# Swift (iOS / macOS) Bindings

Native Swift bindings, generated via UniFFI and distributed as a Swift Package
backed by an `XCFramework`.

## Quick Start

```swift
// Package.swift
.package(url: "https://github.com/Phala-Network/dcap-qvl-swift", from: "0.5.2")
```

or in Xcode: **File → Add Package Dependencies…** and paste the URL.

## Usage

```swift
import DcapQvl

// `collateralJson` is the raw PCCS response body — fetch it via URLSession.
let (collateralJson, _) = try await URLSession.shared.data(from: pccsURL)
let quote = try parseQuote(rawQuote: rawQuote)
let report = try verify(
    rawQuote: rawQuote,
    collateralJson: collateralJson,
    nowSecs: UInt64(Date().timeIntervalSince1970)
)
print(report.status, report.advisoryIds)
```

See [dcap-qvl-mobile/ios/](dcap-qvl-mobile/ios/) for complete documentation.

# License

This crate is licensed under the MIT license. See the LICENSE file for details.
