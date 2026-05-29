# dcap-qvl Mobile Bindings

Native Kotlin and Swift bindings for [`dcap-qvl`](../), built with
[UniFFI](https://mozilla.github.io/uniffi-rs/). A single Rust crate
(`dcap-qvl-mobile`) defines the FFI surface; `uniffi-bindgen` emits idiomatic
Kotlin and Swift sources that are shipped with the platform-specific build
artifacts.

| Platform | Artifact                       | Package                   |
| -------- | ------------------------------ | ------------------------- |
| Android  | `dcap-qvl-android.aar`         | `com.phala:dcap-qvl-android` |
| iOS      | `DcapQvl` Swift Package + `DcapQvlFFI.xcframework` | `DcapQvl` (SPM target)   |

## API surface (v1)

The bindings expose the same offline verification surface as the Go binding —
caller fetches collateral from PCCS via native HTTP, then passes it in.

```kotlin
// Kotlin — collateralJson is the raw PCCS response body
val quote: Quote = parseQuote(rawQuote)
val report: VerifiedReport = verify(rawQuote, collateralJson, nowSecs)
val report2: VerifiedReport = verifyWithRootCa(rawQuote, collateralJson, rootCaDer, nowSecs)
val ext: PckExtension = parsePckExtensionFromPem(pemBytes)
```

```swift
// Swift — collateralJson is the raw PCCS response body
let quote: Quote = try parseQuote(rawQuote: rawQuote)
let report = try verify(rawQuote: rawQuote, collateralJson: collateralJson, nowSecs: now)
let report2 = try verifyWithRootCa(rawQuote: rawQuote, collateralJson: collateralJson,
                                   rootCaDer: rootCaDer, nowSecs: now)
let ext = try parsePckExtensionFromPem(pem: pemBytes)
```

## Layout

```
dcap-qvl-mobile/
├── Cargo.toml          # depends on dcap-qvl (default-features=false, +std +ring +default-x509)
├── uniffi.toml         # binding-language config (Kotlin package, Swift module name)
├── src/                # Rust source — UniFFI proc-macro types and exported fns
│   ├── lib.rs
│   ├── types.rs        # UniFFI-friendly Record/Enum mirrors of dcap_qvl types
│   └── errors.rs       # DcapError enum
├── tests/              # Rust-side smoke tests using the binding surface
├── ios/                # Swift Package (Package.swift + Sources/ + Tests/)
├── android/            # Gradle library project (AAR)
└── scripts/
    ├── build_ios.sh        # cross-compile + xcodebuild XCFramework
    └── build_android.sh    # cross-compile via cargo-ndk + assembleRelease
```

## Build & test

```bash
# Rust side (works anywhere a Rust toolchain is installed)
make test_mobile_rust

# iOS (requires macOS + Xcode + Rust apple targets)
make build_mobile_ios
make test_mobile_ios

# Android (requires Android NDK + cargo-ndk + JDK 17)
make build_mobile_android
make test_mobile_android
```

See [`android/README.md`](android/README.md) and [`ios/README.md`](ios/README.md)
for platform-specific requirements.

## Design notes

* **Offline verification only.** Mobile apps fetch PCCS collateral with
  OkHttp / URLSession and pass the JSON in. This keeps the mobile binary
  small (no `reqwest`/`tokio` on-device) and lets apps use platform-native
  HTTP with proper certificate pinning, proxy support, etc.
* **`ring` backend only.** Smaller and faster than `rustcrypto`; matches the
  default used by the Go binding.
* **Type mirrors, not opaque handles.** `Quote`, `VerifiedReport`, etc. are
  exposed as Kotlin data classes / Swift structs. The shape mirrors
  [`src/ffi.rs`](../src/ffi.rs) so downstream tooling has one canonical schema.
* **No async on the wire.** The verifier is synchronous. Callers can wrap in
  `withContext(Dispatchers.IO)` on Kotlin or `Task.detached` on Swift.
