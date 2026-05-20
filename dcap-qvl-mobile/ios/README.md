# dcap-qvl for iOS / macOS

Native Swift Package for [`dcap-qvl`](../../). Distributed as a SwiftPM module
backed by `DcapQvlFFI.xcframework` (Rust static libs for `arm64` device +
`arm64`/`x86_64` simulator).

## Install

In your `Package.swift`:

```swift
.package(url: "https://github.com/Phala-Network/dcap-qvl", from: "0.4.1")
```

Or in Xcode: **File → Add Package Dependencies…** and paste the URL.

## Use

```swift
import DcapQvl

let raw = try Data(contentsOf: quoteURL)
let quote = try parseQuote(rawQuote: raw)

// Fetch the collateral JSON via URLSession and pass the raw bytes straight
// in — no field-by-field marshalling needed.
let (collateralJson, _) = try await URLSession.shared.data(from: pccsURL)
let report = try verify(
    rawQuote: raw,
    collateralJson: collateralJson,
    nowSecs: UInt64(Date().timeIntervalSince1970)
)
print(report.status, report.advisoryIds)
```

Verification is synchronous and CPU-bound — wrap in `Task.detached` or
`DispatchQueue.global` if calling from `@MainActor`.

## Build from source

Requires:

* macOS (Xcode 14+) — the XCFramework packaging step (`xcodebuild
  -create-xcframework`) is macOS-only.
* Rust toolchain with iOS targets:
  `rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios`

Then:

```bash
make build_mobile_ios   # from repository root
```

Produces `ios/DcapQvlFFI.xcframework/` and writes the UniFFI-generated Swift
sources into `ios/Sources/DcapQvl/`.

## Tests

```bash
make test_mobile_ios
```

Runs `swift test` against the iOS SwiftPM target. The Rust-side smoke tests
(under `dcap-qvl-mobile/tests/`) can additionally be run on any platform via
`cargo test`.

## Limitations

* Same as Android — no PCCS HTTP client, no async runtime, no encrypted-PPID
  PCK fetch flow. Verify-only.
* visionOS, watchOS, tvOS slices are not built by default. Add them to
  `scripts/build_ios.sh` if you need them.
