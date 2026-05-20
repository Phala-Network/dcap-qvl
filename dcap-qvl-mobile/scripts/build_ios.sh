#!/usr/bin/env bash
# Build the iOS XCFramework + generated Swift sources for the SwiftPM package.
#
# Requires macOS with Xcode (>= 14.0). Run from anywhere — the script anchors
# itself relative to its own location.
#
# Produces:
#   ios/DcapQvlFFI.xcframework/  — fat binary for arm64 device + arm64/x86_64 sim
#   ios/Sources/DcapQvl/DcapQvl.swift — generated UniFFI Swift bindings

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "build_ios.sh requires macOS (need Xcode for xcodebuild -create-xcframework)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
IOS_DIR="$CRATE_DIR/ios"
SOURCES_DIR="$IOS_DIR/Sources/DcapQvl"
XCFRAMEWORK="$IOS_DIR/DcapQvlFFI.xcframework"

# Targets: iOS device + iOS simulator (arm64 + x86_64 lipo'd into a sim slice)
# + macOS (arm64 + x86_64 lipo'd into a mac slice). The macOS slice is what
# `swift test` actually consumes when the test host is a Mac — without it
# SwiftPM can't resolve the binary-target module and the generated Swift fails
# with "cannot find type 'RustBuffer'".
TARGETS=(
    aarch64-apple-ios
    aarch64-apple-ios-sim
    x86_64-apple-ios
    aarch64-apple-darwin
    x86_64-apple-darwin
)

echo "==> Installing Rust targets"
for t in "${TARGETS[@]}"; do
    rustup target add "$t"
done

echo "==> Building cdylib + staticlib for each target"
cd "$CRATE_DIR"
for t in "${TARGETS[@]}"; do
    cargo build --release --target "$t"
done

# Combine simulator slices into one universal static library.
SIM_LIB="$CRATE_DIR/target/universal-ios-sim/libdcap_qvl_mobile.a"
mkdir -p "$(dirname "$SIM_LIB")"
lipo -create \
    "$CRATE_DIR/target/aarch64-apple-ios-sim/release/libdcap_qvl_mobile.a" \
    "$CRATE_DIR/target/x86_64-apple-ios/release/libdcap_qvl_mobile.a" \
    -output "$SIM_LIB"

# Same for macOS — one universal static library covering Apple Silicon + Intel.
MAC_LIB="$CRATE_DIR/target/universal-macos/libdcap_qvl_mobile.a"
mkdir -p "$(dirname "$MAC_LIB")"
lipo -create \
    "$CRATE_DIR/target/aarch64-apple-darwin/release/libdcap_qvl_mobile.a" \
    "$CRATE_DIR/target/x86_64-apple-darwin/release/libdcap_qvl_mobile.a" \
    -output "$MAC_LIB"

echo "==> Generating Swift bindings"
mkdir -p "$SOURCES_DIR"
cargo run --bin uniffi-bindgen -- generate \
    --library "$CRATE_DIR/target/aarch64-apple-ios/release/libdcap_qvl_mobile.a" \
    --language swift \
    --config "$CRATE_DIR/uniffi.toml" \
    --out-dir "$IOS_DIR/build/generated"

# Move generated Swift sources into the SwiftPM target.
cp "$IOS_DIR/build/generated/DcapQvl.swift" "$SOURCES_DIR/DcapQvl.swift"

# Stage headers + modulemap for the XCFramework.
HEADERS_DIR="$IOS_DIR/build/headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR"
cp "$IOS_DIR/build/generated/DcapQvlFFI.h" "$HEADERS_DIR/DcapQvlFFI.h"
cp "$IOS_DIR/build/generated/DcapQvlFFI.modulemap" "$HEADERS_DIR/module.modulemap"

echo "==> Assembling XCFramework"
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$CRATE_DIR/target/aarch64-apple-ios/release/libdcap_qvl_mobile.a" \
    -headers "$HEADERS_DIR" \
    -library "$SIM_LIB" \
    -headers "$HEADERS_DIR" \
    -library "$MAC_LIB" \
    -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK"

# Dump the resulting XCFramework structure to make module-resolution issues
# diagnosable from CI logs.
echo "==> XCFramework layout:"
find "$XCFRAMEWORK" -type f | sort
echo "==> Sample modulemap:"
find "$XCFRAMEWORK" -name 'module.modulemap' -print -exec cat {} \;

# Stage sample quote fixtures for the Swift unit tests. Symlinks work for
# SwiftPM but we mirror the Android side here for consistency and to make
# `swift test` work in a freshly-checked-out tree without manual setup.
echo "==> Staging test fixtures"
TEST_RES="$IOS_DIR/Tests/DcapQvlTests/Resources"
mkdir -p "$TEST_RES"
for fixture in sgx_quote sgx_quote_collateral.json tdx_quote tdx_quote_collateral.json; do
    cp "$CRATE_DIR/../sample/$fixture" "$TEST_RES/$fixture"
done

echo "==> Done"
echo "    XCFramework: $XCFRAMEWORK"
echo "    Swift sources: $SOURCES_DIR"
