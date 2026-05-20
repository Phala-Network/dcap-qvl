#!/usr/bin/env bash
# Build the Android AAR — cross-compile the Rust cdylib to all four ABIs,
# regenerate the Kotlin bindings, and assemble.
#
# Requires:
#   * Android NDK (>= r25). Set ANDROID_NDK_HOME or ANDROID_NDK_ROOT.
#   * cargo-ndk:  `cargo install cargo-ndk`
#   * JDK 17 and gradle 8+ (the Gradle wrapper bootstraps Gradle itself).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ANDROID_DIR="$CRATE_DIR/android"
JNI_DIR="$ANDROID_DIR/src/main/jniLibs"
KOTLIN_OUT="$ANDROID_DIR/src/main/java"

: "${ANDROID_NDK_HOME:=${ANDROID_NDK_ROOT:-}}"
if [[ -z "${ANDROID_NDK_HOME}" ]]; then
    echo "ANDROID_NDK_HOME or ANDROID_NDK_ROOT must point at an Android NDK install." >&2
    exit 1
fi

if ! command -v cargo-ndk >/dev/null; then
    echo "cargo-ndk not found. Install with: cargo install cargo-ndk" >&2
    exit 1
fi

cd "$CRATE_DIR"

# Cross-compile the four standard Android ABIs.
echo "==> Building Rust cdylib for Android ABIs"
cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86 \
    -t x86_64 \
    -o "$JNI_DIR" \
    build --release

# Generate Kotlin sources from the (host-built) cdylib metadata.
echo "==> Generating Kotlin bindings"
cargo build --release
mkdir -p "$KOTLIN_OUT"
cargo run --bin uniffi-bindgen -- generate \
    --library "$CRATE_DIR/target/release/libdcap_qvl_mobile.so" \
    --language kotlin \
    --config "$CRATE_DIR/uniffi.toml" \
    --out-dir "$KOTLIN_OUT"

# JNA looks for the host library under `<jna-arch>/lib<name>.so`. Drop the
# host-built .so into the test resources so the local JVM unit tests can run
# without an emulator.
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) JNA_ARCH=linux-x86-64 ;;
    aarch64|arm64) JNA_ARCH=linux-aarch64 ;;
    *) JNA_ARCH="" ;;
esac
if [[ -n "$JNA_ARCH" ]]; then
    TEST_RES="$ANDROID_DIR/src/test/resources/$JNA_ARCH"
    mkdir -p "$TEST_RES"
    cp "$CRATE_DIR/target/release/libdcap_qvl_mobile.so" "$TEST_RES/"
fi

# Assemble the AAR.
echo "==> Assembling AAR"
cd "$ANDROID_DIR"
./gradlew --no-daemon clean assembleRelease test

echo "==> AAR produced at: $ANDROID_DIR/build/outputs/aar/"
