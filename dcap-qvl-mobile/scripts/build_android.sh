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

# Stage sample quote fixtures for the JVM unit tests. We can't symlink them
# because Gradle's `processDebugUnitTestJavaRes` task refuses to follow
# symlinks; copying keeps the canonical fixtures in `sample/` and avoids
# duplicating committed data.
echo "==> Staging test fixtures"
TEST_RES_BASE="$ANDROID_DIR/src/test/resources"
mkdir -p "$TEST_RES_BASE"
for fixture in sgx_quote sgx_quote_collateral.json tdx_quote tdx_quote_collateral.json; do
    cp "$CRATE_DIR/../sample/$fixture" "$TEST_RES_BASE/$fixture"
done

# Drop the host-built .so into a known directory referenced by `jna.library.path`
# in build.gradle.kts, so the local JVM unit tests can dlopen it directly.
HOST_LIB_DIR="$ANDROID_DIR/build/host-jna"
mkdir -p "$HOST_LIB_DIR"
cp "$CRATE_DIR/target/release/libdcap_qvl_mobile.so" "$HOST_LIB_DIR/"

# Assemble the AAR. Prefer the Gradle wrapper when present (a developer can
# `gradle wrapper` once and commit it locally); otherwise fall back to the
# system `gradle` binary (which CI provides via `gradle/actions/setup-gradle`).
echo "==> Assembling AAR"
cd "$ANDROID_DIR"
if [[ -x "./gradlew" ]]; then
    GRADLE_CMD=("./gradlew")
elif command -v gradle >/dev/null; then
    GRADLE_CMD=("gradle")
else
    echo "Neither ./gradlew nor a system gradle was found. Install Gradle 8+ or" >&2
    echo "run \`gradle wrapper --gradle-version 8.10\` from $ANDROID_DIR first." >&2
    exit 1
fi
"${GRADLE_CMD[@]}" --no-daemon clean assembleRelease test

echo "==> AAR produced at: $ANDROID_DIR/build/outputs/aar/"
