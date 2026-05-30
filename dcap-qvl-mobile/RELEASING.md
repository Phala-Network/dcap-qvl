# Releasing the mobile bindings

## Android (Maven Central)

Tag `android-v<X.Y.Z>` → `.github/workflows/android-aar.yml` builds, signs, and
auto-publishes `com.phala:dcap-qvl-android:<X.Y.Z>` to Maven Central (the
deployment auto-releases once it passes validation — no manual promotion).

One-time setup is documented in [`SONATYPE_ONBOARDING.md`](SONATYPE_ONBOARDING.md)
(namespace, signing key, and the `maven-central` environment secrets).

## iOS / macOS (Swift Package)

Tag `v<X.Y.Z>` (the unified release tag) → `.github/workflows/ios-release.yml`:

1. builds `DcapQvlFFI.xcframework` (device + simulator + macOS slices) via
   `scripts/build_ios.sh`;
2. zips it and computes the SwiftPM checksum;
3. attaches the zip to the `v<X.Y.Z>` GitHub Release on this repo;
4. pushes a matching `<X.Y.Z>` tag to the
   [`dcap-qvl-swift`](https://github.com/Phala-Network/dcap-qvl-swift)
   distribution repo, with a `Package.swift` whose `.binaryTarget` points at the
   release asset and pins its checksum.

Consumers then resolve `https://github.com/Phala-Network/dcap-qvl-swift` at the
matching version — the same `X.Y.Z` as crates.io / npm / Maven.

### Required secret (one-time)

The satellite push needs write access to a second repo, which the default
`GITHUB_TOKEN` can't grant. Add a repository (or `release`-environment) secret:

| Secret             | Value                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| `SWIFT_REPO_TOKEN` | A fine-grained PAT with **Contents: read/write** on `Phala-Network/dcap-qvl-swift` |

Without it the workflow still builds the XCFramework and computes the checksum
(handy for a dry run), and just skips the satellite push with a warning.

### Dry run (no tag, no publish)

```
gh workflow run ios-release.yml -f tag=v0.0.0-test -f push_satellite=false
```

Builds the XCFramework and prints the checksum without touching any release or
the satellite repo.

## Unified versioning

`crates.io`, `npm`, Maven Central, and SwiftPM all share one `X.Y.Z`. The iOS
pipeline keys on the bare `v<X.Y.Z>` tag; Android keeps its `android-v*` trigger
for now. Consolidating every ecosystem onto a single `v*` tag is a follow-up —
it only needs the existing per-ecosystem workflows' triggers pointed at `v*`.
