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

### Cross-repo auth (already set up)

The satellite push needs write access to a second repo, which the default
`GITHUB_TOKEN` can't grant. Instead of a user-level PAT, this uses a
**write-enabled deploy key** scoped to just `dcap-qvl-swift`:

- the public half is a read-write **deploy key** on `Phala-Network/dcap-qvl-swift`;
- the private half is the `SWIFT_REPO_SSH_KEY` secret on this repo.

Both were provisioned with the `gh` CLI (`gh repo deploy-key add --allow-write`
+ `gh secret set`). To rotate: `ssh-keygen` a new pair, replace the deploy key
and the secret. Without the secret the workflow still builds + checksums and
just skips the push with a warning.

### Dry run (no tag, no publish)

```
gh workflow run ios-release.yml -f tag=v0.0.0-test -f push_satellite=false
```

Builds the XCFramework and prints the checksum without touching any release or
the satellite repo.

## Unified versioning

A single **`v<X.Y.Z>`** tag releases every ecosystem at the same version:

| Workflow | Publishes |
| --- | --- |
| `release.yml` | `dcap-qvl` + `dcap-qvl-cli` → crates.io, CLI binaries, GitHub Release |
| `python-wheels.yml` | `dcap-qvl` wheels → PyPI |
| `android-aar.yml` | `com.phala:dcap-qvl-android` → Maven Central |
| `publish-npm.yml` | `@phala/dcap-qvl` → npm |
| `ios-release.yml` | Swift package → `dcap-qvl-swift` |

Bump every manifest to the new version first (root `Cargo.toml`,
`cli/Cargo.toml` + its `dcap-qvl` dep, `dcap-qvl-js/package.json`,
`dcap-qvl-mobile/Cargo.toml`), commit, then push the `v<X.Y.Z>` tag.

The per-ecosystem prefixes (`android-v*`, `npm-v*`) still work for releasing a
single ecosystem out of band, but the normal path is one `v*` tag for all.
