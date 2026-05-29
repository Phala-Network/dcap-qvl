# Maven Central / Sonatype Onboarding Checklist

This is a one-time setup the maintainers need to complete before the
`.github/workflows/android-aar.yml` workflow can publish to Maven Central.
Once done, every push of an `android-v<X.Y.Z>` tag will publish the AAR.

## 1. Claim the `com.phala` namespace

1. Sign in at **https://central.sonatype.com** (Google or GitHub auth is fine).
2. Open **Namespaces → Add Namespace**.
3. Enter `com.phala` and select **I'd like to verify by DNS**.
4. Sonatype shows a verification code like `1a2b3c4d-...`.
5. Add it to the **phala.com** DNS as a `TXT` record on the apex:

   ```
   phala.com.   IN   TXT   "sonatype-verify:1a2b3c4d-..."
   ```

6. Wait for the record to propagate (a few minutes), then click **Verify**.
7. Approval is usually instant once DNS matches.

After approval, you can publish anything under `com.phala.*`.

## 2. Generate a PGP key for signing

Maven Central requires every artifact to be PGP-signed. (Sigstore keyless
signing is now *accepted* by the Central Portal but remains optional and
additive — PGP is still mandatory, so we can't skip the key.)

```bash
gpg --batch --gen-key <<'EOF'        # RSA 4096, no expiry, no passphrase
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign,cert
Name-Real: Phala Release Signing
Name-Email: dev@phala.com
Expire-Date: 0
%commit
EOF
gpg --list-secret-keys --keyid-format=long
# Note the long key id, e.g. ABCDEF0123456789

# Publish the public half so Maven Central can verify the signature.
gpg --keyserver keyserver.ubuntu.com --send-keys ABCDEF0123456789
gpg --keyserver keys.openpgp.org    --send-keys ABCDEF0123456789

# Export the private half for CI (ASCII-armored).
gpg --armor --export-secret-keys ABCDEF0123456789 > signing-key.asc
```

We generate the key **without a passphrase**: the `maven-central` GitHub
Environment is the trust boundary, and a passphrase stored next to the key
in the same environment adds nothing. If instead you keep the key in a
plaintext backup, set a passphrase (`gpg --change-passphrase <id>`, re-export,
add the `SIGNING_PASSWORD` secret) — the build script treats it as optional.

Keep `signing-key.asc` out of git — it goes into a GitHub secret below.
Store it (and the revocation cert `gpg` wrote under
`~/.gnupg/openpgp-revocs.d/`) in an encrypted backup.

## 3. Mint a Central user token

1. On https://central.sonatype.com, open **Account → Generate User Token**.
2. Copy both the token **name** and **value** — you'll only see the value once.

## 4. Wire up GitHub repository secrets

Create a GitHub **Environment** called `maven-central` (Settings →
Environments → New environment). Optionally protect it with required
reviewers so each release needs explicit approval.

Add these four secrets to the environment:

| Secret name        | Value                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `OSSRH_USERNAME`   | User token **name** from step 3                                      |
| `OSSRH_TOKEN`      | User token **value** from step 3                                     |
| `SIGNING_KEY_ID`   | The 8- or 16-char short id of the PGP key (last digits of the long id) |
| `SIGNING_KEY`      | Contents of `signing-key.asc` (paste the whole ASCII-armored block)   |

Optional fifth secret — only if you protected the key with a passphrase:

| Secret name        | Value                                                                |
| ------------------ | -------------------------------------------------------------------- |
| `SIGNING_PASSWORD` | The passphrase. Omit entirely for an unprotected key.                |

The workflow consumes these via `ORG_GRADLE_PROJECT_*` env vars, which
Gradle automatically exposes as project properties.

## 5. Smoke-test the workflow

```
gh workflow run android-aar.yml -f publish_target=none
```

This builds + tests but doesn't publish, confirming the toolchain wiring.

## 6. Cut the first release

```
git tag android-v0.5.0
git push origin android-v0.5.0
```

The workflow:

1. cross-compiles the four Android ABIs via cargo-ndk;
2. regenerates Kotlin sources via `uniffi-bindgen`;
3. assembles the AAR;
4. runs the JVM unit tests;
5. signs + uploads to Sonatype Central.

After the upload, the Central portal will show the deployment under
**Deployments**. The first release of a new namespace needs to be
manually promoted from staging to public (later releases auto-promote
if you tick the "Auto-publish" checkbox).

Consumers can then add:

```kotlin
dependencies {
    implementation("com.phala:dcap-qvl-android:0.5.0")
}
```

## Notes / Pitfalls

- **Source of truth for version:** the workflow patches
  `dcap-qvl-mobile/android/build.gradle.kts` with the tag's version before
  publishing, so the tag is authoritative. The committed value just needs
  to be a valid SemVer.
- **Pre-releases:** Sonatype accepts SemVer pre-release markers
  (`0.5.0-rc.1`, `0.5.0-beta.1`); tag them `android-v0.5.0-rc.1`.
- **Forgotten DNS verify:** once verified, leave the TXT record in place —
  Sonatype may re-check periodically.
- **Key rotation:** to rotate the PGP key, generate a new one, publish it,
  update the `SIGNING_*` secrets. Old releases stay valid because the
  signature is verified against the published key, not the current one.

## Reducing raw-key exposure (optional hardening)

The CI needs the raw PGP private key because Maven Central mandates a PGP
signature and there's no token-less "trusted publishing" for Maven Central
yet (unlike npm/PyPI). Ways to shrink the blast radius, in increasing effort:

1. **GitHub Environment + required reviewers** (already wired) — the key
   secret is only readable from the gated `maven-central` environment, and a
   release can require human approval before the job runs.
2. **Dedicated signing subkey, master kept offline** — generate a signing
   *subkey*, export only that to CI, and keep the certifying master key
   offline. If the CI secret leaks you revoke the subkey, not the whole
   identity. Best effort-to-payoff ratio.
3. **Cloud KMS / HSM signing** — the private key never leaves a hardware
   module; CI calls a "sign this digest" API authenticated via GitHub OIDC
   (no stored cloud creds). Strongest, but GPG-over-KMS tooling is fiddly —
   usually overkill for a single library.
4. **Sigstore keyless signatures** — can be *added* alongside PGP (the Central
   Portal validates `.sigstore.json` files) for OIDC-based provenance, but
   cannot *replace* the mandatory PGP signature today.
