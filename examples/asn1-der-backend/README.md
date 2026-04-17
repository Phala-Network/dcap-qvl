# `asn1_der`-based downstream backend (example)

Reference implementation of [`dcap_qvl::config::Config`] backed by `asn1_der`
instead of the audited `x509-cert` + `der` stack. **Not part of the
audited `dcap-qvl` codebase** — copy and adapt.

## Why

`x509-cert` + `der` add roughly 37 KiB to a `wasm32-unknown-unknown` build
(`lto="fat"` + `wasm-opt -O`). For WASM smart contracts (NEAR, ink!, etc.)
that overhead matters. `asn1_der` is already a transitive dependency of
`dcap-qvl`, so a backend built on it adds no new dependencies and avoids
duplicating ASN.1 parsing logic.

To opt out of the audited backend, depend on `dcap-qvl` without the
`default-x509` feature:

```toml
[dependencies]
dcap-qvl = { version = "...", default-features = false, features = ["std", "ring"] }
```

This drops `der` and `x509-cert` from the build entirely. The trade-off
is that the non-generic entry points (`verify::verify`,
`intel::quote_fmspc`, `intel::quote_ca`, etc.) are gone — you must use
the `_with::<C>` variants and supply your own `Config` impl, which is
what this example provides.

## Layout

| File | Purpose |
|---|---|
| `src/lib.rs` | Re-exports + `Asn1DerConfig` bundle |
| `src/x509.rs` | `Asn1DerCertBackend` (`X509Codec`) + `Asn1DerParsedCert<'_>` (`ParsedCert`) — zero-copy via the `Parsed<'a>` GAT |
| `src/sig.rs` | `Asn1DerSigEncoder` (`EcdsaSigEncoder`) |
| `tests/conformance.rs` | Drop-in equivalence checks against `DefaultConfig` on the bundled SGX/TDX corpus |

## Usage

```rust
use asn1_der_backend_example::Asn1DerConfig;

let report = dcap_qvl::verify::verify_with::<Asn1DerConfig>(
    &raw_quote,
    &collateral,
    now_secs,
)?;
```

## Run it

```sh
cd examples/asn1-der-backend

# End-to-end demo against the bundled TDX sample (no args).
cargo run --example verify_sample

# Or with your own quote / collateral / now (unix secs):
cargo run --example verify_sample -- path/to/quote.bin path/to/collateral.json 1700000000

# Conformance tests vs DefaultConfig.
cargo test
```

The interesting line is in `examples/verify_sample.rs`:

```rust
let report = verify_with::<Asn1DerConfig>(&quote, &collateral, now)?;
```

That single type parameter is the entire opt-in surface — every X.509,
DER, and crypto operation downstream of that call goes through
`Asn1DerConfig`'s associated types.

## Adapting this for your project

1. Copy `src/x509.rs` and `src/sig.rs` into your crate.
2. Define your own `Config` impl picking the crypto provider you prefer
   (`RingCrypto`, `RustCryptoCrypto`, or your own `CryptoProvider`).
3. Run `tests/conformance.rs` against a corpus that matches your
   production traffic.
4. Audit the parser changes yourself — `dcap-qvl` only audits the
   in-tree `X509CertBackend` / `DerSigEncoder`.

## Caveats

- `Asn1DerParsedCert::issuer_dn` returns a comma-joined sequence of
  printable RDN values, **not** RFC 4514. It is sufficient for the
  substring matching `dcap_qvl::intel::pck_ca_with` performs (`"Processor"`
  / `"Platform"`), but is not a full DN renderer. If you need stable
  RFC 4514 output, add the formatting yourself.
- This crate handles only `PrintableString` (`0x13`), `UTF8String`
  (`0x0C`), and `IA5String` (`0x16`) inside RDN values. Intel's PCK certs
  use `PrintableString`; if your corpus contains other DirectoryString
  variants (`BMPString`, `TeletexString`, etc.), extend `STRING_TAGS`.
- This crate is **not audited**.
