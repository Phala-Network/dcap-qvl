# dcap-qvl-cli

Command-line tool to **decode and verify** Intel SGX and TDX (DCAP) attestation quotes.

> Part of [**dcap-qvl**](../) — a pure-Rust verifier for SGX/TDX quotes. See the
> [main README](../README.md) for the library and the other language bindings.

## Install

```bash
cargo install dcap-qvl-cli
```

This installs a binary named **`dcap-qvl`**.

## Commands

The tool has three subcommands. Each takes a quote file, and `--hex` if that file
is hex-encoded rather than raw bytes.

### `verify` — fetch collateral and verify a quote

```bash
dcap-qvl verify quote.bin
```

Collateral is fetched from Phala's PCCS by default. Point it at another PCCS with
the `PCCS_URL` environment variable:

```bash
PCCS_URL=https://your-pccs/sgx/certification/v4/ dcap-qvl verify quote.bin
```

The verified report is printed as JSON on stdout; progress goes to stderr.

### `decode` — parse a quote into JSON

```bash
dcap-qvl decode quote.bin           # full parsed quote as JSON
dcap-qvl decode --hex quote.hex     # hex-encoded input
dcap-qvl decode --fmspc quote.bin   # print just the FMSPC
```

### `pckinfo` — extract Intel identifiers from the PCK certificate

```bash
dcap-qvl pckinfo quote.bin
```

## Run from source

```bash
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl
cargo run -p dcap-qvl-cli --bin dcap-qvl -- decode --hex sample/tdx-quote.hex | jq .
```

## License

MIT — see [../LICENSE](../LICENSE).
