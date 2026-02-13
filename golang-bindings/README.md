# DCAP-QVL Go Bindings

Go bindings for the DCAP-QVL (Data Center Attestation Primitives Quote Verification Library) via CGO + Rust FFI.

## Installation

```bash
go get github.com/Phala-Network/dcap-qvl/golang-bindings
```

Requires a pre-compiled `libdcap_qvl.a` static library for your platform. See [Building](#building) below.

## Usage

```go
package main

import (
	"fmt"
	"os"

	dcap "github.com/Phala-Network/dcap-qvl/golang-bindings"
)

func main() {
	raw, _ := os.ReadFile("quote.bin")

	// Parse quote
	q, err := dcap.ParseQuote(raw)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Quote type: %s, FMSPC: %s\n", q.QuoteType, q.FMSPC)

	// Fetch collateral and verify
	report, err := dcap.GetCollateralAndVerify(raw, dcap.PhalaPCCSURL)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Status: %s, Advisories: %v\n", report.Status, report.AdvisoryIDs)
}
```

## API

| Function | Description |
|----------|-------------|
| `ParseQuote(raw)` | Parse SGX/TDX quote binary |
| `Verify(raw, collateral, nowSecs)` | Verify quote with collateral (Intel production root CA) |
| `VerifyWithRootCA(raw, collateral, rootCADer, nowSecs)` | Verify with custom root CA |
| `GetCollateral(pccsURL, raw)` | Fetch collateral from PCCS |
| `GetCollateralForFMSPC(pccsURL, fmspc, ca, isSGX)` | Fetch collateral by FMSPC |
| `GetCollateralAndVerify(raw, pccsURL)` | Fetch collateral + verify in one call |
| `ParsePCKExtensionFromPEM(pem)` | Parse Intel SGX extension from PCK certificate PEM |
| `PCKExtension.GetValue(oid)` | Look up arbitrary OID in SGX extension (pure Go) |

## Building

The Go bindings link against a Rust static library. To build from source:

```bash
# 1. Build the Rust static library
cargo build --release --features go

# 2. Copy to the Go package lib directory
mkdir -p golang-bindings/lib/darwin_arm64   # adjust for your platform
cp target/release/libdcap_qvl.a golang-bindings/lib/darwin_arm64/

# 3. Run tests
cd golang-bindings && go test -v
```

Supported platforms: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`.

## Testing

```bash
# Unit tests (offline, uses sample fixtures)
cd golang-bindings && go test -v

# Integration tests (requires network, fetches from PCCS)
cd golang-bindings && go test -v -tags integration
```

## Requirements

- Go 1.21+
- Rust toolchain (for building `libdcap_qvl.a`)
- CGO enabled (`CGO_ENABLED=1`, the default)

## License

MIT License - see [../LICENSE](../LICENSE) for details.
