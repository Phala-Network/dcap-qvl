# DCAP-QVL Go Bindings

Go bindings for `dcap-qvl` (DCAP Quote Verification Library) via CGO + Rust FFI.

## Install

```bash
go get github.com/Phala-Network/dcap-qvl/golang-bindings
```

## Quick Start (Recommended)

This package links a native static library (`libdcap_qvl.a`).  
On first build, you may see a linker error if that library is not installed yet.

Common errors:

- Linux: `cannot find -ldcap_qvl`
- macOS: `library 'dcap_qvl' not found`

Install the platform library from GitHub Release assets:

- Unix shells (`bash`/`zsh`):

```bash
DCAP_QVL_VERSION="$(go list -m -f '{{.Version}}' github.com/Phala-Network/dcap-qvl/golang-bindings)"
eval "$(go run github.com/Phala-Network/dcap-qvl/golang-bindings/cmd/install-lib@${DCAP_QVL_VERSION} --version ${DCAP_QVL_VERSION} --print-env)"
```

- PowerShell:

```powershell
$version = go list -m -f '{{.Version}}' github.com/Phala-Network/dcap-qvl/golang-bindings
go run github.com/Phala-Network/dcap-qvl/golang-bindings/cmd/install-lib@$version --version $version --print-env | Invoke-Expression
```

Then rebuild:

```bash
go build ./...
```

Notes:

- The installer downloads from GitHub Releases and verifies SHA256 via `checksums.txt`.
- Files are installed in your user cache dir (`os.UserCacheDir()`), not in your repo.
- If your dependency version is an unreleased branch / pseudo-version, or that release has no Go assets yet, the installer will fail with an explicit message. In that case, use source build mode below.

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

	q, err := dcap.ParseQuote(raw)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Quote type: %s, FMSPC: %s\n", q.QuoteType, q.FMSPC)

	report, err := dcap.GetCollateralAndVerify(raw, dcap.PhalaPCCSURL)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Status: %s, Advisories: %v\n", report.Status, report.AdvisoryIDs)
}
```

## API

| Function | Description |
| --- | --- |
| `ParseQuote(raw)` | Parse SGX/TDX quote binary |
| `Verify(raw, collateral, nowSecs)` | Verify quote with collateral (Intel production root CA) |
| `VerifyWithRootCA(raw, collateral, rootCADer, nowSecs)` | Verify with custom root CA |
| `GetCollateral(pccsURL, raw)` | Fetch collateral from PCCS |
| `GetCollateralForFMSPC(pccsURL, fmspc, ca, isSGX)` | Fetch collateral by FMSPC |
| `GetCollateralAndVerify(raw, pccsURL)` | Fetch collateral + verify in one call |
| `ParsePCKExtensionFromPEM(pem)` | Parse Intel SGX extension from PCK certificate PEM |
| `PCKExtension.GetValue(oid)` | Look up arbitrary OID in SGX extension (pure Go) |

## Installer Details

Installer command:

```bash
go run github.com/Phala-Network/dcap-qvl/golang-bindings/cmd/install-lib@<go-module-version> [flags]
```

Flags:

- `--version` (default: `latest`)
- `--repo` (default: `Phala-Network/dcap-qvl`)
- `--dir` (optional custom install dir)
- `--timeout` (default: `60s`)
- `--print-env` (prints a shell command that sets `CGO_LDFLAGS`)

Expected release asset naming:

- `libdcap_qvl_linux_amd64.a`
- `libdcap_qvl_linux_arm64.a`
- `libdcap_qvl_darwin_amd64.a`
- `libdcap_qvl_darwin_arm64.a`
- `checksums.txt`

## Build From Source (Maintainers / Advanced)

```bash
cargo build --release --features go

# Example (linux/amd64): point linker path to target output
export CGO_LDFLAGS="-L$(pwd)/target/release"
cd golang-bindings && go test -v ./...
```

## Testing

```bash
# Unit tests
cd golang-bindings && go test -v ./...

# Integration tests (network)
cd golang-bindings && go test -v -tags integration ./...
```

## Requirements

- Go 1.21+
- CGO enabled (`CGO_ENABLED=1`)
- A compatible `libdcap_qvl.a` installed and discoverable by the linker

## License

MIT License - see [../LICENSE](../LICENSE).
