
<!-- cargo-rdme start -->

# dcap-qvl

This crate implements the quote verification logic for DCAP (Data Center Attestation Primitives) in pure Rust. It supports both SGX (Software Guard Extensions) and TDX (Trust Domain Extensions) quotes.

# Features
- Verify SGX and TDX quotes
- Get collateral from PCCS or Intel PCS
- Extract information from quotes
- Default PCCS: Phala Network (`https://pccs.phala.network`) - recommended for better availability and lower rate limits

# Usage
Add the following dependency to your `Cargo.toml` file to use this crate:
```toml
[dependencies]
dcap-qvl = "0.1.0"
```

# Example

```rust
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::verify;
use dcap_qvl::PHALA_PCCS_URL;

#[tokio::main]
async fn main() {
    let quote = std::fs::read("quote").expect("quote file not found");

    // Use default Phala PCCS, or override with custom URL
    let pccs_url = std::env::var("PCCS_URL").unwrap_or_else(|_| PHALA_PCCS_URL.to_string());
    let collateral = get_collateral(&pccs_url, &quote).await.expect("failed to get collateral");

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let report = verify(&quote, &collateral, now).expect("failed to verify quote");
    println!("{:?}", report);
}
```

<!-- cargo-rdme end -->

# Python Bindings

Python bindings are available for this crate, providing a Pythonic interface to the DCAP quote verification functionality.

## Quick Start

```bash
# Build and test Python bindings
make build_python
make test_python

# Test across Python versions (3.8-3.12)
make test_python_versions
```

## Usage

```python
import asyncio
import dcap_qvl

async def main():
    quote_data = open("quote.bin", "rb").read()

    # Get collateral and verify in one step (defaults to Phala PCCS)
    result = await dcap_qvl.get_collateral_and_verify(quote_data)
    print(f"Status: {result.status}")

asyncio.run(main())
```

See [python-bindings/](python-bindings/) for complete documentation, examples, and testing information.

# License

This crate is licensed under the MIT license. See the LICENSE file for details.
