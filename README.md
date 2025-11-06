
<!-- cargo-rdme start -->

# dcap-qvl

This crate implements the quote verification logic for DCAP (Data Center Attestation Primitives) in pure Rust. It supports both SGX (Software Guard Extensions) and TDX (Trust Domain Extensions) quotes.

# Features
- Verify SGX and TDX quotes
- Get collateral from PCCS
- Extract information from quotes

# Usage
Add the following dependency to your `Cargo.toml` file to use this crate:
```toml
[dependencies]
dcap-qvl = "0.1.0"
```

# Examples

## Get Collateral from PCCS_URL and Verify Quote

To get collateral from a PCCS_URL and verify a quote, you can use the following example code:
```rust
use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::verify;

#[tokio::main]
async fn main() {
    // Get PCCS_URL from environment variable. The URL is like "https://localhost:8081/sgx/certification/v4/".
    let pccs_url = std::env::var("PCCS_URL").expect("PCCS_URL is not set");
    let quote = std::fs::read("tdx_quote").expect("tdx_quote is not found");
    let collateral = get_collateral(&pccs_url, &quote, std::time::Duration::from_secs(10)).await.expect("failed to get collateral");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tcb = verify(&quote, &collateral, now).expect("failed to verify quote");
    println!("{:?}", tcb);
}
```

## Get Collateral from Intel PCS and Verify Quote

```rust
use dcap_qvl::collateral::get_collateral_from_pcs;
use dcap_qvl::verify::verify;

#[tokio::main]
async fn main() {
    let quote = std::fs::read("tdx_quote").expect("tdx_quote is not found");
    let collateral = get_collateral_from_pcs(&quote, std::time::Duration::from_secs(10)).await.expect("failed to get collateral");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let tcb = verify(&quote, &collateral, now).expect("failed to verify quote");
    println!("{:?}", tcb);
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
    # Get collateral from Intel PCS (async)
    quote_data = open("quote.bin", "rb").read()
    collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
    
    # Verify quote
    result = dcap_qvl.verify(quote_data, collateral, timestamp)
    print(f"Status: {result.status}")
    
    # Or get collateral and verify in one step (async)
    result = await dcap_qvl.get_collateral_and_verify(quote_data)
    print(f"Status: {result.status}")

# Run async code
asyncio.run(main())
```

See [python-bindings/](python-bindings/) for complete documentation, examples, and testing information.

# JavaScript/TypeScript Bindings

A pure JavaScript/TypeScript implementation is available, supporting both Node.js and browser environments.

## Installation

```bash
npm install @phala/dcap-qvl
```

## Usage

### Node.js

```javascript
import { verify, getCollateralFromPcs } from '@phala/dcap-qvl';
import { readFileSync } from 'fs';

// Get collateral from Intel PCS
const quoteData = readFileSync('quote.bin');
const collateral = await getCollateralFromPcs(quoteData);

// Verify quote
const timestamp = Math.floor(Date.now() / 1000);
const result = verify(quoteData, collateral, timestamp);
console.log(`Status: ${result.status}`);
console.log(`Advisory IDs: ${result.advisory_ids}`);
```

### Browser

```javascript
import { verify, getCollateralFromPcs } from '@phala/dcap-qvl/web';

// Fetch and verify quote
const response = await fetch('quote.bin');
const quoteData = new Uint8Array(await response.arrayBuffer());
const collateral = await getCollateralFromPcs(quoteData);

const timestamp = Math.floor(Date.now() / 1000);
const result = verify(quoteData, collateral, timestamp);
console.log(`Status: ${result.status}`);
```

## Development

```bash
# Build JavaScript package
cd dcap-qvl-js
npm install
npm run build

# Run tests
npm test

# Test with coverage
npm run test:coverage
```

See [dcap-qvl-js/](dcap-qvl-js/) for complete documentation and examples.

# License

This crate is licensed under the MIT license. See the LICENSE file for details.
