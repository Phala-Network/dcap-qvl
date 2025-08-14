# Python Bindings for DCAP-QVL

This package provides Python bindings for the DCAP (Data Center Attestation Primitives) quote verification library implemented in Rust.

## Quick Start

```bash
# Install from PyPI
pip install dcap-qvl

# Basic usage
python -c "
import dcap_qvl
print('DCAP-QVL Python bindings successfully installed!')
print(f'Available functions: {dcap_qvl.__all__}')
"
```

## Features

- Verify SGX and TDX quotes
- Handle quote collateral data
- Parse verification results
- Pure Rust implementation with Python bindings
- Cross-platform compatibility (Linux, macOS, Windows)
- Asynchronous collateral fetching from PCCS/PCS with async/await support
- Compatible with Python 3.8+

## Installation

### From PyPI (recommended)

```bash
pip install dcap-qvl
```

### Using uv

```bash
uv add dcap-qvl
```

## Usage

### Basic Quote Verification

```python
import dcap_qvl
import json
import time

# Load quote data (binary)
with open("path/to/quote", "rb") as f:
    quote_data = f.read()

# Load collateral data (JSON)
with open("path/to/collateral.json", "r") as f:
    collateral_json = json.load(f)

# Create collateral object
collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))

# Verify the quote
now = int(time.time())
try:
    result = dcap_qvl.verify(quote_data, collateral, now)
    print(f"Verification successful! Status: {result.status}")
    print(f"Advisory IDs: {result.advisory_ids}")
except ValueError as e:
    print(f"Verification failed: {e}")
```

### Working with Collateral Data

```python
# Create collateral manually
collateral = dcap_qvl.QuoteCollateralV3(
    pck_crl_issuer_chain="...",
    root_ca_crl=b"...",  # bytes
    pck_crl=b"...",      # bytes
    tcb_info_issuer_chain="...",
    tcb_info="...",      # JSON string
    tcb_info_signature=b"...",  # bytes
    qe_identity_issuer_chain="...",
    qe_identity="...",   # JSON string
    qe_identity_signature=b"...",  # bytes
)

# Serialize to JSON
json_str = collateral.to_json()

# Deserialize from JSON
collateral = dcap_qvl.QuoteCollateralV3.from_json(json_str)
```

## API Reference

### Async Collateral Functions

All collateral functions are asynchronous and must be awaited. They use the Rust async runtime for optimal performance.

#### `async get_collateral_for_fmspc(pccs_url: str, fmspc: str, ca: str, is_sgx: bool) -> QuoteCollateralV3`

Get collateral for a specific FMSPC directly from PCCS URL (Rust async export).

**Parameters:**
- `pccs_url`: PCCS URL (e.g., "https://api.trustedservices.intel.com")
- `fmspc`: FMSPC value as hex string (e.g., "B0C06F000000")
- `ca`: Certificate Authority ("processor" or "platform")
- `is_sgx`: True for SGX quotes, False for TDX quotes

**Returns:**
- `QuoteCollateralV3`: Quote collateral data

**Raises:**
- `ValueError`: If FMSPC is invalid or collateral cannot be retrieved
- `RuntimeError`: If network request fails

**Example:**
```python
import asyncio
import dcap_qvl

async def main():
    collateral = await dcap_qvl.get_collateral_for_fmspc(
        pccs_url="https://api.trustedservices.intel.com",
        fmspc="B0C06F000000",
        ca="processor",
        is_sgx=True
    )
    print(f"Got collateral: {len(collateral.tcb_info)} chars")

asyncio.run(main())
```

#### `async get_collateral(pccs_url: str, raw_quote: bytes) -> QuoteCollateralV3`

Get collateral from a custom PCCS URL by parsing the quote.

**Parameters:**
- `pccs_url`: PCCS URL (e.g., "https://api.trustedservices.intel.com")
- `raw_quote`: Raw quote data as bytes

**Returns:**
- `QuoteCollateralV3`: Quote collateral data

**Raises:**
- `ValueError`: If quote is invalid or FMSPC cannot be extracted
- `RuntimeError`: If network request fails

**Example:**
```python
import asyncio
import dcap_qvl

async def main():
    pccs_url = "https://api.trustedservices.intel.com"
    quote_data = open("quote.bin", "rb").read()
    collateral = await dcap_qvl.get_collateral(pccs_url, quote_data)
    print(f"Got collateral: {len(collateral.tcb_info)} chars")

asyncio.run(main())
```

#### `async get_collateral_from_pcs(raw_quote: bytes) -> QuoteCollateralV3`

Get collateral from Intel's PCS (default).

**Parameters:**
- `raw_quote`: Raw quote data as bytes

**Returns:**
- `QuoteCollateralV3`: Quote collateral data

**Raises:**
- `ValueError`: If quote is invalid or FMSPC cannot be extracted
- `RuntimeError`: If network request fails

**Example:**
```python
import asyncio
import dcap_qvl

async def main():
    quote_data = open("quote.bin", "rb").read()
    collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
    print(f"Got collateral from Intel PCS")

asyncio.run(main())
```

#### `async get_collateral_and_verify(raw_quote: bytes, pccs_url: Optional[str] = None) -> VerifiedReport`

Get collateral and verify quote in one step.

**Parameters:**
- `raw_quote`: Raw quote data as bytes
- `pccs_url`: Optional PCCS URL (uses Intel PCS if None)

**Returns:**
- `VerifiedReport`: Verification results

**Raises:**
- `ValueError`: If quote is invalid or verification fails
- `RuntimeError`: If network request fails

**Example:**
```python
import asyncio
import dcap_qvl

async def main():
    quote_data = open("quote.bin", "rb").read()
    result = await dcap_qvl.get_collateral_and_verify(quote_data)
    print(f"Status: {result.status}")
    print(f"Advisory IDs: {result.advisory_ids}")

asyncio.run(main())
```

### Classes

#### `QuoteCollateralV3`

Represents quote collateral data required for verification.

**Constructor:**
```python
QuoteCollateralV3(
    pck_crl_issuer_chain: str,
    root_ca_crl: bytes,
    pck_crl: bytes,
    tcb_info_issuer_chain: str,
    tcb_info: str,
    tcb_info_signature: bytes,
    qe_identity_issuer_chain: str,
    qe_identity: str,
    qe_identity_signature: bytes,
)
```

**Methods:**
- `to_json() -> str`: Serialize to JSON string
- `from_json(json_str: str) -> QuoteCollateralV3`: Create from JSON string (static method)

**Properties:**
- `pck_crl_issuer_chain: str`
- `root_ca_crl: bytes`
- `pck_crl: bytes`
- `tcb_info_issuer_chain: str`
- `tcb_info: str`
- `tcb_info_signature: bytes`
- `qe_identity_issuer_chain: str`
- `qe_identity: str`
- `qe_identity_signature: bytes`

#### `VerifiedReport`

Contains the results of quote verification.

**Properties:**
- `status: str`: Verification status
- `advisory_ids: List[str]`: List of advisory IDs

**Methods:**
- `to_json() -> str`: Serialize to JSON string

### Functions

#### `verify(raw_quote: bytes, collateral: QuoteCollateralV3, now_secs: int) -> VerifiedReport`

Verify a quote with the provided collateral data.

**Parameters:**
- `raw_quote`: Raw quote data as bytes
- `collateral`: Quote collateral data
- `now_secs`: Current timestamp in seconds since Unix epoch

**Returns:**
- `VerifiedReport`: Verification results

**Raises:**
- `ValueError`: If verification fails

## Development

### Building from Source

If you want to build from source or contribute to development:

```bash
# Clone the repository
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl/python-bindings

# Install development dependencies (including maturin)
uv sync

# Build and install the Python extension in development mode
uv run maturin develop --features python

# Run tests
uv run python -m pytest tests/test_python_bindings.py
```

**Note:** maturin is only required for building from source. Regular users installing from PyPI don't need maturin.

### Running Examples

After installing the package, you can run the examples:

```bash
# Download the examples from the repository
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl/python-bindings

# Basic functionality test
python examples/basic_test.py

# Full example (requires sample data files)
python examples/python_example.py
```

Or if you're using uv for development:

```bash
# Basic functionality test
uv run python examples/basic_test.py

# Full example (requires sample data files)
uv run python examples/python_example.py
```

### Testing Across Python Versions

The project includes comprehensive testing across all supported Python versions:

```bash
# Quick test across all Python versions
make test_python_versions

# Test current Python version only
make test_python
```

See [PYTHON_TESTING.md](PYTHON_TESTING.md) for detailed information about Python version compatibility testing.

## Requirements

### For regular usage (installing from PyPI):
- Python 3.8+

### For development (building from source):
- Python 3.8+
- Rust toolchain (rustc, cargo)
- maturin (automatically installed with `uv sync`)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.