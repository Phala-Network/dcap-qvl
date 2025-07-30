# Python Bindings for DCAP-QVL

This package provides Python bindings for the DCAP (Data Center Attestation Primitives) quote verification library implemented in Rust.

## Features

- Verify SGX and TDX quotes
- Handle quote collateral data
- Parse verification results
- Pure Rust implementation with Python bindings

## Installation

### Using uv (recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Build and install the Python package
uv pip install maturin
maturin develop --features python
```

### Using pip with maturin

```bash
pip install maturin
maturin develop --features python
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

```bash
# Clone the repository
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl

# Build the Python extension
uv run maturin develop --features python

# Run tests
uv run python -m pytest tests/test_python_bindings.py
```

### Running Examples

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

# Detailed test with JSON report
make test_python_versions_detailed

# Test current Python version only
make test_python
```

See [PYTHON_TESTING.md](PYTHON_TESTING.md) for detailed information about Python version compatibility testing.

## Requirements

- Python 3.8+
- Rust toolchain (for building from source)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.