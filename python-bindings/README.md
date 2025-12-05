# DCAP-QVL Python Bindings

This directory contains the Python bindings for the DCAP-QVL (Data Center Attestation Primitives Quote Verification Library) implemented in Rust.

## Directory Structure

```
python-bindings/
├── README.md                    # This file
├── pyproject.toml              # Python project configuration
├── uv.lock                     # uv lock file
├── python/                     # Python package source
│   └── dcap_qvl/
│       ├── __init__.py         # Main package with async API
├── examples/                   # Example scripts
│   ├── basic_test.py          # Basic functionality test
│   └── python_example.py      # Real-world usage example
├── tests/                      # All test files
│   ├── test_python_bindings.py      # Basic Python binding tests
│   ├── test_collateral_api.py       # Async collateral API tests
│   ├── test_all_async_functions.py  # Comprehensive async tests
│   ├── test_with_samples.py         # Tests with real sample data
│   ├── test_async_collateral.py     # Basic async collateral tests
│   ├── test_python_versions.sh      # Multi-version testing script
│   ├── test_cross_versions.sh       # Cross-version compatibility
│   └── test_installation.py         # Installation verification
├── scripts/                    # Build scripts
│   ├── build_wheels.py        # Wheel building script
│   └── build_wheels.sh         # Wheel building shell script
└── docs/                       # Documentation
    ├── README_Python.md        # Main Python bindings documentation
    ├── PYTHON_TESTING.md        # Python version testing guide
    └── BUILDING.md              # Build instructions
```

## Quick Start

### Building and Testing

```bash
# From the project root directory
make build_python                    # Build Python bindings
make test_python                     # Test basic functionality
make test_python_versions            # Test across Python versions

# Or directly from this directory
cd python-bindings
uv run maturin develop --features python
uv run python examples/basic_test.py
```

### Installation

```bash
# Using uv (recommended)
cd python-bindings
uv sync
uv run maturin develop --features python

# Using pip with maturin
pip install maturin
cd python-bindings
maturin develop --features python
```

## Features

- **Python 3.8+ Support**: Compatible with Python 3.8 through 3.13
- **Async API**: Full async/await support for collateral fetching and verification
- **Modern Tooling**: Uses uv for package management and maturin for building
- **Comprehensive Testing**: Automated testing across all supported Python versions
- **Clean API**: Pythonic async interface to the Rust library
- **Type Safety**: Proper error handling and type annotations with async support

## API Overview

```python
import asyncio
import dcap_qvl

async def main():
    # Get collateral from Intel PCS (async)
    quote_data = open("quote.bin", "rb").read()
    collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
    
    # Or get collateral for specific FMSPC (async)
    collateral = await dcap_qvl.get_collateral_for_fmspc(
        pccs_url="https://api.trustedservices.intel.com",
        fmspc="B0C06F000000",
        ca="processor",
        is_sgx=True
    )
    
    # Verify quote with collateral
    result = dcap_qvl.verify(quote_data, collateral, timestamp)
    print(f"Status: {result.status}")
    
    # Or get collateral and verify in one step (async)
    result = await dcap_qvl.get_collateral_and_verify(quote_data)
    print(f"Advisory IDs: {result.advisory_ids}")

# Run async code
asyncio.run(main())
```

## Documentation

- **[README_Python.md](docs/README_Python.md)**: Complete API documentation and usage guide
- **[PYTHON_TESTING.md](docs/PYTHON_TESTING.md)**: Python version compatibility testing guide

## Development

The Python bindings are built using:

- **[PyO3](https://pyo3.rs/)**: Rust bindings for Python
- **[maturin](https://github.com/PyO3/maturin)**: Build tool for Rust-based Python extensions
- **[uv](https://github.com/astral-sh/uv)**: Modern Python package management

### Adding New Features

1. Add Rust implementation in `../src/python.rs`
2. Update Python package in `python/dcap_qvl/__init__.py`
3. Add tests in `tests/` directory (use appropriate test file)
5. Update documentation in `docs/`

### Testing

The project includes comprehensive testing:

- **Unit tests**: Basic functionality testing with pytest
- **Async tests**: Full async/await testing with pytest-asyncio
- **Integration tests**: Real-world usage scenarios with sample data
- **Version compatibility**: Testing across Python 3.8-3.13
- **Cross-version testing**: Automated testing across multiple Python versions
- **CI/CD**: Automated testing in GitHub Actions

## Requirements

- Python 3.8+
- Rust toolchain (for building)
- uv (recommended) or pip with maturin

## License

MIT License - see [../LICENSE](../LICENSE) for details.