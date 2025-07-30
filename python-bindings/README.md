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
│       └── __init__.py
├── examples/                   # Example scripts
│   ├── basic_test.py          # Basic functionality test
│   └── python_example.py      # Real-world usage example
├── tests/                      # Test files
│   └── test_python_bindings.py
├── scripts/                    # Testing scripts
│   ├── test_python_versions.py   # Detailed version testing
│   └── test_python_versions.sh   # Quick version testing
└── docs/                       # Documentation
    ├── README_Python.md        # Main Python bindings documentation
    └── PYTHON_TESTING.md        # Python version testing guide
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

- **Python 3.8+ Support**: Compatible with Python 3.8 through 3.12
- **Modern Tooling**: Uses uv for package management and maturin for building
- **Comprehensive Testing**: Automated testing across all supported Python versions
- **Clean API**: Pythonic interface to the Rust library
- **Type Safety**: Proper error handling and type annotations

## API Overview

```python
import dcap_qvl

# Create collateral
collateral = dcap_qvl.QuoteCollateralV3.from_json(json_data)

# Verify quote
result = dcap_qvl.verify(quote_bytes, collateral, timestamp)

# Access results
print(f"Status: {result.status}")
print(f"Advisory IDs: {result.advisory_ids}")
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
3. Add tests in `tests/test_python_bindings.py`
4. Update documentation in `docs/`

### Testing

The project includes comprehensive testing:

- **Unit tests**: Basic functionality testing
- **Integration tests**: Real-world usage scenarios  
- **Version compatibility**: Testing across Python 3.8-3.12
- **CI/CD**: Automated testing in GitHub Actions

## Requirements

- Python 3.8+
- Rust toolchain (for building)
- uv (recommended) or pip with maturin

## License

MIT License - see [../LICENSE](../LICENSE) for details.