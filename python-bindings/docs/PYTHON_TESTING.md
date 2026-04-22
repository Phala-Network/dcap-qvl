# Python Version Testing

This document describes how to test the DCAP-QVL Python bindings across multiple Python versions to ensure compatibility.

## Overview

The Python bindings support Python 3.8+ as specified in `pyproject.toml`. We provide automated testing scripts to verify compatibility across all supported versions.

## Supported Python Versions

- Python 3.8
- Python 3.9
- Python 3.10
- Python 3.11
- Python 3.12
- Python 3.13

## Testing Scripts

### 1. Shell Script (Quick Test)

```bash
# Run the shell script for a quick test
./tests/test_python_versions.sh

# Or use the Makefile target
make test_python_versions
```

**Features:**
- ✅ Fast execution
- ✅ Colored output
- ✅ Tests build, import, and basic functionality
- ✅ Continues testing even if one version fails
- ✅ Summary report at the end

## Test Process

Each Python version goes through the following test phases:

1. **Availability Check**: Verify the Python version is available via uv
2. **Environment Setup**: Create a clean virtual environment
3. **Dependency Installation**: Install maturin and build tools
4. **Build Test**: Compile the Rust extension for the Python version
5. **Import Test**: Verify the module can be imported successfully
6. **Basic Functionality Test**: Test core operations:
   - Create `QuoteCollateralV3` objects
   - JSON serialization/deserialization
   - Error handling with invalid data
   - Async collateral functions with `await` syntax
7. **Unit Tests**: Run pytest unit tests with async support (pytest-asyncio)
8. **Async Tests**: Test async collateral functions:
   - `get_collateral`
   - `get_collateral_from_pcs`
   - `get_collateral_and_verify`

## Example Output

```bash
$ make test_python_versions

============================================================
DCAP-QVL Python Version Compatibility Test
============================================================
ℹ️  Project root: /home/user/dcap-qvl
ℹ️  Testing Python versions: 3.8 3.9 3.10 3.11 3.12
✅ Using uv 0.8.3

============================================================
Testing Python 3.8
============================================================
ℹ️  Checking if Python 3.8 is available...
✅ Python 3.8 is available
ℹ️  Creating virtual environment...
ℹ️  Installing maturin...
ℹ️  Building Python extension...
✅ Build successful
ℹ️  Testing import...
✅ Import successful
ℹ️  Testing basic functionality...
✅ Basic functionality test passed
ℹ️  Installing pytest and running unit tests...
✅ Unit tests passed
✅ Python 3.8: All tests passed ✅

============================================================
Test Summary
============================================================
✅ Successful versions: 3.8 3.9 3.10 3.11 3.12

============================================================
Final Results
============================================================
✅ 🎉 All Python versions passed!
```

## Troubleshooting

### Common Issues

1. **Python Version Not Available**
   ```
   ⚠️  Python 3.x is not available
   ```
   **Solution**: Install the Python version via your system package manager or use uv to install it:
   ```bash
   uv python install 3.x
   ```

2. **Build Failures**
   ```
   ❌ Build failed: ...
   ```
   **Solution**: Check that you have:
   - Rust toolchain installed
   - Required system dependencies
   - Proper compilation flags for the target architecture

3. **Import Failures**
   ```
   ❌ Import failed: ...
   ```
   **Solution**: Usually indicates a build issue or missing runtime dependencies

### Manual Testing

If you need to test a specific Python version manually:

```bash
# Create environment with specific Python version
uv venv test-env --python 3.9

# Activate and install maturin
source test-env/bin/activate
pip install maturin

# Build and install
maturin develop --features python

# Test import
python -c "import dcap_qvl; print('Success!')"
```

## Continuous Integration

For CI/CD pipelines, you can use the testing scripts:

```yaml
# GitHub Actions example
- name: Test Python versions
  run: |
    ./python-bindings/tests/test_python_versions.sh

- name: Test async functions
  run: |
    cd python-bindings
    uv run python tests/test_all_async_functions.py
```

## Report Generation

The detailed Python script generates a JSON report (`python_version_test_report.json`) with:

```json
{
  "test_summary": {
    "total_versions": 5,
    "successful_versions": ["3.8", "3.9", "3.10", "3.11", "3.12"],
    "failed_versions": [],
    "success_rate": "5/5"
  },
  "detailed_results": [
    {
      "version": "3.8",
      "available": true,
      "build_success": true,
      "import_success": true,
      "basic_test_success": true,
      "unit_test_success": true,
      "errors": []
    }
  ]
}
```

## Makefile Targets

| Target | Description |
|--------|-------------|
| `make build_python` | Build Python bindings for current Python version |
| `make test_python` | Run basic Python functionality test |
| `make test_python_versions` | Test across all Python versions (shell script) |
| `make test_async` | Test async collateral functions with samples |
| `make test_async_comprehensive` | Run comprehensive async function tests |
| `make python_clean` | Clean Python build artifacts |

## Requirements

- **uv**: Modern Python package manager
- **Rust**: Rust toolchain for compilation
- **Python versions**: Target Python versions should be available on the system

## Best Practices

1. **Regular Testing**: Run version tests before releases
2. **CI Integration**: Include version testing in your CI pipeline
3. **Report Review**: Check detailed reports for any warnings or partial failures
4. **Environment Isolation**: Scripts use temporary environments to avoid conflicts
5. **Timeout Handling**: Each version test has a 5-minute timeout to prevent hanging
