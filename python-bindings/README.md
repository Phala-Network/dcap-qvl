# dcap-qvl for Python

Verify Intel SGX and TDX (DCAP) attestation quotes from Python, with a clean
async API. Built on the Rust [`dcap-qvl`](../) core via [PyO3](https://pyo3.rs/).

> Part of [**dcap-qvl**](../) — see the [main README](../README.md) for the
> library and the other language bindings.

## Install

```bash
pip install dcap-qvl
```

Wheels are published for CPython 3.8–3.13 on Linux, macOS, and Windows.

## Quick start

```python
import asyncio
import dcap_qvl

async def main():
    quote = open("quote.bin", "rb").read()

    # Fetch collateral and verify in one step (defaults to Phala's PCCS).
    result = await dcap_qvl.get_collateral_and_verify(quote)
    print("status:", result.status)
    print("advisories:", result.advisory_ids)

asyncio.run(main())
```

## API

```python
# One-step: fetch collateral from a PCCS and verify.
result = await dcap_qvl.get_collateral_and_verify(quote, pccs_url=None)

# Or do it in two steps.
collateral = await dcap_qvl.get_collateral("https://pccs.phala.network", quote)
collateral = await dcap_qvl.get_collateral_from_pcs(quote)   # Intel PCS
result = dcap_qvl.verify(quote, collateral, timestamp)        # synchronous

# Parse a quote without verifying.
quote_obj = dcap_qvl.parse_quote(raw_quote)
```

`result` is a `VerifiedReport` with `status`, `advisory_ids`, `report`, and
`ppid`. Collateral fetching is async; `verify()` itself is synchronous.

See [docs/README_Python.md](docs/README_Python.md) for the complete API
reference.

## Develop

Building the extension from source requires Rust 1.83 or newer. Build the
extension locally and run the tests:

```bash
# From the repo root
make build_python      # build the extension in-place
make test_python       # run the test suite (incl. multiple Python versions)

# Or directly, with uv
cd python-bindings
uv sync
uv run maturin develop --features python
uv run python examples/basic_test.py
```

Layout: Rust glue in [`../src/python.rs`](../src/python.rs), the Python package
in [`python/dcap_qvl/`](python/dcap_qvl/), tests in [`tests/`](tests/), and
build scripts in [`scripts/`](scripts/). Build details are in
[docs/BUILDING.md](docs/BUILDING.md); version-compatibility testing is in
[docs/PYTHON_TESTING.md](docs/PYTHON_TESTING.md).

## License

MIT — see [../LICENSE](../LICENSE).
