# dcap-qvl (Python)

Python bindings for **dcap-qvl**, a Rust implementation of Intel DCAP quote parsing and verification.

This package is designed to be a drop-in foundation for services that need to **parse SGX/TDX quotes** and (optionally) verify them with DCAP collateral.

- Package name: `dcap-qvl`
- Import name: `dcap_qvl`
- Supported Python: 3.8+

## Installation

### From PyPI

```bash
pip install dcap-qvl
```

### From source (local development)

```bash
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl

python -m pip install -U pip
python -m pip install -U maturin

# Editable install of the Python bindings (builds the Rust extension)
python -m pip install -e python-bindings
```

## Quickstart: parse a quote (Milestone 1 API)

```python
from __future__ import annotations

import dcap_qvl

raw = open("sample/tdx_quote", "rb").read()  # or any SGX/TDX quote bytes
q = dcap_qvl.Quote.parse(raw)

# Header
hdr = q.header
tee_type = dcap_qvl.TeeType(hdr.tee_type)
ak_type = dcap_qvl.AttestationKeyType(hdr.attestation_key_type)

print("version:", hdr.version)
print("tee_type:", tee_type.name)
print("ak_type:", ak_type.name)
print("qe_vendor_id:", hdr.qe_vendor_id.hex())
print("user_data:", hdr.user_data.hex())

# Report (TDX TDREPORT10/15 or SGX enclave report)
r = q.report
print("report type:", type(r).__name__)

# Quote-level identifiers derived from embedded PCK cert chain
print("fmspc:", q.fmspc())
print("ca:", q.ca())

# Embedded PCK certificate chain as PEM bytes (best-effort)
chain_pem = q.cert_chain_pem_bytes()
if chain_pem:
    print("pem chain bytes:", len(chain_pem))

# SGX extension values from leaf PCK cert (best-effort)
# If parsing fails, this returns None (no exception).
ext = q.pck_extension()
if ext:
    print("ppid:", ext.ppid_hex())
    print("fmspc (from ext):", ext.fmspc_hex())
```

### Notes on "best-effort" parsing

- `Quote.cert_chain_pem_bytes()` returns `bytes | None`.
- `Quote.pck_extension()` returns `PckExtension | None`.
  - If the SGX extension is missing or cannot be parsed, it returns `None` instead of raising.

This is intentional: quote parsing should remain robust even when optional certificate details are malformed.

## Verification (optional)

If you already have collateral (e.g. cached JSON), you can verify a quote:

```python
import json, time
import dcap_qvl

quote_data = open("sample/tdx_quote", "rb").read()
collateral_json = json.load(open("sample/tdx_quote_collateral.json"))
collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))

now = int(time.time())
report = dcap_qvl.verify(quote_data, collateral, now)
print(report.status)
print(report.advisory_ids)
```

## Async collateral APIs (network)

The package also exposes async helpers to fetch DCAP collateral (network):

- `await dcap_qvl.get_collateral_for_fmspc(pccs_url, fmspc, ca, is_sgx)`
- `await dcap_qvl.get_collateral(pccs_url, raw_quote)`
- `await dcap_qvl.get_collateral_from_pcs(raw_quote)`
- `await dcap_qvl.get_collateral_and_verify(raw_quote, pccs_url=None)`

These require running inside an asyncio event loop.

## Testing

From repo root:

```bash
python -m pip install -e python-bindings
pytest -q python-bindings/tests
```

Network tests are **disabled by default**. To enable:

```bash
DCAP_QVL_RUN_NETWORK_TESTS=1 pytest -q python-bindings/tests
```

## Documentation for LLM tools

A compact, machine-oriented reference is shipped in the wheel at:

- `dcap_qvl/llm.txt`

## License

MIT (see `LICENSE`).
