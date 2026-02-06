"""Unit tests for quote parsing using local sample data.

This replaces the old `test_with_samples.py` script-style test.
We keep the old script under `python-bindings/examples/` for reference.

These tests:
- do NOT perform any network access
- require the extension module to be built (e.g. via `maturin develop`)
"""

from __future__ import annotations

from pathlib import Path

import pytest


dcap_qvl = pytest.importorskip("dcap_qvl")


SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample"


def _load_sample(name: str) -> bytes:
    p = SAMPLE_DIR / name
    if not p.exists():
        pytest.skip(f"sample file not found: {p}")
    return p.read_bytes()


@pytest.mark.parametrize(
    "sample_name, expected_type",
    [
        ("tdx_quote", "TDX"),
        ("sgx_quote", "SGX"),
    ],
)
def test_parse_sample_quote(sample_name: str, expected_type: str):
    raw = _load_sample(sample_name)

    q = dcap_qvl.parse_quote(raw)
    assert q.quote_type() == expected_type

    hdr = q.header
    assert isinstance(hdr.version, int)
    assert isinstance(hdr.attestation_key_type, int)
    assert isinstance(hdr.tee_type, int)
    assert isinstance(hdr.qe_svn, int)
    assert isinstance(hdr.pce_svn, int)

    assert isinstance(hdr.qe_vendor_id, (bytes, bytearray))
    assert isinstance(hdr.user_data, (bytes, bytearray))
    assert len(hdr.qe_vendor_id) == 16
    assert len(hdr.user_data) == 20

    rep = q.report
    if expected_type == "TDX":
        # TDREPORT fields
        assert hasattr(rep, "rt_mr0")
        assert isinstance(rep.rt_mr0, (bytes, bytearray))
        assert len(rep.rt_mr0) == 48
        assert isinstance(rep.report_data, (bytes, bytearray))
        assert len(rep.report_data) == 64

    pem = q.cert_chain_pem_bytes()
    assert pem is not None
    assert isinstance(pem, (bytes, bytearray))
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")

    ext = q.pck_extension()
    if ext is not None:
        assert isinstance(ext.fmspc, (bytes, bytearray))
        assert len(ext.fmspc) == 6
        assert isinstance(ext.ppid, (bytes, bytearray))
        assert len(ext.ppid) > 0
