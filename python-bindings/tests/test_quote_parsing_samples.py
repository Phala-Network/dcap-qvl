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


@pytest.mark.parametrize("sample_name", ["tdx_quote", "sgx_quote"])
def test_parse_pck_extension_from_pem(sample_name: str):
    """parse_pck_extension_from_pem should produce the same result as q.pck_extension()."""
    raw = _load_sample(sample_name)
    q = dcap_qvl.parse_quote(raw)
    pem = q.cert_chain_pem_bytes()
    assert pem is not None

    ext_from_quote = q.pck_extension()
    assert ext_from_quote is not None

    ext_from_pem = dcap_qvl.parse_pck_extension_from_pem(pem)
    assert ext_from_pem.fmspc == ext_from_quote.fmspc
    assert ext_from_pem.ppid == ext_from_quote.ppid
    assert ext_from_pem.cpu_svn == ext_from_quote.cpu_svn
    assert ext_from_pem.pce_svn == ext_from_quote.pce_svn
    assert ext_from_pem.pce_id == ext_from_quote.pce_id
    assert ext_from_pem.sgx_type == ext_from_quote.sgx_type


@pytest.mark.parametrize("sample_name", ["tdx_quote", "sgx_quote"])
def test_get_value_matches_typed_fields(sample_name: str):
    """get_value() for known OIDs should match the typed PckExtension fields."""
    raw = _load_sample(sample_name)
    q = dcap_qvl.parse_quote(raw)
    ext = q.pck_extension()
    assert ext is not None

    assert ext.get_value("1.2.840.113741.1.13.1.1") == bytes(ext.ppid)
    assert ext.get_value("1.2.840.113741.1.13.1.3") == bytes(ext.pce_id)
    assert ext.get_value("1.2.840.113741.1.13.1.4") == bytes(ext.fmspc)

    pcesvn_bytes = ext.get_value("1.2.840.113741.1.13.1.2.17")
    assert pcesvn_bytes is not None

    cpusvn_bytes = ext.get_value("1.2.840.113741.1.13.1.2.18")
    assert cpusvn_bytes is not None
    assert cpusvn_bytes == bytes(ext.cpu_svn)


@pytest.mark.parametrize("sample_name", ["tdx_quote", "sgx_quote"])
def test_get_value_missing_oid_returns_none(sample_name: str):
    """get_value() for a non-existent OID should return None."""
    raw = _load_sample(sample_name)
    ext = dcap_qvl.parse_quote(raw).pck_extension()
    assert ext is not None
    assert ext.get_value("1.2.840.113741.1.13.1.99") is None


def test_get_value_invalid_oid_raises():
    """get_value() with a malformed OID string should raise ValueError."""
    raw = _load_sample("tdx_quote")
    ext = dcap_qvl.parse_quote(raw).pck_extension()
    assert ext is not None
    with pytest.raises(ValueError):
        ext.get_value("not.a.valid.oid")


def test_parse_pck_extension_from_pem_bad_input():
    """parse_pck_extension_from_pem with invalid data should raise ValueError."""
    with pytest.raises(ValueError):
        dcap_qvl.parse_pck_extension_from_pem(b"not a PEM")
