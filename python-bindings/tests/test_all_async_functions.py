"""Tests for async collateral functions.

This file used to be a script-like demo. It is now a pytest-friendly test module.

By default we only test *API surface* (functions exist, are async, and do basic
input validation checks).

To enable real network calls (Intel PCS), set:

  DCAP_QVL_RUN_NETWORK_TESTS=1
"""

from __future__ import annotations

import inspect
import os

import pytest

from ._async_utils import is_async_callable


dcap_qvl = pytest.importorskip("dcap_qvl")

RUN_NETWORK = os.getenv("DCAP_QVL_RUN_NETWORK_TESTS") == "1"


def test_async_functions_are_exported() -> None:
    expected = [
        "get_collateral_for_fmspc",
        "get_collateral",
        "get_collateral_from_pcs",
        "get_collateral_and_verify",
    ]

    for name in expected:
        assert hasattr(dcap_qvl, name), f"{name} is not exported"

    # get_collateral_for_fmspc may require a running event loop to even create
    # the awaitable. We only assert its existence here and check awaitable-ness
    # in an async test below.
    assert callable(dcap_qvl.get_collateral_for_fmspc)

    # These are Python-level async wrappers.
    assert is_async_callable(
        dcap_qvl.get_collateral,
        "http://example.com",
        b"short",
    )
    assert is_async_callable(dcap_qvl.get_collateral_from_pcs, b"short")
    assert is_async_callable(dcap_qvl.get_collateral_and_verify, b"short")


@pytest.mark.asyncio
async def test_get_collateral_for_fmspc_returns_awaitable() -> None:
    # In PyO3, this can be a built-in that requires a running event loop.
    ret = dcap_qvl.get_collateral_for_fmspc(
        pccs_url="https://api.trustedservices.intel.com",
        fmspc="000000000000",
        ca="processor",
        for_sgx=True,
    )
    assert inspect.isawaitable(ret)
    if inspect.iscoroutine(ret):
        ret.close()


@pytest.mark.asyncio
async def test_get_collateral_rejects_non_bytes_quote() -> None:
    with pytest.raises(TypeError, match="raw_quote must be bytes"):
        await dcap_qvl.get_collateral("http://example.com", "not bytes")


@pytest.mark.asyncio
async def test_get_collateral_from_pcs_rejects_invalid_quote() -> None:
    with pytest.raises(ValueError, match="Failed to parse quote"):
        await dcap_qvl.get_collateral_from_pcs(b"short")


@pytest.mark.asyncio
async def test_get_collateral_and_verify_rejects_invalid_quote() -> None:
    with pytest.raises(ValueError, match="Failed to parse quote"):
        await dcap_qvl.get_collateral_and_verify(b"short")


@pytest.mark.asyncio
@pytest.mark.skipif(
    not RUN_NETWORK,
    reason="Network test disabled (set DCAP_QVL_RUN_NETWORK_TESTS=1 to enable)",
)
async def test_get_collateral_from_pcs_network_smoke(sample_sgx_quote_bytes: bytes) -> None:
    # This calls Intel PCS (network). Only do a very light smoke test.
    collateral = await dcap_qvl.get_collateral_from_pcs(sample_sgx_quote_bytes)
    assert collateral is not None


@pytest.fixture
def sample_sgx_quote_bytes() -> bytes:
    # Local sample file (no network)
    with open("sample/sgx_quote", "rb") as f:
        return f.read()
