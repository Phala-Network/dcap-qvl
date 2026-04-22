"""Tests for async collateral API surface.

IMPORTANT: By default, these tests do **not** perform any network I/O.

To run the real (network) collateral retrieval smoke tests, set:

  DCAP_QVL_RUN_NETWORK_TESTS=1

in your environment.
"""

from __future__ import annotations

import inspect
import os

import pytest

from ._async_utils import is_async_callable


dcap_qvl = pytest.importorskip("dcap_qvl")

RUN_NETWORK = os.getenv("DCAP_QVL_RUN_NETWORK_TESTS") == "1"


def test_get_collateral_exported() -> None:
    assert hasattr(dcap_qvl, "get_collateral")
    assert callable(dcap_qvl.get_collateral)


@pytest.mark.asyncio
async def test_get_collateral_returns_awaitable() -> None:
    # Requires a running event loop for some PyO3 async exports.
    # Use an invalid URL and await to completion so no pending task survives
    # interpreter teardown.
    ret = dcap_qvl.get_collateral(
        pccs_url="://invalid-url",
        raw_quote=b"short",
    )
    assert inspect.isawaitable(ret)
    with pytest.raises(ValueError):
        await ret


@pytest.mark.asyncio
@pytest.mark.skipif(
    not RUN_NETWORK,
    reason="Network test disabled (set DCAP_QVL_RUN_NETWORK_TESTS=1 to enable)",
)
async def test_get_collateral_network_smoke() -> None:
    # Intel PCS / PCCS — uses the bundled cert_type 5 SGX sample.
    with open("sample/sgx_quote", "rb") as f:
        raw_quote = f.read()
    collateral = await dcap_qvl.get_collateral(
        pccs_url="https://api.trustedservices.intel.com",
        raw_quote=raw_quote,
    )

    # Just sanity-check shape/types (do NOT assert exact contents)
    assert collateral is not None
    assert isinstance(collateral.root_ca_crl, (bytes, bytearray))
    assert isinstance(collateral.pck_crl, (bytes, bytearray))
    assert isinstance(collateral.tcb_info, str)
    assert isinstance(collateral.qe_identity, str)
