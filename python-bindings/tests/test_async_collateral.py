"""Tests for async collateral API surface.

IMPORTANT: By default, these tests do **not** perform any network I/O.

To run the real (network) collateral retrieval smoke tests, set:

  DCAP_QVL_RUN_NETWORK_TESTS=1

in your environment.
"""

from __future__ import annotations

import os

import pytest

from ._async_utils import is_async_callable


dcap_qvl = pytest.importorskip("dcap_qvl")

RUN_NETWORK = os.getenv("DCAP_QVL_RUN_NETWORK_TESTS") == "1"


def test_get_collateral_for_fmspc_exported_and_async() -> None:
    assert hasattr(dcap_qvl, "get_collateral_for_fmspc")

    # `get_collateral_for_fmspc` may be a built-in function (PyO3) which returns
    # an awaitable but isn't detected by `inspect.iscoroutinefunction`.
    assert is_async_callable(
        dcap_qvl.get_collateral_for_fmspc,
        pccs_url="https://api.trustedservices.intel.com",
        fmspc="000000000000",
        ca="processor",
        for_sgx=True,
    )


@pytest.mark.asyncio
@pytest.mark.skipif(
    not RUN_NETWORK,
    reason="Network test disabled (set DCAP_QVL_RUN_NETWORK_TESTS=1 to enable)",
)
async def test_get_collateral_for_fmspc_network_smoke() -> None:
    # Intel PCS / PCCS
    collateral = await dcap_qvl.get_collateral_for_fmspc(
        pccs_url="https://api.trustedservices.intel.com",
        fmspc="B0C06F000000",
        ca="processor",
        for_sgx=True,
    )

    # Just sanity-check shape/types (do NOT assert exact contents)
    assert collateral is not None
    assert isinstance(collateral.root_ca_crl, (bytes, bytearray))
    assert isinstance(collateral.pck_crl, (bytes, bytearray))
    assert isinstance(collateral.tcb_info, str)
    assert isinstance(collateral.qe_identity, str)
