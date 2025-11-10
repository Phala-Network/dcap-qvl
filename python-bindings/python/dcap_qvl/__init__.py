"""
DCAP Quote Verification Library

This package provides Python bindings for the DCAP (Data Center Attestation Primitives)
quote verification library implemented in Rust.

Main classes:
- QuoteCollateralV3: Represents quote collateral data
- VerifiedReport: Contains verification results

Main functions:
- verify: Verify a quote with collateral data
- get_collateral: Get collateral from PCCS URL
- get_collateral_from_pcs: Get collateral from Intel PCS
- get_collateral_and_verify: Get collateral and verify quote
"""

import time
import json
from typing import Optional, Union

from .dcap_qvl import (
    PyQuoteCollateralV3 as QuoteCollateralV3,
    PyVerifiedReport as VerifiedReport,
    PyQuote as Quote,
    py_verify as verify,
    py_verify_with_root_ca as verify_with_root_ca,
    parse_quote,
    get_collateral_for_fmspc,
)

# Default Intel PCS URL
PCS_URL = "https://api.trustedservices.intel.com"


async def get_collateral(pccs_url: str, raw_quote: bytes) -> QuoteCollateralV3:
    """Get collateral from PCCS URL.

    Args:
        pccs_url: PCCS server URL
        raw_quote: Raw quote bytes

    Returns:
        QuoteCollateralV3: Quote collateral data

    Raises:
        ValueError: If quote is invalid or FMSPC cannot be extracted
        RuntimeError: If network request fails
    """
    if not isinstance(raw_quote, (bytes, bytearray)):
        raise TypeError("raw_quote must be bytes")

    quote = Quote.parse(raw_quote)
    fmspc = quote.fmspc()
    is_sgx = quote.is_sgx()
    ca = quote.ca()
    return await get_collateral_for_fmspc(pccs_url, fmspc, ca, is_sgx)


async def get_collateral_from_pcs(raw_quote: bytes) -> QuoteCollateralV3:
    """Get collateral from Intel PCS.

    Args:
        raw_quote: Raw quote bytes

    Returns:
        QuoteCollateralV3: Quote collateral data

    Raises:
        ValueError: If quote is invalid or FMSPC cannot be extracted
        RuntimeError: If network request fails
    """
    return await get_collateral(PCS_URL, raw_quote)


async def get_collateral_and_verify(
    raw_quote: bytes, pccs_url: Optional[str] = None
) -> VerifiedReport:
    """Get collateral and verify the quote.

    Args:
        raw_quote: Raw quote bytes
        pccs_url: Optional PCCS URL (defaults to Intel PCS)

    Returns:
        VerifiedReport: Verification result

    Raises:
        ValueError: If quote is invalid or verification fails
        RuntimeError: If network request fails
    """
    # Use provided PCCS URL or default to Intel PCS
    url = pccs_url.strip() if pccs_url else PCS_URL
    if not url:
        url = PCS_URL

    # Get collateral
    collateral = await get_collateral(url, raw_quote)

    # Get current time
    now_secs = int(time.time())

    print("Collateral:", collateral.to_json())
    # Verify quote
    return verify(raw_quote, collateral, now_secs)


__all__ = [
    "QuoteCollateralV3",
    "VerifiedReport",
    "Quote",
    "verify",
    "verify_with_root_ca",
    "get_collateral",
    "get_collateral_from_pcs",
    "get_collateral_and_verify",
    "get_collateral_for_fmspc",
    "parse_quote",
]

__version__ = "0.3.2"
