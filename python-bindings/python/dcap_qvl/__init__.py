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

try:
    import requests
except ImportError:
    requests = None

from .dcap_qvl import (
    PyQuoteCollateralV3 as QuoteCollateralV3,
    PyVerifiedReport as VerifiedReport,
    PyQuote as Quote,
    py_verify as verify,
    parse_quote,
)

# Default Intel PCS URL
PCS_URL = "https://api.trustedservices.intel.com"


# Note: These functions are now implemented in Rust and imported above
# The manual parsing logic has been replaced with proper Rust-based parsing


def _make_pcs_request(url: str) -> bytes:
    """Make HTTP request to PCS endpoint."""
    if requests is None:
        raise ImportError(
            "requests library is required for collateral fetching. Install with: pip install requests")

    try:
        response = requests.get(url, timeout=30, verify=False)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch from {url}: {e}")


def get_collateral(pccs_url: str, raw_quote: bytes) -> QuoteCollateralV3:
    """Get collateral from PCCS URL.

    Args:
        pccs_url: PCCS server URL
        raw_quote: Raw quote bytes

    Returns:
        QuoteCollateralV3: Quote collateral data

    Raises:
        ValueError: If quote is invalid or FMSPC cannot be extracted
        RuntimeError: If network request fails
        ImportError: If requests library is not available
    """
    if not isinstance(raw_quote, (bytes, bytearray)):
        raise TypeError("raw_quote must be bytes")

    quote = Quote.parse(raw_quote)
    # Extract FMSPC from quote
    fmspc = quote.fmspc()

    # Determine if SGX or TDX
    is_tdx = quote.is_tdx()
    ca = quote.ca()

    # Build PCS endpoints
    base_url = pccs_url.rstrip('/')

    if is_tdx:
        # TDX endpoints
        pckcrl_url = f"{base_url}/tdx/certification/v4/pckcrl?ca={ca}&encoding=der"
        rootcacrl_url = f"{base_url}/tdx/certification/v4/rootcacrl"
        tcb_url = f"{base_url}/tdx/certification/v4/tcb?fmspc={fmspc}"
        qe_identity_url = f"{base_url}/tdx/certification/v4/qe/identity?update=standard"
    else:
        # SGX endpoints
        pckcrl_url = f"{base_url}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"
        rootcacrl_url = f"{base_url}/sgx/certification/v4/rootcacrl"
        tcb_url = f"{base_url}/sgx/certification/v4/tcb?fmspc={fmspc}"
        qe_identity_url = f"{base_url}/sgx/certification/v4/qe/identity?update=standard"

    # Fetch collateral data
    try:
        # Get PCK CRL and issuer chain
        pckcrl_response = _make_pcs_request(pckcrl_url)
        pck_crl = pckcrl_response
        pck_crl_issuer_chain = ""  # Would need to parse from response headers

        # Get Root CA CRL
        root_ca_crl = _make_pcs_request(rootcacrl_url)

        # Get TCB Info
        tcb_response = _make_pcs_request(tcb_url)
        tcb_data = json.loads(tcb_response.decode('utf-8'))
        tcb_info = json.dumps(tcb_data.get('tcbInfo', {}))
        tcb_info_issuer_chain = ""  # Would need to parse from response headers

        # Extract TCB signature
        tcb_signature_hex = tcb_data.get('signature', '')
        tcb_info_signature = bytes.fromhex(
            tcb_signature_hex) if tcb_signature_hex else b''

        # Get QE Identity
        qe_response = _make_pcs_request(qe_identity_url)
        qe_data = json.loads(qe_response.decode('utf-8'))
        qe_identity = json.dumps(qe_data.get('enclaveIdentity', {}))
        qe_identity_issuer_chain = ""  # Would need to parse from response headers

        # Extract QE signature
        qe_signature_hex = qe_data.get('signature', '')
        qe_identity_signature = bytes.fromhex(
            qe_signature_hex) if qe_signature_hex else b''

        return QuoteCollateralV3(
            pck_crl_issuer_chain=pck_crl_issuer_chain,
            root_ca_crl=root_ca_crl,
            pck_crl=pck_crl,
            tcb_info_issuer_chain=tcb_info_issuer_chain,
            tcb_info=tcb_info,
            tcb_info_signature=tcb_info_signature,
            qe_identity_issuer_chain=qe_identity_issuer_chain,
            qe_identity=qe_identity,
            qe_identity_signature=qe_identity_signature,
        )

    except Exception as e:
        raise RuntimeError(f"Failed to get collateral: {e}")


def get_collateral_from_pcs(raw_quote: bytes) -> QuoteCollateralV3:
    """Get collateral from Intel PCS.

    Args:
        raw_quote: Raw quote bytes

    Returns:
        QuoteCollateralV3: Quote collateral data

    Raises:
        ValueError: If quote is invalid or FMSPC cannot be extracted
        RuntimeError: If network request fails
        ImportError: If requests library is not available
    """
    return get_collateral(PCS_URL, raw_quote)


def get_collateral_and_verify(raw_quote: bytes, pccs_url: Optional[str] = None) -> VerifiedReport:
    """Get collateral and verify the quote.

    Args:
        raw_quote: Raw quote bytes
        pccs_url: Optional PCCS URL (defaults to Intel PCS)

    Returns:
        VerifiedReport: Verification result

    Raises:
        ValueError: If quote is invalid or verification fails
        RuntimeError: If network request fails
        ImportError: If requests library is not available
    """
    # Use provided PCCS URL or default to Intel PCS
    url = pccs_url.strip() if pccs_url else PCS_URL
    if not url:
        url = PCS_URL

    # Get collateral
    collateral = get_collateral(url, raw_quote)

    # Get current time
    now_secs = int(time.time())

    # Verify quote
    return verify(raw_quote, collateral, now_secs)


__all__ = [
    "QuoteCollateralV3",
    "VerifiedReport",
    "Quote",
    "verify",
    "get_collateral",
    "get_collateral_from_pcs",
    "get_collateral_and_verify",
]

__version__ = "0.3.0"
