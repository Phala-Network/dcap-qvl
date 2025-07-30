"""
DCAP Quote Verification Library

This package provides Python bindings for the DCAP (Data Center Attestation Primitives) 
quote verification library implemented in Rust.

Main classes:
- QuoteCollateralV3: Represents quote collateral data
- VerifiedReport: Contains verification results

Main functions:
- verify: Verify a quote with collateral data
"""

from .dcap_qvl import (
    PyQuoteCollateralV3 as QuoteCollateralV3,
    PyVerifiedReport as VerifiedReport,
    py_verify as verify,
)

__version__ = "0.3.0"
__all__ = ["QuoteCollateralV3", "VerifiedReport", "verify"]