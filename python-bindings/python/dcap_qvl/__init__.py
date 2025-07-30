"""
DCAP Quote Verification Library

This package provides Python bindings for the DCAP (Data Center Attestation Primitives) 
quote verification library implemented in Rust.

Main classes:
- QuoteCollateralV3: Represents quote collateral data
- VerifiedReport: Contains verification results

Main functions:
- verify: Verify a quote with collateral data
- get_collateral: Get collateral from PCCS URL (async)
- get_collateral_from_pcs: Get collateral from Intel PCS (async)  
- get_collateral_and_verify: Get collateral and verify quote (async)
"""

from .dcap_qvl import (
    PyQuoteCollateralV3 as QuoteCollateralV3,
    PyVerifiedReport as VerifiedReport,
    py_verify as verify,
)

# Async functions (only available if compiled with 'report' feature)
try:
    from .dcap_qvl import (
        py_get_collateral as get_collateral,
        py_get_collateral_from_pcs as get_collateral_from_pcs,
        py_get_collateral_and_verify as get_collateral_and_verify,
    )
    __all__ = [
        "QuoteCollateralV3", 
        "VerifiedReport", 
        "verify",
        "get_collateral",
        "get_collateral_from_pcs", 
        "get_collateral_and_verify"
    ]
except ImportError:
    # Async functions not available (compiled without 'report' feature)
    __all__ = ["QuoteCollateralV3", "VerifiedReport", "verify"]

__version__ = "0.3.0"