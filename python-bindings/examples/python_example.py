#!/usr/bin/env python3
"""
Example usage of the DCAP QVL Python bindings.

This example demonstrates how to:
1. Load a quote from a file
2. Create quote collateral from JSON
3. Verify the quote
"""

import json
import time
from pathlib import Path

import dcap_qvl


def main():
    # Example paths - adjust these to your actual sample files
    this_file = Path(__file__)
    quote_file = this_file.parent.parent.parent / "sample/tdx_quote"
    collateral_file = (
        this_file.parent.parent.parent / "sample/tdx_quote_collateral.json"
    )

    if not quote_file.exists():
        print(f"Quote file not found: {quote_file}")
        print("Please ensure you have sample quote files available")
        return

    if not collateral_file.exists():
        print(f"Collateral file not found: {collateral_file}")
        print("Please ensure you have sample collateral files available")
        return

    # Load quote
    with open(quote_file, "rb") as f:
        quote_data = f.read()

    # Load collateral
    with open(collateral_file, "r") as f:
        collateral_json = f.read()

    # Create QuoteCollateralV3 object
    collateral = dcap_qvl.QuoteCollateralV3.from_json(collateral_json)

    # Get current timestamp
    now = 1750320802

    try:
        # Verify the quote
        result = dcap_qvl.verify(quote_data, collateral, now)

        print("Verification successful!")
        print(f"Status: {result.status}")
        print(f"Advisory IDs: {result.advisory_ids}")
        print("\nFull result:")
        print(result.to_json())

    except Exception as e:
        print(f"Verification failed: {e}")


if __name__ == "__main__":
    main()
