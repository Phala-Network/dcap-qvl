#!/usr/bin/env python3
"""
Python implementation of verify_sample CLI tool for DCAP quote verification.

Usage:
    verify_sample.py <quote_file> <collateral_file> [root_ca_file]

Exit codes:
    0 - Verification successful
    1 - Verification failed
    2 - Unexpected error (file not found, parse error, etc.)

Output:
    Prints verification result to stdout
    Prints errors to stderr
"""

import sys
import json
from pathlib import Path

# Try to import dcap_qvl
try:
    import dcap_qvl
except ImportError:
    print("Error: dcap_qvl module not found", file=sys.stderr)
    print("Please install the Python bindings first:", file=sys.stderr)
    print("  cd python-bindings && pip install -e .", file=sys.stderr)
    sys.exit(2)


def main():
    """Main entry point for verify_sample."""
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <quote_file> <collateral_file> [root_ca_file]",
            file=sys.stderr,
        )
        sys.exit(2)

    quote_file = Path(sys.argv[1])
    collateral_file = Path(sys.argv[2])
    root_ca_file = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    # Read quote
    try:
        quote_bytes = quote_file.read_bytes()
    except Exception as e:
        print(f"Failed to read quote file: {e}", file=sys.stderr)
        sys.exit(2)

    # Read collateral
    try:
        collateral_json = collateral_file.read_text()
        collateral = json.loads(collateral_json)
    except Exception as e:
        print(f"Failed to read collateral file: {e}", file=sys.stderr)
        sys.exit(2)

    # Read custom root CA if provided
    root_ca_der = None
    if root_ca_file:
        try:
            root_ca_der = root_ca_file.read_bytes()
        except Exception as e:
            print(f"Failed to read root CA file: {e}", file=sys.stderr)
            sys.exit(2)

    # Verify quote
    import time

    # Use current time like the Rust CLI
    now_secs = int(time.time())

    try:
        # Convert collateral dict to QuoteCollateralV3 object
        collateral_obj = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral))

        # Verify using the Rust backend
        if root_ca_der:
            # Use custom root CA for testing
            result = dcap_qvl.verify_with_root_ca(
                quote_bytes, collateral_obj, root_ca_der, now_secs
            )
        else:
            # Use production Intel root CA
            result = dcap_qvl.verify(quote_bytes, collateral_obj, now_secs)

        # Verification successful
        print("Verification successful")
        print(f"Status: {result.status}")
        sys.exit(0)

    except Exception as e:
        # Verification failed - match Rust CLI output format
        print(f"Verification failed: {e}", file=sys.stderr)

        # Try to extract cause chain - match Rust CLI format
        cause = e.__cause__
        while cause:
            print(f"  Caused by: {cause}", file=sys.stderr)
            cause = cause.__cause__

        sys.exit(1)


if __name__ == "__main__":
    main()
