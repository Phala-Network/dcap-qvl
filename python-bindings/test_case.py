#!/usr/bin/env python3
"""
Python implementation of test_case CLI tool for DCAP quote verification.

Usage:
    test_case.py <command> [args...]

Commands:
    verify <quote_file> <collateral_file> [root_ca_file]
    get-collateral [--pccs-url URL] <quote_file>

Exit codes:
    0 - Command successful
    1 - Command failed
    2 - Unexpected error (file not found, parse error, etc.)

Output:
    Prints result to stdout
    Prints errors to stderr
"""

import sys
import json
import asyncio
import argparse
import time
from pathlib import Path

# Try to import dcap_qvl
try:
    import dcap_qvl
except ImportError:
    print("Error: dcap_qvl module not found", file=sys.stderr)
    print("Please install the Python bindings first:", file=sys.stderr)
    print("  cd python-bindings && pip install -e .", file=sys.stderr)
    sys.exit(2)


def cmd_verify(args):
    """Verify a quote with collateral."""
    quote_file = Path(args.quote_file)
    collateral_file = Path(args.collateral_file)
    root_ca_file = Path(args.root_ca_file) if args.root_ca_file else None

    # Read quote
    try:
        quote_bytes = quote_file.read_bytes()
    except Exception as e:
        print(f"Failed to read quote file: {e}", file=sys.stderr)
        return 2

    # Read collateral
    try:
        collateral_json = collateral_file.read_text()
        collateral = json.loads(collateral_json)
    except Exception as e:
        print(f"Failed to read collateral file: {e}", file=sys.stderr)
        return 2

    # Read custom root CA if provided
    root_ca_der = None
    if root_ca_file:
        try:
            root_ca_der = root_ca_file.read_bytes()
        except Exception as e:
            print(f"Failed to read root CA file: {e}", file=sys.stderr)
            return 2

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
        return 0

    except Exception as e:
        # Verification failed - match Rust CLI output format
        print(f"Verification failed: {e}", file=sys.stderr)

        # Try to extract cause chain - match Rust CLI format
        cause = e.__cause__
        while cause:
            print(f"  Caused by: {cause}", file=sys.stderr)
            cause = cause.__cause__

        return 1


async def cmd_get_collateral(args):
    """Fetch collateral from PCCS."""
    quote_file = Path(args.quote_file)
    pccs_url = args.pccs_url

    # Read quote
    try:
        quote_bytes = quote_file.read_bytes()
    except Exception as e:
        print(f"Failed to read quote file: {e}", file=sys.stderr)
        return 2

    try:
        # Use the same get_collateral function as Rust (parses quote properly)
        collateral = await dcap_qvl.get_collateral(pccs_url, quote_bytes)

        if not collateral or not hasattr(collateral, 'tcb_info_issuer_chain'):
            print(json.dumps({"error": "Collateral missing required fields"}))
            return 1

        # Output collateral JSON directly
        if hasattr(collateral, 'to_json'):
            print(collateral.to_json())
        else:
            print(json.dumps(collateral.__dict__))
        return 0

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1


def main():
    """Main entry point for test_case."""
    parser = argparse.ArgumentParser(
        description="Python implementation of test_case CLI tool for DCAP quote verification",
        add_help=False
    )

    parser.add_argument('command', choices=['verify', 'get-collateral'],
                       help='Command to run')
    parser.add_argument('--help', action='store_true', help='Show help message')

    # Parse only the command first
    if len(sys.argv) < 2:
        parser.print_help()
        print("\nCommands:")
        print("  verify <quote_file> <collateral_file> [root_ca_file]")
        print("    Verify a quote with collateral")
        print("  get-collateral [--pccs-url URL] <quote_file>")
        print("    Fetch collateral from PCCS")
        sys.exit(2)

    cmd = sys.argv[1]

    if cmd == '--help' or (len(sys.argv) == 2 and cmd == 'help'):
        parser.print_help()
        sys.exit(0)

    if cmd == 'verify':
        sub_parser = argparse.ArgumentParser(prog='test_case.py verify')
        sub_parser.add_argument('quote_file', help='Path to quote file')
        sub_parser.add_argument('collateral_file', help='Path to collateral JSON file')
        sub_parser.add_argument('root_ca_file', nargs='?', help='Optional path to custom root CA DER file')
        args = sub_parser.parse_args(sys.argv[2:])
        sys.exit(cmd_verify(args))

    elif cmd == 'get-collateral':
        sub_parser = argparse.ArgumentParser(prog='test_case.py get-collateral')
        sub_parser.add_argument('--pccs-url',
                               default='https://pccs.phala.network/tdx/certification/v4',
                               help='PCCS URL (default: https://pccs.phala.network/tdx/certification/v4)')
        sub_parser.add_argument('quote_file', help='Path to quote file')
        args = sub_parser.parse_args(sys.argv[2:])
        sys.exit(asyncio.run(cmd_get_collateral(args)))

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
