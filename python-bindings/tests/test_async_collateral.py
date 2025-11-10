#!/usr/bin/env python3
"""
Test script for the new async get_collateral_for_fmspc function.

This script demonstrates how to use the new async Rust function exported to Python.
"""

import asyncio
import sys
import os

# Add the python package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "python"))

try:
    import dcap_qvl

    print("✓ Successfully imported dcap_qvl")
except ImportError as e:
    print(f"✗ Failed to import dcap_qvl: {e}")
    print("Make sure the Python bindings are built first.")
    sys.exit(1)


async def test_get_collateral_for_fmspc():
    """Test the async get_collateral_for_fmspc function."""
    print("\n=== Testing async get_collateral_for_fmspc ===")

    # Test parameters
    pccs_url = "https://api.trustedservices.intel.com"
    fmspc = "B0C06F000000"  # Example FMSPC from memory
    ca = "processor"  # Common CA value
    for_sgx = True  # Test with SGX

    try:
        print(f"Calling get_collateral_for_fmspc with:")
        print(f"  PCCS URL: {pccs_url}")
        print(f"  FMSPC: {fmspc}")
        print(f"  CA: {ca}")
        print(f"  For SGX: {for_sgx}")

        # Call the async function
        collateral = await dcap_qvl.get_collateral_for_fmspc(
            pccs_url=pccs_url, fmspc=fmspc, ca=ca, for_sgx=for_sgx
        )

        print("✓ Successfully retrieved collateral!")
        print(f"  Type: {type(collateral)}")
        print(f"  PCK CRL Issuer Chain length: {len(collateral.pck_crl_issuer_chain)}")
        print(f"  Root CA CRL size: {len(collateral.root_ca_crl)} bytes")
        print(f"  PCK CRL size: {len(collateral.pck_crl)} bytes")
        print(f"  TCB Info length: {len(collateral.tcb_info)}")
        print(f"  QE Identity length: {len(collateral.qe_identity)}")

        return True

    except Exception as e:
        print(f"✗ Error calling get_collateral_for_fmspc: {e}")
        print(f"  Error type: {type(e)}")
        return False


async def test_function_availability():
    """Test that the new functions are available in the module."""
    print("\n=== Testing function availability ===")

    expected_functions = ["get_collateral_for_fmspc"]

    all_available = True
    for func_name in expected_functions:
        if hasattr(dcap_qvl, func_name):
            func = getattr(dcap_qvl, func_name)
            print(f"✓ {func_name} is available (type: {type(func)})")
        else:
            print(f"✗ {func_name} is NOT available")
            all_available = False

    # Check if the function is in __all__
    if hasattr(dcap_qvl, "__all__"):
        print(f"\n__all__ exports: {dcap_qvl.__all__}")
        for func_name in expected_functions:
            if func_name in dcap_qvl.__all__:
                print(f"✓ {func_name} is in __all__")
            else:
                print(f"✗ {func_name} is NOT in __all__")
                all_available = False

    return all_available


async def main():
    """Main test function."""
    print("Testing new async collateral functions...")

    # Test function availability
    availability_ok = await test_function_availability()

    if not availability_ok:
        print("\n✗ Some functions are not available. Check the build.")
        return False

    # Test the actual async function
    collateral_ok = await test_get_collateral_for_fmspc()

    if availability_ok and collateral_ok:
        print("\n✓ All tests passed!")
        return True
    else:
        print("\n✗ Some tests failed.")
        return False


if __name__ == "__main__":
    try:
        success = asyncio.run(main())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n✗ Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)
