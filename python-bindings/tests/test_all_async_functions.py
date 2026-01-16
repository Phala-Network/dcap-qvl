#!/usr/bin/env python3
"""
Comprehensive test script for all async collateral functions.

This script tests all the async functions in the dcap_qvl package:
- get_collateral_for_fmspc (direct Rust export)
- get_collateral (Python wrapper using get_collateral_for_fmspc)
- get_collateral_from_pcs (Python wrapper using Intel PCS)
- get_collateral_and_verify (Python wrapper with verification)
"""

import asyncio
import sys
import os
import time

thisdir = os.path.dirname(os.path.abspath(__file__))
# Add the python package to the path
sys.path.insert(0, os.path.join(thisdir, "python"))

try:
    import dcap_qvl

    print("✓ Successfully imported dcap_qvl")
except ImportError as e:
    print(f"✗ Failed to import dcap_qvl: {e}")
    print("Make sure the Python bindings are built first.")
    sys.exit(1)


SAMPLE_SGX_QUOTE = open(os.path.join(thisdir, "../../sample/sgx_quote"), "rb").read()


async def test_function_availability():
    """Test that all expected async functions are available."""
    print("\n=== Testing Function Availability ===")

    expected_functions = [
        "get_collateral_for_fmspc",
        "get_collateral",
        "get_collateral_from_pcs",
        "get_collateral_and_verify",
    ]

    all_available = True
    for func_name in expected_functions:
        if hasattr(dcap_qvl, func_name):
            func = getattr(dcap_qvl, func_name)
            print(f"✓ {func_name} is available (type: {type(func)})")

            # Check if function is async (coroutine function)
            import inspect

            if inspect.iscoroutinefunction(func):
                print(f"  ✓ {func_name} is async")
            else:
                print(f"  ⚠ {func_name} is NOT async")
        else:
            print(f"✗ {func_name} is NOT available")
            all_available = False

    # Check __all__ exports
    if hasattr(dcap_qvl, "__all__"):
        print(f"\n__all__ exports: {dcap_qvl.__all__}")
        for func_name in expected_functions:
            if func_name in dcap_qvl.__all__:
                print(f"✓ {func_name} is in __all__")
            else:
                print(f"✗ {func_name} is NOT in __all__")
                all_available = False

    return all_available


async def test_get_collateral_for_fmspc():
    """Test the direct Rust async function get_collateral_for_fmspc."""
    print("\n=== Testing get_collateral_for_fmspc (Direct Rust Export) ===")

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

        start_time = time.time()
        collateral = await dcap_qvl.get_collateral_for_fmspc(
            pccs_url=pccs_url, fmspc=fmspc, ca=ca, for_sgx=for_sgx
        )
        end_time = time.time()

        print(f"✓ Successfully retrieved collateral in {end_time - start_time:.2f}s!")
        print(f"  Type: {type(collateral)}")
        print(f"  PCK CRL Issuer Chain length: {len(collateral.pck_crl_issuer_chain)}")
        print(f"  Root CA CRL size: {len(collateral.root_ca_crl)} bytes")
        print(f"  PCK CRL size: {len(collateral.pck_crl)} bytes")
        print(f"  TCB Info length: {len(collateral.tcb_info)}")
        print(f"  QE Identity length: {len(collateral.qe_identity)}")

        return collateral

    except Exception as e:
        print(f"✗ Error calling get_collateral_for_fmspc: {e}")
        print(f"  Error type: {type(e)}")
        return None


async def test_get_collateral_with_quote():
    """Test get_collateral function with a quote."""
    print("\n=== Testing get_collateral (Python Wrapper with Quote) ===")

    try:
        # First, try to parse a quote to get FMSPC
        print("Attempting to parse sample quote...")
        quote = dcap_qvl.Quote.parse(SAMPLE_SGX_QUOTE)
        fmspc = quote.fmspc()
        ca = quote.ca()
        is_tdx = quote.is_tdx()

        print(f"✓ Parsed quote successfully:")
        print(f"  FMSPC: {fmspc}")
        print(f"  CA: {ca}")
        print(f"  Is TDX: {is_tdx}")

        # Now test get_collateral
        pccs_url = "https://api.trustedservices.intel.com"

        print(f"\nCalling get_collateral with:")
        print(f"  PCCS URL: {pccs_url}")
        print(f"  Quote size: {len(SAMPLE_SGX_QUOTE)} bytes")

        start_time = time.time()
        collateral = await dcap_qvl.get_collateral(pccs_url, SAMPLE_SGX_QUOTE)
        end_time = time.time()

        print(f"✓ Successfully retrieved collateral in {end_time - start_time:.2f}s!")
        print(f"  Type: {type(collateral)}")

        return collateral

    except Exception as e:
        print(f"✗ Error in get_collateral: {e}")
        print(f"  Error type: {type(e)}")
        return None


async def test_get_collateral_from_pcs():
    """Test get_collateral_from_pcs function."""
    print("\n=== Testing get_collateral_from_pcs (Intel PCS) ===")

    try:
        print(f"Calling get_collateral_from_pcs with:")
        print(f"  Quote size: {len(SAMPLE_SGX_QUOTE)} bytes")
        print(f"  Using Intel PCS URL")

        start_time = time.time()
        collateral = await dcap_qvl.get_collateral_from_pcs(SAMPLE_SGX_QUOTE)
        end_time = time.time()

        print(f"✓ Successfully retrieved collateral in {end_time - start_time:.2f}s!")
        print(f"  Type: {type(collateral)}")

        return collateral

    except Exception as e:
        print(f"✗ Error in get_collateral_from_pcs: {e}")
        print(f"  Error type: {type(e)}")
        return None


async def test_get_collateral_and_verify():
    """Test get_collateral_and_verify function."""
    print("\n=== Testing get_collateral_and_verify (Full Pipeline) ===")

    try:
        print(f"Calling get_collateral_and_verify with:")
        print(f"  Quote size: {len(SAMPLE_SGX_QUOTE)} bytes")
        print(f"  Using Intel PCS URL")

        start_time = time.time()
        verified_report = await dcap_qvl.get_collateral_and_verify(SAMPLE_SGX_QUOTE)
        end_time = time.time()

        print(f"✓ Successfully verified quote in {end_time - start_time:.2f}s!")
        print(f"  Type: {type(verified_report)}")
        print(f"  Status: {verified_report.status}")
        print(f"  Advisory IDs: {verified_report.advisory_ids}")

        return verified_report

    except Exception as e:
        print(f"✗ Error in get_collateral_and_verify: {e}")
        print(f"  Error type: {type(e)}")
        return None


async def test_error_handling():
    """Test error handling with invalid inputs."""
    print("\n=== Testing Error Handling ===")

    test_cases = [
        {
            "name": "Invalid FMSPC",
            "func": dcap_qvl.get_collateral_for_fmspc,
            "args": (
                "https://api.trustedservices.intel.com",
                "INVALID",
                "processor",
                True,
            ),
            "kwargs": {},
        },
        {
            "name": "Invalid URL",
            "func": dcap_qvl.get_collateral_for_fmspc,
            "args": (
                "https://invalid-url-that-does-not-exist.com",
                "B0C06F000000",
                "processor",
                True,
            ),
            "kwargs": {},
        },
        {
            "name": "Invalid quote bytes",
            "func": dcap_qvl.get_collateral,
            "args": ("https://api.trustedservices.intel.com", b"invalid_quote"),
            "kwargs": {},
        },
    ]

    for test_case in test_cases:
        try:
            print(f"\nTesting {test_case['name']}...")
            result = await test_case["func"](*test_case["args"], **test_case["kwargs"])
            print(f"⚠ Expected error but got result: {type(result)}")
        except Exception as e:
            print(f"✓ Correctly caught error: {type(e).__name__}: {e}")


async def main():
    """Main test function."""
    print("=" * 60)
    print("COMPREHENSIVE ASYNC COLLATERAL FUNCTIONS TEST")
    print("=" * 60)

    # Test function availability
    availability_ok = await test_function_availability()

    if not availability_ok:
        print("\n✗ Some functions are not available. Check the build.")
        return False

    # Test individual functions
    results = {}

    # Test direct Rust export
    results["get_collateral_for_fmspc"] = await test_get_collateral_for_fmspc()

    # Test Python wrappers
    results["get_collateral"] = await test_get_collateral_with_quote()
    results["get_collateral_from_pcs"] = await test_get_collateral_from_pcs()
    results["get_collateral_and_verify"] = await test_get_collateral_and_verify()

    # Test error handling
    await test_error_handling()

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    success_count = sum(1 for result in results.values() if result is not None)
    total_count = len(results)

    for func_name, result in results.items():
        status = "✓ PASS" if result is not None else "✗ FAIL"
        print(f"{status} {func_name}")

    print(f"\nOverall: {success_count}/{total_count} functions passed")

    if success_count == total_count:
        print("🎉 All async collateral functions are working correctly!")
        return True
    else:
        print("❌ Some functions failed. Check the errors above.")
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
        import traceback

        traceback.print_exc()
        sys.exit(1)
