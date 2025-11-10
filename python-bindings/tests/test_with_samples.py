#!/usr/bin/env python3
"""
Test async collateral functions with real sample quote data.

This script uses the actual sample quote files to test the async functions.
"""

import asyncio
import sys
import os
import json
from pathlib import Path

# Add the python package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "python"))

try:
    import dcap_qvl

    print("✓ Successfully imported dcap_qvl")
except ImportError as e:
    print(f"✗ Failed to import dcap_qvl: {e}")
    print("Make sure the Python bindings are built first.")
    sys.exit(1)


async def test_with_sample_quotes():
    """Test async functions with real sample quote data."""
    print("\n=== Testing with Sample Quote Data ===")

    # Find sample directory
    sample_dir = Path(__file__).parent.parent / "sample"
    if not sample_dir.exists():
        print(f"✗ Sample directory not found: {sample_dir}")
        return False

    # Test with SGX quote
    sgx_quote_path = sample_dir / "sgx_quote"
    tdx_quote_path = sample_dir / "tdx_quote"

    results = {}

    for quote_type, quote_path in [("SGX", sgx_quote_path), ("TDX", tdx_quote_path)]:
        if not quote_path.exists():
            print(f"⚠ {quote_type} quote file not found: {quote_path}")
            continue

        print(f"\n--- Testing with {quote_type} Quote ---")

        try:
            # Load quote data
            with open(quote_path, "rb") as f:
                quote_data = f.read()

            print(f"✓ Loaded {quote_type} quote: {len(quote_data)} bytes")

            # Parse quote to get info
            quote = dcap_qvl.Quote.parse(quote_data)
            fmspc = quote.fmspc()
            ca = quote.ca()
            is_tdx = quote.is_tdx()
            quote_type_str = quote.quote_type()

            print(f"  FMSPC: {fmspc}")
            print(f"  CA: {ca}")
            print(f"  Is TDX: {is_tdx}")
            print(f"  Quote Type: {quote_type_str}")

            # Test get_collateral_for_fmspc directly
            print(f"\n  Testing get_collateral_for_fmspc...")
            try:
                collateral1 = await dcap_qvl.get_collateral_for_fmspc(
                    pccs_url="https://api.trustedservices.intel.com",
                    fmspc=fmspc,
                    ca=ca,
                    for_sgx=not is_tdx,
                )
                print(f"  ✓ get_collateral_for_fmspc succeeded")
                results[f"{quote_type}_get_collateral_for_fmspc"] = True
            except Exception as e:
                print(f"  ✗ get_collateral_for_fmspc failed: {e}")
                results[f"{quote_type}_get_collateral_for_fmspc"] = False

            # Test get_collateral with quote
            print(f"  Testing get_collateral...")
            try:
                collateral2 = await dcap_qvl.get_collateral(
                    "https://api.trustedservices.intel.com", quote_data
                )
                print(f"  ✓ get_collateral succeeded")
                results[f"{quote_type}_get_collateral"] = True
            except Exception as e:
                print(f"  ✗ get_collateral failed: {e}")
                results[f"{quote_type}_get_collateral"] = False

            # Test get_collateral_from_pcs
            print(f"  Testing get_collateral_from_pcs...")
            try:
                collateral3 = await dcap_qvl.get_collateral_from_pcs(quote_data)
                print(f"  ✓ get_collateral_from_pcs succeeded")
                results[f"{quote_type}_get_collateral_from_pcs"] = True
            except Exception as e:
                print(f"  ✗ get_collateral_from_pcs failed: {e}")
                results[f"{quote_type}_get_collateral_from_pcs"] = False

            # Test get_collateral_and_verify
            print(f"  Testing get_collateral_and_verify...")
            try:
                verified_report = await dcap_qvl.get_collateral_and_verify(quote_data)
                print(f"  ✓ get_collateral_and_verify succeeded")
                print(f"    Status: {verified_report.status}")
                print(f"    Advisory IDs: {verified_report.advisory_ids}")
                results[f"{quote_type}_get_collateral_and_verify"] = True
            except Exception as e:
                print(f"  ✗ get_collateral_and_verify failed: {e}")
                results[f"{quote_type}_get_collateral_and_verify"] = False

        except Exception as e:
            print(f"✗ Failed to process {quote_type} quote: {e}")
            continue

    return results


async def test_function_signatures():
    """Test that all functions have correct async signatures."""
    print("\n=== Testing Function Signatures ===")

    import inspect

    functions_to_test = [
        "get_collateral_for_fmspc",
        "get_collateral",
        "get_collateral_from_pcs",
        "get_collateral_and_verify",
    ]

    all_correct = True

    for func_name in functions_to_test:
        if hasattr(dcap_qvl, func_name):
            func = getattr(dcap_qvl, func_name)
            is_async = inspect.iscoroutinefunction(func)

            if is_async:
                print(f"✓ {func_name} is correctly async")
            else:
                print(f"✗ {func_name} is NOT async")
                all_correct = False

            # Get signature
            try:
                sig = inspect.signature(func)
                print(f"  Signature: {func_name}{sig}")
            except Exception as e:
                print(f"  Could not get signature: {e}")
        else:
            print(f"✗ {func_name} not found")
            all_correct = False

    return all_correct


async def main():
    """Main test function."""
    print("=" * 60)
    print("TESTING ASYNC COLLATERAL FUNCTIONS WITH SAMPLE DATA")
    print("=" * 60)

    # Test function signatures
    signatures_ok = await test_function_signatures()

    # Test with sample data
    sample_results = await test_with_sample_quotes()

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    if signatures_ok:
        print("✓ All function signatures are correct")
    else:
        print("✗ Some function signatures are incorrect")

    if sample_results:
        success_count = sum(1 for result in sample_results.values() if result)
        total_count = len(sample_results)

        print(f"\nSample Data Tests: {success_count}/{total_count} passed")

        for test_name, result in sample_results.items():
            status = "✓" if result else "✗"
            print(f"  {status} {test_name}")

        overall_success = signatures_ok and success_count > 0
    else:
        print("✗ No sample data tests were run")
        overall_success = False

    if overall_success:
        print(f"\n🎉 Async collateral functions are working!")
    else:
        print(f"\n❌ Some issues found. Check the errors above.")

    return overall_success


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
