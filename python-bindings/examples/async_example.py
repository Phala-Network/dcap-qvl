#!/usr/bin/env python3
"""
Async example usage of the DCAP QVL Python bindings.

This example demonstrates how to use the async functions to:
1. Get collateral from PCCS
2. Get collateral from Intel PCS
3. Get collateral and verify in one step
"""

import asyncio
import time
from pathlib import Path

import dcap_qvl


async def test_async_functions():
    """Test async functionality of the Python bindings."""

    print("🧪 Testing DCAP QVL Python Async Functions\n")

    # Check if async functions are available
    if not hasattr(dcap_qvl, "get_collateral"):
        print(
            "❌ Async functions not available. Make sure the library was compiled with 'report' feature."
        )
        return

    print("✅ Async functions are available!")

    # Example paths - adjust these to your actual sample files
    quote_file = Path("sample/tdx_quote")
    if not quote_file.exists():
        quote_file = Path("../sample/tdx_quote")  # Try from project root

    if not quote_file.exists():
        print("⚠️  Sample quote file not found. Creating mock quote data for demo.")
        # Create some mock quote data for demonstration
        quote_data = b"mock_quote_data_for_demo_purposes_" + b"x" * 100
    else:
        with open(quote_file, "rb") as f:
            quote_data = f.read()
        print(f"📖 Loaded quote from: {quote_file}")

    print(f"Quote size: {len(quote_data)} bytes\n")

    # Test 1: Get collateral from Intel PCS (this will likely fail with mock data, but shows the API)
    print("1. Testing get_collateral_from_pcs (async)...")
    try:
        collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
        print("✅ Successfully got collateral from Intel PCS")
        print(f"   TCB Info length: {len(collateral.tcb_info)} characters")
    except Exception as e:
        print(f"⚠️  Expected error with mock/test data: {str(e)[:100]}...")

    # Test 2: Get collateral from custom PCCS URL
    print("\n2. Testing get_collateral with custom PCCS URL (async)...")
    pccs_url = "https://api.trustedservices.intel.com/sgx/certification/v4/"
    try:
        collateral = await dcap_qvl.get_collateral(pccs_url, quote_data)
        print("✅ Successfully got collateral from custom PCCS")
        print(f"   PCK CRL Issuer Chain: {collateral.pck_crl_issuer_chain[:50]}...")
    except Exception as e:
        print(f"⚠️  Expected error with mock/test data: {str(e)[:100]}...")

    # Test 3: Get collateral and verify in one step
    print("\n3. Testing get_collateral_and_verify (async)...")
    try:
        result = await dcap_qvl.get_collateral_and_verify(
            quote_data, None
        )  # None = use default PCS
        print("✅ Successfully got collateral and verified quote")
        print(f"   Status: {result.status}")
        print(f"   Advisory IDs: {result.advisory_ids}")
    except Exception as e:
        print(f"⚠️  Expected error with mock/test data: {str(e)[:100]}...")

    print("\n🎉 Async function testing complete!")
    print("\nNote: Errors are expected when using mock data or expired certificates.")
    print("For real usage, provide valid quote data and ensure network connectivity.")


async def test_concurrent_requests():
    """Test concurrent async requests."""
    print("\n🔄 Testing concurrent async requests...\n")

    # Create some mock quote data
    quote_data1 = b"mock_quote_1_" + b"x" * 50
    quote_data2 = b"mock_quote_2_" + b"y" * 50
    quote_data3 = b"mock_quote_3_" + b"z" * 50

    async def get_collateral_safe(quote_data, name):
        try:
            start_time = time.time()
            collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
            duration = time.time() - start_time
            return f"✅ {name}: Success in {duration:.2f}s"
        except Exception as e:
            duration = time.time() - start_time
            return f"⚠️  {name}: Error in {duration:.2f}s - {str(e)[:50]}..."

    # Run multiple requests concurrently
    tasks = [
        get_collateral_safe(quote_data1, "Request 1"),
        get_collateral_safe(quote_data2, "Request 2"),
        get_collateral_safe(quote_data3, "Request 3"),
    ]

    results = await asyncio.gather(*tasks)

    for result in results:
        print(result)

    print("\n✅ Concurrent request testing complete!")


def test_sync_vs_async_api():
    """Demonstrate the difference between sync and async APIs."""
    print("\n⚖️  Sync vs Async API Comparison\n")

    # Show sync API
    print("Sync API:")
    print("  result = dcap_qvl.verify(quote_data, collateral, timestamp)")
    print("  # Blocks until complete")

    print("\nAsync API:")
    print("  collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)")
    print("  result = await dcap_qvl.get_collateral_and_verify(quote_data)")
    print("  # Can run concurrently with other async operations")

    print("\nUse async functions when:")
    print("  ✅ Making network requests to PCCS/PCS")
    print("  ✅ Processing multiple quotes concurrently")
    print("  ✅ Integrating with async Python frameworks (FastAPI, aiohttp)")

    print("\nUse sync functions when:")
    print("  ✅ You already have collateral data")
    print("  ✅ Simple scripts or synchronous applications")
    print("  ✅ No network I/O required")


async def main():
    """Run all async tests."""
    await test_async_functions()
    await test_concurrent_requests()
    test_sync_vs_async_api()


if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())
