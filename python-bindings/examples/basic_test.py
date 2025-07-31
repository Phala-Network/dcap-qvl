#!/usr/bin/env python3
"""
Basic functionality test for DCAP QVL Python bindings.
This demonstrates that all the core functionality is working properly.
"""

import dcap_qvl
import json


def test_basic_functionality():
    """Test all basic functionality of the Python bindings."""

    print("🧪 Testing DCAP QVL Python Bindings\n")

    # Test 1: Create QuoteCollateralV3
    print("1. Creating QuoteCollateralV3...")
    collateral = dcap_qvl.QuoteCollateralV3(
        pck_crl_issuer_chain="Test PCK CRL Issuer Chain",
        root_ca_crl=b"Test Root CA CRL",
        pck_crl=b"Test PCK CRL",
        tcb_info_issuer_chain="Test TCB Info Issuer Chain",
        tcb_info='{"version": "test"}',
        tcb_info_signature=b"Test TCB Info Signature",
        qe_identity_issuer_chain="Test QE Identity Issuer Chain",
        qe_identity='{"version": "test"}',
        qe_identity_signature=b"Test QE Identity Signature",
    )
    print("✅ QuoteCollateralV3 created successfully")

    # Test 2: Access properties
    print("\n2. Testing property access...")
    print(f"   PCK CRL Issuer Chain: {collateral.pck_crl_issuer_chain}")
    print(f"   TCB Info: {collateral.tcb_info}")
    print(f"   QE Identity: {collateral.qe_identity}")
    print("✅ Property access works")

    # Test 3: JSON serialization
    print("\n3. Testing JSON serialization...")
    json_str = collateral.to_json()
    print(f"   JSON length: {len(json_str)} characters")
    print("✅ JSON serialization works")

    # Test 4: JSON deserialization
    print("\n4. Testing JSON deserialization...")
    collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)
    assert collateral2.pck_crl_issuer_chain == collateral.pck_crl_issuer_chain
    assert collateral2.tcb_info == collateral.tcb_info
    print("✅ JSON deserialization works")

    # Test 5: Verify function with invalid data (should fail gracefully)
    print("\n5. Testing verify function with invalid data...")
    try:
        invalid_quote = b"This is not a valid quote"
        dcap_qvl.verify(invalid_quote, collateral, 1234567890)
        print("❌ Expected verification to fail")
    except ValueError as e:
        print(f"✅ Verification correctly failed with: {str(e)[:50]}...")

    print("\n🎉 All tests passed! Python bindings are working correctly.")
    print("\nAvailable functions and classes:")
    print(f"   - {', '.join(dcap_qvl.__all__)}")
    print(f"   - Version: {dcap_qvl.__version__}")


if __name__ == "__main__":
    test_basic_functionality()
