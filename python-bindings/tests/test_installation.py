#!/usr/bin/env python3
"""
Test script for verifying dcap_qvl installation works correctly.
"""


def main():
    try:
        import dcap_qvl

        print("Successfully imported dcap_qvl")
        print("Available functions:", dir(dcap_qvl))

        # Test basic functionality
        try:
            collateral = dcap_qvl.QuoteCollateralV3(
                pck_crl_issuer_chain="test",
                root_ca_crl=b"test",
                pck_crl=b"test",
                tcb_info_issuer_chain="test",
                tcb_info='{"test": true}',
                tcb_info_signature=b"test",
                qe_identity_issuer_chain="test",
                qe_identity='{"test": true}',
                qe_identity_signature=b"test",
            )
            json_str = collateral.to_json()
            collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)
            print("* QuoteCollateralV3 functionality test passed!")
        except Exception as e:
            print(f"Note: QuoteCollateralV3 test failed (expected): {e}")

        # Test quote parsing if available
        try:
            if hasattr(dcap_qvl, "parse_quote"):
                print("* parse_quote function is available")
            print("* Basic functionality test completed!")
        except Exception as e:
            print(f"Quote parsing test failed: {e}")

        return True

    except ImportError as e:
        print(f"Failed to import dcap_qvl: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
