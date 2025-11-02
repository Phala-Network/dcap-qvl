"""Test the synchronous Python API implementation."""

import dcap_qvl
import pytest
import sys
import os

# Add the python package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))


class TestCollateralAPI:
    """Test the collateral API functions."""

    def test_module_imports(self):
        """Test that all expected functions are available."""
        # Basic functions should always be available
        assert hasattr(dcap_qvl, "QuoteCollateralV3")
        assert hasattr(dcap_qvl, "VerifiedReport")
        assert hasattr(dcap_qvl, "verify")

        # Pure Python functions should be available
        assert hasattr(dcap_qvl, "get_collateral")
        assert hasattr(dcap_qvl, "get_collateral_from_pcs")
        assert hasattr(dcap_qvl, "get_collateral_and_verify")

        # Check __all__ contains all expected functions
        expected_functions = [
            "QuoteCollateralV3",
            "VerifiedReport",
            "Quote",
            "verify",
            "get_collateral",
            "get_collateral_from_pcs",
            "get_collateral_and_verify",
        ]

        for func in expected_functions:
            assert func in dcap_qvl.__all__, f"{func} not in __all__"

    @pytest.mark.asyncio
    async def test_get_collateral_invalid_input(self):
        """Test get_collateral with invalid inputs."""
        # Test with non-bytes input
        with pytest.raises(TypeError, match="raw_quote must be bytes"):
            await dcap_qvl.get_collateral("http://example.com", "not bytes")

        # Test with invalid quote (too short)
        with pytest.raises(ValueError, match="Failed to parse quote"):
            await dcap_qvl.get_collateral("http://example.com", b"short")

    @pytest.mark.asyncio
    async def test_get_collateral_from_pcs_invalid_input(self):
        """Test get_collateral_from_pcs with invalid inputs."""
        # Test with invalid quote (too short)
        with pytest.raises(ValueError, match="Failed to parse quote"):
            await dcap_qvl.get_collateral_from_pcs(b"short")

    @pytest.mark.asyncio
    async def test_get_collateral_and_verify_invalid_input(self):
        """Test get_collateral_and_verify with invalid inputs."""
        # Test with invalid quote (too short)
        with pytest.raises(ValueError, match="Failed to parse quote"):
            await dcap_qvl.get_collateral_and_verify(b"short")

    def test_quote_collateral_creation(self):
        """Test QuoteCollateralV3 creation and serialization."""
        # Create a sample collateral object
        collateral = dcap_qvl.QuoteCollateralV3(
            pck_crl_issuer_chain="test_issuer_chain",
            root_ca_crl=b"test_root_ca_crl",
            pck_crl=b"test_pck_crl",
            tcb_info_issuer_chain="test_tcb_issuer_chain",
            tcb_info='{"test": "tcb_info"}',
            tcb_info_signature=b"test_tcb_signature",
            qe_identity_issuer_chain="test_qe_issuer_chain",
            qe_identity='{"test": "qe_identity"}',
            qe_identity_signature=b"test_qe_signature",
        )

        # Test properties
        assert collateral.pck_crl_issuer_chain == "test_issuer_chain"
        assert collateral.root_ca_crl == b"test_root_ca_crl"
        assert collateral.pck_crl == b"test_pck_crl"
        assert collateral.tcb_info_issuer_chain == "test_tcb_issuer_chain"
        assert collateral.tcb_info == '{"test": "tcb_info"}'
        assert collateral.tcb_info_signature == b"test_tcb_signature"
        assert collateral.qe_identity_issuer_chain == "test_qe_issuer_chain"
        assert collateral.qe_identity == '{"test": "qe_identity"}'
        assert collateral.qe_identity_signature == b"test_qe_signature"

        # Test JSON serialization/deserialization
        json_str = collateral.to_json()
        assert isinstance(json_str, str)

        # Create from JSON
        collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)
        assert collateral2.pck_crl_issuer_chain == collateral.pck_crl_issuer_chain
        assert collateral2.tcb_info == collateral.tcb_info

    @pytest.mark.asyncio
    async def test_get_collateral_and_verify_happy_path(self):
        """Test get_collateral_and_verify with real sample quote data."""

        # Load real sample quote data from the samples directory
        sample_dir = os.path.join(os.path.dirname(__file__), "..", "..", "sample")

        try:
            with open(os.path.join(sample_dir, "tdx_quote"), "rb") as f:
                test_quote = f.read()
        except FileNotFoundError:
            # If no sample files found, skip this test
            pytest.skip("Sample quote files not found")

        result = await dcap_qvl.get_collateral_and_verify(bytes(test_quote))

        # If it somehow succeeds, verify the result structure
        assert hasattr(result, "status")
        assert hasattr(result, "advisory_ids")


if __name__ == "__main__":
    pytest.main([__file__])
