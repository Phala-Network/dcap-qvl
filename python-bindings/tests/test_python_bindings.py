"""
Tests for the Python bindings of dcap-qvl.
"""

import json
import pytest
from pathlib import Path

import dcap_qvl


class TestQuoteCollateralV3:
    """Test QuoteCollateralV3 class."""

    def test_create_collateral(self):
        """Test creating a QuoteCollateralV3 object."""
        collateral = dcap_qvl.QuoteCollateralV3(
            pck_crl_issuer_chain="test_chain",
            root_ca_crl=b"test_root_crl",
            pck_crl=b"test_pck_crl",
            tcb_info_issuer_chain="test_tcb_chain",
            tcb_info="test_tcb_info",
            tcb_info_signature=b"test_tcb_sig",
            qe_identity_issuer_chain="test_qe_chain",
            qe_identity="test_qe_identity",
            qe_identity_signature=b"test_qe_sig",
        )

        assert collateral.pck_crl_issuer_chain == "test_chain"
        assert collateral.tcb_info == "test_tcb_info"
        assert collateral.qe_identity == "test_qe_identity"

    def test_json_serialization(self):
        """Test JSON serialization and deserialization."""
        collateral = dcap_qvl.QuoteCollateralV3(
            pck_crl_issuer_chain="test_chain",
            root_ca_crl=b"test_root_crl",
            pck_crl=b"test_pck_crl",
            tcb_info_issuer_chain="test_tcb_chain",
            tcb_info="test_tcb_info",
            tcb_info_signature=b"test_tcb_sig",
            qe_identity_issuer_chain="test_qe_chain",
            qe_identity="test_qe_identity",
            qe_identity_signature=b"test_qe_sig",
        )

        # Serialize to JSON
        json_str = collateral.to_json()
        assert isinstance(json_str, str)

        # Deserialize from JSON
        collateral2 = dcap_qvl.QuoteCollateralV3.from_json(json_str)
        assert collateral2.pck_crl_issuer_chain == collateral.pck_crl_issuer_chain
        assert collateral2.tcb_info == collateral.tcb_info


class TestVerify:
    """Test quote verification functionality."""

    def test_verify_with_invalid_quote(self):
        """Test verification with invalid quote data."""
        collateral = dcap_qvl.QuoteCollateralV3(
            pck_crl_issuer_chain="test_chain",
            root_ca_crl=b"test_root_crl",
            pck_crl=b"test_pck_crl",
            tcb_info_issuer_chain="test_tcb_chain",
            tcb_info="test_tcb_info",
            tcb_info_signature=b"test_tcb_sig",
            qe_identity_issuer_chain="test_qe_chain",
            qe_identity="test_qe_identity",
            qe_identity_signature=b"test_qe_sig",
        )

        invalid_quote = b"invalid_quote_data"

        with pytest.raises(ValueError):
            dcap_qvl.verify(invalid_quote, collateral, 1234567890)


@pytest.mark.skipif(
    not Path("sample/tdx_quote").exists()
    or not Path("sample/tdx_quote_collateral.json").exists(),
    reason="Sample files not available",
)
class TestWithSampleData:
    """Test with actual sample data if available."""

    def test_verify_with_sample_data(self):
        """Test verification with sample TDX quote and collateral."""
        # Load sample quote
        with open("sample/tdx_quote", "rb") as f:
            quote_data = f.read()

        # Load sample collateral
        with open("sample/tdx_quote_collateral.json", "r") as f:
            collateral_json = json.load(f)

        collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))

        # Note: We use a timestamp that might make the test pass
        # In a real scenario, you'd use the current time or a known good time
        result = dcap_qvl.verify(quote_data, collateral, 1234567890)

        assert isinstance(result, dcap_qvl.VerifiedReport)
        assert isinstance(result.status, str)
        assert isinstance(result.advisory_ids, list)
