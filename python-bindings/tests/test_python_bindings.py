"""Tests for the Python bindings of dcap-qvl.

These tests require the extension module to be built (e.g. via `maturin develop`).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


dcap_qvl = pytest.importorskip("dcap_qvl")


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


class TestRegoPolicies:
    """Test Rego policy bindings."""

    def test_rego_policy_constructor(self):
        """Test creating a RegoPolicy from valid JSON."""
        policy_json = json.dumps(
            {
                "environment": {
                    "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
                },
                "reference": {
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                },
            }
        )

        policy = dcap_qvl.RegoPolicy(policy_json)
        assert isinstance(policy, dcap_qvl.RegoPolicy)

    def test_rego_policy_set_constructor(self):
        """Test creating a RegoPolicySet from valid JSON policies."""
        policy_json = json.dumps(
            {
                "environment": {
                    "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
                },
                "reference": {
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                },
            }
        )

        policies = dcap_qvl.RegoPolicySet([policy_json])
        assert isinstance(policies, dcap_qvl.RegoPolicySet)

    def test_rego_policy_missing_class_id(self):
        """Test that missing class_id is rejected."""
        policy_json = json.dumps(
            {
                "reference": {
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                },
            }
        )

        with pytest.raises(ValueError):
            dcap_qvl.RegoPolicy(policy_json)


@pytest.mark.skipif(
    os.getenv("DCAP_QVL_RUN_SAMPLE_VERIFY") != "1",
    reason="Sample verify is an integration test. Set DCAP_QVL_RUN_SAMPLE_VERIFY=1 to run.",
)
class TestWithSampleData:
    """Integration test with actual sample data (time-sensitive)."""

    def test_verify_with_sample_data(self):
        """Test verification with sample TDX quote and collateral."""
        if not Path("sample/tdx_quote").exists() or not Path(
            "sample/tdx_quote_collateral.json"
        ).exists():
            pytest.skip("Sample files not available")

        # Load sample quote
        with open("sample/tdx_quote", "rb") as f:
            quote_data = f.read()

        # Load sample collateral
        with open("sample/tdx_quote_collateral.json", "r") as f:
            collateral_json = json.load(f)

        collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))

        # Phase 1: crypto verification
        qvr = dcap_qvl.verify(quote_data, collateral, 1234567890)
        assert isinstance(qvr, dcap_qvl.QuoteVerificationResult)

        # Phase 2: policy validation
        policy = dcap_qvl.SimplePolicy.strict(1234567890)
        result = qvr.validate(policy)

        assert isinstance(result, dcap_qvl.VerifiedReport)
        assert isinstance(result.status, str)
        assert isinstance(result.advisory_ids, list)

    def test_validate_with_rego_policy(self):
        """Test validation with RegoPolicy using sample SGX quote."""
        if not Path("sample/sgx_quote").exists() or not Path(
            "sample/sgx_quote_collateral.json"
        ).exists():
            pytest.skip("Sample files not available")

        with open("sample/sgx_quote", "rb") as f:
            quote_data = f.read()

        with open("sample/sgx_quote_collateral.json", "r") as f:
            collateral_json = json.load(f)

        collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))
        qvr = dcap_qvl.verify(quote_data, collateral, 1234567890)

        policy_json = json.dumps(
            {
                "environment": {
                    "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
                },
                "reference": {
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                },
            }
        )
        policy = dcap_qvl.RegoPolicy(policy_json)
        result = qvr.validate(policy)

        assert isinstance(result, dcap_qvl.VerifiedReport)
        assert isinstance(result.status, str)

    def test_validate_with_rego_policy_set(self):
        """Test validation with RegoPolicySet using sample SGX quote."""
        if not Path("sample/sgx_quote").exists() or not Path(
            "sample/sgx_quote_collateral.json"
        ).exists():
            pytest.skip("Sample files not available")

        with open("sample/sgx_quote", "rb") as f:
            quote_data = f.read()

        with open("sample/sgx_quote_collateral.json", "r") as f:
            collateral_json = json.load(f)

        collateral = dcap_qvl.QuoteCollateralV3.from_json(json.dumps(collateral_json))
        qvr = dcap_qvl.verify(quote_data, collateral, 1234567890)

        policy_json = json.dumps(
            {
                "environment": {
                    "class_id": "3123ec35-8d38-4ea5-87a5-d6c48b567570",
                },
                "reference": {
                    "accepted_tcb_status": ["UpToDate"],
                    "collateral_grace_period": 0,
                },
            }
        )
        policy = dcap_qvl.RegoPolicySet([policy_json])
        result = qvr.validate(policy)

        assert isinstance(result, dcap_qvl.VerifiedReport)
        assert isinstance(result.status, str)
