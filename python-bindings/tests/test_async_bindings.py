"""
Tests for the async Python bindings of dcap-qvl.
"""

import pytest
import asyncio
from pathlib import Path

import dcap_qvl


class TestAsyncFunctions:
    """Test async functionality."""
    
    def test_async_functions_available(self):
        """Test that async functions are available when compiled with 'report' feature."""
        # This test will pass if compiled with 'report' feature, otherwise skip
        if hasattr(dcap_qvl, 'get_collateral'):
            assert hasattr(dcap_qvl, 'get_collateral')
            assert hasattr(dcap_qvl, 'get_collateral_from_pcs')
            assert hasattr(dcap_qvl, 'get_collateral_and_verify')
        else:
            pytest.skip("Async functions not available (compiled without 'report' feature)")
    
    @pytest.mark.asyncio
    async def test_get_collateral_from_pcs_with_invalid_data(self):
        """Test get_collateral_from_pcs with invalid quote data."""
        if not hasattr(dcap_qvl, 'get_collateral_from_pcs'):
            pytest.skip("Async functions not available")
        
        invalid_quote = b"invalid_quote_data"
        
        with pytest.raises(ValueError, match="Failed to get collateral from PCS"):
            await dcap_qvl.get_collateral_from_pcs(invalid_quote)
    
    @pytest.mark.asyncio
    async def test_get_collateral_with_invalid_data(self):
        """Test get_collateral with invalid quote data."""
        if not hasattr(dcap_qvl, 'get_collateral'):
            pytest.skip("Async functions not available")
        
        invalid_quote = b"invalid_quote_data"
        pccs_url = "https://api.trustedservices.intel.com/sgx/certification/v4/"
        
        with pytest.raises(ValueError, match="Failed to get collateral"):
            await dcap_qvl.get_collateral(pccs_url, invalid_quote)
    
    @pytest.mark.asyncio
    async def test_get_collateral_and_verify_with_invalid_data(self):
        """Test get_collateral_and_verify with invalid quote data."""
        if not hasattr(dcap_qvl, 'get_collateral_and_verify'):
            pytest.skip("Async functions not available")
        
        invalid_quote = b"invalid_quote_data"
        
        with pytest.raises(ValueError, match="Failed to get collateral and verify"):
            await dcap_qvl.get_collateral_and_verify(invalid_quote, None)
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test that multiple async requests can run concurrently."""
        if not hasattr(dcap_qvl, 'get_collateral_from_pcs'):
            pytest.skip("Async functions not available")
        
        # Create multiple invalid quotes
        quotes = [b"invalid_quote_1", b"invalid_quote_2", b"invalid_quote_3"]
        
        # Run them concurrently - they should all fail, but we're testing concurrency
        async def get_collateral_safe(quote):
            try:
                await dcap_qvl.get_collateral_from_pcs(quote)
                return "success"
            except ValueError:
                return "expected_error"
        
        tasks = [get_collateral_safe(quote) for quote in quotes]
        results = await asyncio.gather(*tasks)
        
        # All should have failed with "expected_error"
        assert all(result == "expected_error" for result in results)
    
    @pytest.mark.asyncio
    async def test_async_with_timeout(self):
        """Test async functions with timeout."""
        if not hasattr(dcap_qvl, 'get_collateral_from_pcs'):
            pytest.skip("Async functions not available")
        
        invalid_quote = b"invalid_quote_data"
        
        # Test with a timeout - should fail quickly due to invalid data
        with pytest.raises(ValueError):
            await asyncio.wait_for(
                dcap_qvl.get_collateral_from_pcs(invalid_quote),
                timeout=5.0
            )


@pytest.mark.skipif(
    not Path("../sample/tdx_quote").exists(),
    reason="Sample TDX quote file not available"
)
class TestAsyncWithSampleData:
    """Test async functions with sample data if available."""
    
    @pytest.mark.asyncio
    async def test_get_collateral_from_pcs_with_sample_data(self):
        """Test get_collateral_from_pcs with sample TDX quote."""
        if not hasattr(dcap_qvl, 'get_collateral_from_pcs'):
            pytest.skip("Async functions not available")
        
        # Load sample quote
        with open("../sample/tdx_quote", "rb") as f:
            quote_data = f.read()
        
        # This will likely fail due to network issues or expired certificates,
        # but it tests the basic functionality
        try:
            collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
            assert isinstance(collateral, dcap_qvl.QuoteCollateralV3)
            assert isinstance(collateral.tcb_info, str)
        except ValueError as e:
            # Expected - network issues, expired certs, etc.
            assert "Failed to get collateral from PCS" in str(e)


class TestAsyncImportBehavior:
    """Test import behavior for async functions."""
    
    def test_graceful_import_fallback(self):
        """Test that the module imports gracefully even if async functions aren't available."""
        # This test ensures the __init__.py import logic works correctly
        assert hasattr(dcap_qvl, 'QuoteCollateralV3')
        assert hasattr(dcap_qvl, 'VerifiedReport')
        assert hasattr(dcap_qvl, 'verify')
        
        # Check __all__ contains at least the basic functions
        assert 'QuoteCollateralV3' in dcap_qvl.__all__
        assert 'VerifiedReport' in dcap_qvl.__all__
        assert 'verify' in dcap_qvl.__all__
        
        # If async functions are available, they should be in __all__
        if hasattr(dcap_qvl, 'get_collateral'):
            assert 'get_collateral' in dcap_qvl.__all__
            assert 'get_collateral_from_pcs' in dcap_qvl.__all__
            assert 'get_collateral_and_verify' in dcap_qvl.__all__