"""
Type stubs for dcap_qvl Python bindings.

This file provides type hints for the compiled Rust extension, enabling better
IDE support, type checking with mypy, and improved developer experience.
"""

from typing import List, Optional, Union, Awaitable
from typing_extensions import Literal

__version__: str
__all__: List[str]


class QuoteCollateralV3:
    """
    Represents quote collateral data required for DCAP quote verification.

    This class contains all the necessary certificate chains, CRLs, and
    attestation information needed to verify an SGX or TDX quote.
    """

    def __init__(
        self,
        pck_crl_issuer_chain: str,
        root_ca_crl: bytes,
        pck_crl: bytes,
        tcb_info_issuer_chain: str,
        tcb_info: str,
        tcb_info_signature: bytes,
        qe_identity_issuer_chain: str,
        qe_identity: str,
        qe_identity_signature: bytes,
    ) -> None:
        """
        Create a new QuoteCollateralV3 instance.

        Args:
            pck_crl_issuer_chain: PCK CRL issuer certificate chain (PEM format)
            root_ca_crl: Root CA certificate revocation list
            pck_crl: PCK certificate revocation list
            tcb_info_issuer_chain: TCB info issuer certificate chain (PEM format)
            tcb_info: TCB (Trusted Computing Base) information (JSON string)
            tcb_info_signature: Signature for the TCB info
            qe_identity_issuer_chain: QE identity issuer certificate chain (PEM format)
            qe_identity: Quoting Enclave identity information (JSON string)
            qe_identity_signature: Signature for the QE identity
        """
        ...

    @property
    def pck_crl_issuer_chain(self) -> str:
        """PCK CRL issuer certificate chain in PEM format."""
        ...

    @property
    def root_ca_crl(self) -> bytes:
        """Root CA certificate revocation list."""
        ...

    @property
    def pck_crl(self) -> bytes:
        """PCK certificate revocation list."""
        ...

    @property
    def tcb_info_issuer_chain(self) -> str:
        """TCB info issuer certificate chain in PEM format."""
        ...

    @property
    def tcb_info(self) -> str:
        """TCB (Trusted Computing Base) information as JSON string."""
        ...

    @property
    def tcb_info_signature(self) -> bytes:
        """Signature for the TCB info."""
        ...

    @property
    def qe_identity_issuer_chain(self) -> str:
        """QE identity issuer certificate chain in PEM format."""
        ...

    @property
    def qe_identity(self) -> str:
        """Quoting Enclave identity information as JSON string."""
        ...

    @property
    def qe_identity_signature(self) -> bytes:
        """Signature for the QE identity."""
        ...

    def to_json(self) -> str:
        """
        Serialize the collateral to a JSON string.

        Returns:
            JSON string representation of the collateral data

        Raises:
            ValueError: If serialization fails
        """
        ...

    @staticmethod
    def from_json(json_str: str) -> "QuoteCollateralV3":
        """
        Create a QuoteCollateralV3 instance from a JSON string.

        Args:
            json_str: JSON string containing collateral data

        Returns:
            New QuoteCollateralV3 instance

        Raises:
            ValueError: If JSON parsing fails or data is invalid
        """
        ...


class VerifiedReport:
    """
    Contains the results of DCAP quote verification.

    This class holds the verification status and any security advisories
    that were found during the quote verification process.
    """

    @property
    def status(self) -> str:
        """
        Verification status string.

        Common values include:
        - "OK": Verification successful, no issues
        - "SW_HARDENING_NEEDED": Software hardening recommended
        - "CONFIGURATION_NEEDED": Platform configuration required
        - "OUT_OF_DATE": TCB is out of date
        - "REVOKED": Certificate or key has been revoked
        """
        ...

    @property
    def advisory_ids(self) -> List[str]:
        """
        List of security advisory IDs that apply to this quote.

        These are Intel security advisory identifiers (e.g., "INTEL-SA-00334")
        that indicate known security issues affecting the attested platform.
        """
        ...

    def to_json(self) -> str:
        """
        Serialize the verification report to a JSON string.

        Returns:
            JSON string representation of the verification report

        Raises:
            ValueError: If serialization fails
        """
        ...

# Synchronous functions


def verify(
    raw_quote: bytes,
    collateral: QuoteCollateralV3,
    now_secs: int
) -> VerifiedReport:
    """
    Verify an SGX or TDX quote with the provided collateral data.

    This function performs cryptographic verification of the quote against
    the provided collateral information, checking certificates, signatures,
    and revocation status.

    Args:
        raw_quote: Raw quote data as bytes (SGX or TDX format)
        collateral: Quote collateral containing certificates and attestation data
        now_secs: Current timestamp in seconds since Unix epoch for time-based checks

    Returns:
        VerifiedReport containing verification status and advisory information

    Raises:
        ValueError: If verification fails due to invalid data, expired certificates,
                   revoked keys, or other verification errors

    Example:
        >>> import dcap_qvl
        >>> import time
        >>>
        >>> # Load quote and collateral data
        >>> with open("quote.bin", "rb") as f:
        ...     quote_data = f.read()
        >>>
        >>> collateral = dcap_qvl.QuoteCollateralV3.from_json(collateral_json)
        >>> result = dcap_qvl.verify(quote_data, collateral, int(time.time()))
        >>> print(f"Status: {result.status}")
    """
    ...

# Asynchronous functions (available when compiled with 'report' feature)


async def get_collateral(
    pccs_url: str,
    raw_quote: bytes
) -> QuoteCollateralV3:
    """
    Fetch quote collateral from a PCCS (Provisioning Certificate Caching Service).

    This async function connects to a PCCS server to retrieve the necessary
    collateral data for verifying the provided quote.

    Args:
        pccs_url: PCCS server URL (e.g., "https://localhost:8081/sgx/certification/v4/")
        raw_quote: Raw quote data as bytes to get collateral for

    Returns:
        QuoteCollateralV3 containing the fetched collateral data

    Raises:
        ValueError: If the request fails, server returns an error, or data is invalid

    Example:
        >>> import asyncio
        >>> import dcap_qvl
        >>>
        >>> async def main():
        ...     pccs_url = "https://api.trustedservices.intel.com/sgx/certification/v4/"
        ...     with open("quote.bin", "rb") as f:
        ...         quote_data = f.read()
        ...     collateral = await dcap_qvl.get_collateral(pccs_url, quote_data)
        ...     print(f"Got collateral with TCB info: {len(collateral.tcb_info)} chars")
        >>>
        >>> asyncio.run(main())
    """
    ...


async def get_collateral_from_pcs(raw_quote: bytes) -> QuoteCollateralV3:
    """
    Fetch quote collateral from Intel's default PCS (Provisioning Certificate Service).

    This is a convenience function that uses Intel's production PCS endpoint
    to retrieve collateral data.

    Args:
        raw_quote: Raw quote data as bytes to get collateral for

    Returns:
        QuoteCollateralV3 containing the fetched collateral data

    Raises:
        ValueError: If the request fails, server returns an error, or data is invalid

    Example:
        >>> import asyncio
        >>> import dcap_qvl
        >>>
        >>> async def main():
        ...     with open("quote.bin", "rb") as f:
        ...         quote_data = f.read()
        ...     collateral = await dcap_qvl.get_collateral_from_pcs(quote_data)
        ...     return collateral
        >>>
        >>> collateral = asyncio.run(main())
    """
    ...


async def get_collateral_and_verify(
    raw_quote: bytes,
    pccs_url: Optional[str]
) -> VerifiedReport:
    """
    Fetch collateral and verify quote in a single operation.

    This convenience function combines collateral fetching and quote verification
    into a single async operation.

    Args:
        raw_quote: Raw quote data as bytes
        pccs_url: Optional PCCS URL. If None, uses Intel's default PCS

    Returns:
        VerifiedReport containing verification results

    Raises:
        ValueError: If collateral fetching or verification fails

    Example:
        >>> import asyncio
        >>> import dcap_qvl
        >>>
        >>> async def verify_quote():
        ...     with open("quote.bin", "rb") as f:
        ...         quote_data = f.read()
        ...
        ...     # Use default Intel PCS (pass None for pccs_url)
        ...     result = await dcap_qvl.get_collateral_and_verify(quote_data, None)
        ...     print(f"Verification status: {result.status}")
        ...
        ...     # Or use custom PCCS
        ...     custom_url = "https://my-pccs.example.com/sgx/certification/v4/"
        ...     result = await dcap_qvl.get_collateral_and_verify(quote_data, custom_url)
        ...     return result
        >>>
        >>> result = asyncio.run(verify_quote())
    """
    ...
