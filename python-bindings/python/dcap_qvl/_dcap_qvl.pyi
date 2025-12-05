"""
Type stubs for the _dcap_qvl C extension module.

This file provides detailed type hints for the compiled Rust extension,
enabling better IDE support, type checking with mypy, and improved
developer experience.
"""

from typing import List

class PyQuoteCollateralV3:
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
        Create a new PyQuoteCollateralV3 instance.

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
    def from_json(json_str: str) -> "PyQuoteCollateralV3":
        """
        Create a PyQuoteCollateralV3 instance from a JSON string.

        Args:
            json_str: JSON string containing collateral data

        Returns:
            New PyQuoteCollateralV3 instance

        Raises:
            ValueError: If JSON parsing fails or data is invalid
        """
        ...

class PyVerifiedReport:
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

class PyQuote:
    """
    Represents a parsed SGX or TDX quote.

    This class provides access to quote metadata and identifiers
    without requiring collateral data for verification.
    """

    @staticmethod
    def parse(raw_quote: bytes) -> "PyQuote":
        """
        Parse a raw quote from bytes.

        Args:
            raw_quote: Raw quote data as bytes (SGX or TDX format)

        Returns:
            PyQuote instance with parsed quote data

        Raises:
            ValueError: If quote parsing fails due to invalid format or corrupted data
        """
        ...

    def fmspc(self) -> str:
        """
        Extract the FMSPC (Family-Model-Stepping-Platform-CustomSKU) identifier.

        The FMSPC is a 6-byte identifier that uniquely identifies the
        platform's TCB level and is used for collateral retrieval.

        Returns:
            FMSPC as uppercase hexadecimal string (12 characters)

        Raises:
            ValueError: If FMSPC cannot be extracted from the quote
        """
        ...

    def ca(self) -> str:
        """
        Extract the CA (Certificate Authority) identifier.

        The CA identifier indicates which certificate authority
        should be used for quote verification.

        Returns:
            CA identifier as string

        Raises:
            ValueError: If CA identifier cannot be extracted from the quote
        """
        ...

    def is_tdx(self) -> bool:
        """
        Check if this is a TDX (Trust Domain Extensions) quote.

        Returns:
            True if the quote is TDX format, False if SGX format
        """
        ...

    def is_sgx(self) -> bool:
        """
        Check if this is an SGX quote.

        Returns:
            True if the quote is SGX format, False if TDX format
        """
        ...

    def quote_type(self) -> str:
        """
        Get the quote type as a string.

        Returns:
            "TDX" for TDX quotes, "SGX" for SGX quotes
        """
        ...

def py_verify(
    raw_quote: bytes, collateral: PyQuoteCollateralV3, now_secs: int
) -> PyVerifiedReport:
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
        PyVerifiedReport containing verification status and advisory information

    Raises:
        ValueError: If verification fails due to invalid data, expired certificates,
                   revoked keys, or other verification errors
    """
    ...

def py_verify_with_root_ca(
    raw_quote: bytes,
    collateral: PyQuoteCollateralV3,
    root_ca_der: bytes,
    now_secs: int
) -> PyVerifiedReport:
    """
    Verify an SGX or TDX quote with the provided collateral data and custom root CA.

    Args:
        raw_quote: Raw quote data as bytes (SGX or TDX format)
        collateral: Quote collateral containing certificates and attestation data
        root_ca_der: Custom root CA certificate in DER format
        now_secs: Current timestamp in seconds since Unix epoch for time-based checks

    Returns:
        PyVerifiedReport containing verification status and advisory information

    Raises:
        ValueError: If verification fails
    """
    ...

def parse_quote(raw_quote: bytes) -> PyQuote:
    """
    Parse a raw quote from bytes (convenience function).

    This is a convenience function that calls PyQuote.parse() directly.

    Args:
        raw_quote: Raw quote data as bytes (SGX or TDX format)

    Returns:
        PyQuote instance with parsed quote data

    Raises:
        ValueError: If quote parsing fails due to invalid format or corrupted data
    """
    ...

async def get_collateral_for_fmspc(
    pccs_url: str, fmspc: str, ca: str, is_sgx: bool
) -> PyQuoteCollateralV3:
    """
    Get collateral for a specific FMSPC from PCCS URL.

    Args:
        pccs_url: PCCS server URL
        fmspc: FMSPC identifier as hex string
        ca: Certificate authority identifier
        is_sgx: True for SGX, False for TDX

    Returns:
        PyQuoteCollateralV3 with collateral data

    Raises:
        ValueError: If FMSPC is invalid
        RuntimeError: If network request fails
    """
    ...
