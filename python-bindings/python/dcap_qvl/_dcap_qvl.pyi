"""
Type stubs for the _dcap_qvl C extension module.

This file provides detailed type hints for the compiled Rust extension,
enabling better IDE support, type checking with mypy, and improved
developer experience.
"""

from __future__ import annotations

from typing import List, Optional, Union

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

    @property
    def ppid(self) -> bytes:
        """Platform PPID parsed from the PCK certificate SGX extension."""
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

class PyQuoteHeader:
    """Structured quote header parsed from raw quote."""

    @property
    def version(self) -> int: ...

    @property
    def attestation_key_type(self) -> int: ...

    @property
    def tee_type(self) -> int: ...

    @property
    def qe_svn(self) -> int: ...

    @property
    def pce_svn(self) -> int: ...

    @property
    def qe_vendor_id(self) -> bytes: ...

    @property
    def user_data(self) -> bytes: ...


class PyTdReport10:
    """TDX TDREPORT (1.0) structure."""

    @property
    def tee_tcb_svn(self) -> bytes: ...

    @property
    def mr_seam(self) -> bytes: ...

    @property
    def mr_signer_seam(self) -> bytes: ...

    @property
    def seam_attributes(self) -> bytes: ...

    @property
    def td_attributes(self) -> bytes: ...

    @property
    def xfam(self) -> bytes: ...

    @property
    def mr_td(self) -> bytes: ...

    @property
    def mr_config_id(self) -> bytes: ...

    @property
    def mr_owner(self) -> bytes: ...

    @property
    def mr_owner_config(self) -> bytes: ...

    @property
    def rt_mr0(self) -> bytes: ...

    @property
    def rt_mr1(self) -> bytes: ...

    @property
    def rt_mr2(self) -> bytes: ...

    @property
    def rt_mr3(self) -> bytes: ...

    @property
    def report_data(self) -> bytes: ...


class PyTdReport15(PyTdReport10):
    """TDX TDREPORT 1.5 structure."""

    @property
    def tee_tcb_svn2(self) -> bytes: ...

    @property
    def mr_service_td(self) -> bytes: ...


class PySgxEnclaveReport:
    """SGX enclave report structure."""

    @property
    def cpu_svn(self) -> bytes: ...

    @property
    def attributes(self) -> bytes: ...

    @property
    def mr_enclave(self) -> bytes: ...

    @property
    def mr_signer(self) -> bytes: ...

    @property
    def report_data(self) -> bytes: ...


class PyPckExtension:
    """Parsed values from Intel SGX extension in the PCK leaf certificate."""

    @property
    def ppid(self) -> bytes: ...

    @property
    def cpu_svn(self) -> bytes: ...

    @property
    def pce_svn(self) -> int: ...

    @property
    def pce_id(self) -> bytes: ...

    @property
    def fmspc(self) -> bytes: ...

    @property
    def sgx_type(self) -> int: ...

    @property
    def platform_instance_id(self) -> Optional[bytes]: ...

    def get_value(self, oid: str) -> Optional[bytes]:
        """Look up an arbitrary OID inside the raw Intel SGX extension.

        The search is recursive so nested OIDs can be found with a single
        OID string (e.g. ``"1.2.840.113741.1.13.1.2.17"`` for PCESVN).

        Args:
            oid: Dotted-decimal OID string

        Returns:
            Raw DER value bytes, or None if the OID is not present.

        Raises:
            ValueError: If the OID string is malformed.
        """
        ...


class PySimplePolicy:
    """Verification policy with builder pattern.

    Use ``SimplePolicy.strict(now_secs)`` to create a strict policy (only UpToDate),
    then chain builder methods to relax constraints.

    Example::

        policy = SimplePolicy.strict(now_secs) \\
            .allow_status("SWHardeningNeeded") \\
            .accept_advisory("INTEL-SA-00334") \\
            .collateral_grace_period(90 * 24 * 3600) \\
            .qe_grace_period(7 * 24 * 3600)
    """

    @staticmethod
    def strict(now_secs: int) -> "PySimplePolicy":
        """Create a strict policy: only UpToDate, no grace, no advisory tolerance."""
        ...

    def allow_status(self, status: str) -> "PySimplePolicy":
        """Allow an additional TCB status (e.g. "SWHardeningNeeded")."""
        ...

    def accept_advisory(self, advisory_id: str) -> "PySimplePolicy":
        """Accept a specific advisory ID (e.g. "INTEL-SA-00334")."""
        ...

    def collateral_grace_period(self, secs: int) -> "PySimplePolicy":
        """Set collateral grace period in seconds."""
        ...

    def platform_grace_period(self, secs: int) -> "PySimplePolicy":
        """Set platform grace period in seconds."""
        ...

    def qe_grace_period(self, secs: int) -> "PySimplePolicy":
        """Set QE grace period in seconds."""
        ...

    def min_tcb_eval_data_number(self, min: int) -> "PySimplePolicy":
        """Set minimum TCB evaluation data number."""
        ...

    def allow_dynamic_platform(self, allow: bool) -> "PySimplePolicy":
        """Set whether dynamic platforms are allowed."""
        ...

    def allow_cached_keys(self, allow: bool) -> "PySimplePolicy":
        """Set whether cached keys are allowed."""
        ...

    def allow_smt(self, allow: bool) -> "PySimplePolicy":
        """Set whether SMT (hyperthreading) is allowed."""
        ...

    def accepted_sgx_types(self, types: List[int]) -> "PySimplePolicy":
        """Set accepted SGX types (e.g. [0, 1, 2])."""
        ...


class PyRegoPolicy:
    """Intel QAL-compatible Rego policy."""

    def __init__(self, policy_json: str) -> None:
        """Create a Rego policy from Intel-format JSON."""
        ...

    @staticmethod
    def with_rego(policy_json: str, rego_source: str) -> "PyRegoPolicy":
        """Create a Rego policy with a custom Rego script."""
        ...


class PyRegoPolicySet:
    """Intel QAL-compatible multi-measurement Rego policy set."""

    def __init__(self, policy_jsons: List[str]) -> None:
        """Create a Rego policy set from multiple Intel-format JSON policies."""
        ...

    @staticmethod
    def with_rego(
        policy_jsons: List[str], rego_source: str
    ) -> "PyRegoPolicySet":
        """Create a Rego policy set with a custom Rego script."""
        ...


class PyQuoteVerificationResult:
    """Intermediate result from crypto verification (phase 1).

    Use ``validate(policy)`` to apply a policy and get a ``PyVerifiedReport``.
    Use ``into_report_unchecked()`` to skip policy validation (dangerous).

    The result is consumed on validate/into_report_unchecked — calling twice raises ValueError.
    """

    def validate(
        self, policy: Union[PySimplePolicy, PyRegoPolicy, PyRegoPolicySet]
    ) -> PyVerifiedReport:
        """Validate against a policy, returning a VerifiedReport. Consumes the result.

        Args:
            policy: Verification policy

        Returns:
            PyVerifiedReport containing verification status

        Raises:
            ValueError: If result already consumed or policy validation fails
        """
        ...

    def into_report_unchecked(self) -> PyVerifiedReport:
        """Get VerifiedReport without policy validation. Consumes the result.

        WARNING: Skips all policy checks. Use only when you handle validation externally.

        Returns:
            PyVerifiedReport containing verification status

        Raises:
            ValueError: If result already consumed
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

    @property
    def header(self) -> PyQuoteHeader:
        """Structured quote header."""
        ...

    @property
    def report(self) -> Union[PyTdReport10, PyTdReport15, PySgxEnclaveReport]:
        """Structured quote report (TDX TDREPORT10/15 or SGX enclave report)."""
        ...

    def cert_chain_pem_bytes(self) -> Optional[bytes]:
        """Return embedded PCK certificate chain as PEM bytes (best-effort).

        Returns None if the quote doesn't contain a PEM chain.
        """
        ...

    def pck_extension(self) -> Optional[PyPckExtension]:
        """Parse Intel SGX extension from leaf PCK certificate (best-effort).

        Returns None if parsing fails or the leaf certificate isn't available.
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
) -> PyQuoteVerificationResult:
    """
    Verify an SGX or TDX quote (crypto only, phase 1).

    Performs cryptographic verification of the quote against the provided
    collateral. Returns a QuoteVerificationResult that must be validated
    with a policy via .validate(policy) to get a VerifiedReport.

    Args:
        raw_quote: Raw quote data as bytes (SGX or TDX format)
        collateral: Quote collateral containing certificates and attestation data
        now_secs: Current timestamp in seconds since Unix epoch for time-based checks

    Returns:
        PyQuoteVerificationResult: use .validate(policy) to get VerifiedReport

    Raises:
        ValueError: If cryptographic verification fails
    """
    ...

def py_verify_with_root_ca(
    raw_quote: bytes,
    collateral: PyQuoteCollateralV3,
    root_ca_der: bytes,
    now_secs: int,
) -> PyQuoteVerificationResult:
    """
    Verify an SGX or TDX quote with custom root CA (crypto only, phase 1).

    Args:
        raw_quote: Raw quote data as bytes (SGX or TDX format)
        collateral: Quote collateral containing certificates and attestation data
        root_ca_der: Custom root CA certificate in DER format
        now_secs: Current timestamp in seconds since Unix epoch for time-based checks

    Returns:
        PyQuoteVerificationResult: use .validate(policy) to get VerifiedReport

    Raises:
        ValueError: If cryptographic verification fails
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

def parse_pck_extension_from_pem(pem_bytes: bytes) -> PyPckExtension:
    """Parse the Intel SGX extension from a PEM-encoded certificate chain.

    The first (leaf) certificate in the chain is used.

    Args:
        pem_bytes: PEM-encoded certificate chain as bytes

    Returns:
        PyPckExtension with parsed extension fields

    Raises:
        ValueError: If parsing fails or no certificates are found
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
