from __future__ import annotations

from enum import IntEnum


class AttestationKeyType(IntEnum):
    """Attestation key type (subset used in SGX/TDX DCAP quotes)."""

    ECDSA_P256 = 2
    ECDSA_P384 = 3


class TeeType(IntEnum):
    """TEE type values used by Intel DCAP quote header."""

    SGX = 0x00000000
    TDX = 0x00000081
