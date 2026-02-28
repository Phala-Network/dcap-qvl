//! SP1 zkVM P-256 ECDSA verification backend.
//!
//! Uses SP1's native secp256r1 precompiles (`syscall_secp256r1_add`,
//! `syscall_secp256r1_double`) for accelerated elliptic curve point operations.
//! Scalar field arithmetic uses the `p256` crate. When running outside the
//! zkVM (tests, host), SP1-lib falls back to software implementations.

use alloc::vec::Vec;
use p256::elliptic_curve::{ops::Reduce, Field, PrimeField};
use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::Digest;
use sp1_lib::secp256r1::Secp256r1Point;
use sp1_lib::utils::AffinePoint;

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// AlgorithmIdentifier for id-ecPublicKey with secp256r1.
const ECDSA_P256_ALG_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07,
]);

/// AlgorithmIdentifier for ecdsa-with-SHA256.
const ECDSA_SHA256_ALG_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
]);

// ---------------------------------------------------------------------------
// DER signature parsing
// ---------------------------------------------------------------------------

/// Parse a DER-encoded ECDSA signature into raw 64-byte (r || s) form.
fn der_sig_to_raw(der: &[u8]) -> Result<[u8; 64], InvalidSignature> {
    let mut pos = 0usize;

    if der.get(pos).copied() != Some(0x30) {
        return Err(InvalidSignature);
    }
    pos = pos.wrapping_add(1);

    let (_seq_len, consumed) = parse_der_length(der.get(pos..).ok_or(InvalidSignature)?)?;
    pos = pos.wrapping_add(consumed);

    let (r_bytes, consumed) = parse_der_integer(der.get(pos..).ok_or(InvalidSignature)?)?;
    pos = pos.wrapping_add(consumed);

    let (s_bytes, _consumed) = parse_der_integer(der.get(pos..).ok_or(InvalidSignature)?)?;

    let mut raw = [0u8; 64];
    copy_integer_to_fixed(&mut raw, 0, r_bytes)?;
    copy_integer_to_fixed(&mut raw, 32, s_bytes)?;
    Ok(raw)
}

fn parse_der_length(data: &[u8]) -> Result<(usize, usize), InvalidSignature> {
    let first = *data.first().ok_or(InvalidSignature)?;
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        let len = *data.get(1).ok_or(InvalidSignature)? as usize;
        Ok((len, 2))
    } else {
        Err(InvalidSignature)
    }
}

fn parse_der_integer(data: &[u8]) -> Result<(&[u8], usize), InvalidSignature> {
    if data.first().copied() != Some(0x02) {
        return Err(InvalidSignature);
    }
    let (len, len_size) = parse_der_length(data.get(1..).ok_or(InvalidSignature)?)?;
    let start = 1usize.wrapping_add(len_size);
    let end = start.wrapping_add(len);
    let value = data.get(start..end).ok_or(InvalidSignature)?;
    Ok((value, end))
}

fn copy_integer_to_fixed(
    out: &mut [u8; 64],
    offset: usize,
    int_bytes: &[u8],
) -> Result<(), InvalidSignature> {
    let stripped = match int_bytes.iter().position(|&b| b != 0) {
        Some(p) => int_bytes.get(p..).ok_or(InvalidSignature)?,
        None => &[0u8],
    };
    if stripped.len() > 32 {
        return Err(InvalidSignature);
    }
    let pad = 32usize.wrapping_sub(stripped.len());
    let dest = out
        .get_mut(offset.wrapping_add(pad)..offset.wrapping_add(32))
        .ok_or(InvalidSignature)?;
    dest.copy_from_slice(stripped);
    Ok(())
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

/// Convert a `p256::Scalar` to a little-endian bit vector (LSB first, 256 bits).
#[allow(clippy::arithmetic_side_effects)]
fn scalar_to_le_bits(scalar: &p256::Scalar) -> Vec<bool> {
    let be_bytes: p256::FieldBytes = scalar.to_repr();
    let mut bits = Vec::with_capacity(256);
    // Iterate bytes from LSB (last byte) to MSB (first byte)
    for &byte in be_bytes.iter().rev() {
        for bit in 0..8u32 {
            bits.push((byte.wrapping_shr(bit)) & 1 == 1);
        }
    }
    bits
}

/// Reverse a 32-byte slice (big-endian ↔ little-endian).
fn reverse_32(bytes: &[u8]) -> Result<[u8; 32], InvalidSignature> {
    if bytes.len() != 32 {
        return Err(InvalidSignature);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out.reverse();
    Ok(out)
}

/// Extract 32 bytes from a slice into an array.
fn to_array_32(slice: &[u8]) -> Result<[u8; 32], InvalidSignature> {
    if slice.len() != 32 {
        return Err(InvalidSignature);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Parse big-endian bytes as a nonzero P-256 scalar (must be in [1, n-1]).
fn be_to_nonzero_scalar(be: &[u8; 32]) -> Result<p256::Scalar, InvalidSignature> {
    let repr = p256::FieldBytes::from(*be);
    let scalar: p256::Scalar =
        Option::from(p256::Scalar::from_repr(repr)).ok_or(InvalidSignature)?;
    if bool::from(scalar.is_zero()) {
        return Err(InvalidSignature);
    }
    Ok(scalar)
}

/// Parse big-endian bytes as a P-256 scalar, reducing mod n.
/// Used for the message hash which can theoretically be >= n.
fn be_to_scalar_reduce(be: &[u8; 32]) -> p256::Scalar {
    <p256::Scalar as Reduce<p256::U256>>::reduce_bytes(&p256::FieldBytes::from(*be))
}

// ---------------------------------------------------------------------------
// SignatureVerificationAlgorithm implementation
// ---------------------------------------------------------------------------

/// ECDSA P-256 SHA-256 verification using SP1's secp256r1 precompiles.
#[derive(Debug)]
pub struct Sp1EcdsaP256;

impl SignatureVerificationAlgorithm for Sp1EcdsaP256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_P256_ALG_ID
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_SHA256_ALG_ID
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // 1. Hash the message with SHA-256
        let z_bytes: [u8; 32] = sha2::Sha256::digest(message).into();

        // 2. Parse DER-encoded signature to raw (r || s)
        let raw_sig = der_sig_to_raw(signature)?;
        let r_bytes = to_array_32(raw_sig.get(..32).ok_or(InvalidSignature)?)?;
        let s_bytes = to_array_32(raw_sig.get(32..).ok_or(InvalidSignature)?)?;

        // 3. Parse SEC1 uncompressed public key: 0x04 || x (32 BE) || y (32 BE)
        if public_key.first() != Some(&0x04) || public_key.len() != 65 {
            return Err(InvalidSignature);
        }
        let pk_x_be = to_array_32(public_key.get(1..33).ok_or(InvalidSignature)?)?;
        let pk_y_be = to_array_32(public_key.get(33..65).ok_or(InvalidSignature)?)?;

        // 4. Scalar field arithmetic (ECDSA verify algorithm)
        let r = be_to_nonzero_scalar(&r_bytes)?;
        let s = be_to_nonzero_scalar(&s_bytes)?;
        let z = be_to_scalar_reduce(&z_bytes);

        // w = s⁻¹ mod n (s is nonzero, so invert always succeeds)
        let w: p256::Scalar =
            Option::<p256::Scalar>::from(s.invert()).ok_or(InvalidSignature)?;

        // u1 = z·w mod n, u2 = r·w mod n
        let u1 = z * w;
        let u2 = r * w;

        // 5. Build SP1 points: convert BE coords to LE for SP1
        let pk_x_le = reverse_32(&pk_x_be)?;
        let pk_y_le = reverse_32(&pk_y_be)?;
        let q = <Secp256r1Point as AffinePoint<8>>::from(&pk_x_le, &pk_y_le);

        // 6. Compute R = u1·G + u2·Q using SP1 precompiles (Shamir's trick)
        let g = Secp256r1Point::GENERATOR_T;
        let u1_bits = scalar_to_le_bits(&u1);
        let u2_bits = scalar_to_le_bits(&u2);
        let result =
            Secp256r1Point::multi_scalar_multiplication(&u1_bits, g, &u2_bits, q);

        // 7. Check R is not the point at infinity
        if result.is_identity() {
            return Err(InvalidSignature);
        }

        // 8. Extract R.x (LE bytes from SP1) → BE and compare with r
        let result_le_bytes = result.to_le_bytes();
        let rx_le = result_le_bytes.get(..32).ok_or(InvalidSignature)?;
        let rx_be = reverse_32(rx_le)?;

        // For P-256, p > n but p - n ≈ 2^128, so Pr[R.x ∈ [n, p)] ≈ 2^-128.
        // Standard ECDSA: check R.x mod n == r. Since the probability of
        // R.x >= n is negligible, comparing bytes directly is safe in practice.
        if rx_be == r_bytes {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
}

/// ECDSA P-256 SHA-256 algorithm using SP1 secp256r1 precompiles.
pub static ECDSA_P256_SHA256: &Sp1EcdsaP256 = &Sp1EcdsaP256;

// ---------------------------------------------------------------------------
// Native syscall stubs (software fallback for testing on non-zkVM targets)
// ---------------------------------------------------------------------------

/// Software implementations of SP1's secp256r1 syscalls for native testing.
/// These are only compiled when not targeting the zkVM.
#[cfg(not(target_os = "zkvm"))]
mod native_stubs {
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};

    /// Convert SP1's LE u64 limbs to a p256 AffinePoint.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn limbs_to_projective(limbs: &[u64; 8]) -> ProjectivePoint {
        // Convert limbs to LE bytes, then reverse to BE for each coordinate
        let mut x_le = [0u8; 32];
        let mut y_le = [0u8; 32];
        for i in 0..4 {
            let xb = limbs[i].to_le_bytes();
            let yb = limbs[i + 4].to_le_bytes();
            x_le[i * 8..(i + 1) * 8].copy_from_slice(&xb);
            y_le[i * 8..(i + 1) * 8].copy_from_slice(&yb);
        }
        x_le.reverse();
        y_le.reverse();

        let encoded = EncodedPoint::from_affine_coordinates(
            &x_le.into(),
            &y_le.into(),
            false,
        );
        let affine: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        ProjectivePoint::from(affine.unwrap_or(AffinePoint::IDENTITY))
    }

    /// Convert a p256 ProjectivePoint back to SP1's LE u64 limbs.
    #[allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
    fn projective_to_limbs(point: ProjectivePoint, limbs: &mut [u64; 8]) {
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(false);
        let x_be = encoded.x().expect("not identity");
        let y_be = encoded.y().expect("not identity");

        let mut x_le = [0u8; 32];
        let mut y_le = [0u8; 32];
        x_le.copy_from_slice(x_be);
        y_le.copy_from_slice(y_be);
        x_le.reverse();
        y_le.reverse();

        for i in 0..4 {
            limbs[i] = u64::from_le_bytes([
                x_le[i * 8],
                x_le[i * 8 + 1],
                x_le[i * 8 + 2],
                x_le[i * 8 + 3],
                x_le[i * 8 + 4],
                x_le[i * 8 + 5],
                x_le[i * 8 + 6],
                x_le[i * 8 + 7],
            ]);
            limbs[i + 4] = u64::from_le_bytes([
                y_le[i * 8],
                y_le[i * 8 + 1],
                y_le[i * 8 + 2],
                y_le[i * 8 + 3],
                y_le[i * 8 + 4],
                y_le[i * 8 + 5],
                y_le[i * 8 + 6],
                y_le[i * 8 + 7],
            ]);
        }
    }

    #[no_mangle]
    unsafe extern "C" fn syscall_secp256r1_add(p: *mut [u64; 8], q: *const [u64; 8]) {
        let a = limbs_to_projective(&*p);
        let b = limbs_to_projective(&*q);
        use core::ops::Add;
        projective_to_limbs(a.add(b), &mut *p);
    }

    #[no_mangle]
    #[allow(clippy::arithmetic_side_effects)]
    unsafe extern "C" fn syscall_secp256r1_double(p: *mut [u64; 8]) {
        let a = limbs_to_projective(&*p);
        projective_to_limbs(a + a, &mut *p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_ids_match() {
        use rustls_pki_types::alg_id;
        assert_eq!(
            ECDSA_P256_ALG_ID.as_ref(),
            alg_id::ECDSA_P256.as_ref(),
            "P-256 public key AlgorithmIdentifier mismatch"
        );
        assert_eq!(
            ECDSA_SHA256_ALG_ID.as_ref(),
            alg_id::ECDSA_SHA256.as_ref(),
            "ECDSA-SHA256 signature AlgorithmIdentifier mismatch"
        );
    }

    #[test]
    fn test_ecdsa_verify_roundtrip() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key =
            SigningKey::from_bytes(&[0xAB; 32].into()).expect("valid signing key");
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let message = b"test message for SP1 backend verification";

        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        let der_sig = sig.to_der();

        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = pubkey.as_bytes();

        let result = Sp1EcdsaP256.verify_signature(pubkey_bytes, message, der_sig.as_bytes());
        assert!(result.is_ok(), "SP1 backend verification failed: {:?}", result);
    }

    #[test]
    fn test_ecdsa_verify_wrong_message() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key =
            SigningKey::from_bytes(&[0xCD; 32].into()).expect("valid signing key");
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);

        let sig: p256::ecdsa::Signature = signing_key.sign(b"correct message");
        let der_sig = sig.to_der();
        let pubkey = verifying_key.to_encoded_point(false);

        let result =
            Sp1EcdsaP256.verify_signature(pubkey.as_bytes(), b"wrong message", der_sig.as_bytes());
        assert!(result.is_err(), "Should fail with wrong message");
    }

    #[test]
    fn test_ecdsa_verify_wrong_key() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let signing_key =
            SigningKey::from_bytes(&[0xEF; 32].into()).expect("valid signing key");
        let wrong_key =
            SigningKey::from_bytes(&[0x12; 32].into()).expect("valid signing key");
        let wrong_verifying = p256::ecdsa::VerifyingKey::from(&wrong_key);

        let message = b"test message";
        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        let der_sig = sig.to_der();
        let pubkey = wrong_verifying.to_encoded_point(false);

        let result =
            Sp1EcdsaP256.verify_signature(pubkey.as_bytes(), message, der_sig.as_bytes());
        assert!(result.is_err(), "Should fail with wrong key");
    }
}
