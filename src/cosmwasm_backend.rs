//! CosmWasm P-256 ECDSA verification backend.
//!
//! Uses the CosmWasm host's native `secp256r1_verify` function for ECDSA P-256
//! signature verification, which is orders of magnitude cheaper than pure-WASM
//! implementations. Requires wasmd v0.51+ / CosmWasm 2.1+.

use rustls_pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use sha2::Digest;

// ---------------------------------------------------------------------------
// CosmWasm FFI types
// ---------------------------------------------------------------------------

/// Memory region descriptor matching the CosmWasm VM ABI.
/// Must be 12 bytes: offset (u32) + capacity (u32) + length (u32).
#[cfg(target_arch = "wasm32")]
#[repr(C)]
struct Region {
    offset: u32,
    capacity: u32,
    length: u32,
}

#[cfg(target_arch = "wasm32")]
impl Region {
    /// Create a Region pointing to an existing slice (borrowed, no allocation).
    fn from_slice(slice: &[u8]) -> Self {
        Self {
            offset: slice.as_ptr() as u32,
            capacity: slice.len() as u32,
            length: slice.len() as u32,
        }
    }

    fn as_ptr(&self) -> u32 {
        (self as *const Self) as u32
    }
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    /// CosmWasm host function: secp256r1 ECDSA verification.
    /// Returns 0 on success, 1 on verification failure, >1 on error.
    fn secp256r1_verify(message_hash_ptr: u32, signature_ptr: u32, public_key_ptr: u32) -> u32;
}

// ---------------------------------------------------------------------------
// OID constants — must match the exact DER bytes used by webpki/rustcrypto
// ---------------------------------------------------------------------------

/// AlgorithmIdentifier for id-ecPublicKey with secp256r1.
/// OID 1.2.840.10045.2.1 + 1.2.840.10045.3.1.7
const ECDSA_P256_ALG_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07,
]);

/// AlgorithmIdentifier for ecdsa-with-SHA256.
/// OID 1.2.840.10045.4.3.2
const ECDSA_SHA256_ALG_ID: AlgorithmIdentifier = AlgorithmIdentifier::from_slice(&[
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
]);

// ---------------------------------------------------------------------------
// DER signature parsing
// ---------------------------------------------------------------------------

/// Parse a DER-encoded ECDSA signature into raw 64-byte (r || s) form.
///
/// DER: SEQUENCE { INTEGER r, INTEGER s }
/// Each integer may have a leading 0x00 byte for sign padding.
/// We must extract exactly 32 bytes for each, left-padded with zeros.
fn der_sig_to_raw(der: &[u8]) -> Result<[u8; 64], InvalidSignature> {
    // Minimal DER parsing for SEQUENCE { INTEGER, INTEGER }
    let mut pos = 0;

    // SEQUENCE tag
    if der.get(pos).copied() != Some(0x30) {
        return Err(InvalidSignature);
    }
    pos = pos.wrapping_add(1);

    // SEQUENCE length
    let (_seq_len, consumed) = parse_der_length(der.get(pos..).ok_or(InvalidSignature)?)?;
    pos = pos.wrapping_add(consumed);

    // First INTEGER (r)
    let (r_bytes, consumed) = parse_der_integer(der.get(pos..).ok_or(InvalidSignature)?)?;
    pos = pos.wrapping_add(consumed);

    // Second INTEGER (s)
    let (s_bytes, _consumed) = parse_der_integer(der.get(pos..).ok_or(InvalidSignature)?)?;

    let mut raw = [0u8; 64];
    copy_integer_to_fixed(&mut raw, 0, r_bytes)?;
    copy_integer_to_fixed(&mut raw, 32, s_bytes)?;
    Ok(raw)
}

/// Parse a DER length field, returning (length, bytes_consumed).
fn parse_der_length(data: &[u8]) -> Result<(usize, usize), InvalidSignature> {
    let first = *data.first().ok_or(InvalidSignature)?;
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        let len = *data.get(1).ok_or(InvalidSignature)? as usize;
        Ok((len, 2))
    } else {
        // Signatures shouldn't need longer length encodings
        Err(InvalidSignature)
    }
}

/// Parse a DER INTEGER, returning (value_bytes, total_bytes_consumed).
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

/// Copy a variable-length big-endian integer into a fixed 32-byte slot.
/// Handles leading zero bytes (sign padding) and short values.
fn copy_integer_to_fixed(
    out: &mut [u8; 64],
    offset: usize,
    int_bytes: &[u8],
) -> Result<(), InvalidSignature> {
    // Strip leading zeros
    let stripped = match int_bytes.iter().position(|&b| b != 0) {
        Some(p) => int_bytes.get(p..).ok_or(InvalidSignature)?,
        None => &[0u8], // all zeros
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
// SignatureVerificationAlgorithm implementation
// ---------------------------------------------------------------------------

/// ECDSA P-256 SHA-256 verification using CosmWasm's native host function.
#[derive(Debug)]
pub struct CosmWasmEcdsaP256;

impl SignatureVerificationAlgorithm for CosmWasmEcdsaP256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_P256_ALG_ID
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        ECDSA_SHA256_ALG_ID
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        // 1. Hash the message (CosmWasm expects pre-hashed 32-byte digest)
        let hash: [u8; 32] = sha2::Sha256::digest(message).into();

        // 2. DER-decode signature to raw 64-byte (r || s)
        let raw_sig = der_sig_to_raw(signature)?;

        // 3. Call the host function
        #[cfg(target_arch = "wasm32")]
        {
            let hash_region = Region::from_slice(&hash);
            let sig_region = Region::from_slice(&raw_sig);
            let pk_region = Region::from_slice(public_key);

            let result = unsafe {
                secp256r1_verify(hash_region.as_ptr(), sig_region.as_ptr(), pk_region.as_ptr())
            };

            match result {
                0 => Ok(()),
                _ => Err(InvalidSignature),
            }
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&hash, &raw_sig, public_key);
            Err(InvalidSignature)
        }
    }
}

/// ECDSA P-256 SHA-256 algorithm using CosmWasm native host verification.
pub static ECDSA_P256_SHA256: &CosmWasmEcdsaP256 = &CosmWasmEcdsaP256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_sig_parsing() {
        // A known DER-encoded ECDSA signature (simplified test vector)
        // SEQUENCE { INTEGER(32 bytes r), INTEGER(32 bytes s) }
        let mut der = alloc::vec![0x30, 0x44]; // SEQUENCE, length 68
        der.push(0x02);
        der.push(0x20); // INTEGER, length 32
        der.extend_from_slice(&[0x01; 32]); // r = 0x0101...01
        der.push(0x02);
        der.push(0x20); // INTEGER, length 32
        der.extend_from_slice(&[0x02; 32]); // s = 0x0202...02

        let raw = der_sig_to_raw(&der).expect("should parse");
        assert_eq!(&raw[..32], &[0x01; 32]);
        assert_eq!(&raw[32..], &[0x02; 32]);
    }

    #[test]
    fn test_der_sig_with_leading_zero() {
        // r has leading 0x00 (sign padding), actual value is 31 bytes
        let mut der = alloc::vec![0x30, 0x45]; // SEQUENCE, length 69
        der.push(0x02);
        der.push(0x21); // INTEGER, length 33
        der.push(0x00); // leading zero
        der.extend_from_slice(&[0xFF; 32]); // r = 0x00FF...FF
        der.push(0x02);
        der.push(0x20); // INTEGER, length 32
        der.extend_from_slice(&[0x01; 32]); // s

        let raw = der_sig_to_raw(&der).expect("should parse");
        assert_eq!(&raw[..32], &[0xFF; 32]);
        assert_eq!(&raw[32..], &[0x01; 32]);
    }

    #[test]
    fn test_der_sig_short_integer() {
        // r is only 20 bytes (should be zero-padded to 32)
        let mut der = alloc::vec![0x30, 0x38]; // SEQUENCE, length 56
        der.push(0x02);
        der.push(0x14); // INTEGER, length 20
        der.extend_from_slice(&[0xAB; 20]); // r = short
        der.push(0x02);
        der.push(0x20); // INTEGER, length 32
        der.extend_from_slice(&[0xCD; 32]); // s

        let raw = der_sig_to_raw(&der).expect("should parse");
        // r should be zero-padded: 12 zeros + 20 bytes of 0xAB
        assert_eq!(&raw[..12], &[0x00; 12]);
        assert_eq!(&raw[12..32], &[0xAB; 20]);
        assert_eq!(&raw[32..], &[0xCD; 32]);
    }

    #[test]
    fn test_algorithm_ids_match_rustcrypto() {
        // Verify our OID bytes match what rustls-pki-types defines
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
    fn test_der_parsing_matches_p256_crate() {
        // Generate a real P-256 signature and verify our DER parsing matches p256's
        use p256::ecdsa::{signature::Signer, SigningKey, Signature};

        let signing_key = SigningKey::from_bytes(&[0xAB; 32].into()).unwrap();
        let message = b"test message for cosmwasm backend";

        // Sign (produces DER-encoded signature)
        let sig: Signature = signing_key.sign(message);
        let der_sig = sig.to_der();

        // Parse with our code
        let our_raw = der_sig_to_raw(der_sig.as_bytes()).expect("our DER parser should work");

        // Compare with p256's raw representation
        let p256_raw: [u8; 64] = sig.to_bytes().into();

        assert_eq!(our_raw, p256_raw, "DER parsing mismatch:\nours: {:02x?}\np256: {:02x?}", our_raw, p256_raw);
    }

    #[test]
    fn test_full_verify_flow_native() {
        // End-to-end test: sign, hash, DER-parse, prehash-verify
        // This mirrors what happens in WASM but using p256 directly
        use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let signing_key = SigningKey::from_bytes(&[0xCD; 32].into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);
        let message = b"certificate TBS data simulation";

        // 1. Sign the message (p256 internally hashes with SHA-256)
        let sig: p256::ecdsa::Signature = signing_key.sign(message);
        let der_sig = sig.to_der();

        // 2. Our flow: hash message, parse DER signature
        let hash: [u8; 32] = sha2::Sha256::digest(message).into();
        let raw_sig = der_sig_to_raw(der_sig.as_bytes()).expect("DER parse");

        // 3. Verify using prehash (same as cosmwasm host would do)
        let p256_sig = p256::ecdsa::Signature::from_bytes((&raw_sig).into()).unwrap();
        let result = verifying_key.verify_prehash(&hash, &p256_sig);
        assert!(result.is_ok(), "Prehash verification failed: {:?}", result);

        // 4. Also verify the public key format matches what webpki would pass
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        assert_eq!(pubkey_bytes.as_bytes().len(), 65);
        assert_eq!(pubkey_bytes.as_bytes()[0], 0x04);
    }
}
