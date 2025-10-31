/**
 * Cryptographic operations using Web Crypto API
 */

import { QuoteVerificationError } from './types';

// Get crypto object (works in both Node.js and browsers)
const getCrypto = (): Crypto => {
  if (typeof globalThis.crypto !== 'undefined') {
    return globalThis.crypto;
  }
  // Node.js
  if (typeof require !== 'undefined') {
    const { webcrypto } = require('crypto');
    return webcrypto as Crypto;
  }
  throw new QuoteVerificationError('Web Crypto API not available');
};

/**
 * Compute SHA-256 hash
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const crypto = getCrypto();
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Verify ECDSA P-256 signature
 * @param publicKey - 65-byte uncompressed public key (0x04 || X || Y)
 * @param message - Message that was signed
 * @param signature - 64-byte raw signature (R || S) in IEEE P1363 format
 */
export async function verifyEcdsaP256Signature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  try {
    const crypto = getCrypto();

    // Ensure public key is in uncompressed format
    if (publicKey.length !== 65 || publicKey[0] !== 0x04) {
      return false;
    }

    if (signature.length !== 64) {
      return false;
    }

    // Import public key
    const keyData = publicKey;
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    // Web Crypto API in Node.js expects IEEE P1363 format (raw R || S)
    // which is exactly what we have
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      key,
      signature,
      message
    );

    return isValid;
  } catch {
    return false;
  }
}

/**
 * Encode ECDSA signature from raw format (R || S) to DER format
 * Input: 64 bytes (32-byte R + 32-byte S)
 * Output: DER-encoded SEQUENCE
 */
export function encodeEcdsaSignatureAsDer(signature: Uint8Array): Uint8Array {
  if (signature.length !== 64) {
    throw new QuoteVerificationError('Signature must be 64 bytes');
  }

  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);

  // Encode integer with padding if high bit is set
  const encodeInteger = (value: Uint8Array): Uint8Array => {
    // Remove leading zeros
    let start = 0;
    while (start < value.length && value[start] === 0) {
      start++;
    }

    // If all zeros, keep one
    if (start === value.length) {
      start = value.length - 1;
    }

    const trimmed = value.slice(start);

    // Add padding byte if high bit is set (to keep it positive)
    const needsPadding = trimmed[0] >= 0x80;
    const length = trimmed.length + (needsPadding ? 1 : 0);

    const result = new Uint8Array(2 + length);
    result[0] = 0x02; // INTEGER tag
    result[1] = length;

    if (needsPadding) {
      result[2] = 0x00;
      result.set(trimmed, 3);
    } else {
      result.set(trimmed, 2);
    }

    return result;
  };

  const rEncoded = encodeInteger(r);
  const sEncoded = encodeInteger(s);

  // Build SEQUENCE
  const totalLength = rEncoded.length + sEncoded.length;
  const result = new Uint8Array(2 + totalLength);

  result[0] = 0x30; // SEQUENCE tag
  result[1] = totalLength;
  result.set(rEncoded, 2);
  result.set(sEncoded, 2 + rEncoded.length);

  return result;
}

/**
 * Verify certificate signature
 * This is a simplified version - full implementation would need more ASN.1 parsing
 */
export async function verifyCertificateSignature(
  tbsCertificate: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  algorithm: 'ECDSA' | 'RSA' = 'ECDSA'
): Promise<boolean> {
  if (algorithm === 'ECDSA') {
    return verifyEcdsaP256Signature(publicKey, tbsCertificate, signature);
  }
  throw new QuoteVerificationError('Unsupported signature algorithm');
}
