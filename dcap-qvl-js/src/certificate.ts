/**
 * X.509 Certificate handling and Intel extension parsing
 */

import { X509Certificate } from '@peculiar/x509';
import { QuoteVerificationError } from './types';
import { pemToDer, parsePemChain, hexToBytes } from './utils';
import { verifyEcdsaP256Signature } from './crypto';
import {
  TRUSTED_ROOT_CA_DER,
  SGX_EXTENSION_OID,
  FMSPC_OID,
  TCB_OID,
  CPUSVN_OID,
  PCESVN_OID,
  PPID_OID,
  PCEID_OID,
  SGX_TYPE_OID,
  PLATFORM_INSTANCE_ID_OID,
} from './constants';

/**
 * Parse PEM certificate chain into X509Certificate objects
 */
export function parsePemCertificateChain(pem: string): X509Certificate[] {
  const pemCerts = parsePemChain(pem);
  return pemCerts.map((p) => new X509Certificate(pemToDer(p)));
}

/**
 * Extract Intel SGX extension from certificate
 */
export function extractIntelExtension(cert: X509Certificate): Uint8Array {
  const ext = cert.extensions.find((e) => e.type === SGX_EXTENSION_OID);
  if (!ext) {
    throw new QuoteVerificationError('Intel SGX extension not found');
  }
  // Extension value is already the raw bytes
  return new Uint8Array(ext.value);
}

/**
 * Parse DER structure to find OID value
 */
function findExtensionValue(extensionData: Uint8Array, oidPath: string[]): Uint8Array | null {
  try {
    let data = extensionData;

    for (let pathIndex = 0; pathIndex < oidPath.length; pathIndex++) {
      const oid = oidPath[pathIndex];
      const isLast = pathIndex === oidPath.length - 1;

      // Parse SEQUENCE
      if (data[0] !== 0x30) {
        return null;
      }

      const sequenceLength = parseLength(data, 1);
      let offset = 1 + getLengthSize(data, 1);

      let found = false;
      while (offset < sequenceLength.end) {
        // Each entry is a SEQUENCE containing OID and value
        if (data[offset] !== 0x30) {
          break;
        }

        const entryLength = parseLength(data, offset + 1);
        const entryStart = offset + 1 + getLengthSize(data, offset + 1);
        const entryEnd = offset + 1 + getLengthSize(data, offset + 1) + entryLength.value;

        // Parse OID
        let innerOffset = entryStart;
        if (data[innerOffset] !== 0x06) {
          // Not an OID
          offset = entryEnd;
          continue;
        }

        const oidLength = data[innerOffset + 1];
        const oidBytes = data.slice(innerOffset + 2, innerOffset + 2 + oidLength);
        const oidString = oidBytesToString(oidBytes);

        if (oidString === oid) {
          // Found the OID, get the value
          innerOffset += 2 + oidLength;
          const valueData = data.slice(innerOffset, entryEnd);

          // If this is the last OID in the path, extract the raw value
          if (isLast) {
            // Skip tag and length to get raw value
            if (valueData.length < 2) {
              return null;
            }
            const valueLength = parseLength(valueData, 1);
            const valueStart = 1 + getLengthSize(valueData, 1);
            return valueData.slice(valueStart, valueStart + valueLength.value);
          } else {
            // For intermediate nodes, the value should be a SEQUENCE to continue parsing
            data = valueData;
          }
          found = true;
          break;
        }

        offset = entryEnd;
      }

      if (!found) {
        return null;
      }
    }

    return data;
  } catch {
    return null;
  }
}

/**
 * Parse DER length field
 */
function parseLength(data: Uint8Array, offset: number): { value: number; end: number } {
  const first = data[offset];

  if (first < 0x80) {
    // Short form
    return { value: first, end: offset + 1 + first };
  }

  // Long form
  const numBytes = first & 0x7f;
  let value = 0;
  for (let i = 0; i < numBytes; i++) {
    value = value * 256 + data[offset + 1 + i];
  }

  return { value, end: offset + 1 + numBytes + value };
}

/**
 * Get size of length field
 */
function getLengthSize(data: Uint8Array, offset: number): number {
  const first = data[offset];
  if (first < 0x80) {
    return 1;
  }
  return 1 + (first & 0x7f);
}

/**
 * Convert OID bytes to dotted string notation
 */
function oidBytesToString(bytes: Uint8Array): string {
  if (bytes.length === 0) {
    return '';
  }

  const parts: number[] = [];

  // First byte encodes first two nodes
  parts.push(Math.floor(bytes[0] / 40));
  parts.push(bytes[0] % 40);

  // Remaining bytes
  let value = 0;
  for (let i = 1; i < bytes.length; i++) {
    value = value * 128 + (bytes[i] & 0x7f);
    if ((bytes[i] & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  return parts.join('.');
}

/**
 * Extract FMSPC from Intel extension
 */
export function getFmspc(extensionData: Uint8Array): Uint8Array {
  const value = findExtensionValue(extensionData, [FMSPC_OID]);
  if (!value || value.length !== 6) {
    throw new QuoteVerificationError('Failed to extract FMSPC');
  }
  return value;
}

/**
 * Extract CPU SVN from Intel extension
 */
export function getCpuSvn(extensionData: Uint8Array): Uint8Array {
  const value = findExtensionValue(extensionData, [TCB_OID, CPUSVN_OID]);
  if (!value || value.length !== 16) {
    console.error('getCpuSvn: Failed to find value');
    console.error('Extension data length:', extensionData.length);
    console.error('Extension data (first 100 bytes):', Array.from(extensionData.slice(0, 100)).map(b => b.toString(16).padStart(2, '0')).join(' '));
    console.error('Value found:', value ? `length ${value.length}` : 'null');
    throw new QuoteVerificationError('Failed to extract CPU SVN');
  }
  return value;
}

/**
 * Extract PCE SVN from Intel extension
 */
export function getPceSvn(extensionData: Uint8Array): number {
  const value = findExtensionValue(extensionData, [TCB_OID, PCESVN_OID]);
  if (!value) {
    throw new QuoteVerificationError('Failed to extract PCE SVN');
  }

  if (value.length === 1) {
    return value[0];
  } else if (value.length === 2) {
    return (value[0] << 8) | value[1];
  }

  throw new QuoteVerificationError('Invalid PCE SVN length');
}

/**
 * Extract PPID from Intel extension
 */
export function getPpid(extensionData: Uint8Array): Uint8Array {
  const value = findExtensionValue(extensionData, [PPID_OID]);
  if (!value) {
    return new Uint8Array(0);
  }
  return value;
}

/**
 * Verify certificate chain against root CA
 * Simplified version - full implementation would check dates, key usage, etc.
 */
export async function verifyCertificateChain(
  leafCert: X509Certificate,
  intermediateCerts: X509Certificate[],
  rootCert: X509Certificate,
  crls: Uint8Array[],
  now: Date
): Promise<void> {
  // Check leaf certificate validity
  if (now < leafCert.notBefore || now > leafCert.notAfter) {
    throw new QuoteVerificationError('Leaf certificate expired or not yet valid');
  }

  // Verify leaf cert is signed by first intermediate (or root if no intermediates)
  const issuer = intermediateCerts.length > 0 ? intermediateCerts[0] : rootCert;

  try {
    const isValid = await leafCert.verify({
      publicKey: await issuer.publicKey.export(),
      signatureOnly: true,
    });

    if (!isValid) {
      throw new QuoteVerificationError('Leaf certificate signature invalid');
    }
  } catch (error) {
    throw new QuoteVerificationError(`Certificate verification failed: ${error}`);
  }

  // Verify intermediate certificates
  for (let i = 0; i < intermediateCerts.length; i++) {
    const cert = intermediateCerts[i];

    // Check validity
    if (now < cert.notBefore || now > cert.notAfter) {
      throw new QuoteVerificationError(`Intermediate certificate ${i} expired`);
    }

    // Verify signature
    const certIssuer = i < intermediateCerts.length - 1 ? intermediateCerts[i + 1] : rootCert;

    try {
      const isValid = await cert.verify({
        publicKey: await certIssuer.publicKey.export(),
        signatureOnly: true,
      });

      if (!isValid) {
        throw new QuoteVerificationError(`Intermediate certificate ${i} signature invalid`);
      }
    } catch (error) {
      throw new QuoteVerificationError(`Certificate ${i} verification failed: ${error}`);
    }
  }

  // TODO: Full CRL checking would require parsing CRL format
  // For now, we assume CRLs are valid and don't contain revoked certs
}

/**
 * Get root CA certificate
 */
export function getRootCaCertificate(): X509Certificate {
  return new X509Certificate(TRUSTED_ROOT_CA_DER);
}

/**
 * Parse CRL (simplified - just validates it's parseable)
 */
export function parseCrl(crlDer: Uint8Array): void {
  // Basic validation that it looks like a CRL
  if (crlDer.length < 10 || crlDer[0] !== 0x30) {
    throw new QuoteVerificationError('Invalid CRL format');
  }
  // Full CRL parsing would be needed for production
  // For now, we trust that the CRL is valid
}
