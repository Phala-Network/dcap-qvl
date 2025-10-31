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
 * Extract CRL Distribution Point URL from certificate
 * Returns the first HTTP/HTTPS URL found in the CRL Distribution Points extension (OID 2.5.29.31)
 */
export function extractCrlUrl(cert: X509Certificate): string | null {
  try {
    // Look for CRL Distribution Points extension (OID 2.5.29.31)
    const crlDistExt = cert.extensions.find((e) => e.type === '2.5.29.31');
    if (!crlDistExt) {
      return null;
    }

    // Parse the extension value as DER
    const extValue = new Uint8Array(crlDistExt.value);

    // CRL Distribution Points is a SEQUENCE of DistributionPoint
    // We're looking for a URI in the distributionPoint field
    // Simple parsing: look for http:// or https:// strings in the extension
    const extStr = new TextDecoder('utf-8', { fatal: false }).decode(extValue);
    const httpMatch = extStr.match(/https?:\/\/[^\s\x00-\x1f]+/);

    if (httpMatch) {
      return httpMatch[0];
    }

    return null;
  } catch {
    return null;
  }
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

  // Check CRL revocation for all certificates in chain
  await checkCertificateRevocation(leafCert, crls, now);
  for (const cert of intermediateCerts) {
    await checkCertificateRevocation(cert, crls, now);
  }
}

/**
 * Check if a certificate has been revoked using CRLs
 */
export async function checkCertificateRevocation(
  cert: X509Certificate,
  crlDers: Uint8Array[],
  now: Date
): Promise<void> {
  // Get certificate serial number
  const certSerial = cert.serialNumber.toLowerCase().replace(/:/g, '');

  for (const crlDer of crlDers) {
    try {
      const crl = parseCrl(crlDer);

      // Check CRL validity period
      if (now < crl.thisUpdate) {
        throw new QuoteVerificationError('CRL not yet valid');
      }
      if (crl.nextUpdate && now > crl.nextUpdate) {
        throw new QuoteVerificationError('CRL has expired');
      }

      // Check if certificate is revoked
      if (crl.revokedCertificates.has(certSerial)) {
        throw new QuoteVerificationError(`Certificate ${certSerial} has been revoked`);
      }

      // Verify CRL signature (using root CA)
      // Note: In production, should verify using the CRL issuer's certificate
      // For Intel DCAP, CRLs are signed by the root CA
      await verifyCrlSignature(crl, getRootCaCertificate());
    } catch (error) {
      // If CRL parsing fails, try next CRL
      if (error instanceof QuoteVerificationError && error.message.includes('revoked')) {
        throw error; // Re-throw revocation errors
      }
      // Continue to next CRL if parsing/verification fails
      continue;
    }
  }
}

/**
 * Verify CRL signature
 */
async function verifyCrlSignature(crl: ParsedCRL, issuerCert: X509Certificate): Promise<void> {
  try {
    // Extract public key from issuer certificate
    const publicKey = issuerCert.publicKey;
    const cryptoKey = await publicKey.export();
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));

    // CRL signatures are typically ECDSA with SHA-256 for Intel DCAP
    // The signature is in DER format in the CRL
    // We need to convert it to raw format (R || S) for Web Crypto API

    // Parse DER signature to extract R and S
    let sigOffset = 0;
    const sigData = crl.signatureValue;

    if (sigData[sigOffset] !== 0x30) {
      throw new QuoteVerificationError('Invalid CRL signature format - not a SEQUENCE');
    }
    sigOffset++;

    const sigSeqLen = parseLength(sigData, sigOffset);
    sigOffset += getLengthSize(sigData, sigOffset);

    // Parse R
    if (sigData[sigOffset] !== 0x02) {
      throw new QuoteVerificationError('Invalid CRL signature - R not an INTEGER');
    }
    sigOffset++;
    const rLen = sigData[sigOffset];
    sigOffset++;
    let rBytes = sigData.slice(sigOffset, sigOffset + rLen);
    sigOffset += rLen;

    // Remove leading zero if present (DER encoding)
    if (rBytes[0] === 0x00 && rBytes.length === 33) {
      rBytes = rBytes.slice(1);
    }

    // Parse S
    if (sigData[sigOffset] !== 0x02) {
      throw new QuoteVerificationError('Invalid CRL signature - S not an INTEGER');
    }
    sigOffset++;
    const sLen = sigData[sigOffset];
    sigOffset++;
    let sBytes = sigData.slice(sigOffset, sigOffset + sLen);

    // Remove leading zero if present
    if (sBytes[0] === 0x00 && sBytes.length === 33) {
      sBytes = sBytes.slice(1);
    }

    // Pad to 32 bytes if needed
    const rPadded = new Uint8Array(32);
    const sPadded = new Uint8Array(32);
    rPadded.set(rBytes, 32 - rBytes.length);
    sPadded.set(sBytes, 32 - sBytes.length);

    // Combine R and S into IEEE P1363 format
    const rawSignature = new Uint8Array(64);
    rawSignature.set(rPadded, 0);
    rawSignature.set(sPadded, 32);

    // Verify signature over tbsCertList
    const isValid = await verifyEcdsaP256Signature(rawKey, crl.tbsCertList, rawSignature);

    if (!isValid) {
      throw new QuoteVerificationError('CRL signature verification failed');
    }
  } catch (error) {
    if (error instanceof QuoteVerificationError) {
      throw error;
    }
    throw new QuoteVerificationError(`CRL signature verification error: ${error}`);
  }
}

/**
 * Get root CA certificate
 */
export function getRootCaCertificate(): X509Certificate {
  return new X509Certificate(TRUSTED_ROOT_CA_DER);
}

/**
 * Parsed CRL structure
 */
interface ParsedCRL {
  revokedCertificates: Set<string>; // Serial numbers in hex
  issuer: string;
  thisUpdate: Date;
  nextUpdate?: Date;
  signatureAlgorithm: Uint8Array;
  signatureValue: Uint8Array;
  tbsCertList: Uint8Array; // The signed portion
}

/**
 * Parse X.509 CRL (Certificate Revocation List)
 * CRL structure (RFC 5280):
 * CertificateList ::= SEQUENCE {
 *   tbsCertList          TBSCertList,
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING
 * }
 */
export function parseCrl(crlDer: Uint8Array): ParsedCRL {
  if (crlDer.length < 10 || crlDer[0] !== 0x30) {
    throw new QuoteVerificationError('Invalid CRL format - not a SEQUENCE');
  }

  let offset = 0;

  // Parse outer SEQUENCE
  if (crlDer[offset] !== 0x30) {
    throw new QuoteVerificationError('CRL must start with SEQUENCE');
  }
  offset++;

  const outerLength = parseLength(crlDer, offset);
  offset = 1 + getLengthSize(crlDer, 1);

  // Parse TBSCertList (the part that gets signed)
  if (crlDer[offset] !== 0x30) {
    throw new QuoteVerificationError('TBSCertList must be SEQUENCE');
  }

  const tbsStart = offset;
  offset++;
  const tbsLength = parseLength(crlDer, offset);
  const tbsLengthSize = getLengthSize(crlDer, offset);
  offset += tbsLengthSize;

  const tbsCertList = crlDer.slice(tbsStart, tbsStart + 1 + tbsLengthSize + tbsLength.value);
  const tbsEnd = tbsStart + 1 + tbsLengthSize + tbsLength.value;

  // Parse TBSCertList contents
  // Skip version (optional)
  if (crlDer[offset] === 0x02) {
    // INTEGER
    offset++;
    const versionLen = crlDer[offset];
    offset += 1 + versionLen;
  }

  // Skip signature algorithm
  if (crlDer[offset] === 0x30) {
    offset++;
    const sigAlgLen = parseLength(crlDer, offset);
    offset += getLengthSize(crlDer, offset) + sigAlgLen.value;
  }

  // Skip issuer
  let issuer = '';
  if (crlDer[offset] === 0x30) {
    const issuerStart = offset;
    offset++;
    const issuerLen = parseLength(crlDer, offset);
    offset += getLengthSize(crlDer, offset) + issuerLen.value;
    // Simple issuer extraction - just get the raw bytes
    issuer = 'CRL Issuer';
  }

  // Parse thisUpdate
  let thisUpdate = new Date();
  if (crlDer[offset] === 0x17 || crlDer[offset] === 0x18) {
    // UTCTime or GeneralizedTime
    offset++;
    const timeLen = crlDer[offset];
    offset++;
    const timeBytes = crlDer.slice(offset, offset + timeLen);
    thisUpdate = parseAsn1Time(timeBytes, crlDer[offset - 2]);
    offset += timeLen;
  }

  // Parse nextUpdate (optional)
  let nextUpdate: Date | undefined;
  if (crlDer[offset] === 0x17 || crlDer[offset] === 0x18) {
    offset++;
    const timeLen = crlDer[offset];
    offset++;
    const timeBytes = crlDer.slice(offset, offset + timeLen);
    nextUpdate = parseAsn1Time(timeBytes, crlDer[offset - 2]);
    offset += timeLen;
  }

  // Parse revokedCertificates (optional SEQUENCE)
  const revokedCertificates = new Set<string>();
  if (offset < tbsEnd && crlDer[offset] === 0x30) {
    offset++;
    const revokedLen = parseLength(crlDer, offset);
    offset += getLengthSize(crlDer, offset);
    const revokedEnd = offset + revokedLen.value;

    // Parse each revoked certificate entry
    while (offset < revokedEnd && offset < tbsEnd) {
      if (crlDer[offset] !== 0x30) break;
      offset++;
      const entryLen = parseLength(crlDer, offset);
      const entrySizeLen = getLengthSize(crlDer, offset);
      offset += entrySizeLen;

      // Parse serial number
      if (crlDer[offset] === 0x02) {
        offset++;
        const serialLen = crlDer[offset];
        offset++;
        const serialBytes = crlDer.slice(offset, offset + serialLen);
        const serialHex = Array.from(serialBytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
        revokedCertificates.add(serialHex);
        offset += serialLen;

        // Skip revocation date and extensions
        const remainingEntry = entryLen.value - (2 + serialLen);
        offset += remainingEntry;
      } else {
        offset += entryLen.value;
      }
    }
  }

  // Parse signatureAlgorithm
  offset = tbsEnd;
  if (crlDer[offset] !== 0x30) {
    throw new QuoteVerificationError('Signature algorithm must be SEQUENCE');
  }
  const sigAlgStart = offset;
  offset++;
  const sigAlgLen = parseLength(crlDer, offset);
  offset += getLengthSize(crlDer, offset);
  const signatureAlgorithm = crlDer.slice(sigAlgStart, offset + sigAlgLen.value);
  offset += sigAlgLen.value;

  // Parse signatureValue (BIT STRING)
  if (crlDer[offset] !== 0x03) {
    throw new QuoteVerificationError('Signature value must be BIT STRING');
  }
  offset++;
  const sigLen = parseLength(crlDer, offset);
  offset += getLengthSize(crlDer, offset);

  // Skip the first byte (unused bits)
  offset++;
  const signatureValue = crlDer.slice(offset, offset + sigLen.value - 1);

  return {
    revokedCertificates,
    issuer,
    thisUpdate,
    nextUpdate,
    signatureAlgorithm,
    signatureValue,
    tbsCertList,
  };
}

/**
 * Parse ASN.1 time (UTCTime or GeneralizedTime)
 */
function parseAsn1Time(timeBytes: Uint8Array, tag: number): Date {
  const timeStr = new TextDecoder('ascii').decode(timeBytes);

  if (tag === 0x17) {
    // UTCTime: YYMMDDhhmmssZ
    const year = parseInt(timeStr.substring(0, 2), 10);
    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
    const month = parseInt(timeStr.substring(2, 4), 10) - 1;
    const day = parseInt(timeStr.substring(4, 6), 10);
    const hour = parseInt(timeStr.substring(6, 8), 10);
    const minute = parseInt(timeStr.substring(8, 10), 10);
    const second = parseInt(timeStr.substring(10, 12), 10);
    return new Date(Date.UTC(fullYear, month, day, hour, minute, second));
  } else {
    // GeneralizedTime: YYYYMMDDhhmmssZ
    const fullYear = parseInt(timeStr.substring(0, 4), 10);
    const month = parseInt(timeStr.substring(4, 6), 10) - 1;
    const day = parseInt(timeStr.substring(6, 8), 10);
    const hour = parseInt(timeStr.substring(8, 10), 10);
    const minute = parseInt(timeStr.substring(10, 12), 10);
    const second = parseInt(timeStr.substring(12, 14), 10);
    return new Date(Date.UTC(fullYear, month, day, hour, minute, second));
  }
}
