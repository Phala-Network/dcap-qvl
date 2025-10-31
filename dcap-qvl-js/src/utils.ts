/**
 * Utility functions for binary parsing and data manipulation
 */

/**
 * Read 16-bit little-endian unsigned integer
 */
export function readU16LE(buffer: Uint8Array, offset: number): number {
  return buffer[offset] | (buffer[offset + 1] << 8);
}

/**
 * Read 32-bit little-endian unsigned integer
 */
export function readU32LE(buffer: Uint8Array, offset: number): number {
  return (
    buffer[offset] |
    (buffer[offset + 1] << 8) |
    (buffer[offset + 2] << 16) |
    (buffer[offset + 3] << 24)
  ) >>> 0;
}

/**
 * Read 64-bit little-endian unsigned integer as BigInt
 */
export function readU64LE(buffer: Uint8Array, offset: number): bigint {
  const low = BigInt(readU32LE(buffer, offset));
  const high = BigInt(readU32LE(buffer, offset + 4));
  return low | (high << 32n);
}

/**
 * Read bytes from buffer
 */
export function readBytes(
  buffer: Uint8Array,
  offset: number,
  length: number
): Uint8Array {
  return buffer.slice(offset, offset + length);
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/^0x/, '').replace(/\s/g, '');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Compare two Uint8Arrays for equality
 */
export function arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Compare two arrays lexicographically (for TCB comparison)
 */
export function arrayLexCompare(a: Uint8Array | number[], b: number[]): number {
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

/**
 * Check if array a >= array b (for TCB SVN comparison)
 */
export function arrayGreaterOrEqual(a: Uint8Array | number[], b: number[]): boolean {
  return arrayLexCompare(a, b) >= 0;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/**
 * Parse PEM certificate chain
 */
export function parsePemChain(pem: string): string[] {
  const certRegex = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g;
  return pem.match(certRegex) || [];
}

/**
 * Extract DER from PEM
 */
export function pemToDer(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, '')
    .replace(/-----END CERTIFICATE-----/, '')
    .replace(/\s/g, '');
  return base64ToBytes(base64);
}

/**
 * Convert base64 to Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  // Handle both Node.js and browser environments
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Convert Uint8Array to base64
 */
export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  } else {
    const binaryString = String.fromCharCode(...bytes);
    return btoa(binaryString);
  }
}
