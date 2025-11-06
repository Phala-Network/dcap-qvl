/**
 * Helper module for modifying quote bytes for testing
 * This is a TypeScript port of tests/quote_modifier.rs
 * Allows us to test exception cases by corrupting specific fields
 */

/**
 * Modify quote version (offset 0, 2 bytes, little-endian)
 */
export function modifyVersion(quote: Uint8Array, version: number): Uint8Array {
  const modified = new Uint8Array(quote);
  modified[0] = version & 0xff;
  modified[1] = (version >> 8) & 0xff;
  return modified;
}

/**
 * Modify attestation key type (offset 2, 2 bytes, little-endian)
 */
export function modifyAttestationKeyType(quote: Uint8Array, keyType: number): Uint8Array {
  const modified = new Uint8Array(quote);
  modified[2] = keyType & 0xff;
  modified[3] = (keyType >> 8) & 0xff;
  return modified;
}

/**
 * Modify TEE type (offset 4, 4 bytes, little-endian)
 */
export function modifyTeeType(quote: Uint8Array, teeType: number): Uint8Array {
  const modified = new Uint8Array(quote);
  modified[4] = teeType & 0xff;
  modified[5] = (teeType >> 8) & 0xff;
  modified[6] = (teeType >> 16) & 0xff;
  modified[7] = (teeType >> 24) & 0xff;
  return modified;
}

/**
 * Modify SGX attributes (for SGX quote version 3/4)
 * Attributes are at offset 48 + 96 = 144 bytes from start
 * Header (48) + cpu_svn(16) + misc_select(4) + reserved1(28) + attributes(16)
 */
export function modifySgxAttributes(quote: Uint8Array, attributes: Uint8Array): Uint8Array {
  if (attributes.length !== 16) {
    throw new Error('SGX attributes must be 16 bytes');
  }
  const modified = new Uint8Array(quote);
  const attrOffset = 48 + 96;
  modified.set(attributes, attrOffset);
  return modified;
}

/**
 * Set SGX debug mode bit (bit 1 of attributes[0])
 */
export function setSgxDebugMode(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const attrOffset = 48 + 96;
  modified[attrOffset] |= 0x02; // Set bit 1
  return modified;
}

/**
 * Modify TDX TD attributes (for TDX quote version 4)
 * TD attributes are at offset 48 + 120 bytes from start
 * Header (48) + tee_tcb_svn(16) + mr_seam(48) + mr_signer_seam(48) + seam_attributes(8) = 168
 */
export function modifyTdxAttributes(quote: Uint8Array, tdAttributes: Uint8Array): Uint8Array {
  if (tdAttributes.length !== 8) {
    throw new Error('TDX attributes must be 8 bytes');
  }
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified.set(tdAttributes, tdAttrOffset);
  return modified;
}

/**
 * Set TDX debug mode (TUD = 1, byte 0 of td_attributes)
 */
export function setTdxDebugMode(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset] = 1; // Set TUD to 1
  return modified;
}

/**
 * Set TDX reserved bits in SEC (bytes 1-3)
 */
export function setTdxReservedBits(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 1] = 0xff; // Set reserved lower bits
  return modified;
}

/**
 * Clear SEPT_VE_DISABLE bit (bit 4 of byte 3)
 */
export function clearTdxSeptVeDisable(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 3] &= ~0x10; // Clear bit 4
  return modified;
}

/**
 * Set TDX reserved bit 29 (bit 5 of byte 3)
 */
export function setTdxReservedBit29(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 3] |= 0x20; // Set bit 5
  return modified;
}

/**
 * Set TDX PKS bit (bit 6 of byte 3)
 */
export function setTdxPks(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 3] |= 0x40; // Set bit 6
  return modified;
}

/**
 * Set TDX KL bit (bit 7 of byte 3)
 */
export function setTdxKl(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 3] |= 0x80; // Set bit 7
  return modified;
}

/**
 * Set TDX OTHER reserved bits (bytes 4-7)
 */
export function setTdxOtherReservedBits(quote: Uint8Array): Uint8Array {
  const modified = new Uint8Array(quote);
  const tdAttrOffset = 48 + 120;
  modified[tdAttrOffset + 4] = 0xff; // Set reserved bits
  return modified;
}

/**
 * Get version from quote
 */
export function getVersion(quote: Uint8Array): number {
  return quote[0] | (quote[1] << 8);
}

/**
 * Get TEE type from quote
 */
export function getTeeType(quote: Uint8Array): number {
  return quote[4] | (quote[5] << 8) | (quote[6] << 16) | (quote[7] << 24);
}
