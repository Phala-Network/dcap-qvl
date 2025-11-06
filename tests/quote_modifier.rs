/// Helper module for modifying quote bytes for testing
/// This allows us to test exception cases by corrupting specific fields

/// Modify quote version (offset 0, 2 bytes)
pub fn modify_version(quote: &[u8], version: u16) -> Vec<u8> {
    let mut modified = quote.to_vec();
    modified[0] = (version & 0xFF) as u8;
    modified[1] = ((version >> 8) & 0xFF) as u8;
    modified
}

/// Modify attestation key type (offset 2, 2 bytes)
pub fn modify_attestation_key_type(quote: &[u8], key_type: u16) -> Vec<u8> {
    let mut modified = quote.to_vec();
    modified[2] = (key_type & 0xFF) as u8;
    modified[3] = ((key_type >> 8) & 0xFF) as u8;
    modified
}

/// Modify TEE type (offset 4, 4 bytes)
pub fn modify_tee_type(quote: &[u8], tee_type: u32) -> Vec<u8> {
    let mut modified = quote.to_vec();
    modified[4] = (tee_type & 0xFF) as u8;
    modified[5] = ((tee_type >> 8) & 0xFF) as u8;
    modified[6] = ((tee_type >> 16) & 0xFF) as u8;
    modified[7] = ((tee_type >> 24) & 0xFF) as u8;
    modified
}

/// Modify SGX attributes (for SGX quote version 3/4)
/// Attributes are at offset 48 + 96 = 144 bytes from start
pub fn modify_sgx_attributes(quote: &[u8], attributes: &[u8; 16]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let attr_offset = 48 + 96; // Header (48) + cpu_svn(16) + misc_select(4) + reserved1(28) + attributes(16)
    modified[attr_offset..attr_offset + 16].copy_from_slice(attributes);
    modified
}

/// Set SGX debug mode bit (bit 1 of attributes[0])
pub fn set_sgx_debug_mode(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let attr_offset = 48 + 96;
    modified[attr_offset] |= 0x02; // Set bit 1
    modified
}

/// Modify TDX TD attributes (for TDX quote version 4)
/// TD attributes are at offset 48 + 120 bytes from start
/// Header (48) + tee_tcb_svn(16) + mr_seam(48) + mr_signer_seam(48) + seam_attributes(8) = 168
pub fn modify_tdx_attributes(quote: &[u8], td_attributes: &[u8; 8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120; // Header (48) + 120 bytes into TDReport10
    modified[td_attr_offset..td_attr_offset + 8].copy_from_slice(td_attributes);
    modified
}

/// Set TDX debug mode (TUD = 1, byte 0 of td_attributes)
pub fn set_tdx_debug_mode(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset] = 1; // Set TUD to 1
    modified
}

/// Set TDX reserved bits in SEC (bytes 1-3)
pub fn set_tdx_reserved_bits(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 1] = 0xFF; // Set reserved lower bits
    modified
}

/// Clear SEPT_VE_DISABLE bit (bit 4 of byte 3)
pub fn clear_tdx_sept_ve_disable(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 3] &= !0x10; // Clear bit 4
    modified
}

/// Set TDX reserved bit 29 (bit 5 of byte 3)
pub fn set_tdx_reserved_bit29(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 3] |= 0x20; // Set bit 5
    modified
}

/// Set TDX PKS bit (bit 6 of byte 3)
pub fn set_tdx_pks(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 3] |= 0x40; // Set bit 6
    modified
}

/// Set TDX KL bit (bit 7 of byte 3)
pub fn set_tdx_kl(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 3] |= 0x80; // Set bit 7
    modified
}

/// Set TDX OTHER reserved bits (bytes 4-7)
pub fn set_tdx_other_reserved_bits(quote: &[u8]) -> Vec<u8> {
    let mut modified = quote.to_vec();
    let td_attr_offset = 48 + 120;
    modified[td_attr_offset + 4] = 0xFF; // Set reserved bits
    modified
}

/// Get version from quote
pub fn get_version(quote: &[u8]) -> u16 {
    u16::from_le_bytes([quote[0], quote[1]])
}

/// Get TEE type from quote
pub fn get_tee_type(quote: &[u8]) -> u32 {
    u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modify_version() {
        let quote = vec![0x03, 0x00, 0x02, 0x00]; // version 3
        let modified = modify_version(&quote, 2);
        assert_eq!(get_version(&modified), 2);
    }

    #[test]
    fn test_modify_tee_type() {
        let mut quote = vec![0; 48];
        quote[0] = 3; // version
        quote[4] = 0x00; // TEE_TYPE_SGX

        let modified = modify_tee_type(&quote, 0x81);
        assert_eq!(get_tee_type(&modified), 0x81);
    }
}
