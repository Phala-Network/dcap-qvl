/**
 * CRL Validation Tests
 * Tests the Certificate Revocation List parsing and validation
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { parseCrl } from '../src/certificate';
import { hexToBytes } from '../src/utils';
import { verify } from '../src/verify';

describe('CRL Validation', () => {
  it('should parse CRL structure correctly', () => {
    // Load a real CRL from collateral
    const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));
    const rootCaCrlHex = collateral.root_ca_crl;
    const rootCaCrl = hexToBytes(rootCaCrlHex);

    // Parse the CRL
    const parsed = parseCrl(rootCaCrl);

    // Verify structure
    expect(parsed).toBeDefined();
    expect(parsed.tbsCertList).toBeInstanceOf(Uint8Array);
    expect(parsed.signatureValue).toBeInstanceOf(Uint8Array);
    expect(parsed.revokedCertificates).toBeInstanceOf(Set);
    expect(parsed.thisUpdate).toBeInstanceOf(Date);
  });

  it('should detect revoked certificates', () => {
    const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));
    const rootCaCrlHex = collateral.root_ca_crl;
    const rootCaCrl = hexToBytes(rootCaCrlHex);

    const parsed = parseCrl(rootCaCrl);

    // The CRL should be parsed successfully
    expect(parsed.revokedCertificates).toBeDefined();

    // Log number of revoked certificates for debugging
    console.log(`   CRL contains ${parsed.revokedCertificates.size} revoked certificate(s)`);
  });

  it('should validate CRL dates', () => {
    const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));
    const rootCaCrlHex = collateral.root_ca_crl;
    const rootCaCrl = hexToBytes(rootCaCrlHex);

    const parsed = parseCrl(rootCaCrl);

    // Check that dates are valid
    expect(parsed.thisUpdate).toBeInstanceOf(Date);
    expect(parsed.thisUpdate.getTime()).toBeGreaterThan(0);

    if (parsed.nextUpdate) {
      expect(parsed.nextUpdate).toBeInstanceOf(Date);
      expect(parsed.nextUpdate.getTime()).toBeGreaterThan(parsed.thisUpdate.getTime());
    }
  });

  it('should verify quotes with CRL checking enabled', async () => {
    const rawQuote = readFileSync('./sample/sgx_quote');
    const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

    // Use same timestamp as main tests
    const TEST_TIMESTAMP = 1750320802;

    // This should pass - none of the certificates should be revoked
    const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);

    expect(result.status).toBe('ConfigurationAndSWHardeningNeeded');
    expect(result.advisory_ids).toContain('INTEL-SA-00289');
    expect(result.advisory_ids).toContain('INTEL-SA-00615');
  });

  it('should parse PCK CRL', () => {
    const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));
    const pckCrlHex = collateral.pck_crl;
    const pckCrl = hexToBytes(pckCrlHex);

    const parsed = parseCrl(pckCrl);

    expect(parsed).toBeDefined();
    expect(parsed.revokedCertificates).toBeInstanceOf(Set);

    console.log(`   PCK CRL contains ${parsed.revokedCertificates.size} revoked certificate(s)`);
  });
});
