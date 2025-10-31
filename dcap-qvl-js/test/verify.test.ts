/**
 * Main verification tests - must match Rust output exactly
 */

import { describe, it, expect } from 'vitest';
import { verify, parseQuote } from '../src';
import { readFileSync } from 'fs';
import { TEE_TYPE_SGX, TEE_TYPE_TDX } from '../src/constants';

describe('DCAP Quote Verification', () => {
  // Test timestamp matching Rust tests
  const TEST_TIMESTAMP = 1750320802;

  describe('SGX Quote Verification', () => {
    const rawQuote = readFileSync('./sample/sgx_quote');
    const collateral = JSON.parse(
      readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
    );

    it('should parse SGX quote successfully', () => {
      const quote = parseQuote(rawQuote);
      expect(quote).toBeDefined();
      expect(quote.header.version).toBe(3);
      expect(quote.header.tee_type).toBe(TEE_TYPE_SGX);
    });

    it('should verify SGX quote and match Rust output', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // These values MUST match the Rust test output
      expect(result.status).toBe('ConfigurationAndSWHardeningNeeded');
      expect(result.advisory_ids).toEqual(['INTEL-SA-00289', 'INTEL-SA-00615']);
    });

    it('should extract correct PPID', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);
      expect(result.ppid).toBeDefined();
    });

    it('should parse SGX enclave report', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);
      expect(result.report.type).toBe('SgxEnclave');

      const report = result.report.report;
      expect(report.mr_enclave).toHaveLength(32);
      expect(report.mr_signer).toHaveLength(32);
      expect(report.report_data).toHaveLength(64);
    });
  });

  describe('TDX Quote Verification', () => {
    const rawQuote = readFileSync('./sample/tdx_quote');
    const collateral = JSON.parse(
      readFileSync('./sample/tdx_quote_collateral.json', 'utf-8')
    );

    it('should parse TDX quote successfully', () => {
      const quote = parseQuote(rawQuote);
      expect(quote).toBeDefined();
      expect(quote.header.version).toBe(4);
      expect(quote.header.tee_type).toBe(TEE_TYPE_TDX);
    });

    it('should verify TDX quote and match Rust output', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // These values MUST match the Rust test output
      expect(result.status).toBe('UpToDate');
      expect(result.advisory_ids).toEqual([]);
    });

    it('should parse TDX report', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);
      expect(result.report.type).toMatch(/^TD(10|15)$/);

      const tdReport =
        result.report.type === 'TD15' ? result.report.report.base : result.report.report;

      expect(tdReport.mr_td).toHaveLength(48);
      expect(tdReport.mr_seam).toHaveLength(48);
      expect(tdReport.tee_tcb_svn).toHaveLength(16);
    });
  });

  describe('Error Cases', () => {
    it('should reject expired TCB info', async () => {
      const rawQuote = readFileSync('./sample/tdx_quote');
      const collateral = JSON.parse(
        readFileSync('./sample/tdx_quote_collateral.json', 'utf-8')
      );

      // Use a timestamp far in the future
      const futureTime = 9999999999;

      await expect(verify(rawQuote, collateral, futureTime)).rejects.toThrow('TCBInfo expired');
    });

    it('should reject corrupted signature', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(
        readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
      );

      // Corrupt the signature bytes
      const corrupted = new Uint8Array(rawQuote);
      corrupted[100] ^= 0xff;

      await expect(verify(corrupted, collateral, TEST_TIMESTAMP)).rejects.toThrow();
    });
  });
});
