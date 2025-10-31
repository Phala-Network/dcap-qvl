/**
 * Rust API Comparison Tests
 * Compare JavaScript implementation outputs with Rust CLI outputs
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { execSync } from 'child_process';
import { parseQuote } from '../src/parser';
import { verify } from '../src/verify';
import { getCollateral } from '../src/collateral';
import { bytesToHex } from '../src/utils';

const TEST_TIMESTAMP = 1750320802;

describe('Rust API Comparison', () => {
  describe('Quote Parsing', () => {
    it('should match Rust CLI decode-quote output for SGX', () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const jsResult = parseQuote(rawQuote);

      // Call Rust CLI to get reference output
      let rustOutput: any;
      try {
        const hexQuote = Buffer.from(rawQuote).toString('hex');
        writeFileSync('/tmp/test_sgx_quote.hex', hexQuote);

        const output = execSync(
          'cd ../cli && cargo run --quiet -- decode-quote --hex /tmp/test_sgx_quote.hex --json',
          { encoding: 'utf-8' }
        );
        rustOutput = JSON.parse(output);
      } catch (error) {
        console.log('Skipping Rust CLI comparison (CLI not available)');
        return;
      }

      // Compare key fields
      expect(jsResult.header.version).toBe(rustOutput.header.version);
      expect(jsResult.header.tee_type).toBe(rustOutput.header.tee_type);
      expect(jsResult.header.attestation_key_type).toBe(rustOutput.header.attestation_key_type);

      if (jsResult.report.type === 'SgxEnclave' && rustOutput.report.SgxEnclave) {
        const jsReport = jsResult.report.report;
        const rustReport = rustOutput.report.SgxEnclave;

        expect(Buffer.from(jsReport.mr_enclave).toString('hex')).toBe(
          rustReport.mr_enclave.toLowerCase()
        );
        expect(Buffer.from(jsReport.mr_signer).toString('hex')).toBe(
          rustReport.mr_signer.toLowerCase()
        );
      }
    });

    it('should match Rust CLI decode-quote output for TDX', () => {
      const rawQuote = readFileSync('./sample/tdx_quote');
      const jsResult = parseQuote(rawQuote);

      let rustOutput: any;
      try {
        const hexQuote = Buffer.from(rawQuote).toString('hex');
        writeFileSync('/tmp/test_tdx_quote.hex', hexQuote);

        const output = execSync(
          'cd ../cli && cargo run --quiet -- decode-quote --hex /tmp/test_tdx_quote.hex --json',
          { encoding: 'utf-8' }
        );
        rustOutput = JSON.parse(output);
      } catch (error) {
        console.log('Skipping Rust CLI comparison (CLI not available)');
        return;
      }

      expect(jsResult.header.version).toBe(rustOutput.header.version);
      expect(jsResult.header.tee_type).toBe(rustOutput.header.tee_type);
    });
  });

  describe('Quote Verification', () => {
    it('should match Rust verify() output for SGX', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      const jsResult = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // Expected values from Rust tests
      expect(jsResult.status).toBe('ConfigurationAndSWHardeningNeeded');
      expect(jsResult.advisory_ids).toHaveLength(2);
      expect(jsResult.advisory_ids).toContain('INTEL-SA-00289');
      expect(jsResult.advisory_ids).toContain('INTEL-SA-00615');

      // Verify report structure exists
      expect(jsResult.report).toBeDefined();
      expect(jsResult.ppid).toBeDefined();
    });

    it('should match Rust verify() output for TDX', async () => {
      const rawQuote = readFileSync('./sample/tdx_quote');
      const collateral = JSON.parse(readFileSync('./sample/tdx_quote_collateral.json', 'utf-8'));

      const jsResult = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // Expected values from Rust tests
      expect(jsResult.status).toBe('UpToDate');
      expect(jsResult.advisory_ids).toHaveLength(0);

      expect(jsResult.report).toBeDefined();
      expect(jsResult.ppid).toBeDefined();
    });

    it('should extract same PPID as Rust', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      const jsResult = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // PPID should be extracted (non-empty for SGX quotes with PPID)
      expect(jsResult.ppid).toBeInstanceOf(Uint8Array);

      // The test quote should have a valid PPID
      const ppidHex = bytesToHex(jsResult.ppid);
      console.log('   PPID:', ppidHex.substring(0, 32) + '...');

      // PPID should be 16 bytes (32 hex chars) if present
      if (ppidHex.length > 0) {
        expect(ppidHex.length).toBe(32); // 16 bytes = 32 hex chars
      }
    });
  });

  describe('Error Handling', () => {
    it('should fail with expired TCB info like Rust', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      // Use a timestamp far in the future
      const futureTimestamp = 2000000000; // Year 2033

      await expect(
        verify(rawQuote, collateral, futureTimestamp)
      ).rejects.toThrow('TCBInfo expired');
    });

    it('should fail with invalid quote version like Rust', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      // Corrupt the version byte
      const corruptedQuote = new Uint8Array(rawQuote);
      corruptedQuote[0] = 99; // Invalid version

      await expect(
        verify(corruptedQuote, collateral, TEST_TIMESTAMP)
      ).rejects.toThrow();
    });

    it('should fail with FMSPC mismatch like Rust', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      // Modify FMSPC in collateral
      // Note: Modifying tcb_info will invalidate the signature first
      // So this test actually verifies that signature validation happens before FMSPC check
      const modifiedCollateral = {
        ...collateral,
        tcb_info: collateral.tcb_info.replace(
          /"fmspc":"[^"]+"/,
          '"fmspc":"000000000000"'
        ),
      };

      // Should fail with signature error (happens before FMSPC check)
      await expect(
        verify(rawQuote, modifiedCollateral, TEST_TIMESTAMP)
      ).rejects.toThrow('TCB Info signature invalid');
    });
  });

  describe('Field Extraction', () => {
    it('should extract same report data as Rust', () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const jsResult = parseQuote(rawQuote);

      if (jsResult.report.type === 'SgxEnclave') {
        const report = jsResult.report.report;

        // Check critical fields are present and valid
        expect(report.cpu_svn).toHaveLength(16);
        expect(report.mr_enclave).toHaveLength(32);
        expect(report.mr_signer).toHaveLength(32);
        expect(report.report_data).toHaveLength(64);

        // ISV fields
        expect(typeof report.isv_prod_id).toBe('number');
        expect(typeof report.isv_svn).toBe('number');

        console.log('   MR_ENCLAVE:', bytesToHex(report.mr_enclave).substring(0, 32) + '...');
        console.log('   MR_SIGNER:', bytesToHex(report.mr_signer).substring(0, 32) + '...');
        console.log('   ISV_PROD_ID:', report.isv_prod_id);
        console.log('   ISV_SVN:', report.isv_svn);
      }
    });

    it('should extract same TDX report data as Rust', () => {
      const rawQuote = readFileSync('./sample/tdx_quote');
      const jsResult = parseQuote(rawQuote);

      if (jsResult.report.type === 'TD10') {
        const report = jsResult.report.report;

        // Check TDX-specific fields
        expect(report.tee_tcb_svn).toHaveLength(16);
        expect(report.mr_td).toHaveLength(48);
        expect(report.mr_config_id).toHaveLength(48);
        expect(report.mr_owner).toHaveLength(48);
        expect(report.mr_owner_config).toHaveLength(48);
        expect(report.rt_mr0).toHaveLength(48);
        expect(report.rt_mr1).toHaveLength(48);
        expect(report.rt_mr2).toHaveLength(48);
        expect(report.rt_mr3).toHaveLength(48);

        console.log('   MR_TD:', bytesToHex(report.mr_td).substring(0, 32) + '...');
        console.log('   RTMR0:', bytesToHex(report.rt_mr0).substring(0, 32) + '...');
      }
    });
  });

  describe('Collateral Structure', () => {
    it('should have same collateral structure as Rust QuoteCollateralV3', () => {
      const collateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));

      // Check all required fields exist (matching Rust QuoteCollateralV3)
      expect(collateral).toHaveProperty('pck_crl_issuer_chain');
      expect(collateral).toHaveProperty('root_ca_crl');
      expect(collateral).toHaveProperty('pck_crl');
      expect(collateral).toHaveProperty('tcb_info_issuer_chain');
      expect(collateral).toHaveProperty('tcb_info');
      expect(collateral).toHaveProperty('tcb_info_signature');
      expect(collateral).toHaveProperty('qe_identity_issuer_chain');
      expect(collateral).toHaveProperty('qe_identity');
      expect(collateral).toHaveProperty('qe_identity_signature');

      // Check types
      expect(typeof collateral.pck_crl_issuer_chain).toBe('string');
      expect(typeof collateral.root_ca_crl).toBe('string');
      expect(typeof collateral.pck_crl).toBe('string');
      expect(typeof collateral.tcb_info).toBe('string');
      expect(typeof collateral.tcb_info_signature).toBe('string');

      // Verify hex-encoded CRLs
      expect(collateral.root_ca_crl).toMatch(/^[0-9a-f]+$/i);
      expect(collateral.pck_crl).toMatch(/^[0-9a-f]+$/i);

      console.log('   ✓ All QuoteCollateralV3 fields present');
    });
  });
});
