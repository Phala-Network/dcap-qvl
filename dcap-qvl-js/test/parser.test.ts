/**
 * Parser tests
 */

import { describe, it, expect } from 'vitest';
import { parseQuote } from '../src/parser';
import { readFileSync } from 'fs';
import { TEE_TYPE_SGX, TEE_TYPE_TDX } from '../src/constants';

describe('Quote Parser', () => {
  describe('SGX Quote', () => {
    const rawQuote = readFileSync('./sample/sgx_quote');

    it('should parse SGX quote header', () => {
      const quote = parseQuote(rawQuote);

      expect(quote.header.version).toBe(3);
      expect(quote.header.tee_type).toBe(TEE_TYPE_SGX);
      expect(quote.header.attestation_key_type).toBe(2);
    });

    it('should parse SGX enclave report', () => {
      const quote = parseQuote(rawQuote);

      expect(quote.report.type).toBe('SgxEnclave');
      expect(quote.report.report.mr_enclave).toHaveLength(32);
      expect(quote.report.report.mr_signer).toHaveLength(32);
      expect(quote.report.report.cpu_svn).toHaveLength(16);
    });

    it('should parse auth data', () => {
      const quote = parseQuote(rawQuote);

      expect(quote.auth_data.version).toBe(3);
      expect(quote.auth_data.data.ecdsa_signature).toHaveLength(64);
      expect(quote.auth_data.data.ecdsa_attestation_key).toHaveLength(64);
    });

    it('should calculate correct signed length', () => {
      const quote = parseQuote(rawQuote);
      expect(quote.signed_length).toBeGreaterThan(0);
    });
  });

  describe('TDX Quote', () => {
    const rawQuote = readFileSync('./sample/tdx_quote');

    it('should parse TDX quote header', () => {
      const quote = parseQuote(rawQuote);

      expect(quote.header.version).toBe(4);
      expect(quote.header.tee_type).toBe(TEE_TYPE_TDX);
    });

    it('should parse TD Report 1.0', () => {
      const quote = parseQuote(rawQuote);

      expect(quote.report.type).toBe('TD10');
      expect(quote.report.report.tee_tcb_svn).toHaveLength(16);
      expect(quote.report.report.mr_td).toHaveLength(48);
      expect(quote.report.report.mr_seam).toHaveLength(48);
    });
  });

  describe('Error Handling', () => {
    it('should reject invalid quote', () => {
      const invalidQuote = new Uint8Array([0, 1, 2, 3]);
      expect(() => parseQuote(invalidQuote)).toThrow();
    });

    it('should reject truncated quote', () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const truncated = rawQuote.slice(0, 100);
      expect(() => parseQuote(truncated)).toThrow();
    });
  });
});
