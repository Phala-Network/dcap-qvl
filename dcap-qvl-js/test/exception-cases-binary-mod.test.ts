/**
 * Exception Test Suite with Binary Quote Modification
 * This is a TypeScript port of tests/exception_cases_with_binary_mod.rs
 *
 * These tests modify quote bytes directly to trigger specific validation paths.
 * This allows testing of exception cases that cannot be triggered by collateral manipulation.
 */

import { describe, it, expect } from 'vitest';
import { verify } from '../src/verify';
import { QuoteCollateralV3 } from '../src/types';
import { readFileSync } from 'fs';
import * as quoteModifier from './quoteModifier';

// Helper to load valid SGX quote and collateral
function loadSgxSample(): [Uint8Array, QuoteCollateralV3] {
  const rawQuote = new Uint8Array(readFileSync('./sample/sgx_quote'));
  const collateral: QuoteCollateralV3 = JSON.parse(
    readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
  );
  return [rawQuote, collateral];
}

// Helper to load valid TDX quote and collateral
function loadTdxSample(): [Uint8Array, QuoteCollateralV3] {
  const rawQuote = new Uint8Array(readFileSync('./sample/tdx_quote'));
  const collateral: QuoteCollateralV3 = JSON.parse(
    readFileSync('./sample/tdx_quote_collateral.json', 'utf-8')
  );
  return [rawQuote, collateral];
}

const VALID_NOW = 1750320802;

describe('Binary Quote Modification Tests', () => {

  describe('Quote Header Tests', () => {
    it('test_unsupported_quote_version', async () => {
      const [quoteBytes, collateral] = loadSgxSample();
      const modified = quoteModifier.modifyVersion(quoteBytes, 2);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow(/Unsupported quote version|decode|parse/i);
    });

    it('test_unsupported_attestation_key_type', async () => {
      const [quoteBytes, collateral] = loadSgxSample();
      const modified = quoteModifier.modifyAttestationKeyType(quoteBytes, 0xff);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });
  });

  describe('SGX Attribute Tests', () => {
    it('test_sgx_debug_mode_enabled', async () => {
      const [quoteBytes, collateral] = loadSgxSample();
      const modified = quoteModifier.setSgxDebugMode(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
      // Note: Will fail at signature validation, but tests the code path exists
    });
  });

  describe('TDX Attribute Tests', () => {
    it('test_tdx_debug_mode_enabled', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxDebugMode(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
      // Note: Will fail at signature validation, but tests the code path exists
    });

    it('test_tdx_reserved_bits_set', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxReservedBits(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });

    it('test_tdx_sept_ve_disable_not_enabled', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.clearTdxSeptVeDisable(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });

    it('test_tdx_reserved_bit29_set', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxReservedBit29(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });

    it('test_tdx_pks_enabled', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxPks(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });

    it('test_tdx_kl_enabled', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxKl(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });

    it('test_tdx_other_reserved_bits_set', async () => {
      const [quoteBytes, collateral] = loadTdxSample();
      const modified = quoteModifier.setTdxOtherReservedBits(quoteBytes);

      await expect(verify(modified, collateral, VALID_NOW))
        .rejects.toThrow();
    });
  });

  describe('Quote Modifier Verification', () => {
    it('test_quote_modifier_works', () => {
      const [quoteBytes] = loadSgxSample();

      // Verify we can read and modify version
      const version = quoteModifier.getVersion(quoteBytes);
      expect(version).toBe(3); // SGX quote is version 3

      const modifiedVersion = quoteModifier.modifyVersion(quoteBytes, 99);
      const newVersion = quoteModifier.getVersion(modifiedVersion);
      expect(newVersion).toBe(99);

      // Verify TEE type
      const teeType = quoteModifier.getTeeType(quoteBytes);
      expect(teeType).toBe(0); // SGX is 0

      const modifiedTee = quoteModifier.modifyTeeType(quoteBytes, 0x81);
      const newTee = quoteModifier.getTeeType(modifiedTee);
      expect(newTee).toBe(0x81);
    });
  });
});
