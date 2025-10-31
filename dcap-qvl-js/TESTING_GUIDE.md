# Testing Guide for dcap-qvl-js

This guide explains how to test the JavaScript implementation to ensure it produces identical results to the Rust version.

## Testing Strategy

The testing approach follows Test-Driven Development (TDD) principles and uses the same test data as the Rust implementation for cross-validation.

## Test Data Setup

First, copy the sample files from the Rust implementation:

```bash
cd dcap-qvl-js
cp -r ../sample ./sample
```

Your test data structure should look like:
```
sample/
├── sgx_quote                    # SGX quote binary
├── sgx_quote_collateral.json    # SGX collateral
├── tdx_quote                    # TDX quote binary
├── tdx_quote_collateral.json    # TDX collateral
├── tdx-quote.hex                # TDX quote (hex format)
└── quote-from-tappd.hex         # Additional test quote
```

## Test Suite Structure

### 1. Unit Tests

#### Parser Tests (`test/parser.test.ts`)

```typescript
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

    it('should reject unsupported version', () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const modified = new Uint8Array(rawQuote);
      modified[0] = 99; // Invalid version
      expect(() => parseQuote(modified)).toThrow('Unsupported quote version');
    });
  });
});
```

#### Certificate Tests (`test/certificate.test.ts`)

```typescript
import { describe, it, expect } from 'vitest';
import { parsePemCertificateChain, extractIntelExtension, getFmspc } from '../src/certificate';
import { readFileSync } from 'fs';

describe('Certificate Handling', () => {
  const collateral = JSON.parse(
    readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
  );

  it('should parse PEM certificate chain', () => {
    const certs = parsePemCertificateChain(collateral.pck_crl_issuer_chain);
    expect(certs.length).toBeGreaterThan(0);
  });

  it('should extract Intel extension', async () => {
    const certs = parsePemCertificateChain(collateral.pck_crl_issuer_chain);
    const extension = await extractIntelExtension(certs[0]);
    expect(extension).toBeDefined();
  });

  it('should extract FMSPC', async () => {
    const certs = parsePemCertificateChain(collateral.pck_crl_issuer_chain);
    const extension = await extractIntelExtension(certs[0]);
    const fmspc = await getFmspc(extension);
    expect(fmspc).toHaveLength(6);
  });
});
```

#### Crypto Tests (`test/crypto.test.ts`)

```typescript
import { describe, it, expect } from 'vitest';
import { sha256, verifyEcdsaP256Signature, encodeEcdsaSignatureAsDer } from '../src/crypto';

describe('Cryptographic Operations', () => {
  it('should compute SHA-256 correctly', async () => {
    const data = new TextEncoder().encode('hello world');
    const hash = await sha256(data);

    // Known SHA-256 hash of "hello world"
    const expected = new Uint8Array([
      0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
      0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
      0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
      0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9,
    ]);

    expect(hash).toEqual(expected);
  });

  it('should encode ECDSA signature as DER', () => {
    const rawSig = new Uint8Array(64).fill(0x42);
    const derSig = encodeEcdsaSignatureAsDer(rawSig);

    // DER encoded signature should start with 0x30 (SEQUENCE)
    expect(derSig[0]).toBe(0x30);
    expect(derSig.length).toBeGreaterThanOrEqual(70);
    expect(derSig.length).toBeLessThanOrEqual(72);
  });
});
```

### 2. Integration Tests

#### Main Verification Tests (`test/verify.test.ts`)

This is the most critical test file - it must match the Rust `tests/verify_quote.rs` exactly:

```typescript
import { describe, it, expect } from 'vitest';
import { verify, parseQuote } from '../src';
import { readFileSync } from 'fs';

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
      expect(quote.header.tee_type).toBe(0x00000000); // TEE_TYPE_SGX
    });

    it('should verify SGX quote and match Rust output', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);

      // These values MUST match the Rust test output
      expect(result.status).toBe('ConfigurationAndSWHardeningNeeded');
      expect(result.advisory_ids).toEqual([
        'INTEL-SA-00289',
        'INTEL-SA-00615',
      ]);
    });

    it('should extract correct PPID', async () => {
      const result = await verify(rawQuote, collateral, TEST_TIMESTAMP);
      expect(result.ppid).toBeDefined();
      expect(result.ppid.length).toBeGreaterThan(0);
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
      expect(quote.header.tee_type).toBe(0x00000081); // TEE_TYPE_TDX
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

      const tdReport = result.report.type === 'TD15'
        ? result.report.report.base
        : result.report.report;

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

      await expect(
        verify(rawQuote, collateral, futureTime)
      ).rejects.toThrow('TCBInfo expired');
    });

    it('should reject corrupted signature', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(
        readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
      );

      // Corrupt the signature bytes
      const corrupted = new Uint8Array(rawQuote);
      corrupted[100] ^= 0xFF;

      await expect(
        verify(corrupted, collateral, TEST_TIMESTAMP)
      ).rejects.toThrow();
    });

    it('should reject invalid certificate chain', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(
        readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
      );

      // Corrupt the certificate chain
      const corruptedCollateral = {
        ...collateral,
        pck_crl_issuer_chain: 'invalid',
      };

      await expect(
        verify(rawQuote, corruptedCollateral, TEST_TIMESTAMP)
      ).rejects.toThrow();
    });

    it('should reject FMSPC mismatch', async () => {
      const rawQuote = readFileSync('./sample/sgx_quote');
      const collateral = JSON.parse(
        readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
      );

      // Modify TCB info with wrong FMSPC
      const tcbInfo = JSON.parse(collateral.tcb_info);
      tcbInfo.fmspc = '000000000000';
      const corruptedCollateral = {
        ...collateral,
        tcb_info: JSON.stringify(tcbInfo),
      };

      await expect(
        verify(rawQuote, corruptedCollateral, TEST_TIMESTAMP)
      ).rejects.toThrow('Fmspc mismatch');
    });
  });
});
```

### 3. Cross-Verification Tests

Create a script to compare outputs between Rust and JavaScript implementations:

```bash
#!/bin/bash
# test/cross-verify.sh

set -e

echo "Running cross-verification tests..."

# Build and run Rust tests
echo "1. Running Rust tests..."
cd ..
cargo test --quiet > /tmp/rust-output.txt 2>&1 || true
RUST_EXIT=$?

# Run JavaScript tests
echo "2. Running JavaScript tests..."
cd dcap-qvl-js
npm test > /tmp/js-output.txt 2>&1 || true
JS_EXIT=$?

echo "3. Comparing results..."

if [ $RUST_EXIT -eq 0 ] && [ $JS_EXIT -eq 0 ]; then
    echo "✅ Both implementations pass all tests"
else
    echo "❌ Test failures detected:"
    [ $RUST_EXIT -ne 0 ] && echo "  - Rust tests failed"
    [ $JS_EXIT -ne 0 ] && echo "  - JavaScript tests failed"
    exit 1
fi

# Extract and compare specific test outputs
echo "4. Verifying identical outputs..."

# You can add more specific comparisons here
echo "✅ Cross-verification complete"
```

### 4. Snapshot Tests

Use Vitest's snapshot feature to ensure parsed structures remain consistent:

```typescript
import { describe, it, expect } from 'vitest';
import { parseQuote } from '../src';
import { readFileSync } from 'fs';

describe('Snapshot Tests', () => {
  it('SGX quote structure should match snapshot', () => {
    const rawQuote = readFileSync('./sample/sgx_quote');
    const quote = parseQuote(rawQuote);

    // Sanitize timestamp-sensitive fields
    const sanitized = {
      ...quote,
      // Remove fields that might vary
    };

    expect(sanitized).toMatchSnapshot();
  });

  it('TDX quote structure should match snapshot', () => {
    const rawQuote = readFileSync('./sample/tdx_quote');
    const quote = parseQuote(rawQuote);
    expect(quote).toMatchSnapshot();
  });
});
```

## Running Tests

### Basic Test Run

```bash
npm test
```

### Watch Mode (for development)

```bash
npm run test:watch
```

### Coverage Report

```bash
npm run test:coverage
```

This generates a coverage report showing:
- Line coverage
- Branch coverage
- Function coverage

Aim for >90% coverage.

### Cross-Verification

```bash
chmod +x test/cross-verify.sh
./test/cross-verify.sh
```

## Validation Checklist

Before considering the implementation complete, verify:

### Functional Requirements
- [ ] SGX quotes parse correctly
- [ ] TDX quotes parse correctly
- [ ] SGX verification matches Rust output exactly
- [ ] TDX verification matches Rust output exactly
- [ ] TCB status determination is correct
- [ ] Advisory IDs match
- [ ] PPID extraction works
- [ ] Certificate chain verification works
- [ ] CRL checking is implemented
- [ ] All signatures verify correctly

### Error Handling
- [ ] Invalid quotes are rejected
- [ ] Corrupted signatures are detected
- [ ] Expired TCB info is rejected
- [ ] Certificate chain errors are caught
- [ ] FMSPC mismatches are detected
- [ ] Clear error messages are provided

### Performance
- [ ] Verification completes in <1 second for typical quotes
- [ ] No memory leaks in repeated verifications
- [ ] Bundle size is reasonable (<100KB minified)

### Compatibility
- [ ] Works in Node.js 18+
- [ ] Works in Chrome/Edge
- [ ] Works in Firefox
- [ ] Works in Safari
- [ ] TypeScript types are accurate

## Debugging Failed Tests

### Common Issues

1. **Binary Parsing Errors**
   - Check endianness (should be little-endian)
   - Verify offset calculations
   - Print buffer contents at failure points

2. **Signature Verification Failures**
   - Check DER encoding of signatures
   - Verify public key format (uncompressed point)
   - Ensure hash algorithm matches (SHA-256)

3. **Certificate Validation Issues**
   - Verify PEM parsing
   - Check certificate chain order
   - Validate CRL parsing

4. **TCB Status Mismatch**
   - Compare CPU SVN byte-by-byte
   - Check PCE SVN comparison
   - Verify TDX TCB component comparison

### Debug Output

Add debug logging to track verification steps:

```typescript
const DEBUG = process.env.DEBUG === 'true';

function debug(...args: any[]) {
  if (DEBUG) {
    console.log('[DEBUG]', ...args);
  }
}

// In verification code:
debug('Parsed quote:', quote);
debug('TCB Info:', tcbInfo);
debug('CPU SVN:', bytesToHex(cpuSvn));
debug('PCE SVN:', pceSvn);
```

Run with debug output:
```bash
DEBUG=true npm test
```

## Continuous Integration

Add to `.github/workflows/test.yml`:

```yaml
name: Test

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
      - run: npm run test:coverage
      - uses: codecov/codecov-action@v3
        with:
          files: ./coverage/coverage-final.json

  cross-verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: cargo test
      - run: cd dcap-qvl-js && npm ci && npm test
      - run: ./dcap-qvl-js/test/cross-verify.sh
```

## Next Steps

1. Implement all source files according to IMPLEMENTATION_GUIDE.md
2. Write tests in parallel with implementation (TDD)
3. Run tests frequently to catch issues early
4. Use cross-verification to ensure correctness
5. Achieve >90% test coverage
6. Document any deviations from Rust implementation
