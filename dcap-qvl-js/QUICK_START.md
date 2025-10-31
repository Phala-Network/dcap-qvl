# Quick Start Guide

## Setup (5 minutes)

```bash
cd dcap-qvl-js
npm install
cp -r ../sample ./sample
```

## Verify Setup

```bash
npm run typecheck  # Should pass
npm run lint       # Should pass
npm run build      # Should build (but entry points are empty)
```

## Implementation Order

### Day 1-3: Parser
**File:** `src/parser.ts`

```typescript
// Start here
export function parseQuote(rawQuote: Uint8Array): Quote {
  let offset = 0;

  // 1. Parse header (48 bytes)
  const header = parseHeader(rawQuote, offset);
  offset += HEADER_BYTE_LEN;

  // 2. Parse report (384-648 bytes depending on type)
  const report = parseReport(rawQuote, offset, header);
  offset += reportLength(header, report);

  // 3. Parse auth data (variable length)
  const authDataSize = readU32LE(rawQuote, offset);
  offset += 4;
  const authData = parseAuthData(rawQuote.slice(offset, offset + authDataSize), header.version);

  return { header, report, auth_data: authData, signed_length: calculateSignedLength(header, report) };
}
```

**Test:** `test/parser.test.ts`

```typescript
import { parseQuote } from '../src/parser';
import { readFileSync } from 'fs';

it('should parse SGX quote', () => {
  const raw = readFileSync('./sample/sgx_quote');
  const quote = parseQuote(raw);
  expect(quote.header.version).toBe(3);
});
```

**Reference:** Rust `src/quote.rs` lines 445-555

### Day 4-5: Cryptography
**File:** `src/crypto.ts`

```typescript
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

export async function verifyEcdsaP256Signature(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  // Import public key
  const key = await crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );

  // Convert signature to DER
  const derSig = encodeEcdsaSignatureAsDer(signature);

  // Verify
  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    derSig,
    message
  );
}
```

**Reference:** Rust `src/verify.rs` lines 180-218

### Day 6-8: Certificates
**File:** `src/certificate.ts`

```typescript
import { X509Certificate } from '@peculiar/x509';

export function parsePemCertificateChain(pem: string): X509Certificate[] {
  const pemCerts = parsePemChain(pem);
  return pemCerts.map(p => new X509Certificate(pemToDer(p)));
}

export async function extractIntelExtension(cert: X509Certificate): Promise<any> {
  // Find extension with OID 1.2.840.113741.1.13.1
  const ext = cert.extensions.find(e => e.type === SGX_EXTENSION_OID);
  if (!ext) throw new Error('Intel extension not found');
  return ext;
}
```

**Reference:** Rust `src/utils.rs` and `src/intel.rs`

### Day 9-12: Verification ⚠️ CRITICAL
**File:** `src/verify.ts`

```typescript
export async function verify(
  rawQuote: Uint8Array,
  collateral: QuoteCollateralV3,
  nowSecs: number
): Promise<VerifiedReport> {
  // 1. Parse quote
  const quote = parseQuote(rawQuote);

  // 2. Parse TCB info
  const tcbInfo = JSON.parse(collateral.tcb_info) as TcbInfo;

  // 3. Check expiration
  const nextUpdate = new Date(tcbInfo.nextUpdate);
  if (nowSecs > nextUpdate.getTime() / 1000) {
    throw new Error('TCBInfo expired');
  }

  // 4. Verify TCB Info signature
  const tcbCerts = parsePemCertificateChain(collateral.tcb_info_issuer_chain);
  await verifyCertificateChain(tcbCerts, crls, new Date(nowSecs * 1000));
  await verifyEcdsaP256Signature(
    tcbCerts[0].publicKey.rawData,
    Buffer.from(collateral.tcb_info),
    hexToBytes(collateral.tcb_info_signature)
  );

  // ... Continue with 12 verification steps ...
  // See IMPLEMENTATION_GUIDE.md for full details

  return { status, advisory_ids, report: quote.report, ppid };
}
```

**Reference:** Rust `src/verify.rs` lines 89-334

### Day 13-14: Collateral & Testing
**File:** `src/collateral.ts`

```typescript
export async function getCollateralFromPcs(
  rawQuote: Uint8Array,
  timeout = 10000
): Promise<QuoteCollateralV3> {
  const quote = parseQuote(rawQuote);
  const fmspc = extractFmspc(quote);
  const ca = extractCa(quote);

  // Fetch from Intel PCS
  const baseUrl = 'https://api.trustedservices.intel.com';
  // ... make HTTP requests ...

  return collateral;
}
```

## Test Commands

```bash
# Run specific test
npm test -- parser

# Run with debug output
DEBUG=true npm test

# Run specific file
npm test -- test/parser.test.ts

# Watch mode
npm run test:watch
```

## Verify Against Rust

```bash
# Terminal 1
cd ..
cargo test

# Terminal 2
cd dcap-qvl-js
npm test
```

**Expected outputs MUST match:**
- SGX: status="ConfigurationAndSWHardeningNeeded", advisories=["INTEL-SA-00289", "INTEL-SA-00615"]
- TDX: status="UpToDate", advisories=[]

## Debug Tips

### Add Logging
```typescript
const DEBUG = process.env.DEBUG === 'true';
function debug(...args: any[]) {
  if (DEBUG) console.log('[DEBUG]', ...args);
}

debug('Parsed header:', header);
debug('CPU SVN:', bytesToHex(cpuSvn));
```

### Compare Byte-by-Byte
```typescript
console.log('Offset:', offset);
console.log('Next 16 bytes:', bytesToHex(buffer.slice(offset, offset + 16)));
```

### Use Rust as Reference
```rust
// In Rust code, add println! statements
println!("header: {:?}", header);
println!("cpu_svn: {:?}", cpu_svn);
```

## Common Issues

### Issue: "Buffer too short"
**Fix:** Check offset calculations, ensure you're reading the right number of bytes

### Issue: "Signature verification failed"
**Fix:**
1. Check DER encoding
2. Verify public key format (should be 65 bytes with 0x04 prefix)
3. Ensure message is exactly the signed portion

### Issue: "TCB status mismatch"
**Fix:**
1. Compare CPU SVN arrays element by element
2. Check byte order (little-endian)
3. Verify comparison logic (should be >=)

## File Completion Checklist

- [x] constants.ts
- [x] types.ts
- [x] utils.ts
- [ ] parser.ts ← START HERE
- [ ] crypto.ts
- [ ] certificate.ts
- [ ] verify.ts ← CRITICAL
- [ ] collateral.ts
- [ ] index.ts
- [ ] web.ts
- [ ] node.ts

## Test Completion Checklist

- [ ] test/parser.test.ts
- [ ] test/crypto.test.ts
- [ ] test/certificate.test.ts
- [ ] test/verify.test.ts ← MUST PASS

## Success Criteria

✅ `npm test` passes with 0 failures
✅ SGX quote: status="ConfigurationAndSWHardeningNeeded"
✅ TDX quote: status="UpToDate"
✅ Coverage >90%

## Next Steps

1. Read IMPLEMENTATION_GUIDE.md (detailed instructions)
2. Read TESTING_GUIDE.md (testing strategy)
3. Start implementing `src/parser.ts`
4. Test continuously
5. Compare with Rust frequently

## Help Resources

- **Rust source**: ../src/
- **Rust tests**: ../tests/verify_quote.rs
- **Implementation guide**: IMPLEMENTATION_GUIDE.md
- **Testing guide**: TESTING_GUIDE.md
- **Project status**: PROJECT_STATUS.md

Good luck! 🚀
