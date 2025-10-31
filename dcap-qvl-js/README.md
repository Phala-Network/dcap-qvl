# @phala/dcap-qvl

Pure JavaScript implementation of Intel DCAP (Data Center Attestation Primitives) Quote Verification Library for SGX and TDX attestation.

## Features

- ✅ **Pure JavaScript** - No WASM, no native dependencies
- ✅ **Universal** - Works in Node.js, browsers, and React Native
- ✅ **TypeScript** - Full type definitions included
- ✅ **SGX & TDX** - Supports both Intel SGX and TDX quotes
- ✅ **Standards Compliant** - Follows Intel's DCAP specification
- ✅ **Well Tested** - Comprehensive test suite with real quote samples

## Installation

```bash
npm install @phala/dcap-qvl
```

For web-optimized build:
```bash
npm install @phala/dcap-qvl-web
```

For Node.js-optimized build:
```bash
npm install @phala/dcap-qvl-node
```

## Quick Start

### Verify a Quote

```typescript
import { verify, parseQuote } from '@phala/dcap-qvl';
import { readFileSync } from 'fs';

// Load quote and collateral
const rawQuote = readFileSync('quote.bin');
const collateral = JSON.parse(readFileSync('collateral.json', 'utf-8'));

// Verify the quote
const now = Math.floor(Date.now() / 1000);
const result = await verify(rawQuote, collateral, now);

console.log('TCB Status:', result.status);
console.log('Advisory IDs:', result.advisory_ids);
console.log('PPID:', Buffer.from(result.ppid).toString('hex'));
```

### Parse a Quote

```typescript
import { parseQuote } from '@phala/dcap-qvl';

const rawQuote = readFileSync('quote.bin');
const quote = parseQuote(rawQuote);

console.log('Quote Version:', quote.header.version);
console.log('TEE Type:', quote.header.tee_type === 0 ? 'SGX' : 'TDX');

if (quote.report.type === 'SgxEnclave') {
  console.log('MR_ENCLAVE:', Buffer.from(quote.report.report.mr_enclave).toString('hex'));
  console.log('MR_SIGNER:', Buffer.from(quote.report.report.mr_signer).toString('hex'));
} else if (quote.report.type === 'TD10' || quote.report.type === 'TD15') {
  const tdReport = quote.report.type === 'TD15' ? quote.report.report.base : quote.report.report;
  console.log('MR_TD:', Buffer.from(tdReport.mr_td).toString('hex'));
}
```

### Fetch Collateral

```typescript
import { getCollateralFromPcs, verify } from '@phala/dcap-qvl';

const rawQuote = readFileSync('quote.bin');

// Fetch collateral from Intel PCS
const collateral = await getCollateralFromPcs(rawQuote);

// Verify with fetched collateral
const now = Math.floor(Date.now() / 1000);
const result = await verify(rawQuote, collateral, now);
```

### Get Collateral from Custom PCCS

```typescript
import { getCollateral } from '@phala/dcap-qvl';

const rawQuote = readFileSync('quote.bin');
const pccsUrl = 'https://your-pccs-server.com/sgx/certification/v4/';

const collateral = await getCollateral(pccsUrl, rawQuote, 10000); // 10s timeout
```

## API Reference

### Main Functions

#### `verify(rawQuote, collateral, nowSecs): Promise<VerifiedReport>`

Verifies a DCAP quote against provided collateral.

**Parameters:**
- `rawQuote: Uint8Array` - Raw quote bytes
- `collateral: QuoteCollateralV3` - Quote collateral containing certificates, CRLs, and TCB info
- `nowSecs: number` - Current time in seconds since Unix epoch

**Returns:** `Promise<VerifiedReport>`
```typescript
interface VerifiedReport {
  status: string;              // TCB status (e.g., "UpToDate", "OutOfDate")
  advisory_ids: string[];      // Security advisory IDs
  report: Report;              // Parsed report (SGX or TDX)
  ppid: Uint8Array;           // Platform Provisioning ID
}
```

**Throws:** `QuoteVerificationError` if verification fails

#### `parseQuote(rawQuote): Quote`

Parses a raw DCAP quote into a structured format.

**Parameters:**
- `rawQuote: Uint8Array` - Raw quote bytes

**Returns:** `Quote` object

#### `getCollateralFromPcs(rawQuote, timeout?): Promise<QuoteCollateralV3>`

Fetches collateral from Intel's PCS (Provisioning Certificate Service).

**Parameters:**
- `rawQuote: Uint8Array` - Raw quote bytes
- `timeout?: number` - Request timeout in milliseconds (default: 10000)

**Returns:** `Promise<QuoteCollateralV3>`

#### `getCollateral(pccsUrl, rawQuote, timeout?): Promise<QuoteCollateralV3>`

Fetches collateral from a custom PCCS server.

**Parameters:**
- `pccsUrl: string` - PCCS base URL
- `rawQuote: Uint8Array` - Raw quote bytes
- `timeout?: number` - Request timeout in milliseconds (default: 10000)

**Returns:** `Promise<QuoteCollateralV3>`

### Types

#### `QuoteCollateralV3`

```typescript
interface QuoteCollateralV3 {
  pck_crl_issuer_chain: string;
  root_ca_crl: string;
  pck_crl: string;
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: string;
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: string;
}
```

#### `Quote`

```typescript
interface Quote {
  header: Header;
  report: Report;
  auth_data: AuthData;
  signed_length: number;
}
```

See [types.ts](src/types.ts) for complete type definitions.

## Browser Usage

```html
<script type="module">
  import { verify } from 'https://cdn.jsdelivr.net/npm/@phala/dcap-qvl-web/+esm';

  async function verifyQuote() {
    const quoteResponse = await fetch('/quote.bin');
    const quote = new Uint8Array(await quoteResponse.arrayBuffer());

    const collateralResponse = await fetch('/collateral.json');
    const collateral = await collateralResponse.json();

    const now = Math.floor(Date.now() / 1000);
    const result = await verify(quote, collateral, now);

    console.log('Verification result:', result);
  }

  verifyQuote();
</script>
```

## React Native Usage

```typescript
import { verify } from '@phala/dcap-qvl';
import RNFS from 'react-native-fs';

async function verifyQuote() {
  // Read quote from file
  const quoteBase64 = await RNFS.readFile(quotePath, 'base64');
  const quote = Uint8Array.from(atob(quoteBase64), c => c.charCodeAt(0));

  // Fetch collateral
  const response = await fetch('https://api.example.com/collateral');
  const collateral = await response.json();

  // Verify
  const now = Math.floor(Date.now() / 1000);
  const result = await verify(quote, collateral, now);

  return result;
}
```

## Comparison with Rust Version

This JavaScript implementation is a line-by-line port of the [Rust dcap-qvl](https://github.com/Phala-Network/dcap-qvl) library, ensuring identical verification logic and results.

**Advantages of JS version:**
- ✅ No build toolchain required
- ✅ Works on all platforms without compilation
- ✅ Smaller bundle size for web apps
- ✅ Easier to integrate in existing JS/TS projects
- ✅ Works on Android devices without WASM support

**When to use Rust version:**
- High-performance server applications
- No-std / embedded environments
- Smart contracts (with `contract` feature)

## Testing

The library includes a comprehensive test suite that verifies:
- SGX quote parsing and verification
- TDX quote parsing and verification
- Certificate chain validation
- CRL checking
- Signature verification
- TCB status determination
- Error handling

Run tests:
```bash
npm test
```

Run tests with coverage:
```bash
npm run test:coverage
```

## Development

### Setup

```bash
git clone https://github.com/Phala-Network/dcap-qvl-js.git
cd dcap-qvl-js
npm install
```

### Build

```bash
npm run build
```

### Test

```bash
npm test              # Run once
npm run test:watch    # Watch mode
npm run test:coverage # With coverage
```

### Lint

```bash
npm run lint
```

### Type Check

```bash
npm run typecheck
```

## Architecture

The library is structured into several modules:

- `constants.ts` - All DCAP constants and OIDs
- `types.ts` - TypeScript type definitions
- `utils.ts` - Binary parsing utilities
- `parser.ts` - Quote parsing logic
- `certificate.ts` - X.509 certificate handling
- `crypto.ts` - Cryptographic operations (ECDSA, SHA-256)
- `collateral.ts` - Collateral fetching from PCS/PCCS
- `verify.ts` - Main verification logic

The verification process follows Intel's DCAP specification:
1. Parse the quote structure
2. Verify TCB Info hasn't expired
3. Verify certificate chains (PCK, TCB Info)
4. Check CRLs for revoked certificates
5. Verify all cryptographic signatures
6. Determine TCB status based on CPU SVN and PCE SVN
7. Validate security attributes

## Security Considerations

- Always verify quotes with up-to-date collateral
- Check the returned `status` and `advisory_ids` fields
- Consider `OutOfDate`, `OutOfDateConfigurationNeeded`, and similar statuses as potentially insecure
- Validate that debug mode is disabled (`status` should not be `Debug`)
- Keep the library updated to include latest security patches

## License

MIT License - see [LICENSE](LICENSE) for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

- 📖 [Documentation](https://github.com/Phala-Network/dcap-qvl-js)
- 🐛 [Issue Tracker](https://github.com/Phala-Network/dcap-qvl-js/issues)
- 💬 [Discussions](https://github.com/Phala-Network/dcap-qvl-js/discussions)

## Related Projects

- [dcap-qvl (Rust)](https://github.com/Phala-Network/dcap-qvl) - Original Rust implementation
- [Phala Network](https://phala.network/) - Privacy-preserving cloud computing

## Acknowledgments

This project is a pure JavaScript port of the Rust dcap-qvl library developed by Phala Network. Special thanks to the original authors and Intel for the DCAP specification.
