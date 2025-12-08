# dcap-qvl-js

Pure JavaScript implementation of Intel SGX DCAP Quote Verification Library.

## Description

`dcap-qvl-js` provides a pure JavaScript implementation for verifying Intel SGX DCAP (Data Center Attestation Primitives) quotes. It allows you to parse quotes, fetch collateral (PCK certificates, TCB info, QE identity), and verify the quote's validity and TCB status.

## Features

- **Pure JavaScript**: No native dependencies, runs in both Node.js and browser environments
- **Universal/Isomorphic**: Works seamlessly in Node.js and browsers with bundler polyfills
- **Full TypeScript Support**: Complete type declarations for type safety and IDE autocompletion
- **Quote Parsing**: Parse and inspect SGX/TDX DCAP quotes
- **Collateral Retrieval**: Helper functions to fetch necessary collateral from PCCS servers
- **Complete Verification**: Full verification logic including signature checks, certificate chain validation, and TCB level comparison

## Installation

```bash
npm install @phala/dcap-qvl
```

## Quick Start

### Basic Usage (Node.js)

```javascript
import { getCollateralAndVerify } from '@phala/dcap-qvl';

async function verifyQuote(quoteBuffer) {
    // Fetch collateral and verify in one step (defaults to Phala PCCS)
    const result = await getCollateralAndVerify(quoteBuffer);
    console.log('TCB Status:', result.status);
}
```

### Custom PCCS Server

```javascript
import { verify, getCollateral, PHALA_PCCS_URL } from '@phala/dcap-qvl';

async function verifyQuote(quoteBuffer) {
    // Use default Phala PCCS, or specify your own
    const pccsUrl = process.env.PCCS_URL || PHALA_PCCS_URL;
    const collateral = await getCollateral(pccsUrl, quoteBuffer);

    const currentTimestamp = Date.now() / 1000;
    const result = verify(quoteBuffer, collateral, currentTimestamp);

    console.log('TCB Status:', result.status);
    console.log('Advisory IDs:', result.advisory_ids);
}
```

### TypeScript Usage

The library includes full TypeScript type declarations for enhanced development experience:

```typescript
import { verify, getCollateral, Quote, VerifiedReport } from '@phala/dcap-qvl';

async function verifyQuote(quoteBuffer: Buffer): Promise<VerifiedReport> {
    const pccsUrl = 'https://your-pccs-server.com/sgx/certification/v4/';
    const collateral = await getCollateral(pccsUrl, quoteBuffer);

    const currentTimestamp = Date.now() / 1000;
    const result = verify(quoteBuffer, collateral, currentTimestamp);

    // TypeScript knows the exact type of result
    console.log('TCB Status:', result.status);
    console.log('Advisory IDs:', result.advisory_ids);
    console.log('Report:', result.report);
    console.log('PPID:', result.ppid);

    return result;
}

// Parse quote structure
function parseQuote(quoteBuffer: Buffer): void {
    const quote = Quote.parse(quoteBuffer);
    console.log('Quote Version:', quote.header.version);
    console.log('TEE Type:', quote.header.teeType);
    console.log('Report Data:', quote.report);
}
```

### Browser Usage

For browser environments, you need to configure Node.js polyfills for `crypto`, `buffer`, and `stream` modules.

#### Vite Configuration

```bash
npm install --save-dev vite-plugin-node-polyfills
```

```javascript
// vite.config.js
import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ['crypto', 'stream', 'buffer', 'util'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
    }),
  ],
});
```

#### Webpack 5 Configuration

```bash
npm install --save-dev crypto-browserify stream-browserify buffer process
```

```javascript
// webpack.config.js
module.exports = {
  resolve: {
    fallback: {
      crypto: require.resolve('crypto-browserify'),
      stream: require.resolve('stream-browserify'),
      buffer: require.resolve('buffer/'),
    },
  },
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: 'process/browser',
    }),
  ],
};
```

#### Browser Example

```html
<!DOCTYPE html>
<html>
<head>
    <title>DCAP Quote Verification</title>
</head>
<body>
    <h1>DCAP Quote Verification</h1>
    <button id="verifyBtn">Verify Quote</button>
    <pre id="result"></pre>

    <script type="module">
        import { verify, getCollateral, Quote } from '@phala/dcap-qvl';

        document.getElementById('verifyBtn').addEventListener('click', async () => {
            try {
                // Load your quote data (as Uint8Array or Buffer)
                const quoteBuffer = new Uint8Array([/* quote bytes */]);

                const pccsUrl = 'https://your-pccs-server.com/sgx/certification/v4/';
                const collateral = await getCollateral(pccsUrl, quoteBuffer);

                const currentTimestamp = Date.now() / 1000;
                const result = verify(quoteBuffer, collateral, currentTimestamp);

                document.getElementById('result').textContent = JSON.stringify(result, null, 2);
            } catch (error) {
                document.getElementById('result').textContent = 'Error: ' + error.message;
            }
        });
    </script>
</body>
</html>
```

## API Reference

### Main Functions

#### `verify(rawQuote, collateral, nowSecs)`

Verifies a DCAP quote with the provided collateral.

**Parameters:**
- `rawQuote` (Buffer | Uint8Array): Raw quote bytes
- `collateral` (Object): Quote collateral containing TCB info, certificates, and CRLs
- `nowSecs` (number): Current timestamp in seconds (Unix time)

**Returns:** `VerifiedReport` object containing:
- `status` (string): TCB status (e.g., "UpToDate", "OutOfDate", "ConfigurationNeeded")
- `advisory_ids` (string[]): Array of advisory IDs
- `report` (Object): Parsed quote report data
- `ppid` (Buffer): Platform Provisioning ID

**Example:**
```javascript
const result = verify(quoteBuffer, collateral, Date.now() / 1000);
console.log('TCB Status:', result.status);
```

#### `getCollateral(pccsUrl, rawQuote)`

Fetches collateral from a PCCS server for the given quote.

**Parameters:**
- `pccsUrl` (string): PCCS server base URL (must end with `/`)
- `rawQuote` (Buffer | Uint8Array): Raw quote bytes

**Returns:** Promise resolving to collateral object containing:
- `tcb_info` (string): TCB information JSON
- `tcb_info_signature` (string | Buffer): TCB info signature
- `tcb_info_issuer_chain` (string | Buffer): TCB info certificate chain
- `pck_crl` (string | Buffer): PCK Certificate Revocation List
- `root_ca_crl` (string | Buffer): Root CA Certificate Revocation List

**Example:**
```javascript
const collateral = await getCollateral('https://pccs.example.com/sgx/certification/v4/', quoteBuffer);
```

#### `getCollateralAndVerify(rawQuote, pccsUrl?)`

Convenience function that fetches collateral and verifies the quote in one step.

**Parameters:**
- `rawQuote` (Buffer | Uint8Array): Raw quote bytes
- `pccsUrl` (string, optional): PCCS server URL (defaults to `PHALA_PCCS_URL`)

**Returns:** Promise resolving to `VerifiedReport` object

**Example:**
```javascript
const result = await getCollateralAndVerify(quoteBuffer);
console.log('TCB Status:', result.status);
```

#### `Quote.parse(rawQuote)`

Parses a raw quote buffer into a structured Quote object.

**Parameters:**
- `rawQuote` (Buffer | Uint8Array): Raw quote bytes

**Returns:** `Quote` object containing:
- `header`: Quote header information (version, attestation key type, TEE type)
- `report`: Enclave or TD report data
- `authData`: Authentication data including certificates and signatures

**Example:**
```javascript
const quote = Quote.parse(quoteBuffer);
console.log('Version:', quote.header.version);
console.log('TEE Type:', quote.header.teeType);
```

### Classes

#### `QuoteVerifier`

Advanced quote verification with custom root CA support.

**Methods:**
- `QuoteVerifier.newProd()`: Create verifier with Intel's production root CA
- `QuoteVerifier.newWithRootCa(rootCaDer)`: Create verifier with custom root CA
- `verify(rawQuote, collateral, nowSecs)`: Verify a quote

**Example:**
```javascript
import { QuoteVerifier } from '@phala/dcap-qvl';

// Use production Intel root CA
const verifier = QuoteVerifier.newProd();
const result = verifier.verify(quoteBuffer, collateral, Date.now() / 1000);

// Use custom root CA
const customRootCa = Buffer.from(/* custom root CA DER bytes */);
const customVerifier = QuoteVerifier.newWithRootCa(customRootCa);
const result2 = customVerifier.verify(quoteBuffer, collateral, Date.now() / 1000);
```

### Constants

#### `PHALA_PCCS_URL`

Default PCCS URL pointing to Phala Network's PCCS server (`https://pccs.phala.network`).

#### `INTEL_PCS_URL`

Intel's official Provisioning Certification Service URL (`https://api.trustedservices.intel.com`).

**Example:**
```javascript
import { getCollateral, PHALA_PCCS_URL, INTEL_PCS_URL } from '@phala/dcap-qvl';

// Use Phala PCCS (recommended)
const collateral = await getCollateral(PHALA_PCCS_URL, quoteBuffer);

// Or use Intel PCS directly
const collateral2 = await getCollateral(INTEL_PCS_URL, quoteBuffer);
```

## Browser Compatibility Notes

When running in browser environments:

1. **Polyfills Required**: You must configure polyfills for Node.js built-in modules (`crypto`, `stream`, `buffer`)
2. **Bundle Size**: The library includes cryptographic operations which may increase bundle size (typically ~500KB minified)
3. **CORS**: Ensure your PCCS server supports CORS if fetching collateral from the browser
4. **Performance**: Browser crypto operations may be slower than Node.js native implementations

## Supported Quote Types

- **SGX DCAP Quotes**: Version 3, 4, 5
- **TDX Quotes**: TD 1.0 and TD 1.5 reports
- **Attestation Key**: ECDSA-256 with P-256 curve

## Error Handling

The library throws descriptive errors for various failure scenarios:

```javascript
try {
    const result = verify(quoteBuffer, collateral, Date.now() / 1000);
    console.log('Verification successful:', result.status);
} catch (error) {
    if (error.message.includes('expired')) {
        console.error('TCB information or certificate expired');
    } else if (error.message.includes('signature')) {
        console.error('Signature verification failed');
    } else if (error.message.includes('revoked')) {
        console.error('Certificate has been revoked');
    } else {
        console.error('Verification error:', error.message);
    }
}
```

## Common TCB Status Values

- `"UpToDate"`: Platform is up-to-date, no known issues
- `"OutOfDate"`: Platform TCB is out of date, update recommended
- `"ConfigurationNeeded"`: Platform requires configuration changes
- `"ConfigurationAndSWHardeningNeeded"`: Platform needs both configuration and software updates
- `"SWHardeningNeeded"`: Software hardening updates needed
- `"OutOfDateConfigurationNeeded"`: Platform is out of date and needs configuration

## License

Apache-2.0

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`./run-tests.sh`)
- Code follows existing style conventions
- TypeScript types are updated if adding new APIs

## Support

For issues and questions:
- GitHub Issues: [https://github.com/Phala-Network/dcap-qvl](https://github.com/Phala-Network/dcap-qvl)
- Documentation: See inline JSDoc comments and TypeScript definitions
