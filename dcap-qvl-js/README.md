# dcap-qvl-js

Pure JavaScript implementation of DCAP Quote Verification Library.

## Description

`dcap-qvl-js` provides a pure JavaScript implementation for verifying Intel SGX DCAP (Data Center Attestation Primitives) quotes. It allows you to parse quotes, fetch collateral (PCK certificates, TCB info, QE identity), and verify the quote's validity and TCB status.

## Installation

```bash
npm install @phala/dcap-qvl
```

## Usage

### Verifying a Quote

To verify a quote, you need the raw quote bytes and the associated collateral.

```javascript
import { verify, getCollateral } from '@phala/dcap-qvl';

async function verifyQuote(quoteBuffer) {
    // 1. Get Collateral (requires PCCS URL)
    const pccsUrl = 'https://your-pccs-server.com/sgx/certification/v4/';
    const collateral = await getCollateral(pccsUrl, quoteBuffer);

    // 2. Verify the quote
    // The verify function returns a VerifiedReport object
    const currentTimestamp = Date.now() / 1000; // Current time in seconds
    const result = verify(quoteBuffer, collateral, currentTimestamp);

    console.log('Verification Result:', result);
    console.log('TCB Status:', result.status);
}
```

### Parsing a Quote

You can also just parse the quote structure without full verification.

```javascript
import { Quote } from '@phala/dcap-qvl';

const quote = Quote.parse(quoteBuffer);
console.log('Quote Header:', quote.header);
console.log('Report Body:', quote.report);
```

## Features

- **Pure JavaScript**: No native dependencies, easy to run in Node.js environments.
- **Quote Parsing**: Parse and inspect SGX DCAP quotes.
- **Collateral Retrieval**: Helper functions to fetch necessary collateral from a PCCS.
- **Verification**: Full verification logic including signature checks and TCB level comparison.

## License

Apache-2.0
