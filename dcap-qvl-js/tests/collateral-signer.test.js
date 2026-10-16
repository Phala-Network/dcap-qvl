const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { verify } = require('../src');

const SAMPLE = path.join(__dirname, '..', '..', 'sample');
const QUOTE = fs.readFileSync(path.join(SAMPLE, 'tdx_quote'));
const COLLATERAL = JSON.parse(
    fs.readFileSync(path.join(SAMPLE, 'tdx_quote_collateral.json'), 'utf8')
);
const NOW_SECS = 1751000000; // 2025-06-27T03:06:40Z
const PCK_CHAIN = QUOTE.toString('latin1').match(
    /-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----/
)[0];

test('PCK chain is rejected as the collateral signer', () => {
    for (const [field, what] of [
        ['tcb_info_issuer_chain', 'TCB Info'],
        ['qe_identity_issuer_chain', 'QE Identity'],
    ]) {
        const forged = { ...COLLATERAL, [field]: PCK_CHAIN };
        assert.throws(() => verify(QUOTE, forged, NOW_SECS), new RegExp(`${what} signer`));
    }
});
