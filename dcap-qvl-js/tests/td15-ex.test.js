const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { Quote, verify } = require('../src');

const SAMPLE = path.join(__dirname, '..', '..', 'sample');
const QUOTE = fs.readFileSync(path.join(SAMPLE, 'tdx_quote_td15ex'));
const COLLATERAL = JSON.parse(
    fs.readFileSync(path.join(SAMPLE, 'tdx_quote_td15ex_collateral.json'), 'utf8')
);
const NOW_SECS = Date.parse('2026-10-08T02:45:00Z') / 1000;

test('quote v5 body type 4 (TD report 1.5ex) parses with Intel offsets', () => {
    const quote = Quote.parse(QUOTE);
    assert.equal(quote.report.type, 'td15ex');
    const ex = quote.report.asTd15Ex();
    assert.equal(QUOTE.readUInt16LE(48), 4);
    assert.equal(QUOTE.readUInt32LE(50), 885);
    assert.equal(QUOTE[54 + 648], ex.vmid);
    assert.deepEqual(Buffer.from(ex.tdId), QUOTE.subarray(54 + 649, 54 + 681));
    assert.equal(quote.report.asTd15(), ex.base);
    assert.equal(quote.report.asTd10(), ex.base.base);
    assert.equal(quote.signedLength(), 48 + 6 + 885);
});

test('real TD report 1.5ex quote verifies', () => {
    const result = verify(QUOTE, COLLATERAL, NOW_SECS);
    assert.equal(result.status, 'UpToDate');
    assert.equal(result.report.type, 'td15ex');
});

test('TD report 1.5ex extension fields are covered by the signature', () => {
    // td_id starts at body offset 649; the last 1.5ex field ends at 885.
    for (const offset of [54 + 649, 54 + 884]) {
        const tampered = Buffer.from(QUOTE);
        tampered[offset] ^= 1;
        assert.throws(() => verify(tampered, COLLATERAL, NOW_SECS), /signature is invalid/);
    }
});
