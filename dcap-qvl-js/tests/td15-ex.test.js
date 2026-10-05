const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { Quote } = require('../src');

const TDX_QUOTE = fs.readFileSync(path.join(__dirname, '..', '..', 'sample', 'tdx_quote'));

// Builds a quote v5 with a TD report 1.5ex body (body type 4) from the sample v4 TDX quote: its
// header (version set to 5), its TD 1.0 report, zeroed TD 1.5 fields, distinctive 1.5ex fields, and
// its auth data. No real 1.5ex quote is public yet (upstream KVM does not enable TD ID reporting), so
// this checks the layout against the offsets in Intel's sgx_quote_5.h, not a signature.
function syntheticTd15ExQuote() {
    const header = Buffer.from(TDX_QUOTE.subarray(0, 48));
    header.writeUInt16LE(5, 0);
    const td10 = TDX_QUOTE.subarray(48, 48 + 584);
    const rest = TDX_QUOTE.subarray(48 + 584);
    const body = Buffer.alloc(6);
    body.writeUInt16LE(4, 0);
    body.writeUInt32LE(885, 2);
    const tdId = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xa0 ^ i));
    const ext = Buffer.concat([
        Buffer.from([2]), // vmid
        tdId,
        Buffer.alloc(48, 0xd1), // devinfo
        Buffer.alloc(48, 0x11), Buffer.alloc(8, 0x12), Buffer.alloc(16, 0x13),
        Buffer.alloc(16, 0x14), Buffer.alloc(12, 0x15), Buffer.alloc(48, 0x16), Buffer.alloc(8, 0x17),
    ]);
    const td15Fields = Buffer.alloc(16 + 48);
    return { bytes: Buffer.concat([header, body, td10, td15Fields, ext, rest]), tdId };
}

test('quote v5 body type 4 (TD report 1.5ex) parses with Intel offsets', () => {
    const { bytes, tdId } = syntheticTd15ExQuote();
    assert.equal(bytes.readUInt16LE(48), 4);
    assert.equal(bytes.readUInt32LE(50), 885);
    assert.deepEqual(bytes.subarray(54 + 649, 54 + 681), tdId);

    const quote = Quote.parse(bytes);
    assert.equal(quote.report.type, 'td15ex');
    const ex = quote.report.asTd15Ex();
    assert.equal(ex.vmid, 2);
    assert.deepEqual(Buffer.from(ex.tdId), tdId);
    assert.deepEqual(Buffer.from(ex.devInfo), Buffer.alloc(48, 0xd1));
    assert.deepEqual(Buffer.from(ex.curServiceTdAttributes), Buffer.alloc(8, 0x17));
    assert.equal(quote.report.asTd15(), ex.base);
    assert.equal(quote.report.asTd10(), ex.base.base);
    assert.deepEqual(Buffer.from(ex.base.base.mrTd), TDX_QUOTE.subarray(48 + 136, 48 + 184));
    assert.equal(quote.signedLength(), 48 + 6 + 885);
});
