const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { Quote } = require('../src');
const utils = require('../src/utils');
const intel = require('../src/intel');

const SAMPLE = path.join(__dirname, '..', '..', 'sample');
const SGX_QUOTE = fs.readFileSync(path.join(SAMPLE, 'sgx_quote'));
const TDX_QUOTE = fs.readFileSync(path.join(SAMPLE, 'tdx_quote'));

test('intel.getCa returns "processor" for a Processor-signed quote', () => {
    assert.equal(intel.getCa(Quote.parse(SGX_QUOTE)), 'processor');
});

test('intel.getCa returns "platform" for a Platform-signed quote', () => {
    assert.equal(intel.getCa(Quote.parse(TDX_QUOTE)), 'platform');
});

test('utils.getCertIssuer surfaces the actual CA common name', () => {
    const procLeaf = utils.extractCerts(Quote.parse(SGX_QUOTE).rawCertChain())[0];
    const platLeaf = utils.extractCerts(Quote.parse(TDX_QUOTE).rawCertChain())[0];
    assert.match(utils.getCertIssuer(procLeaf), /Intel SGX PCK Processor CA/);
    assert.match(utils.getCertIssuer(platLeaf), /Intel SGX PCK Platform CA/);
});

test('utils.getCertIssuer throws on invalid DER', () => {
    assert.throws(() => utils.getCertIssuer(Buffer.from([0x00, 0x01])));
});
