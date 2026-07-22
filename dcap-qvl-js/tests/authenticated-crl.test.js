const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { verify } = require('../src');
const utils = require('../src/utils');
const { TRUSTED_ROOT_CA_DER } = require('../src/constants');

const SAMPLE = path.join(__dirname, '..', '..', 'sample');
const TDX_QUOTE = fs.readFileSync(path.join(SAMPLE, 'tdx_quote'));
const TDX_COLLATERAL = JSON.parse(
    fs.readFileSync(path.join(SAMPLE, 'tdx_quote_collateral.json'), 'utf8')
);

// Within all bundled certificate, CRL, TCB Info, and QE Identity windows.
const NOW_SECS = 1751000000; // 2025-06-27T03:06:40Z

// Both CRLs are signed by an attacker-owned EC key. The second one lists the
// bundled quote's real PCK serial. Neither chains to Intel.
const ATTACKER_EMPTY_PCK_CRL_HEX =
    '3081b93062020101300a06082a8648ce3d04030230223120301e06035504030c175046322041747461636b65722043524c20497373756572170d3235303632363030303030305a170d3235303732363030303030305aa00f300d300b0603551d14040402021000300a06082a8648ce3d040302034700304402204d4fcf9d42f6090bbf64f705f01b5c22caab765a37262006c997c179e47cd72c02205fc43408e1ae5e670502f47d0b49a8cd4d9d85a10c40e40b065dc96096d031ef';

const ATTACKER_REVOKING_PCK_CRL_HEX =
    '3081e530818b020101300a06082a8648ce3d04030230223120301e06035504030c175046322041747461636b65722043524c20497373756572170d3235303632363030303030305a170d3235303732363030303030305a3027302502143c16ed54eacbb4ced072be72630c85788cf46e36170d3235303632363030303030305aa00f300d300b0603551d14040402021001300a06082a8648ce3d0403020349003046022100a5d942878f70ea8a063859b4d08077c86acad770c8fd9272749ae1c4839e50ac02210092f3bd828f4300c55da3d763ad07caa04a93abd5ba51d5d6d63447d951066487';

function cloneCollateral() {
    return JSON.parse(JSON.stringify(TDX_COLLATERAL));
}

function verifyWithPckCrl(pckCrlHex) {
    const collateral = cloneCollateral();
    collateral.pck_crl = pckCrlHex;
    return verify(TDX_QUOTE, collateral, NOW_SECS);
}

test('bundled quote succeeds with authenticated, current Intel CRLs', () => {
    assert.equal(verify(TDX_QUOTE, TDX_COLLATERAL, NOW_SECS).status, 'UpToDate');
});

test('rejects an attacker-signed empty PCK CRL', () => {
    assert.throws(
        () => verifyWithPckCrl(ATTACKER_EMPTY_PCK_CRL_HEX),
        /CRL issuer does not match|CRL signature is invalid/,
    );
});

test('rejects an attacker-signed PCK CRL even when it lists the target serial', () => {
    assert.throws(
        () => verifyWithPckCrl(ATTACKER_REVOKING_PCK_CRL_HEX),
        /CRL issuer does not match|CRL signature is invalid/,
    );
});

test('rejects a corrupted PCK CRL signature', () => {
    const collateral = cloneCollateral();
    const crl = Buffer.from(collateral.pck_crl, 'hex');
    crl[crl.length - 1] ^= 0x01;
    collateral.pck_crl = crl.toString('hex');

    assert.throws(
        () => verify(TDX_QUOTE, collateral, NOW_SECS),
        /CRL signature is invalid/,
    );
});

test('rejects a corrupted root CA CRL signature', () => {
    const collateral = cloneCollateral();
    const crl = Buffer.from(collateral.root_ca_crl, 'hex');
    crl[crl.length - 1] ^= 0x01;
    collateral.root_ca_crl = crl.toString('hex');

    assert.throws(
        () => verify(TDX_QUOTE, collateral, NOW_SECS),
        /CRL signature is invalid/,
    );
});

test('rejects malformed PCK CRL data instead of failing open', () => {
    assert.throws(
        () => verifyWithPckCrl('00010203deadbeef'),
        /Failed to parse CRL/,
    );
});

test('requires and authenticates pck_crl_issuer_chain', () => {
    const collateral = cloneCollateral();
    collateral.pck_crl_issuer_chain = 'not a certificate chain';

    assert.throws(
        () => verify(TDX_QUOTE, collateral, NOW_SECS),
        /PCK CRL issuer chain is empty or malformed/,
    );
});

test('rejects a valid Intel chain that is not a PCK CRL issuer chain', () => {
    const collateral = cloneCollateral();
    collateral.pck_crl_issuer_chain = collateral.tcb_info_issuer_chain;

    assert.throws(
        () => verify(TDX_QUOTE, collateral, NOW_SECS),
        /CRL issuer certificate is not a CA|sign CRLs|CRL issuer does not match/,
    );
});

test('rejects a CRL before thisUpdate', () => {
    assert.throws(
        () => utils.validateCollateralCrls(
            TRUSTED_ROOT_CA_DER,
            TDX_COLLATERAL.pck_crl_issuer_chain,
            Buffer.from(TDX_COLLATERAL.root_ca_crl, 'hex'),
            Buffer.from(TDX_COLLATERAL.pck_crl, 'hex'),
            1750327234, // one second before the PCK CRL's thisUpdate
        ),
        /CRL is not yet valid/,
    );
});

test('rejects a CRL after nextUpdate', () => {
    assert.throws(
        () => utils.validateCollateralCrls(
            TRUSTED_ROOT_CA_DER,
            TDX_COLLATERAL.pck_crl_issuer_chain,
            Buffer.from(TDX_COLLATERAL.root_ca_crl, 'hex'),
            Buffer.from(TDX_COLLATERAL.pck_crl, 'hex'),
            1752919236, // one second after the PCK CRL's nextUpdate
        ),
        /CRL is expired/,
    );
});
