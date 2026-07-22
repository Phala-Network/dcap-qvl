const test = require('node:test');
const assert = require('node:assert/strict');

const utils = require('../src/utils');
const pki = require('./helpers/test-pki');

const NOW_SECS = 1751000000; // 2025-06-27T03:06:40Z
const NOT_BEFORE = new Date((NOW_SECS - 86400) * 1000);
const NOT_AFTER = new Date((NOW_SECS + 86400) * 1000);

const CA_USAGE = pki.KEY_USAGE.keyCertSign | pki.KEY_USAGE.cRLSign;

// Test PKI:
//   root (trust anchor, no pathLenConstraint)
//     -> intA (CA, pathLenConstraint = 0)
//       -> intB (CA) -> leaf   [invalid: intA's pathLen forbids intB]
//       -> leaf                [valid]
const rootKeys = pki.generateKeyPair();
const intAKeys = pki.generateKeyPair();
const intBKeys = pki.generateKeyPair();
const leafKeys = pki.generateKeyPair();

const root = { cn: 'Test Root CA', key: rootKeys.privateKey };
const intA = { cn: 'Test Intermediate A', key: intAKeys.privateKey };
const intB = { cn: 'Test Intermediate B', key: intBKeys.privateKey };

const common = { notBefore: NOT_BEFORE, notAfter: NOT_AFTER };

const rootCert = pki.issueCertificate({
    subjectCN: root.cn,
    issuer: root,
    publicKey: rootKeys.publicKey,
    serialNumber: [0x01],
    isCa: true,
    keyUsageFlags: CA_USAGE,
    ...common,
});
const intACert = pki.issueCertificate({
    subjectCN: intA.cn,
    issuer: root,
    publicKey: intAKeys.publicKey,
    serialNumber: [0x02],
    isCa: true,
    pathLenConstraint: 0,
    keyUsageFlags: CA_USAGE,
    ...common,
});
const intBCert = pki.issueCertificate({
    subjectCN: intB.cn,
    issuer: intA,
    publicKey: intBKeys.publicKey,
    serialNumber: [0x03],
    isCa: true,
    keyUsageFlags: CA_USAGE,
    ...common,
});

function makeLeaf(issuer, serialNumber, overrides = {}) {
    return pki.issueCertificate({
        subjectCN: 'Test Leaf',
        issuer,
        publicKey: leafKeys.publicKey,
        serialNumber,
        isCa: false,
        keyUsageFlags: pki.KEY_USAGE.digitalSignature,
        ...common,
        ...overrides,
    });
}

function makeCrls({ intARevokedSerials = [] } = {}) {
    const window = { thisUpdate: NOT_BEFORE, nextUpdate: NOT_AFTER };
    return [
        pki.issueCrl({ issuer: root, ...window }),
        pki.issueCrl({ issuer: intA, revokedSerials: intARevokedSerials, ...window }),
        pki.issueCrl({ issuer: intB, ...window }),
    ];
}

test('control: synthetic chain within pathLenConstraint verifies', () => {
    const leaf = makeLeaf(intA, [0x10]);
    assert.equal(
        utils.verifyCertificateChain(leaf, [intACert, rootCert], NOW_SECS, makeCrls(), rootCert),
        true,
    );
});

test('rejects a chain violating an intermediate pathLenConstraint', () => {
    const leaf = makeLeaf(intB, [0x11]);
    assert.throws(
        () => utils.verifyCertificateChain(
            leaf, [intBCert, intACert, rootCert], NOW_SECS, makeCrls(), rootCert),
        /path length constraint violated/,
    );
});

test('rejects a certificate whose tbs signature algorithm mismatches the outer one', () => {
    const leaf = makeLeaf(intA, [0x12], {
        tbsSignatureAlgorithmOid: pki.ECDSA_WITH_SHA384,
    });
    assert.throws(
        () => utils.verifyCertificateChain(
            leaf, [intACert, rootCert], NOW_SECS, makeCrls(), rootCert),
        /Certificate signature algorithm mismatch/,
    );
});

test('a negative revoked serial does not match a positive certificate serial', () => {
    // Certificate serial 255 is DER-encoded as 0x00FF; the CRL lists 0xFF,
    // which is the DER INTEGER -1. Stripping the padding byte without keeping
    // the sign would make these compare equal and falsely revoke the leaf.
    const leaf = makeLeaf(intA, [0x00, 0xff]);
    const crls = makeCrls({ intARevokedSerials: [[0xff]] });
    assert.equal(
        utils.verifyCertificateChain(leaf, [intACert, rootCert], NOW_SECS, crls, rootCert),
        true,
    );
});

test('a matching positive revoked serial still revokes the certificate', () => {
    const leaf = makeLeaf(intA, [0x00, 0xff]);
    const crls = makeCrls({ intARevokedSerials: [[0x00, 0xff]] });
    assert.throws(
        () => utils.verifyCertificateChain(leaf, [intACert, rootCert], NOW_SECS, crls, rootCert),
        /Certificate is revoked/,
    );
});
