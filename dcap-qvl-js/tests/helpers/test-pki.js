'use strict';

// Test-only mini PKI: builds EC P-256 X.509 certificates and CRLs with
// @peculiar/asn1-x509 and signs them with node:crypto. Used to exercise
// negative paths (pathLenConstraint, signature-algorithm binding, serial
// sign handling) that cannot be reached with the bundled Intel collateral.

const crypto = require('node:crypto');
const { Buffer } = require('node:buffer');
const { AsnParser, AsnSerializer, OctetString } = require('@peculiar/asn1-schema');
const x509 = require('@peculiar/asn1-x509');

const ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
const ECDSA_WITH_SHA384 = '1.2.840.10045.4.3.3';

const KEY_USAGE = x509.KeyUsageFlags;

function generateKeyPair() {
    return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

function commonName(value) {
    return new x509.Name([
        new x509.RelativeDistinguishedName([
            new x509.AttributeTypeAndValue({
                type: '2.5.4.3', // id-at-commonName
                value: new x509.AttributeValue({ printableString: value }),
            }),
        ]),
    ]);
}

function makeExtension(extnID, critical, value) {
    return new x509.Extension({
        extnID,
        critical,
        extnValue: new OctetString(AsnSerializer.serialize(value)),
    });
}

function algorithm(oid) {
    return new x509.AlgorithmIdentifier({ algorithm: oid });
}

function toArrayBuffer(bytes) {
    return new Uint8Array(bytes).buffer;
}

function signDer(privateKey, tbsDer) {
    return crypto.sign('sha256', Buffer.from(tbsDer), { key: privateKey, dsaEncoding: 'der' });
}

// Issue a certificate. `issuer` is `{ cn, key }`; `subject` is a CN string.
function issueCertificate({
    subjectCN,
    issuer,
    publicKey,
    serialNumber,
    isCa = false,
    pathLenConstraint,
    keyUsageFlags,
    notBefore,
    notAfter,
    tbsSignatureAlgorithmOid = ECDSA_WITH_SHA256,
}) {
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const spki = AsnParser.parse(spkiDer, x509.SubjectPublicKeyInfo);

    const basicConstraints = new x509.BasicConstraints({ cA: isCa });
    if (pathLenConstraint !== undefined) {
        basicConstraints.pathLenConstraint = pathLenConstraint;
    }
    const extensions = new x509.Extensions([
        makeExtension(x509.id_ce_basicConstraints, true, basicConstraints),
    ]);
    if (keyUsageFlags !== undefined) {
        extensions.push(makeExtension(x509.id_ce_keyUsage, true, new x509.KeyUsage(keyUsageFlags)));
    }

    const tbs = new x509.TBSCertificate({
        version: x509.Version.v3,
        serialNumber: toArrayBuffer(serialNumber),
        signature: algorithm(tbsSignatureAlgorithmOid),
        issuer: commonName(issuer.cn),
        validity: new x509.Validity({ notBefore, notAfter }),
        subject: commonName(subjectCN),
        subjectPublicKeyInfo: spki,
        extensions,
    });

    const signature = signDer(issuer.key, AsnSerializer.serialize(tbs));
    const certificate = new x509.Certificate({
        tbsCertificate: tbs,
        signatureAlgorithm: algorithm(ECDSA_WITH_SHA256),
        signatureValue: toArrayBuffer(signature),
    });
    return Buffer.from(AsnSerializer.serialize(certificate));
}

// Issue a v2 CRL signed by `issuer` (`{ cn, key }`). `revokedSerials` is an
// array of DER INTEGER content byte arrays.
function issueCrl({ issuer, revokedSerials = [], thisUpdate, nextUpdate }) {
    const tbs = new x509.TBSCertList({
        version: 1, // v2
        signature: algorithm(ECDSA_WITH_SHA256),
        issuer: commonName(issuer.cn),
        thisUpdate: new x509.Time(thisUpdate),
        nextUpdate: new x509.Time(nextUpdate),
    });
    if (revokedSerials.length > 0) {
        tbs.revokedCertificates = revokedSerials.map(serial => new x509.RevokedCertificate({
            userCertificate: toArrayBuffer(serial),
            revocationDate: new x509.Time(thisUpdate),
        }));
    }

    const signature = signDer(issuer.key, AsnSerializer.serialize(tbs));
    const crl = new x509.CertificateList({
        tbsCertList: tbs,
        signatureAlgorithm: algorithm(ECDSA_WITH_SHA256),
        signature: toArrayBuffer(signature),
    });
    return Buffer.from(AsnSerializer.serialize(crl));
}

module.exports = {
    ECDSA_WITH_SHA256,
    ECDSA_WITH_SHA384,
    KEY_USAGE,
    generateKeyPair,
    issueCertificate,
    issueCrl,
};
