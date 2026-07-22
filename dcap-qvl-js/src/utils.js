// Utility functions for certificate and DER handling
// Converted from utils.rs

const crypto = require('./crypto-compat');
const { Buffer } = require('buffer');
const asn1 = require('asn1.js');
const BN = require('bn.js');
const { AsnParser, AsnSerializer } = require('@peculiar/asn1-schema');
const {
    BasicConstraints,
    Certificate: X509CertificateSchema,
    CertificateList: X509CertificateListSchema,
    KeyUsage,
} = require('@peculiar/asn1-x509');
const oids = require('./oids');

// Helper function to compare OID array with OID string
function oidEquals(oidArray, oidString) {
    if (!Array.isArray(oidArray) || typeof oidString !== 'string') {
        return false;
    }
    const expectedArray = oidString.split('.').map(Number);
    if (oidArray.length !== expectedArray.length) {
        return false;
    }
    return oidArray.every((val, idx) => val === expectedArray[idx]);
}

// ASN.1 Schema Definitions (need to be defined outside functions to avoid recursion issues)
const Extension = asn1.define('Extension', function () {
    this.seq().obj(
        this.key('extnID').objid(),
        this.key('critical').bool().optional().def(false),
        this.key('extnValue').octstr()
    );
});

const DirectoryString = asn1.define('DirectoryString', function () {
    this.choice({
        utf8String: this.utf8str(),
        printableString: this.printstr(),
        ia5String: this.ia5str(),
        teletexString: this.t61str(),
        universalString: this.unistr(),
        bmpString: this.bmpstr()
    });
});

const AttributeTypeAndValue = asn1.define('AttributeTypeAndValue', function () {
    this.seq().obj(
        this.key('type').objid(),
        this.key('value').use(DirectoryString)
    );
});

const RelativeDistinguishedName = asn1.define('RelativeDistinguishedName', function () {
    this.setof(AttributeTypeAndValue);
});

const Name = asn1.define('Name', function () {
    this.seqof(RelativeDistinguishedName);
});

const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').optional().any()
    );
});

const Time = asn1.define('Time', function () {
    this.choice({
        utcTime: this.utctime(),
        generalTime: this.gentime(),
    });
});

const TBSCertificate = asn1.define('TBSCertificate', function () {
    this.seq().obj(
        this.key('version').explicit(0).int().optional(),
        this.key('serialNumber').int(),
        this.key('signature').seq().obj(
            this.key('algorithm').objid(),
            this.key('parameters').optional().any()
        ),
        this.key('issuer').use(Name),
        this.key('validity').any(),
        this.key('subject').use(Name),
        this.key('subjectPublicKeyInfo').any(),
        this.key('issuerUniqueID').implicit(1).bitstr().optional(),
        this.key('subjectUniqueID').implicit(2).bitstr().optional(),
        this.key('extensions').explicit(3).seqof(Extension).optional()
    );
});

const Certificate = asn1.define('Certificate', function () {
    this.seq().obj(
        this.key('tbsCertificate').use(TBSCertificate),
        this.key('signatureAlgorithm').any(),
        this.key('signatureValue').bitstr()
    );
});

const RevokedCertificate = asn1.define('RevokedCertificate', function () {
    this.seq().obj(
        this.key('userCertificate').int(),
        this.key('revocationDate').use(Time),
        this.key('crlEntryExtensions').seqof(Extension).optional()
    );
});

const TBSCertList = asn1.define('TBSCertList', function () {
    this.seq().obj(
        this.key('version').int().optional(),
        this.key('signature').use(AlgorithmIdentifier),
        this.key('issuer').use(Name),
        this.key('thisUpdate').use(Time),
        this.key('nextUpdate').use(Time).optional(),
        this.key('revokedCertificates').seqof(RevokedCertificate).optional(),
        this.key('crlExtensions').explicit(0).seqof(Extension).optional()
    );
});

const CertificateList = asn1.define('CertificateList', function () {
    this.seq().obj(
        this.key('tbsCertList').use(TBSCertList),
        this.key('signatureAlgorithm').use(AlgorithmIdentifier),
        this.key('signature').bitstr()
    );
});

// Extract PEM certificates and return raw DER bytes
function extractRawCerts(certChain) {
    if (typeof certChain === 'string') {
        certChain = Buffer.from(certChain, 'utf-8');
    } else if (certChain instanceof Uint8Array) {
        certChain = Buffer.from(certChain);
    }

    const certs = [];
    const pemRegex = /-----BEGIN CERTIFICATE-----\r?\n?([A-Za-z0-9+\/=\r\n]+)\r?\n?-----END CERTIFICATE-----/g;
    let match;

    while ((match = pemRegex.exec(certChain.toString('utf-8'))) !== null) {
        const base64Cert = match[1].replace(/\r?\n/g, '');
        const derCert = Buffer.from(base64Cert, 'base64');
        certs.push(derCert);
    }

    // Rust implementation returns empty vector if no certs found, it doesn't error here
    // The caller checks the length and errors if needed

    return certs;
}

function extractCerts(certChain) {
    return extractRawCerts(certChain);
}

// Get Intel SGX extension from certificate
function getIntelExtension(derEncoded) {
    const cert = Certificate.decode(derEncoded, 'der');

    if (!cert.tbsCertificate.extensions) {
        throw new Error('Intel extension not found');
    }

    const sgxExtensions = cert.tbsCertificate.extensions.filter(ext =>
        oidEquals(ext.extnID, oids.SGX_EXTENSION)
    );

    if (sgxExtensions.length === 0) {
        throw new Error('Intel extension not found');
    }

    if (sgxExtensions.length > 1) {
        throw new Error('Intel extension ambiguity');
    }

    return sgxExtensions[0].extnValue;
}

// DER object navigation for finding OID values
function findExtension(path, raw) {
    const Sequence = asn1.define('Sequence', function () {
        this.seqof(asn1.define('Item', function () {
            this.seq().obj(
                this.key('oid').objid(),
                this.key('value').any()
            );
        }));
    });

    let currentValue = raw;

    for (const oid of path) {
        const seq = Sequence.decode(currentValue, 'der');
        const found = seq.find(item => oidEquals(item.oid, oid));

        if (!found) {
            throw new Error(`OID ${oid} is missing`);
        }

        currentValue = found.value;
    }

    // Try to decode as octet string
    const OctetString = asn1.define('OctetString', function () {
        this.octstr();
    });

    try {
        return OctetString.decode(currentValue, 'der');
    } catch (e) {
        // Return raw value if not an octet string
        if (Buffer.isBuffer(currentValue)) {
            return currentValue;
        }
        // If it's still encoded, try to extract raw bytes
        return Buffer.from(currentValue);
    }
}

function getFmspc(extensionSection) {
    const data = findExtension([oids.FMSPC], extensionSection);
    if (data.length !== 6) {
        throw new Error('Fmspc length mismatch');
    }
    return data;
}

function getCpuSvn(extensionSection) {
    const data = findExtension([oids.TCB, oids.CPUSVN], extensionSection);
    if (data.length !== 16) {
        throw new Error('CpuSvn length mismatch');
    }
    return data;
}

function getPceSvn(extensionSection) {
    let data = findExtension([oids.TCB, oids.PCESVN], extensionSection);

    // findExtension returns the full DER-encoded value (including tag and length)
    // We need to decode it to get the actual value bytes
    // Check if it's a DER INTEGER (tag 0x02)
    if (data.length >= 2 && data[0] === 0x02) {
        const length = data[1];
        data = data.slice(2, 2 + length);
    }

    if (data.length === 1) {
        return data[0];
    } else if (data.length === 2) {
        return (data[0] << 8) | data[1];
    } else {
        throw new Error('PceSvn length mismatch');
    }
}

// Encode 64-byte value (ECDSA signature or public key) as DER
function encodeAsDer(data) {
    // Convert to Buffer if needed
    const buf = Buffer.from(data);

    if (buf.length !== 64) {
        throw new Error(`Key length is invalid: expected 64, got ${buf.length}`);
    }

    // Convert to ASN.1 SEQUENCE of two INTEGERs
    const DerSignature = asn1.define('DerSignature', function () {
        this.seq().obj(
            this.key('r').int(),
            this.key('s').int()
        );
    });

    const rBN = new BN(buf.slice(0, 32));
    const sBN = new BN(buf.slice(32, 64));

    return DerSignature.encode({
        r: rBN,
        s: sBN
    }, 'der');
}

// Convert DER to PEM
function derToPem(der, label) {
    const base64 = Buffer.from(der).toString('base64');
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

const CRL_SIGNATURE_HASHES = Object.freeze({
    // ecdsa-with-SHA224 / SHA256 / SHA384 / SHA512
    '1.2.840.10045.4.3.1': 'sha224',
    '1.2.840.10045.4.3.2': 'sha256',
    '1.2.840.10045.4.3.3': 'sha384',
    '1.2.840.10045.4.3.4': 'sha512',
});

function toStrictDerBuffer(value, label) {
    let der;
    try {
        der = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value);
    } catch (e) {
        throw new Error(`Invalid ${label}`, { cause: e });
    }
    if (der.length === 0) {
        throw new Error(`Invalid ${label}: empty input`);
    }
    return der;
}

function parseCertificateStrict(certDer) {
    const der = toStrictDerBuffer(certDer, 'certificate');
    let certificate;
    try {
        certificate = AsnParser.parse(der, X509CertificateSchema);
    } catch (e) {
        throw new Error('Failed to parse certificate', { cause: e });
    }

    // AsnParser accepts trailing bytes. Re-encoding also rejects non-DER input,
    // which is important because signatures cover the exact DER value.
    const canonical = Buffer.from(AsnSerializer.serialize(certificate));
    if (!canonical.equals(der)) {
        throw new Error('Failed to parse certificate: non-canonical or trailing DER data');
    }

    // RFC 5280 4.1.1.2/4.1.2.3: the outer signatureAlgorithm must match the
    // signed tbsCertificate.signature. Mirrors the equivalent CRL check.
    if (!certificate.tbsCertificate.signature.isEqual(certificate.signatureAlgorithm)) {
        throw new Error('Certificate signature algorithm mismatch');
    }
    return { der, certificate };
}

function serializeName(name) {
    return Buffer.from(AsnSerializer.serialize(name));
}

function serialBytes(serial) {
    let bytes = Buffer.from(serial);
    // DER INTEGERs are signed. Record the sign before stripping the positive
    // padding byte so a negative serial (invalid per RFC 5280 but encodable,
    // e.g. 0xFF = -1) can never compare equal to a positive one (0x00FF = 255).
    const signByte = bytes.length > 0 && (bytes[0] & 0x80) !== 0 ? 0x01 : 0x00;
    while (bytes.length > 1 && bytes[0] === 0) {
        bytes = bytes.subarray(1);
    }
    return Buffer.concat([Buffer.from([signByte]), bytes]);
}

function validateNow(timeSecs) {
    if (typeof timeSecs !== 'number' || !Number.isFinite(timeSecs) || timeSecs < 0) {
        throw new Error('Invalid verification time');
    }
    return timeSecs * 1000;
}

function validateCertificateTime(parsedCert, timeSecs) {
    const nowMs = validateNow(timeSecs);
    const validity = parsedCert.certificate.tbsCertificate.validity;
    const notBeforeMs = validity.notBefore.getTime().getTime();
    const notAfterMs = validity.notAfter.getTime().getTime();
    if (!Number.isFinite(notBeforeMs) || !Number.isFinite(notAfterMs)) {
        throw new Error('Certificate has an invalid validity window');
    }
    if (nowMs < notBeforeMs || nowMs > notAfterMs) {
        throw new Error('Certificate is expired or not yet valid');
    }
}

function extensionValue(parsedCert, oid) {
    const extensions = parsedCert.certificate.tbsCertificate.extensions || [];
    return extensions.find(extension => extension.extnID === oid);
}

function certificateBasicConstraints(parsedCert) {
    const extension = extensionValue(parsedCert, '2.5.29.19');
    if (!extension) {
        return undefined;
    }
    try {
        return AsnParser.parse(extension.extnValue, BasicConstraints);
    } catch (e) {
        throw new Error('Certificate has invalid basic constraints', { cause: e });
    }
}

function certificateIsCa(parsedCert) {
    const constraints = certificateBasicConstraints(parsedCert);
    return constraints !== undefined && constraints.cA === true;
}

function certificateIsSelfIssued(parsedCert) {
    const tbs = parsedCert.certificate.tbsCertificate;
    return serializeName(tbs.subject).equals(serializeName(tbs.issuer));
}

function requireKeyUsage(parsedCert, flag, description) {
    const extension = extensionValue(parsedCert, '2.5.29.15');
    // RFC 5280 only constrains use when keyUsage is present.
    if (!extension) {
        return;
    }
    let keyUsage;
    try {
        keyUsage = AsnParser.parse(extension.extnValue, KeyUsage).toNumber();
    } catch (e) {
        throw new Error('Certificate has invalid key usage', { cause: e });
    }
    if ((keyUsage & flag) === 0) {
        throw new Error(`Certificate is not allowed to ${description}`);
    }
}

function parseCrl(crlDer) {
    const der = toStrictDerBuffer(crlDer, 'CRL');
    let crl;
    try {
        crl = AsnParser.parse(der, X509CertificateListSchema);
    } catch (e) {
        throw new Error('Failed to parse CRL', { cause: e });
    }

    const canonical = Buffer.from(AsnSerializer.serialize(crl));
    if (!canonical.equals(der)) {
        throw new Error('Failed to parse CRL: non-canonical or trailing DER data');
    }

    if (!crl.tbsCertList.nextUpdate) {
        throw new Error('CRL is missing nextUpdate');
    }
    if (crl.tbsCertList.version !== undefined && crl.tbsCertList.version !== 1) {
        throw new Error('Unsupported CRL version');
    }
    const hasExtensions = (crl.tbsCertList.crlExtensions || []).length > 0 ||
        (crl.tbsCertList.revokedCertificates || []).some(
            revoked => (revoked.crlEntryExtensions || []).length > 0,
        );
    if (hasExtensions && crl.tbsCertList.version !== 1) {
        throw new Error('CRL extensions require a version 2 CRL');
    }
    if (!crl.tbsCertList.signature.isEqual(crl.signatureAlgorithm)) {
        throw new Error('CRL signature algorithm mismatch');
    }

    // We do not implement delta or indirect CRLs. Reject critical extensions
    // instead of silently applying incomplete revocation semantics.
    for (const extension of crl.tbsCertList.crlExtensions || []) {
        if (extension.critical) {
            throw new Error(`Unsupported critical CRL extension: ${extension.extnID}`);
        }
    }
    for (const revoked of crl.tbsCertList.revokedCertificates || []) {
        for (const extension of revoked.crlEntryExtensions || []) {
            if (extension.critical) {
                throw new Error(`Unsupported critical CRL entry extension: ${extension.extnID}`);
            }
        }
    }

    return {
        der,
        crl,
        issuerName: serializeName(crl.tbsCertList.issuer),
        tbsDer: Buffer.from(crl.tbsCertListRaw),
    };
}

function crlInputDer(crl) {
    return crl && crl.der ? crl.der : crl;
}

function normalizeCrls(crls) {
    if (!Array.isArray(crls) || crls.length === 0) {
        throw new Error('CRLs are required');
    }
    // Always parse from the signed DER. Do not trust a caller-supplied decoded
    // object whose revokedCertificates could differ from its signed tbsDer.
    return crls.map(crl => parseCrl(crlInputDer(crl)));
}

function validateCrlTime(parsedCrl, timeSecs) {
    const nowMs = validateNow(timeSecs);
    const thisUpdateMs = parsedCrl.crl.tbsCertList.thisUpdate.getTime().getTime();
    const nextUpdateMs = parsedCrl.crl.tbsCertList.nextUpdate.getTime().getTime();
    if (!Number.isFinite(thisUpdateMs) || !Number.isFinite(nextUpdateMs) ||
        nextUpdateMs < thisUpdateMs) {
        throw new Error('CRL has an invalid validity window');
    }
    if (nowMs < thisUpdateMs) {
        throw new Error('CRL is not yet valid');
    }
    if (nowMs > nextUpdateMs) {
        throw new Error('CRL is expired');
    }
}

function verifyCrl(parsedCrlOrDer, issuerCertDer, timeSecs) {
    const parsedCrl = parseCrl(crlInputDer(parsedCrlOrDer));
    const issuer = parseCertificateStrict(issuerCertDer);

    if (!certificateIsCa(issuer)) {
        throw new Error('CRL issuer is not a CA certificate');
    }
    // KeyUsageFlags.cRLSign = 64.
    requireKeyUsage(issuer, 64, 'sign CRLs');

    const issuerSubject = serializeName(issuer.certificate.tbsCertificate.subject);
    if (!parsedCrl.issuerName.equals(issuerSubject)) {
        throw new Error('CRL issuer does not match the expected issuer certificate');
    }

    validateCrlTime(parsedCrl, timeSecs);

    const algorithm = parsedCrl.crl.signatureAlgorithm.algorithm;
    const hash = CRL_SIGNATURE_HASHES[algorithm];
    if (!hash) {
        throw new Error(`Unsupported CRL signature algorithm: ${algorithm}`);
    }

    const issuerX509 = new crypto.X509Certificate(derToPem(issuer.der, 'CERTIFICATE'));
    const verifier = crypto.createVerify(hash);
    verifier.update(parsedCrl.tbsDer);
    if (!verifier.verify(issuerX509.publicKey, Buffer.from(parsedCrl.crl.signature))) {
        throw new Error('CRL signature is invalid');
    }

    return parsedCrl;
}

function checkCertificateRevocation(certDer, issuerCertDer, parsedCrls, timeSecs) {
    const cert = parseCertificateStrict(certDer);
    const certIssuer = serializeName(cert.certificate.tbsCertificate.issuer);
    const matchingCrls = parsedCrls.filter(crl => crl.issuerName.equals(certIssuer));
    if (matchingCrls.length === 0) {
        throw new Error('Certificate revocation status is unknown');
    }

    const certSerial = serialBytes(cert.certificate.tbsCertificate.serialNumber);
    for (const crl of matchingCrls) {
        const verifiedCrl = verifyCrl(crl, issuerCertDer, timeSecs);
        for (const revoked of verifiedCrl.crl.tbsCertList.revokedCertificates || []) {
            if (certSerial.equals(serialBytes(revoked.userCertificate))) {
                throw new Error('Certificate is revoked');
            }
        }
    }
}

function verifyCertificatePath(
    leafCertDer,
    intermediateCertsDer,
    timeSecs,
    parsedCrls,
    trustAnchorDer,
    leafMustBeCa,
) {
    const trustAnchor = parseCertificateStrict(trustAnchorDer);
    const path = [leafCertDer, ...intermediateCertsDer].map(parseCertificateStrict);
    if (path.length === 0) {
        throw new Error('Certificate chain is empty');
    }

    if (leafMustBeCa) {
        if (!certificateIsCa(path[0])) {
            throw new Error('CRL issuer certificate is not a CA');
        }
    } else if (certificateIsCa(path[0])) {
        throw new Error('CaUsedAsEndEntity');
    }

    for (let i = 0; i < path.length; i++) {
        const current = path[i];
        const isExplicitTrustAnchor = current.der.equals(trustAnchor.der);
        if (isExplicitTrustAnchor) {
            if (i !== path.length - 1) {
                throw new Error('Certificate chain continues after the trust anchor');
            }
            continue;
        }

        const issuer = i + 1 < path.length ? path[i + 1] : trustAnchor;
        if (i > 0 && !certificateIsCa(current)) {
            throw new Error('Non-CA certificate used as an intermediate');
        }
        if (i > 0) {
            // KeyUsageFlags.keyCertSign = 32.
            requireKeyUsage(current, 32, 'sign certificates');

            // RFC 5280 4.2.1.9: pathLenConstraint bounds the number of
            // non-self-issued intermediate certificates that may follow this
            // certificate in the path (the end entity is not counted).
            const constraints = certificateBasicConstraints(current);
            if (constraints && constraints.pathLenConstraint !== undefined) {
                const followingIntermediates = path
                    .slice(1, i)
                    .filter(cert => !certificateIsSelfIssued(cert))
                    .length;
                if (followingIntermediates > constraints.pathLenConstraint) {
                    throw new Error('Certificate path length constraint violated');
                }
            }
        }

        const currentIssuer = serializeName(current.certificate.tbsCertificate.issuer);
        const issuerSubject = serializeName(issuer.certificate.tbsCertificate.subject);
        if (!currentIssuer.equals(issuerSubject)) {
            throw new Error('Failed to verify certificate chain - issuer name mismatch');
        }

        const currentX509 = new crypto.X509Certificate(derToPem(current.der, 'CERTIFICATE'));
        const issuerX509 = new crypto.X509Certificate(derToPem(issuer.der, 'CERTIFICATE'));
        if (!currentX509.verify(issuerX509.publicKey)) {
            throw new Error('Failed to verify certificate chain - signature invalid');
        }

        validateCertificateTime(current, timeSecs);
        checkCertificateRevocation(current.der, issuer.der, parsedCrls, timeSecs);
    }

    return true;
}

// Verify a certificate path and require authenticated, current revocation
// status for every non-trust-anchor certificate in the path.
function verifyCertificateChain(leafCertDer, intermediateCertsDer, timeSecs, crlDers, trustAnchorDer) {
    const parsedCrls = normalizeCrls(crlDers);
    return verifyCertificatePath(
        leafCertDer,
        intermediateCertsDer,
        timeSecs,
        parsedCrls,
        trustAnchorDer,
        false,
    );
}

// Authenticate the two DCAP collateral CRLs before any revocation result is
// consumed. The PCK CRL is bound to the issuer chain returned by PCS/PCCS.
function validateCollateralCrls(
    rootCaDer,
    pckCrlIssuerChain,
    rootCaCrlDer,
    pckCrlDer,
    timeSecs,
) {
    const rootCrl = parseCrl(rootCaCrlDer);
    const pckCrl = parseCrl(pckCrlDer);

    // The root CRL must be directly authenticated by the configured trust
    // anchor. Also apply it to the root itself, matching webpki's strict root
    // revocation check in the Rust verifier.
    verifyCrl(rootCrl, rootCaDer, timeSecs);
    checkCertificateRevocation(rootCaDer, rootCaDer, [rootCrl], timeSecs);

    const pckIssuerCerts = extractCerts(Buffer.from(pckCrlIssuerChain || ''));
    if (pckIssuerCerts.length === 0) {
        throw new Error('PCK CRL issuer chain is empty or malformed');
    }

    // Authenticate the PCK CRL issuer chain using only the already-validated
    // root CRL. The issuer certificate is a CA, so it cannot go through the
    // end-entity-only public verifier.
    verifyCertificatePath(
        pckIssuerCerts[0],
        pckIssuerCerts.slice(1),
        timeSecs,
        [rootCrl],
        rootCaDer,
        true,
    );
    verifyCrl(pckCrl, pckIssuerCerts[0], timeSecs);

    return [rootCrl.der, pckCrl.der];
}

// Extract CRL distribution point URL from certificate
function extractCrlUrl(certDer) {
    try {
        const cert = Certificate.decode(certDer, 'der');

        if (!cert.tbsCertificate.extensions) {
            return null;
        }

        const crlDistPointExt = cert.tbsCertificate.extensions.find(ext =>
            oidEquals(ext.extnID, '2.5.29.31') // CRL Distribution Points OID
        );

        if (!crlDistPointExt) {
            return null;
        }

        // Try to extract URI from the extension value
        // This is a simplified parser
        const extValue = crlDistPointExt.extnValue.toString('utf-8');
        const httpMatch = extValue.match(/https?:\/\/[^\s\x00-\x1f]+/);
        if (httpMatch) {
            return httpMatch[0];
        }
    } catch (e) {
        // Ignore parse errors
    }

    return null;
}

// Extract issuer string from certificate
function getCertIssuer(certDer) {
    const cert = Certificate.decode(certDer, 'der');
    // Convert issuer RDNs to a comma separated string
    const parts = [];
    for (const rdn of cert.tbsCertificate.issuer) {
        for (const attr of rdn) {
            if (attr.value && typeof attr.value.value === 'string') {
                parts.push(attr.value.value);
            }
        }
    }
    return parts.join(', ');
}

module.exports = {
    extractRawCerts,
    extractCerts,
    getIntelExtension,
    findExtension,
    getFmspc,
    getCpuSvn,
    getPceSvn,
    encodeAsDer,
    verifyCertificateChain,
    validateCollateralCrls,
    extractCrlUrl,
    getCertIssuer,
    derToPem,
    Certificate,
    CertificateList,
};
