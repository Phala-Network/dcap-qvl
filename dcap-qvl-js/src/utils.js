// Utility functions for certificate and DER handling
// Converted from utils.rs

const crypto = require('./crypto-compat');
const { Buffer } = require('buffer');
const asn1 = require('asn1.js');
const BN = require('bn.js');
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

const TBSCertificate = asn1.define('TBSCertificate', function () {
    this.seq().obj(
        this.key('version').explicit(0).int().optional(),
        this.key('serialNumber').int(),
        this.key('signature').seq().obj(
            this.key('algorithm').objid(),
            this.key('parameters').optional().any()
        ),
        this.key('issuer').any(),
        this.key('validity').any(),
        this.key('subject').any(),
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
        this.key('revocationDate').any(),
        this.key('crlEntryExtensions').optional().any()
    );
});

const TBSCertList = asn1.define('TBSCertList', function () {
    this.seq().obj(
        this.key('version').int().optional(),
        this.key('signature').any(),
        this.key('issuer').any(),
        this.key('thisUpdate').any(),
        this.key('nextUpdate').any().optional(),
        this.key('revokedCertificates').seqof(RevokedCertificate).optional(),
        this.key('crlExtensions').explicit(0).optional().any()
    );
});

const CertificateList = asn1.define('CertificateList', function () {
    this.seq().obj(
        this.key('tbsCertList').use(TBSCertList),
        this.key('signatureAlgorithm').any(),
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

// Simple certificate chain verification using Node.js crypto
function verifyCertificateChain(leafCertDer, intermediateCertsDer, timeSecs, crlDers, trustAnchorDer) {
    // Build the full chain string in PEM format
    const leafPem = derToPem(leafCertDer, 'CERTIFICATE');
    const intermediatePems = intermediateCertsDer.map(der => derToPem(der, 'CERTIFICATE'));
    const rootPem = derToPem(trustAnchorDer, 'CERTIFICATE');

    // Check certificate chain using Node.js crypto
    const leafCert = new crypto.X509Certificate(leafPem);

    // Verify leaf cert is signed by intermediate (or root if no intermediate)
    const issuerCert = intermediateCertsDer.length > 0
        ? new crypto.X509Certificate(intermediatePems[0])
        : new crypto.X509Certificate(rootPem);

    if (!leafCert.verify(issuerCert.publicKey)) {
        throw new Error('Failed to verify certificate chain - leaf signature invalid');
    }

    const now = new Date(timeSecs * 1000);
    if (new Date(leafCert.validFrom) > now || new Date(leafCert.validTo) < now) {
        throw new Error('Certificate is expired or not yet valid');
    }

    // Verify intermediate chain up to root
    for (let i = 0; i < intermediateCertsDer.length; i++) {
        const cert = new crypto.X509Certificate(intermediatePems[i]);
        const issuer = i < intermediateCertsDer.length - 1
            ? new crypto.X509Certificate(intermediatePems[i + 1])
            : new crypto.X509Certificate(rootPem);

        if (!cert.verify(issuer.publicKey)) {
            throw new Error('Failed to verify certificate chain - intermediate signature invalid');
        }

        if (new Date(cert.validFrom) > now || new Date(cert.validTo) < now) {
            throw new Error('Certificate is expired or not yet valid');
        }
    }

    // Check CRL revocation
    checkCrlRevocation(leafCertDer, crlDers);
    for (const intermediateCert of intermediateCertsDer) {
        checkCrlRevocation(intermediateCert, crlDers);
    }
    checkCrlRevocation(trustAnchorDer, crlDers);

    return true;
}

// Check if certificate is revoked
function checkCrlRevocation(certDer, crlDers) {
    const cert = Certificate.decode(certDer, 'der');
    const certSerial = cert.tbsCertificate.serialNumber.toString();

    for (const crlDer of crlDers) {
        const crlBuffer = Buffer.isBuffer(crlDer) ? crlDer : Buffer.from(crlDer);

        try {
            const crl = CertificateList.decode(crlBuffer, 'der');

            if (crl.tbsCertList.revokedCertificates) {
                for (const revokedCert of crl.tbsCertList.revokedCertificates) {
                    const revokedSerial = revokedCert.userCertificate.toString();

                    if (certSerial === revokedSerial) {
                        throw new Error('Certificate is revoked');
                    }
                }
            }
        } catch (e) {
            if (e.message === 'Certificate is revoked') {
                throw e;
            }
            // Ignore CRL parse errors, continue with next CRL
        }
    }
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
    extractCrlUrl,
    derToPem,
    Certificate,
    CertificateList,
};
