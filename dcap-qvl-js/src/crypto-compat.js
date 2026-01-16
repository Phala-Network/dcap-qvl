const crypto = require('crypto');
const { Buffer } = require('buffer');
const asn1 = require('asn1.js');
const hashJs = require('hash.js');
const EC = require('elliptic').ec;

const isBrowser = typeof window !== 'undefined' || !crypto.X509Certificate;

const AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', function () {
    this.seq().obj(
        this.key('algorithm').objid(),
        this.key('parameters').optional().any()
    );
});

const SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function () {
    this.seq().obj(
        this.key('algorithm').use(AlgorithmIdentifier),
        this.key('subjectPublicKey').bitstr()
    );
});

const TBSCertificate = asn1.define('TBSCertificate', function () {
    this.seq().obj(
        this.key('version').explicit(0).int().optional(),
        this.key('serialNumber').int(),
        this.key('signature').use(AlgorithmIdentifier),
        this.key('issuer').any(),
        this.key('validity').any(),
        this.key('subject').any(),
        this.key('subjectPublicKeyInfo').use(SubjectPublicKeyInfo),
        this.key('extensions').explicit(3).optional().any()
    );
});

const Certificate = asn1.define('Certificate', function () {
    this.seq().obj(
        this.key('tbsCertificate').use(TBSCertificate),
        this.key('signatureAlgorithm').use(AlgorithmIdentifier),
        this.key('signature').bitstr()
    );
});

function parseECPublicKeyFromCert(certDer) {
    try {
        const cert = Certificate.decode(certDer, 'der');
        const publicKeyBits = cert.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey.data;
        return Buffer.from(publicKeyBits);
    } catch (e) {
        return null;
    }
}

let X509Certificate;

if (isBrowser) {
    X509Certificate = class BrowserX509Certificate {
        constructor(pemOrBuffer) {
            let pem;
            if (Buffer.isBuffer(pemOrBuffer)) {
                pem = pemOrBuffer.toString('utf8');
            } else {
                pem = pemOrBuffer;
            }
            this._pem = pem;

            // Convert PEM to DER
            const base64 = pem
                .replace(/-----BEGIN CERTIFICATE-----/, '')
                .replace(/-----END CERTIFICATE-----/, '')
                .replace(/\s+/g, '');
            this._der = Buffer.from(base64, 'base64');

            // Try to extract public key
            try {
                this._publicKeyData = parseECPublicKeyFromCert(this._der);
            } catch (e) {
                this._publicKeyData = null;
            }
        }

        get publicKey() {
            let publicKeyPem;
            try {
                const cert = Certificate.decode(this._der, 'der');
                publicKeyPem = extractPublicKeyPemFromCert(cert);
            } catch (e) {
                console.error("Failed to extract public key", e);
            }

            return {
                export: (options) => {
                    if (options?.format === 'pem') {
                        return publicKeyPem;
                    }
                    return publicKeyPem;
                },
                asymmetricKeyType: 'ec',
                type: 'public',
                _pem: publicKeyPem,
                _isCustomKey: true
            };
        }

        verify(publicKey) {
            // In browser environment, verify certificate signature against issuer's public key
            try {
                const cert = Certificate.decode(this._der, 'der');
                const signature = Buffer.from(cert.signature.data);
                const tbsBytes = getTBSBytesFromDer(this._der);

                // Extract public key PEM
                let keyToUse = publicKey;
                if (publicKey && typeof publicKey.export === 'function') {
                    try {
                        keyToUse = publicKey.export({ format: 'pem', type: 'spki' });
                    } catch (e) {
                        // Use publicKey as-is
                    }
                }

                if (typeof keyToUse === 'string' && keyToUse.includes('-----BEGIN CERTIFICATE-----')) {
                    try {
                        const pemStr = keyToUse.replace(/-----BEGIN CERTIFICATE-----/, '')
                            .replace(/-----END CERTIFICATE-----/, '')
                            .replace(/\s+/g, '');
                        const certDer = Buffer.from(pemStr, 'base64');
                        const issuerCert = Certificate.decode(certDer, 'der');
                        keyToUse = extractPublicKeyPemFromCert(issuerCert);
                    } catch (e) {
                        console.error("Error parsing issuer certificate:", e);
                    }
                }

                // Determine signature algorithm from certificate
                const sigAlgOid = cert.signatureAlgorithm.algorithm.join('.');

                let algorithm = 'sha256'; // Default to sha256

                const oidMap = {
                    '1.2.840.113549.1.1.11': 'sha256',
                    '1.2.840.113549.1.1.12': 'sha384',
                    '1.2.840.113549.1.1.13': 'sha512',
                    '1.2.840.113549.1.1.14': 'sha224',

                    '1.2.840.10045.4.3.2': 'sha256',
                    '1.2.840.10045.4.3.3': 'sha384',
                    '1.2.840.10045.4.3.4': 'sha512',
                };

                if (oidMap[sigAlgOid]) {
                    algorithm = oidMap[sigAlgOid];
                }

                const verifier = createVerify(algorithm);
                verifier.update(tbsBytes);
                return verifier.verify(keyToUse, signature);
            } catch (e) {
                return false;
            }
        }

        toString() {
            return this._pem;
        }
    };
} else {
    X509Certificate = crypto.X509Certificate;
}

const createHash = function (algorithm) {
    if (isBrowser) {
        // hash.js uses sha256() instead of createHash('sha256')
        const algo = algorithm.toLowerCase();
        if (hashJs[algo]) {
            const hash = hashJs[algo]();
            return {
                update: function (data) {
                    hash.update(data);
                    return this;
                },
                digest: function (encoding) {
                    const result = hash.digest(encoding);
                    if (!encoding) {
                        return Buffer.from(result);
                    }
                    return result;
                }
            };
        }
        throw new Error(`Unsupported hash algorithm: ${algorithm}`);
    } else {
        return crypto.createHash(algorithm);
    }
};

const createVerify = function (algorithm) {
    let verifier;

    if (isBrowser) {
        // Pure JS implementation using elliptic and hash.js
        const algoName = typeof algorithm === 'string' ? algorithm.toLowerCase() : algorithm;
        const hashAlgo = algoName.replace('rsa-', ''); // Handle rsa-sha256 -> sha256

        // hash.js instance
        let hash;
        if (hashJs[hashAlgo]) {
            hash = hashJs[hashAlgo]();
        } else {
            throw new Error(`Unsupported hash algorithm: ${hashAlgo}`);
        }

        verifier = {
            update: function (data) {
                hash.update(data);
                return this;
            },
            verify: function (publicKey, signature, signatureFormat) {
                try {
                    const digest = hash.digest();

                    // We only support EC P-256 for now as that's what DCAP uses
                    const ec = new EC('p256');

                    let key;
                    if (typeof publicKey === 'string') {
                        // PEM string
                        if (publicKey.includes('PUBLIC KEY')) {
                            // Extract key from PEM
                            const pemStr = publicKey.replace(/-----BEGIN PUBLIC KEY-----/, '')
                                .replace(/-----END PUBLIC KEY-----/, '')
                                .replace(/\s+/g, '');
                            const der = Buffer.from(pemStr, 'base64');

                            // Parse SubjectPublicKeyInfo to get the key data
                            const spki = SubjectPublicKeyInfo.decode(der, 'der');
                            const keyData = spki.subjectPublicKey.data;
                            key = ec.keyFromPublic(keyData);
                        } else {
                            // Assume raw hex or other format if not PEM (unlikely for this use case)
                            throw new Error("Unsupported key format");
                        }
                    } else if (publicKey && publicKey._isCustomKey && publicKey._pem) {
                        // Recursive call with PEM
                        return this.verify(publicKey._pem, signature, signatureFormat);
                    } else {
                        throw new Error("Unsupported public key object");
                    }

                    // Signature can be DER or raw. elliptic supports DER.
                    // DCAP utils.js converts to DER before calling verify.
                    return key.verify(digest, signature);
                } catch (e) {
                    // console.error("Verification error:", e);
                    return false;
                }
            }
        };
    } else {
        verifier = crypto.createVerify(algorithm);
    }

    const originalVerify = verifier.verify.bind(verifier);

    verifier.verify = function (publicKey, signature, signatureFormat) {
        let keyToUse = publicKey;

        if (publicKey && publicKey._isCustomKey && publicKey._pem) {
            keyToUse = publicKey._pem;
        }
        else if (publicKey && typeof publicKey.export === 'function') {
            try {
                keyToUse = publicKey.export({ format: 'pem', type: 'spki' });
            } catch (e) {
            }
        }

        try {
            return originalVerify(keyToUse, signature, signatureFormat);
        } catch (e) {
            return false;
        }
    };

    return verifier;
};

const SpkiP256 = asn1.define('SpkiP256', function () {
    this.seq().obj(
        this.key('algorithm').seq().obj(
            this.key('id').objid(),
            this.key('curve').objid()
        ),
        this.key('pubKey').bitstr()
    );
});

function getTBSBytesFromDer(derBuffer) {
    let offset = 0;

    if (derBuffer[offset++] !== 0x30) throw new Error("Certificate is not a SEQUENCE");

    let lenByte = derBuffer[offset++];
    if (lenByte & 0x80) {
        const numBytes = lenByte & 0x7f;
        offset += numBytes;
    }

    const tbsStart = offset;

    if (derBuffer[offset++] !== 0x30) throw new Error("TBSCertificate is not a SEQUENCE");

    let tbsLength = 0;
    lenByte = derBuffer[offset++];
    if (lenByte & 0x80) {
        const numLenBytes = lenByte & 0x7f;
        for (let i = 0; i < numLenBytes; i++) {
            tbsLength = (tbsLength << 8) | derBuffer[offset++];
        }
    } else {
        tbsLength = lenByte;
    }

    const tbsEnd = offset + tbsLength;

    return derBuffer.subarray(tbsStart, tbsEnd);
}

function extractPublicKeyPemFromCert(certObj) {
    try {
        const spki = certObj.tbsCertificate.subjectPublicKeyInfo;

        const spkiDer = SubjectPublicKeyInfo.encode(spki, 'der');

        const b64 = spkiDer.toString('base64');
        const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;

        return pem;
    } catch (e) {
        console.error("Failed to extract public key from cert:", e);
        return null;
    }
}

function base64UrlToBuffer(str) {
    if (!str) return Buffer.alloc(0);
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return Buffer.from(base64, 'base64');
}

const createPublicKey = function (key) {
    if (!isBrowser && crypto.createPublicKey) {
        return crypto.createPublicKey(key);
    }

    let jwkData = null;

    if (typeof key === 'object' && key.format === 'jwk' && key.key) {
        jwkData = key.key;
    } else if (typeof key === 'object' && key.kty) {
        jwkData = key;
    }

    if (jwkData && jwkData.kty === 'EC' && jwkData.crv === 'P-256') {
        try {
            const xBuf = base64UrlToBuffer(jwkData.x);
            const yBuf = base64UrlToBuffer(jwkData.y);

            const uncompressedPoint = Buffer.concat([
                Buffer.from([0x04]),
                xBuf,
                yBuf
            ]);

            const der = SpkiP256.encode({
                algorithm: {
                    id: [1, 2, 840, 10045, 2, 1],
                    curve: [1, 2, 840, 10045, 3, 1, 7]
                },
                pubKey: {
                    unused: 0,
                    data: uncompressedPoint
                }
            }, 'der');

            const b64 = der.toString('base64');
            const pem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----\n`;

            return {
                export: (options) => {
                    if (options && options.format === 'pem') return pem;
                    return der;
                },
                type: 'public',
                asymmetricKeyType: 'ec',
                _pem: pem,
                _isCustomKey: true
            };

        } catch (e) {
            throw new Error("Failed to create public key from JWK: " + e.message);
        }
    }

    if (typeof key === 'string' && key.includes('-----BEGIN')) {
        return {
            export: () => key,
            type: 'public',
            asymmetricKeyType: 'unknown',
            _pem: key,
            _isCustomKey: true
        };
    }

    throw new Error("Browser createPublicKey polyfill currently only supports EC P-256 JWK or PEM strings.");
};

module.exports = {
    ...crypto,
    X509Certificate,
    createHash: createHash,
    createVerify: createVerify,
    createPublicKey: createPublicKey,
    isBrowser,
};