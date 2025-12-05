// Quote verification logic
// Converted from verify.rs

const crypto = require('./crypto-compat');
const { Buffer } = require('buffer');
const { Quote, EnclaveReport } = require('./quote');
const { TcbInfo } = require('./tcb_info');
const utils = require('./utils');
const intel = require('./intel');
const {
    TRUSTED_ROOT_CA_DER,
    ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE,
    PCK_CERT_CHAIN,
    QE_HASH_DATA_BYTE_LEN,
    ATTESTATION_KEY_LEN,
    TEE_TYPE_TDX,
} = require('./constants');

class VerifiedReport {
    constructor(status, advisoryIds, report, ppid) {
        this.status = status;
        this.advisory_ids = advisoryIds;
        this.report = report;
        this.ppid = ppid;
    }
}

class QuoteVerifier {
    constructor(rootCaDer) {
        this.rootCaDer = rootCaDer || TRUSTED_ROOT_CA_DER;
    }

    static newProd() {
        return new QuoteVerifier(TRUSTED_ROOT_CA_DER);
    }

    static newWithRootCa(rootCaDer) {
        return new QuoteVerifier(rootCaDer);
    }

    verify(rawQuote, collateral, nowSecs) {
        return verifyImpl(rawQuote, collateral, nowSecs, this.rootCaDer);
    }
}

function verifyImpl(rawQuote, collateral, nowSecs, rootCaDer) {
    const now = new Date(nowSecs * 1000);

    // Parse quote
    let quote;
    try {
        quote = Quote.parse(rawQuote);
    } catch (e) {
        throw new Error('Failed to decode quote', { cause: e });
    }
    const signedQuoteLen = quote.signedLength();

    // Parse TCB info
    let tcbInfo;
    try {
        tcbInfo = TcbInfo.fromJSON(collateral.tcb_info);
    } catch (e) {
        throw new Error('Failed to decode TcbInfo', { cause: e });
    }

    // Check TCB info expiration
    const nextUpdate = new Date(tcbInfo.nextUpdate);
    if (nowSecs > nextUpdate.getTime() / 1000) {
        throw new Error('TCBInfo expired');
    }

    // Prepare CRLs (convert from hex if needed)
    const rootCaCrl = typeof collateral.root_ca_crl === 'string'
        ? Buffer.from(collateral.root_ca_crl, 'hex')
        : Buffer.from(collateral.root_ca_crl);
    const pckCrl = typeof collateral.pck_crl === 'string'
        ? Buffer.from(collateral.pck_crl, 'hex')
        : Buffer.from(collateral.pck_crl);
    const crls = [rootCaCrl, pckCrl];

    // Check root CA against CRL
    checkSingleCertCrl(rootCaDer, crls, nowSecs);

    // Verify TCB info certificate chain and signature
    const tcbLeafCerts = utils.extractCerts(Buffer.from(collateral.tcb_info_issuer_chain));
    if (tcbLeafCerts.length < 2) {
        throw new Error('Certificate chain is too short in quote_collateral');
    }

    utils.verifyCertificateChain(
        tcbLeafCerts[0],
        tcbLeafCerts.slice(1),
        nowSecs,
        crls,
        rootCaDer
    );

    // Verify TCB info signature
    const tcbInfoSig = typeof collateral.tcb_info_signature === 'string'
        ? Buffer.from(collateral.tcb_info_signature, 'hex')
        : Buffer.from(collateral.tcb_info_signature);
    const tcbInfoSignatureDer = utils.encodeAsDer(tcbInfoSig);
    try {
        verifyEcdsaSignature(
            tcbLeafCerts[0],
            Buffer.from(collateral.tcb_info, 'utf-8'),
            tcbInfoSignatureDer
        );
    } catch (e) {
        throw new Error('Signature is invalid for tcb_info');
    }

    // Check quote version
    if (![3, 4, 5].includes(quote.header.version)) {
        throw new Error('Unsupported DCAP quote version');
    }

    // Check attestation key type
    if (quote.header.attestationKeyType !== ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE) {
        throw new Error('Unsupported DCAP attestation key type');
    }

    // Extract auth data
    const authData = quote.authData.intoV3();
    const certificationData = authData.certificationData;

    // Check certification data type
    if (certificationData.certType !== PCK_CERT_CHAIN) {
        throw new Error('Unsupported DCAP PCK cert format');
    }

    // Extract PCK certificate chain
    const qeCertificationCerts = utils.extractCerts(certificationData.body);
    if (qeCertificationCerts.length < 2) {
        throw new Error('Certificate chain is too short in quote');
    }

    // Verify PCK certificate chain
    utils.verifyCertificateChain(
        qeCertificationCerts[0],
        qeCertificationCerts.slice(1),
        nowSecs,
        crls,
        rootCaDer
    );

    // Extract PPID
    let ppid = Buffer.alloc(0);
    try {
        const pckExt = intel.parsePckExtension(qeCertificationCerts[0]);
        ppid = pckExt.ppid;
    } catch (e) {
        // Ignore
    }

    // Verify QE report signature
    const qeReportSig = Buffer.from(authData.qeReportSignature);
    const qeReportSignatureDer = utils.encodeAsDer(qeReportSig);
    try {
        verifyEcdsaSignature(
            qeCertificationCerts[0],
            Buffer.from(authData.qeReport),
            qeReportSignatureDer
        );
    } catch (e) {
        throw new Error('Signature is invalid for qe_report in quote');
    }

    // Decode QE report
    const { BinaryReader } = require('./quote');
    const qeReportReader = new BinaryReader(authData.qeReport);
    const qeReport = EnclaveReport.decode(qeReportReader);

    // Verify QE hash
    const qeHashData = Buffer.alloc(QE_HASH_DATA_BYTE_LEN);
    Buffer.from(authData.ecdsaAttestationKey).copy(qeHashData, 0);
    Buffer.from(authData.qeAuthData).copy(qeHashData, ATTESTATION_KEY_LEN);

    const qeHash = crypto.createHash('sha256').update(qeHashData).digest();

    if (!qeHash.equals(Buffer.from(qeReport.reportData.slice(0, 32)))) {
        throw new Error('QE report hash mismatch');
    }

    // Verify quote signature using ECDSA attestation key
    const publicKeyBytes = Buffer.concat([
        Buffer.from([0x04]), // Uncompressed format
        Buffer.from(authData.ecdsaAttestationKey)
    ]);

    const publicKey = crypto.createPublicKey({
        key: {
            kty: 'EC',
            crv: 'P-256',
            x: toBase64Url(Buffer.from(authData.ecdsaAttestationKey.slice(0, 32))),
            y: toBase64Url(Buffer.from(authData.ecdsaAttestationKey.slice(32, 64))),
        },
        format: 'jwk'
    });

    const signedData = Buffer.from(rawQuote).slice(0, signedQuoteLen);
    const signature = Buffer.from(authData.ecdsaSignature);

    // Convert signature to DER format for verification
    const signatureDer = utils.encodeAsDer(signature);

    const verifier = crypto.createVerify('SHA256');
    verifier.update(signedData);

    if (!verifier.verify(publicKey, signatureDer)) {
        throw new Error('Isv enclave report signature is invalid');
    }

    // Extract PCK extension information
    const extensionSection = utils.getIntelExtension(qeCertificationCerts[0]);
    const cpuSvn = utils.getCpuSvn(extensionSection);
    const pceSvn = utils.getPceSvn(extensionSection);
    const fmspc = utils.getFmspc(extensionSection);

    // Check FMSPC match
    const tcbFmspc = Buffer.from(tcbInfo.fmspc, 'hex');
    if (!Buffer.from(fmspc).equals(tcbFmspc)) {
        throw new Error('Fmspc mismatch');
    }

    // Check TDX-specific requirements
    if (quote.header.teeType === TEE_TYPE_TDX && (tcbInfo.version < 3 || tcbInfo.id !== 'TDX')) {
        throw new Error('TDX quote with non-TDX TCB info in the collateral');
    }

    // Find TCB status
    let tcbStatus = 'Unknown';
    let advisoryIds = [];

    for (const tcbLevel of tcbInfo.tcbLevels) {
        // Check PCE SVN
        if (pceSvn < tcbLevel.tcb.pcesvn) {
            continue;
        }

        // Check SGX components
        const sgxComponents = tcbLevel.tcb.sgxtcbcomponents.map(c => c.svn);
        if (sgxComponents.length === 0) {
            throw new Error('No SGX components in the TCB info');
        }

        if (!compareSvnArrays(cpuSvn, sgxComponents)) {
            continue;
        }

        // Check TDX components for TDX quotes
        if (quote.header.teeType === TEE_TYPE_TDX) {
            const tdReport = quote.report.asTd10();
            if (!tdReport) {
                throw new Error('Failed to get TD10 report');
            }

            const tdxComponents = tcbLevel.tcb.tdxtcbcomponents.map(c => c.svn);
            if (tdxComponents.length === 0) {
                throw new Error('No TDX components in the TCB info');
            }

            if (!compareSvnArrays(tdReport.teeTcbSvn, tdxComponents)) {
                continue;
            }
        }

        // Found matching TCB level
        tcbStatus = tcbLevel.tcbStatus;
        advisoryIds = [...tcbLevel.advisoryIDs];
        break;
    }

    // Validate attributes
    validateAttrs(quote.report);

    return new VerifiedReport(tcbStatus, advisoryIds, quote.report, ppid);
}

// Compare SVN arrays (must be >= for each component)
function compareSvnArrays(actual, required) {
    if (actual.length !== required.length) {
        return false;
    }

    // Rust implementation uses lexicographical comparison (Vec::cmp), not component-wise
    // So we convert to Buffer and compare
    const actualBuf = Buffer.isBuffer(actual) ? actual : Buffer.from(actual);
    const requiredBuf = Buffer.isBuffer(required) ? required : Buffer.from(required);

    return actualBuf.compare(requiredBuf) >= 0;
}

// Validate report attributes
function validateAttrs(report) {
    if (report.type === 'sgx') {
        validateSgx(report.data);
    } else if (report.type === 'td10') {
        validateTd10(report.data);
    } else if (report.type === 'td15') {
        validateTd15(report.data);
    }
}

function validateSgx(report) {
    // Check if debug mode is enabled (bit 1 of attributes[0])
    const isDebug = (report.attributes[0] & 0x02) !== 0;
    if (isDebug) {
        throw new Error('Debug mode is enabled');
    }
}

function validateTd10(report) {
    const tdAttrs = parseTdAttributes(report.tdAttributes);

    if (tdAttrs.tud !== 0) {
        throw new Error('Debug mode is enabled');
    }

    if (tdAttrs.sec.reservedLower !== 0 || tdAttrs.sec.reservedBit29 || tdAttrs.other.reserved !== 0) {
        throw new Error('Reserved bits in TD attributes are set');
    }

    if (!tdAttrs.sec.septVeDisable) {
        throw new Error('SEPT_VE_DISABLE is not enabled');
    }
}

function validateTd15(report) {
    // Check mr_service_td is all zeros
    const allZero = report.mrServiceTd.every(b => b === 0);
    if (!allZero) {
        throw new Error('Invalid mr service td');
    }

    validateTd10(report.base);
}

function parseTdAttributes(input) {
    const tud = input[0];

    // Extract SEC flags
    const reservedLower = ((input[3] & 0x0f) << 16) | (input[2] << 8) | input[1];
    const septVeDisable = (input[3] & 0x10) !== 0;
    const reservedBit29 = (input[3] & 0x20) !== 0;
    const pks = (input[3] & 0x40) !== 0;
    const kl = (input[3] & 0x80) !== 0;

    // Extract OTHER flags
    const reservedOther = ((input[7] & 0x7f) << 24) | (input[6] << 16) | (input[5] << 8) | input[4];
    const perfmon = (input[7] & 0x80) !== 0;

    return {
        tud,
        sec: {
            reservedLower,
            septVeDisable,
            reservedBit29,
            pks,
            kl,
        },
        other: {
            reserved: reservedOther,
            perfmon,
        },
    };
}

// Check single certificate against CRL
function checkSingleCertCrl(certDer, crlDers, nowSecs) {
    const cert = utils.Certificate.decode(certDer, 'der');
    const certSerial = cert.tbsCertificate.serialNumber.toString();

    for (const crlDer of crlDers) {
        const crlBuffer = Buffer.isBuffer(crlDer) ? crlDer : Buffer.from(crlDer);

        try {
            const crl = utils.CertificateList.decode(crlBuffer, 'der');

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
            // Ignore CRL parse errors
        }
    }
}

// Verify ECDSA signature using certificate
function verifyEcdsaSignature(certDer, data, signatureDer) {
    // Convert cert to PEM and use Node.js crypto
    const certPem = utils.derToPem(certDer, 'CERTIFICATE');
    const cert = new crypto.X509Certificate(certPem);

    // Verify signature
    const verifier = crypto.createVerify('SHA256');
    verifier.update(data);

    if (!verifier.verify(cert.publicKey, signatureDer)) {
        throw new Error('Signature verification failed');
    }
}

// Main verify function using Intel's root CA
function verify(rawQuote, collateral, nowSecs) {
    return QuoteVerifier.newProd().verify(rawQuote, collateral, nowSecs);
}

function toBase64Url(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

module.exports = {
    QuoteVerifier,
    VerifiedReport,
    verify,
};
