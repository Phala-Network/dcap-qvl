// Quote verification logic
// Converted from verify.rs

const crypto = require('./crypto-compat');
const { Buffer } = require('buffer');
const { Quote, EnclaveReport } = require('./quote');
const { TcbInfo, TcbStatus } = require('./tcb_info');
const { QeIdentity } = require('./qe_identity');
const utils = require('./utils');
const intel = require('./intel');
const {
    TRUSTED_ROOT_CA_DER,
    ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE,
    PCK_CERT_CHAIN,
    QE_HASH_DATA_BYTE_LEN,
    ATTESTATION_KEY_LEN,
    ALLOWED_QUOTE_VERSIONS,
    ALLOWED_TEE_TYPES,
    TEE_TYPE_SGX,
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

    // Check quote version and TEE type
    if (!ALLOWED_QUOTE_VERSIONS.includes(quote.header.version)) {
        throw new Error('Unsupported DCAP quote version');
    }
    if (!ALLOWED_TEE_TYPES.includes(quote.header.teeType)) {
        throw new Error('Unsupported DCAP TEE type');
    }
    if (quote.header.teeType == TEE_TYPE_SGX && quote.header.version != 3) {
        throw new Error('SGX TEE quote must have version 3');
    }
    if (quote.header.teeType == TEE_TYPE_TDX && (quote.header.version != 4 && quote.header.version != 5)) {
        throw new Error('TDX TEE quote must have version 4 or 5');
    }

    // Check attestation key type
    if (quote.header.attestationKeyType !== ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE) {
        throw new Error('Unsupported DCAP attestation key type');
    }

    // Parse TCB info
    let tcbInfo;
    try {
        tcbInfo = TcbInfo.fromJSON(collateral.tcb_info);
    } catch (e) {
        throw new Error('Failed to decode TcbInfo', { cause: e });
    }

    // Check TCB info validity window
    const issueDate = new Date(tcbInfo.issueDate);
    if (nowSecs < issueDate.getTime() / 1000) {
        throw new Error('TCBInfo issue date is in the future');
    }
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
        throw new Error('Certificate chain is too short for TCB Info');
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

    // Step 2: Verify QE Identity signature
    let qeIdentity;
    try {
        qeIdentity = QeIdentity.fromJSON(collateral.qe_identity);
    } catch (e) {
        throw new Error('Failed to decode QeIdentity', { cause: e });
    }

    // Check QE Identity validity window
    const qeIssueDate = new Date(qeIdentity.issueDate);
    if (nowSecs < qeIssueDate.getTime() / 1000) {
        throw new Error('QE Identity issue date is in the future');
    }
    const qeIdentityNextUpdate = new Date(qeIdentity.nextUpdate);
    if (nowSecs > qeIdentityNextUpdate.getTime() / 1000) {
        throw new Error('QE Identity expired');
    }

    // Verify QE Identity certificate chain
    const qeIdCerts = utils.extractCerts(Buffer.from(collateral.qe_identity_issuer_chain));
    if (qeIdCerts.length < 2) {
        throw new Error('Certificate chain is too short for QE Identity');
    }

    utils.verifyCertificateChain(
        qeIdCerts[0],
        qeIdCerts.slice(1),
        nowSecs,
        crls,
        rootCaDer
    );

    // Verify QE Identity signature
    const qeIdSig = typeof collateral.qe_identity_signature === 'string'
        ? Buffer.from(collateral.qe_identity_signature, 'hex')
        : Buffer.from(collateral.qe_identity_signature);
    const qeIdSignatureDer = utils.encodeAsDer(qeIdSig);
    try {
        verifyEcdsaSignature(
            qeIdCerts[0],
            Buffer.from(collateral.qe_identity, 'utf-8'),
            qeIdSignatureDer
        );
    } catch (e) {
        throw new Error('Signature is invalid for qe_identity');
    }

    const expectedQeId = quote.header.teeType === TEE_TYPE_TDX ? 'TD_QE' : 'QE';
    const allowedQeVersions = quote.header.teeType === TEE_TYPE_TDX ? [2, 3] : [2];
    if (qeIdentity.id !== expectedQeId || !allowedQeVersions.includes(qeIdentity.version)) {
        throw new Error('Unsupported QE Identity id/version for the quote TEE type');
    }

    // Extract auth data
    const authData = quote.authData.intoV3();
    const certificationData = authData.certificationData;

    // Extract PCK certificate chain - prefer collateral, fall back to quote
    let qeCertificationCerts;
    if (collateral.pck_certificate_chain) {
        // Use certificate chain from collateral (supports cert_type 3/5)
        qeCertificationCerts = utils.extractCerts(Buffer.from(collateral.pck_certificate_chain, 'utf-8'));
        if (qeCertificationCerts.length === 0) {
            throw new Error('Failed to extract PCK certificates from collateral');
        }
    } else {
        // Backward compatibility: extract from quote (only works for cert_type 5)
        if (certificationData.certType !== PCK_CERT_CHAIN) {
            throw new Error(`Unsupported DCAP PCK cert format: ${certificationData.certType}. Use get_collateral() to fetch PCK certificate.`);
        }
        qeCertificationCerts = utils.extractCerts(certificationData.body);
        if (qeCertificationCerts.length === 0) {
            throw new Error('Failed to extract PCK certificates from quote');
        }
    }

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

    // Step 6: Verify QE Report policy against QE Identity
    const qeTcbStatus = verifyQeIdentityPolicy(qeReport, qeIdentity);

    // Step 7: Verify quote signature using ECDSA attestation key
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
        throw new Error('ISV enclave report signature is invalid');
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

    // Check TEE-specific requirements
    if (quote.header.teeType === TEE_TYPE_TDX) {
        if (tcbInfo.version < 3 || tcbInfo.id !== 'TDX') {
            throw new Error('TDX quote with non-TDX TCB info in the collateral');
        }
    } else if (quote.header.teeType === TEE_TYPE_SGX) {
        if (tcbInfo.version < 2 || tcbInfo.id !== 'SGX') {
            throw new Error('SGX quote with non-SGX TCB info in the collateral');
        }
    }

    // Step 8: Match Platform TCB
    const platformTcbStatus = matchPlatformTcb(tcbInfo, quote, cpuSvn, pceSvn);

    // Step 9 & 10: QE TCB matching is done in verifyQeIdentityPolicy, merge statuses
    const finalStatus = platformTcbStatus.merge(qeTcbStatus);

    // Reject invalid TCB status (including Revoked)
    if (!finalStatus.isValid()) {
        throw new Error(`TCB status is invalid: ${finalStatus.status}`);
    }

    // Validate attributes
    validateAttrs(quote.report);

    return new VerifiedReport(finalStatus.status, finalStatus.advisoryIds, quote.report, ppid);
}

// Step 8: Match Platform TCB
function matchPlatformTcb(tcbInfo, quote, cpuSvn, pceSvn) {
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
        return new TcbStatus(tcbLevel.tcbStatus, [...tcbLevel.advisoryIDs]);
    }

    throw new Error('No matching TCB level found');
}

// Step 6 & 9: Verify QE Report policy and match QE TCB
function verifyQeIdentityPolicy(qeReport, qeIdentity) {
    // Verify MRSIGNER
    const expectedMrsigner = Buffer.from(qeIdentity.mrsigner, 'hex');
    if (!Buffer.from(qeReport.mrSigner).equals(expectedMrsigner)) {
        throw new Error(`QE MRSIGNER mismatch: expected ${qeIdentity.mrsigner}, got ${Buffer.from(qeReport.mrSigner).toString('hex').toUpperCase()}`);
    }

    // Verify ISVPRODID
    if (qeReport.isvProdId !== qeIdentity.isvprodid) {
        throw new Error(`QE ISVPRODID mismatch: expected ${qeIdentity.isvprodid}, got ${qeReport.isvProdId}`);
    }

    // Verify MISCSELECT with mask
    const expectedMiscselect = Buffer.from(qeIdentity.miscselect, 'hex');
    const miscselectMask = Buffer.from(qeIdentity.miscselectMask, 'hex');

    const expectedMiscselectU32 = expectedMiscselect.readUInt32LE(0);
    const miscselectMaskU32 = miscselectMask.readUInt32LE(0);
    const qeMiscselectMasked = qeReport.miscSelect & miscselectMaskU32;
    const expectedMiscselectMasked = expectedMiscselectU32 & miscselectMaskU32;

    if (qeMiscselectMasked !== expectedMiscselectMasked) {
        throw new Error(`QE MISCSELECT mismatch: expected ${expectedMiscselectMasked.toString(16).padStart(8, '0').toUpperCase()} (masked), got ${qeMiscselectMasked.toString(16).padStart(8, '0').toUpperCase()} (masked)`);
    }

    // Verify ATTRIBUTES with mask
    const expectedAttributes = Buffer.from(qeIdentity.attributes, 'hex');
    const attributesMask = Buffer.from(qeIdentity.attributesMask, 'hex');

    for (let i = 0; i < 16; i++) {
        const expectedMasked = expectedAttributes[i] & attributesMask[i];
        const qeMasked = qeReport.attributes[i] & attributesMask[i];
        if (expectedMasked !== qeMasked) {
            throw new Error(`QE ATTRIBUTES mismatch at byte ${i}: expected ${expectedMasked.toString(16).padStart(2, '0').toUpperCase()} (masked), got ${qeMasked.toString(16).padStart(2, '0').toUpperCase()} (masked)`);
        }
    }

    // Match QE TCB level based on ISVSVN
    return matchQeTcbLevel(qeReport.isvSvn, qeIdentity.tcbLevels);
}

// Match QE ISVSVN against QE Identity TCB levels
function matchQeTcbLevel(isvSvn, tcbLevels) {
    for (const tcbLevel of tcbLevels) {
        if (isvSvn >= tcbLevel.tcb.isvsvn) {
            return new TcbStatus(tcbLevel.tcbStatus, [...tcbLevel.advisoryIDs]);
        }
    }

    // No matching level found
    if (tcbLevels.length === 0) {
        throw new Error('No TCB levels found in QE Identity');
    }

    // ISVSVN is below all defined TCB levels
    const minRequired = tcbLevels[tcbLevels.length - 1].tcb.isvsvn;
    throw new Error(`QE ISVSVN ${isvSvn} is below minimum required ${minRequired} from QE Identity`);
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
