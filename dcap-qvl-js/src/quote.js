// Quote parsing and structures
// Converted from quote.rs

const {
    HEADER_BYTE_LEN,
    ENCLAVE_REPORT_BYTE_LEN,
    TD_REPORT10_BYTE_LEN,
    TD_REPORT15_BYTE_LEN,
    TEE_TYPE_SGX,
    TEE_TYPE_TDX,
    BODY_SGX_ENCLAVE_REPORT_TYPE,
    BODY_TD_REPORT10_TYPE,
    BODY_TD_REPORT15_TYPE,
    ECDSA_SIGNATURE_BYTE_LEN,
    ECDSA_PUBKEY_BYTE_LEN,
    QE_REPORT_SIG_BYTE_LEN,
    BODY_BYTE_SIZE,
} = require('./constants');
const { Buffer } = require('buffer');

// Binary reader helper
class BinaryReader {
    constructor(buffer) {
        this.buffer = Buffer.from(buffer);
        this.offset = 0;
    }

    checkBounds(length) {
        if (this.offset + length > this.buffer.length) {
            throw new Error('Not enough data to fill buffer');
        }
    }

    readU8() {
        this.checkBounds(1);
        const value = this.buffer.readUInt8(this.offset);
        this.offset += 1;
        return value;
    }

    readU16LE() {
        this.checkBounds(2);
        const value = this.buffer.readUInt16LE(this.offset);
        this.offset += 2;
        return value;
    }

    readU32LE() {
        this.checkBounds(4);
        const value = this.buffer.readUInt32LE(this.offset);
        this.offset += 4;
        return value;
    }

    readBytes(length) {
        this.checkBounds(length);
        const bytes = this.buffer.slice(this.offset, this.offset + length);
        this.offset += length;
        return new Uint8Array(bytes);
    }

    remaining() {
        return this.buffer.length - this.offset;
    }

    getOffset() {
        return this.offset;
    }
}

class Header {
    constructor(version, attestationKeyType, teeType, qeSvn, pceSvn, qeVendorId, userData) {
        this.version = version;
        this.attestationKeyType = attestationKeyType;
        this.teeType = teeType;
        this.qeSvn = qeSvn;
        this.pceSvn = pceSvn;
        this.qeVendorId = qeVendorId;
        this.userData = userData;
    }

    isSgx() {
        return this.teeType === TEE_TYPE_SGX;
    }

    static decode(reader) {
        const version = reader.readU16LE();
        const attestationKeyType = reader.readU16LE();
        const teeType = reader.readU32LE();
        const qeSvn = reader.readU16LE();
        const pceSvn = reader.readU16LE();
        const qeVendorId = reader.readBytes(16);
        const userData = reader.readBytes(20);

        return new Header(version, attestationKeyType, teeType, qeSvn, pceSvn, qeVendorId, userData);
    }
}

class Body {
    constructor(bodyType, size) {
        this.bodyType = bodyType;
        this.size = size;
    }

    static decode(reader) {
        const bodyType = reader.readU16LE();
        const size = reader.readU32LE();
        return new Body(bodyType, size);
    }
}

class EnclaveReport {
    constructor(data) {
        this.cpuSvn = data.cpuSvn;
        this.miscSelect = data.miscSelect;
        this.reserved1 = data.reserved1;
        this.attributes = data.attributes;
        this.mrEnclave = data.mrEnclave;
        this.reserved2 = data.reserved2;
        this.mrSigner = data.mrSigner;
        this.reserved3 = data.reserved3;
        this.isvProdId = data.isvProdId;
        this.isvSvn = data.isvSvn;
        this.reserved4 = data.reserved4;
        this.reportData = data.reportData;
    }

    static decode(reader) {
        return new EnclaveReport({
            cpuSvn: reader.readBytes(16),
            miscSelect: reader.readU32LE(),
            reserved1: reader.readBytes(28),
            attributes: reader.readBytes(16),
            mrEnclave: reader.readBytes(32),
            reserved2: reader.readBytes(32),
            mrSigner: reader.readBytes(32),
            reserved3: reader.readBytes(96),
            isvProdId: reader.readU16LE(),
            isvSvn: reader.readU16LE(),
            reserved4: reader.readBytes(60),
            reportData: reader.readBytes(64),
        });
    }
}

class TDReport10 {
    constructor(data) {
        this.teeTcbSvn = data.teeTcbSvn;
        this.mrSeam = data.mrSeam;
        this.mrSignerSeam = data.mrSignerSeam;
        this.seamAttributes = data.seamAttributes;
        this.tdAttributes = data.tdAttributes;
        this.xfam = data.xfam;
        this.mrTd = data.mrTd;
        this.mrConfigId = data.mrConfigId;
        this.mrOwner = data.mrOwner;
        this.mrOwnerConfig = data.mrOwnerConfig;
        this.rtMr0 = data.rtMr0;
        this.rtMr1 = data.rtMr1;
        this.rtMr2 = data.rtMr2;
        this.rtMr3 = data.rtMr3;
        this.reportData = data.reportData;
    }

    static decode(reader) {
        return new TDReport10({
            teeTcbSvn: reader.readBytes(16),
            mrSeam: reader.readBytes(48),
            mrSignerSeam: reader.readBytes(48),
            seamAttributes: reader.readBytes(8),
            tdAttributes: reader.readBytes(8),
            xfam: reader.readBytes(8),
            mrTd: reader.readBytes(48),
            mrConfigId: reader.readBytes(48),
            mrOwner: reader.readBytes(48),
            mrOwnerConfig: reader.readBytes(48),
            rtMr0: reader.readBytes(48),
            rtMr1: reader.readBytes(48),
            rtMr2: reader.readBytes(48),
            rtMr3: reader.readBytes(48),
            reportData: reader.readBytes(64),
        });
    }
}

class TDReport15 {
    constructor(base, teeTcbSvn2, mrServiceTd) {
        this.base = base;
        this.teeTcbSvn2 = teeTcbSvn2;
        this.mrServiceTd = mrServiceTd;
    }

    static decode(reader) {
        const base = TDReport10.decode(reader);
        const teeTcbSvn2 = reader.readBytes(16);
        const mrServiceTd = reader.readBytes(48);
        return new TDReport15(base, teeTcbSvn2, mrServiceTd);
    }
}

class Report {
    constructor(type, data) {
        this.type = type; // 'sgx', 'td10', or 'td15'
        this.data = data;
    }

    isSgx() {
        return this.type === 'sgx';
    }

    asTd10() {
        if (this.type === 'td10') return this.data;
        if (this.type === 'td15') return this.data.base;
        return null;
    }

    asTd15() {
        return this.type === 'td15' ? this.data : null;
    }

    asSgx() {
        return this.type === 'sgx' ? this.data : null;
    }
}

class CertificationData {
    constructor(certType, body) {
        this.certType = certType;
        this.body = body;
    }

    static decode(reader) {
        const certType = reader.readU16LE();
        const bodySize = reader.readU32LE();
        const body = reader.readBytes(bodySize);
        return new CertificationData(certType, body);
    }
}

class QEReportCertificationData {
    constructor(qeReport, qeReportSignature, qeAuthData, certificationData) {
        this.qeReport = qeReport;
        this.qeReportSignature = qeReportSignature;
        this.qeAuthData = qeAuthData;
        this.certificationData = certificationData;
    }

    static decode(reader) {
        const qeReport = reader.readBytes(ENCLAVE_REPORT_BYTE_LEN);
        const qeReportSignature = reader.readBytes(QE_REPORT_SIG_BYTE_LEN);
        const qeAuthDataSize = reader.readU16LE();
        const qeAuthData = reader.readBytes(qeAuthDataSize);
        const certificationData = CertificationData.decode(reader);
        return new QEReportCertificationData(qeReport, qeReportSignature, qeAuthData, certificationData);
    }
}

class AuthDataV3 {
    constructor(ecdsaSignature, ecdsaAttestationKey, qeReport, qeReportSignature, qeAuthData, certificationData) {
        this.ecdsaSignature = ecdsaSignature;
        this.ecdsaAttestationKey = ecdsaAttestationKey;
        this.qeReport = qeReport;
        this.qeReportSignature = qeReportSignature;
        this.qeAuthData = qeAuthData;
        this.certificationData = certificationData;
    }

    static decode(reader) {
        const ecdsaSignature = reader.readBytes(ECDSA_SIGNATURE_BYTE_LEN);
        const ecdsaAttestationKey = reader.readBytes(ECDSA_PUBKEY_BYTE_LEN);
        const qeReport = reader.readBytes(ENCLAVE_REPORT_BYTE_LEN);
        const qeReportSignature = reader.readBytes(QE_REPORT_SIG_BYTE_LEN);
        const qeAuthDataSize = reader.readU16LE();
        const qeAuthData = reader.readBytes(qeAuthDataSize);
        const certificationData = CertificationData.decode(reader);
        return new AuthDataV3(ecdsaSignature, ecdsaAttestationKey, qeReport, qeReportSignature, qeAuthData, certificationData);
    }
}

class AuthDataV4 {
    constructor(ecdsaSignature, ecdsaAttestationKey, certificationData, qeReportData) {
        this.ecdsaSignature = ecdsaSignature;
        this.ecdsaAttestationKey = ecdsaAttestationKey;
        this.certificationData = certificationData;
        this.qeReportData = qeReportData;
    }

    intoV3() {
        return new AuthDataV3(
            this.ecdsaSignature,
            this.ecdsaAttestationKey,
            this.qeReportData.qeReport,
            this.qeReportData.qeReportSignature,
            this.qeReportData.qeAuthData,
            this.qeReportData.certificationData
        );
    }

    static decode(reader) {
        const ecdsaSignature = reader.readBytes(ECDSA_SIGNATURE_BYTE_LEN);
        const ecdsaAttestationKey = reader.readBytes(ECDSA_PUBKEY_BYTE_LEN);
        const certificationData = CertificationData.decode(reader);

        // Decode QEReportCertificationData from the certification data body
        const bodyReader = new BinaryReader(certificationData.body);
        const qeReportData = QEReportCertificationData.decode(bodyReader);

        return new AuthDataV4(ecdsaSignature, ecdsaAttestationKey, certificationData, qeReportData);
    }
}

class AuthData {
    constructor(version, data) {
        this.version = version; // 3 or 4
        this.data = data;
    }

    intoV3() {
        if (this.version === 3) return this.data;
        if (this.version === 4) return this.data.intoV3();
        throw new Error('Unsupported auth data version');
    }

    static decode(version, reader) {
        if (version === 3) {
            return new AuthData(3, AuthDataV3.decode(reader));
        } else if (version === 4) {
            return new AuthData(4, AuthDataV4.decode(reader));
        } else {
            throw new Error(`Unsupported auth data version: ${version}`);
        }
    }
}

class Quote {
    constructor(header, report, authData) {
        this.header = header;
        this.report = report;
        this.authData = authData;
    }

    static parse(quoteBytes) {
        const reader = new BinaryReader(quoteBytes);

        // Decode header
        const header = Header.decode(reader);

        // Decode report based on version and tee type
        let report;
        if (header.version === 3) {
            if (header.teeType !== TEE_TYPE_SGX) {
                throw new Error('Invalid tee type for version 3');
            }
            report = new Report('sgx', EnclaveReport.decode(reader));
        } else if (header.version === 4) {
            if (header.teeType === TEE_TYPE_SGX) {
                report = new Report('sgx', EnclaveReport.decode(reader));
            } else if (header.teeType === TEE_TYPE_TDX) {
                report = new Report('td10', TDReport10.decode(reader));
            } else {
                throw new Error('Invalid TEE type');
            }
        } else if (header.version === 5) {
            const body = Body.decode(reader);
            if (body.bodyType === BODY_SGX_ENCLAVE_REPORT_TYPE) {
                report = new Report('sgx', EnclaveReport.decode(reader));
            } else if (body.bodyType === BODY_TD_REPORT10_TYPE) {
                report = new Report('td10', TDReport10.decode(reader));
            } else if (body.bodyType === BODY_TD_REPORT15_TYPE) {
                report = new Report('td15', TDReport15.decode(reader));
            } else {
                throw new Error('Unsupported body type');
            }
        } else {
            throw new Error('Unsupported quote version');
        }

        // Decode auth data
        const authDataSize = reader.readU32LE();
        const authDataBytes = reader.readBytes(authDataSize);
        const authDataReader = new BinaryReader(authDataBytes);

        // Quote v5 uses v4 auth data format
        const authVersion = header.version === 5 ? 4 : header.version;
        const authData = AuthData.decode(authVersion, authDataReader);

        return new Quote(header, report, authData);
    }

    rawCertChain() {
        const certData = this.authData.version === 3
            ? this.authData.data.certificationData
            : this.authData.data.qeReportData.certificationData;

        if (certData.certType !== 5) {
            throw new Error(`Unsupported cert type: ${certData.certType}`);
        }

        return certData.body;
    }

    signedLength() {
        let len;
        if (this.report.type === 'sgx') {
            len = HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN;
        } else if (this.report.type === 'td10') {
            len = HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN;
        } else if (this.report.type === 'td15') {
            len = HEADER_BYTE_LEN + TD_REPORT15_BYTE_LEN;
        }

        if (this.header.version === 5) {
            len += BODY_BYTE_SIZE;
        }

        return len;
    }
}

module.exports = {
    BinaryReader,
    Header,
    Body,
    EnclaveReport,
    TDReport10,
    TDReport15,
    Report,
    CertificationData,
    QEReportCertificationData,
    AuthDataV3,
    AuthDataV4,
    AuthData,
    Quote,
};
