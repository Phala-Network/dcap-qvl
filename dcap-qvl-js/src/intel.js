// Intel SGX PCK extension parsing
// Converted from intel.rs

const utils = require('./utils');
const oids = require('./oids');
const asn1 = require('asn1.js');
const { PROCESSOR_ISSUER, PLATFORM_ISSUER, PROCESSOR_ISSUER_ID, PLATFORM_ISSUER_ID } = require('./constants');

class PckExtension {
    constructor(ppid, cpuSvn, pceSvn, pceId, fmspc, sgxType, platformInstanceId) {
        this.ppid = ppid;
        this.cpuSvn = cpuSvn;
        this.pceSvn = pceSvn;
        this.pceId = pceId;
        this.fmspc = fmspc;
        this.sgxType = sgxType;
        this.platformInstanceId = platformInstanceId;
    }
}

function findExtensionRequired(path, extension) {
    return utils.findExtension(path, extension);
}

function findExtensionOptional(path, extension) {
    try {
        return utils.findExtension(path, extension);
    } catch (e) {
        return null;
    }
}

function decodeEnumerated(bytes) {
    if (bytes.length === 1) {
        return bytes[0];
    } else if (bytes.length === 2) {
        return (bytes[0] << 8) | bytes[1];
    } else {
        throw new Error(`Unexpected ENUMERATED length: ${bytes.length}`);
    }
}

function parsePckExtension(certDer) {
    const extension = utils.getIntelExtension(certDer);

    const ppid = findExtensionRequired([oids.PPID], extension);
    const cpuSvn = utils.getCpuSvn(extension);
    const pceSvn = utils.getPceSvn(extension);
    const pceId = findExtensionRequired([oids.PCEID], extension);
    const fmspc = utils.getFmspc(extension);
    const sgxType = decodeEnumerated(findExtensionRequired([oids.SGX_TYPE], extension));
    const platformInstanceId = findExtensionOptional([oids.PLATFORM_INSTANCE_ID], extension);

    return new PckExtension(ppid, cpuSvn, pceSvn, pceId, fmspc, sgxType, platformInstanceId);
}

function extractCertChain(quote) {
    try {
        const chainBytes = quote.rawCertChain();
        const certs = utils.extractCerts(chainBytes);
        return certs;
    } catch (e) {
        const certData = quote.authData.version === 3
            ? quote.authData.data.certificationData
            : quote.authData.data.qeReportData.certificationData;

        if (certData.certType === 4) { // PCK_ID_PCK_CERTIFICATE
            return [certData.body];
        }

        throw new Error(`Certification data type ${certData.certType} is not supported (expecting 4 or 5)`);
    }
}

// Get CA type from quote (processor or platform)
function getCa(quote) {
    try {
        const rawCertChain = quote.rawCertChain();
        const certs = utils.extractCerts(rawCertChain);

        if (certs.length === 0) {
            throw new Error('Invalid certificate');
        }

        const cert = utils.Certificate.decode(certs[0], 'der');
        const issuerStr = formatDistinguishedName(cert.tbsCertificate.issuer);

        if (issuerStr.includes(PROCESSOR_ISSUER)) {
            return PROCESSOR_ISSUER_ID;
        } else if (issuerStr.includes(PLATFORM_ISSUER)) {
            return PLATFORM_ISSUER_ID;
        }

        return PROCESSOR_ISSUER_ID; // default
    } catch (e) {
        return PROCESSOR_ISSUER_ID; // default
    }
}

// Format X.509 Distinguished Name to string
function formatDistinguishedName(name) {
    // The 'name' is an ASN.1 encoded RDNSequence
    // For simplicity, we'll decode it as a buffer and convert to string
    // In production, you'd want to properly parse the RDNSequence structure

    const DistinguishedName = asn1.define('DistinguishedName', function () {
        this.any();
    });

    const encoded = DistinguishedName.encode(name, 'der');
    return encoded.toString('hex'); // Simple hex representation for matching
}

// Get FMSPC from quote
function getFmspc(quote) {
    const rawCertChain = quote.rawCertChain();
    const certs = utils.extractCerts(rawCertChain);

    if (certs.length === 0) {
        throw new Error('Invalid certificate');
    }

    const extensionSection = utils.getIntelExtension(certs[0]);
    return utils.getFmspc(extensionSection);
}

module.exports = {
    PckExtension,
    parsePckExtension,
    extractCertChain,
    getCa,
    getFmspc,
};
