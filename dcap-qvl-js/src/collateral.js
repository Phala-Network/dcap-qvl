// Collateral fetching from PCCS
// Converted from collateral.rs

// Use native fetch in browsers, node-fetch in Node.js
const fetch = typeof globalThis.fetch !== 'undefined'
    ? globalThis.fetch
    : require('node-fetch');
const { Buffer } = require('buffer');
const { Quote } = require('./quote');
const intel = require('./intel');
const utils = require('./utils');

// Default PCCS URL (Phala Network's PCCS server - recommended)
const PHALA_PCCS_URL = 'https://pccs.phala.network';

// Intel's official PCS URL
const INTEL_PCS_URL = 'https://api.trustedservices.intel.com';

class PcsEndpoints {
    constructor(baseUrl, forSgx, fmspc, ca) {
        this.tee = forSgx ? 'sgx' : 'tdx';
        this.fmspc = fmspc;
        this.ca = ca;

        // Normalize base URL
        this.baseUrl = baseUrl
            .replace(/\/$/, '')
            .replace(/\/sgx\/certification\/v4$/, '')
            .replace(/\/tdx\/certification\/v4$/, '');
    }

    isPcs() {
        return this.baseUrl.startsWith(INTEL_PCS_URL);
    }

    urlPckcrl() {
        return this.mkUrl('sgx', `pckcrl?ca=${this.ca}&encoding=der`);
    }

    urlRootcacrl() {
        return this.mkUrl('sgx', 'rootcacrl');
    }

    urlTcb() {
        return this.mkUrl(this.tee, `tcb?fmspc=${this.fmspc}`);
    }

    urlQeIdentity() {
        return this.mkUrl(this.tee, 'qe/identity?update=standard');
    }

    mkUrl(tee, path) {
        return `${this.baseUrl}/${tee}/certification/v4/${path}`;
    }
}

function getHeader(response, name) {
    const value = response.headers.get(name);
    if (!value) {
        throw new Error(`Missing ${name}`);
    }
    return decodeURIComponent(value);
}

async function httpGet(url) {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    return Buffer.from(await response.arrayBuffer());
}

async function getCollateral(pccsUrl, quoteBytes) {
    const quote = Quote.parse(quoteBytes);
    const ca = intel.getCa(quote);
    const fmspc = Buffer.from(intel.getFmspc(quote)).toString('hex').toUpperCase();
    return getCollateralForFmspc(pccsUrl, fmspc, ca, quote.header.isSgx());
}

async function getCollateralForFmspc(pccsUrl, fmspc, ca, forSgx) {
    const endpoints = new PcsEndpoints(pccsUrl, forSgx, fmspc, ca);

    // Fetch PCK CRL
    let pckCrlIssuerChain, pckCrl;
    {
        const response = await fetch(endpoints.urlPckcrl());
        if (!response.ok) {
            throw new Error(`Failed to fetch PCK CRL: ${response.status}`);
        }
        pckCrlIssuerChain = getHeader(response, 'SGX-PCK-CRL-Issuer-Chain');
        pckCrl = Buffer.from(await response.arrayBuffer());
    }

    // Fetch TCB Info
    let tcbInfoIssuerChain, rawTcbInfo;
    {
        const response = await fetch(endpoints.urlTcb());
        if (!response.ok) {
            throw new Error(`Failed to fetch TCB info: ${response.status}`);
        }

        // Try both header names
        try {
            tcbInfoIssuerChain = getHeader(response, 'SGX-TCB-Info-Issuer-Chain');
        } catch (e) {
            tcbInfoIssuerChain = getHeader(response, 'TCB-Info-Issuer-Chain');
        }

        rawTcbInfo = await response.text();
    }

    // Fetch QE Identity
    let qeIdentityIssuerChain, rawQeIdentity;
    {
        const response = await fetch(endpoints.urlQeIdentity());
        if (!response.ok) {
            throw new Error(`Failed to fetch QE identity: ${response.status}`);
        }
        qeIdentityIssuerChain = getHeader(response, 'SGX-Enclave-Identity-Issuer-Chain');
        rawQeIdentity = await response.text();
    }

    // Fetch Root CA CRL
    let rootCaCrl = null;

    // Try to get from PCCS endpoint first (for non-PCS URLs)
    if (!endpoints.isPcs()) {
        try {
            const crl = await httpGet(endpoints.urlRootcacrl());
            // PCCS returns hex-encoded CRL
            const hexStr = crl.toString('utf-8');
            rootCaCrl = Buffer.from(hexStr, 'hex');
        } catch (e) {
            // Ignore, will try extracting from cert chain
        }
    }

    // If not available, extract from certificate chain
    if (!rootCaCrl) {
        const certs = utils.extractCerts(Buffer.from(qeIdentityIssuerChain));
        if (certs.length === 0) {
            throw new Error('No certificates found in QE identity issuer chain');
        }

        const rootCertDer = certs[certs.length - 1];
        const crlUrl = utils.extractCrlUrl(rootCertDer);

        if (!crlUrl) {
            throw new Error('Could not find CRL distribution point in root certificate');
        }

        rootCaCrl = await httpGet(crlUrl);
    }

    // Parse TCB info
    const tcbInfoJson = JSON.parse(rawTcbInfo);
    const tcbInfo = JSON.stringify(tcbInfoJson.tcbInfo);
    const tcbInfoSignature = Buffer.from(tcbInfoJson.signature, 'hex');

    // Parse QE identity
    const qeIdentityJson = JSON.parse(rawQeIdentity);
    const qeIdentity = JSON.stringify(qeIdentityJson.enclaveIdentity);
    const qeIdentitySignature = Buffer.from(qeIdentityJson.signature, 'hex');

    return {
        pck_crl_issuer_chain: pckCrlIssuerChain,
        root_ca_crl: Array.from(rootCaCrl),
        pck_crl: Array.from(pckCrl),
        tcb_info_issuer_chain: tcbInfoIssuerChain,
        tcb_info: tcbInfo,
        tcb_info_signature: Array.from(tcbInfoSignature),
        qe_identity_issuer_chain: qeIdentityIssuerChain,
        qe_identity: qeIdentity,
        qe_identity_signature: Array.from(qeIdentitySignature),
    };
}

async function getCollateralFromPcs(quoteBytes) {
    return getCollateral(INTEL_PCS_URL, quoteBytes);
}

async function getCollateralAndVerify(quoteBytes, pccsUrl) {
    const url = (pccsUrl || '').trim() || PHALA_PCCS_URL;
    const collateral = await getCollateral(url, quoteBytes);
    const now = Math.floor(Date.now() / 1000);

    const { verify } = require('./verify');
    return verify(quoteBytes, collateral, now);
}

module.exports = {
    getCollateral,
    getCollateralForFmspc,
    getCollateralFromPcs,
    getCollateralAndVerify,
    PHALA_PCCS_URL,
    INTEL_PCS_URL,
};
