// Collateral fetching from PCCS
// Converted from collateral.rs

// Requires Node.js >= 18.17 (global fetch, AbortSignal.timeout).
const { Buffer } = require('buffer');
const { Quote } = require('./quote');
const intel = require('./intel');
const utils = require('./utils');
const {
    PCK_ID_ENCRYPTED_PPID_2048,
    PCK_ID_ENCRYPTED_PPID_3072,
    PCK_ID_PCK_CERT_CHAIN,
    PROCESSOR_ISSUER,
    PLATFORM_ISSUER,
    PROCESSOR_ISSUER_ID,
    PLATFORM_ISSUER_ID,
} = require('./constants');

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

// Default deadline for a whole collateral operation. All serial fetches in
// one getCollateral* call share a single deadline created at the entry point.
const DEFAULT_COLLATERAL_TIMEOUT_MS = 30_000;

// Build the per-operation signal: the caller's signal plus one deadline that
// bounds the entire collateral fetch sequence.
function operationSignal(options) {
    const { signal, timeoutMs } = options || {};
    const effective = timeoutMs === undefined ? DEFAULT_COLLATERAL_TIMEOUT_MS : timeoutMs;
    const signals = [
        signal,
        effective > 0 ? AbortSignal.timeout(effective) : null,
    ].filter(Boolean);
    return signals.length ? AbortSignal.any(signals) : null;
}

function rethrowClassified(error, url) {
    if (error && error.name === 'TimeoutError') {
        throw new Error(`Collateral fetch timed out: ${url}`, { cause: error });
    }
    throw error;
}

/**
 * Fetch a URL and return a Response whose body is fully buffered.
 *
 * `signal` must carry the whole-operation deadline/cancellation (see
 * operationSignal). The signal stays attached for the body read, so the
 * deadline covers the whole response: a stalled body read rejects as soon as
 * the signal fires (verified on Node 18/20/22/24 — the pending arrayBuffer()
 * rejects within ~150ms of abort).
 */
async function fetchBuffered(url, { signal } = {}) {
    try {
        const response = await fetch(url, signal ? { signal } : {});
        const buffer = await response.arrayBuffer();
        return new Response(buffer, {
            status: response.status,
            statusText: response.statusText,
            headers: response.headers,
        });
    } catch (error) {
        rethrowClassified(error, url);
    }
}

async function httpGet(url, options) {
    const response = await fetchBuffered(url, options);
    if (!response.ok) {
        throw new Error(`Failed to fetch ${url}: ${response.status}`);
    }
    return Buffer.from(await response.arrayBuffer());
}

/**
 * Fetch PCK certificate from PCCS using encrypted PPID parameters.
 */
async function fetchPckCertificate(pccsUrl, params, options) {
    // PCCS normalizes parameters to uppercase, Intel PCS accepts both
    // Use uppercase for compatibility with both
    const qeid = Buffer.from(params.qeid).toString('hex').toUpperCase();
    const encryptedPpid = Buffer.from(params.encryptedPpid).toString('hex').toUpperCase();
    const cpusvn = Buffer.from(params.cpusvn).toString('hex').toUpperCase();
    const pcesvnBytes = Buffer.alloc(2);
    pcesvnBytes.writeUInt16LE(params.pcesvn, 0);
    const pcesvn = pcesvnBytes.toString('hex').toUpperCase();
    const pceid = Buffer.from(params.pceid).toString('hex').toUpperCase();

    const baseUrl = pccsUrl
        .replace(/\/$/, '')
        .replace(/\/sgx\/certification\/v4$/, '')
        .replace(/\/tdx\/certification\/v4$/, '');

    const url = `${baseUrl}/sgx/certification/v4/pckcert?qeid=${qeid}&encrypted_ppid=${encryptedPpid}&cpusvn=${cpusvn}&pcesvn=${pcesvn}&pceid=${pceid}`;

    const response = await fetchBuffered(url, options);
    if (!response.ok) {
        throw new Error(`Failed to fetch PCK certificate from ${url}: ${response.status}`);
    }

    // Check if Intel returned a certificate for a different TCB level
    // SGX-TCBm header format: cpusvn (16 bytes) + pcesvn (2 bytes, little-endian)
    const tcbmHeader = response.headers.get('SGX-TCBm');
    if (tcbmHeader) {
        const tcbmBytes = Buffer.from(tcbmHeader, 'hex');
        if (tcbmBytes.length < 18) {
            throw new Error(`SGX-TCBm header too short: expected 18 bytes, got ${tcbmBytes.length}`);
        }
        const matchedCpusvn = tcbmBytes.slice(0, 16);
        const matchedPcesvn = tcbmBytes.readUInt16LE(16);

        const paramCpusvnBuf = Buffer.from(params.cpusvn);
        if (!matchedCpusvn.equals(paramCpusvnBuf) || matchedPcesvn !== params.pcesvn) {
            throw new Error(
                `TCB level mismatch: Platform's current TCB (cpusvn=${paramCpusvnBuf.toString('hex')}, pcesvn=${params.pcesvn}) ` +
                `is not registered with Intel PCS. Intel matched to a lower TCB level ` +
                `(cpusvn=${matchedCpusvn.toString('hex')}, pcesvn=${matchedPcesvn}). ` +
                `This typically means the platform had a microcode/firmware update but MPA registration was not re-run afterward. ` +
                `Solution: Run 'mpa_manage -c mpa_registration.conf' on the platform to register the new TCB level with Intel.`
            );
        }
    }

    // The response includes the PCK certificate chain in a header
    const pckCertChain = getHeader(response, 'SGX-PCK-Certificate-Issuer-Chain');

    // The body is the leaf PCK certificate
    const pckCert = await response.text();

    // Combine into a full PEM chain (leaf first, then issuer chain)
    return `${pckCert}\n${pckCertChain}`;
}

/**
 * Extract FMSPC and CA type from a PEM certificate chain.
 */
function extractFmspcAndCa(pemChain) {
    const certs = utils.extractCerts(Buffer.from(pemChain));
    if (certs.length === 0) {
        throw new Error('Empty certificate chain');
    }

    const cert = certs[0];

    // Extract FMSPC from Intel extension
    const extension = utils.getIntelExtension(cert);
    const fmspc = utils.getFmspc(extension);
    const fmspcHex = Buffer.from(fmspc).toString('hex').toUpperCase();

    // Extract CA type from issuer
    const issuer = utils.getCertIssuer(cert);
    let ca;
    if (issuer.includes(PROCESSOR_ISSUER)) {
        ca = PROCESSOR_ISSUER_ID;
    } else if (issuer.includes(PLATFORM_ISSUER)) {
        ca = PLATFORM_ISSUER_ID;
    } else {
        ca = PROCESSOR_ISSUER_ID;
    }

    return { fmspc: fmspcHex, ca };
}

/**
 * Get PCK certificate chain for a quote.
 * - cert_type 5: extracts from quote
 * - cert_type 2/3: fetches from PCCS using encrypted PPID
 */
async function getPckChain(pccsUrl, quote, options) {
    const innerCertType = quote.innerCertType();

    switch (innerCertType) {
        case PCK_ID_PCK_CERT_CHAIN: {
            const rawChain = quote.rawCertChain();
            return Buffer.from(rawChain).toString('utf-8');
        }
        case PCK_ID_ENCRYPTED_PPID_2048:
        case PCK_ID_ENCRYPTED_PPID_3072: {
            const params = quote.encryptedPpidParams();
            return fetchPckCertificate(pccsUrl, params, options);
        }
        default:
            throw new Error(`Unsupported certification data type: ${innerCertType}`);
    }
}

async function getCollateral(pccsUrl, quoteBytes, options) {
    const op = { signal: operationSignal(options) };
    const quote = Quote.parse(quoteBytes);

    // Get PCK certificate chain (from quote or PCCS)
    const pckChain = await getPckChain(pccsUrl, quote, op);

    // Extract FMSPC and CA from the certificate
    const { fmspc, ca } = extractFmspcAndCa(pckChain);

    // Fetch the rest of the collateral
    const collateral = await getCollateralForFmspcImpl(pccsUrl, fmspc, ca, quote.header.isSgx(), op);

    // Attach the PCK certificate chain for offline verification
    collateral.pck_certificate_chain = pckChain;

    return collateral;
}

/**
 * Get collateral for a known FMSPC (public API).
 * @param options - Optional { signal, timeoutMs }; timeoutMs (default 30000)
 *                  is one deadline for the whole operation, 0 disables it.
 */
async function getCollateralForFmspc(pccsUrl, fmspc, ca, forSgx, options) {
    return getCollateralForFmspcImpl(pccsUrl, fmspc, ca, forSgx, { signal: operationSignal(options) });
}

/**
 * Internal implementation for fetching collateral by FMSPC.
 */
async function getCollateralForFmspcImpl(pccsUrl, fmspc, ca, forSgx, options) {
    const endpoints = new PcsEndpoints(pccsUrl, forSgx, fmspc, ca);

    // Fetch PCK CRL
    let pckCrlIssuerChain, pckCrl;
    {
        const response = await fetchBuffered(endpoints.urlPckcrl(), options);
        if (!response.ok) {
            throw new Error(`Failed to fetch PCK CRL: ${response.status}`);
        }
        pckCrlIssuerChain = getHeader(response, 'SGX-PCK-CRL-Issuer-Chain');
        pckCrl = Buffer.from(await response.arrayBuffer());
    }

    // Fetch TCB Info
    let tcbInfoIssuerChain, rawTcbInfo;
    {
        const response = await fetchBuffered(endpoints.urlTcb(), options);
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
        const response = await fetchBuffered(endpoints.urlQeIdentity(), options);
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
            const crl = await httpGet(endpoints.urlRootcacrl(), options);
            // PCCS returns hex-encoded CRL
            const hexStr = crl.toString('utf-8');
            rootCaCrl = Buffer.from(hexStr, 'hex');
        } catch (error) {
            // Caller cancellation and the operation deadline must surface;
            // only benign failures fall back to the cert-chain extraction.
            if (options && options.signal && options.signal.aborted) throw error;
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

        rootCaCrl = await httpGet(crlUrl, options);
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
        pck_certificate_chain: null,
    };
}

async function getCollateralFromPcs(quoteBytes, options) {
    return getCollateral(INTEL_PCS_URL, quoteBytes, options);
}

async function getCollateralAndVerify(quoteBytes, pccsUrl, options) {
    const url = (pccsUrl || '').trim() || PHALA_PCCS_URL;
    const collateral = await getCollateral(url, quoteBytes, options);
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
