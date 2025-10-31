/**
 * Collateral fetching from PCS and PCCS
 */

import { QuoteCollateralV3, QuoteVerificationError } from './types';
import { parseQuote } from './parser';
import { parsePemCertificateChain, extractIntelExtension, getFmspc, extractCrlUrl } from './certificate';
import { bytesToHex, hexToBytes } from './utils';
import { TEE_TYPE_SGX, PROCESSOR_ISSUER, PLATFORM_ISSUER } from './constants';

const PCS_URL = 'https://api.trustedservices.intel.com';

/**
 * Fetch collateral from Intel PCS
 */
export async function getCollateralFromPcs(
  rawQuote: Uint8Array,
  timeout = 10000
): Promise<QuoteCollateralV3> {
  return getCollateral(PCS_URL, rawQuote, timeout);
}

/**
 * Fetch collateral from a PCCS server
 */
export async function getCollateral(
  pccsUrl: string,
  rawQuote: Uint8Array,
  timeout = 10000
): Promise<QuoteCollateralV3> {
  // Parse quote to extract FMSPC and CA type
  const quote = parseQuote(rawQuote);

  // Get FMSPC from quote
  const fmspc = await extractFmspcFromQuote(rawQuote);
  const fmspcHex = bytesToHex(fmspc);

  // Get CA type (processor or platform)
  const ca = await extractCaFromQuote(rawQuote);

  // Determine TEE type
  const isSgx = quote.header.tee_type === TEE_TYPE_SGX;
  const tee = isSgx ? 'sgx' : 'tdx';

  // Normalize PCCS URL
  const baseUrl = pccsUrl
    .replace(/\/$/, '')
    .replace(/\/sgx\/certification\/v4$/, '')
    .replace(/\/tdx\/certification\/v4$/, '');

  // Build URLs
  const certUrl = `${baseUrl}/${tee}/certification/v4`;

  // Create abort controller for timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    // Fetch PCK CRL
    const pckCrlUrl = `${certUrl}/pckcrl?ca=${ca}&encoding=der`;
    const pckCrlResp = await fetch(pckCrlUrl, { signal: controller.signal });
    if (!pckCrlResp.ok) {
      throw new QuoteVerificationError(`Failed to fetch PCK CRL: ${pckCrlResp.statusText}`);
    }
    const pckCrlBytes = new Uint8Array(await pckCrlResp.arrayBuffer());
    const pckCrl = bytesToHex(pckCrlBytes);
    const pckCrlIssuerChain =
      pckCrlResp.headers.get('SGX-PCK-CRL-Issuer-Chain') ||
      pckCrlResp.headers.get('TCB-Info-Issuer-Chain') ||
      '';

    // Fetch TCB Info
    const tcbInfoUrl = `${certUrl}/tcb?fmspc=${fmspcHex}`;
    const tcbInfoResp = await fetch(tcbInfoUrl, { signal: controller.signal });
    if (!tcbInfoResp.ok) {
      throw new QuoteVerificationError(`Failed to fetch TCB info: ${tcbInfoResp.statusText}`);
    }
    const tcbInfoJson = (await tcbInfoResp.json()) as any;
    const tcbInfo = JSON.stringify(tcbInfoJson.tcbInfo);
    const tcbInfoSignature = tcbInfoJson.signature || '';
    const tcbInfoIssuerChain =
      tcbInfoResp.headers.get('TCB-Info-Issuer-Chain') ||
      tcbInfoResp.headers.get('SGX-TCB-Info-Issuer-Chain') ||
      '';

    // Fetch QE Identity
    const qeIdentityUrl = `${certUrl}/qe/identity?update=standard`;
    const qeIdentityResp = await fetch(qeIdentityUrl, { signal: controller.signal });
    if (!qeIdentityResp.ok) {
      throw new QuoteVerificationError(
        `Failed to fetch QE identity: ${qeIdentityResp.statusText}`
      );
    }
    const qeIdentityJson = (await qeIdentityResp.json()) as any;
    const qeIdentity = JSON.stringify(qeIdentityJson.enclaveIdentity);
    const qeIdentitySignature = qeIdentityJson.signature || '';
    const qeIdentityIssuerChain =
      qeIdentityResp.headers.get('SGX-Enclave-Identity-Issuer-Chain') ||
      qeIdentityResp.headers.get('TCB-Info-Issuer-Chain') ||
      '';

    // Fetch root CA CRL - different logic for PCS vs PCCS
    const isPcs = baseUrl.startsWith(PCS_URL);
    let rootCaCrl: string;

    if (!isPcs) {
      // PCCS: try to fetch from rootcacrl endpoint (returns hex-encoded string)
      const rootCaCrlUrl = `${baseUrl}/sgx/certification/v4/rootcacrl`;
      try {
        const rootCaCrlResp = await fetch(rootCaCrlUrl, { signal: controller.signal });
        if (rootCaCrlResp.ok) {
          // PCCS returns hex-encoded CRL as plain text
          const hexCrl = await rootCaCrlResp.text();
          rootCaCrl = hexCrl.replace(/\s/g, '').toLowerCase();
        } else {
          // Fallback: extract CRL URL from root certificate
          rootCaCrl = await extractRootCaCrlFromCert(qeIdentityIssuerChain, controller.signal);
        }
      } catch {
        // Fallback: extract CRL URL from root certificate
        rootCaCrl = await extractRootCaCrlFromCert(qeIdentityIssuerChain, controller.signal);
      }
    } else {
      // PCS: extract CRL URL from root certificate and fetch from there
      rootCaCrl = await extractRootCaCrlFromCert(qeIdentityIssuerChain, controller.signal);
    }

    return {
      pck_crl_issuer_chain: decodeURIComponent(pckCrlIssuerChain),
      root_ca_crl: hexStringToHexEncoded(rootCaCrl),
      pck_crl: hexStringToHexEncoded(pckCrl),
      tcb_info_issuer_chain: decodeURIComponent(tcbInfoIssuerChain),
      tcb_info: tcbInfo,
      tcb_info_signature: tcbInfoSignature,
      qe_identity_issuer_chain: decodeURIComponent(qeIdentityIssuerChain),
      qe_identity: qeIdentity,
      qe_identity_signature: qeIdentitySignature,
    };
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw new QuoteVerificationError('Collateral fetch timeout');
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Extract FMSPC from quote
 */
async function extractFmspcFromQuote(rawQuote: Uint8Array): Promise<Uint8Array> {
  const quote = parseQuote(rawQuote);
  const authData =
    quote.auth_data.version === 3
      ? quote.auth_data.data
      : {
          ...quote.auth_data.data,
          certification_data: quote.auth_data.data.qe_report_data.certification_data,
        };

  const certChainPem = new TextDecoder().decode(authData.certification_data.body);
  const certs = parsePemCertificateChain(certChainPem);

  if (certs.length === 0) {
    throw new QuoteVerificationError('No certificates found in quote');
  }

  const extension = extractIntelExtension(certs[0]);
  return getFmspc(extension);
}

/**
 * Extract CA type from quote
 */
async function extractCaFromQuote(rawQuote: Uint8Array): Promise<string> {
  const quote = parseQuote(rawQuote);
  const authData =
    quote.auth_data.version === 3
      ? quote.auth_data.data
      : {
          ...quote.auth_data.data,
          certification_data: quote.auth_data.data.qe_report_data.certification_data,
        };

  const certChainPem = new TextDecoder().decode(authData.certification_data.body);
  const certs = parsePemCertificateChain(certChainPem);

  if (certs.length === 0) {
    throw new QuoteVerificationError('No certificates found in quote');
  }

  const issuer = certs[0].issuer;

  if (issuer.includes(PROCESSOR_ISSUER)) {
    return 'processor';
  } else if (issuer.includes(PLATFORM_ISSUER)) {
    return 'platform';
  }

  // Default to processor
  return 'processor';
}

/**
 * Convert hex string (with or without spaces/newlines) to hex-encoded format
 */
function hexStringToHexEncoded(hexStr: string): string {
  // Remove whitespace and newlines
  return hexStr.replace(/\s/g, '').toLowerCase();
}

/**
 * Extract root CA CRL from certificate chain
 * Extracts the CRL distribution point URL from the root certificate and fetches it
 */
async function extractRootCaCrlFromCert(
  issuerChain: string,
  signal: AbortSignal
): Promise<string> {
  // Parse the issuer chain to get certificates
  const certs = parsePemCertificateChain(issuerChain);

  if (certs.length === 0) {
    throw new QuoteVerificationError('No certificates found in issuer chain');
  }

  // Get the root certificate (last one in chain)
  const rootCert = certs[certs.length - 1];

  // Extract CRL distribution point URL
  const crlUrl = extractCrlUrl(rootCert);

  if (!crlUrl) {
    throw new QuoteVerificationError('Could not find CRL distribution point in root certificate');
  }

  // Fetch the CRL from the URL
  const crlResp = await fetch(crlUrl, { signal });

  if (!crlResp.ok) {
    throw new QuoteVerificationError(`Failed to fetch root CA CRL from ${crlUrl}: ${crlResp.statusText}`);
  }

  // CRL is returned as binary DER, convert to hex
  const crlBytes = new Uint8Array(await crlResp.arrayBuffer());
  return bytesToHex(crlBytes);
}
