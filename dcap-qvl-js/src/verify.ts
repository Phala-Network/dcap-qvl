/**
 * Main quote verification logic
 */

import {
  QuoteCollateralV3,
  VerifiedReport,
  TcbInfo,
  Report,
  EnclaveReport,
  QuoteVerificationError,
} from './types';
import { parseQuote, getAuthDataV3, parseEnclaveReport } from './parser';
import {
  parsePemCertificateChain,
  extractIntelExtension,
  getFmspc,
  getCpuSvn,
  getPceSvn,
  getPpid,
  verifyCertificateChain,
  getRootCaCertificate,
  parseCrl,
} from './certificate';
import { sha256, verifyEcdsaP256Signature, encodeEcdsaSignatureAsDer } from './crypto';
import { hexToBytes, bytesToHex, arraysEqual, arrayGreaterOrEqual } from './utils';
import {
  TEE_TYPE_TDX,
  ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE,
  PCK_CERT_CHAIN,
  ENCLAVE_REPORT_BYTE_LEN,
} from './constants';

/**
 * Extract raw public key from X509 certificate
 */
async function extractPublicKeyFromCert(cert: any): Promise<Uint8Array> {
  try {
    // Get the raw public key data from the certificate
    const publicKey = cert.publicKey;

    // Export as raw format for ECDSA P-256
    const cryptoKey = await publicKey.export();
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));

    return rawKey;
  } catch (error) {
    throw new QuoteVerificationError(`Failed to extract public key: ${error}`);
  }
}

/**
 * Verify a DCAP quote
 */
export async function verify(
  rawQuote: Uint8Array,
  collateral: QuoteCollateralV3,
  nowSecs: number
): Promise<VerifiedReport> {
  // 1. Parse quote
  const quote = parseQuote(rawQuote);

  // 2. Parse TCB info
  const tcbInfo: TcbInfo = JSON.parse(collateral.tcb_info);

  // 3. Check TCB info expiration
  const nextUpdate = new Date(tcbInfo.nextUpdate);
  if (nowSecs > nextUpdate.getTime() / 1000) {
    throw new QuoteVerificationError('TCBInfo expired');
  }

  const now = new Date(nowSecs * 1000);

  // 4. Parse CRLs
  const rootCaCrl = hexToBytes(collateral.root_ca_crl);
  const pckCrl = hexToBytes(collateral.pck_crl);
  const crls = [rootCaCrl, pckCrl];

  // Validate CRLs are parseable
  parseCrl(rootCaCrl);
  parseCrl(pckCrl);

  // 5. Get root CA
  const rootCa = getRootCaCertificate();

  // 6. Verify TCB Info certificate chain and signature
  const tcbCerts = parsePemCertificateChain(collateral.tcb_info_issuer_chain);
  if (tcbCerts.length < 2) {
    throw new QuoteVerificationError('TCB Info certificate chain too short');
  }

  await verifyCertificateChain(tcbCerts[0], tcbCerts.slice(1), rootCa, crls, now);

  // Verify TCB Info signature
  const tcbInfoSig = hexToBytes(collateral.tcb_info_signature);
  const tcbInfoBytes = new TextEncoder().encode(collateral.tcb_info);

  // Extract public key from certificate
  const tcbPubKeyRaw = await extractPublicKeyFromCert(tcbCerts[0]);

  const tcbSigValid = await verifyEcdsaP256Signature(tcbPubKeyRaw, tcbInfoBytes, tcbInfoSig);
  if (!tcbSigValid) {
    throw new QuoteVerificationError('TCB Info signature invalid');
  }

  // 7. Check quote structure
  if (![3, 4, 5].includes(quote.header.version)) {
    throw new QuoteVerificationError('Unsupported quote version');
  }

  if (quote.header.attestation_key_type !== ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE) {
    throw new QuoteVerificationError('Unsupported attestation key type');
  }

  // 8. Extract auth data
  const authData = getAuthDataV3(quote.auth_data);

  // Check certification data type
  if (authData.certification_data.cert_type !== PCK_CERT_CHAIN) {
    throw new QuoteVerificationError('Unsupported certification data type');
  }

  // 9. Verify PCK certificate chain
  const pckCerts = parsePemCertificateChain(
    new TextDecoder().decode(authData.certification_data.body)
  );
  if (pckCerts.length < 2) {
    throw new QuoteVerificationError('PCK certificate chain too short');
  }

  await verifyCertificateChain(pckCerts[0], pckCerts.slice(1), rootCa, crls, now);

  // Extract PPID
  const pckExtension = extractIntelExtension(pckCerts[0]);
  const ppid = getPpid(pckExtension);

  // 10. Verify QE report signature
  const pckPubKeyRaw = await extractPublicKeyFromCert(pckCerts[0]);

  const qeReportSigValid = await verifyEcdsaP256Signature(
    pckPubKeyRaw,
    authData.qe_report,
    authData.qe_report_signature
  );

  if (!qeReportSigValid) {
    throw new QuoteVerificationError('QE report signature invalid');
  }

  // 11. Parse and verify QE report
  // QE report is a raw EnclaveReport structure, not a full quote
  const qeReport = parseEnclaveReport(authData.qe_report, 0);

  // Verify QE hash
  const qeHashData = new Uint8Array(96);
  qeHashData.set(authData.ecdsa_attestation_key, 0);
  qeHashData.set(authData.qe_auth_data, 64);
  const qeHash = await sha256(qeHashData);

  if (!arraysEqual(qeHash, qeReport.report_data.slice(0, 32))) {
    throw new QuoteVerificationError('QE report hash mismatch');
  }

  // 12. Verify quote signature
  const pubKey = new Uint8Array(65);
  pubKey[0] = 0x04; // Uncompressed point
  pubKey.set(authData.ecdsa_attestation_key, 1);

  const signedData = rawQuote.slice(0, quote.signed_length);
  const quoteSigValid = await verifyEcdsaP256Signature(
    pubKey,
    signedData,
    authData.ecdsa_signature
  );

  if (!quoteSigValid) {
    throw new QuoteVerificationError('Quote signature invalid');
  }

  // 13. Extract and verify Intel extension fields
  const fmspc = getFmspc(pckExtension);
  const cpuSvn = getCpuSvn(pckExtension);
  const pceSvn = getPceSvn(pckExtension);

  const tcbFmspc = hexToBytes(tcbInfo.fmspc);
  if (!arraysEqual(fmspc, tcbFmspc)) {
    throw new QuoteVerificationError('FMSPC mismatch');
  }

  // 14. Check for TDX-specific requirements
  if (quote.header.tee_type === TEE_TYPE_TDX) {
    if (tcbInfo.version < 3 || tcbInfo.id !== 'TDX') {
      throw new QuoteVerificationError('TDX quote requires TDX TCB info');
    }
  }

  // 15. Determine TCB status
  let tcbStatus = 'Unknown';
  let advisoryIds: string[] = [];

  for (const tcbLevel of tcbInfo.tcbLevels) {
    // Check PCE SVN
    if (pceSvn < tcbLevel.tcb.pcesvn) {
      continue;
    }

    // Check CPU SVN components
    const sgxComponents = tcbLevel.tcb.sgxtcbcomponents.map((c) => c.svn);
    if (!arrayGreaterOrEqual(cpuSvn, sgxComponents)) {
      continue;
    }

    // For TDX, also check TDX components
    if (quote.header.tee_type === TEE_TYPE_TDX) {
      if (!tcbLevel.tcb.tdxtcbcomponents || tcbLevel.tcb.tdxtcbcomponents.length === 0) {
        throw new QuoteVerificationError('Missing TDX TCB components');
      }

      const tdReport =
        quote.report.type === 'TD15' ? quote.report.report.base :
        quote.report.type === 'TD10' ? quote.report.report : null;

      if (!tdReport) {
        throw new QuoteVerificationError('Invalid TDX report type');
      }

      const tdxComponents = tcbLevel.tcb.tdxtcbcomponents.map((c) => c.svn);
      if (!arrayGreaterOrEqual(tdReport.tee_tcb_svn, tdxComponents)) {
        continue;
      }
    }

    // Found matching TCB level
    tcbStatus = tcbLevel.tcbStatus;
    advisoryIds = tcbLevel.advisoryIDs || [];
    break;
  }

  // 16. Validate attributes
  validateAttributes(quote.report);

  return {
    status: tcbStatus,
    advisory_ids: advisoryIds,
    report: quote.report,
    ppid,
  };
}

/**
 * Validate report attributes
 */
function validateAttributes(report: Report): void {
  if (report.type === 'SgxEnclave') {
    validateSgxAttributes(report.report);
  } else if (report.type === 'TD10') {
    validateTd10Attributes(report.report);
  } else if (report.type === 'TD15') {
    validateTd10Attributes(report.report.base);
    // Check MR_SERVICE_TD is zero
    const allZero = report.report.mr_service_td.every((b) => b === 0);
    if (!allZero) {
      throw new QuoteVerificationError('Invalid MR_SERVICE_TD');
    }
  }
}

/**
 * Validate SGX attributes
 */
function validateSgxAttributes(report: EnclaveReport): void {
  // Check if debug mode is enabled (bit 1 of attributes[0])
  const isDebug = (report.attributes[0] & 0x02) !== 0;
  if (isDebug) {
    throw new QuoteVerificationError('Debug mode is enabled');
  }
}

/**
 * Validate TD 1.0 attributes
 */
function validateTd10Attributes(report: any): void {
  const tdAttrs = report.td_attributes;

  // Parse TD attributes
  const tud = tdAttrs[0];
  if (tud !== 0) {
    throw new QuoteVerificationError('Debug mode is enabled (TUD != 0)');
  }

  // Check SEC flags (bytes 1-3)
  const reservedLower = ((tdAttrs[3] & 0x0f) << 16) | (tdAttrs[2] << 8) | tdAttrs[1];
  if (reservedLower !== 0) {
    throw new QuoteVerificationError('Reserved SEC bits are set');
  }

  const septVeDisable = (tdAttrs[3] & 0x10) !== 0;
  if (!septVeDisable) {
    throw new QuoteVerificationError('SEPT_VE_DISABLE is not enabled');
  }

  const reservedBit29 = (tdAttrs[3] & 0x20) !== 0;
  if (reservedBit29) {
    throw new QuoteVerificationError('Reserved bit 29 is set');
  }

  const pks = (tdAttrs[3] & 0x40) !== 0;
  if (pks) {
    throw new QuoteVerificationError('PKS is enabled');
  }

  const kl = (tdAttrs[3] & 0x80) !== 0;
  if (kl) {
    throw new QuoteVerificationError('KL is enabled');
  }

  // Check OTHER flags reserved bits (bytes 4-7)
  const reservedOther =
    ((tdAttrs[7] & 0x7f) << 24) | (tdAttrs[6] << 16) | (tdAttrs[5] << 8) | (tdAttrs[4] & 0x7f);
  if (reservedOther !== 0) {
    throw new QuoteVerificationError('Reserved OTHER bits are set');
  }
}
