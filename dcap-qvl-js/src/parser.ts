/**
 * Quote parser - converts binary quote data into structured format
 */

import {
  Quote,
  Header,
  Report,
  EnclaveReport,
  TDReport10,
  TDReport15,
  AuthData,
  AuthDataV3,
  AuthDataV4,
  CertificationData,
  QEReportCertificationData,
  QuoteVerificationError,
} from './types';
import {
  readU16LE,
  readU32LE,
  readBytes,
} from './utils';
import {
  HEADER_BYTE_LEN,
  ENCLAVE_REPORT_BYTE_LEN,
  TD_REPORT10_BYTE_LEN,
  TD_REPORT15_BYTE_LEN,
  BODY_BYTE_SIZE,
  TEE_TYPE_SGX,
  TEE_TYPE_TDX,
  BODY_SGX_ENCLAVE_REPORT_TYPE,
  BODY_TD_REPORT10_TYPE,
  BODY_TD_REPORT15_TYPE,
  ECDSA_SIGNATURE_BYTE_LEN,
  ECDSA_PUBKEY_BYTE_LEN,
  QE_REPORT_BYTE_LEN,
  QE_REPORT_SIG_BYTE_LEN,
} from './constants';

/**
 * Parse a DCAP quote from binary data
 */
export function parseQuote(rawQuote: Uint8Array): Quote {
  let offset = 0;

  // Parse header (48 bytes)
  const header = parseHeader(rawQuote, offset);
  offset += HEADER_BYTE_LEN;

  // Parse report based on version and TEE type
  let report: Report;
  let reportSize: number;

  if (header.version === 3) {
    // Version 3: SGX only
    if (header.tee_type !== TEE_TYPE_SGX) {
      throw new QuoteVerificationError('Invalid TEE type for version 3');
    }
    const enclaveReport = parseEnclaveReport(rawQuote, offset);
    report = { type: 'SgxEnclave', report: enclaveReport };
    reportSize = ENCLAVE_REPORT_BYTE_LEN;
  } else if (header.version === 4) {
    // Version 4: SGX or TDX
    if (header.tee_type === TEE_TYPE_SGX) {
      const enclaveReport = parseEnclaveReport(rawQuote, offset);
      report = { type: 'SgxEnclave', report: enclaveReport };
      reportSize = ENCLAVE_REPORT_BYTE_LEN;
    } else if (header.tee_type === TEE_TYPE_TDX) {
      const tdReport = parseTDReport10(rawQuote, offset);
      report = { type: 'TD10', report: tdReport };
      reportSize = TD_REPORT10_BYTE_LEN;
    } else {
      throw new QuoteVerificationError('Invalid TEE type for version 4');
    }
  } else if (header.version === 5) {
    // Version 5: Has body type field
    const bodyType = readU16LE(rawQuote, offset);
    offset += BODY_BYTE_SIZE;

    if (bodyType === BODY_SGX_ENCLAVE_REPORT_TYPE) {
      const enclaveReport = parseEnclaveReport(rawQuote, offset);
      report = { type: 'SgxEnclave', report: enclaveReport };
      reportSize = ENCLAVE_REPORT_BYTE_LEN;
    } else if (bodyType === BODY_TD_REPORT10_TYPE) {
      const tdReport = parseTDReport10(rawQuote, offset);
      report = { type: 'TD10', report: tdReport };
      reportSize = TD_REPORT10_BYTE_LEN;
    } else if (bodyType === BODY_TD_REPORT15_TYPE) {
      const tdReport = parseTDReport15(rawQuote, offset);
      report = { type: 'TD15', report: tdReport };
      reportSize = TD_REPORT15_BYTE_LEN;
    } else {
      throw new QuoteVerificationError('Unsupported body type');
    }
  } else {
    throw new QuoteVerificationError('Unsupported quote version');
  }

  offset += reportSize;

  // Parse auth data size
  const authDataSize = readU32LE(rawQuote, offset);
  offset += 4;

  // Parse auth data
  const authDataBuffer = readBytes(rawQuote, offset, authDataSize);
  const authData = parseAuthData(authDataBuffer, header.version);

  // Calculate signed length
  const signed_length = calculateSignedLength(header, report);

  return {
    header,
    report,
    auth_data: authData,
    signed_length,
  };
}

/**
 * Parse quote header
 */
function parseHeader(buffer: Uint8Array, offset: number): Header {
  if (buffer.length < offset + HEADER_BYTE_LEN) {
    throw new QuoteVerificationError('Buffer too short for header');
  }

  return {
    version: readU16LE(buffer, offset),
    attestation_key_type: readU16LE(buffer, offset + 2),
    tee_type: readU32LE(buffer, offset + 4),
    qe_svn: readU16LE(buffer, offset + 8),
    pce_svn: readU16LE(buffer, offset + 10),
    qe_vendor_id: readBytes(buffer, offset + 12, 16),
    user_data: readBytes(buffer, offset + 28, 20),
  };
}

/**
 * Parse SGX enclave report
 */
export function parseEnclaveReport(buffer: Uint8Array, offset: number): EnclaveReport {
  if (buffer.length < offset + ENCLAVE_REPORT_BYTE_LEN) {
    throw new QuoteVerificationError('Buffer too short for enclave report');
  }

  return {
    cpu_svn: readBytes(buffer, offset, 16),
    misc_select: readU32LE(buffer, offset + 16),
    reserved1: readBytes(buffer, offset + 20, 28),
    attributes: readBytes(buffer, offset + 48, 16),
    mr_enclave: readBytes(buffer, offset + 64, 32),
    reserved2: readBytes(buffer, offset + 96, 32),
    mr_signer: readBytes(buffer, offset + 128, 32),
    reserved3: readBytes(buffer, offset + 160, 96),
    isv_prod_id: readU16LE(buffer, offset + 256),
    isv_svn: readU16LE(buffer, offset + 258),
    reserved4: readBytes(buffer, offset + 260, 60),
    report_data: readBytes(buffer, offset + 320, 64),
  };
}

/**
 * Parse TDX Report 1.0
 */
function parseTDReport10(buffer: Uint8Array, offset: number): TDReport10 {
  if (buffer.length < offset + TD_REPORT10_BYTE_LEN) {
    throw new QuoteVerificationError('Buffer too short for TD Report 1.0');
  }

  return {
    tee_tcb_svn: readBytes(buffer, offset, 16),
    mr_seam: readBytes(buffer, offset + 16, 48),
    mr_signer_seam: readBytes(buffer, offset + 64, 48),
    seam_attributes: readBytes(buffer, offset + 112, 8),
    td_attributes: readBytes(buffer, offset + 120, 8),
    xfam: readBytes(buffer, offset + 128, 8),
    mr_td: readBytes(buffer, offset + 136, 48),
    mr_config_id: readBytes(buffer, offset + 184, 48),
    mr_owner: readBytes(buffer, offset + 232, 48),
    mr_owner_config: readBytes(buffer, offset + 280, 48),
    rt_mr0: readBytes(buffer, offset + 328, 48),
    rt_mr1: readBytes(buffer, offset + 376, 48),
    rt_mr2: readBytes(buffer, offset + 424, 48),
    rt_mr3: readBytes(buffer, offset + 472, 48),
    report_data: readBytes(buffer, offset + 520, 64),
  };
}

/**
 * Parse TDX Report 1.5
 */
function parseTDReport15(buffer: Uint8Array, offset: number): TDReport15 {
  if (buffer.length < offset + TD_REPORT15_BYTE_LEN) {
    throw new QuoteVerificationError('Buffer too short for TD Report 1.5');
  }

  const base = parseTDReport10(buffer, offset);

  return {
    base,
    tee_tcb_svn2: readBytes(buffer, offset + TD_REPORT10_BYTE_LEN, 16),
    mr_service_td: readBytes(buffer, offset + TD_REPORT10_BYTE_LEN + 16, 48),
  };
}

/**
 * Parse authentication data (version 3 or 4)
 */
function parseAuthData(buffer: Uint8Array, version: number): AuthData {
  if (version === 3) {
    return { version: 3, data: parseAuthDataV3(buffer) };
  } else if (version === 4) {
    return { version: 4, data: parseAuthDataV4(buffer) };
  } else {
    throw new QuoteVerificationError('Unsupported auth data version');
  }
}

/**
 * Parse authentication data version 3
 */
function parseAuthDataV3(buffer: Uint8Array): AuthDataV3 {
  let offset = 0;

  const ecdsa_signature = readBytes(buffer, offset, ECDSA_SIGNATURE_BYTE_LEN);
  offset += ECDSA_SIGNATURE_BYTE_LEN;

  const ecdsa_attestation_key = readBytes(buffer, offset, ECDSA_PUBKEY_BYTE_LEN);
  offset += ECDSA_PUBKEY_BYTE_LEN;

  const qe_report = readBytes(buffer, offset, QE_REPORT_BYTE_LEN);
  offset += QE_REPORT_BYTE_LEN;

  const qe_report_signature = readBytes(buffer, offset, QE_REPORT_SIG_BYTE_LEN);
  offset += QE_REPORT_SIG_BYTE_LEN;

  const qe_auth_data_size = readU16LE(buffer, offset);
  offset += 2;

  const qe_auth_data = readBytes(buffer, offset, qe_auth_data_size);
  offset += qe_auth_data_size;

  const certification_data = parseCertificationData(buffer, offset);

  return {
    ecdsa_signature,
    ecdsa_attestation_key,
    qe_report,
    qe_report_signature,
    qe_auth_data,
    certification_data,
  };
}

/**
 * Parse authentication data version 4
 */
function parseAuthDataV4(buffer: Uint8Array): AuthDataV4 {
  let offset = 0;

  const ecdsa_signature = readBytes(buffer, offset, ECDSA_SIGNATURE_BYTE_LEN);
  offset += ECDSA_SIGNATURE_BYTE_LEN;

  const ecdsa_attestation_key = readBytes(buffer, offset, ECDSA_PUBKEY_BYTE_LEN);
  offset += ECDSA_PUBKEY_BYTE_LEN;

  const certification_data = parseCertificationData(buffer, offset);

  // Parse QE report data from certification data body
  const qe_report_data = parseQEReportCertificationData(certification_data.body);

  return {
    ecdsa_signature,
    ecdsa_attestation_key,
    certification_data,
    qe_report_data,
  };
}

/**
 * Parse certification data
 */
function parseCertificationData(buffer: Uint8Array, offset: number): CertificationData {
  const cert_type = readU16LE(buffer, offset);
  offset += 2;

  const size = readU32LE(buffer, offset);
  offset += 4;

  const body = readBytes(buffer, offset, size);

  return { cert_type, body };
}

/**
 * Parse QE Report Certification Data
 */
function parseQEReportCertificationData(buffer: Uint8Array): QEReportCertificationData {
  let offset = 0;

  const qe_report = readBytes(buffer, offset, QE_REPORT_BYTE_LEN);
  offset += QE_REPORT_BYTE_LEN;

  const qe_report_signature = readBytes(buffer, offset, QE_REPORT_SIG_BYTE_LEN);
  offset += QE_REPORT_SIG_BYTE_LEN;

  const qe_auth_data_size = readU16LE(buffer, offset);
  offset += 2;

  const qe_auth_data = readBytes(buffer, offset, qe_auth_data_size);
  offset += qe_auth_data_size;

  const certification_data = parseCertificationData(buffer, offset);

  return {
    qe_report,
    qe_report_signature,
    qe_auth_data,
    certification_data,
  };
}

/**
 * Calculate the length of the signed portion of the quote
 */
function calculateSignedLength(header: Header, report: Report): number {
  let len = HEADER_BYTE_LEN;

  if (header.version === 5) {
    len += BODY_BYTE_SIZE;
  }

  switch (report.type) {
    case 'SgxEnclave':
      len += ENCLAVE_REPORT_BYTE_LEN;
      break;
    case 'TD10':
      len += TD_REPORT10_BYTE_LEN;
      break;
    case 'TD15':
      len += TD_REPORT15_BYTE_LEN;
      break;
  }

  return len;
}

/**
 * Get AuthDataV3 from either version (converts V4 to V3 if needed)
 */
export function getAuthDataV3(authData: AuthData): AuthDataV3 {
  if (authData.version === 3) {
    return authData.data;
  } else {
    // Convert V4 to V3
    const v4 = authData.data;
    return {
      ecdsa_signature: v4.ecdsa_signature,
      ecdsa_attestation_key: v4.ecdsa_attestation_key,
      qe_report: v4.qe_report_data.qe_report,
      qe_report_signature: v4.qe_report_data.qe_report_signature,
      qe_auth_data: v4.qe_report_data.qe_auth_data,
      certification_data: v4.qe_report_data.certification_data,
    };
  }
}
