// Type definitions for @phala/dcap-qvl
// Project: https://github.com/Phala-Network/dcap-qvl
// Definitions by: Phala Network

/// <reference types="node" />

// ============================================================================
// Quote Structures
// ============================================================================

export class BinaryReader {
  constructor(buffer: Buffer | Uint8Array);
  checkBounds(length: number): void;
  readU8(): number;
  readU16LE(): number;
  readU32LE(): number;
  readBytes(length: number): Uint8Array;
  remaining(): number;
  getOffset(): number;
}

export class Header {
  version: number;
  attestationKeyType: number;
  teeType: number;
  qeSvn: number;
  pceSvn: number;
  qeVendorId: Uint8Array;
  userData: Uint8Array;

  constructor(
    version: number,
    attestationKeyType: number,
    teeType: number,
    qeSvn: number,
    pceSvn: number,
    qeVendorId: Uint8Array,
    userData: Uint8Array
  );

  isSgx(): boolean;
  static decode(reader: BinaryReader): Header;
}

export class Body {
  bodyType: number;
  size: number;

  constructor(bodyType: number, size: number);
  static decode(reader: BinaryReader): Body;
}

export class EnclaveReport {
  cpuSvn: Uint8Array;
  miscSelect: number;
  reserved1: Uint8Array;
  attributes: Uint8Array;
  mrEnclave: Uint8Array;
  reserved2: Uint8Array;
  mrSigner: Uint8Array;
  reserved3: Uint8Array;
  isvProdId: number;
  isvSvn: number;
  reserved4: Uint8Array;
  reportData: Uint8Array;

  constructor(data: {
    cpuSvn: Uint8Array;
    miscSelect: number;
    reserved1: Uint8Array;
    attributes: Uint8Array;
    mrEnclave: Uint8Array;
    reserved2: Uint8Array;
    mrSigner: Uint8Array;
    reserved3: Uint8Array;
    isvProdId: number;
    isvSvn: number;
    reserved4: Uint8Array;
    reportData: Uint8Array;
  });

  static decode(reader: BinaryReader): EnclaveReport;
}

export class TDReport10 {
  teeTcbSvn: Uint8Array;
  mrSeam: Uint8Array;
  mrSignerSeam: Uint8Array;
  seamAttributes: Uint8Array;
  tdAttributes: Uint8Array;
  xfam: Uint8Array;
  mrTd: Uint8Array;
  mrConfigId: Uint8Array;
  mrOwner: Uint8Array;
  mrOwnerConfig: Uint8Array;
  rtMr0: Uint8Array;
  rtMr1: Uint8Array;
  rtMr2: Uint8Array;
  rtMr3: Uint8Array;
  reportData: Uint8Array;

  constructor(data: {
    teeTcbSvn: Uint8Array;
    mrSeam: Uint8Array;
    mrSignerSeam: Uint8Array;
    seamAttributes: Uint8Array;
    tdAttributes: Uint8Array;
    xfam: Uint8Array;
    mrTd: Uint8Array;
    mrConfigId: Uint8Array;
    mrOwner: Uint8Array;
    mrOwnerConfig: Uint8Array;
    rtMr0: Uint8Array;
    rtMr1: Uint8Array;
    rtMr2: Uint8Array;
    rtMr3: Uint8Array;
    reportData: Uint8Array;
  });

  static decode(reader: BinaryReader): TDReport10;
}

export class TDReport15 {
  base: TDReport10;
  teeTcbSvn2: Uint8Array;
  mrServiceTd: Uint8Array;

  constructor(base: TDReport10, teeTcbSvn2: Uint8Array, mrServiceTd: Uint8Array);
  static decode(reader: BinaryReader): TDReport15;
}

export class Report {
  type: 'sgx' | 'td10' | 'td15';
  data: EnclaveReport | TDReport10 | TDReport15;

  constructor(type: 'sgx' | 'td10' | 'td15', data: EnclaveReport | TDReport10 | TDReport15);

  isSgx(): boolean;
  asTd10(): TDReport10 | null;
  asTd15(): TDReport15 | null;
  asSgx(): EnclaveReport | null;
}

export class CertificationData {
  certType: number;
  body: Uint8Array;

  constructor(certType: number, body: Uint8Array);
  static decode(reader: BinaryReader): CertificationData;
}

export class QEReportCertificationData {
  qeReport: Uint8Array;
  qeReportSignature: Uint8Array;
  qeAuthData: Uint8Array;
  certificationData: CertificationData;

  constructor(
    qeReport: Uint8Array,
    qeReportSignature: Uint8Array,
    qeAuthData: Uint8Array,
    certificationData: CertificationData
  );

  static decode(reader: BinaryReader): QEReportCertificationData;
}

export class AuthDataV3 {
  ecdsaSignature: Uint8Array;
  ecdsaAttestationKey: Uint8Array;
  qeReport: Uint8Array;
  qeReportSignature: Uint8Array;
  qeAuthData: Uint8Array;
  certificationData: CertificationData;

  constructor(
    ecdsaSignature: Uint8Array,
    ecdsaAttestationKey: Uint8Array,
    qeReport: Uint8Array,
    qeReportSignature: Uint8Array,
    qeAuthData: Uint8Array,
    certificationData: CertificationData
  );

  static decode(reader: BinaryReader): AuthDataV3;
}

export class AuthDataV4 {
  ecdsaSignature: Uint8Array;
  ecdsaAttestationKey: Uint8Array;
  certificationData: CertificationData;
  qeReportData: QEReportCertificationData;

  constructor(
    ecdsaSignature: Uint8Array,
    ecdsaAttestationKey: Uint8Array,
    certificationData: CertificationData,
    qeReportData: QEReportCertificationData
  );

  intoV3(): AuthDataV3;
  static decode(reader: BinaryReader): AuthDataV4;
}

export class AuthData {
  version: 3 | 4;
  data: AuthDataV3 | AuthDataV4;

  constructor(version: 3 | 4, data: AuthDataV3 | AuthDataV4);

  intoV3(): AuthDataV3;
  static decode(version: number, reader: BinaryReader): AuthData;
}

export class Quote {
  header: Header;
  report: Report;
  authData: AuthData;

  constructor(header: Header, report: Report, authData: AuthData);

  /**
   * Parse a raw quote from bytes
   * @param quoteBytes - Raw quote bytes (Buffer or Uint8Array)
   */
  static parse(quoteBytes: Buffer | Uint8Array): Quote;

  /**
   * Get the raw certificate chain from the quote
   */
  rawCertChain(): Uint8Array;

  /**
   * Get the length of the signed portion of the quote
   */
  signedLength(): number;
}

// ============================================================================
// Verification
// ============================================================================

export type TcbStatus =
  | 'UpToDate'
  | 'SWHardeningNeeded'
  | 'ConfigurationNeeded'
  | 'ConfigurationAndSWHardeningNeeded'
  | 'OutOfDate'
  | 'OutOfDateConfigurationNeeded'
  | 'Revoked'
  | 'Unknown';

export class VerifiedReport {
  status: TcbStatus;
  advisory_ids: string[];
  report: Report;
  ppid: Buffer;

  constructor(status: TcbStatus, advisoryIds: string[], report: Report, ppid: Buffer);
}

export class QuoteVerifier {
  rootCaDer: Buffer;

  constructor(rootCaDer?: Buffer);

  /**
   * Create a new QuoteVerifier using Intel's production root CA
   */
  static newProd(): QuoteVerifier;

  /**
   * Create a new QuoteVerifier with a custom root CA
   * @param rootCaDer - Root CA certificate in DER format
   */
  static newWithRootCa(rootCaDer: Buffer): QuoteVerifier;

  /**
   * Verify a quote
   * @param rawQuote - Raw quote bytes
   * @param collateral - Quote collateral
   * @param nowSecs - Current timestamp in seconds
   */
  verify(rawQuote: Buffer | Uint8Array, collateral: Collateral, nowSecs: number): VerifiedReport;
}

/**
 * Verify a quote using Intel's production root CA
 * @param rawQuote - Raw quote bytes
 * @param collateral - Quote collateral
 * @param nowSecs - Current timestamp in seconds
 */
export function verify(
  rawQuote: Buffer | Uint8Array,
  collateral: Collateral,
  nowSecs: number
): VerifiedReport;

/**
 * Check if running in browser environment
 */
export const isBrowser: boolean;

// ============================================================================
// Collateral
// ============================================================================

/**
 * Default PCCS URL (Phala Network's PCCS server - recommended)
 * Provides better availability and lower rate limits compared to Intel's PCS.
 */
export const PHALA_PCCS_URL: string;

/**
 * Intel's official PCS (Provisioning Certification Service) URL.
 * Use getCollateralFromPcs() to fetch collateral directly from Intel.
 */
export const INTEL_PCS_URL: string;

export interface Collateral {
  pck_crl_issuer_chain: string;
  root_ca_crl: number[] | string;
  pck_crl: number[] | string;
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: number[] | string;
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: number[] | string;
}

/**
 * Get collateral for a quote from a PCCS server
 * @param pccsUrl - PCCS server URL (e.g., 'https://your-pccs-server.com/sgx/certification/v4/')
 * @param quoteBytes - Raw quote bytes
 */
export function getCollateral(
  pccsUrl: string,
  quoteBytes: Buffer | Uint8Array
): Promise<Collateral>;

/**
 * Get collateral for a specific FMSPC
 * @param pccsUrl - PCCS server URL
 * @param fmspc - FMSPC as hex string
 * @param ca - CA type ('processor' or 'platform')
 * @param forSgx - Whether this is for SGX (true) or TDX (false)
 */
export function getCollateralForFmspc(
  pccsUrl: string,
  fmspc: string,
  ca: string,
  forSgx: boolean
): Promise<Collateral>;

/**
 * Get collateral from Intel's PCS (Production Certification Service)
 * @param quoteBytes - Raw quote bytes
 */
export function getCollateralFromPcs(quoteBytes: Buffer | Uint8Array): Promise<Collateral>;

/**
 * Get collateral and verify a quote in one call
 * @param quoteBytes - Raw quote bytes
 * @param pccsUrl - Optional PCCS server URL (defaults to Phala PCCS)
 */
export function getCollateralAndVerify(
  quoteBytes: Buffer | Uint8Array,
  pccsUrl?: string
): Promise<VerifiedReport>;

// ============================================================================
// TCB Info
// ============================================================================

export interface TcbComponent {
  svn: number;
}

export interface TcbLevel {
  tcb: {
    pcesvn: number;
    sgxtcbcomponents: TcbComponent[];
    tdxtcbcomponents: TcbComponent[];
  };
  tcbStatus: TcbStatus;
  advisoryIDs: string[];
}

export class TcbInfo {
  version: number;
  issueDate: string;
  nextUpdate: string;
  fmspc: string;
  pceId: string;
  tcbType: number;
  tcbEvaluationDataNumber: number;
  tcbLevels: TcbLevel[];
  id?: string;

  constructor(data: {
    version: number;
    issueDate: string;
    nextUpdate: string;
    fmspc: string;
    pceId: string;
    tcbType: number;
    tcbEvaluationDataNumber: number;
    tcbLevels: TcbLevel[];
    id?: string;
  });

  static fromJSON(json: string): TcbInfo;
}

// ============================================================================
// Utilities and Constants
// ============================================================================

export const utils: {
  extractCerts(certChain: Buffer): Buffer[];
  verifyCertificateChain(
    leafCert: Buffer,
    intermediateCerts: Buffer[],
    nowSecs: number,
    crls: Buffer[],
    rootCaDer: Buffer
  ): void;
  encodeAsDer(signature: Buffer): Buffer;
  derToPem(der: Buffer, label: string): string;
  getIntelExtension(cert: Buffer): any;
  getCpuSvn(extension: any): Buffer;
  getPceSvn(extension: any): number;
  getFmspc(extension: any): Buffer;
  extractCrlUrl(cert: Buffer): string | null;
  Certificate: any;
  CertificateList: any;
};

export const intel: {
  getCa(quote: Quote): string;
  getFmspc(quote: Quote): Buffer;
  parsePckExtension(cert: Buffer): { ppid: Buffer };
};

export const constants: {
  TRUSTED_ROOT_CA_DER: Buffer;
  HEADER_BYTE_LEN: number;
  ENCLAVE_REPORT_BYTE_LEN: number;
  TD_REPORT10_BYTE_LEN: number;
  TD_REPORT15_BYTE_LEN: number;
  TEE_TYPE_SGX: number;
  TEE_TYPE_TDX: number;
  BODY_SGX_ENCLAVE_REPORT_TYPE: number;
  BODY_TD_REPORT10_TYPE: number;
  BODY_TD_REPORT15_TYPE: number;
  ECDSA_SIGNATURE_BYTE_LEN: number;
  ECDSA_PUBKEY_BYTE_LEN: number;
  QE_REPORT_SIG_BYTE_LEN: number;
  BODY_BYTE_SIZE: number;
  ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE: number;
  PCK_CERT_CHAIN: number;
  QE_HASH_DATA_BYTE_LEN: number;
  ATTESTATION_KEY_LEN: number;
};

export const oids: Record<string, string>;
