/**
 * Type definitions for DCAP Quote Verification
 */

/**
 * Quote collateral data structure (version 3)
 */
export interface QuoteCollateralV3 {
  pck_crl_issuer_chain: string;
  root_ca_crl: string;
  pck_crl: string;
  tcb_info_issuer_chain: string;
  tcb_info: string;
  tcb_info_signature: string;
  qe_identity_issuer_chain: string;
  qe_identity: string;
  qe_identity_signature: string;
}

/**
 * Quote header
 */
export interface Header {
  version: number;
  attestation_key_type: number;
  tee_type: number;
  qe_svn: number;
  pce_svn: number;
  qe_vendor_id: Uint8Array;
  user_data: Uint8Array;
}

/**
 * SGX Enclave Report
 */
export interface EnclaveReport {
  cpu_svn: Uint8Array;
  misc_select: number;
  reserved1: Uint8Array;
  attributes: Uint8Array;
  mr_enclave: Uint8Array;
  reserved2: Uint8Array;
  mr_signer: Uint8Array;
  reserved3: Uint8Array;
  isv_prod_id: number;
  isv_svn: number;
  reserved4: Uint8Array;
  report_data: Uint8Array;
}

/**
 * TDX Report 1.0
 */
export interface TDReport10 {
  tee_tcb_svn: Uint8Array;
  mr_seam: Uint8Array;
  mr_signer_seam: Uint8Array;
  seam_attributes: Uint8Array;
  td_attributes: Uint8Array;
  xfam: Uint8Array;
  mr_td: Uint8Array;
  mr_config_id: Uint8Array;
  mr_owner: Uint8Array;
  mr_owner_config: Uint8Array;
  rt_mr0: Uint8Array;
  rt_mr1: Uint8Array;
  rt_mr2: Uint8Array;
  rt_mr3: Uint8Array;
  report_data: Uint8Array;
}

/**
 * TDX Report 1.5
 */
export interface TDReport15 {
  base: TDReport10;
  tee_tcb_svn2: Uint8Array;
  mr_service_td: Uint8Array;
}

/**
 * Report type (enum)
 */
export type Report =
  | { type: 'SgxEnclave'; report: EnclaveReport }
  | { type: 'TD10'; report: TDReport10 }
  | { type: 'TD15'; report: TDReport15 };

/**
 * Certification data
 */
export interface CertificationData {
  cert_type: number;
  body: Uint8Array;
}

/**
 * QE Report Certification Data
 */
export interface QEReportCertificationData {
  qe_report: Uint8Array;
  qe_report_signature: Uint8Array;
  qe_auth_data: Uint8Array;
  certification_data: CertificationData;
}

/**
 * Auth Data V3
 */
export interface AuthDataV3 {
  ecdsa_signature: Uint8Array;
  ecdsa_attestation_key: Uint8Array;
  qe_report: Uint8Array;
  qe_report_signature: Uint8Array;
  qe_auth_data: Uint8Array;
  certification_data: CertificationData;
}

/**
 * Auth Data V4
 */
export interface AuthDataV4 {
  ecdsa_signature: Uint8Array;
  ecdsa_attestation_key: Uint8Array;
  certification_data: CertificationData;
  qe_report_data: QEReportCertificationData;
}

/**
 * Auth Data type (enum)
 */
export type AuthData =
  | { version: 3; data: AuthDataV3 }
  | { version: 4; data: AuthDataV4 };

/**
 * Complete Quote structure
 */
export interface Quote {
  header: Header;
  report: Report;
  auth_data: AuthData;
  signed_length: number;
}

/**
 * TCB Component
 */
export interface TcbComponents {
  svn: number;
}

/**
 * TCB structure
 */
export interface Tcb {
  sgxtcbcomponents: TcbComponents[];
  tdxtcbcomponents?: TcbComponents[];
  pcesvn: number;
}

/**
 * TCB Level
 */
export interface TcbLevel {
  tcb: Tcb;
  tcbDate: string;
  tcbStatus: string;
  advisoryIDs?: string[];
}

/**
 * TCB Info
 */
export interface TcbInfo {
  id: string;
  version: number;
  issueDate: string;
  nextUpdate: string;
  fmspc: string;
  pceId: string;
  tcbType: number;
  tcbEvaluationDataNumber: number;
  tcbLevels: TcbLevel[];
}

/**
 * Verified Quote Result
 */
export interface VerifiedReport {
  status: string;
  advisory_ids: string[];
  report: Report;
  ppid: Uint8Array;
}

/**
 * Error class for quote verification
 */
export class QuoteVerificationError extends Error {
  constructor(message: string, public readonly code?: string) {
    super(message);
    this.name = 'QuoteVerificationError';
  }
}
