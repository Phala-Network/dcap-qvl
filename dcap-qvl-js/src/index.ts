/**
 * Main entry point for dcap-qvl
 * Universal build for Node.js and browsers
 */

export { parseQuote, getAuthDataV3 } from './parser';
export { verify } from './verify';
export { getCollateral, getCollateralFromPcs } from './collateral';
export {
  sha256,
  verifyEcdsaP256Signature,
  encodeEcdsaSignatureAsDer,
} from './crypto';
export {
  parsePemCertificateChain,
  extractIntelExtension,
  getFmspc,
  getCpuSvn,
  getPceSvn,
  getPpid,
  verifyCertificateChain,
  getRootCaCertificate,
} from './certificate';
export {
  hexToBytes,
  bytesToHex,
  readU16LE,
  readU32LE,
  readU64LE,
  readBytes,
  arraysEqual,
  arrayGreaterOrEqual,
} from './utils';

// Export types
export type {
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
  QuoteCollateralV3,
  VerifiedReport,
  TcbInfo,
  TcbLevel,
  Tcb,
  TcbComponents,
} from './types';

export { QuoteVerificationError } from './types';

// Re-export constants
export * from './constants';
