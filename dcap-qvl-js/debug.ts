import { readFileSync } from 'fs';
import { parsePemCertificateChain } from './src/certificate';
import { hexToBytes, bytesToHex } from './src/utils';

const collateral = JSON.parse(
  readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
);

// Check TCB Info signature
console.log('TCB Info (first 100 chars):', collateral.tcb_info.substring(0, 100));
console.log('TCB Info Signature:', collateral.tcb_info_signature);
console.log('Signature length:', collateral.tcb_info_signature.length / 2, 'bytes');

// Parse certificate
const tcbCerts = parsePemCertificateChain(collateral.tcb_info_issuer_chain);
console.log('Number of TCB certs:', tcbCerts.length);

async function extractPubKey(cert: any) {
  const publicKey = cert.publicKey;
  const cryptoKey = await publicKey.export();
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', cryptoKey));
  console.log('Public key length:', rawKey.length);
  console.log('Public key (first 20 bytes):', bytesToHex(rawKey.slice(0, 20)));
  return rawKey;
}

await extractPubKey(tcbCerts[0]);
