/**
 * Compare outputs between Rust and JS implementations
 */

import { readFileSync } from 'fs';
import { parseQuote } from '../src/parser';
import { verify } from '../src/verify';

async function main() {
  console.log('=== Comparing Rust vs JavaScript Implementation Outputs ===\n');

  // Use same timestamp as tests to avoid expiration issues
  const TEST_TIMESTAMP = 1750320802;

  // Test 1: SGX Quote Parsing
  console.log('1. SGX Quote Parsing:');
  const sgxQuote = readFileSync('./sample/sgx_quote');
  const sgxParsed = parseQuote(sgxQuote);

  console.log('   - Quote version:', sgxParsed.header.version);
  console.log('   - TEE type:', sgxParsed.header.tee_type === 0 ? 'SGX' : 'TDX');
  console.log('   - Attestation key type:', sgxParsed.header.attestation_key_type);
  if (sgxParsed.report.type === 'SgxEnclave') {
    console.log('   - MRENCLAVE:', Buffer.from(sgxParsed.report.report.mr_enclave).toString('hex').substring(0, 32) + '...');
    console.log('   - MRSIGNER:', Buffer.from(sgxParsed.report.report.mr_signer).toString('hex').substring(0, 32) + '...');
  }
  console.log('   ✓ SGX quote parsing works\n');

  // Test 2: TDX Quote Parsing
  console.log('2. TDX Quote Parsing:');
  const tdxQuote = readFileSync('./sample/tdx_quote');
  const tdxParsed = parseQuote(tdxQuote);

  console.log('   - Quote version:', tdxParsed.header.version);
  console.log('   - TEE type:', tdxParsed.header.tee_type === 0x81 ? 'TDX' : 'SGX');
  if (tdxParsed.report.type === 'TdxReport10') {
    console.log('   - MRTD:', Buffer.from(tdxParsed.report.report.mr_td).toString('hex').substring(0, 32) + '...');
  }
  console.log('   ✓ TDX quote parsing works\n');

  // Test 3: SGX Quote Verification
  console.log('3. SGX Quote Verification:');
  const sgxCollateral = JSON.parse(readFileSync('./sample/sgx_quote_collateral.json', 'utf-8'));
  const sgxResult = await verify(sgxQuote, sgxCollateral, TEST_TIMESTAMP);

  console.log('   - TCB Status:', sgxResult.status);
  console.log('   - Advisory IDs:', sgxResult.advisory_ids);
  console.log('   - Expected: ConfigurationAndSWHardeningNeeded, [INTEL-SA-00289, INTEL-SA-00615]');

  if (sgxResult.status === 'ConfigurationAndSWHardeningNeeded' &&
      sgxResult.advisory_ids.length === 2 &&
      sgxResult.advisory_ids.includes('INTEL-SA-00289') &&
      sgxResult.advisory_ids.includes('INTEL-SA-00615')) {
    console.log('   ✓ SGX verification matches Rust output\n');
  } else {
    console.log('   ✗ SGX verification DOES NOT match Rust output\n');
  }

  // Test 4: TDX Quote Verification
  console.log('4. TDX Quote Verification:');
  const tdxCollateral = JSON.parse(readFileSync('./sample/tdx_quote_collateral.json', 'utf-8'));
  const tdxResult = await verify(tdxQuote, tdxCollateral, TEST_TIMESTAMP);

  console.log('   - TCB Status:', tdxResult.status);
  console.log('   - Advisory IDs:', tdxResult.advisory_ids);
  console.log('   - Expected: UpToDate, []');

  if (tdxResult.status === 'UpToDate' && tdxResult.advisory_ids.length === 0) {
    console.log('   ✓ TDX verification matches Rust output\n');
  } else {
    console.log('   ✗ TDX verification DOES NOT match Rust output\n');
  }

  console.log('=== Comparison Complete ===');
}

main().catch(console.error);
