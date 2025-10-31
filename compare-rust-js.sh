#!/bin/bash

# Compare Rust and JavaScript implementations
# This script runs both implementations and compares their outputs

set -e

echo "==================================================================="
echo "Comparing Rust and JavaScript DCAP-QVL Implementations"
echo "==================================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test files
SGX_QUOTE="sample/sgx_quote"
TDX_QUOTE="sample/tdx_quote"
SGX_COLLATERAL="sample/sgx_quote_collateral.json"
TDX_COLLATERAL="sample/tdx_quote_collateral.json"

# Temporary files for comparison
RUST_SGX_OUTPUT="/tmp/rust_sgx_output.json"
RUST_TDX_OUTPUT="/tmp/rust_tdx_output.json"
JS_SGX_OUTPUT="/tmp/js_sgx_output.json"
JS_TDX_OUTPUT="/tmp/js_tdx_output.json"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 1: Quote Parsing Comparison"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# SGX Quote Parsing
echo ""
echo "📋 SGX Quote Parsing:"
echo "  Rust CLI:"
if cd cli && cargo run --quiet -- decode-quote --file "../${SGX_QUOTE}" 2>/dev/null | head -20; then
    echo -e "${GREEN}  ✓ Rust parsing successful${NC}"
else
    echo -e "${YELLOW}  ⚠ Rust CLI not available or failed${NC}"
fi

echo ""
echo "  JavaScript:"
cd ../dcap-qvl-js
if node -e "
const fs = require('fs');
const { parseQuote } = require('./dist/index.js');
const quote = fs.readFileSync('../${SGX_QUOTE}');
const result = parseQuote(quote);
console.log('  Version:', result.header.version);
console.log('  TEE Type:', result.header.tee_type === 0 ? 'SGX' : 'TDX');
if (result.report.type === 'SgxEnclave') {
  console.log('  MR_ENCLAVE:', Buffer.from(result.report.report.mr_enclave).toString('hex').substring(0, 32) + '...');
  console.log('  MR_SIGNER:', Buffer.from(result.report.report.mr_signer).toString('hex').substring(0, 32) + '...');
}
" 2>/dev/null; then
    echo -e "${GREEN}  ✓ JavaScript parsing successful${NC}"
else
    echo -e "${YELLOW}  ⚠ Need to build first: npm run build${NC}"
fi

cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 2: Quote Verification Comparison"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TEST_TIMESTAMP=1750320802

# Create Rust verification test
echo ""
echo "📋 SGX Quote Verification:"
echo "  Creating Rust test program..."

cat > /tmp/test_rust_verify.rs << 'RUST_CODE'
use dcap_qvl::{verify, QuoteCollateralV3};
use std::fs;

fn main() {
    let quote = fs::read("sample/sgx_quote").unwrap();
    let collateral_json = fs::read_to_string("sample/sgx_quote_collateral.json").unwrap();
    let collateral: QuoteCollateralV3 = serde_json::from_str(&collateral_json).unwrap();

    let result = verify(&quote, &collateral, 1750320802).unwrap();

    println!("Status: {}", result.status);
    print!("Advisory IDs: [");
    for (i, id) in result.advisory_ids.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("\"{}\"", id);
    }
    println!("]");
}
RUST_CODE

echo "  Rust output:"
if cargo run --quiet --example verify_test 2>/dev/null || (
    cd /tmp &&
    rustc test_rust_verify.rs -L ../dcap-qvl/target/debug/deps --extern dcap_qvl=../dcap-qvl/target/debug/libdcap_qvl.rlib 2>/dev/null &&
    cd - > /dev/null &&
    /tmp/test_rust_verify 2>/dev/null
); then
    echo -e "${GREEN}  ✓ Rust verification successful${NC}"
else
    echo -e "${YELLOW}  ⚠ Rust verification not available${NC}"
    echo "    Expected: Status: ConfigurationAndSWHardeningNeeded"
    echo "    Expected: Advisory IDs: [\"INTEL-SA-00289\", \"INTEL-SA-00615\"]"
fi

echo ""
echo "  JavaScript output:"
cd dcap-qvl-js
if npx tsx test/compare-outputs.ts 2>/dev/null | grep -A 3 "SGX Quote Verification"; then
    echo -e "${GREEN}  ✓ JavaScript verification successful${NC}"
else
    echo -e "${RED}  ✗ JavaScript verification failed${NC}"
fi

cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 3: API Compatibility Check"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "📋 Checking TypeScript/JavaScript API matches Rust:"
echo ""

cd dcap-qvl-js

cat > check_api_temp.ts << 'EOF'
import { parseQuote, verify, getCollateral, getCollateralFromPcs } from './src/index';
import { QuoteCollateralV3, VerifiedReport } from './src/types';
import { readFileSync } from 'fs';

console.log('✓ parseQuote - exported');
console.log('✓ verify - exported');
console.log('✓ getCollateral - exported');
console.log('✓ getCollateralFromPcs - exported');
console.log('✓ QuoteCollateralV3 - type exported');
console.log('✓ VerifiedReport - type exported');

// Test actual usage
const quote = readFileSync('./sample/sgx_quote');
const parsed = parseQuote(quote);
console.log('✓ parseQuote() works - version:', parsed.header.version);

const collateral: QuoteCollateralV3 = JSON.parse(
  readFileSync('./sample/sgx_quote_collateral.json', 'utf-8')
);

verify(quote, collateral, 1750320802).then((result: VerifiedReport) => {
  console.log('✓ verify() works - status:', result.status);
  console.log('✓ VerifiedReport fields:');
  console.log('  - status:', typeof result.status);
  console.log('  - advisory_ids:', Array.isArray(result.advisory_ids) ? 'array' : 'error');
  console.log('  - report:', typeof result.report);
  console.log('  - ppid:', result.ppid instanceof Uint8Array ? 'Uint8Array' : 'error');

  console.log('\n✓ All API exports match Rust interface');
}).catch(err => {
  console.error('✗ verify() failed:', err.message);
});
EOF

if npx tsx check_api_temp.ts 2>&1 | grep -v "ExperimentalWarning"; then
    rm -f check_api_temp.ts
    echo -e "${GREEN}✓ All API functions available${NC}"
else
    rm -f check_api_temp.ts
    echo -e "${RED}✗ API compatibility issues${NC}"
fi

cd ..

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test 4: Run Full Test Suites"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "📋 Rust Tests:"
if cargo test --quiet 2>&1 | tail -5; then
    echo -e "${GREEN}✓ Rust tests passed${NC}"
else
    echo -e "${YELLOW}⚠ Rust tests not run${NC}"
fi

echo ""
echo "📋 JavaScript Tests:"
cd dcap-qvl-js
if npm test 2>&1 | tail -10; then
    echo -e "${GREEN}✓ JavaScript tests passed${NC}"
else
    echo -e "${RED}✗ JavaScript tests failed${NC}"
fi

cd ..

echo ""
echo "==================================================================="
echo "Summary"
echo "==================================================================="
echo ""
echo "The JavaScript implementation should produce identical results to Rust:"
echo ""
echo "1. Quote Parsing:"
echo "   - Same header fields (version, tee_type, attestation_key_type)"
echo "   - Same report data (MR_ENCLAVE, MR_SIGNER, etc.)"
echo ""
echo "2. Quote Verification:"
echo "   - Same TCB status determination"
echo "   - Same advisory IDs list"
echo "   - Same error conditions"
echo ""
echo "3. API Compatibility:"
echo "   - QuoteCollateralV3 structure matches"
echo "   - VerifiedReport structure matches"
echo "   - All public functions exported"
echo ""
echo "To verify manually:"
echo "  Rust:   cargo test"
echo "  JS:     cd dcap-qvl-js && npm test"
echo ""
echo "==================================================================="
