const fs = require('fs');
const path = require('path');
const { js_verify } = require('../../pkg/node/dcap-qvl-node');

// Function to read a file as a Uint8Array
function readFileAsUint8Array(filePath) {
    const data = fs.readFileSync(filePath);
    return new Uint8Array(data);
}

// Paths to your sample files
const rawQuotePath = path.join(__dirname, '../../sample', 'tdx_quote');
const quoteCollateralPath = path.join(__dirname, '../../sample', 'tdx_quote_collateral');

// Read the files
const rawQuote = readFileAsUint8Array(rawQuotePath);
const quoteCollateral = readFileAsUint8Array(quoteCollateralPath);

// Current timestamp
// TCBInfoExpired when using current timestamp, pick the time from verify_quote.rs
// const now = BigInt(Math.floor(Date.now() / 1000));
const now = BigInt(1725258675);

try {
    // Call the js_verify function
    const result = js_verify(rawQuote, quoteCollateral, now);
    console.log('Verification Result:', result);
} catch (error) {
    console.error('Verification failed:', error);
}