import init, { js_verify } from '/pkg/web/dcap-qvl-web.js';

// Function to fetch a file as a Uint8Array
async function fetchFileAsUint8Array(url) {
    const response = await fetch(url);
    const data = await response.arrayBuffer();
    return new Uint8Array(data);
}

// URLs to your sample files
const rawQuoteUrl = '/sample/tdx_quote';
const quoteCollateralUrl = '/sample/tdx_quote_collateral';

// Load the files
async function loadFilesAndVerify() {
    try {
        // Initialize the WASM module
        await init('/pkg/web/dcap-qvl-web_bg.wasm');

        const rawQuote = await fetchFileAsUint8Array(rawQuoteUrl);
        const quoteCollateral = await fetchFileAsUint8Array(quoteCollateralUrl);

        // Current timestamp
        const now = BigInt(1725258675);

        // Call the js_verify function
        const result = js_verify(rawQuote, quoteCollateral, now);
        console.log('Verification Result:', result);
    } catch (error) {
        console.error('Verification failed:', error);
    }
}

// Execute the verification
loadFilesAndVerify();

