import init, { js_verify, js_get_collateral } from "/pkg/web/dcap-qvl-web.js";

// Function to fetch a file as a Uint8Array
async function fetchFileAsUint8Array(url) {
  const response = await fetch(url);
  const data = await response.arrayBuffer();
  return new Uint8Array(data);
}

function fetchFileAsString(filePath) {
  return fetch(filePath).then((response) => response.text());
}

// URLs to your sample files
const rawQuoteUrl = "/sample/tdx_quote";
const quoteCollateralUrl = "/sample/tdx_quote_collateral.json";

// Load the files
async function loadFilesAndVerify() {
  try {
    // Initialize the WASM module
    await init("/pkg/web/dcap-qvl-web_bg.wasm");

    // Get the raw quote from local file
    const rawQuote = await fetchFileAsUint8Array(rawQuoteUrl);

    // Get the quote collateral
    let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
    const quoteCollateral = await js_get_collateral(pccs_url, rawQuote);

    // Current timestamp
    const now = BigInt(Math.floor(Date.now() / 1000));

    // Call the js_verify function
    const result = js_verify(rawQuote, quoteCollateral, now);
    console.log("Verification Result:", result);
  } catch (error) {
    console.error("Verification failed:", error);
  }
}

// Execute the verification
loadFilesAndVerify();
