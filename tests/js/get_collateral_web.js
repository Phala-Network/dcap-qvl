import init, { js_get_collateral } from "/pkg/web/dcap-qvl-web.js";

// Function to fetch a file as a Uint8Array
async function fetchFileAsUint8Array(url) {
    const response = await fetch(url);
    const data = await response.arrayBuffer();
    return new Uint8Array(data);
}

// URLs to your sample files
const rawQuoteUrl = "/sample/tdx_quote";

// Load the files
async function getCollateral() {
    try {
        // Initialize the WASM module
        await init("/pkg/web/dcap-qvl-web_bg.wasm");

        const rawQuote = await fetchFileAsUint8Array(rawQuoteUrl);

        // Call the js_get_collateral function for TDX quote
        let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
        const result = await js_get_collateral(pccs_url, rawQuote);
        console.log("Collateral Result:", result);
    } catch (error) {
        console.error("Get collateral failed:", error);
    }
}

// Execute the verification
getCollateral();
