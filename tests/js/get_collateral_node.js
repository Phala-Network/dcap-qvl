const fs = require("fs");
const path = require("path");
const { js_get_collateral } = require("../../pkg/node/dcap-qvl-node");

// Function to read a file as a Uint8Array
function readFileAsUint8Array(filePath) {
    const data = fs.readFileSync(filePath);
    return new Uint8Array(data);
}

// Paths to your sample files
const rawQuotePath = path.join(__dirname, "../../sample", "tdx_quote");
const rawQuote = readFileAsUint8Array(rawQuotePath);

(async () => {
    try {
        // Call the js_get_collateral function for TDX quote
        let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
        const result = await js_get_collateral(pccs_url, rawQuote);
        console.log("Collateral Result:", result);
    } catch (error) {
        console.error("Get collateral failed:", error);
    }
})();
