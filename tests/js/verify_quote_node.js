const fs = require("fs");
const path = require("path");
const {
  js_verify,
  js_get_collateral,
} = require("../../pkg/node/dcap-qvl-node");

// Function to read a file as a Uint8Array
function readFileAsUint8Array(filePath) {
  const data = fs.readFileSync(filePath);
  return new Uint8Array(data);
}

// Paths to your sample files
const rawQuotePath = path.join(__dirname, "../../sample", "tdx_quote");

// Read the files
const rawQuote = readFileAsUint8Array(rawQuotePath);

// Current timestamp
const now = BigInt(Math.floor(Date.now() / 1000));

(async () => {
  try {
    // Call the js_verify function
    let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
    const quoteCollateral = await js_get_collateral(pccs_url, rawQuote);
    const result = js_verify(rawQuote, quoteCollateral, now);
    console.log("Verification Result:", result);
  } catch (error) {
    console.error("Verification failed:", error);
  }
})();
