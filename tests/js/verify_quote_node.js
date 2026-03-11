const fs = require("fs");
const path = require("path");
const { QuoteVerifier } = require("../../pkg/node/dcap-qvl-node");

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
    let pccs_url = "https://pccs.phala.network/tdx/certification/v4";
    const quoteCollateral = await QuoteVerifier.get_collateral(pccs_url, rawQuote);
    const verifier = new QuoteVerifier();
    const result = verifier.verify(rawQuote, quoteCollateral, now);
    const report = result.into_report_unchecked();
    console.log("Verification Result:", report);
  } catch (error) {
    console.error("Verification failed:", error);
  }
})();
