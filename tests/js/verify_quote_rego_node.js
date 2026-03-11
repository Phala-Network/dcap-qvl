const fs = require("fs");
const path = require("path");
const {
  QuoteVerifier,
  RegoPolicy,
  RegoPolicySet,
} = require("../../pkg/node/dcap-qvl-node");

function readFileAsUint8Array(filePath) {
  const data = fs.readFileSync(filePath);
  return new Uint8Array(data);
}

const rawQuotePath = path.join(__dirname, "../../sample", "sgx_quote");
const rawQuote = readFileAsUint8Array(rawQuotePath);
const now = BigInt(Math.floor(Date.now() / 1000));

const platformPolicyJson = JSON.stringify({
  environment: {
    class_id: "3123ec35-8d38-4ea5-87a5-d6c48b567570",
  },
  reference: {
    accepted_tcb_status: ["UpToDate"],
    collateral_grace_period: 0,
  },
});

(async () => {
  try {
    const pccsUrl = "https://pccs.phala.network/sgx/certification/v4";
    const collateral = await QuoteVerifier.get_collateral(pccsUrl, rawQuote);
    const verifier = new QuoteVerifier();

    const regoReport = verifier
      .verify(rawQuote, collateral, now)
      .validate_rego(new RegoPolicy(platformPolicyJson));
    console.log("RegoPolicy report:", regoReport);

    const regoSetReport = verifier
      .verify(rawQuote, collateral, now)
      .validate_rego_set(new RegoPolicySet([platformPolicyJson]));
    console.log("RegoPolicySet report:", regoSetReport);
  } catch (error) {
    console.error("Rego verification failed:", error);
  }
})();
