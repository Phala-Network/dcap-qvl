import init, { QuoteVerifier, SimplePolicy } from "@phala/dcap-qvl-web";
import wasm from "@phala/dcap-qvl-web/dcap-qvl-web_bg.wasm";

const PCCS_URL = "https://pccs.phala.network/tdx/certification/v4";

async function fetchQuoteAsUint8Array(url: string): Promise<Uint8Array> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch file: ${response.statusText}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}

init(wasm).then(() => {
  console.log("Phala DCAP QVL initialized!");
  fetchQuoteAsUint8Array("/sample/tdx_quote").then(async (rawQuote) => {
    const quoteCollateral = await QuoteVerifier.get_collateral(PCCS_URL, rawQuote);
    const now = BigInt(Math.floor(Date.now() / 1000));
    const verifier = new QuoteVerifier();
    const result = verifier.verify(rawQuote, quoteCollateral, now);
    const policy = new SimplePolicy(now);
    const report = result.validate(policy);
    console.log("Verification Result:", report);
  });
}).catch((error: unknown) => {
  console.error("Error:", error);
});

const app = document.getElementById("app");
if (app) {
  app.innerHTML = `
    <div style="text-align: center;">
    <h3>esbuild + @phala/dcap-qvl-web</h3>
    <p>Open the console to see verification results.</p>
  `;
} 