#!/usr/bin/env node
/**
 * Node.js implementation of test_case CLI tool for DCAP quote verification.
 *
 * Usage:
 *     test_case.js <command> [args...]
 *
 * Commands:
 *     verify <quote_file> <collateral_file> [root_ca_file]
 *     get-collateral [--pccs-url URL] <quote_file>
 *
 * Exit codes:
 *     0 - Command successful
 *     1 - Command failed
 *     2 - Unexpected error (file not found, parse error, etc.)
 *
 * Output:
 *     Prints result to stdout
 *     Prints errors to stderr
 */

const fs = require("fs");
const path = require("path");

function readFileAsUint8Array(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return new Uint8Array(data);
    } catch (e) {
        console.error(`Failed to read file ${filePath}: ${e.message}`);
        process.exit(2);
    }
}

function hexToUint8Array(hexString) {
    if (!hexString) return new Uint8Array();
    if (typeof hexString !== 'string') return hexString;
    const matches = hexString.match(/.{1,2}/g);
    if (!matches) return new Uint8Array();
    return new Uint8Array(matches.map(byte => parseInt(byte, 16)));
}

function uint8ArrayToHex(uint8Array) {
    if (!uint8Array) return "";
    // Check if it's already a hex string
    if (typeof uint8Array === 'string') return uint8Array;
    // Check if it's an object with numeric keys (like {"0": 1, "1": 2...}) which often happens in JS WASM interop
    if (typeof uint8Array === 'object' && !Array.isArray(uint8Array) && !(uint8Array instanceof Uint8Array)) {
        // Convert array-like object to real array
        uint8Array = Object.values(uint8Array);
    }
    
    return Array.from(uint8Array)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

function showHelp() {
    console.log("Node.js implementation of test_case CLI tool for DCAP quote verification");
    console.log("");
    console.log("Usage:");
    console.log("  test_case.js <command> [args...]");
    console.log("");
    console.log("Commands:");
    console.log("  verify <quote_file> <collateral_file> [root_ca_file]");
    console.log("    Verify a quote with collateral");
    console.log("  get-collateral [--pccs-url URL] <quote_file>");
    console.log("    Fetch collateral from PCCS");
    console.log("");
    console.log("Exit codes:");
    console.log("  0 - Command successful");
    console.log("  1 - Command failed");
    console.log("  2 - Unexpected error (file not found, parse error, etc.)");
}

async function cmdVerify(args) {
    const quoteFile = args[0];
    const collateralFile = args[1];
    const rootCaFile = args[2];

    if (!quoteFile || !collateralFile) {
        console.error("Error: Missing required arguments for verify command");
        console.error("Usage: test_case.js verify <quote_file> <collateral_file> [root_ca_file]");
        process.exit(2);
    }

    const quoteBytes = readFileAsUint8Array(quoteFile);

    let collateral;
    try {
        const collateralJson = fs.readFileSync(collateralFile, "utf8");
        collateral = JSON.parse(collateralJson);
        
        // Convert hex strings to Uint8Array for fields that require bytes in WASM
        // Fields marked with #[serde(with = "serde_bytes")] in Rust struct
        const byteFields = ['root_ca_crl', 'pck_crl', 'tcb_info_signature', 'qe_identity_signature'];
        for (const field of byteFields) {
            if (collateral[field] && typeof collateral[field] === 'string') {
                collateral[field] = hexToUint8Array(collateral[field]);
            }
        }
    } catch (e) {
        console.error(`Failed to read collateral file: ${e.message}`);
        process.exit(2);
    }

    const rootCaDer = rootCaFile ? readFileAsUint8Array(rootCaFile) : null;

    const now = BigInt(Math.floor(Date.now() / 1000));

    let wasmModule;
    try {
        wasmModule = require("../pkg/node/dcap-qvl-node");
    } catch (e) {
        console.error("Failed to load WASM module:", e.message);
        console.error("Please build the WASM bindings first:");
        console.error("  make build_node_pkg");
        process.exit(2);
    }

    try {
        let result;
        if (rootCaDer) {
            result = wasmModule.js_verify_with_root_ca(quoteBytes, collateral, rootCaDer, now);
        } else {
            result = wasmModule.js_verify(quoteBytes, collateral, now);
        }

        console.log("Verification successful");
        console.log(`Status: ${result.status}`);
        process.exit(0);
    } catch (e) {
        console.error(`Verification failed: ${e}`);
        process.exit(1);
    }
}

async function cmdGetCollateral(args) {
    let quoteFile;
    let pccsUrl = "https://pccs.phala.network/tdx/certification/v4";

    // Parse arguments
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--pccs-url' && i + 1 < args.length) {
            pccsUrl = args[i + 1];
            i++; // Skip next argument
        } else if (!quoteFile) {
            quoteFile = args[i];
        }
    }

    if (!quoteFile) {
        console.error("Error: Missing quote file argument");
        console.error("Usage: test_case.js get-collateral [--pccs-url URL] <quote_file>");
        process.exit(2);
    }

    const quoteBytes = readFileAsUint8Array(quoteFile);

    let wasmModule;
    try {
        wasmModule = require("../pkg/node/dcap-qvl-node");
    } catch (e) {
        console.error("Failed to load WASM module:", e.message);
        console.error("Please build the WASM bindings first:");
        console.error("  make build_node_pkg");
        process.exit(2);
    }

    try {
        const result = await wasmModule.js_get_collateral(pccsUrl, quoteBytes);

        if (!result || !result.tcb_info_issuer_chain) {
            console.error("Error: Collateral missing required fields");
            process.exit(1);
        }

        // Convert Uint8Array fields back to hex strings for JSON output compatibility with other tools
        const byteFields = ['root_ca_crl', 'pck_crl', 'tcb_info_signature', 'qe_identity_signature'];
        for (const field of byteFields) {
            if (result[field]) {
                result[field] = uint8ArrayToHex(result[field]);
            }
        }

        // Output collateral JSON directly (like Rust and Python versions)
        console.log(JSON.stringify(result));
        process.exit(0);
    } catch (e) {
        console.error(`Get collateral failed: ${e}`);
        process.exit(1);
    }
}

async function main() {
    const args = process.argv.slice(2);

    if (args.length === 0 || args[0] === '--help' || args[0] === 'help') {
        showHelp();
        process.exit(0);
    }

    const command = args[0];
    const commandArgs = args.slice(1);

    switch (command) {
        case 'verify':
            await cmdVerify(commandArgs);
            break;
        case 'get-collateral':
            await cmdGetCollateral(commandArgs);
            break;
        default:
            console.error(`Error: Unknown command '${command}'`);
            console.error("Use 'test_case.js --help' for usage information");
            process.exit(2);
    }
}

main().catch(error => {
    console.error(`Unexpected error: ${error.message}`);
    process.exit(2);
});
