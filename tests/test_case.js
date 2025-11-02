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