#!/usr/bin/env node
/**
 * Node.js implementation of verify_sample CLI tool for DCAP quote verification.
 *
 * Usage:
 *     verify_sample.js <quote_file> <collateral_file> [root_ca_file]
 *
 * Exit codes:
 *     0 - Verification successful
 *     1 - Verification failed
 *     2 - Unexpected error (file not found, parse error, etc.)
 *
 * Output:
 *     Prints verification result to stdout
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

function main() {
    if (process.argv.length < 4) {
        console.error(`Usage: ${process.argv[1]} <quote_file> <collateral_file> [root_ca_file]`);
        process.exit(2);
    }

    const quoteFile = process.argv[2];
    const collateralFile = process.argv[3];
    const rootCaFile = process.argv.length > 4 ? process.argv[4] : null;

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
        wasmModule = require("./pkg/node/dcap-qvl-node");
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

main();
